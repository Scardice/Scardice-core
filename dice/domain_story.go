package dice

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

type storyLogSnapshotRepository interface {
	GetStoryLogStateSnapshot(ctx context.Context, diceID, groupID string) (eventstore.StoryLogState, eventstore.CatalogReadExpectation, error)
}

type storyLogParticipant struct {
	mu      sync.RWMutex
	state   eventstore.StoryLogState
	updates []eventstore.LogUpdate
}

func storyLogParticipantKey(diceID, groupID string) execution.ParticipantKey {
	return execution.ParticipantKey{Kind: "story-log-scope", ID: fmt.Sprintf("%d:%s%d:%s", len(diceID), diceID, len(groupID), groupID)}
}

func (p *storyLogParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return eventstore.UnitOfWork{LogUpdates: append([]eventstore.LogUpdate(nil), p.updates...)}, nil
}

func (t *DurableCallbackTransaction) storyLogOwner(ctx context.Context, diceID, groupID string) (*storyLogParticipant, error) {
	if t == nil || t.domain == nil || diceID == "" || groupID == "" {
		return nil, execution.ErrDomainTxUnavailable
	}
	key := storyLogParticipantKey(diceID, groupID)
	if existing, ok := t.domain.LookupOwner(key); ok {
		owner, matches := existing.(*storyLogParticipant)
		if !matches {
			return nil, execution.ErrParticipantType
		}
		return owner, nil
	}
	repository, ok := t.store.(storyLogSnapshotRepository)
	if !ok {
		return nil, errors.New("dice: atomic Story snapshot is unavailable")
	}
	participant, err := t.domain.Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		state, expectation, loadErr := repository.GetStoryLogStateSnapshot(loadCtx, diceID, groupID)
		if loadErr != nil {
			return nil, execution.ReadDependencies{}, loadErr
		}
		if state.DiceID != diceID || state.GroupID != groupID || expectation.Catalog == "" || expectation.Owner == "" {
			return nil, execution.ReadDependencies{}, eventstore.ErrInvalidMetadata
		}
		return &storyLogParticipant{state: state}, execution.ReadDependencies{CatalogReads: []eventstore.CatalogReadExpectation{expectation}}, nil
	})
	if err != nil {
		return nil, err
	}
	owner, ok := participant.(*storyLogParticipant)
	if !ok {
		return nil, execution.ErrParticipantType
	}
	return owner, nil
}

// ReadStoryLogState returns the current canonical selection for this root.
// An already-loaded value remains readable after closure; closure cannot load
// a new owner and silently turn a historical handle into a live database view.
func (t *DurableCallbackTransaction) ReadStoryLogState(ctx context.Context, diceID, groupID string) (eventstore.StoryLogState, error) {
	owner, err := t.storyLogOwner(ctx, diceID, groupID)
	if err != nil {
		return eventstore.StoryLogState{}, err
	}
	owner.mu.RLock()
	defer owner.mu.RUnlock()
	return owner.state, nil
}

func (t *DurableCallbackTransaction) SetStoryLogState(ctx context.Context, state eventstore.StoryLogState) error {
	return t.addStoryLogUpdate(ctx, eventstore.NewStoryLogStateUpdate(state))
}

func (t *DurableCallbackTransaction) AddLogUpdate(update eventstore.LogUpdate) error {
	if t == nil {
		return execution.ErrDomainTxUnavailable
	}
	return t.addStoryLogUpdate(t.executionContext, update)
}

func storyLogUpdateOwner(update eventstore.LogUpdate) (string, string) {
	if update.DiceID != "" && update.GroupID != "" {
		return update.DiceID, update.GroupID
	}
	if update.Entry.DiceID != "" && update.Entry.GroupID != "" {
		return update.Entry.DiceID, update.Entry.GroupID
	}
	return update.Intent.Entry.DiceID, update.Intent.Entry.GroupID
}

func (t *DurableCallbackTransaction) addStoryLogUpdate(ctx context.Context, update eventstore.LogUpdate) error {
	if t == nil || t.domain == nil {
		return execution.ErrDomainTxUnavailable
	}
	diceID, groupID := storyLogUpdateOwner(update)
	if diceID == "" || groupID == "" {
		return eventstore.ErrInvalidMetadata
	}
	owner, err := t.storyLogOwner(ctx, diceID, groupID)
	if err != nil {
		return err
	}
	owned := cloneDomainLogUpdate(update)
	return t.domain.Mutate(storyLogParticipantKey(diceID, groupID), func(participant execution.Participant) error {
		current, ok := participant.(*storyLogParticipant)
		if !ok || current != owner {
			return execution.ErrParticipantType
		}
		current.mu.Lock()
		defer current.mu.Unlock()
		if len(current.updates) >= eventstore.MaxUnitOfWorkEvents {
			return eventstore.ErrOversizeInput
		}
		if owned.IsStoryLogStateUpdate() {
			if owned.State.DiceID != diceID || owned.State.GroupID != groupID {
				return eventstore.ErrInvalidMetadata
			}
			current.state = owned.State
		} else if owned.DeletesStoryLogSession() && current.state.Name == owned.Name {
			current.state = eventstore.StoryLogState{DiceID: diceID, GroupID: groupID}
		}
		current.updates = append(current.updates, owned)
		return nil
	})
}

func (t *DurableCallbackTransaction) HasStoryLogStateUpdate(diceID, groupID string) bool {
	if t == nil || t.domain == nil {
		return false
	}
	if t.collector.HasStoryLogStateUpdate(diceID, groupID) {
		return true
	}
	participant, ok := t.domain.LookupOwner(storyLogParticipantKey(diceID, groupID))
	if !ok {
		return false
	}
	owner, ok := participant.(*storyLogParticipant)
	if !ok {
		return false
	}
	owner.mu.RLock()
	defer owner.mu.RUnlock()
	for _, update := range owner.updates {
		if update.IsStoryLogStateUpdate() {
			return true
		}
	}
	return false
}

func cloneDomainLogUpdate(update eventstore.LogUpdate) eventstore.LogUpdate {
	update.Entry = cloneDomainLogEntry(update.Entry)
	update.Intent.Entry = cloneDomainLogEntry(update.Intent.Entry)
	return update
}

func cloneDomainLogEntry(entry eventstore.StoryLogEntry) eventstore.StoryLogEntry {
	entry.CommandInfo = append([]byte(nil), entry.CommandInfo...)
	if entry.Seq != nil {
		value := *entry.Seq
		entry.Seq = &value
	}
	if entry.Removed != nil {
		value := *entry.Removed
		entry.Removed = &value
	}
	if entry.ParentID != nil {
		value := *entry.ParentID
		entry.ParentID = &value
	}
	return entry
}
