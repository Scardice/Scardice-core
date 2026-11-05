package dice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/core/execution"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

const (
	moderationDetailsEndpoint = "moderation-details"
	moderationDetailsAdapter  = "moderation"
)

type moderationEventStore interface {
	eventstore.ProjectionDependencyRepository
	eventstore.Store
	ListStreamHeads(ctx context.Context, namespace string) ([]eventstore.StreamHead, error)
	ListProjectionRows(ctx context.Context, namespace string) ([]eventstore.ProjectionRow, error)
	ResolveSecret(ctx context.Context, reference string, version uint64) (eventstore.SecretResolution, error)
	PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
}

type moderationDetails struct {
	BanListInfoItem
	BanUpdatedAt int64 `json:"banUpdatedAt"`
}

type moderationBanRepository struct {
	store  moderationEventStore
	states *playerstate.Repository
	diceID string
}

func newModerationBanRepository(d *Dice) (*moderationBanRepository, error) {
	if d == nil || d.DurableStore == nil || d.BaseConfig.Name == "" {
		return nil, errors.New("dice: EventStore moderation identity is unavailable")
	}
	store, ok := d.DurableStore.(moderationEventStore)
	if !ok {
		return nil, errors.New("dice: EventStore does not support moderation details")
	}
	return &moderationBanRepository{
		store:  store,
		states: playerstate.NewRepository(store),
		diceID: d.BaseConfig.Name,
	}, nil
}

func moderationDetailsSecretRef(diceID, subjectID string) (string, error) {
	stream := playerstate.ModerationStream(diceID, "global", subjectID)
	if stream.AggregateID == "" {
		return "", playerstate.ErrInvalidIdentity
	}
	return "vault:moderation-details:" + stream.AggregateID, nil
}

func (r *moderationBanRepository) load(ctx context.Context) (map[string]*BanListInfoItem, error) {
	if r == nil || r.store == nil {
		return nil, errors.New("dice: EventStore moderation repository is unavailable")
	}
	heads, err := r.store.ListStreamHeads(ctx, playerstate.ModerationAggregateType)
	if err != nil {
		return nil, fmt.Errorf("dice: list moderation streams: %w", err)
	}
	prefix := playerstate.ModerationStreamPrefix(r.diceID, "global").Prefix
	expectedVersions := make(map[string]uint64)
	for _, head := range heads {
		if strings.HasPrefix(head.Stream.AggregateID, prefix) {
			expectedVersions[head.Stream.AggregateID] = head.Version
		}
	}
	rows, err := r.store.ListProjectionRows(ctx, playerstate.ModerationProjectionName)
	if err != nil {
		return nil, fmt.Errorf("dice: list moderation projections: %w", err)
	}
	loaded := make(map[string]*BanListInfoItem)
	for _, row := range rows {
		if !strings.HasPrefix(row.RowKey, prefix) {
			continue
		}
		var state playerstate.ModerationState
		if err := json.Unmarshal(row.Payload, &state); err != nil {
			return nil, fmt.Errorf("dice: decode moderation projection %q: %w", row.RowKey, err)
		}
		stream := playerstate.ModerationStream(state.DiceID, state.GroupID, state.SubjectID)
		if state.Version == 0 || stream.AggregateID == "" || stream.AggregateID != row.RowKey ||
			state.DiceID != r.diceID || state.GroupID != "global" {
			return nil, fmt.Errorf("dice: invalid moderation projection identity %q", row.RowKey)
		}
		expectedVersion, exists := expectedVersions[row.RowKey]
		if !exists || expectedVersion != state.Version {
			return nil, fmt.Errorf("dice: moderation projection version mismatch for %q", state.SubjectID)
		}
		envelopes, err := r.store.Load(ctx, stream, 1)
		if err != nil {
			return nil, fmt.Errorf("dice: load moderation events for %q: %w", state.SubjectID, err)
		}
		var replayed playerstate.ModerationState
		for _, envelope := range envelopes {
			replayed, err = playerstate.ApplyModerationEnvelope(replayed, envelope, stream)
			if err != nil {
				return nil, fmt.Errorf("dice: replay moderation events for %q: %w", state.SubjectID, err)
			}
		}
		if len(envelopes) == 0 || replayed != state {
			return nil, fmt.Errorf("dice: moderation projection does not match stream %q", row.RowKey)
		}
		delete(expectedVersions, row.RowKey)
		if state.Deleted {
			continue
		}
		ref, err := moderationDetailsSecretRef(state.DiceID, state.SubjectID)
		if err != nil {
			return nil, err
		}
		secret, err := r.store.ResolveSecret(ctx, ref, 0)
		if errors.Is(err, eventstore.ErrNotFound) {
			return nil, fmt.Errorf("dice: moderation history is missing for %q", state.SubjectID)
		}
		if err != nil {
			return nil, fmt.Errorf("dice: resolve moderation history for %q: %w", state.SubjectID, err)
		}
		var details moderationDetails
		if secret.SecretVersion == 0 || json.Unmarshal(secret.Value, &details) != nil {
			return nil, fmt.Errorf("dice: invalid moderation history for %q", state.SubjectID)
		}
		item, itemErr := details.item(state)
		if itemErr != nil {
			return nil, itemErr
		}
		loaded[item.ID] = item
	}
	if len(expectedVersions) != 0 {
		return nil, fmt.Errorf("dice: %d moderation streams have no projection row", len(expectedVersions))
	}
	return loaded, nil
}

// item rebuilds the public ban item from the projected state plus its persisted
// history. The two stores must agree on rank and score: the projection row is
// not independently verifiable per read, so divergence fails closed.
func (details moderationDetails) item(state playerstate.ModerationState) (*BanListInfoItem, error) {
	if details.ID != "" && details.ID != state.SubjectID {
		return nil, fmt.Errorf("dice: moderation history identity mismatch for %q", state.SubjectID)
	}
	if details.Rank != BanRankType(state.Rank) || details.Score != state.Score {
		return nil, fmt.Errorf("dice: moderation projection differs from history for %q", state.SubjectID)
	}
	item := cloneBanListItem(&details.BanListInfoItem)
	item.ID = state.SubjectID
	item.BanUpdatedAt = details.BanUpdatedAt
	item.EventStoreVersion = state.Version
	return item, nil
}
func (r *moderationBanRepository) listSubjectIDs(ctx context.Context) ([]string, error) {
	if r == nil || r.store == nil {
		return nil, errors.New("dice: EventStore moderation repository is unavailable")
	}
	heads, err := r.store.ListStreamHeads(ctx, playerstate.ModerationAggregateType)
	if err != nil {
		return nil, fmt.Errorf("dice: list moderation streams: %w", err)
	}
	prefix := playerstate.ModerationStreamPrefix(r.diceID, "global").Prefix
	expectedVersions := make(map[string]uint64)
	for _, head := range heads {
		if strings.HasPrefix(head.Stream.AggregateID, prefix) {
			expectedVersions[head.Stream.AggregateID] = head.Version
		}
	}
	rows, err := r.store.ListProjectionRows(ctx, playerstate.ModerationProjectionName)
	if err != nil {
		return nil, fmt.Errorf("dice: list moderation projections: %w", err)
	}
	subjectIDs := make([]string, 0, len(expectedVersions))
	for _, row := range rows {
		if !strings.HasPrefix(row.RowKey, prefix) {
			continue
		}
		var state playerstate.ModerationState
		if err = json.Unmarshal(row.Payload, &state); err != nil {
			return nil, fmt.Errorf("dice: decode moderation projection %q: %w", row.RowKey, err)
		}
		stream := playerstate.ModerationStream(state.DiceID, state.GroupID, state.SubjectID)
		expectedVersion, exists := expectedVersions[row.RowKey]
		if !exists || state.Version == 0 || stream.AggregateID == "" || stream.AggregateID != row.RowKey ||
			state.DiceID != r.diceID || state.GroupID != "global" || expectedVersion != state.Version {
			return nil, fmt.Errorf("dice: invalid moderation projection identity %q", row.RowKey)
		}
		delete(expectedVersions, row.RowKey)
		if !state.Deleted {
			subjectIDs = append(subjectIDs, state.SubjectID)
		}
	}
	if len(expectedVersions) != 0 {
		return nil, errors.New("dice: moderation projection is missing stream heads")
	}
	return subjectIDs, nil
}

func (r *moderationBanRepository) loadItem(ctx context.Context, subjectID string) (*BanListInfoItem, bool, error) {
	if r == nil || r.store == nil || strings.TrimSpace(subjectID) == "" {
		return nil, false, errors.New("dice: invalid moderation item lookup")
	}
	stream := playerstate.ModerationStream(r.diceID, "global", subjectID)
	snapshot, err := r.store.ReadProjectionDependency(ctx, playerstate.ModerationProjectionName, stream.AggregateID, stream)
	if err != nil {
		return nil, false, err
	}
	if !snapshot.Found {
		if snapshot.StreamVersion != 0 {
			return nil, false, execution.ErrDomainSnapshotChanged
		}
		return nil, false, nil
	}
	var state playerstate.ModerationState
	if err = json.Unmarshal(snapshot.Row.Payload, &state); err != nil {
		return nil, false, err
	}
	if state.DiceID != r.diceID || state.GroupID != "global" || state.SubjectID != subjectID ||
		state.Version != snapshot.StreamVersion {
		return nil, false, execution.ErrDomainSnapshotChanged
	}
	if state.Deleted {
		return nil, false, nil
	}
	ref, err := moderationDetailsSecretRef(r.diceID, subjectID)
	if err != nil {
		return nil, false, err
	}
	secret, err := r.store.ResolveSecret(ctx, ref, 0)
	if err != nil {
		return nil, false, fmt.Errorf("dice: resolve moderation history for %q: %w", subjectID, err)
	}
	var details moderationDetails
	if err = json.Unmarshal(secret.Value, &details); err != nil {
		return nil, false, fmt.Errorf("dice: decode moderation history for %q: %w", subjectID, err)
	}
	item, err := details.item(state)
	if err != nil {
		return nil, false, err
	}
	return item, true, nil
}

type moderationParticipant struct {
	store         moderationEventStore
	diceID        string
	subjectID     string
	base          playerstate.ModerationState
	item          *BanListInfoItem
	baseDetails   []byte
	secretRef     string
	secretVersion uint64
	deleted       bool
	dirty         bool
	metadata      eventstore.Metadata
}

func moderationDetailsPayload(item *BanListInfoItem) ([]byte, error) {
	if item == nil {
		return nil, errors.New("dice: moderation details are nil")
	}
	detached := cloneBanListItem(item)
	detached.EventStoreVersion = 0
	return json.Marshal(moderationDetails{
		BanListInfoItem: *detached,
		BanUpdatedAt:    detached.BanUpdatedAt,
	})
}

func (p *moderationParticipant) Contribute(ctx context.Context) (eventstore.UnitOfWork, error) {
	if p == nil || !p.dirty {
		return eventstore.UnitOfWork{}, nil
	}
	if p.deleted {
		if p.base.Version == 0 || p.base.Deleted {
			return eventstore.UnitOfWork{}, nil
		}
		event, err := playerstate.NewEventWithFactory(
			eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}},
			playerstate.NewModerationDeletedV1(),
			p.metadata,
		)
		if err != nil {
			return eventstore.UnitOfWork{}, err
		}
		return eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
			Stream:          playerstate.ModerationStream(p.diceID, "global", p.subjectID),
			ExpectedVersion: p.base.Version,
			Events:          []eventstore.NewEvent{event},
		}}}, nil
	}
	if p.item == nil || p.item.ID != p.subjectID {
		return eventstore.UnitOfWork{}, errors.New("dice: invalid moderation participant item")
	}
	detailsBytes, err := moderationDetailsPayload(p.item)
	if err != nil {
		return eventstore.UnitOfWork{}, fmt.Errorf("dice: encode moderation history for %q: %w", p.subjectID, err)
	}
	historyBytes, err := json.Marshal(struct {
		Times   []int64  `json:"times"`
		Reasons []string `json:"reasons"`
		Places  []string `json:"places"`
	}{p.item.Times, p.item.Reasons, p.item.Places})
	if err != nil {
		return eventstore.UnitOfWork{}, fmt.Errorf("dice: encode moderation history digest for %q: %w", p.subjectID, err)
	}
	digest := eventstore.DigestBytes("moderation-history/v1", historyBytes)
	events := make([]playerstate.ModerationEvent, 0, 3)
	switch {
	case p.base.Version == 0:
		events = append(events, playerstate.NewModerationCreatedV1(p.diceID, "global", p.subjectID, int(p.item.Rank), p.item.Score))
	case p.base.Deleted:
		events = append(events, playerstate.NewModerationRestoredV1(int(p.item.Rank), p.item.Score))
	case p.base.Rank != int(p.item.Rank):
		events = append(events, playerstate.NewModerationRankChangedV1(int(p.item.Rank)))
	}
	digestHex := hex.EncodeToString(digest)
	if p.base.Version == 0 || p.base.Deleted || p.base.Score != p.item.Score || p.base.ReasonDigest != digestHex {
		events = append(events, playerstate.NewModerationScoreChangedV1(p.item.Score, digestHex))
	}
	detailsChanged := !bytes.Equal(p.baseDetails, detailsBytes)
	if len(events) == 0 && !detailsChanged {
		return eventstore.UnitOfWork{}, nil
	}
	factory := eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}
	metadata := p.metadata
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for _, typed := range events {
		event, encodeErr := playerstate.NewEventWithFactory(factory, typed, metadata)
		if encodeErr != nil {
			return eventstore.UnitOfWork{}, encodeErr
		}
		encoded = append(encoded, event)
		metadata.EventID = ""
	}
	work := eventstore.UnitOfWork{}
	if len(encoded) != 0 {
		work.Streams = []eventstore.StreamAppend{{
			Stream:          playerstate.ModerationStream(p.diceID, "global", p.subjectID),
			ExpectedVersion: p.base.Version,
			Events:          encoded,
		}}
	}
	if detailsChanged {
		update, prepareErr := p.store.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{
			SecretRef:       p.secretRef,
			EndpointID:      moderationDetailsEndpoint,
			AdapterID:       moderationDetailsAdapter,
			ExpectedVersion: p.secretVersion,
			SecretVersion:   p.secretVersion + 1,
			Value:           detailsBytes,
		})
		if prepareErr != nil {
			return eventstore.UnitOfWork{}, fmt.Errorf("dice: prepare moderation history for %q: %w", p.subjectID, prepareErr)
		}
		work.SecretUpdates = []eventstore.SecretUpdate{update}
	}
	return work, nil
}

func (d *Dice) moderationOwner(
	ctx context.Context,
	tx *execution.DomainTx,
	subjectID string,
) (*moderationParticipant, execution.ParticipantKey, error) {
	if d == nil || d.DurableStore == nil || tx == nil || d.BaseConfig.Name == "" || strings.TrimSpace(subjectID) == "" {
		return nil, execution.ParticipantKey{}, execution.ErrDomainTxUnavailable
	}
	repository, err := newModerationBanRepository(d)
	if err != nil {
		return nil, execution.ParticipantKey{}, err
	}
	reader, ok := d.DurableStore.(eventstore.ProjectionDependencyRepository)
	if !ok {
		return nil, execution.ParticipantKey{}, errors.New("dice: moderation projection dependency reader is unavailable")
	}
	stream := playerstate.ModerationStream(repository.diceID, "global", subjectID)
	if stream.AggregateID == "" {
		return nil, execution.ParticipantKey{}, playerstate.ErrInvalidIdentity
	}
	key := execution.StreamParticipantKey(stream)
	participant, err := tx.Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		snapshot, readErr := reader.ReadProjectionDependency(loadCtx, playerstate.ModerationProjectionName, stream.AggregateID, stream)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		var state playerstate.ModerationState
		if snapshot.Found {
			if readErr = json.Unmarshal(snapshot.Row.Payload, &state); readErr != nil {
				return nil, execution.ReadDependencies{}, readErr
			}
			if state.DiceID != repository.diceID || state.GroupID != "global" || state.SubjectID != subjectID ||
				state.Version != snapshot.StreamVersion {
				return nil, execution.ReadDependencies{}, execution.ErrDomainSnapshotChanged
			}
		} else if snapshot.StreamVersion != 0 {
			return nil, execution.ReadDependencies{}, execution.ErrDomainSnapshotChanged
		}
		secretRef, readErr := moderationDetailsSecretRef(repository.diceID, subjectID)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		installed := &moderationParticipant{
			store:     repository.store,
			diceID:    repository.diceID,
			subjectID: subjectID,
			base:      state,
			secretRef: secretRef,
			deleted:   state.Deleted,
		}
		if state.Version != 0 {
			secret, secretErr := repository.store.ResolveSecret(loadCtx, secretRef, 0)
			if secretErr == nil {
				var details moderationDetails
				if jsonErr := json.Unmarshal(secret.Value, &details); jsonErr != nil {
					return nil, execution.ReadDependencies{}, fmt.Errorf("dice: decode moderation history for %q: %w", subjectID, jsonErr)
				}
				installed.baseDetails = append([]byte(nil), secret.Value...)
				installed.secretVersion = secret.SecretVersion
				if state.Deleted {
					// Deleted history is only a restore baseline; its live rank and
					// score are no longer projected.
					details.Rank = BanRankType(state.Rank)
					details.Score = state.Score
				}
				item, itemErr := details.item(state)
				if itemErr != nil {
					return nil, execution.ReadDependencies{}, itemErr
				}
				installed.item = item
			} else if !state.Deleted || !errors.Is(secretErr, eventstore.ErrNotFound) {
				return nil, execution.ReadDependencies{}, fmt.Errorf("dice: resolve moderation history for %q: %w", subjectID, secretErr)
			}
		}
		if installed.item == nil {
			installed.item = &BanListInfoItem{
				ID:                subjectID,
				Rank:              BanRankType(state.Rank),
				Score:             state.Score,
				EventStoreVersion: state.Version,
			}
		}
		return installed, execution.ReadDependenciesFromStream(eventstore.StreamSnapshot{
			Stream: stream, Version: snapshot.StreamVersion, Snapshot: snapshot.Snapshot,
		}), nil
	})
	if err != nil {
		return nil, execution.ParticipantKey{}, err
	}
	typed, ok := participant.(*moderationParticipant)
	if !ok {
		return nil, execution.ParticipantKey{}, execution.ErrInvalidParticipant
	}
	return typed, key, nil
}

type moderationOverlayParticipant struct {
	subjects map[string]bool
}

func (*moderationOverlayParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	return eventstore.UnitOfWork{}, nil
}

func (d *Dice) moderationOverlayKey() execution.ParticipantKey {
	return execution.ParticipantKey{Kind: "moderation-overlay", ID: d.BaseConfig.Name}
}

func (d *Dice) moderationOverlayOwner(
	ctx context.Context,
	tx *execution.DomainTx,
) (*moderationOverlayParticipant, execution.ParticipantKey, error) {
	if d == nil || tx == nil || d.BaseConfig.Name == "" {
		return nil, execution.ParticipantKey{}, execution.ErrDomainTxUnavailable
	}
	key := d.moderationOverlayKey()
	participant, err := tx.Owner(ctx, key, func(context.Context) (execution.Participant, execution.ReadDependencies, error) {
		return &moderationOverlayParticipant{subjects: make(map[string]bool)}, execution.ReadDependencies{}, nil
	})
	if err != nil {
		return nil, execution.ParticipantKey{}, err
	}
	overlay, ok := participant.(*moderationOverlayParticipant)
	if !ok {
		return nil, execution.ParticipantKey{}, execution.ErrInvalidParticipant
	}
	return overlay, key, nil
}

func (d *Dice) moderationOverlaySnapshot(tx *execution.DomainTx) (map[string]bool, error) {
	if d == nil || tx == nil {
		return nil, execution.ErrDomainTxUnavailable
	}
	key := d.moderationOverlayKey()
	if _, exists := tx.LookupOwner(key); !exists {
		// No moderation writes means a successful empty overlay, not a missing item.
		return map[string]bool{}, nil
	}
	var snapshot map[string]bool
	err := tx.Mutate(key, func(participant execution.Participant) error {
		overlay, ok := participant.(*moderationOverlayParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		snapshot = make(map[string]bool, len(overlay.subjects))
		for subjectID, exists := range overlay.subjects {
			snapshot[subjectID] = exists
		}
		return nil
	})
	return snapshot, err
}

func (d *Dice) ModerationItemForDomain(
	ctx context.Context,
	tx *execution.DomainTx,
	subjectID string,
) (*BanListInfoItem, bool, error) {
	participant, _, err := d.moderationOwner(ctx, tx, subjectID)
	if err != nil {
		return nil, false, err
	}
	if participant.deleted || (participant.base.Version == 0 && !participant.dirty) {
		return nil, false, nil
	}
	return cloneBanListItem(participant.item), true, nil
}

func (d *Dice) ContributeModerationMutation(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	subjectID string,
	mutate func(item *BanListInfoItem, exists bool) error,
) error {
	if mutate == nil {
		return execution.ErrInvalidParticipant
	}
	_, key, err := d.moderationOwner(ctx, tx, subjectID)
	if err != nil {
		return err
	}
	_, overlayKey, err := d.moderationOverlayOwner(ctx, tx)
	if err != nil {
		return err
	}
	if err = tx.Mutate(key, func(owner execution.Participant) error {
		typed, ok := owner.(*moderationParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		exists := !typed.deleted && (typed.base.Version != 0 || typed.dirty)
		working := cloneBanListItem(typed.item)
		if !exists {
			working = &BanListInfoItem{ID: subjectID}
		}
		if mutateErr := mutate(working, exists); mutateErr != nil {
			return mutateErr
		}
		if working.ID == "" {
			working.ID = subjectID
		}
		if working.ID != subjectID {
			return playerstate.ErrInvalidIdentity
		}
		typed.item = cloneBanListItem(working)
		typed.deleted = false
		typed.dirty = true
		if typed.metadata.CommandID == "" {
			typed.metadata = metadata
		}
		return nil
	}); err != nil {
		return err
	}
	return tx.Mutate(overlayKey, func(participant execution.Participant) error {
		overlay, ok := participant.(*moderationOverlayParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		overlay.subjects[subjectID] = true
		return nil
	})
}

func (d *Dice) ContributeModerationDelete(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	subjectID string,
) error {
	_, key, err := d.moderationOwner(ctx, tx, subjectID)
	if err != nil {
		return err
	}
	_, overlayKey, err := d.moderationOverlayOwner(ctx, tx)
	if err != nil {
		return err
	}
	if err = tx.Mutate(key, func(owner execution.Participant) error {
		typed, ok := owner.(*moderationParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		typed.deleted = true
		typed.dirty = true
		if typed.metadata.CommandID == "" {
			typed.metadata = metadata
		}
		return nil
	}); err != nil {
		return err
	}
	return tx.Mutate(overlayKey, func(participant execution.Participant) error {
		overlay, ok := participant.(*moderationOverlayParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		overlay.subjects[subjectID] = false
		return nil
	})
}
