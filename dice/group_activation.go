package dice

import (
	"context"
	"time"

	"Scardice-core/core/groupstate"
	"Scardice-core/eventstore"
)

// RecordGroupActivation records that the given dice accounts are switched on
// or off in a group. Durable callbacks rebuild the group from recorded state
// for every message, so a change made only to the in-memory group would be
// undone by the next one. Accounts already in the requested state and groups
// with no recorded state are left alone; without an event store this does
// nothing.
func (d *Dice) RecordGroupActivation(ctx context.Context, groupID string, diceIDs []string, active bool) error {
	if d == nil || d.DurableStore == nil {
		return nil
	}
	repository := groupstate.NewRepository(d.DurableStore)
	state, err := repository.Load(ctx, d.BaseConfig.Name, groupID)
	if err != nil || state.Version == 0 {
		return err
	}
	for _, diceID := range diceIDs {
		if diceID == "" || state.DiceIDActive[diceID] == active {
			continue
		}
		commandID, err := (eventstore.UUIDGenerator{}).NewID()
		if err != nil {
			return err
		}
		metadata := eventstore.Metadata{CommandID: commandID, CorrelationID: commandID, Producer: "dice/group-set-active", OccurredAt: time.Now().UTC()}
		if _, err := repository.DecideAndAppend(ctx, state, state.Version, metadata, groupstate.Command{
			Kind: groupstate.CommandActivation, DiceIDForActivation: diceID, Active: active, Exists: state.DiceIDExists[diceID],
		}); err != nil {
			return err
		}
		if state, err = repository.Load(ctx, d.BaseConfig.Name, groupID); err != nil {
			return err
		}
	}
	return nil
}
