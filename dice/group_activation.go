package dice

import (
	"context"
	"encoding/json"
	"errors"

	"Scardice-core/core/groupstate"

	"github.com/google/uuid"
)

// RecordGroupActivation records all requested endpoint toggles in one explicit
// root execution. Missing durable authority is an error, never a no-op.
func (d *Dice) RecordGroupActivation(ctx context.Context, groupID string, diceIDs []string, active bool) error {
	if d == nil || d.DurableStore == nil {
		return errors.New("dice: durable store unavailable")
	}
	if groupID == "" {
		return errors.New("dice: group identity unavailable")
	}
	if len(diceIDs) == 0 {
		return errors.New("dice: no endpoint identities selected")
	}
	request, err := json.Marshal(struct {
		GroupID string   `json:"groupId"`
		DiceIDs []string `json:"diceIds"`
		Active  bool     `json:"active"`
	}{GroupID: groupID, DiceIDs: diceIDs, Active: active})
	if err != nil {
		return err
	}
	identity := d.DomainExecutionIdentity("group-set-active", uuid.NewString())
	return d.WithDomainExecution(ctx, identity, request, func(transaction *DurableCallbackTransaction) error {
		group, loadErr := transaction.Domain().Group(ctx, d.BaseConfig.Name, groupID)
		if loadErr != nil {
			return loadErr
		}
		if group.Version() == 0 {
			return errors.New("dice: group does not exist")
		}
		for _, diceID := range diceIDs {
			if diceID == "" {
				return errors.New("dice: endpoint identity unavailable")
			}
			if decideErr := group.Decide(groupstate.Command{
				Kind: groupstate.CommandActivation, DiceIDForActivation: diceID,
				Active: active, ActiveSet: true,
			}); decideErr != nil {
				return decideErr
			}
		}
		return transaction.Domain().Err()
	})
}
