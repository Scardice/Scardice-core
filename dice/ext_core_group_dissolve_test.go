//nolint:testpackage
package dice

import (
	"testing"

	"Scardice-core/dice/events"
)

func TestGroupSelfDissolveDoesNotBlacklistBot(t *testing.T) {
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	d.Config.BanList.ScoreGroupKicked = 1

	coreExt, ok := d.ExtRegistry.Load("core")
	if !ok || coreExt.OnGroupLeave == nil {
		t.Fatal("core group-leave handler is not registered")
	}
	ctx := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}

	coreExt.OnGroupLeave(ctx, &events.GroupLeaveEvent{
		GroupID:    "QQ-Group:6100",
		UserID:     endpoint.UserID,
		OperatorID: endpoint.UserID,
	})

	if _, exists := d.Config.BanList.GetByID(endpoint.UserID); exists {
		t.Fatal("bot self-dissolve must not create a blacklist entry")
	}
}

func TestGroupExternalDissolveBlacklistsOperator(t *testing.T) {
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	d.Config.BanList.ScoreGroupKicked = 1

	coreExt, ok := d.ExtRegistry.Load("core")
	if !ok || coreExt.OnGroupLeave == nil {
		t.Fatal("core group-leave handler is not registered")
	}
	ctx := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}
	operatorID := "QQ:6200"

	coreExt.OnGroupLeave(ctx, &events.GroupLeaveEvent{
		GroupID:    "QQ-Group:6101",
		UserID:     endpoint.UserID,
		OperatorID: operatorID,
	})

	item, exists := d.Config.BanList.GetByID(operatorID)
	if !exists {
		t.Fatal("external dissolve must retain operator blacklist behavior")
	}
	if item.Score != 1 {
		t.Fatalf("operator score = %d, want 1", item.Score)
	}
}
