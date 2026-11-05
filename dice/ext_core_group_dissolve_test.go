//nolint:testpackage
package dice

import (
	"testing"

	"Scardice-core/dice/events"
)

func TestGroupSelfDissolveDoesNotBlacklistBot(t *testing.T) {
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.BanList.ScoreGroupKicked = 1 })

	coreExt, ok := d.ExtRegistry.Load("core")
	if !ok || coreExt.OnGroupLeave == nil {
		t.Fatal("core group-leave handler is not registered")
	}
	msg := &Message{MessageType: "group", GroupID: "QQ-Group:6100", Platform: "QQ", Sender: SenderBase{UserID: endpoint.UserID}}
	withCanonicalTestMessageContext(t, d, endpoint, msg, "self-dissolve", func(ctx *MsgContext) error {
		coreExt.OnGroupLeave(ctx, &events.GroupLeaveEvent{
			GroupID: msg.GroupID, UserID: endpoint.UserID, OperatorID: endpoint.UserID,
		})
		return ctx.getExecutionError()
	})

	if _, exists := d.Config().BanList.GetByID(endpoint.UserID); exists {
		t.Fatal("bot self-dissolve must not create a blacklist entry")
	}
}

func TestGroupExternalDissolveBlacklistsOperator(t *testing.T) {
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.BanList.ScoreGroupKicked = 1 })

	coreExt, ok := d.ExtRegistry.Load("core")
	if !ok || coreExt.OnGroupLeave == nil {
		t.Fatal("core group-leave handler is not registered")
	}
	operatorID := "QQ:6200"

	msg := &Message{MessageType: "group", GroupID: "QQ-Group:6101", Platform: "QQ", Sender: SenderBase{UserID: operatorID}}
	withCanonicalTestMessageContext(t, d, endpoint, msg, "external-dissolve", func(ctx *MsgContext) error {
		coreExt.OnGroupLeave(ctx, &events.GroupLeaveEvent{
			GroupID: msg.GroupID, UserID: endpoint.UserID, OperatorID: operatorID,
		})
		return ctx.getExecutionError()
	})

	item, exists := d.Config().BanList.GetByID(operatorID)
	if !exists {
		t.Fatal("external dissolve must retain operator blacklist behavior")
	}
	if item.Score != 1 {
		t.Fatalf("operator score = %d, want 1", item.Score)
	}
}
