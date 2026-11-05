package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/core/groupstate"
)

func TestFacadeEqualValueSetterStillRequiresRuntimeAuthority(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:revoked-bot")
	ctx := newCanonicalTestMessageContext(
		t, d, endpoint,
		newGroupMsg("QQ-Group:revoked", "QQ:revoked-user", "message"),
		"revoked-equal-setter",
	)
	d.ImSession.InvalidateGroupRuntime(ctx.Group.GroupID())

	if err := ctx.Group.SetSystem(ctx.Group.System()); !errors.Is(err, ErrGroupRuntimeRevoked) {
		t.Fatalf("equal group setter error = %v, want %v", err, ErrGroupRuntimeRevoked)
	}
	if err := ctx.Player.SetName(ctx.Player.Name()); !errors.Is(err, ErrGroupRuntimeRevoked) {
		t.Fatalf("equal player setter error = %v, want %v", err, ErrGroupRuntimeRevoked)
	}
}

func TestGroupFacadeWorkingStateIsIsolatedPerRootTransaction(t *testing.T) {
	d, _ := newDomainExecutionFixture(t)
	d.ImSession = &IMSession{Parent: d}
	callCtx := context.Background()
	const groupID = "QQ-Group:facade-isolation"

	if err := d.WithDomainExecution(callCtx, "facade-isolation-seed", []byte("seed"), func(transaction *DurableCallbackTransaction) error {
		handle, loadErr := transaction.Domain().Group(callCtx, d.BaseConfig.Name, groupID)
		if loadErr != nil {
			return loadErr
		}
		return handle.Decide(groupstate.Command{
			Kind: groupstate.CommandCreate, DiceID: d.BaseConfig.Name,
			GroupID: groupID, GroupName: "committed",
		})
	}); err != nil {
		t.Fatal(err)
	}

	abortErr := errors.New("abort isolated root")
	var abortedFacade *GroupInfo
	err := d.WithDomainExecution(callCtx, "facade-isolation-abort", []byte("abort"), func(transaction *DurableCallbackTransaction) error {
		messageContext := &MsgContext{
			Dice: d, Session: d.ImSession, callbackTransaction: transaction,
		}
		group, resolveErr := messageContext.ResolveGroup(callCtx, groupID)
		if resolveErr != nil {
			return resolveErr
		}
		abortedFacade = group
		if setErr := group.SetGroupName("uncommitted"); setErr != nil {
			return setErr
		}
		if got := group.GroupName(); got != "uncommitted" {
			t.Fatalf("aborted root working name = %q", got)
		}
		return abortErr
	})
	if !errors.Is(err, abortErr) {
		t.Fatalf("aborted root error = %v", err)
	}

	if err = d.WithDomainExecution(callCtx, "facade-isolation-read", []byte("read"), func(transaction *DurableCallbackTransaction) error {
		messageContext := &MsgContext{
			Dice: d, Session: d.ImSession, callbackTransaction: transaction,
		}
		group, resolveErr := messageContext.ResolveGroup(callCtx, groupID)
		if resolveErr != nil {
			return resolveErr
		}
		if group == abortedFacade {
			t.Fatal("a later root reused the prior root's facade")
		}
		if got := group.GroupName(); got != "committed" {
			t.Fatalf("later root observed aborted working state %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
