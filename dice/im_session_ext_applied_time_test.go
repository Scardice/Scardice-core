package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/core/groupstate"
)

func TestActivatedExtensionsRemainResolvableAcrossRootsWhenExtUpdateTimeZero(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	extension := &ExtInfo{Name: "core"}
	installCanonicalTestExtensions(d, extension)
	endpoint := newCanonicalTestEndpoint(d, "QQ:ext-applied-bot")
	message := newGroupMsg("QQ-Group:ext-applied", "QQ:ext-applied-user", "")
	withCanonicalTestMessageContext(
		t, d, endpoint, message, "ext-applied-enable",
		func(ctx *MsgContext) error {
			if err := ctx.Group.SetExtension(extension.Name, true); err != nil {
				return err
			}
			got := ctx.Group.GetActivatedExtList(d)
			if len(got) != 1 || got[0] != extension {
				t.Fatalf("enabling root extensions = %#v", got)
			}
			return nil
		},
	)
	withCanonicalTestMessageContext(
		t, d, endpoint, message, "ext-applied-read",
		func(ctx *MsgContext) error {
			first := ctx.Group.GetActivatedExtList(d)
			second := ctx.Group.GetActivatedExtList(d)
			if len(first) != 1 || len(second) != 1 || first[0] != extension || second[0] != extension {
				t.Fatalf("later root extensions = %#v then %#v", first, second)
			}
			return nil
		},
	)
}

func TestAbortedRootDoesNotPublishSpeculativeExtensionCache(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	extension := &ExtInfo{Name: "speculative"}
	installCanonicalTestExtensions(d, extension)
	callCtx := context.Background()
	const groupID = "QQ-Group:extension-cache-isolation"

	withCanonicalTestRoot(t, d, "extension-cache-seed", func(transaction *DurableCallbackTransaction) error {
		handle, err := transaction.Domain().Group(callCtx, d.BaseConfig.Name, groupID)
		if err != nil {
			return err
		}
		return handle.Decide(groupstate.Command{
			Kind: groupstate.CommandCreate, DiceID: d.BaseConfig.Name,
			GroupID: groupID, GroupName: "committed",
		})
	})

	abortErr := errors.New("abort speculative extension state")
	err := d.WithDomainExecution(
		callCtx,
		d.DomainExecutionIdentity("test-fixture", "extension-cache-abort"),
		[]byte("extension-cache-abort"),
		func(transaction *DurableCallbackTransaction) error {
			messageContext := &MsgContext{
				Dice: d, Session: d.ImSession, callbackTransaction: transaction,
			}
			group, resolveErr := messageContext.ResolveGroup(callCtx, groupID)
			if resolveErr != nil {
				return resolveErr
			}
			if setErr := group.SetExtension(extension.Name, true); setErr != nil {
				return setErr
			}
			if got := group.GetActivatedExtList(d); len(got) != 1 || got[0] != extension {
				t.Fatalf("speculative extension list = %#v", got)
			}
			return abortErr
		},
	)
	if !errors.Is(err, abortErr) {
		t.Fatalf("aborted root error = %v", err)
	}

	withCanonicalTestRoot(t, d, "extension-cache-after-abort", func(transaction *DurableCallbackTransaction) error {
		messageContext := &MsgContext{
			Dice: d, Session: d.ImSession, callbackTransaction: transaction,
		}
		group, resolveErr := messageContext.ResolveGroup(callCtx, groupID)
		if resolveErr != nil {
			return resolveErr
		}
		if setErr := group.SetGroupName("committed-after-abort"); setErr != nil {
			return setErr
		}
		if got := group.GetActivatedExtList(d); len(got) != 0 {
			t.Fatalf("later root observed speculative extensions: %#v", got)
		}
		return nil
	})
}
