package dice

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

// This test owner uses the production owner's admission/cancel/join contract.
// In particular, a completed Notify call does not imply its hook has stopped.
type bridgeTestNotificationOwner struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	accepting bool
	wg        sync.WaitGroup
	stopOnce  sync.Once
	done      chan struct{}
}

var _ OutboundNotificationOwner = (*bridgeTestNotificationOwner)(nil)

func newBridgeTestNotificationOwner(t *testing.T) *bridgeTestNotificationOwner {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	owner := &bridgeTestNotificationOwner{ctx: ctx, cancel: cancel, accepting: true, done: make(chan struct{})}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		if err := owner.shutdown(stopCtx); err != nil {
			t.Errorf("join outbound completion owner: %v", err)
		}
	})
	return owner
}

func (owner *bridgeTestNotificationOwner) Go(run func(context.Context)) bool {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.accepting || run == nil {
		return false
	}
	owner.wg.Add(1)
	go func() {
		defer owner.wg.Done()
		run(owner.ctx)
	}()
	return true
}

func (owner *bridgeTestNotificationOwner) beginShutdown() {
	owner.stopOnce.Do(func() {
		owner.mu.Lock()
		owner.accepting = false
		owner.cancel()
		owner.mu.Unlock()
		go func() {
			owner.wg.Wait()
			close(owner.done)
		}()
	})
}

func (owner *bridgeTestNotificationOwner) shutdown(ctx context.Context) error {
	owner.beginShutdown()
	select {
	case <-owner.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDurableBridgeCompletionOwnerCancelsAndJoinsInFlightHook(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	messageCtx, message, _ := canonicalBridgeTestContext(t, submitter)
	bridge := messageCtx.Dice.OutboundBridge.(*DurableOutboundBridge)
	owner := newBridgeTestNotificationOwner(t)
	bridge.notifications = owner

	started := make(chan context.Context, 1)
	canceled := make(chan struct{})
	exited := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHook := func() { releaseOnce.Do(func() { close(release) }) }
	messageCtx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(hookCtx *MsgContext, _ *Message, _ string) {
		defer close(exited)
		started <- hookCtx.executionContext
		select {
		case <-hookCtx.executionContext.Done():
			close(canceled)
		case <-release:
		}
		<-release
	}}}
	if err := bridge.SubmitText(messageCtx, message, "owned-completion", "", false); err != nil {
		t.Fatal(err)
	}
	effect := submitter.request.Effect
	identity := messageCtx.Dice.DomainExecutionIdentity("outbound-provider-completion", string(effect.ID))
	t.Cleanup(func() {
		releaseHook()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			t.Error("completion hook did not exit during cleanup")
			return
		}
		// Also join the durable root, so an incorrectly detached completion
		// cannot race the fixture's store cleanup after an assertion fails.
		awaitBridgeCompletionTerminal(t, messageCtx.Dice, identity)
	})

	bridge.NotifyOutboundEffectResult(t.Context(), effect, adapterapi.SucceededResult("provider-owned-lifetime"))
	var hookContext context.Context
	select {
	case hookContext = <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("completion hook did not start")
	}
	if deadline, ok := hookContext.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
		t.Error("completion hook has no finite notification deadline")
	}
	owner.beginShutdown()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Error("owner shutdown did not cancel the in-flight completion context")
	}
	select {
	case <-owner.done:
		t.Error("owner joined before its admitted hook returned")
	default:
	}
	releaseHook()
	stopCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := owner.shutdown(stopCtx); err != nil {
		t.Fatalf("completion did not join after its hook returned: %v", err)
	}
	receipt := awaitBridgeCompletionTerminal(t, messageCtx.Dice, identity)
	if receipt.Status != eventstore.ExecutionStatusAmbiguous {
		t.Fatalf("canceled completion status = %q, want ambiguous", receipt.Status)
	}
}

func TestDurableBridgeStoppedCompletionOwnerRejectsNewHooks(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	messageCtx, message, _ := canonicalBridgeTestContext(t, submitter)
	bridge := messageCtx.Dice.OutboundBridge.(*DurableOutboundBridge)
	owner := newBridgeTestNotificationOwner(t)
	bridge.notifications = owner
	called := make(chan struct{}, 1)
	messageCtx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
		called <- struct{}{}
	}}}
	if err := bridge.SubmitText(messageCtx, message, "completion-after-shutdown", "", false); err != nil {
		t.Fatal(err)
	}
	stopCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := owner.shutdown(stopCtx); err != nil {
		t.Fatal(err)
	}
	effect := submitter.request.Effect
	bridge.NotifyOutboundEffectResult(t.Context(), effect, adapterapi.SucceededResult("provider-after-shutdown"))
	if pending := bridgePendingNotifications(bridge); pending != 0 {
		t.Fatalf("stopped owner retained %d completed notifications", pending)
	}
	select {
	case <-called:
		t.Fatal("completion hook started after its owner stopped")
	case <-time.After(50 * time.Millisecond):
	}
	identity := messageCtx.Dice.DomainExecutionIdentity("outbound-provider-completion", string(effect.ID))
	repository := messageCtx.Dice.DurableStore.(eventstore.ExecutionReceiptRepository)
	if receipt, err := repository.LookupExecution(t.Context(), identity); err != nil || receipt.Status != eventstore.ExecutionStatusUnknown || receipt.Admitted {
		t.Fatalf("stopped owner admitted a completion root: receipt=%#v err=%v", receipt, err)
	}
}

func awaitBridgeCompletionTerminal(t *testing.T, d *Dice, identity string) eventstore.ExecutionReceipt {
	t.Helper()
	repository := d.DurableStore.(eventstore.ExecutionReceiptRepository)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		receipt, err := repository.LookupExecution(context.Background(), identity)
		if err == nil && receipt.Status != eventstore.ExecutionStatusStarted {
			return receipt
		}
		if err != nil && !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatalf("lookup completion receipt: %v", err)
		}
		select {
		case <-deadline.C:
			t.Fatalf("completion root %q did not terminate: receipt=%#v err=%v", identity, receipt, err)
		case <-ticker.C:
		}
	}
}
