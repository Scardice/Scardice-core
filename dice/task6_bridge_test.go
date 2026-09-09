package dice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
)

type task6BridgeIDs struct {
	mu     sync.Mutex
	values []string
	next   int
}

func (g *task6BridgeIDs) NewID() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.next >= len(g.values) {
		return "", errors.New("task6 bridge ID sequence exhausted")
	}
	id := g.values[g.next]
	g.next++
	return id, nil
}

func task6BridgeContext(submitter *bridgeTestSubmitter, ids ...string) (*MsgContext, *Message, *DurableOutboundBridge) {
	ctx, msg, _ := bridgeTestContext(submitter)
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.ids = &task6BridgeIDs{values: append([]string(nil), ids...)}
	bridge.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	return ctx, msg, bridge
}

func task6BridgePending(bridge *DurableOutboundBridge) int {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	return len(bridge.pending)
}

func TestTask6DurableBridgeSuccessCallbackWaitsForSubmitCommit(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, bridge := task6BridgeContext(submitter, "effect-task6-commit", "operation-task6-commit")
	callback := make(chan *Message, 1)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, sent *Message, _ string) { callback <- sent }}}

	started := make(chan struct{})
	allowReturn := make(chan struct{})
	submitter.onSubmit = func(request messageflow.SubmitRequest) {
		close(started)
		effect := request.Effect
		go bridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.SucceededResult("provider-task6-commit"))
		<-allowReturn
	}
	submitDone := make(chan error, 1)
	go func() { submitDone <- bridge.SubmitText(ctx, msg, "committed", "", false) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("submit did not reach provider acceptance hook")
	}
	select {
	case <-callback:
		t.Fatal("success callback ran before Submit committed")
	default:
	}
	close(allowReturn)
	select {
	case err := <-submitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Submit did not return")
	}
	select {
	case sent := <-callback:
		if sent.Message != "committed" || sent.RawID != "provider-task6-commit" {
			t.Fatalf("callback message = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("committed success callback was not delivered")
	}
}

func TestTask6DurableBridgeNonSuccessOutcomesNeverNotify(t *testing.T) {
	tests := []struct {
		name   string
		result adapterapi.EffectResult
		reject bool
	}{
		{name: "terminal", result: adapterapi.TerminalResult("provider-terminal", "rejected by provider")},
		{name: "unsupported", result: adapterapi.UnsupportedResult("missing-capability")},
		{name: "ambiguous", result: adapterapi.AmbiguousResult("timeout-after-send", "delivery unknown")},
		{name: "rejected", reject: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			submitter := &bridgeTestSubmitter{}
			if test.reject {
				submitter.err = errors.New("durable acceptance rejected")
			}
			ctx, msg, bridge := task6BridgeContext(submitter, "effect-task6-"+test.name, "operation-task6-"+test.name)
			var callbackCount atomic.Int32
			called := make(chan struct{}, 1)
			ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
				callbackCount.Add(1)
				called <- struct{}{}
			}}}
			err := bridge.SubmitText(ctx, msg, "must-not-notify", "", false)
			if test.reject {
				if err == nil {
					t.Fatal("rejected durable acceptance returned nil")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if pending := task6BridgePending(bridge); pending != 1 {
					t.Fatalf("pending before terminal result = %d, want 1", pending)
				}
				bridge.NotifyOutboundEffectResult(context.Background(), submitter.request.Effect, test.result)
			}
			if pending := task6BridgePending(bridge); pending != 0 {
				t.Fatalf("pending after %s = %d, want 0", test.name, pending)
			}
			select {
			case <-called:
				t.Fatal("non-success outcome invoked OnMessageSend")
			case <-time.After(50 * time.Millisecond):
			}
			if got := callbackCount.Load(); got != 0 {
				t.Fatalf("OnMessageSend calls = %d, want 0", got)
			}
		})
	}
}

func TestTask6DurableBridgeDuplicateTerminalResultNotifiesOnce(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, bridge := task6BridgeContext(submitter, "effect-task6-duplicate", "operation-task6-duplicate")
	var callbackCount atomic.Int32
	called := make(chan *Message, 2)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, sent *Message, _ string) {
		callbackCount.Add(1)
		called <- sent
	}}}
	if err := bridge.SubmitText(ctx, msg, "exactly once", "", false); err != nil {
		t.Fatal(err)
	}
	effect := submitter.request.Effect
	bridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.SucceededResult("provider-task6-first"))
	bridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.SucceededResult("provider-task6-duplicate"))
	select {
	case sent := <-called:
		if sent.RawID != "provider-task6-first" {
			t.Fatalf("duplicate callback replaced first result: %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("success callback was not delivered")
	}
	select {
	case <-called:
		t.Fatal("duplicate terminal result invoked callback twice")
	case <-time.After(50 * time.Millisecond):
	}
	if got := callbackCount.Load(); got != 1 {
		t.Fatalf("callback count = %d, want 1", got)
	}
}

func TestTask6DurableBridgeCallbackPanicIsolated(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, bridge := task6BridgeContext(submitter,
		"effect-task6-panic-1", "operation-task6-panic-1",
		"effect-task6-panic-2", "operation-task6-panic-2")
	var callbackCount atomic.Int32
	firstStarted := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
		current := callbackCount.Add(1)
		if current == 1 {
			close(firstStarted)
			defer close(firstDone)
			panic("task6 callback panic")
		}
		close(secondDone)
	}}}
	if err := bridge.SubmitText(ctx, msg, "panic-isolated-1", "", false); err != nil {
		t.Fatal(err)
	}
	firstEffect := submitter.request.Effect
	bridge.NotifyOutboundEffectResult(context.Background(), firstEffect, adapterapi.SucceededResult("provider-task6-panic-1"))
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first callback did not start")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("panic callback did not unwind")
	}
	if err := bridge.SubmitText(ctx, msg, "panic-isolated-2", "", false); err != nil {
		t.Fatal(err)
	}
	secondEffect := submitter.request.Effect
	bridge.NotifyOutboundEffectResult(context.Background(), secondEffect, adapterapi.SucceededResult("provider-task6-panic-2"))
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("callback dispatch stopped after panic")
	}
	if got := callbackCount.Load(); got != 2 {
		t.Fatalf("callback count = %d, want 2", got)
	}
}

func TestTask6FreshBridgeDoesNotNotifyDurableTerminalResult(t *testing.T) {
	firstSubmitter := &bridgeTestSubmitter{}
	ctx, msg, firstBridge := task6BridgeContext(firstSubmitter, "effect-task6-restart", "operation-task6-restart")
	var firstCallbacks atomic.Int32
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) { firstCallbacks.Add(1) }}}
	if err := firstBridge.SubmitText(ctx, msg, "already terminal", "", false); err != nil {
		t.Fatal(err)
	}
	effect := firstSubmitter.request.Effect
	firstBridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.TerminalResult("durable-terminal", "already completed"))
	if pending := task6BridgePending(firstBridge); pending != 0 {
		t.Fatalf("old bridge pending notifications = %d", pending)
	}

	freshSubmitter := &bridgeTestSubmitter{}
	freshCtx, _, freshBridge := task6BridgeContext(freshSubmitter, "unused-effect", "unused-operation")
	var freshCallbacks atomic.Int32
	freshCalled := make(chan struct{}, 1)
	freshCtx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
		freshCallbacks.Add(1)
		freshCalled <- struct{}{}
	}}}
	freshBridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.TerminalResult("durable-terminal", "already completed"))
	select {
	case <-freshCalled:
		t.Fatal("fresh bridge synthesized notification for durable terminal result")
	case <-time.After(50 * time.Millisecond):
	}
	if firstCallbacks.Load() != 0 || freshCallbacks.Load() != 0 {
		t.Fatalf("terminal callback counts = old:%d fresh:%d", firstCallbacks.Load(), freshCallbacks.Load())
	}
	if pending := task6BridgePending(freshBridge); pending != 0 {
		t.Fatalf("fresh bridge pending notifications = %d", pending)
	}
}

func TestTask6DurableBridgeActionArtifactResultNeverReachesOnMessageSend(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, _, bridge := task6BridgeContext(submitter, "effect-task6-action", "operation-task6-action")
	called := make(chan struct{}, 1)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) { called <- struct{}{} }}}
	payload := adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadBan,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:7001", Member: "QQ:1001"},
		DurationSeconds: 60,
	}
	if err := bridge.SubmitAction(ctx, payload); err != nil {
		t.Fatal(err)
	}
	effect := submitter.request.Effect
	if effect.Kind != adapterapi.EffectKindAction || effect.Payload.Kind != adapterapi.EffectPayloadBan {
		t.Fatalf("submitted action effect = %#v", effect)
	}
	artifact := adapterapi.NewArtifactResult("image/png", "provider-proof.png", []byte("secret-provider-artifact"))
	result := adapterapi.SucceededResult("provider-task6-action")
	result.Artifact = &artifact
	bridge.NotifyOutboundEffectResult(context.Background(), effect, result)
	select {
	case <-called:
		t.Fatal("action artifact result reached OnMessageSend")
	case <-time.After(50 * time.Millisecond):
	}
	if pending := task6BridgePending(bridge); pending != 0 {
		t.Fatalf("action pending notifications = %d, want 0", pending)
	}
}
