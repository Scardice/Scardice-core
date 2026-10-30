package dice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

type bridgeTestSubmitter struct {
	mu       sync.Mutex
	request  messageflow.SubmitRequest
	err      error
	dedup    bool
	effectID string
	onSubmit func(messageflow.SubmitRequest)
}

func (s *bridgeTestSubmitter) Submit(_ context.Context, request messageflow.SubmitRequest) (messageflow.SubmitResult, error) {
	s.mu.Lock()
	s.request = request
	onSubmit := s.onSubmit
	effectID := s.effectID
	err := s.err
	s.mu.Unlock()
	if onSubmit != nil {
		onSubmit(request)
	}
	if err != nil {
		return messageflow.SubmitResult{}, err
	}
	if effectID == "" {
		effectID = string(request.Effect.ID)
	}
	return messageflow.SubmitResult{EffectID: effectID, OperationID: string(request.Effect.OperationID), Deduplicated: s.dedup}, nil
}

func (s *bridgeTestSubmitter) Prepare(_ context.Context, request messageflow.SubmitRequest) (messageflow.PreparedOutbound, error) {
	if s.err != nil {
		return messageflow.PreparedOutbound{}, s.err
	}
	effect := eventstore.NewEffect{EffectID: string(request.Effect.ID), EndpointID: string(request.Effect.EndpointID), LaneHMAC: []byte("lane"), EffectType: "message", RiskClass: eventstore.RiskNonIdempotentAfterDispatch, Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"}
	stream := eventstore.StreamAppend{Stream: eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []eventstore.NewEvent{{EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: eventstore.Metadata{EventID: "event", CommandID: request.CommandID, CorrelationID: string(request.Effect.CorrelationID)}}}}
	operation := eventstore.OperationUpdate{OperationID: string(request.Effect.OperationID), ResourceID: effect.EffectID, IdempotencyScope: "outbound", IdempotencyKey: request.CommandID}
	return messageflow.PreparedOutbound{Work: eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{stream}, Operations: []eventstore.OperationUpdate{operation}, Effects: []eventstore.NewEffect{effect}}, Result: messageflow.SubmitResult{EffectID: effect.EffectID, OperationID: operation.OperationID}}, nil
}

type bridgeTestResolver struct{ snapshot messageflow.EndpointSnapshot }

func (r bridgeTestResolver) Resolve(context.Context, adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	return r.snapshot, nil
}

type bridgeTestIndexSigner struct {
	root []byte
	id   string
}

func (s bridgeTestIndexSigner) KeyedDigest(_ context.Context, domain string, parts ...string) ([]byte, string, error) {
	mac := hmac.New(sha256.New, s.root)
	_, _ = mac.Write([]byte(domain))
	for _, part := range parts {
		_, _ = mac.Write([]byte(part))
	}
	return mac.Sum(nil), s.id, nil
}

func bridgeTestContext(submitter *bridgeTestSubmitter) (*MsgContext, *Message, *mockPlatformAdapter) {
	d := &Dice{Logger: logger.M()}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: "endpoint-1", Platform: "QQ", ProtocolType: "pureonebot", UserID: "QQ:9001", Enable: true, State: StateConnected}}
	adapter := newMockPlatformAdapter()
	ep.Adapter = adapter
	ep.Session = &IMSession{Parent: d}
	d.ImSession = ep.Session
	bridge := NewDurableOutboundBridge(submitter, bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "root-1", IndexSigner: bridgeTestIndexSigner{root: []byte("01234567890123456789012345678901"), id: "root-1"}}}, eventstore.UUIDGenerator{})
	d.OutboundBridge = bridge
	return &MsgContext{Dice: d, EndPoint: ep, Session: ep.Session}, &Message{MessageType: "private", Platform: "QQ", Sender: SenderBase{UserID: "QQ:1001"}}, adapter
}
func bridgePendingNotifications(bridge *DurableOutboundBridge) int {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	return len(bridge.pending)
}

func TestReplyToSenderPureOnebotUsesDurableBridge(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, legacy := bridgeTestContext(submitter)
	ReplyToSender(ctx, msg, "durable hello")
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("legacy adapter called: %#v", legacy)
	}
	if submitter.request.Effect.Payload.Kind != adapterapi.EffectPayloadPersonText || submitter.request.Effect.Payload.Target.Conversation != "QQ:1001" || submitter.request.Effect.Payload.Text != "durable hello" {
		t.Fatalf("request = %#v", submitter.request)
	}
}

func TestReplyToSenderPureOnebotReadViewUsesDurableBridge(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	ctx.EndPoint.Adapter = nil
	ReplyToSender(ctx, msg, "read view hello")
	if submitter.request.Effect.Payload.Text != "read view hello" {
		t.Fatalf("request = %#v", submitter.request)
	}
}

func TestReplyToSenderCallbackStagesPreparedOutbound(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, legacy := bridgeTestContext(submitter)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction := &DurableCallbackTransaction{collector: collector}
	ctx.callbackTransaction = transaction
	ReplyToSender(ctx, msg, "callback hello")
	if submitter.request.Effect.ID != "" {
		t.Fatalf("callback invoked independent submit: %#v", submitter.request)
	}
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("callback invoked legacy adapter: %#v", legacy)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 {
		t.Fatalf("callback outbound work = %#v", work)
	}
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.mu.Lock()
	pendingBeforeCommit := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingBeforeCommit != 0 {
		t.Fatalf("callback notification registered before commit: %d", pendingBeforeCommit)
	}
	if transaction.callbackCommitFence == nil || len(transaction.callbackAfterCommit) != 1 {
		t.Fatalf("callback commit fence=%v after=%d", transaction.callbackCommitFence, len(transaction.callbackAfterCommit))
	}
	if !transaction.callbackCommitFence.TryLock() {
		t.Fatal("callback commit fence is busy")
	}
	transaction.callbackAfterCommit[0]()
	bridge.mu.Lock()
	pendingUnderFence := len(bridge.pending)
	bridge.mu.Unlock()
	transaction.callbackCommitFence.Unlock()
	if pendingUnderFence != 1 {
		t.Fatalf("callback notification missing after commit: %d", pendingUnderFence)
	}
}

func TestReplyToSenderCallbackProxyStagesRollbackSafeCompletion(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, legacy := bridgeTestContext(submitter)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction := &DurableCallbackTransaction{collector: collector}
	ctx.callbackTransaction = transaction
	ctx.callbackMetadata = eventstore.Metadata{
		CommandID: "proxy-callback", CorrelationID: "proxy-callback",
		OccurredAt: time.Unix(1, 0).UTC(),
	}
	ctx.Group = &GroupInfo{GroupID: "QQ-Group:7001", Players: new(SyncMap[string, *GroupPlayerInfo])}
	ctx.Player = &GroupPlayerInfo{UserID: "QQ:1001", Name: "Sender"}
	target := &GroupPlayerInfo{UserID: "QQ:1002", Name: "Target"}
	ctx.Group.Players.Store(target.UserID, target)

	proxy, found := (&AtInfo{UserID: target.UserID}).CopyCtx(ctx)
	if !found || proxy.Player != target {
		t.Fatalf("proxy context player = %#v, found=%t", proxy.Player, found)
	}
	if proxy.callbackTransaction != transaction || proxy.callbackMetadata.CommandID != "proxy-callback" {
		t.Fatal("proxy context dropped durable callback ownership")
	}
	ReplyToSender(proxy, msg, "proxy callback hello")

	if submitter.request.Effect.ID != "" {
		t.Fatalf("proxy callback invoked independent submit: %#v", submitter.request)
	}
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("proxy callback invoked legacy adapter: %#v", legacy)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 {
		t.Fatalf("proxy callback outbound work = %#v", work)
	}
	if transaction.callbackCommitFence == nil || len(transaction.callbackAfterCommit) != 1 {
		t.Fatalf("proxy callback completion fence=%v after=%d", transaction.callbackCommitFence, len(transaction.callbackAfterCommit))
	}
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.mu.Lock()
	pendingBeforeCommit := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingBeforeCommit != 0 {
		t.Fatalf("proxy callback rollback boundary registered notification early: %d", pendingBeforeCommit)
	}
}
func TestReplyToSenderPureOnebotDurableRejectionDoesNotCallLegacy(t *testing.T) {
	submitter := &bridgeTestSubmitter{err: errors.New("rejected")}
	ctx, msg, legacy := bridgeTestContext(submitter)
	ReplyToSender(ctx, msg, "rejected hello")
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("legacy adapter called after rejection: %#v", legacy)
	}
	if ctx.IsCommandReplied() {
		t.Fatal("durable rejection marked command replied")
	}
}

func TestFailClosedOutboundBridgeNeverFallsBackToLegacyAdapter(t *testing.T) {
	ctx, msg, legacy := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.Dice.OutboundBridge = NewFailClosedOutboundBridge()
	ReplyToSender(ctx, msg, "startup window")
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("legacy adapter called in startup window: %#v", legacy)
	}
	if ctx.IsCommandReplied() {
		t.Fatal("rejected startup reply marked command replied")
	}
}

func TestPureOnebotNilBridgeFailsClosedForPersonAndGroup(t *testing.T) {
	ctx, msg, legacy := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.Dice.OutboundBridge = nil

	if accepted := deliverReplyPlan(ctx, msg, "private reply", "", false); accepted {
		t.Fatal("private reply accepted without an outbound bridge")
	}
	msg.MessageType = "group"
	msg.GroupID = "QQ-Group:2001"
	if accepted := deliverReplyPlan(ctx, msg, "group reply", "", true); accepted {
		t.Fatal("group reply accepted without an outbound bridge")
	}

	legacy.mu.Lock()
	personCalls, groupCalls := len(legacy.personMsgs), len(legacy.groupMsgs)
	legacy.mu.Unlock()
	if personCalls != 0 || groupCalls != 0 {
		t.Fatalf("legacy adapter calls = person:%d group:%d, want both 0", personCalls, groupCalls)
	}
}

func TestDurableOutboundBridgeRoutesTextByProviderDescriptor(t *testing.T) {
	tests := []struct {
		name       string
		adapterKey adapterapi.AdapterKey
		platform   string
		group      bool
		message    Message
		want       adapterapi.ConversationID
	}{
		{
			name: "discord private", adapterKey: DiscordAdapterKey, platform: "DISCORD",
			message: Message{MessageType: "private", Platform: "DISCORD", Sender: SenderBase{UserID: "DISCORD:user-1"}},
			want:    "DISCORD:user-1",
		},
		{
			name: "dingtalk group", adapterKey: DingTalkAdapterKey, platform: "DINGTALK", group: true,
			message: Message{MessageType: "group", Platform: "DINGTALK", GroupID: "DINGTALK-Group:group-1", Sender: SenderBase{UserID: "DINGTALK:user-1"}},
			want:    "DINGTALK-Group:group-1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			submitter := &bridgeTestSubmitter{}
			d := &Dice{Logger: logger.M()}
			ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
				ID: "endpoint-1", Platform: test.platform, ProtocolType: string(test.adapterKey),
				UserID: test.platform + ":bot", Enable: true, State: StateConnected,
			}}
			ep.Session = &IMSession{Parent: d}
			d.ImSession = ep.Session
			d.OutboundBridge = NewDurableOutboundBridge(submitter, bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{
				EndpointID: "endpoint-1", AdapterKey: test.adapterKey, DesiredState: "enabled",
				ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound,
				Actions:     adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
				IndexRootID: "root-1", IndexSigner: bridgeTestIndexSigner{
					root: []byte("01234567890123456789012345678901"), id: "root-1",
				},
			}}, eventstore.UUIDGenerator{})
			ctx := &MsgContext{Dice: d, EndPoint: ep, Session: ep.Session}
			if err := d.OutboundBridge.SubmitText(ctx, &test.message, "hello", "", test.group); err != nil {
				t.Fatal(err)
			}
			if got := submitter.request.Effect.Payload.Target.Conversation; got != test.want {
				t.Fatalf("target = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDurableBridgeNotifiesOnlyCommittedSuccess(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	called := make(chan *Message, 1)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, message *Message, _ string) { called <- message }}}
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "hello", "", false); err != nil {
		t.Fatal(err)
	}
	effect := submitter.request.Effect
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.NotifyOutboundEffectSucceeded(context.Background(), effect, adapterapi.SucceededResult("provider-42"))
	select {
	case sent := <-called:
		if sent.RawID != "provider-42" || sent.Message != "hello" || sent.MessageType != "private" || sent.Sender.UserID != ctx.EndPoint.UserID {
			t.Fatalf("sent = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("success hook not called")
	}
}

func TestDurableBridgePostCommitSendHookOwnsOnlyReturnedPromise(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	ctx.Dice.Config.JsEnable = true
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	manager := NewJsLoopManager()
	generation := manager.SetLoop(loop)
	ctx.Dice.ExtLoopManager = manager
	t.Cleanup(func() { manager.SetLoop(nil) })

	ext := &ExtInfo{Name: "post-commit-scope", IsJsExt: true, JSLoopVersion: generation, dice: ctx.Dice}
	ctx.Dice.ExtList = []*ExtInfo{ext}
	started := make(chan struct{})
	type observation struct {
		ctx *MsgContext
		err error
	}
	beforeSettle := make(chan observation, 1)
	floated := make(chan error, 1)
	barrier := make(chan struct{}, 1)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if vm, ok := gojaengine.Raw(runtime); ok {
			vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
		}
		if err := runtime.Bind("extension", ext); err != nil {
			return err
		}
		if err := runtime.Bind("hookStarted", func() { close(started) }); err != nil {
			return err
		}
		if err := runtime.Bind("beforeSettle", func(hookCtx *MsgContext) {
			beforeSettle <- observation{ctx: hookCtx, err: hookCtx.checkExecution()}
		}); err != nil {
			return err
		}
		if err := runtime.Bind("floated", func(hookCtx *MsgContext) {
			floated <- hookCtx.checkExecution()
		}); err != nil {
			return err
		}
		if err := runtime.Bind("barrier", func() { barrier <- struct{}{} }); err != nil {
			return err
		}
		_, err := runtime.RunString("post-commit-send-hook.js", `
extension.onMessageSend = async function (hookCtx) {
  hookStarted();
  await new Promise(function (resolve) { globalThis.resolvePostCommitHook = resolve; });
  beforeSettle(hookCtx);
  setTimeout(function () { floated(hookCtx); }, 0);
};`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "hello", "", false); err != nil {
		t.Fatal(err)
	}
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.NotifyOutboundEffectSucceeded(context.Background(), submitter.request.Effect, adapterapi.SucceededResult("provider-owned-scope"))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("post-commit send hook did not start")
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolve-post-commit-send-hook.js", "resolvePostCommitHook()")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var hook observation
	select {
	case hook = <-beforeSettle:
		if hook.err != nil {
			t.Fatalf("returned send-hook Promise lost its scope before settlement: %v", hook.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("returned send-hook Promise did not resume")
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for !hook.ctx.executionReleased.Load() {
		select {
		case <-deadline.C:
			t.Fatal("post-commit hook scope was not released after returned Promise settlement")
		default:
			runtime.Gosched()
		}
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("post-commit-barrier.js", "setTimeout(barrier, 0)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-barrier:
	case <-time.After(2 * time.Second):
		t.Fatal("post-commit timer barrier did not run")
	}
	select {
	case err := <-floated:
		if err == nil {
			t.Fatal("floated continuation retained authority after returned Promise settled")
		}
	default:
		// Fail-closed providers reject the stale timer before entering its body.
	}
}

func TestDurableBridgeConcurrentTerminalNotificationFencesReconciliation(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	const canonicalEffectID = "canonical-effect-id"
	started := make(chan struct{})
	allowReturn := make(chan struct{})
	releaseSubmit := sync.OnceFunc(func() { close(allowReturn) })
	defer releaseSubmit()
	submitter.effectID = canonicalEffectID
	submitter.onSubmit = func(request messageflow.SubmitRequest) {
		go func() {
			close(started)
			effect := request.Effect
			effect.ID = adapterapi.EffectID(canonicalEffectID)
			bridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.SucceededResult("provider-race"))
		}()
		<-allowReturn
	}
	var callbackCount atomic.Int32
	callback := make(chan *Message, 2)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, sent *Message, _ string) {
		callbackCount.Add(1)
		callback <- sent
	}}}

	submitDone := make(chan error, 1)
	go func() {
		submitDone <- bridge.SubmitText(ctx, msg, "race", "", false)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("terminal notification did not start during Submit")
	}
	select {
	case sent := <-callback:
		t.Fatalf("success callback ran before Submit committed: %#v", sent)
	case <-time.After(50 * time.Millisecond):
	}
	releaseSubmit()
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
		if sent.RawID != "provider-race" || sent.Message != "race" {
			t.Fatalf("callback message = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal success callback not delivered")
	}
	if pending := bridgePendingNotifications(bridge); pending != 0 {
		t.Fatalf("pending notifications = %d", pending)
	}
	bridge.NotifyOutboundEffectResult(context.Background(), adapterapi.OutboundEffect{ID: canonicalEffectID}, adapterapi.SucceededResult("provider-duplicate"))
	select {
	case duplicate := <-callback:
		t.Fatalf("duplicate terminal result delivered another callback: %#v", duplicate)
	case <-time.After(50 * time.Millisecond):
	}
	if got := callbackCount.Load(); got != 1 {
		t.Fatalf("success callback count = %d, want 1", got)
	}
}

func TestDurableBridgeSuccessNotificationPreservesGroupTarget(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	msg.MessageType, msg.GroupID = "group", "QQ-Group:7001"
	called := make(chan *Message, 1)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, message *Message, _ string) { called <- message }}}
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "group hello", "", true); err != nil {
		t.Fatal(err)
	}
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.NotifyOutboundEffectSucceeded(context.Background(), submitter.request.Effect, adapterapi.SucceededResult("provider-43"))
	select {
	case sent := <-called:
		if sent.MessageType != "group" || sent.GroupID != "QQ-Group:7001" || sent.RawID != "provider-43" {
			t.Fatalf("sent = %#v", sent)
		}
	case <-time.After(time.Second):
		t.Fatal("success hook not called")
	}
}

func TestDurableBridgeNonSuccessOutcomesDropNotification(t *testing.T) {
	tests := []struct {
		name   string
		result adapterapi.EffectResult
		reject bool
	}{
		{name: "terminal", result: adapterapi.TerminalResult("provider-terminal", "rejected by provider")},
		{name: "unsupported", result: adapterapi.UnsupportedResult("missing-capability")},
		{name: "ambiguous", result: adapterapi.AmbiguousResult("timeout-after-send", "delivery unknown")},
		{name: "submit rejected", reject: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			submitter := &bridgeTestSubmitter{}
			if test.reject {
				submitter.err = errors.New("durable acceptance rejected")
			}
			ctx, msg, _ := bridgeTestContext(submitter)
			bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
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
				if pending := bridgePendingNotifications(bridge); pending != 1 {
					t.Fatalf("pending before terminal result = %d, want 1", pending)
				}
				bridge.NotifyOutboundEffectResult(context.Background(), submitter.request.Effect, test.result)
			}
			if pending := bridgePendingNotifications(bridge); pending != 0 {
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

func TestDurableBridgeDeduplicatedReplayWithoutPendingDoesNotLeak(t *testing.T) {
	submitter := &bridgeTestSubmitter{dedup: true}
	ctx, msg, _ := bridgeTestContext(submitter)
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "replayed", "", false); err != nil {
		t.Fatal(err)
	}
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.mu.Lock()
	pending := len(bridge.pending)
	bridge.mu.Unlock()
	if pending != 0 {
		t.Fatalf("deduplicated replay created pending notification: %d", pending)
	}
}
func TestDurableBridgeMessageHookPanicDoesNotStopDispatch(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	var callbackCount atomic.Int32
	firstStarted := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
		current := callbackCount.Add(1)
		if current == 1 {
			close(firstStarted)
			defer close(firstDone)
			panic("message hook panic")
		}
		close(secondDone)
	}}}
	if err := bridge.SubmitText(ctx, msg, "panic-isolated-1", "", false); err != nil {
		t.Fatal(err)
	}
	firstEffect := submitter.request.Effect
	bridge.NotifyOutboundEffectResult(context.Background(), firstEffect, adapterapi.SucceededResult("provider-panic-1"))
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
	bridge.NotifyOutboundEffectResult(context.Background(), secondEffect, adapterapi.SucceededResult("provider-panic-2"))
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("callback dispatch stopped after panic")
	}
	if got := callbackCount.Load(); got != 2 {
		t.Fatalf("callback count = %d, want 2", got)
	}
}

func TestFreshDurableBridgeIgnoresPriorTerminalResult(t *testing.T) {
	firstSubmitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(firstSubmitter)
	firstBridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	var firstCallbacks atomic.Int32
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) { firstCallbacks.Add(1) }}}
	if err := firstBridge.SubmitText(ctx, msg, "already terminal", "", false); err != nil {
		t.Fatal(err)
	}
	effect := firstSubmitter.request.Effect
	firstBridge.NotifyOutboundEffectResult(context.Background(), effect, adapterapi.TerminalResult("durable-terminal", "already completed"))
	if pending := bridgePendingNotifications(firstBridge); pending != 0 {
		t.Fatalf("old bridge pending notifications = %d", pending)
	}

	freshSubmitter := &bridgeTestSubmitter{}
	freshCtx, _, _ := bridgeTestContext(freshSubmitter)
	freshBridge := freshCtx.Dice.OutboundBridge.(*DurableOutboundBridge)
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
	if pending := bridgePendingNotifications(freshBridge); pending != 0 {
		t.Fatalf("fresh bridge pending notifications = %d", pending)
	}
}

func TestDurableBridgeActionArtifactNeverInvokesMessageHook(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, _, _ := bridgeTestContext(submitter)
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	called := make(chan struct{}, 1)
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) { called <- struct{}{} }}}
	payload := adapterapi.EffectPayload{
		Kind:            adapterapi.EffectPayloadBan,
		Target:          adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:7001", Member: "QQ:1001"},
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
	result := adapterapi.SucceededResult("provider-action")
	result.Artifact = &artifact
	bridge.NotifyOutboundEffectResult(context.Background(), effect, result)
	select {
	case <-called:
		t.Fatal("action artifact result reached OnMessageSend")
	case <-time.After(50 * time.Millisecond):
	}
	if pending := bridgePendingNotifications(bridge); pending != 0 {
		t.Fatalf("action pending notifications = %d, want 0", pending)
	}
}

func TestMemberBanRejectsDurationOverflow(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, _, _ := bridgeTestContext(submitter)
	MemberBan(ctx, "QQ-Group:7001", "QQ:1001", int64(^uint32(0))+1)
	submitter.mu.Lock()
	requested := submitter.request.Effect.ID != ""
	submitter.mu.Unlock()
	if requested {
		t.Fatal("duration overflow submitted an invalid ban effect")
	}
}

func configureBridgeForManagementActions(ctx *MsgContext) {
	ctx.EndPoint.Platform = "DISCORD"
	ctx.EndPoint.ProtocolType = "discord"
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.resolver = bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "endpoint-1", AdapterKey: "discord", DesiredState: "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions: adapterapi.ActionSet(0).
			With(adapterapi.ActionKindBan, adapterapi.ActionKindKick, adapterapi.ActionKindQuit),
		IndexRootID: "root-1",
		IndexSigner: bridgeTestIndexSigner{root: []byte("01234567890123456789012345678901"), id: "root-1"},
	}}
}

func TestManagementActionsUseDurableBridgeForEveryProvider(t *testing.T) {
	tests := []struct {
		name string
		run  func(*MsgContext) error
		kind adapterapi.EffectPayloadKind
	}{
		{name: "ban", run: func(ctx *MsgContext) error {
			MemberBan(ctx, "group-1", "user-1", 60)
			return nil
		}, kind: adapterapi.EffectPayloadBan},
		{name: "kick", run: func(ctx *MsgContext) error {
			MemberKick(ctx, "group-1", "user-1")
			return nil
		}, kind: adapterapi.EffectPayloadKick},
		{name: "quit", run: func(ctx *MsgContext) error {
			return QuitGroup(ctx, "group-1")
		}, kind: adapterapi.EffectPayloadQuit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			submitter := &bridgeTestSubmitter{}
			ctx, _, legacy := bridgeTestContext(submitter)
			configureBridgeForManagementActions(ctx)
			if err := test.run(ctx); err != nil {
				t.Fatalf("management action error: %v", err)
			}
			submitter.mu.Lock()
			request := submitter.request
			submitter.mu.Unlock()
			if request.Effect.Payload.Kind != test.kind {
				t.Fatalf("effect payload = %#v", request.Effect.Payload)
			}
			if len(legacy.bans) != 0 || len(legacy.kicks) != 0 || len(legacy.quitGroups) != 0 {
				t.Fatalf("legacy adapter was called: bans=%v kicks=%v quits=%v", legacy.bans, legacy.kicks, legacy.quitGroups)
			}
		})
	}
}

func TestQuitGroupDelegatesLegacyAdapterWithoutBridge(t *testing.T) {
	ctx, _, legacy := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.Dice.OutboundBridge = nil
	ctx.EndPoint.ProtocolType = "gocq"

	if err := QuitGroup(ctx, "QQ-Group:7002"); err != nil {
		t.Fatalf("legacy QuitGroup error: %v", err)
	}
	if len(legacy.quitGroups) != 1 || legacy.quitGroups[0] != "QQ-Group:7002" {
		t.Fatalf("legacy quit groups = %#v, want one provider call", legacy.quitGroups)
	}
}

func TestFileSendRejectsDurableAndPureOnebotPathsWithoutFallback(t *testing.T) {
	for _, test := range []struct {
		name                string
		withBridge          bool
		callbackTransaction bool
	}{
		{name: "durable bridge", withBridge: true},
		{name: "pure OneBot without bridge"},
		{name: "durable callback transaction", callbackTransaction: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, msg, legacy := bridgeTestContext(&bridgeTestSubmitter{})
			if !test.withBridge {
				ctx.Dice.OutboundBridge = nil
			}
			if test.callbackTransaction {
				ctx.EndPoint.ProtocolType = "gocq"
				ctx.callbackTransaction = &DurableCallbackTransaction{}
			}

			personResult, personErr := SendFileToPersonRaw(ctx, msg, "/synthetic/private.txt", "")
			groupResult, groupErr := SendFileToGroupRaw(ctx, &Message{MessageType: "group", GroupID: "QQ-Group:1001"}, "/synthetic/group.txt", "")
			if personErr == nil || groupErr == nil {
				t.Fatalf("file-send errors = person %v, group %v; both safety boundaries must reject", personErr, groupErr)
			}
			if personResult.Outcome != adapterapi.EffectUnsupported || groupResult.Outcome != adapterapi.EffectUnsupported {
				t.Fatalf("file-send outcomes = person %v, group %v; both safety boundaries must report unsupported", personResult.Outcome, groupResult.Outcome)
			}
			if len(legacy.files) != 0 {
				t.Fatalf("provider file paths reached legacy adapter: %v", legacy.files)
			}
		})
	}
}

func TestFileSendDelegatesLegacyNoBridgeToProvider(t *testing.T) {
	ctx, _, legacy := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.Dice.OutboundBridge = nil
	ctx.EndPoint.ProtocolType = "gocq"

	personMsg := &Message{MessageType: "private", Sender: SenderBase{UserID: "QQ:1001"}}
	groupMsg := &Message{MessageType: "group", GroupID: "QQ-Group:1001"}
	personResult, err := SendFileToPersonRaw(ctx, personMsg, "/synthetic/private.txt", "")
	if err != nil {
		t.Fatalf("SendFileToPersonRaw error = %v", err)
	}
	groupResult, err := SendFileToGroupRaw(ctx, groupMsg, "/synthetic/group.txt", "")
	if err != nil {
		t.Fatalf("SendFileToGroupRaw error = %v", err)
	}
	if personResult.Outcome != adapterapi.EffectAmbiguous || groupResult.Outcome != adapterapi.EffectAmbiguous {
		t.Fatalf("legacy mock outcomes = person %v, group %v; void mock dispatch must remain unconfirmed", personResult.Outcome, groupResult.Outcome)
	}
	if len(legacy.files) != 2 || legacy.files[0] != "/synthetic/private.txt" || legacy.files[1] != "/synthetic/group.txt" {
		t.Fatalf("legacy adapter file paths = %v, want both synthetic paths in call order", legacy.files)
	}
}

func TestFileSendReturnsClearErrorWithoutLegacyAdapter(t *testing.T) {
	ctx, msg, _ := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.Dice.OutboundBridge = nil
	ctx.EndPoint.ProtocolType = "gocq"
	ctx.EndPoint.Adapter = nil

	_, err := SendFileToPersonRaw(ctx, msg, "/synthetic/private.txt", "")
	if err == nil || err.Error() != "文件发送适配器不可用" {
		t.Fatalf("SendFileToPersonRaw error = %v, want clear missing-adapter error", err)
	}
}
