package dice

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

type bridgeTestSubmitter struct {
	mu        sync.Mutex
	request   messageflow.SubmitRequest
	err       error
	dedup     bool
	effectID  string
	onSubmit  func(messageflow.SubmitRequest)
	preparer  durableOutboundPreparer
	submitted int
	prepared  int
}

func (s *bridgeTestSubmitter) Submit(_ context.Context, request messageflow.SubmitRequest) (messageflow.SubmitResult, error) {
	s.mu.Lock()
	s.submitted++
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

func (s *bridgeTestSubmitter) Prepare(ctx context.Context, request messageflow.SubmitRequest) (messageflow.PreparedOutbound, error) {
	s.mu.Lock()
	s.request = request
	s.prepared++
	err := s.err
	preparer := s.preparer
	s.mu.Unlock()
	if err != nil {
		return messageflow.PreparedOutbound{}, err
	}
	if preparer != nil {
		return preparer.Prepare(ctx, request)
	}
	effect := eventstore.NewEffect{EffectID: string(request.Effect.ID), EndpointID: string(request.Effect.EndpointID), Lane: "lane", EffectType: "message", RiskClass: eventstore.RiskNonIdempotentAfterDispatch, Status: eventstore.OutboxStatusPending, Payload: []byte("{}")}
	stream := eventstore.StreamAppend{Stream: eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []eventstore.NewEvent{{EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: eventstore.Metadata{EventID: "event", CommandID: request.CommandID, CorrelationID: string(request.Effect.CorrelationID)}}}}
	operation := eventstore.OperationUpdate{OperationID: string(request.Effect.OperationID), ResourceID: effect.EffectID, IdempotencyScope: "outbound", IdempotencyKey: request.CommandID}
	return messageflow.PreparedOutbound{Work: eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{stream}, Operations: []eventstore.OperationUpdate{operation}, Effects: []eventstore.NewEffect{effect}}, Result: messageflow.SubmitResult{EffectID: effect.EffectID, OperationID: operation.OperationID}}, nil
}

type bridgeTestResolver struct{ snapshot messageflow.EndpointSnapshot }

func (r bridgeTestResolver) Resolve(context.Context, adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	return r.snapshot, nil
}

func bridgeTestContext(t *testing.T, submitter *bridgeTestSubmitter) (*MsgContext, *Message, *mockPlatformAdapter) {
	t.Helper()
	d := &Dice{Logger: logger.M()}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: "endpoint-1", Platform: "QQ", ProtocolType: "pureonebot", UserID: "QQ:9001", Enable: true, State: StateConnected}}
	adapter := newMockPlatformAdapter()
	ep.Adapter = adapter
	ep.Session = &IMSession{Parent: d}
	d.ImSession = ep.Session
	bridge := NewDurableOutboundBridge(submitter, bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)}}, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
	d.OutboundBridge = bridge
	return &MsgContext{Dice: d, EndPoint: ep, Session: ep.Session}, &Message{MessageType: "private", Platform: "QQ", Sender: SenderBase{UserID: "QQ:1001"}}, adapter
}

func canonicalBridgeTestContext(t *testing.T, submitter *bridgeTestSubmitter) (*MsgContext, *Message, *mockPlatformAdapter) {
	t.Helper()
	d, store := newCanonicalTestDice(t)
	ep := newCanonicalTestEndpoint(d, "QQ:9001")
	ep.ID = "endpoint-1"
	ep.Platform = "QQ"
	ep.ProtocolType = "pureonebot"
	ep.State = StateConnected
	adapter := newMockPlatformAdapter()
	ep.Adapter = adapter
	resolver := bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "endpoint-1", AdapterKey: PureOnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	submitter.preparer = outbound
	bridge := NewDurableOutboundBridge(submitter, resolver, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
	d.OutboundBridge = bridge
	return &MsgContext{Dice: d, EndPoint: ep, Session: d.ImSession}, &Message{
		MessageType: "private", Platform: "QQ", Sender: SenderBase{UserID: "QQ:1001"},
	}, adapter
}
func bridgePendingNotifications(bridge *DurableOutboundBridge) int {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	return len(bridge.pending)
}

func TestReplyToSenderPureOnebotUsesDurableBridge(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, legacy := bridgeTestContext(t, submitter)
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
	ctx, msg, _ := bridgeTestContext(t, submitter)
	ctx.EndPoint.Adapter = nil
	ReplyToSender(ctx, msg, "read view hello")
	if submitter.request.Effect.Payload.Text != "read view hello" {
		t.Fatalf("request = %#v", submitter.request)
	}
}

func TestReplyToSenderCallbackStagesPreparedOutbound(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, legacy := canonicalBridgeTestContext(t, submitter)
	root := newCanonicalTestRoot(t, ctx.Dice, "callback-outbound-stage")
	transaction := root.Transaction
	ctx.callbackTransaction = transaction
	ctx.callbackMetadata = root.Metadata
	ctx.executionContext = root.Context
	ReplyToSender(ctx, msg, "callback hello")
	if submitter.submitted != 0 || submitter.prepared != 1 {
		t.Fatalf("callback submission paths = submit:%d prepare:%d", submitter.submitted, submitter.prepared)
	}
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("callback invoked legacy adapter: %#v", legacy)
	}
	work, err := root.Collector.UnitOfWork()
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
	if transaction.callbackCommitFence == nil || len(transaction.callbackPublication) != 1 || len(transaction.callbackAfterCommit) != 0 {
		t.Fatalf("callback commit fence=%v publication=%d after=%d", transaction.callbackCommitFence, len(transaction.callbackPublication), len(transaction.callbackAfterCommit))
	}
	if !transaction.callbackCommitFence.TryLock() {
		t.Fatal("callback commit fence is busy")
	}
	transaction.callbackPublication[0]()
	bridge.mu.Lock()
	pendingUnderFence := len(bridge.pending)
	bridge.mu.Unlock()
	transaction.callbackCommitFence.Unlock()
	if pendingUnderFence != 1 {
		t.Fatalf("callback notification missing during committed publication: %d", pendingUnderFence)
	}
}

func TestReplyToSenderCallbackProxyStagesRollbackSafeCompletion(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	base, _, legacy := canonicalBridgeTestContext(t, submitter)
	msg := &Message{MessageType: "group", GroupID: "QQ-Group:7001", Sender: SenderBase{UserID: "QQ:1001", Nickname: "Sender"}}
	ctx := newCanonicalTestMessageContext(t, base.Dice, base.EndPoint, msg, "proxy-callback-outbound")
	transaction := ctx.callbackTransaction
	ctx.callbackMetadata = eventstore.Metadata{
		CommandID: "proxy-callback", CorrelationID: "proxy-callback",
		OccurredAt: time.Unix(1, 0).UTC(),
	}
	target, err := ctx.ResolvePlayer(ctx.domainContext(), ctx.Group.GroupID(), "QQ:1002")
	if err != nil {
		t.Fatal(err)
	}
	if target.Version() == 0 {
		if err = target.create(ctx.Dice.BaseConfig.Name, ctx.Group.GroupID(), "QQ:1002", "Target"); err != nil {
			t.Fatal(err)
		}
	}

	proxy, found := (&AtInfo{UserID: target.UserID()}).CopyCtx(ctx)
	if !found || proxy.Player != target {
		t.Fatalf("proxy context player = %#v, found=%t", proxy.Player, found)
	}
	if proxy.callbackTransaction != transaction || proxy.callbackMetadata.CommandID != "proxy-callback" {
		t.Fatal("proxy context dropped durable callback ownership")
	}
	// Group creation may register unrelated runtime-cache publications; only
	// the outbound reply must not add its own generic AfterCommit hook.
	afterCommitBeforeReply := len(transaction.callbackAfterCommit)
	ReplyToSender(proxy, msg, "proxy callback hello")

	if submitter.submitted != 0 || submitter.prepared != 1 {
		t.Fatalf("proxy callback submission paths = submit:%d prepare:%d", submitter.submitted, submitter.prepared)
	}
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("proxy callback invoked legacy adapter: %#v", legacy)
	}
	work, err := transaction.collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 1 || len(work.Effects) != 1 {
		t.Fatalf("proxy callback outbound participants = operations:%d effects:%d", len(work.Operations), len(work.Effects))
	}
	if transaction.callbackCommitFence == nil || len(transaction.callbackPublication) != 1 || len(transaction.callbackAfterCommit) != afterCommitBeforeReply {
		t.Fatalf("proxy callback completion fence=%v publication=%d after=%d (before reply: %d)", transaction.callbackCommitFence, len(transaction.callbackPublication), len(transaction.callbackAfterCommit), afterCommitBeforeReply)
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
	ctx, msg, legacy := bridgeTestContext(t, submitter)
	ReplyToSender(ctx, msg, "rejected hello")
	if legacy.personMsgs != nil || legacy.groupMsgs != nil {
		t.Fatalf("legacy adapter called after rejection: %#v", legacy)
	}
	if ctx.IsCommandReplied() {
		t.Fatal("durable rejection marked command replied")
	}
}

func TestFailClosedOutboundBridgeNeverFallsBackToLegacyAdapter(t *testing.T) {
	ctx, msg, legacy := bridgeTestContext(t, &bridgeTestSubmitter{})
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
	ctx, msg, legacy := bridgeTestContext(t, &bridgeTestSubmitter{})
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
				Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
			}}, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
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
	ctx, msg, _ := canonicalBridgeTestContext(t, submitter)
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
	ctx, msg, _ := canonicalBridgeTestContext(t, submitter)
	updateCanonicalTestConfig(t, ctx.Dice, func(config *Config) { config.JsEnable = true })
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
	completionIdentity := ctx.Dice.DomainExecutionIdentity("outbound-provider-completion", string(submitter.request.Effect.ID))
	bridge.NotifyOutboundEffectSucceeded(context.Background(), submitter.request.Effect, adapterapi.SucceededResult("provider-owned-scope"))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("post-commit send hook did not start")
	}
	repository := ctx.Dice.DurableStore.(eventstore.ExecutionReceiptRepository)
	receipt, err := repository.LookupExecution(context.Background(), completionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != eventstore.ExecutionStatusStarted {
		t.Fatalf("completion root sealed before its Promise settled: %#v", receipt)
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
	awaitCanonicalTestExecutionCommit(t, ctx.Dice, completionIdentity)

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
	ctx, msg, _ := canonicalBridgeTestContext(t, submitter)
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
	ctx, msg, _ := canonicalBridgeTestContext(t, submitter)
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

func TestDurableBridgeCompletionUsesFreshSourceHandlesAndSentTarget(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	base, _, _ := canonicalBridgeTestContext(t, submitter)
	source := &Message{
		MessageType: "group", GroupID: "QQ-Group:6001",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Source"},
	}
	target := &Message{
		MessageType: "group", GroupID: "QQ-Group:7001",
		Sender: SenderBase{UserID: "QQ:2002", Nickname: "Target"},
	}
	type hookObservation struct {
		groupID, playerID, targetID string
		fresh                       bool
	}
	observed := make(chan hookObservation, 1)
	var sourceGroup *GroupInfo
	var sourcePlayer *GroupPlayerInfo
	base.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(hookCtx *MsgContext, sent *Message, _ string) {
		observation := hookObservation{targetID: sent.GroupID}
		if hookCtx.Group != nil {
			observation.groupID = hookCtx.Group.GroupID()
		}
		if hookCtx.Player != nil {
			observation.playerID = hookCtx.Player.UserID()
		}
		observation.fresh = hookCtx.Group != sourceGroup && hookCtx.Player != sourcePlayer
		if err := hookCtx.Group.SetGroupName("completion committed"); err != nil {
			hookCtx.setExecutionError(err)
		}
		observed <- observation
	}}}

	withCanonicalTestMessageContext(t, base.Dice, base.EndPoint, source, "source-outbound", func(ctx *MsgContext) error {
		sourceGroup, sourcePlayer = ctx.Group, ctx.Player
		return base.Dice.OutboundBridge.SubmitText(ctx, target, "to target", "", true)
	})
	effect := submitter.request.Effect
	base.Dice.OutboundBridge.(*DurableOutboundBridge).NotifyOutboundEffectSucceeded(
		context.Background(), effect, adapterapi.SucceededResult("provider-source-target"),
	)
	select {
	case got := <-observed:
		if got.groupID != source.GroupID || got.playerID != source.Sender.UserID || got.targetID != target.GroupID || !got.fresh {
			t.Fatalf("completion identities = %#v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("completion hook did not run")
	}
	identity := base.Dice.DomainExecutionIdentity("outbound-provider-completion", string(effect.ID))
	awaitCanonicalTestExecutionCommit(t, base.Dice, identity)
	state, err := groupstate.NewRepository(base.Dice.DurableStore).Load(context.Background(), base.Dice.BaseConfig.Name, source.GroupID)
	if err != nil {
		t.Fatal(err)
	}
	if state.GroupName != "completion committed" {
		t.Fatalf("completion mutation persisted name = %q", state.GroupName)
	}
}

func TestDurableBridgeNonSuccessOutcomesDropNotification(t *testing.T) {
	tests := []struct {
		name   string
		result adapterapi.EffectResult
		reject bool
		mutate func(*adapterapi.OutboundEffect)
	}{
		{name: "terminal", result: adapterapi.TerminalResult("provider-terminal", "rejected by provider")},
		{name: "unsupported", result: adapterapi.UnsupportedResult("missing-capability")},
		{name: "ambiguous", result: adapterapi.AmbiguousResult("timeout-after-send", "delivery unknown")},
		{name: "typed result for message", result: adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
			Conversation: "QQ-Group:2002", Name: "not a message completion",
		})},
		{name: "mismatched accepted target", result: adapterapi.SucceededResult("provider-mismatch"), mutate: func(effect *adapterapi.OutboundEffect) {
			effect.Payload.Target.Conversation = "QQ:9999"
		}},
		{name: "submit rejected", reject: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			submitter := &bridgeTestSubmitter{}
			if test.reject {
				submitter.err = errors.New("durable acceptance rejected")
			}
			ctx, msg, _ := canonicalBridgeTestContext(t, submitter)
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
				effect := submitter.request.Effect
				if test.mutate != nil {
					test.mutate(&effect)
				}
				bridge.NotifyOutboundEffectResult(context.Background(), effect, test.result)
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
	ctx, msg, _ := bridgeTestContext(t, submitter)
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
	ctx, msg, _ := canonicalBridgeTestContext(t, submitter)
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
	firstIdentity := ctx.Dice.DomainExecutionIdentity("outbound-provider-completion", string(firstEffect.ID))
	repository := ctx.Dice.DurableStore.(eventstore.ExecutionReceiptRepository)
	deadline := time.Now().Add(2 * time.Second)
	for {
		receipt, err := repository.LookupExecution(context.Background(), firstIdentity)
		if err == nil && receipt.Status == eventstore.ExecutionStatusAmbiguous {
			break
		}
		if err == nil && receipt.Status == eventstore.ExecutionStatusCommitted {
			t.Fatalf("panicking completion was fabricated as committed: %#v", receipt)
		}
		if time.Now().After(deadline) {
			t.Fatalf("panicking completion did not become ambiguous: receipt=%#v err=%v", receipt, err)
		}
		time.Sleep(time.Millisecond)
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
	ctx, msg, _ := canonicalBridgeTestContext(t, firstSubmitter)
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
	freshCtx, _, _ := canonicalBridgeTestContext(t, freshSubmitter)
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
	ctx, _, _ := bridgeTestContext(t, submitter)
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
	ctx, _, _ := bridgeTestContext(t, submitter)
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
			ctx, _, legacy := bridgeTestContext(t, submitter)
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
	ctx, _, legacy := bridgeTestContext(t, &bridgeTestSubmitter{})
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
			ctx, msg, legacy := bridgeTestContext(t, &bridgeTestSubmitter{})
			if test.callbackTransaction {
				ctx, msg, legacy = canonicalBridgeTestContext(t, &bridgeTestSubmitter{})
			}
			if !test.withBridge {
				ctx.Dice.OutboundBridge = nil
			}
			if test.callbackTransaction {
				ctx.EndPoint.ProtocolType = "gocq"
				root := newCanonicalTestRoot(t, ctx.Dice, "file-send-callback")
				ctx.callbackTransaction = root.Transaction
				ctx.callbackMetadata = root.Metadata
				ctx.executionContext = root.Context
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
	ctx, _, legacy := bridgeTestContext(t, &bridgeTestSubmitter{})
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
	ctx, msg, _ := bridgeTestContext(t, &bridgeTestSubmitter{})
	ctx.Dice.OutboundBridge = nil
	ctx.EndPoint.ProtocolType = "gocq"
	ctx.EndPoint.Adapter = nil

	_, err := SendFileToPersonRaw(ctx, msg, "/synthetic/private.txt", "")
	if err == nil || err.Error() != "文件发送适配器不可用" {
		t.Fatalf("SendFileToPersonRaw error = %v, want clear missing-adapter error", err)
	}
}
