package dice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
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

func TestDurableBridgeConcurrentTerminalNotificationFencesReconciliation(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	const canonicalEffectID = "canonical-effect-id"
	started := make(chan struct{})
	allowReturn := make(chan struct{})
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
	callbackDone := make(chan struct{})
	ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
		if callbackCount.Add(1) == 1 {
			close(callbackDone)
		}
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
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("terminal success callback not delivered")
	}
	bridge.mu.Lock()
	pending := len(bridge.pending)
	bridge.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending notifications = %d", pending)
	}
	bridge.NotifyOutboundEffectResult(context.Background(), adapterapi.OutboundEffect{ID: canonicalEffectID}, adapterapi.SucceededResult("provider-duplicate"))
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

func TestDurableBridgeTerminalFailureDropsNotification(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "failed", "", false); err != nil {
		t.Fatal(err)
	}
	bridge := ctx.Dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.NotifyOutboundEffectResult(context.Background(), submitter.request.Effect, adapterapi.TerminalResult("provider_failed", "failed"))
	bridge.mu.Lock()
	pending := len(bridge.pending)
	bridge.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending notifications = %d", pending)
	}
}

func TestDurableBridgeIDsAreStablePerLogicalReplyAndDistinctPerSplitItem(t *testing.T) {
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "part one", "", false); err != nil {
		t.Fatal(err)
	}
	submitter.mu.Lock()
	first := submitter.request
	submitter.mu.Unlock()
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "part one", "", false); err != nil {
		t.Fatal(err)
	}
	submitter.mu.Lock()
	same := submitter.request
	submitter.mu.Unlock()
	if first.CommandID != same.CommandID {
		t.Fatalf("same split item changed command ID: %q != %q", first.CommandID, same.CommandID)
	}
	if first.Effect.CorrelationID != same.Effect.CorrelationID {
		t.Fatalf("same split item changed correlation ID: %q != %q", first.Effect.CorrelationID, same.Effect.CorrelationID)
	}
	if first.Effect.CausationID != same.Effect.CausationID {
		t.Fatalf("same split item changed causation ID: %q != %q", first.Effect.CausationID, same.Effect.CausationID)
	}
	if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "part two", "", false); err != nil {
		t.Fatal(err)
	}
	submitter.mu.Lock()
	distinct := submitter.request
	submitter.mu.Unlock()
	if first.CommandID == distinct.CommandID {
		t.Fatal("different split items reused command ID")
	}
	if first.Effect.CorrelationID == distinct.Effect.CorrelationID {
		t.Fatal("different split items reused correlation ID")
	}
	if first.Effect.CausationID == distinct.Effect.CausationID {
		t.Fatal("different split items reused causation ID")
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
