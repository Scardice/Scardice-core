package dice

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/eventstore"
)

type forwardReplyRawEmitter struct {
	emitter.Emitter
	request  []byte
	response []byte
}

func (e *forwardReplyRawEmitter) RawJSON(_ context.Context, request []byte) ([]byte, error) {
	e.request = append(e.request[:0], request...)
	return e.response, nil
}

func newDurableForwardReplyContext(t *testing.T) (*MsgContext, *Message, *bridgeTestSubmitter, *DurableOutboundBridge) {
	t.Helper()
	submitter := &bridgeTestSubmitter{}
	ctx, msg, _ := bridgeTestContext(submitter)
	ctx.EndPoint.Adapter = nil
	ctx.EndPoint.Nickname = "Dice"
	resolver := bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "endpoint-1", AdapterKey: adapterapi.AdapterKey("pureonebot"),
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
		IndexRootID:  "root-1",
		IndexSigner:  bridgeTestIndexSigner{root: []byte("01234567890123456789012345678901"), id: "root-1"},
	}}
	bridge := NewDurableOutboundBridge(submitter, resolver, eventstore.UUIDGenerator{})
	ctx.Dice.OutboundBridge = bridge
	return ctx, msg, submitter, bridge
}

func TestDurablePureOnebotForwardReplyReachesNativeForwardAction(t *testing.T) {
	for _, test := range []struct {
		name       string
		group      bool
		action     string
		targetID   int64
		targetKind adapterapi.TargetKind
	}{
		{name: "group", group: true, action: "send_group_forward_msg", targetID: 2002, targetKind: adapterapi.TargetGroup},
		{name: "private", action: "send_private_forward_msg", targetID: 1001, targetKind: adapterapi.TargetPerson},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, msg, submitter, bridge := newDurableForwardReplyContext(t)
			notified := make(chan *Message, 1)
			ctx.Dice.ExtList = []*ExtInfo{{OnMessageSend: func(_ *MsgContext, sent *Message, _ string) {
				notified <- sent
			}}}
			if test.group {
				msg.MessageType = "group"
				msg.GroupID = "QQ-Group:2002"
			} else {
				msg.MessageType = "private"
				msg.Sender.UserID = "QQ:1001"
			}
			ctx.InitSplitKey()
			text := ctx.wrapForward("first" + ctx.getSplitKey() + "second")
			if !deliverReplyPlan(ctx, msg, text, "", test.group) {
				t.Fatal("forward reply was not admitted to the durable outbox")
			}

			effect := submitter.request.Effect
			if effect.Payload.Kind != adapterapi.EffectPayloadKind(14) {
				t.Fatalf("outbox payload kind = %d, want structured forward kind 14", effect.Payload.Kind)
			}
			if effect.Kind != adapterapi.EffectKindMessage || effect.RequiredCapabilities != adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages || effect.RequiredAction != adapterapi.ActionKindSendMessage || effect.RetryClass != adapterapi.EffectRetryNonIdempotent {
				t.Fatalf("outbox message contract = %+v", effect)
			}
			if effect.Payload.Target.Kind != test.targetKind || bridgePendingNotifications(bridge) != 1 {
				t.Fatalf("target or success notification missing: target=%+v pending=%d", effect.Payload.Target, bridgePendingNotifications(bridge))
			}

			payloadJSON, err := json.Marshal(effect.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var payloadWire struct {
				ForwardNodes []struct {
					SenderID   string `json:"senderId"`
					SenderName string `json:"senderName"`
					Content    string `json:"content"`
				} `json:"forwardNodes"`
			}
			if err := json.Unmarshal(payloadJSON, &payloadWire); err != nil {
				t.Fatal(err)
			}
			if len(payloadWire.ForwardNodes) != 2 || payloadWire.ForwardNodes[0].Content != "first" || payloadWire.ForwardNodes[1].Content != "second" || payloadWire.ForwardNodes[0].SenderID != "9001" || payloadWire.ForwardNodes[0].SenderName != "Dice" {
				t.Fatalf("outbox forward nodes = %+v", payloadWire.ForwardNodes)
			}

			provider := &forwardReplyRawEmitter{response: []byte(`{"status":"ok","retcode":0,"data":{"message_id":77}}`)}
			runtime := newOnebotRuntime(OnebotConfig{}, nil)
			runtime.emitter = provider
			result := runtime.Execute(context.Background(), effect)
			if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "77" {
				t.Fatalf("OneBot forward result = %+v", result)
			}
			bridge.NotifyOutboundEffectSucceeded(context.Background(), effect, result)
			select {
			case sent := <-notified:
				wantType := "private"
				if test.group {
					wantType = "group"
				}
				if sent.RawID != "77" || sent.Message != "first\nsecond" || sent.MessageType != wantType {
					t.Fatalf("forward success notification = %#v", sent)
				}
			case <-time.After(time.Second):
				t.Fatal("forward success notification was not delivered")
			}
			var request struct {
				Action string `json:"action"`
				Params struct {
					GroupID  int64 `json:"group_id"`
					UserID   int64 `json:"user_id"`
					Messages []struct {
						Type string `json:"type"`
						Data struct {
							UserID   string `json:"user_id"`
							Nickname string `json:"nickname"`
							Content  []struct {
								Type string `json:"type"`
								Data struct {
									Text string `json:"text"`
								} `json:"data"`
							} `json:"content"`
						} `json:"data"`
					} `json:"messages"`
				} `json:"params"`
			}
			if err := json.Unmarshal(provider.request, &request); err != nil {
				t.Fatal(err)
			}
			if request.Action != test.action || len(request.Params.Messages) != 2 {
				t.Fatalf("provider request action/messages = %q/%d", request.Action, len(request.Params.Messages))
			}
			if test.group && request.Params.GroupID != test.targetID || !test.group && request.Params.UserID != test.targetID {
				t.Fatalf("provider target params = %+v", request.Params)
			}
			if request.Params.Messages[0].Type != "node" || request.Params.Messages[0].Data.UserID != "9001" || request.Params.Messages[0].Data.Nickname != "Dice" || len(request.Params.Messages[0].Data.Content) != 1 || request.Params.Messages[0].Data.Content[0].Data.Text != "first" || len(request.Params.Messages[1].Data.Content) != 1 || request.Params.Messages[1].Data.Content[0].Data.Text != "second" {
				t.Fatalf("provider forward nodes = %+v", request.Params.Messages)
			}
		})
	}
}
func TestDurablePureOnebotForwardRejectsOversizedEnvelopeBeforeAdmission(t *testing.T) {
	payload := adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadForward,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:2002"},
		ForwardNodes: []adapterapi.ForwardMessageNode{{
			SenderID: "9001", SenderName: "Dice", Content: "x",
		}},
	}
	sample, err := buildOnebotForwardRequestJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	contentLength := adapterapi.MaxProtocolJSONBytes - len(sample)
	if contentLength > adapterapi.MaxEffectTextBytes {
		t.Fatalf("oversize test content exceeds typed payload limit: %d", contentLength)
	}
	payload.ForwardNodes[0].Content = strings.Repeat("x", contentLength)
	request, err := buildOnebotForwardRequestJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != adapterapi.MaxProtocolJSONBytes-1 {
		t.Fatalf("request size = %d, want %d before echo replacement", len(request), adapterapi.MaxProtocolJSONBytes-1)
	}
	if err := validateOnebotForwardRequestSize(request); err == nil {
		t.Fatal("request accepted despite UUID-sized echo exceeding the protocol limit")
	}

	ctx, msg, submitter, bridge := newDurableForwardReplyContext(t)
	msg.MessageType = "group"
	msg.GroupID = "QQ-Group:2002"
	nodes := BuildForwardNodesFromContext(ctx, "", []string{payload.ForwardNodes[0].Content})
	if err := bridge.submitForward(ctx, msg, nodes, "", true); err == nil {
		t.Fatal("oversized native request was admitted to the durable outbox")
	}
	if submitter.request.Effect.ID != "" {
		t.Fatalf("oversized native request submitted: %+v", submitter.request.Effect)
	}
}

func TestDurablePureOnebotForwardReplyUsesOutboundCensor(t *testing.T) {
	ctx, msg, submitter, _ := newDurableForwardReplyContext(t)
	msg.MessageType = "group"
	msg.GroupID = "QQ-Group:2002"
	installAdapterTestCensor(t, ctx.Dice, OnlyOutputReply)
	ctx.InitSplitKey()
	if deliverReplyPlan(ctx, msg, ctx.wrapForward("gateword"), "", true) {
		t.Fatal("sensitive forward content was accepted")
	}
	if submitter.request.Effect.ID != "" || ctx.Censored == false {
		t.Fatalf("censored forward reached outbox or did not mark context: request=%+v censored=%t", submitter.request, ctx.Censored)
	}
}
