package dice

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

const (
	onebotSelfGroupSent = `{"post_type":"message_sent","message_type":"group","sub_type":"normal","self_id":3003,"user_id":3003,` +
		`"group_id":2002,"message_id":9001,"message_seq":12,"time":1700000000,"sender":{"user_id":3003,"nickname":"Dice","role":"member"},` +
		`"message":[{"type":"text","data":{"text":"hi"}},{"type":"at","data":{"qq":"1001"}}]}`
	onebotSelfGroupMessage = `{"post_type":"message","message_type":"group","self_id":3003,"user_id":3003,` +
		`"group_id":2002,"message_id":9002,"message_seq":13,"time":1700000001,"sender":{"user_id":3003,"role":"member"},"message":".r d100"}`
	onebotSelfPrivateSent = `{"post_type":"message_sent","message_type":"private","sub_type":"friend","self_id":3003,"user_id":3003,` +
		`"target_id":1001,"message_id":9003,"time":1700000002,"message":"hello friend"}`
	onebotSelfPrivateMessage = `{"post_type":"message","message_type":"private","self_id":3003,"user_id":3003,` +
		`"target_id":1001,"message_id":9004,"time":1700000003,"message":".r d100"}`
)

func newOnebotSelfRuntime(t *testing.T) (*onebotRuntime, *onebotPassthroughCore) {
	t.Helper()
	runtime, core := newOnebotPassthroughRuntime(t)
	t.Cleanup(func() { runtime.sentLedger().discard() })
	return runtime, core
}

func receiveOnebotInbound(t *testing.T, core *onebotPassthroughCore) adapterapi.InboundMessage {
	t.Helper()
	select {
	case message := <-core.inboundCh:
		return message
	case <-time.After(2 * time.Second):
		t.Fatal("no inbound was delivered")
		return adapterapi.InboundMessage{}
	}
}

func expectNoOnebotInbound(t *testing.T, core *onebotPassthroughCore) {
	t.Helper()
	select {
	case message := <-core.inboundCh:
		t.Fatalf("unexpected inbound %#v", message)
	case <-time.After(60 * time.Millisecond):
	}
}

// sendActionFrame is the frame of a send action as the emitter writes it.
func sendActionFrame(action, params string) []byte {
	return []byte(`{"action":"` + action + `","params":` + params + `,"echo":"e"}`)
}

func sendActionResponse(messageID int64) []byte {
	return []byte(`{"status":"ok","retcode":0,"data":{"message_id":` + strconv.FormatInt(messageID, 10) + `},"echo":"e"}`)
}

// The behavior table: both shapes in which a protocol end reports the
// account's own message, in a group and in a private chat, become an own
// message placed in the conversation the message belongs to, keeping the
// provider's identity, sequence, text, segments, time and raw event.
func TestOnebotOwnMessagesBecomeSelfMessagesInTheirConversation(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		kind           adapterapi.ConversationKind
		conversation   adapterapi.ConversationID
		messageID      adapterapi.MessageID
		sequence       int64
		text           string
		eventType      string
		providerEvents adapterapi.ProviderEventID
	}{
		{"group message_sent", onebotSelfGroupSent, adapterapi.ConversationKindGroup, "QQ-Group:2002", "9001", 12, "hi[CQ:at,qq=1001]", "message_sent", "onebot-self-message-9001"},
		{"group message from self_id", onebotSelfGroupMessage, adapterapi.ConversationKindGroup, "QQ-Group:2002", "9002", 13, ".r d100", "message", "onebot-self-message-9002"},
		{"private message_sent", onebotSelfPrivateSent, adapterapi.ConversationKindDirect, "QQ:1001", "9003", 0, "hello friend", "message_sent", "onebot-self-message-9003"},
		{"private message from self_id", onebotSelfPrivateMessage, adapterapi.ConversationKindDirect, "QQ:1001", "9004", 0, ".r d100", "message", "onebot-self-message-9004"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime, core := newOnebotSelfRuntime(t)
			if err := runtime.handleProtocolInbound(context.Background(), []byte(tt.raw)); err != nil {
				t.Fatal(err)
			}
			message := receiveOnebotInbound(t, core)
			if message.Kind != adapterapi.InboundKindSelfMessage || message.ConversationKind != tt.kind ||
				message.Conversation != tt.conversation || message.Target != string(tt.conversation) ||
				message.Sender != "QQ:3003" || message.MessageID != tt.messageID || message.Sequence != tt.sequence ||
				message.ProviderEventID != tt.providerEvents || message.SelfOrigin != adapterapi.SelfMessageUnattributed {
				t.Fatalf("self message = %#v", message)
			}
			if message.OccurredAt.Unix() < 1700000000 || (tt.raw == onebotSelfGroupSent && len(message.Segments) != 2) {
				t.Fatalf("self message lost its time or segments: %#v", message)
			}
			if message.AdapterEvent == nil || message.AdapterEvent.Type != tt.eventType || message.AdapterEvent.RawJSON != tt.raw {
				t.Fatalf("self message lost the raw event: %#v", message.AdapterEvent)
			}
		})
	}
}

func TestOnebotSelfMessageKeepsIdentityAcrossBothShapes(t *testing.T) {
	// A protocol end that reports the same message both ways is one message.
	const asMessage = `{"post_type":"message","message_type":"group","self_id":3003,"user_id":3003,"group_id":2002,"message_id":9001,"message_seq":12,"time":1700000000,"message":"hi"}`
	runtime, core := newOnebotSelfRuntime(t)
	for _, raw := range []string{onebotSelfGroupSent, asMessage} {
		if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	first, second := receiveOnebotInbound(t, core), receiveOnebotInbound(t, core)
	if first.ProviderEventID != second.ProviderEventID || first.MessageID != second.MessageID {
		t.Fatalf("one message got two identities: %q vs %q", first.ProviderEventID, second.ProviderEventID)
	}
}

func TestOnebotMessageWithoutSelfIDKeepsOrdinaryBehavior(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	const raw = `{"post_type":"message","message_type":"group","user_id":3003,"group_id":2002,"message_id":5,"message":"x"}`
	if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.Kind != adapterapi.InboundKindMessage || message.ProviderEventID != "onebot-message-5" {
		t.Fatalf("message without self_id = %#v", message)
	}
	const otherUser = `{"post_type":"message","message_type":"group","self_id":3003,"user_id":1001,"group_id":2002,"message_id":6,"message":"x"}`
	if err := runtime.handleProtocolInbound(context.Background(), []byte(otherUser)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.Kind != adapterapi.InboundKindMessage {
		t.Fatalf("another user's message = %#v", message)
	}
}

// A private message of the account whose recipient is unknown has no
// conversation: Core records nothing, and plugins subscribed to every adapter
// event still receive the event, not scoped to the account's own id.
func TestOnebotSelfPrivateMessageWithoutRecipientIsAConversationFreeEvent(t *testing.T) {
	for name, raw := range map[string]string{
		"message_sent": `{"post_type":"message_sent","message_type":"private","self_id":3003,"user_id":3003,"message_id":31,"time":1700000000,"message":"x"}`,
		"message":      `{"post_type":"message","message_type":"private","self_id":3003,"user_id":3003,"message_id":32,"time":1700000000,"message":".r"}`,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, core := newOnebotSelfRuntime(t)
			if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
				t.Fatal(err)
			}
			select {
			case event := <-core.adapterEvents:
				if event.RawJSON != raw {
					t.Fatalf("event = %#v", event)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("conversation-free adapter event was not delivered")
			}
			expectNoOnebotInbound(t, core)
		})
	}
}

func TestOnebotMessageSentWithoutIDStaysAnAdapterEventInItsGroup(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	const raw = `{"post_type":"message_sent","message_type":"group","self_id":3003,"user_id":3003,"group_id":2002,"time":1700000000,"message":"x"}`
	if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	message := receiveOnebotInbound(t, core)
	if message.Kind != adapterapi.InboundKindAdapterEvent || message.Conversation != "QQ-Group:2002" || message.AdapterEvent.RawJSON != raw {
		t.Fatalf("message_sent without an id = %#v", message)
	}
}

func TestOnebotSelfMessageWithoutIDIsRejectedLikeAnyMessage(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	const raw = `{"post_type":"message","message_type":"group","self_id":3003,"user_id":3003,"group_id":2002,"message":"x"}`
	if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
		t.Fatalf("err = %v, want unsupported event", err)
	}
	expectNoOnebotInbound(t, core)
}

// A private opaque event of the account is scoped to its recipient, so plugin
// hooks run in the peer's conversation.
func TestOnebotOpaquePrivateOwnEventUsesTheRecipientConversation(t *testing.T) {
	var envelope onebotInboundEnvelope
	envelope.PostType = "message_sent"
	envelope.UserID = []byte("3003")
	envelope.TargetID = []byte("1001")
	envelope.SelfID = []byte("3003")
	message, scoped, err := opaqueOnebotInbound([]byte(onebotSelfPrivateSent), adapterapi.AdapterEvent{Protocol: "onebot11", Type: "message_sent", RawJSON: onebotSelfPrivateSent}, &envelope)
	if err != nil || !scoped || message.Conversation != "QQ:1001" || message.Sender != "QQ:3003" {
		t.Fatalf("opaque own private event = %#v scoped=%v err=%v", message, scoped, err)
	}
}

func TestOnebotActionRecognition(t *testing.T) {
	for action, want := range map[string]bool{
		"send_msg": true, "send_private_msg": true, "send_group_msg": true, "send_guild_channel_msg": true,
		"send_group_forward_msg": true, "send_private_forward_msg": true, "send_forward_msg": true,
		"SEND_MSG": true, "send_group_msg_async": false, "send_poke": false, "get_msg": false,
		"delete_msg": false, "set_group_card": false, "": false,
	} {
		if got := onebotActionSendsMessage(action); got != want {
			t.Errorf("onebotActionSendsMessage(%q) = %v, want %v", action, got, want)
		}
	}
	for frame, want := range map[string]string{
		`{"action":"send_group_msg","params":{"group_id":2002}}`:                                "g:2002",
		`{"action":"send_private_msg","params":{"user_id":"1001"}}`:                             "p:1001",
		`{"action":"send_msg","params":{"message_type":"group","group_id":2002,"user_id":1}}`:   "g:2002",
		`{"action":"send_msg","params":{"message_type":"private","group_id":2002,"user_id":1}}`: "p:1",
		`{"action":"send_guild_channel_msg","params":{"guild_id":"7","channel_id":8}}`:          "c:7-8",
		`{"action":"send_msg","params":{}}`:                                                     "",
		`not json`:                                                                              "",
	} {
		if got := onebotActionConversationKey([]byte(frame)); got != want {
			t.Errorf("conversation key of %s = %q, want %q", frame, got, want)
		}
	}
	for response, want := range map[string]string{
		`{"status":"ok","retcode":0,"data":{"message_id":55}}`:      "55",
		`{"status":"ok","retcode":0,"data":{"message_id":"abc"}}`:   "abc",
		`{"status":"ok","retcode":0,"data":{"message_id":-7}}`:      "-7",
		`{"status":"failed","retcode":100,"data":{"message_id":9}}`: "",
		`{"status":"ok","retcode":0,"data":{"message_id":0}}`:       "",
		`{"status":"ok","retcode":0,"data":null}`:                   "",
		``: "",
	} {
		if got := onebotSendResponseMessageID([]byte(response)); got != want {
			t.Errorf("message id of %q = %q, want %q", response, got, want)
		}
	}
}

// Core's send reached the provider through callApi, not the outbox: the
// runtime still knows the id it returned, so the report is Core's.
func TestOnebotReportAfterDirectCallAPISendIsIssuedByCore(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_msg", sendActionFrame("send_msg", `{"message_type":"group","group_id":2002,"message":"hi"}`))
	finish(sendActionResponse(9001))

	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageIssuedByCore {
		t.Fatalf("origin = %v, want issued by Core", message.SelfOrigin)
	}
}

func TestOnebotForwardSendIdsAreRemembered(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_group_forward_msg", sendActionFrame("send_group_forward_msg", `{"group_id":2002,"messages":[]}`))
	finish(sendActionResponse(9001))
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageIssuedByCore {
		t.Fatalf("origin = %v, want issued by Core", message.SelfOrigin)
	}
}

// The provider may report a message before the send's response reaches Core.
// The report waits for the response and is then judged by it.
func TestOnebotReportBeforeSendResponseIsIssuedByCore(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_group_msg", sendActionFrame("send_group_msg", `{"group_id":2002,"message":"hi"}`))

	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	expectNoOnebotInbound(t, core)

	finish(sendActionResponse(9001))
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageIssuedByCore || message.MessageID != "9001" {
		t.Fatalf("held report = %#v, want issued by Core", message)
	}
}

// A hand-typed message that lands while a Core send is in flight is not Core's:
// once the send answers with another id the report is delivered as typed by hand.
func TestOnebotReportWithAnotherIDWhileSendInFlightIsUnattributed(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_group_msg", sendActionFrame("send_group_msg", `{"group_id":2002,"message":"hi"}`))
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	expectNoOnebotInbound(t, core)

	finish(sendActionResponse(7777))
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageUnattributed || message.MessageID != "9001" {
		t.Fatalf("held report = %#v, want unattributed", message)
	}
}

func TestOnebotFailedSendReleasesHeldReportsAsUnattributed(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_group_msg", sendActionFrame("send_group_msg", `{"group_id":2002,"message":"hi"}`))
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	finish(nil)
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageUnattributed {
		t.Fatalf("origin = %v, want unattributed", message.SelfOrigin)
	}
}

// Reports wait only for sends that could be their source.
func TestOnebotHeldReportDoesNotWaitForOtherConversations(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_group_msg", sendActionFrame("send_group_msg", `{"group_id":9999,"message":"hi"}`))
	defer finish(nil)

	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageUnattributed {
		t.Fatalf("origin = %v, want unattributed and immediate", message.SelfOrigin)
	}
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfPrivateSent)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.Conversation != "QQ:1001" {
		t.Fatalf("private report = %#v", message)
	}
}

// A send whose target could not be read may have produced any report.
func TestOnebotSendWithUnreadableTargetHoldsEveryReport(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	finish := runtime.sentLedger().BeginAction("send_msg", sendActionFrame("send_msg", `{}`))
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	expectNoOnebotInbound(t, core)
	finish(sendActionResponse(9001))
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageIssuedByCore {
		t.Fatalf("origin = %v, want issued by Core", message.SelfOrigin)
	}
}

func TestOnebotHeldReportIsDeliveredAfterTheHoldLimit(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	runtime.sentLedger().holdTimeout = 30 * time.Millisecond
	runtime.sentLedger().BeginAction("send_group_msg", sendActionFrame("send_group_msg", `{"group_id":2002,"message":"hi"}`))
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.SelfOrigin != adapterapi.SelfMessageUnattributed {
		t.Fatalf("origin = %v, want unattributed after the hold limit", message.SelfOrigin)
	}
}

func TestOnebotHeldReportsAreBounded(t *testing.T) {
	runtime, core := newOnebotSelfRuntime(t)
	runtime.sentLedger().BeginAction("send_group_msg", sendActionFrame("send_group_msg", `{"group_id":2002,"message":"hi"}`))
	for i := range onebotEchoHeldCapacity {
		raw := `{"post_type":"message_sent","message_type":"group","self_id":3003,"user_id":3003,"group_id":2002,"message_id":` + strconv.Itoa(100+i) + `,"time":1700000000,"message":"x"}`
		if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	expectNoOnebotInbound(t, core)
	if err := runtime.handleProtocolInbound(context.Background(), []byte(onebotSelfGroupSent)); err != nil {
		t.Fatal(err)
	}
	if message := receiveOnebotInbound(t, core); message.MessageID != "9001" || message.SelfOrigin != adapterapi.SelfMessageUnattributed {
		t.Fatalf("report beyond the bound = %#v, want judged at once", message)
	}
}

func TestOnebotSentLedgerForgetsOldIDsAndStaysBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newOnebotSentLedger(func(*onebotHeldEcho, adapterapi.SelfMessageOrigin) {})
	ledger.now = func() time.Time { return now }
	finish := ledger.BeginAction("send_msg", sendActionFrame("send_msg", `{"group_id":1}`))
	finish(sendActionResponse(1))
	if !ledger.known("1") {
		t.Fatal("a returned id was not remembered")
	}
	now = now.Add(onebotSentIDTTL + time.Second)
	if ledger.known("1") {
		t.Fatal("an id outlived its lifetime")
	}
	for i := range onebotSentIDCapacity + 10 {
		ledger.begin("g:1")
		ledger.finish("g:1", "id-"+strconv.Itoa(i))
	}
	if len(ledger.ids) > onebotSentIDCapacity || len(ledger.order) > onebotSentIDCapacity {
		t.Fatalf("ledger holds %d ids, bound is %d", len(ledger.ids), onebotSentIDCapacity)
	}
	if ledger.known("id-0") || !ledger.known("id-"+strconv.Itoa(onebotSentIDCapacity+9)) {
		t.Fatal("eviction dropped the newest id instead of the oldest")
	}
}

func TestOnebotHistoryOwnMessagesAreSelfMessages(t *testing.T) {
	own := onebotOwnMessages{selfID: "3003", known: func(id string) bool { return id == "9100" }}
	typed := func(postType, user, id, extra string) string {
		return `{"post_type":"` + postType + `","message_type":"group","user_id":` + user + `,"group_id":2002,"message_id":` + id +
			`,"message_seq":` + id + `,"time":1700000000` + extra + `,"message":"x"}`
	}
	tests := []struct {
		name   string
		raw    string
		kind   adapterapi.InboundKind
		origin adapterapi.SelfMessageOrigin
	}{
		{"message_sent entry", typed("message_sent", "3003", "9101", ""), adapterapi.InboundKindSelfMessage, adapterapi.SelfMessageUnattributed},
		{"message entry from the account", typed("message", "3003", "9102", ""), adapterapi.InboundKindSelfMessage, adapterapi.SelfMessageUnattributed},
		{"entry naming the account in self_id", typed("message", "3003", "9103", `,"self_id":3003`), adapterapi.InboundKindSelfMessage, adapterapi.SelfMessageUnattributed},
		{"entry Core sent", typed("message_sent", "3003", "9100", ""), adapterapi.InboundKindSelfMessage, adapterapi.SelfMessageIssuedByCore},
		{"another member", typed("message", "1001", "9104", ""), adapterapi.InboundKindMessage, adapterapi.SelfMessageUnattributed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := onebotHistoryInbound([]byte(tt.raw), "QQ-Group:2002", own)
			if err != nil {
				t.Fatal(err)
			}
			if message.Kind != tt.kind || message.SelfOrigin != tt.origin {
				t.Fatalf("history entry = kind %v origin %v, want %v %v", message.Kind, message.SelfOrigin, tt.kind, tt.origin)
			}
			if message.Kind == adapterapi.InboundKindSelfMessage && message.ProviderEventID != adapterapi.ProviderEventID("onebot-self-message-"+string(message.MessageID)) {
				t.Fatalf("history identity = %q", message.ProviderEventID)
			}
			result := adapterapi.QueryResult{History: []adapterapi.InboundMessage{message}}
			request := adapterapi.QueryRequest{Kind: adapterapi.QueryKindGroupHistory, Group: "QQ-Group:2002", AfterSequence: 1, BeforeSequence: 1 << 40, Limit: 10}
			if err := result.Validate(request); err != nil {
				t.Fatalf("history answer rejected: %v", err)
			}
		})
	}
}

func TestOnebotHistoryOwnEntryNeedsAMessageID(t *testing.T) {
	const raw = `{"post_type":"message_sent","message_type":"group","user_id":3003,"group_id":2002,"message_seq":5,"time":1700000000,"message":"x"}`
	if _, err := onebotHistoryInbound([]byte(raw), "QQ-Group:2002", onebotOwnMessages{}); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
		t.Fatalf("err = %v, want unsupported event", err)
	}
}
