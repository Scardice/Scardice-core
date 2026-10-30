package dice

import (
	"context"
	"errors"
	"slices"
	"testing"

	"Scardice-core/adapterapi"
)

// The same group message as LLBot sends it live and as get_group_msg_history
// returns it (probed on a live endpoint: every field compared equal).
const onebotGroupMessageJSON = `{"self_id":3003,"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":10272,` +
	`"message_type":"group","sub_type":"normal","post_type":"message","group_id":2002,"group_name":"测试群",` +
	`"sender":{"user_id":1001,"nickname":"Alice","card":"爱丽丝","role":"admin","level":"5","title":""},` +
	`"raw_message":".r d100","message_format":"array","message":[{"type":"text","data":{"text":".r d100"}}]}`

func TestOnebotHistoryMessageIsTheSameFactAsTheLiveOne(t *testing.T) {
	runtime, core := onebotEventRuntime("")
	if err := runtime.handleInbound(context.Background(), []byte(onebotGroupMessageJSON)); err != nil {
		t.Fatal(err)
	}
	live := <-core.inboundCh

	history, err := onebotHistoryInbound([]byte(onebotGroupMessageJSON), "QQ-Group:2002")
	if err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string]adapterapi.InboundMessage{"live": live, "history": history} {
		if err := message.Validate(); err != nil {
			t.Fatalf("%s message is invalid: %v", name, err)
		}
		if message.AdapterEvent == nil ||
			message.AdapterEvent.Protocol != onebotAdapterEventProtocol ||
			message.AdapterEvent.Type != "message" ||
			message.AdapterEvent.RawJSON != onebotGroupMessageJSON {
			t.Fatalf("%s message lost its original adapter event: %#v", name, message.AdapterEvent)
		}
		if message.History != adapterapi.InboundHistoryNone {
			t.Fatalf("%s provider delivery claimed to be history: %d", name, message.History)
		}
	}
	if live.ProviderEventID != "onebot-message-9001" ||
		live.ProviderEventID != history.ProviderEventID ||
		live.MessageID != history.MessageID ||
		live.Sender != history.Sender ||
		live.Conversation != history.Conversation ||
		live.Kind != history.Kind ||
		live.Text != history.Text ||
		live.Sequence != history.Sequence ||
		!live.OccurredAt.Equal(history.OccurredAt) ||
		!slices.Equal(live.Segments, history.Segments) {
		t.Fatalf("history changed the logical message identity:\nlive    %#v\nhistory %#v", live, history)
	}
}

func TestOnebotHistoryMessageTakesItsGroupFromTheRequest(t *testing.T) {
	const withoutGroup = `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":10272,"message_type":"group","post_type":"message",` +
		`"sender":{"nickname":"Alice","role":"member"},"message":[{"type":"text","data":{"text":"hi"}}]}`
	message, err := onebotHistoryInbound([]byte(withoutGroup), "QQ-Group:2002")
	if err != nil {
		t.Fatal(err)
	}
	if message.Conversation != "QQ-Group:2002" || message.ConversationKind != adapterapi.ConversationKindGroup || message.Target != "QQ-Group:2002" {
		t.Fatalf("group not taken from the request: %+v", message)
	}
	if message.AdapterEvent == nil || message.AdapterEvent.RawJSON != withoutGroup {
		t.Fatalf("history event did not preserve the provider body: %#v", message.AdapterEvent)
	}
}

func TestOnebotHistoryRejectsWhatItCannotPlace(t *testing.T) {
	cases := map[string]string{
		"another group":      `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":10272,"message_type":"group","post_type":"message","group_id":9,"message":[]}`,
		"no message id":      `{"user_id":1001,"time":1793116175,"message_seq":10272,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"no time":            `{"user_id":1001,"message_id":9001,"message_seq":10272,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"no sequence":        `{"user_id":1001,"time":1793116175,"message_id":9001,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"a private message":  `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":10272,"message_type":"private","post_type":"message","message":[]}`,
		"not a message":      `{"post_type":"notice","notice_type":"poke","group_id":2002,"time":1793116175}`,
		"not json":           `nope`,
		"no sender":          `{"time":1793116175,"message_id":9001,"message_seq":10272,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"non numeric seq":    `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":"abc","message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"zero sequence":      `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":0,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"negative sequence":  `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":-4,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"fractional seq":     `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":1.5,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
		"oversized sequence": `{"user_id":1001,"time":1793116175,"message_id":9001,"message_seq":99999999999999999999,"message_type":"group","post_type":"message","group_id":2002,"message":[]}`,
	}
	for name, raw := range cases {
		if _, err := onebotHistoryInbound([]byte(raw), "QQ-Group:2002"); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A live message whose sequence is absent or unreadable is still delivered; the
// sequence only feeds gap detection and must never cost the message itself.
func TestOnebotLiveMessageWithoutUsableSequenceIsStillDelivered(t *testing.T) {
	for name, seq := range map[string]string{"absent": ``, "text": `,"message_seq":"abc"`, "negative": `,"message_seq":-3`} {
		raw := `{"post_type":"message","message_type":"group","group_id":2002,"user_id":1001,"message_id":9002,"time":1793116175` + seq + `,"message":[]}`
		runtime, core := onebotEventRuntime("")
		if err := runtime.handleInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := (<-core.inboundCh).Sequence; got != 0 {
			t.Fatalf("%s: sequence = %d, want 0", name, got)
		}
	}
}
