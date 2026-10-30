package adapterapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func groupMessage() InboundMessage {
	return InboundMessage{
		ProviderEventID: "onebot-message-1", Kind: InboundKindMessage, ConversationKind: ConversationKindGroup,
		Conversation: "QQ-Group:1", Sender: "QQ:2", Text: "hello",
	}
}

func TestInboundHistoryOnlyDescribesGroupMessages(t *testing.T) {
	for _, history := range []InboundHistory{InboundHistoryExecute, InboundHistoryRecordOnly} {
		message := groupMessage()
		message.History = history
		if err := message.Validate(); err != nil {
			t.Fatalf("history %d on a group message: %v", history, err)
		}

		direct := message
		direct.ConversationKind = ConversationKindDirect
		if direct.Validate() == nil {
			t.Fatalf("history %d accepted on a direct conversation", history)
		}

		notice := message
		notice.Kind, notice.Event = InboundKindNotice, InboundEventPoke
		if notice.Validate() == nil {
			t.Fatalf("history %d accepted on a notice", history)
		}
	}

	unknown := groupMessage()
	unknown.History = InboundHistoryRecordOnly + 1
	if unknown.Validate() == nil {
		t.Fatal("an unknown history mode was accepted")
	}
}

func TestInboundSequenceCannotBeNegative(t *testing.T) {
	message := groupMessage()
	message.Sequence = 10272
	if err := message.Validate(); err != nil {
		t.Fatalf("a sequence number was rejected: %v", err)
	}
	message.Sequence = -1
	if message.Validate() == nil {
		t.Fatal("a negative sequence number was accepted")
	}
}

// Messages without the new facts must serialize exactly as they did, because
// the encoded message feeds the inbox content digest that deduplicates redelivery.
func TestInboundEncodingOmitsUnsetHistoryFacts(t *testing.T) {
	encoded, err := json.Marshal(groupMessage())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"sequence"`, `"history"`} {
		if strings.Contains(string(encoded), field) {
			t.Fatalf("unset %s appears in %s", field, encoded)
		}
	}

	var old InboundMessage
	if err := json.Unmarshal([]byte(`{"providerEventId":"e","kind":1,"conversationKind":2,"conversation":"QQ-Group:1","occurredAt":"0001-01-01T00:00:00Z"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Sequence != 0 || old.History != InboundHistoryNone {
		t.Fatalf("a stored message without the facts decoded as %+v", old)
	}
}
