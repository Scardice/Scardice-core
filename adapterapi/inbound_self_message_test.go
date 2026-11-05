package adapterapi

import (
	"errors"
	"testing"
)

func selfMessage() InboundMessage {
	return InboundMessage{
		ProviderEventID: "onebot-self-message-9", MessageID: "9", Kind: InboundKindSelfMessage,
		ConversationKind: ConversationKindGroup, Platform: "QQ", Sender: "QQ:3003",
		Conversation: "QQ-Group:2002", Target: "QQ-Group:2002", Text: "hello", Sequence: 12,
	}
}

func TestSelfMessageContract(t *testing.T) {
	valid := selfMessage()
	if err := valid.Validate(); err != nil {
		t.Fatalf("self message rejected: %v", err)
	}
	direct := valid
	direct.ConversationKind, direct.Conversation, direct.Target = ConversationKindDirect, "QQ:1001", "QQ:1001"
	if err := direct.Validate(); err != nil {
		t.Fatalf("direct self message rejected: %v", err)
	}
	core := valid
	core.SelfOrigin = SelfMessageIssuedByCore
	if err := core.Validate(); err != nil {
		t.Fatalf("core-issued self message rejected: %v", err)
	}
	recovered := valid
	recovered.History = InboundHistoryRecordOnly
	if err := recovered.Validate(); err != nil {
		t.Fatalf("recovered self message rejected: %v", err)
	}

	invalid := map[string]func(*InboundMessage){
		"no message id":           func(m *InboundMessage) { m.MessageID = "" },
		"no sender":               func(m *InboundMessage) { m.Sender = "" },
		"no conversation":         func(m *InboundMessage) { m.Conversation, m.Target = "", "" },
		"inconsistent target":     func(m *InboundMessage) { m.Target = "QQ-Group:1" },
		"unknown origin":          func(m *InboundMessage) { m.SelfOrigin = SelfMessageIssuedByCore + 1 },
		"history on direct":       func(m *InboundMessage) { m.ConversationKind, m.History = ConversationKindDirect, InboundHistoryExecute },
		"origin on ordinary":      func(m *InboundMessage) { m.Kind, m.SelfOrigin = InboundKindMessage, SelfMessageIssuedByCore },
		"unknown kind after self": func(m *InboundMessage) { m.Kind = InboundKindSelfMessage + 1 },
	}
	for name, mutate := range invalid {
		m := selfMessage()
		mutate(&m)
		if err := m.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s: err = %v, want invalid contract", name, err)
		}
	}
}

func TestHistoryAnswerMayHoldSelfMessages(t *testing.T) {
	request := QueryRequest{EndpointID: "endpoint-1", Kind: QueryKindGroupHistory, Group: "QQ-Group:2002", AfterSequence: 10, BeforeSequence: 20, Limit: 10}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	result := QueryResult{History: []InboundMessage{selfMessage()}}
	if err := result.Validate(request); err != nil {
		t.Fatalf("history with a self message rejected: %v", err)
	}
}
