package adapterapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMemberRoleQueryRequiresAWellFormedGroupAndMember(t *testing.T) {
	valid := QueryRequest{EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
	invalid := map[string]QueryRequest{
		"no endpoint":     {Kind: QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003"},
		"unknown kind":    {EndpointID: "endpoint-1", Kind: QueryKindInvalid, Group: "QQ-Group:2002", Member: "QQ:3003"},
		"future kind":     {EndpointID: "endpoint-1", Kind: QueryKindMemberRole + 1, Group: "QQ-Group:2002", Member: "QQ:3003"},
		"no group":        {EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Member: "QQ:3003"},
		"no member":       {EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: "QQ-Group:2002"},
		"padded group":    {EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: " QQ-Group:2002", Member: "QQ:3003"},
		"padded member":   {EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003 "},
		"oversized group": {EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: ConversationID(strings.Repeat("g", MaxIdentifierBytes+1)), Member: "QQ:3003"},
	}
	for name, request := range invalid {
		if err := request.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestQueryResultAcceptsOnlyTheClosedRoleVocabulary(t *testing.T) {
	for _, role := range []string{"owner", "admin", "member"} {
		if err := (QueryResult{Role: role}).Validate(QueryRequest{Kind: QueryKindMemberRole}); err != nil {
			t.Errorf("role %q rejected: %v", role, err)
		}
	}
	for _, role := range []string{"", "OWNER", "creator", "administrator", " admin"} {
		if err := (QueryResult{Role: role}).Validate(QueryRequest{Kind: QueryKindMemberRole}); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("role %q accepted: %v", role, err)
		}
	}
}

func TestInboundNamesAreBoundedTextAndSurviveTheDurableRoundTrip(t *testing.T) {
	message := eventMessage(InboundKindNotice, InboundEventMemberJoined)
	message.SenderName, message.SubjectName, message.ConversationName = "爱丽丝", "鲍勃 \"Bob\"", "测试群 <1>"
	if err := message.Validate(); err != nil {
		t.Fatalf("named inbound rejected: %v", err)
	}
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded InboundMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SenderName != "爱丽丝" || decoded.SubjectName != "鲍勃 \"Bob\"" || decoded.ConversationName != "测试群 <1>" {
		t.Fatalf("round trip lost names: %#v", decoded)
	}

	// Names are display text, not identifiers: padding and inner spaces are legitimate.
	spaced := eventMessage(InboundKindMessage, InboundEventNone)
	spaced.SenderName = " 带 空格 的 昵称 "
	if err := spaced.Validate(); err != nil {
		t.Fatalf("display name with spaces rejected: %v", err)
	}

	for name, mutate := range map[string]func(*InboundMessage){
		"oversized sender name":       func(m *InboundMessage) { m.SenderName = strings.Repeat("名", MaxInboundFieldBytes) },
		"oversized subject name":      func(m *InboundMessage) { m.SubjectName = strings.Repeat("a", MaxInboundFieldBytes+1) },
		"oversized conversation name": func(m *InboundMessage) { m.ConversationName = strings.Repeat("a", MaxInboundFieldBytes+1) },
		"invalid utf-8 sender name":   func(m *InboundMessage) { m.SenderName = string([]byte{0xff, 0xfe}) },
	} {
		candidate := eventMessage(InboundKindMessage, InboundEventNone)
		mutate(&candidate)
		if utf8.ValidString(candidate.SenderName+candidate.SubjectName+candidate.ConversationName) && len(candidate.SenderName) <= MaxInboundFieldBytes &&
			len(candidate.SubjectName) <= MaxInboundFieldBytes && len(candidate.ConversationName) <= MaxInboundFieldBytes {
			t.Fatalf("%s: fixture is not actually invalid", name)
		}
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}
