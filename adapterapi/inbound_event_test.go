package adapterapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func eventMessage(kind InboundKind, event InboundEventKind) InboundMessage {
	return InboundMessage{
		ProviderEventID: "event-1", Kind: kind, Event: event,
		ConversationKind: ConversationKindGroup, Platform: "QQ",
		Sender: "QQ:1001", Conversation: "QQ-Group:2002", Target: "QQ-Group:2002",
	}
}

func TestInboundNoticeAndRequestRequireTheirTypedEvent(t *testing.T) {
	valid := []InboundMessage{
		eventMessage(InboundKindNotice, InboundEventPoke),
		eventMessage(InboundKindNotice, InboundEventMemberJoined),
		eventMessage(InboundKindNotice, InboundEventSelfJoined),
		eventMessage(InboundKindNotice, InboundEventSelfRemoved),
		eventMessage(InboundKindNotice, InboundEventSelfLeft),
		eventMessage(InboundKindNotice, InboundEventSelfMuted),
		eventMessage(InboundKindNotice, InboundEventFriendAdded),
	}
	for _, kind := range []InboundEventKind{InboundEventFriendRequest, InboundEventGroupInvite} {
		request := eventMessage(InboundKindRequest, kind)
		request.RequestID = "flag-1"
		valid = append(valid, request)
	}
	for _, message := range valid {
		if err := message.Validate(); err != nil {
			t.Errorf("%v/%v rejected: %v", message.Kind, message.Event, err)
		}
	}

	request := eventMessage(InboundKindRequest, InboundEventFriendRequest)
	request.RequestID = "flag-1"
	invalid := map[string]InboundMessage{
		"notice without event":    eventMessage(InboundKindNotice, InboundEventNone),
		"notice carrying request": func() InboundMessage { m := request; m.Kind = InboundKindNotice; return m }(),
		"request with notice event": func() InboundMessage {
			m := eventMessage(InboundKindRequest, InboundEventPoke)
			m.RequestID = "flag-1"
			return m
		}(),
		"request without request id": eventMessage(InboundKindRequest, InboundEventGroupInvite),
		"unknown event":              eventMessage(InboundKindNotice, InboundEventGroupInvite+1),
		"message carrying event":     eventMessage(InboundKindMessage, InboundEventPoke),
		"message carrying request id": func() InboundMessage {
			m := eventMessage(InboundKindMessage, InboundEventNone)
			m.RequestID = "flag"
			return m
		}(),
		"deleted carrying subject": func() InboundMessage {
			m := eventMessage(InboundKindMessageDeleted, InboundEventNone)
			m.Subject = "QQ:1"
			return m
		}(),
		"padded request id": func() InboundMessage { m := request; m.RequestID = " flag "; return m }(),
		"oversized request id": func() InboundMessage {
			m := request
			m.RequestID = strings.Repeat("f", MaxInboundFieldBytes+1)
			return m
		}(),
		"invalid subject": func() InboundMessage {
			m := eventMessage(InboundKindNotice, InboundEventPoke)
			m.Subject = " QQ:1"
			return m
		}(),
		"invalid operator": func() InboundMessage {
			m := eventMessage(InboundKindNotice, InboundEventSelfJoined)
			m.Operator = "QQ:1 "
			return m
		}(),
	}
	for name, message := range invalid {
		if err := message.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestInboundEventFieldsSurviveTheDurableJSONRoundTrip(t *testing.T) {
	message := eventMessage(InboundKindNotice, InboundEventSelfMuted)
	message.Subject, message.Operator, message.DurationSeconds = "QQ:3003", "QQ:1001", 600
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded InboundMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Event != InboundEventSelfMuted || decoded.Subject != "QQ:3003" || decoded.Operator != "QQ:1001" || decoded.DurationSeconds != 600 {
		t.Fatalf("round trip lost event facts: %#v", decoded)
	}

	// Rows written before typed events existed must still decode and validate as messages.
	legacy := []byte(`{"providerEventId":"p","messageId":"m","platform":"QQ","sender":"QQ:1","conversation":"QQ-Group:2","conversationKind":2,"kind":1,"text":"hi","occurredAt":"2026-01-01T00:00:00Z"}`)
	var old InboundMessage
	if err := json.Unmarshal(legacy, &old); err != nil || old.Validate() != nil || old.Event != InboundEventNone {
		t.Fatalf("legacy inbox row: %#v err=%v validate=%v", old, err, old.Validate())
	}
}

func TestInboundFriendRequestPolicyIsClosedAndOnlyOnFriendRequests(t *testing.T) {
	friend := func(policy string) InboundMessage {
		m := eventMessage(InboundKindRequest, InboundEventFriendRequest)
		m.RequestID = "flag-1"
		m.RequestPolicy = policy
		return m
	}
	for _, policy := range []string{"", "accept", "ignore", "manual", "deny"} {
		if err := friend(policy).Validate(); err != nil {
			t.Errorf("policy %q rejected: %v", policy, err)
		}
	}
	invalid := map[string]InboundMessage{
		"unknown policy":   friend("auto"),
		"padded policy":    friend(" accept"),
		"uppercase policy": friend("DENY"),
		"group invite policy": func() InboundMessage {
			m := eventMessage(InboundKindRequest, InboundEventGroupInvite)
			m.RequestID, m.RequestPolicy = "flag-1", "accept"
			return m
		}(),
		"notice policy": func() InboundMessage {
			m := eventMessage(InboundKindNotice, InboundEventFriendAdded)
			m.RequestPolicy = "accept"
			return m
		}(),
		"message policy": func() InboundMessage {
			m := eventMessage(InboundKindMessage, InboundEventNone)
			m.RequestPolicy = "accept"
			return m
		}(),
	}
	for name, message := range invalid {
		if err := message.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}
