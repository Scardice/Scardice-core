package adapterapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func adapterEventInbound(raw string) InboundMessage {
	return InboundMessage{
		ProviderEventID:  "onebot-adapter-event-1",
		Platform:         "QQ",
		Sender:           "QQ:1001",
		Conversation:     "QQ-Group:2002",
		ConversationKind: ConversationKindGroup,
		Target:           "QQ-Group:2002",
		Kind:             InboundKindAdapterEvent,
		AdapterEvent: &AdapterEvent{
			Protocol: "onebot11",
			Type:     "notice",
			RawJSON:  raw,
		},
	}
}

func TestInboundAdapterEventRequiresRawEventAndConversationIdentity(t *testing.T) {
	valid := adapterEventInbound(`{"post_type":"notice","notice_type":"group_admin"}`)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid adapter event: %v", err)
	}

	invalid := map[string]InboundMessage{
		"missing event": func() InboundMessage {
			message := valid
			message.AdapterEvent = nil
			return message
		}(),
		"missing conversation": func() InboundMessage {
			message := valid
			message.Conversation = ""
			message.Target = ""
			return message
		}(),
		"different target": func() InboundMessage {
			message := valid
			message.Target = "QQ-Group:elsewhere"
			return message
		}(),
		"invalid raw JSON": func() InboundMessage {
			message := valid
			event := *message.AdapterEvent
			event.RawJSON = `[]`
			message.AdapterEvent = &event
			return message
		}(),
		"oversized raw JSON": func() InboundMessage {
			message := valid
			event := *message.AdapterEvent
			event.RawJSON = `{"value":"` + strings.Repeat("x", MaxProtocolJSONBytes) + `"}`
			message.AdapterEvent = &event
			return message
		}(),
	}
	for name, message := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := message.Validate(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func TestInboundAdapterEventRawJSONSurvivesDurableJSONRoundTrip(t *testing.T) {
	const raw = " {\n  \"post_type\" : \"notice\", \"value\" : 900719925474099312345\n} "
	message := adapterEventInbound(raw)
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded InboundMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.AdapterEvent == nil || decoded.AdapterEvent.RawJSON != raw {
		t.Fatalf("raw JSON changed: %#v", decoded.AdapterEvent)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("round-tripped event: %v", err)
	}

	legacy := []byte(`{"providerEventId":"p","messageId":"m","platform":"QQ","sender":"QQ:1","conversation":"QQ-Group:2","conversationKind":2,"kind":1,"text":"hi","occurredAt":"2026-01-01T00:00:00Z"}`)
	var old InboundMessage
	if err := json.Unmarshal(legacy, &old); err != nil || old.AdapterEvent != nil || old.Validate() != nil {
		t.Fatalf("legacy row = %#v, decode=%v, validate=%v", old, err, old.Validate())
	}
}

func TestNormalizedInboundMayCarryOneValidatedAdapterEvent(t *testing.T) {
	message := eventMessage(InboundKindNotice, InboundEventPoke)
	message.AdapterEvent = &AdapterEvent{Protocol: "onebot11", Type: "notice", RawJSON: `{"post_type":"notice","sub_type":"poke"}`}
	if err := message.Validate(); err != nil {
		t.Fatalf("typed event with raw adapter event: %v", err)
	}
	message.AdapterEvent.RawJSON = `{broken`
	if err := message.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("invalid attached event accepted: %v", err)
	}
}
