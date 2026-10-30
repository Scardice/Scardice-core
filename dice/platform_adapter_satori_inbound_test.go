package dice

import (
	"testing"

	"Scardice-core/adapterapi"
)

func TestSatoriMessageCreatedInboundNormalizesProviderIdentity(t *testing.T) {
	inbound, err := satoriMessageCreatedInbound("qq", &SatoriEvent{
		ID:        "evt-1",
		Type:      "message-created",
		Platform:  "qq",
		Timestamp: 1_700_000_000_000,
		Message:   &SatoriMessage{ID: "msg-1", Content: "hello", User: &SatoriUser{ID: "user-1"}, Guild: &SatoriGuild{ID: "guild-1"}},
	})
	if err != nil {
		t.Fatalf("normalize Satori inbound: %v", err)
	}
	if inbound.ProviderEventID != adapterapi.ProviderEventID("evt-1") || inbound.MessageID != adapterapi.MessageID("msg-1") || inbound.Sender != adapterapi.PrincipalID(formatDiceIDSatori("qq", "user-1")) || inbound.Conversation != adapterapi.ConversationID(formatDiceIDSatoriGroup("qq", "guild-1")) || inbound.Text != "hello" || inbound.Kind != adapterapi.InboundKindMessage {
		t.Fatalf("inbound = %#v", inbound)
	}
}

func TestSatoriMessageCreatedInboundRejectsIncompleteProviderFact(t *testing.T) {
	_, err := satoriMessageCreatedInbound("qq", &SatoriEvent{
		ID:      "evt-1",
		Type:    "message-created",
		Message: &SatoriMessage{ID: "msg-1", User: &SatoriUser{}},
	})
	if err == nil {
		t.Fatal("incomplete provider fact was accepted")
	}
}

func TestSatoriMessageCreatedInboundLeavesPrivateConversationEmpty(t *testing.T) {
	inbound, err := satoriMessageCreatedInbound("qq", &SatoriEvent{
		ID:      "evt-private",
		Type:    "message-created",
		Message: &SatoriMessage{ID: "msg-private", User: &SatoriUser{ID: "user-1"}},
	})
	if err != nil {
		t.Fatalf("normalize private Satori inbound: %v", err)
	}
	if inbound.Conversation != "" {
		t.Fatalf("private conversation = %q", inbound.Conversation)
	}
}

func TestSatoriMessageCreatedInboundUsesMillisecondTimestamp(t *testing.T) {
	inbound, err := satoriMessageCreatedInbound("qq", &SatoriEvent{
		ID:        "evt-time",
		Type:      "message-created",
		Timestamp: 1_700_000_000_123,
		Message:   &SatoriMessage{ID: "msg-time", User: &SatoriUser{ID: "user-1"}},
	})
	if err != nil {
		t.Fatalf("normalize timed Satori inbound: %v", err)
	}
	if got := inbound.OccurredAt.UnixMilli(); got != 1_700_000_000_123 {
		t.Fatalf("occurredAt millis = %d", got)
	}
}

func TestSatoriMessageCreatedInboundRejectsMissingEventID(t *testing.T) {
	_, err := satoriMessageCreatedInbound("qq", &SatoriEvent{
		Type:    "message-created",
		Message: &SatoriMessage{ID: "msg-1", User: &SatoriUser{ID: "user-1"}},
	})
	if err == nil {
		t.Fatal("missing provider event ID was accepted")
	}
}

func TestSatoriMessageCreatedInboundRejectsEmptyGuildID(t *testing.T) {
	_, err := satoriMessageCreatedInbound("qq", &SatoriEvent{
		ID:      "evt-1",
		Type:    "message-created",
		Message: &SatoriMessage{ID: "msg-1", User: &SatoriUser{ID: "user-1"}, Guild: &SatoriGuild{}},
	})
	if err == nil {
		t.Fatal("empty guild ID was accepted")
	}
}

func TestSatoriMessageMutationInboundNormalizesUpdateAndDelete(t *testing.T) {
	tests := []struct {
		name string
		kind adapterapi.InboundKind
		typ  string
		text string
	}{
		{name: "updated", kind: adapterapi.InboundKindMessageUpdated, typ: "message-updated", text: "edited"},
		{name: "deleted", kind: adapterapi.InboundKindMessageDeleted, typ: "message-deleted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inbound, err := satoriMessageMutationInbound("qq", &SatoriEvent{
				ID:        "mutation-1",
				Type:      test.typ,
				Timestamp: 1_700_000_000_123,
				Message:   &SatoriMessage{ID: "msg-1", Content: test.text},
				User:      &SatoriUser{ID: "user-1"},
				Channel:   &SatoriChannel{ID: "guild-1", Type: SatoriTextChannel},
			})
			if err != nil {
				t.Fatalf("normalize mutation: %v", err)
			}
			if inbound.Kind != test.kind || inbound.MessageID != "msg-1" || inbound.Conversation != adapterapi.ConversationID(formatDiceIDSatoriGroup("qq", "guild-1")) || inbound.Text != test.text {
				t.Fatalf("inbound = %#v", inbound)
			}
		})
	}
}
