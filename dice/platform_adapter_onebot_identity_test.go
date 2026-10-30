package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
)

func TestOnebotInboundPreservesOpaqueGuildAndMessageIDs(t *testing.T) {
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 2)}
	runtime := &onebotRuntime{core: core}
	const firstMessageID = "BAC3A650-29D8-4A55-8DDB-CE07C726A913=="
	const secondMessageID = "BAC3A650-29D8-4A55-8DDB-CE07C726A914=="
	for _, messageID := range []string{firstMessageID, secondMessageID} {
		raw := []byte(`{"post_type":"message","message_type":"guild","time":1700000000,"user_id":"144115218731218202","guild_id":"515151515151","channel_id":"3574366","message_id":"` + messageID + `","message":"hello"}`)
		if err := runtime.handleInbound(context.Background(), raw); err != nil {
			t.Fatalf("handle inbound %q: %v", messageID, err)
		}
	}
	first, second := <-core.inboundCh, <-core.inboundCh
	if first.Kind != adapterapi.InboundKindMessage || first.ConversationKind != adapterapi.ConversationKindGroup || first.Conversation != "QQ-CH-Group:515151515151-3574366" || first.Target != string(first.Conversation) {
		t.Fatalf("guild message identity or conversation = %#v", first)
	}
	if first.MessageID != firstMessageID || first.ProviderEventID != "onebot-message-"+firstMessageID {
		t.Fatalf("opaque first message identity = %#v", first)
	}
	if second.Kind != adapterapi.InboundKindMessage || second.MessageID != secondMessageID || second.ProviderEventID != "onebot-message-"+secondMessageID || first.ProviderEventID == second.ProviderEventID {
		t.Fatalf("opaque second message identity = %#v", second)
	}
}

func TestOnebotUnsupportedRequestIsRetainedWithoutStoppingWorker(t *testing.T) {
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime := &onebotRuntime{core: core}
	raw := []byte(`{"post_type":"request","request_type":"guild_invite","flag":"x","user_id":"2001","time":1700000000}`)
	if err := runtime.processRuntimeEvent(context.Background(), onebotRuntimeEvent{kind: "inbound", raw: raw}); err != nil {
		t.Fatalf("unsupported request stopped worker: %v", err)
	}
	if got := runtime.inboundRejected.Load(); got != 0 {
		t.Fatalf("retained event count = %d, want 0 rejected", got)
	}
	message := <-core.inboundCh
	if message.Kind != adapterapi.InboundKindAdapterEvent || message.Conversation != "QQ:2001" ||
		message.AdapterEvent == nil || message.AdapterEvent.RawJSON != string(raw) {
		t.Fatalf("unsupported request passthrough = %#v", message)
	}
}

func TestOnebotMessageRequiresStableIdentityAndKeepsWorkerRunning(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "private message missing sender",
			raw:  `{"post_type":"message","message_type":"private","message_id":"stable-1","message":"hello"}`,
		},
		{
			name: "private message missing message ID",
			raw:  `{"post_type":"message","message_type":"private","user_id":"2001","message":"hello"}`,
		},
		{
			name: "null sender",
			raw:  `{"post_type":"message","message_type":"private","user_id":null,"message_id":"stable-1","message":"hello"}`,
		},
		{
			name: "malformed sender",
			raw:  `{"post_type":"message","message_type":"private","user_id":{},"message_id":"stable-1","message":"hello"}`,
		},
		{
			name: "invalid sender",
			raw:  `{"post_type":"message","message_type":"private","user_id":"bad id","message_id":"stable-1","message":"hello"}`,
		},
		{
			name: "null message ID",
			raw:  `{"post_type":"message","message_type":"private","user_id":"2001","message_id":null,"message":"hello"}`,
		},
		{
			name: "malformed message ID",
			raw:  `{"post_type":"message","message_type":"private","user_id":"2001","message_id":[],"message":"hello"}`,
		},
		{
			name: "invalid message ID",
			raw:  `{"post_type":"message","message_type":"private","user_id":"2001","message_id":"bad id","message":"hello"}`,
		},
		{
			name: "invalid group ID",
			raw:  `{"post_type":"message","message_type":"group","user_id":"2001","message_id":"stable-1","group_id":"bad id","message":"hello"}`,
		},
	}
	validRaw := []byte(`{"post_type":"message","message_type":"private","user_id":"2001","message_id":"stable-after-reject","message":"still running"}`)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
			runtime := &onebotRuntime{core: core}
			raw := []byte(test.raw)

			if err := runtime.handleInbound(context.Background(), raw); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
				t.Fatalf("handle inbound error = %v, want unsupported event", err)
			}
			if err := runtime.processRuntimeEvent(context.Background(), onebotRuntimeEvent{kind: "inbound", raw: raw}); err != nil {
				t.Fatalf("rejected identity stopped worker: %v", err)
			}
			if got := runtime.inboundRejected.Load(); got != 1 {
				t.Fatalf("rejected event count = %d, want 1", got)
			}
			select {
			case message := <-core.inboundCh:
				t.Fatalf("invalid identity reached Core: %#v", message)
			default:
			}

			if err := runtime.processRuntimeEvent(context.Background(), onebotRuntimeEvent{kind: "inbound", raw: validRaw}); err != nil {
				t.Fatalf("worker did not survive rejected identity: %v", err)
			}
			select {
			case message := <-core.inboundCh:
				if message.Kind != adapterapi.InboundKindMessage || message.Sender != "QQ:2001" || message.MessageID != "stable-after-reject" ||
					message.ProviderEventID != "onebot-message-stable-after-reject" {
					t.Fatalf("valid message after rejection = %#v", message)
				}
			default:
				t.Fatal("valid message after rejection did not reach Core")
			}
		})
	}
}
