package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
)

func TestTelegramDescriptorRunsPollingIngressAndOutbound(t *testing.T) {
	var polls atomic.Int32
	messageSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/botruntime-token/getMe":
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "result": map[string]any{"id": 100, "username": "Scardice", "is_bot": true}})
		case "/botruntime-token/getUpdates":
			if polls.Add(1) == 1 {
				_ = json.NewEncoder(writer).Encode(map[string]any{
					"ok": true,
					"result": []any{map[string]any{
						"update_id": 7,
						"message": map[string]any{
							"message_id": 42,
							"date":       1_700_000_000,
							"text":       "hello inbound",
							"from":       map[string]any{"id": 101, "username": "alice"},
							"chat":       map[string]any{"id": -200, "type": "group", "title": "Group"},
						},
					}},
				})
				return
			}
			select {
			case <-request.Context().Done():
			case <-time.After(50 * time.Millisecond):
				_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "result": []any{}})
			}
		case "/botruntime-token/sendMessage":
			var body struct {
				ChatID int64  `json:"chat_id"`
				Text   string `json:"text"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || body.ChatID != -200 || body.Text != "hello outbound" {
				http.Error(writer, "invalid message", http.StatusBadRequest)
				return
			}
			messageSeen <- struct{}{}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": 43}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	descriptor := NewTelegramDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"chatId":"","webhookUrl":"","proxyURL":"","apiBaseURL":"`+server.URL+`","token":{"secretRef":"telegram-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "telegram-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "telegram-update:7" || inbound.MessageID != "42" || inbound.Conversation != "TG-Group:-200" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Telegram inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "TG-Group:-200"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "43" {
		t.Fatalf("result = %#v", result)
	}
	<-messageSeen
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("stop runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Telegram runtime did not stop")
	}
}

func TestTelegramOutboundSegmentsMigrateTextMentions(t *testing.T) {
	body, err := telegramOutboundBody(adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadSegments,
		Segments: []adapterapi.MessageSegment{
			{Kind: adapterapi.SegmentKindText, Text: "你"},
			{Kind: adapterapi.SegmentKindMention, Text: "TG:42"},
		},
	}, -200)
	if err != nil {
		t.Fatalf("encode segments: %v", err)
	}
	if body.ChatID != -200 || body.Text != "你@42 " || len(body.Entities) != 1 {
		t.Fatalf("body = %#v", body)
	}
	entity := body.Entities[0]
	if entity.Type != "text_mention" || entity.Offset != 1 || entity.Length != 4 || entity.User == nil || entity.User.ID != 42 {
		t.Fatalf("entity = %#v", entity)
	}
	_, err = telegramOutboundBody(adapterapi.EffectPayload{
		Kind:     adapterapi.EffectPayloadSegments,
		Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindImage, Artifact: &adapterapi.ArtifactInput{ID: "artifact-1"}}},
	}, -200)
	if err == nil || err.Error() != "telegram_artifact_reader_unavailable" {
		t.Fatalf("artifact error = %v", err)
	}
}

func TestTelegramDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewTelegramDescriptor,
		Config:                       json.RawMessage(`{"chatId":"","webhookUrl":"","proxyURL":"","apiBaseURL":"","token":{"secretRef":"telegram-token","version":1}}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "telegram-contract", Generation: 1, DesiredVersion: 1},
		SecretValues:                 []string{"runtime-token"},
		RequireOwnedResourceManifest: true,
	})
}
