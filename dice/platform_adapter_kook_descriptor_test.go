package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
)

func TestKookDescriptorRunsGatewayIngressAndOutbound(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	messageSeen := make(chan struct{}, 1)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bot runtime-token" {
			http.Error(writer, "invalid authorization", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v3/gateway/index":
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"url": "ws" + strings.TrimPrefix(server.URL, "http") + "/gateway"}})
		case "/api/v3/user/me":
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"id": "bot-1", "nickname": "Scardice"}})
		case "/api/v3/message/create":
			var body struct {
				TargetID string `json:"target_id"`
				Type     int    `json:"type"`
				Content  string `json:"content"`
			}
			var cards []struct {
				Type    string `json:"type"`
				Modules []struct {
					Type string `json:"type"`
					Text struct {
						Content string `json:"content"`
						Type    string `json:"type"`
					} `json:"text"`
				} `json:"modules"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil ||
				json.Unmarshal([]byte(body.Content), &cards) != nil ||
				body.TargetID != "channel-1" ||
				body.Type != 7 ||
				len(cards) != 1 ||
				cards[0].Type != "card" ||
				len(cards[0].Modules) != 1 ||
				cards[0].Modules[0].Type != "section" ||
				cards[0].Modules[0].Text.Content != "hello outbound" ||
				cards[0].Modules[0].Text.Type != "plain-text" {
				http.Error(writer, "invalid message", http.StatusBadRequest)
				return
			}
			messageSeen <- struct{}{}
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"msg_id": "message-2"}})
		case "/gateway":
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.WriteJSON(map[string]any{"s": 1, "d": map[string]any{"code": 0, "session_id": "session-1"}})
			_ = connection.WriteJSON(map[string]any{"s": 0, "sn": 1, "d": map[string]any{"channel_type": "GROUP", "type": 1, "target_id": "channel-1", "author_id": "user-1", "content": "hello inbound", "msg_id": "message-1", "msg_timestamp": 1_700_000_000_000, "extra": map[string]any{"guild_id": "guild-1", "author": map[string]any{"id": "user-1", "nickname": "alice"}}}})
			for {
				if _, _, err := connection.ReadMessage(); err != nil {
					return
				}
			}
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	descriptor := NewKookDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","guild":"","channel":"","apiBaseURL":"`+server.URL+`","token":{"secretRef":"kook-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "kook-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "kook-message-created:message-1" || inbound.Conversation != "KOOK-CH-Group:channel-1" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Kook inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "KOOK-CH-Group:channel-1"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "message-2" {
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
		t.Fatal("Kook runtime did not stop")
	}
}

func TestKookDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewKookDescriptor,
		Config:                       json.RawMessage(`{"version":"1","guild":"","channel":"","apiBaseURL":"","token":{"secretRef":"kook-token","version":1}}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "kook-contract", Generation: 1, DesiredVersion: 1},
		SecretValues:                 []string{"runtime-token"},
		RequireOwnedResourceManifest: true,
	})
}
