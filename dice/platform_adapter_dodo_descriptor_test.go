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

func TestDodoDescriptorRunsWebSocketIngressAndOutbound(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	messageSeen := make(chan struct{}, 1)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bot client-1.runtime-token" {
			http.Error(writer, "invalid authorization", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v2/bot/info":
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": 0, "data": map[string]string{"dodoSourceId": "bot-1", "nickName": "Scardice"}})
		case "/api/v2/websocket/connection":
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": 0, "data": map[string]string{"endpoint": "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"}})
		case "/api/v2/channel/message/send":
			var body struct {
				ChannelID   string `json:"channelId"`
				MessageType int    `json:"messageType"`
				MessageBody struct {
					Card json.RawMessage `json:"card"`
				} `json:"messageBody"`
			}
			var card struct {
				Type       string `json:"type"`
				Components []struct {
					Type string `json:"type"`
					Text struct {
						Content string `json:"content"`
						Type    string `json:"type"`
					} `json:"text"`
				} `json:"components"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil ||
				json.Unmarshal(body.MessageBody.Card, &card) != nil ||
				body.ChannelID != "channel-1" ||
				body.MessageType != 6 ||
				card.Type != "card" ||
				len(card.Components) != 1 ||
				card.Components[0].Type != "section" ||
				card.Components[0].Text.Content != "hello outbound" ||
				card.Components[0].Text.Type != "dodo-md" {
				http.Error(writer, "invalid message", http.StatusBadRequest)
				return
			}
			messageSeen <- struct{}{}
			_ = json.NewEncoder(writer).Encode(map[string]any{"status": 0, "data": map[string]string{"messageId": "message-2"}})
		case "/socket":
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.WriteJSON(map[string]any{"type": 0, "data": map[string]any{"eventId": "event-1", "eventType": "2001", "timestamp": 1_700_000_000_000, "eventBody": map[string]any{"islandSourceId": "island-1", "channelId": "channel-1", "dodoSourceId": "user-1", "messageId": "message-1", "messageType": 1, "messageBody": map[string]string{"content": "hello inbound"}}}})
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

	descriptor := NewDodoDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"islandId":"island-1","botId":"","clientID":"client-1","apiBaseURL":"`+server.URL+`","token":{"secretRef":"dodo-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "dodo-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "event-1" || inbound.MessageID != "message-1" || inbound.Conversation != "DODO-Group:channel-1" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Dodo inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "DODO-Group:channel-1"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
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
		t.Fatal("Dodo runtime did not stop")
	}
}

func TestDodoDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewDodoDescriptor,
		Config:                       json.RawMessage(`{"islandId":"island-1","botId":"","clientID":"client-1","apiBaseURL":"","token":{"secretRef":"dodo-token","version":1}}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "dodo-contract", Generation: 1, DesiredVersion: 1},
		SecretValues:                 []string{"runtime-token"},
		RequireOwnedResourceManifest: true,
	})
}
