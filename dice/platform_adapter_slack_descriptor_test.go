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

func TestSlackDescriptorRunsSocketModeIngressAndOutbound(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ackSeen := make(chan struct{}, 1)
	messageSeen := make(chan struct{}, 1)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/auth.test":
			if request.Header.Get("Authorization") != "Bearer xoxb-runtime" {
				http.Error(writer, "invalid bot token", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "user": "Scardice", "user_id": "U-BOT", "team_id": "T1"})
		case "/api/apps.connections.open":
			if request.Header.Get("Authorization") != "Bearer xapp-runtime" {
				http.Error(writer, "invalid app token", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "url": "ws" + strings.TrimPrefix(server.URL, "http") + "/socket"})
		case "/api/chat.postMessage":
			var body struct {
				Channel string `json:"channel"`
				Text    string `json:"text"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || body.Channel != "C1" || body.Text != "hello outbound" {
				http.Error(writer, "invalid message", http.StatusBadRequest)
				return
			}
			messageSeen <- struct{}{}
			_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "channel": "C1", "ts": "1700000001.000200"})
		case "/socket":
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.WriteJSON(map[string]any{"type": "hello", "connection_info": map[string]any{"app_id": "A1"}})
			_ = connection.WriteJSON(map[string]any{"type": "events_api", "envelope_id": "E1", "payload": map[string]any{"team_id": "T1", "event_id": "Ev1", "event": map[string]any{"type": "message", "user": "U1", "text": "hello inbound", "channel": "C1", "channel_type": "channel", "client_msg_id": "M1", "ts": "1700000000.000100"}}})
			var ack map[string]any
			if connection.ReadJSON(&ack) == nil && ack["envelope_id"] == "E1" {
				ackSeen <- struct{}{}
			}
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

	descriptor := NewSlackDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","channel":"","apiBaseURL":"`+server.URL+`/api","appToken":{"secretRef":"slack-app-token","version":1},"botToken":{"secretRef":"slack-bot-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "slack-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"slack-app-token": []byte("xapp-runtime"), "slack-bot-token": []byte("xoxb-runtime")}}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "slack-envelope:E1" || inbound.MessageID != "M1" || inbound.Conversation != "SLACK-CH-Group:C1" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Slack inbound")
	}
	<-ackSeen
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "SLACK-CH-Group:C1"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "1700000001.000200" {
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
		t.Fatal("Slack runtime did not stop")
	}
}

func TestSlackDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewSlackDescriptor,
		Config:                       json.RawMessage(`{"version":"1","channel":"","apiBaseURL":"","appToken":{"secretRef":"slack-app-token","version":1},"botToken":{"secretRef":"slack-bot-token","version":1}}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "slack-contract", Generation: 1, DesiredVersion: 1},
		SecretValues:                 []string{"xapp-runtime", "xoxb-runtime"},
		RequireOwnedResourceManifest: true,
	})
}

type namedRuntimeResolver struct {
	values map[string][]byte
}

func (resolver *namedRuntimeResolver) Resolve(_ context.Context, ref adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	return adapterapi.SecretValue{Bytes: append([]byte(nil), resolver.values[ref.Ref]...), Version: ref.Version}, nil
}
