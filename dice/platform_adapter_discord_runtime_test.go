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
)

func TestDiscordDescriptorRunsGatewayLifecycleAndIngress(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v10/gateway":
			if request.Header.Get("Authorization") != "Bot runtime-token" {
				http.Error(writer, "invalid authorization", http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{"url": "ws" + strings.TrimPrefix(server.URL, "http") + "/gateway"})
		case "/gateway":
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.WriteJSON(map[string]any{"op": 10, "d": map[string]any{"heartbeat_interval": 5_000}})
			_, identify, err := connection.ReadMessage()
			if err != nil {
				return
			}
			var payload struct {
				Op int `json:"op"`
				D  struct {
					Token   string `json:"token"`
					Intents int    `json:"intents"`
				} `json:"d"`
			}
			if json.Unmarshal(identify, &payload) != nil || payload.Op != 2 || payload.D.Token != "runtime-token" || payload.D.Intents == 0 {
				return
			}
			_ = connection.WriteJSON(map[string]any{"op": 0, "t": "READY", "s": 1, "d": map[string]any{"user": map[string]any{"id": "bot-1", "username": "Scardice"}}})
			_ = connection.WriteJSON(map[string]any{"op": 0, "t": "MESSAGE_CREATE", "s": 2, "d": map[string]any{"id": "message-1", "channel_id": "channel-1", "guild_id": "guild-1", "content": "hello", "timestamp": "2023-11-14T22:13:20Z", "author": map[string]any{"id": "user-1", "username": "alice"}}})
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

	descriptor := NewDiscordDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","guild":"","channel":"","token":{"secretRef":"discord-token","version":1},"proxyURL":"","reverseProxyUrl":"`+server.URL+`","reverseProxyCDNUrl":""}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "discord-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "discord-message-created:message-1" || inbound.Text != "hello" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Discord inbound")
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("stop runtime: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Discord runtime did not stop")
	}
}
