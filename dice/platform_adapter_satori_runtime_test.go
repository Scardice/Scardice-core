package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

func TestSatoriDescriptorRunsWebSocketIngressLifecycle(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/events" {
			http.NotFound(writer, request)
			return
		}
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		_, identify, err := connection.ReadMessage()
		if err != nil {
			return
		}
		var payload SatoriPayload[SatoriIdentify]
		if json.Unmarshal(identify, &payload) != nil || payload.Body == nil || payload.Body.Token != "runtime-token" {
			return
		}
		_ = connection.WriteJSON(map[string]any{"op": SatoriOpReady, "body": map[string]any{"logins": []any{map[string]any{"self_id": "bot-1", "platform": "qq", "user": map[string]any{"id": "bot-1", "name": "Satori Bot"}}}}})
		_ = connection.WriteJSON(map[string]any{"op": SatoriOpEvent, "body": map[string]any{"id": 42, "type": "message-created", "platform": "qq", "timestamp": 1_700_000_000_123, "message": map[string]any{"id": "msg-1", "content": "hello", "user": map[string]any{"id": "user-1"}, "guild": map[string]any{"id": "guild-1"}}}})
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	descriptor := NewSatoriDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"v1","platform":"qq","host":"`+serverURL.Hostname()+`","port":`+strconv.Itoa(port)+`,"token":{"secretRef":"satori-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "satori-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "42" || inbound.Text != "hello" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Satori inbound")
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
		t.Fatal("Satori runtime did not stop")
	}
}
