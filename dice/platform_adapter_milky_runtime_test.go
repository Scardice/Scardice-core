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

func TestMilkyDescriptorRunsExternalLifecycleAndIngress(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ws":
			if request.URL.Query().Get("access_token") != "runtime-token" {
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.WriteJSON(map[string]any{"event_type": "message_receive", "data": map[string]any{"peer_id": 200, "message_seq": 42, "sender_id": 100, "time": 1_700_000_000, "message_scene": "group", "segments": []any{map[string]any{"type": "text", "data": map[string]any{"text": "hello"}}}}})
			for {
				if _, _, err := connection.ReadMessage(); err != nil {
					return
				}
			}
		case "/get_login_info":
			if request.Header.Get("Authorization") != "Bearer runtime-token" {
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"status":"ok","retcode":0,"data":{"uin":123,"nickname":"Milky Bot"}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	descriptor := NewMilkyDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":1,"ws_gateway":"`+"ws"+strings.TrimPrefix(server.URL, "http")+`/ws","rest_gateway":"`+server.URL+`","token":{"secretRef":"milky-token","version":1},"built_in_mode":"","ignore_friend_request":false}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "milky-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &onebotRuntimeResolver{bytes: []byte("runtime-token")}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "milky-message:group:200:42" || inbound.Text != "hello" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Milky inbound")
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
		t.Fatal("Milky runtime did not stop")
	}
}
