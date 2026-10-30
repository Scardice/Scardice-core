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

func TestWalleQDescriptorRunsExternalV12Lifecycle(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			_, payload, err := connection.ReadMessage()
			if err != nil {
				return
			}
			var command struct {
				Action string `json:"action"`
				Echo   string `json:"echo"`
			}
			if json.Unmarshal(payload, &command) != nil {
				return
			}
			if command.Action != "get_self_info" {
				continue
			}
			if err := connection.WriteJSON(map[string]any{
				"status": "ok", "retcode": 0, "echo": command.Echo,
				"data": map[string]any{"user_id": "10001", "user_name": "walleq-bot"},
			}); err != nil {
				return
			}
			_ = connection.WriteJSON(map[string]any{
				"id": "event-1", "type": "message", "detail_type": "group", "time": 1700000000,
				"user_id": "42", "user_card": "alice", "group_id": "9", "message_id": "message-1", "alt_message": "hello",
			})
		}
	}))
	defer server.Close()

	descriptor := NewWalleQDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"connectUrl":`+strconvQuote("ws"+strings.TrimPrefix(server.URL, "http"))+`}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "walleq-contract", Generation: 1, DesiredVersion: 1, Config: config})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateStarting)
	identity := core.waitIdentity(t)
	if identity.ProviderID != "QQ:10001" {
		t.Fatalf("provider identity = %q", identity.ProviderID)
	}
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "event-1" || inbound.Sender != "QQ:42" || inbound.Conversation != "QQ-Group:9" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello" {
			t.Fatalf("normalized inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for WalleQ inbound")
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

func TestWalleQDescriptorRejectsMalformedTrailingJSON(t *testing.T) {
	descriptor := NewWalleQDescriptor()
	if _, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"connectUrl":"ws://127.0.0.1:1/ws"} invalid`)); err == nil {
		t.Fatal("WalleQ descriptor accepted malformed trailing JSON")
	}
}

func TestWalleQDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor: NewWalleQDescriptor,
		Config:        json.RawMessage(`{"connectUrl":"ws://127.0.0.1:1/ws"}`),
		Init: adapterapi.RuntimeInit{
			EndpointID:     "walleq-contract",
			Generation:     1,
			DesiredVersion: 1,
			ResourceRoot:   t.TempDir(),
		},
		RequireOwnedResourceManifest: true,
	})
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
