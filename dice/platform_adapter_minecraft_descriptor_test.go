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

func TestMinecraftDescriptorRunsWebSocketIngressAndUnacknowledgedOutbound(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	outboundSeen := make(chan SendMessageMinecraft, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.WriteJSON(MessageMinecraft{Type: "message", Event: &MessageEvent{Content: "hello inbound", Name: "alice", UUID: "user-1", MessageType: "group"}})
		var outbound SendMessageMinecraft
		if connection.ReadJSON(&outbound) == nil {
			outboundSeen <- outbound
		}
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	descriptor := NewMinecraftDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"serverAddress":"server","username":"Scardice","authMode":"none","connectUrl":"ws`+strings.TrimPrefix(server.URL, "http")+`"}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "minecraft-smoke", Generation: 1, DesiredVersion: 1, Config: config})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.Sender != "MC:user-1" || inbound.Conversation != "MC:server" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Minecraft inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "MC:server"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectAmbiguous || result.Code != "minecraft_unacknowledged" {
		t.Fatalf("result = %#v", result)
	}
	select {
	case outbound := <-outboundSeen:
		if outbound.Content != "hello outbound" || outbound.MessageType != "group" {
			t.Fatalf("outbound = %#v", outbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Minecraft outbound")
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
		t.Fatal("Minecraft runtime did not stop")
	}
}

func TestMinecraftDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewMinecraftDescriptor,
		Config:                       json.RawMessage(`{"serverAddress":"server","username":"Scardice","authMode":"none","connectUrl":"ws://127.0.0.1:1"}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "minecraft-contract", Generation: 1, DesiredVersion: 1},
		RequireOwnedResourceManifest: true,
	})
}

func TestMinecraftHandleMessageStampsAdminSenderRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "admin", body: `{"event":{"content":"hi","isAdmin":true,"name":"Alice","uuid":"uuid-1","messageType":"group"}}`, want: "admin"},
		{name: "ordinary", body: `{"event":{"content":"hi","isAdmin":false,"name":"Alice","uuid":"uuid-1","messageType":"group"}}`, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 1), inboundCh: make(chan adapterapi.InboundMessage, 1)}
			if err := minecraftHandleMessage(t.Context(), core, []byte(tc.body)); err != nil {
				t.Fatalf("handle message: %v", err)
			}
			inbound := <-core.inboundCh
			if inbound.SenderRole != tc.want {
				t.Fatalf("SenderRole = %q, want %q", inbound.SenderRole, tc.want)
			}
		})
	}
}
