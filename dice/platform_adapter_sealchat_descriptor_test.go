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
	sealsatori "Scardice-core/utils/satori"
)

func TestSealChatDescriptorRunsGatewayIngressAndAcknowledgedOutbound(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	outboundSeen := make(chan map[string]any, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		var identify struct {
			Op   int               `json:"op"`
			Body map[string]string `json:"body"`
		}
		if connection.ReadJSON(&identify) != nil || identify.Op != 3 || identify.Body["token"] != "sealchat-runtime-token" {
			return
		}
		_ = connection.WriteJSON(map[string]any{"op": 4, "body": map[string]any{"user": map[string]any{"id": "bot-1", "nick": "Seal Bot"}}})
		_ = connection.WriteJSON(map[string]any{"op": 0, "body": map[string]any{"id": "evt-1", "type": "message-created", "timestamp": 1_700_000_000, "message": map[string]any{"id": "msg-1", "content": `hello <at id="user-2"/>`, "timestamp": 1_700_000_000, "channel": map[string]any{"id": "channel-1", "type": 0}, "user": map[string]any{"id": "user-1", "nick": "Alice"}}}})
		for {
			var frame map[string]any
			if connection.ReadJSON(&frame) != nil {
				return
			}
			if frame["api"] == "channel.private.create" {
				data, _ := frame["data"].(map[string]any)
				if data["user_id"] != "user-private" {
					return
				}
				_ = connection.WriteJSON(map[string]any{"echo": frame["echo"], "data": map[string]any{"id": "direct-1"}})
				continue
			}
			if frame["api"] == "message.create" {
				data, _ := frame["data"].(map[string]any)
				outboundSeen <- data
				messageID := "msg-out-1"
				if data["channel_id"] == "direct-1" {
					messageID = "msg-out-private"
				}
				_ = connection.WriteJSON(map[string]any{"echo": frame["echo"], "data": map[string]any{"id": messageID}})
				continue
			}
			if frame["op"] == float64(1) {
				_ = connection.WriteJSON(map[string]any{"op": 2, "body": map[string]any{}})
			}
		}
	}))
	defer server.Close()

	descriptor := NewSealChatDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","appId":"app-1","tenant":"tenant-1","connectUrl":"ws`+strings.TrimPrefix(server.URL, "http")+`","token":{"secretRef":"sealchat-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "sealchat-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"sealchat-token": []byte("sealchat-runtime-token")}}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "evt-1" || inbound.MessageID != "msg-1" || inbound.Sender != "SEALCHAT:user-1" || inbound.Conversation != "SEALCHAT-Group:channel-1" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello <@user-2>" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SealChat inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "SEALCHAT-Group:channel-1"}, Text: `hello <outbound>`}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "msg-out-1" {
		t.Fatalf("result = %#v", result)
	}
	select {
	case data := <-outboundSeen:
		if data["channel_id"] != "channel-1" || data["content"] != "hello &lt;outbound&gt;" {
			t.Fatalf("outbound data = %#v", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SealChat outbound")
	}
	privateEffect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "SEALCHAT:user-private"}, Text: "private outbound"}, adapterapi.CapabilityOutbound)
	privateResult := runtime.Execute(context.Background(), privateEffect)
	if privateResult.Outcome != adapterapi.EffectSucceeded || privateResult.ProviderID != "msg-out-private" {
		t.Fatalf("private result = %#v", privateResult)
	}
	select {
	case data := <-outboundSeen:
		if data["channel_id"] != "direct-1" || data["content"] != "private outbound" {
			t.Fatalf("private outbound data = %#v", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for private SealChat outbound")
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
		t.Fatal("SealChat runtime did not stop")
	}
}

func TestSealChatOutboundContentMigratesLegacySegments(t *testing.T) {
	content, err := sealChatOutboundContent(adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadSegments,
		Segments: []adapterapi.MessageSegment{
			{Kind: adapterapi.SegmentKindText, Text: `hello <world>`},
			{Kind: adapterapi.SegmentKindMention, Text: "SEALCHAT:user-1"},
			{Kind: adapterapi.SegmentKindMention, Text: "all"},
		},
	})
	if err != nil {
		t.Fatalf("encode segments: %v", err)
	}
	if content != `hello &lt;world&gt;<at id="user-1"/><at type="all"/>` {
		t.Fatalf("content = %q", content)
	}
	_, err = sealChatOutboundContent(adapterapi.EffectPayload{
		Kind:     adapterapi.EffectPayloadSegments,
		Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindImage, Artifact: &adapterapi.ArtifactInput{ID: "artifact-1"}}},
	})
	if err == nil || err.Error() != "sealchat_artifact_reader_unavailable" {
		t.Fatalf("artifact error = %v", err)
	}
}

func TestSealChatDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewSealChatDescriptor,
		Config:                       json.RawMessage(`{"version":"1","appId":"app-1","tenant":"tenant-1","connectUrl":"ws://127.0.0.1:1","token":{"secretRef":"sealchat-token","version":1}}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "sealchat-contract", Generation: 1, DesiredVersion: 1, Secrets: &namedRuntimeResolver{values: map[string][]byte{"sealchat-token": []byte("runtime-token")}}},
		RequireOwnedResourceManifest: true,
	})
}

// sealChatCharacterCore records inbound messages, captures character requests,
// and returns a canned response so the descriptor's relay path can be asserted.
type sealChatCharacterCore struct {
	onebotRuntimeCore
	requests chan adapterapi.CharacterRequest
	response adapterapi.CharacterResponse
}

func (core *sealChatCharacterCore) HandleCharacter(_ context.Context, request adapterapi.CharacterRequest) (adapterapi.CharacterResponse, error) {
	if core.requests != nil {
		core.requests <- request
	}
	return core.response, nil
}

func TestSealChatDescriptorRelaysCharacterAPIRequests(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	responses := make(chan map[string]any, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		var identify struct {
			Op   int               `json:"op"`
			Body map[string]string `json:"body"`
		}
		if connection.ReadJSON(&identify) != nil || identify.Op != 3 {
			return
		}
		_ = connection.WriteJSON(map[string]any{"op": 4, "body": map[string]any{"user": map[string]any{"id": "bot-1", "nick": "Seal Bot"}}})
		_ = connection.WriteJSON(map[string]any{"api": "character.set", "echo": "req-1", "data": map[string]any{"group_id": "channel-1", "user_id": "user-1", "name": "John Doe", "attrs": map[string]any{"Close Combat": 55}}})
		_ = connection.WriteJSON(map[string]any{"api": "character.unknown", "echo": "req-2", "data": map[string]any{}})
		for {
			var frame map[string]any
			if connection.ReadJSON(&frame) != nil {
				return
			}
			if echo, ok := frame["echo"].(string); ok && frame["api"] == "" {
				responses <- map[string]any{"echo": echo, "data": frame["data"]}
			}
		}
	}))
	defer server.Close()

	descriptor := NewSealChatDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","appId":"app-1","tenant":"tenant-1","connectUrl":"ws`+strings.TrimPrefix(server.URL, "http")+`","token":{"secretRef":"sealchat-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "sealchat-character", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"sealchat-token": []byte("sealchat-runtime-token")}}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &sealChatCharacterCore{
		onebotRuntimeCore: onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)},
		requests:          make(chan adapterapi.CharacterRequest, 2),
		response:          adapterapi.CharacterResponse{OK: true, Name: "Alice", SheetType: "coc7", Attributes: map[string]any{"STR": 60}, AttributesSet: true},
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)

	select {
	case request := <-core.requests:
		if request.Operation != adapterapi.CharacterOperationSet || request.GroupID != "channel-1" || request.UserID != "user-1" {
			t.Fatalf("character request = %#v", request)
		}
		if !request.NameSet || request.Name != "John Doe" {
			t.Fatalf("character request name = %#v", request)
		}
		if !request.AttrsSet || request.Attributes["Close Combat"] != float64(55) {
			t.Fatalf("character request attrs = %#v", request)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SealChat character request")
	}
	select {
	case response := <-responses:
		if response["echo"] != "req-1" {
			t.Fatalf("response echo = %#v", response)
		}
		data, _ := response["data"].(map[string]any)
		if data["ok"] != true {
			t.Fatalf("character response data = %#v", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SealChat character response")
	}
	select {
	case response := <-responses:
		if response["echo"] != "req-2" {
			t.Fatalf("unknown api response echo = %#v", response)
		}
		data, _ := response["data"].(map[string]any)
		if data["ok"] != false {
			t.Fatalf("unknown api response = %#v", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for unknown api response")
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
		t.Fatal("SealChat runtime did not stop")
	}
}

func TestSealChatInboundCarriesSenderRole(t *testing.T) {
	build := func(roles []string) adapterapi.InboundMessage {
		event := &sealsatori.Event{
			Type: sealsatori.EventMessageCreated,
			Message: &sealsatori.Message{
				ID:      "msg-1",
				Content: "hello",
				User:    &sealsatori.User{ID: "user-1", Nick: "Alice"},
				Member:  &sealsatori.GuildMember{Roles: roles},
				Channel: &sealsatori.Channel{ID: "channel-1", Type: sealsatori.TextChannelType},
			},
		}
		inbound, err := sealChatInbound(event)
		if err != nil {
			t.Fatalf("sealchat inbound: %v", err)
		}
		return inbound
	}
	if role := build([]string{"owner"}).SenderRole; role != "owner" {
		t.Fatalf("owner role = %q", role)
	}
	if role := build([]string{"moderator"}).SenderRole; role != "admin" {
		t.Fatalf("moderator role = %q", role)
	}
	if role := build(nil).SenderRole; role != "member" {
		t.Fatalf("default role = %q", role)
	}
	if role := build([]string{"everyone"}).SenderRole; role != "member" {
		t.Fatalf("plain role = %q", role)
	}
}

func TestSealChatCharacterLimiterIsPerRuntime(t *testing.T) {
	descriptor := NewSealChatDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","appId":"app-1","tenant":"tenant-1","connectUrl":"ws://127.0.0.1:1","token":{"secretRef":"sealchat-token","version":1}}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	firstRuntime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "sealchat-a", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"sealchat-token": []byte("token-a")}}})
	if err != nil {
		t.Fatalf("new runtime a: %v", err)
	}
	secondRuntime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "sealchat-b", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"sealchat-token": []byte("token-b")}}})
	if err != nil {
		t.Fatalf("new runtime b: %v", err)
	}
	first := firstRuntime.(*sealChatRuntime)
	second := secondRuntime.(*sealChatRuntime)
	// Exhaust endpoint A's burst.
	for i := range 5 {
		if !first.characterLimiter.Allow() {
			t.Fatalf("endpoint A burst exhausted early at %d", i)
		}
	}
	if first.characterLimiter.Allow() {
		t.Fatal("endpoint A limiter should be exhausted")
	}
	// Endpoint B keeps its own independent burst.
	for i := range 5 {
		if !second.characterLimiter.Allow() {
			t.Fatalf("endpoint B burst consumed by endpoint A at %d", i)
		}
	}
}
