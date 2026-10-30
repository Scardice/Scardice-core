package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
)

func TestRedDescriptorRunsIngressAndAcknowledgedOutbound(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	outboundSeen := make(chan RedMessageSend, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		var identify RedPack[RedConnectReq]
		if connection.ReadJSON(&identify) != nil || identify.Type != "meta::connect" || identify.Payload == nil || identify.Payload.Token != "red-runtime-token" {
			return
		}
		_ = connection.WriteJSON(map[string]any{"type": "meta::connect::reply", "payload": map[string]any{"version": "1.2.3", "name": "red", "authData": map[string]any{"uin": "10000", "nickName": "Red Bot"}}})
		_ = connection.WriteJSON(map[string]any{"type": "message::recv", "payload": []any{map[string]any{"msgId": "msg-1", "msgTime": "1700000000", "chatType": 2, "senderUin": "10001", "peerUin": "20001", "sendNickName": "Alice", "elements": []any{map[string]any{"elementType": 1, "textElement": map[string]any{"content": "hello inbound"}}}}}})
		var outbound RedPack[RedMessageSend]
		if connection.ReadJSON(&outbound) != nil || outbound.Type != "message::send" || outbound.Payload == nil {
			return
		}
		outboundSeen <- *outbound.Payload
		_ = connection.WriteJSON(map[string]any{"type": "message::send::reply", "payload": map[string]any{"msgId": "msg-out-1"}})
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}

	descriptor := NewRedDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","host":"`+parsed.Hostname()+`","port":`+strconv.Itoa(port)+`,"token":{"secretRef":"red-token","version":1},"device":"","protocol":"","appId":"","redVersion":""}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "red-smoke", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"red-token": []byte("red-runtime-token")}}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case inbound := <-core.inboundCh:
		if inbound.ProviderEventID != "red-message:msg-1" || inbound.MessageID != "msg-1" || inbound.Sender != "QQ:10001" || inbound.Conversation != "QQ-Group:20001" || inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Text != "hello inbound" {
			t.Fatalf("inbound = %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Red inbound")
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:20001"}, Text: "hello outbound"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "msg-out-1" {
		t.Fatalf("result = %#v", result)
	}
	select {
	case outbound := <-outboundSeen:
		if outbound.Peer == nil || outbound.Peer.ChatType != GroupChat || outbound.Peer.PeerUin != "20001" || len(outbound.Elements) != 1 || outbound.Elements[0].TextElement == nil || outbound.Elements[0].TextElement.Content != "hello outbound" {
			t.Fatalf("outbound = %#v", outbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Red outbound")
	}
	liveRuntime, ok := runtime.(*redRuntime)
	if !ok {
		t.Fatalf("runtime type = %T, want *redRuntime", runtime)
	}
	liveRuntime.dispatchTimeout = 50 * time.Millisecond
	result = runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectAmbiguous || result.Code != "red_provider_ambiguous" {
		t.Fatalf("unacknowledged result = %#v", result)
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
		t.Fatal("Red runtime did not stop")
	}
}

func TestRedDescriptorSatisfiesRuntimeContract(t *testing.T) {
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor:                NewRedDescriptor,
		Config:                       json.RawMessage(`{"version":"1","host":"127.0.0.1","port":12345,"token":{"secretRef":"red-token","version":1},"device":"","protocol":"","appId":"","redVersion":""}`),
		Init:                         adapterapi.RuntimeInit{EndpointID: "red-contract", Generation: 1, DesiredVersion: 1, Secrets: &namedRuntimeResolver{values: map[string][]byte{"red-token": []byte("runtime-token")}}},
		RequireOwnedResourceManifest: true,
	})
}

func TestRedDescriptorRejectsUnsafeHost(t *testing.T) {
	for _, host := range []string{"http://example.com", "user@example.com", "host/path", "line\nfeed"} {
		t.Run(strings.ReplaceAll(host, "/", "_"), func(t *testing.T) {
			_, err := NewRedDescriptor().ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","host":`+strconv.Quote(host)+`,"port":12345,"token":{"secretRef":"red-token","version":1},"device":"","protocol":"","appId":"","redVersion":""}`))
			if err == nil {
				t.Fatal("unsafe host was accepted")
			}
		})
	}
}

// redRoleFixtureServer serves the Red websocket handshake plus a controllable
// group/getMemberList HTTP endpoint, so the runtime's real provider lookup path
// is exercised end to end rather than stubbed.
type redRoleFixtureServer struct {
	server       *httptest.Server
	memberCalls  chan string
	memberStatus int
	memberBody   string
}

func newRedRoleFixtureServer(t *testing.T, memberStatus int, memberBody string) *redRoleFixtureServer {
	t.Helper()
	fixture := &redRoleFixtureServer{memberCalls: make(chan string, 8), memberStatus: memberStatus, memberBody: memberBody}
	var members []json.RawMessage
	memberCount := 1
	if json.Unmarshal([]byte(memberBody), &members) == nil && len(members) > 0 {
		memberCount = len(members)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/bot/groups" {
			_ = json.NewEncoder(writer).Encode([]map[string]any{{"groupCode": "20001", "memberCount": memberCount}})
			return
		}
		if request.URL.Path == "/api/group/getMemberList" {
			var body struct {
				Group int64 `json:"group"`
				Size  int   `json:"size"`
			}
			_ = json.NewDecoder(request.Body).Decode(&body)
			select {
			case fixture.memberCalls <- strconv.FormatInt(body.Group, 10):
			default:
			}
			writer.WriteHeader(fixture.memberStatus)
			if len(members) > body.Size && body.Size >= 0 {
				_ = json.NewEncoder(writer).Encode(members[:body.Size])
			} else {
				_, _ = writer.Write([]byte(fixture.memberBody))
			}
			return
		}
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		var identify RedPack[RedConnectReq]
		if connection.ReadJSON(&identify) != nil || identify.Type != "meta::connect" || identify.Payload == nil || identify.Payload.Token != "red-runtime-token" {
			return
		}
		_ = connection.WriteJSON(map[string]any{"type": "meta::connect::reply", "payload": map[string]any{"version": "1.2.3", "name": "red", "authData": map[string]any{"uin": "10000", "nickName": "Red Bot"}}})
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *redRoleFixtureServer) runtimeForTest(t *testing.T) adapterapi.AdapterRuntime {
	t.Helper()
	parsed, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	descriptor := NewRedDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"version":"1","host":"`+parsed.Hostname()+`","port":`+strconv.Itoa(port)+`,"token":{"secretRef":"red-token","version":1},"device":"","protocol":"","appId":"","redVersion":""}`))
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{EndpointID: "red-roles", Generation: 1, DesiredVersion: 1, Config: config, Secrets: &namedRuntimeResolver{values: map[string][]byte{"red-token": []byte("red-runtime-token")}}})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	return runtime
}

// redRoleFixtureMember is one member entry used to build a provider page.
type redRoleFixtureMember struct {
	uin  string
	role int
}

// redRoleFixtureBody renders a group/getMemberList page in the provider's
// {index, detail} envelope shape.
func redRoleFixtureBody(entries ...redRoleFixtureMember) string {
	page := make([]map[string]any, 0, len(entries))
	for index, entry := range entries {
		page = append(page, map[string]any{"index": index, "detail": map[string]any{"uin": entry.uin, "role": entry.role}})
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func TestRedGroupInboundCarriesProviderMemberRole(t *testing.T) {
	body := redRoleFixtureBody(
		redRoleFixtureMember{"10001", 4},
		redRoleFixtureMember{"10002", 3},
		redRoleFixtureMember{"10003", 2},
	)
	cases := []struct {
		uin  string
		want string
	}{
		{uin: "10001", want: "owner"},
		{uin: "10002", want: "admin"},
		{uin: "10003", want: "member"},
	}
	for _, test := range cases {
		t.Run(test.want, func(t *testing.T) {
			fixture := newRedRoleFixtureServer(t, http.StatusOK, body)
			runtime := fixture.runtimeForTest(t)
			live := runtime.(*redRuntime)
			role := live.resolveGroupSenderRole(context.Background(), &RedMessage{ChatType: int(GroupChat), PeerUin: "20001"}, formatDiceIDRed(test.uin))
			if role != test.want {
				t.Fatalf("role = %q, want %q", role, test.want)
			}
			select {
			case group := <-fixture.memberCalls:
				if group != "20001" {
					t.Fatalf("member lookup group = %q, want 20001", group)
				}
			default:
				t.Fatal("provider member list was never queried")
			}
		})
	}
}

func TestRedGroupRoleLookupIncludesMembersBeyondFirst500(t *testing.T) {
	members := make([]redRoleFixtureMember, 601)
	for index := range members {
		members[index] = redRoleFixtureMember{uin: strconv.Itoa(10000 + index), role: 2}
	}
	members[600].role = 3
	fixture := newRedRoleFixtureServer(t, http.StatusOK, redRoleFixtureBody(members...))
	runtime := fixture.runtimeForTest(t).(*redRuntime)
	if role := runtime.resolveGroupSenderRole(context.Background(), &RedMessage{PeerUin: "20001"}, "QQ:10600"); role != "admin" {
		t.Fatalf("last member role = %q, want admin", role)
	}
}

func TestRedGroupCountLookupFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"unavailable", http.StatusServiceUnavailable, "unavailable"},
		{"malformed", http.StatusOK, "{"},
		{"missing-group", http.StatusOK, `[{"groupCode":"other","memberCount":1}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/api/bot/groups" {
					t.Errorf("unexpected request after failed group lookup: %s", request.URL.Path)
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			fixture := &redRoleFixtureServer{server: server}
			runtime := fixture.runtimeForTest(t).(*redRuntime)
			if role := runtime.resolveGroupSenderRole(context.Background(), &RedMessage{PeerUin: "20001"}, "QQ:10001"); role != "" {
				t.Fatalf("failed lookup granted role %q", role)
			}
		})
	}
}

func TestRedGroupFrameEndToEndCarriesResolvedRole(t *testing.T) {
	body := redRoleFixtureBody(redRoleFixtureMember{"10002", 3})
	fixture := newRedRoleFixtureServer(t, http.StatusOK, body)
	runtime := fixture.runtimeForTest(t)
	live := runtime.(*redRuntime)
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	frame := map[string]any{"type": "message::recv", "payload": []any{map[string]any{
		"msgId": "msg-e2e", "msgTime": "1700000000", "chatType": int(GroupChat),
		"senderUin": "10002", "peerUin": "20001", "sendNickName": "Bob", "elements": []any{},
	}}}
	encoded, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.handleFrame(context.Background(), core, encoded); err != nil {
		t.Fatalf("handle group frame: %v", err)
	}
	select {
	case inbound := <-core.inboundCh:
		if inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.SenderRole != "admin" {
			t.Fatalf("group inbound = %#v", inbound)
		}
	default:
		t.Fatal("group inbound did not reach CorePort")
	}
}

func TestRedGroupInboundUnknownMemberRoleIsNotPromoted(t *testing.T) {
	fixture := newRedRoleFixtureServer(t, http.StatusOK, redRoleFixtureBody(redRoleFixtureMember{"10001", 99}))
	runtime := fixture.runtimeForTest(t)
	live := runtime.(*redRuntime)
	if role := live.resolveGroupSenderRole(context.Background(), &RedMessage{ChatType: int(GroupChat), PeerUin: "20001"}, "QQ:10001"); role != "" {
		t.Fatalf("unrecognized provider role was promoted to %q", role)
	}
	if role := live.resolveGroupSenderRole(context.Background(), &RedMessage{ChatType: int(GroupChat), PeerUin: "20001"}, "QQ:10009"); role != "" {
		t.Fatalf("member absent from provider list resolved role %q", role)
	}
}

func TestRedGroupInboundLookupFailureYieldsNoRole(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "provider-error", status: http.StatusInternalServerError, body: `{}`},
		{name: "malformed-body", status: http.StatusOK, body: `not-json`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRedRoleFixtureServer(t, test.status, test.body)
			runtime := fixture.runtimeForTest(t)
			live := runtime.(*redRuntime)
			if role := live.resolveGroupSenderRole(context.Background(), &RedMessage{ChatType: int(GroupChat), PeerUin: "20001"}, "QQ:10001"); role != "" {
				t.Fatalf("failed lookup produced role %q", role)
			}
		})
	}
}

func TestRedGroupMemberLookupIsCachedAcrossMessages(t *testing.T) {
	body := redRoleFixtureBody(redRoleFixtureMember{"10001", 3})
	fixture := newRedRoleFixtureServer(t, http.StatusOK, body)
	runtime := fixture.runtimeForTest(t)
	live := runtime.(*redRuntime)
	message := &RedMessage{ChatType: int(GroupChat), PeerUin: "20001"}
	for attempt := range 3 {
		if role := live.resolveGroupSenderRole(context.Background(), message, "QQ:10001"); role != "admin" {
			t.Fatalf("attempt %d role = %q, want admin", attempt, role)
		}
	}
	select {
	case <-fixture.memberCalls:
	default:
		t.Fatal("member list was never queried")
	}
	select {
	case extra := <-fixture.memberCalls:
		t.Fatalf("member list was re-fetched within TTL (group %q)", extra)
	default:
	}
}

func TestRedPrivateMessageInboundOmitsGroupRole(t *testing.T) {
	fixture := newRedRoleFixtureServer(t, http.StatusOK, redRoleFixtureBody(redRoleFixtureMember{"10001", 4}))
	runtime := fixture.runtimeForTest(t)
	live := runtime.(*redRuntime)
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	frame := map[string]any{"type": "message::recv", "payload": []any{map[string]any{
		"msgId": "msg-p", "msgTime": "1700000000", "chatType": int(PersonChat),
		"senderUin": "10001", "peerUin": "10001", "sendNickName": "Alice", "elements": []any{},
	}}}
	encoded, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.handleFrame(context.Background(), core, encoded); err != nil {
		t.Fatalf("handle private frame: %v", err)
	}
	select {
	case inbound := <-core.inboundCh:
		if inbound.ConversationKind != adapterapi.ConversationKindDirect || inbound.SenderRole != "" {
			t.Fatalf("private inbound = %#v", inbound)
		}
	default:
		t.Fatal("private inbound did not reach CorePort")
	}
	// The private path must not consult the provider member list at all.
	select {
	case group := <-fixture.memberCalls:
		t.Fatalf("private message triggered member lookup for group %q", group)
	default:
	}
}
