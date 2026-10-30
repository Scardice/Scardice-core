package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	socketio "github.com/PaienNate/pineutil/evsocket/v2"
	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/adapterapi/contracttest"
	"Scardice-core/core/messageflow"
)

type onebotRuntimeCore struct {
	mu           sync.Mutex
	observations []adapterapi.LifecycleObservation
	ch           chan adapterapi.LifecycleObservation
	inboundCh    chan adapterapi.InboundMessage
}

func (c *onebotRuntimeCore) HandleInbound(_ context.Context, message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	if c.inboundCh != nil {
		c.inboundCh <- message
	}
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}
func (c *onebotRuntimeCore) ReportObservation(_ context.Context, observation adapterapi.LifecycleObservation) error {
	c.mu.Lock()
	c.observations = append(c.observations, observation)
	c.mu.Unlock()
	select {
	case c.ch <- observation:
	default:
	}
	return nil
}

func (c *onebotRuntimeCore) waitState(t *testing.T, state adapterapi.ObservedState) adapterapi.LifecycleObservation {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case observation := <-c.ch:
			if observation.State == state {
				return observation
			}
		case <-deadline.C:
			t.Fatalf("timed out waiting for state %v", state)
		}
	}
}

func (c *onebotRuntimeCore) waitIdentity(t *testing.T) adapterapi.LifecycleObservation {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case observation := <-c.ch:
			if observation.Kind == adapterapi.LifecycleObservationIdentity {
				return observation
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for identity")
		}
	}
}

type onebotRuntimeResolver struct {
	bytes []byte
	err   error
	calls chan struct{}
}

func (r *onebotRuntimeResolver) Resolve(context.Context, adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	if r.calls != nil {
		r.calls <- struct{}{}
	}
	if r.err != nil {
		return adapterapi.SecretValue{}, r.err
	}
	return adapterapi.SecretValue{Bytes: r.bytes, Version: 1}, nil
}

func TestOnebotInboundProviderKeyUsesStableMessageID(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","message_id":42,"user_id":7,"message":"hello"}`)
	if err := runtime.handleInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	message := <-core.inboundCh
	if message.ProviderEventID != "onebot-message-42" {
		t.Fatalf("provider id = %q", message.ProviderEventID)
	}
}

func TestOnebotInboundWithoutMessageIDIsRejected(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","user_id":7,"message":"hello"}`)
	if err := runtime.handleInbound(context.Background(), raw); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
		t.Fatalf("missing message ID error = %v, want unsupported event", err)
	}
	select {
	case message := <-core.inboundCh:
		t.Fatalf("message without stable identity reached Core: %#v", message)
	default:
	}
}

func TestOnebotInboundCarriesSenderRole(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{role: "owner", want: "owner"},
		{role: "admin", want: "admin"},
		{role: "member", want: "member"},
		{role: "unknown-custom", want: ""},
		{role: "", want: ""},
	}
	for _, test := range cases {
		t.Run(test.role, func(t *testing.T) {
			runtime := newOnebotRuntime(OnebotConfig{}, nil)
			core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
			runtime.core = core
			raw := []byte(`{"post_type":"message","message_type":"group","message_id":90,"user_id":7,"group_id":2002,"sender":{"user_id":7,"role":"` + test.role + `"},"message":"hi"}`)
			if err := runtime.handleInbound(context.Background(), raw); err != nil {
				t.Fatal(err)
			}
			message := <-core.inboundCh
			if message.SenderRole != test.want {
				t.Fatalf("sender role = %q, want %q", message.SenderRole, test.want)
			}
		})
	}
}

func TestOnebotInboundWithoutSenderRoleOmitsRole(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","message_id":91,"user_id":7,"message":"hi"}`)
	if err := runtime.handleInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	message := <-core.inboundCh
	if message.SenderRole != "" {
		t.Fatalf("sender role = %q, want empty", message.SenderRole)
	}
}

func TestOnebotMalformedInboundEventsAreRejectedWithoutStoppingWorker(t *testing.T) {
	longID := strings.Repeat("x", adapterapi.MaxInboundFieldBytes+1)
	tests := []struct {
		name string
		raw  string
	}{
		{name: "malformed JSON", raw: "{"},
		{name: "oversized group ID", raw: fmt.Sprintf(`{"post_type":"notice","notice_type":"group_recall","group_id":%q,"message_id":"recalled"}`, longID)},
		{name: "oversized message ID", raw: fmt.Sprintf(`{"post_type":"notice","notice_type":"group_recall","group_id":"2002","message_id":%q}`, longID)},
		{name: "oversized supplied user ID", raw: fmt.Sprintf(`{"post_type":"notice","notice_type":"group_recall","group_id":"2002","message_id":"recalled","user_id":%q}`, longID)},
		{name: "malformed supplied user ID", raw: `{"post_type":"notice","notice_type":"group_recall","group_id":"2002","message_id":"recalled","user_id":{}}`},
	}
	validRaw := []byte(`{"post_type":"notice","notice_type":"group_recall","group_id":"2002","message_id":"valid-after-reject"}`)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
			runtime := &onebotRuntime{core: core}
			raw := []byte(test.raw)
			if err := runtime.handleInbound(context.Background(), raw); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
				t.Fatalf("malformed recall error = %v, want unsupported event", err)
			}
			if err := runtime.processRuntimeEvent(context.Background(), onebotRuntimeEvent{kind: "inbound", raw: raw}); err != nil {
				t.Fatalf("malformed recall stopped worker: %v", err)
			}
			if got := runtime.RejectedInboundCount(); got != 1 {
				t.Fatalf("rejected event count = %d, want 1", got)
			}
			if err := runtime.processRuntimeEvent(context.Background(), onebotRuntimeEvent{kind: "inbound", raw: validRaw}); err != nil {
				t.Fatalf("worker did not survive malformed recall: %v", err)
			}
			select {
			case message := <-core.inboundCh:
				if message.Kind != adapterapi.InboundKindMessageDeleted || message.MessageID != "valid-after-reject" {
					t.Fatalf("valid recall after rejection = %#v", message)
				}
			default:
				t.Fatal("valid recall after rejection did not reach Core")
			}
		})
	}
}

func TestOnebotInboundAtSegmentCarriesRawProviderTarget(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","message_id":77,"user_id":7,"group_id":2002,"message":[{"type":"at","data":{"qq":"10001"}},{"type":"text","data":{"text":" .r 1d6"}},{"type":"at","data":{"qq":10002}},{"type":"at","data":{"qq":"all"}}]}`)
	if err := runtime.handleInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	message := <-core.inboundCh
	if len(message.Segments) != 4 {
		t.Fatalf("segments = %#v", message.Segments)
	}
	if message.Segments[0].Kind != "at" || message.Segments[0].ProviderID != "10001" {
		t.Fatalf("string at segment = %#v", message.Segments[0])
	}
	if message.Segments[1].Kind != "text" || message.Segments[1].Text != " .r 1d6" {
		t.Fatalf("text segment = %#v", message.Segments[1])
	}
	if message.Segments[2].Kind != "at" || message.Segments[2].ProviderID != "10002" {
		t.Fatalf("numeric at segment = %#v", message.Segments[2])
	}
	if message.Segments[3].Kind != "at" || message.Segments[3].ProviderID != "all" {
		t.Fatalf("at-all segment = %#v", message.Segments[3])
	}
}

func TestOnebotInboundAtSegmentPreservesExplicitIDOverQQ(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","message_id":78,"user_id":7,"message":[{"type":"at","data":{"id":"10003","qq":"10001"}}]}`)
	if err := runtime.handleInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	message := <-core.inboundCh
	if len(message.Segments) != 1 || message.Segments[0].ProviderID != "10003" {
		t.Fatalf("segments = %#v", message.Segments)
	}
}

func TestOnebotInboundAtSegmentWithoutTargetKeepsEmptyProviderID(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","message_id":79,"user_id":7,"message":[{"type":"at","data":{}}]}`)
	if err := runtime.handleInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	message := <-core.inboundCh
	if len(message.Segments) != 1 || message.Segments[0].Kind != "at" || message.Segments[0].ProviderID != "" {
		t.Fatalf("segments = %#v", message.Segments)
	}
}

func TestOnebotInboundRejectsOversizedRawFrameBeforeParsing(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := make([]byte, maxOnebotInboundBytes+1)
	copy(raw, []byte(`{"post_type":"message","message":"`))
	if err := runtime.handleInbound(context.Background(), raw); !errors.Is(err, ErrOnebotInboundPayloadTooLarge) {
		t.Fatalf("oversized inbound err = %v", err)
	}
	if runtime.RejectedInboundCount() != 1 {
		t.Fatalf("rejected count = %d", runtime.RejectedInboundCount())
	}
	select {
	case <-core.inboundCh:
		t.Fatal("oversized frame reached CorePort")
	default:
	}
}

func TestOnebotInboundQueueBackpressureIsObservableWithoutBlocking(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	for range cap(runtime.events) {
		runtime.events <- onebotRuntimeEvent{kind: "inbound"}
	}
	done := make(chan bool, 1)
	go func() {
		done <- runtime.enqueue(onebotRuntimeEvent{kind: "inbound"})
	}()
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("inbound queue silently accepted beyond bounded capacity")
		}
	case <-time.After(time.Second):
		t.Fatal("full inbound queue blocked callback admission")
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.BackpressureInboundCount() != 1 {
		t.Fatalf("backpressure count = %d", runtime.BackpressureInboundCount())
	}
}

func TestOnebotRuntimeKeepsAliveOnRetryableInboundError(t *testing.T) {
	if !isRetryableInboundError(messageflow.ErrIngressBackpressure) {
		t.Fatal("ingress backpressure would terminate the runtime")
	}
	if isRetryableInboundError(adapterapi.ErrInvalidContract) {
		t.Fatal("invalid ingress contract was treated as retryable")
	}
}

func onebotRuntimeServerConfig(t *testing.T) (OnebotConfig, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return OnebotConfig{Mode: "server", ListenAddress: address, ReverseSuffix: "/ws", Token: adapterapi.SecretRef{Ref: "onebot-token", Version: 1}}, address
}

func dialOnebotRuntime(t *testing.T, address string, authorization string) *websocket.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		client, _, err := websocket.DefaultDialer.Dial("ws://"+address+"/ws", http.Header{"Authorization": []string{authorization}})
		if err == nil {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial OneBot runtime: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOnebotRuntimeLifecycleReverse(t *testing.T) {
	config, address := onebotRuntimeServerConfig(t)
	secret := []byte("runtime-token")
	resolver := &onebotRuntimeResolver{bytes: secret, calls: make(chan struct{}, 1)}
	runtime := newOnebotRuntime(config, resolver)
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 16), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateStarting)
	<-resolver.calls

	client := dialOnebotRuntime(t, address, "runtime-token")
	defer client.Close()
	_, request, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Action string `json:"action"`
		Echo   string `json:"echo"`
	}
	if err := json.Unmarshal(request, &action); err != nil {
		t.Fatal(err)
	}
	if action.Action != "get_login_info" || action.Echo == "" {
		t.Fatalf("unexpected login request: %s", request)
	}
	response := fmt.Sprintf(`{"status":"ok","retcode":0,"data":{"user_id":12345,"nickname":"runtime-bot"},"echo":%q}`, action.Echo)
	if err := client.WriteMessage(websocket.TextMessage, []byte(response)); err != nil {
		t.Fatal(err)
	}
	identity := core.waitIdentity(t)
	if identity.ProviderID != "QQ:12345" {
		t.Fatalf("identity provider id = %q", identity.ProviderID)
	}
	if identity.Detail != "runtime-bot" {
		t.Fatalf("identity nickname = %q", identity.Detail)
	}
	inboundJSON := `{"post_type":"message","time":1700000000,"message_id":77,"user_id":42,"group_id":9,"message":[{"type":"text","data":{"text":"hello"}}]}`
	if err := client.WriteMessage(websocket.TextMessage, []byte(inboundJSON)); err != nil {
		t.Fatal(err)
	}
	select {
	case inbound := <-core.inboundCh:
		if inbound.Text != "hello" || inbound.Sender != "QQ:42" || inbound.Conversation != "QQ-Group:9" || inbound.ConversationKind != adapterapi.ConversationKindGroup {
			t.Fatalf("unexpected inbound DTO: %#v", inbound)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for inbound DTO")
	}
	for i := range secret {
		if secret[i] != 0 {
			t.Fatalf("resolver secret byte %d was not zeroed", i)
		}
	}

	if err := client.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "remote close")); err != nil {
		t.Fatal(err)
	}
	if failure := core.waitState(t, adapterapi.ObservedStateFailed); failure.Code != "remote_closed" {
		t.Fatalf("disconnect failure code = %q", failure.Code)
	}
	select {
	case err := <-runDone:
		t.Fatalf("runtime stopped when the protocol end disconnected: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// The protocol end comes back to the same listener.
	again := dialOnebotRuntime(t, address, "runtime-token")
	defer again.Close()
	answerOnebotLogin(t, again, 12345)
	core.waitState(t, adapterapi.ObservedStateConnected)

	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after Stop = %v", err)
	}
	core.waitState(t, adapterapi.ObservedStateStopping)
	core.waitState(t, adapterapi.ObservedStateStopped)
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	if runtime.manager != nil || runtime.conn != nil || runtime.server != nil || runtime.listener != nil || runtime.emitter != nil || runtime.tokenRef != nil || runtime.core != nil {
		t.Fatal("runtime retained resources after cleanup")
	}
	runtime.mu.Unlock()
}

// answerOnebotLogin plays the protocol end's side of the login handshake.
func answerOnebotLogin(t *testing.T, conn *websocket.Conn, userID int64) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, request, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	var action struct {
		Action string `json:"action"`
		Echo   string `json:"echo"`
	}
	if err := json.Unmarshal(request, &action); err != nil || action.Action != "get_login_info" {
		t.Fatalf("unexpected login request %s (%v)", request, err)
	}
	response := fmt.Sprintf(`{"status":"ok","retcode":0,"data":{"user_id":%d,"nickname":"runtime-bot"},"echo":%q}`, userID, action.Echo)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(response)); err != nil {
		t.Fatal(err)
	}
}

func (c *onebotRuntimeCore) count(state adapterapi.ObservedState) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, observation := range c.observations {
		if observation.Kind == adapterapi.LifecycleObservationState && observation.State == state {
			n++
		}
	}
	return n
}

func onebotDiagnostic(runtime *onebotRuntime, code string) string {
	for _, entry := range runtime.Diagnostics(context.Background()).Entries {
		if entry.Code == code {
			return entry.Message
		}
	}
	return ""
}

// An unauthorized client must not be able to take the bot offline.
func TestOnebotRuntimeRejectsUnauthorizedReverseClientAndKeepsServing(t *testing.T) {
	config, address := onebotRuntimeServerConfig(t)
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{bytes: []byte("runtime-token")})
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 16)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateStarting)

	intruder := dialOnebotRuntime(t, address, "wrong-token")
	_ = intruder.Close()
	deadline := time.Now().Add(3 * time.Second)
	for onebotDiagnostic(runtime, "transport.auth_rejected") != "Unauthorized connections rejected: 1" {
		if time.Now().After(deadline) {
			t.Fatalf("auth rejection diagnostic = %q", onebotDiagnostic(runtime, "transport.auth_rejected"))
		}
		time.Sleep(5 * time.Millisecond)
	}

	client := dialOnebotRuntime(t, address, "runtime-token")
	defer client.Close()
	answerOnebotLogin(t, client, 12345)
	core.waitState(t, adapterapi.ObservedStateConnected)
	select {
	case err := <-runDone:
		t.Fatalf("runtime stopped after an unauthorized client: %v", err)
	default:
	}
	if failures := core.count(adapterapi.ObservedStateFailed); failures != 0 {
		t.Fatalf("an unauthorized client reported %d failures", failures)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after Stop = %v", err)
	}
}

// fakeOnebotProtocolEnd accepts forward WebSocket connections and answers the
// login handshake; each accepted connection is handed to the test.
type fakeOnebotProtocolEnd struct {
	server *httptest.Server
	conns  chan *websocket.Conn
}

func startFakeOnebotProtocolEnd(t *testing.T, listener net.Listener) *fakeOnebotProtocolEnd {
	t.Helper()
	end := &fakeOnebotProtocolEnd{conns: make(chan *websocket.Conn, 4)}
	upgrader := websocket.Upgrader{}
	end.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		answerOnebotLogin(t, conn, 12345)
		end.conns <- conn
	}))
	_ = end.server.Listener.Close()
	end.server.Listener = listener
	end.server.Start()
	t.Cleanup(end.server.Close)
	return end
}

func (end *fakeOnebotProtocolEnd) accept(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case conn := <-end.conns:
		return conn
	case <-time.After(3 * time.Second):
		t.Fatal("the runtime did not connect to the protocol end")
		return nil
	}
}

func fastReconnectingClient(url string) *onebotRuntime {
	runtime := newOnebotRuntime(OnebotConfig{Mode: "client", URL: url}, nil)
	runtime.reconnectBase, runtime.reconnectMax = 10*time.Millisecond, 40*time.Millisecond
	return runtime
}

func TestOnebotRuntimeClientReconnectsAfterTheProtocolEndDisconnects(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	end := startFakeOnebotProtocolEnd(t, listener)
	runtime := fastReconnectingClient("ws://" + listener.Addr().String() + "/ws")
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 32)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()

	first := end.accept(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	for round := range 3 {
		_ = first.Close()
		if failure := core.waitState(t, adapterapi.ObservedStateFailed); failure.Code != "remote_closed" {
			t.Fatalf("round %d failure code = %q", round, failure.Code)
		}
		first = end.accept(t)
		core.waitState(t, adapterapi.ObservedStateConnected)
	}
	select {
	case err := <-runDone:
		t.Fatalf("runtime stopped while reconnecting: %v", err)
	default:
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after Stop = %v", err)
	}
}
func TestOnebotRuntimeDoesNotTrackConnectionAfterDisconnect(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	manager := socketio.NewSocketInstance()
	connection := manager.NewClient("ws://127.0.0.1", socketio.ClientOptions{})

	runtime.completeConnection(connection)
	runtime.trackConnection(connection)

	runtime.connectionMu.Lock()
	tracked := len(runtime.connections)
	runtime.connectionMu.Unlock()
	if tracked != 0 {
		t.Fatalf("closed connection was tracked after disconnect: %d", tracked)
	}
}

func TestOnebotRuntimeCleanupDoesNotWaitForMissingDisconnectCallback(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	manager := socketio.NewSocketInstance()
	connection := manager.NewClient("ws://127.0.0.1", socketio.ClientOptions{})
	runtime.connections[connection] = 0

	cleanupDone := make(chan struct{})
	go func() {
		runtime.cleanup()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("cleanup waited for a disconnect callback that can no longer arrive")
	}
}

func TestOnebotRuntimeExplicitStopIsIdempotentAndFenced(t *testing.T) {
	config, _ := onebotRuntimeServerConfig(t)
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{bytes: []byte("token")})
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateStarting)
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after explicit Stop = %v", err)
	}
	core.waitState(t, adapterapi.ObservedStateStopping)
	core.waitState(t, adapterapi.ObservedStateStopped)
}

func TestOnebotRuntimeResolverFailureReportsFailure(t *testing.T) {
	config, _ := onebotRuntimeServerConfig(t)
	wantErr := errors.New("vault unavailable")
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{err: wantErr})
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)}
	err := runtime.Run(context.Background(), core)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want %v", err, wantErr)
	}
	core.waitState(t, adapterapi.ObservedStateStarting)
	failure := core.waitState(t, adapterapi.ObservedStateFailed)
	if failure.Code != "secret_resolve_failed" {
		t.Fatalf("failure code = %q", failure.Code)
	}
	core.waitState(t, adapterapi.ObservedStateStopping)
	core.waitState(t, adapterapi.ObservedStateStopped)
}

// A protocol end that is not up yet, as after a host reboot, is waited for:
// the outage is reported once, not on every attempt.
func TestOnebotRuntimeClientKeepsRetryingUntilTheProtocolEndIsUp(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	_ = reserved.Close()
	runtime := fastReconnectingClient("ws://" + address + "/ws")
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 32)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	if failure := core.waitState(t, adapterapi.ObservedStateFailed); failure.Code != "connect_failed" {
		t.Fatalf("failure code = %q", failure.Code)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.reconnectAttempts.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the runtime stopped retrying")
		}
		time.Sleep(5 * time.Millisecond)
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	end := startFakeOnebotProtocolEnd(t, listener)
	end.accept(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	if failures := core.count(adapterapi.ObservedStateFailed); failures != 1 {
		t.Fatalf("one outage reported %d failures", failures)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after Stop = %v", err)
	}
	core.waitState(t, adapterapi.ObservedStateStopped)
}

// Stop must not wait for a backoff to elapse.
func TestOnebotRuntimeClientStopsWhileWaitingToReconnect(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{Mode: "client", URL: "ws://127.0.0.1:1/ws"}, nil)
	runtime.reconnectBase, runtime.reconnectMax = time.Hour, time.Hour
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateFailed)
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run after Stop = %v", err)
	}
}

func TestOnebotRuntimeStopBeforeRunRejectsStaleCallbacks(t *testing.T) {
	config, _ := onebotRuntimeServerConfig(t)
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{bytes: []byte("token")})
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 1)}
	if err := runtime.Run(context.Background(), core); err != nil {
		t.Fatal(err)
	}
	select {
	case observation := <-core.ch:
		t.Fatalf("stale callback reported observation: %#v", observation)
	case <-time.After(100 * time.Millisecond):
	}
}
func TestOnebotRuntimeInboundQueueBackpressureIsNonBlocking(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	for range cap(runtime.events) {
		runtime.events <- onebotRuntimeEvent{kind: "inbound"}
	}
	done := make(chan bool, 1)
	go func() {
		done <- runtime.enqueue(onebotRuntimeEvent{kind: "inbound"})
	}()
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("inbound queue silently accepted beyond bounded capacity")
		}
	case <-time.After(time.Second):
		t.Fatal("full inbound queue blocked callback admission")
	}
	if runtime.BackpressureInboundCount() != 1 {
		t.Fatalf("backpressure count = %d", runtime.BackpressureInboundCount())
	}
}

func TestOnebotRuntimeInboundRetryIsBounded(t *testing.T) {
	event := &onebotRuntimeEvent{kind: "inbound"}
	if !rehandoffOnebotInbound(event) {
		t.Fatal("expected first bounded rehandoff")
	}
	if !rehandoffOnebotInbound(event) {
		t.Fatal("expected second bounded rehandoff")
	}
	if event.attempt != maxOnebotInboundRetries {
		t.Fatalf("attempts = %d, want %d", event.attempt, maxOnebotInboundRetries)
	}
	if rehandoffOnebotInbound(event) {
		t.Fatal("unexpected rehandoff beyond bound")
	}
}

func TestOnebotRuntimePriorityEventCoalescesAndPreemptsInbound(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	for range cap(runtime.events) {
		runtime.events <- onebotRuntimeEvent{kind: "inbound"}
	}
	if !runtime.enqueue(onebotRuntimeEvent{kind: "disconnect"}) {
		t.Fatal("priority disconnect was not admitted")
	}
	if !runtime.enqueue(onebotRuntimeEvent{kind: "disconnect"}) {
		t.Fatal("priority disconnect was not coalesced")
	}
	if !runtime.enqueue(onebotRuntimeEvent{kind: "connect"}) {
		t.Fatal("priority connect was not admitted")
	}
	select {
	case event := <-runtime.priorityDisconnect:
		if event.kind != "disconnect" {
			t.Fatalf("priority event = %q", event.kind)
		}
	case <-time.After(time.Second):
		t.Fatal("priority disconnect missing after admission")
	}
	select {
	case event := <-runtime.priorityConnect:
		if event.kind != "connect" {
			t.Fatalf("priority event = %q", event.kind)
		}
	case <-time.After(time.Second):
		t.Fatal("priority connect missing after admission")
	}
	if runtime.priorityDropped.Load() != 1 {
		t.Fatalf("coalesced priority count = %d", runtime.priorityDropped.Load())
	}
	if len(runtime.events) != cap(runtime.events) {
		t.Fatalf("inbound queue changed while admitting priority event: %d", len(runtime.events))
	}
}

func TestOnebotRuntimeDiagnosticsExposeIngressCounters(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	runtime.inboundRejected.Store(3)
	runtime.inboundBackpressure.Store(2)
	runtime.inboundCollisions.Store(1)
	runtime.inboundRetries.Store(4)
	report := runtime.Diagnostics(context.Background())
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"inbound.rejected":         "Rejected inbound events: 3",
		"inbound.backpressure":     "Inbound backpressure events: 2",
		"inbound.conflicts":        "Inbound identity conflicts: 1",
		"inbound.retries":          "Inbound bounded rehandoffs: 4",
		"priority.coalesced":       "Coalesced duplicate priority events: 0",
		"transport.dropped_events": "Transport callback events dropped at queue admission: 0",
	}
	for _, entry := range report.Entries {
		if expected, ok := want[entry.Code]; ok {
			if entry.Message != expected {
				t.Fatalf("%s message = %q, want %q", entry.Code, entry.Message, expected)
			}
			delete(want, entry.Code)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing diagnostics = %#v", want)
	}
}

func TestOnebotRuntimeDiagnosticsRetainCompletedTransportDrops(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	runtime.transportDropped.Store(5)
	wrapper := &socketio.WebsocketWrapper{}
	runtime.connectionMu.Lock()
	runtime.connections[wrapper] = 5
	runtime.connectionMu.Unlock()
	report := runtime.Diagnostics(context.Background())
	for _, entry := range report.Entries {
		if entry.Code == "transport.dropped_events" {
			if entry.Message != "Transport callback events dropped at queue admission: 5" {
				t.Fatalf("transport drop diagnostic = %q", entry.Message)
			}
			return
		}
	}
	t.Fatal("missing transport drop diagnostic")
}

func TestPureOnebotDescriptorSatisfiesRuntimeContract(t *testing.T) {
	_, address := onebotRuntimeServerConfig(t)
	contracttest.Verify(t, contracttest.Case{
		NewDescriptor: NewOnebotDescriptor,
		Config: json.RawMessage(fmt.Sprintf(
			`{"mode":"server","listenAddress":%q,"reverseSuffix":"/ws","token":{"secretRef":"onebot-token","version":1}}`,
			address,
		)),
		Init: adapterapi.RuntimeInit{
			EndpointID:     "onebot-contract",
			Generation:     1,
			DesiredVersion: 1,
			ResourceRoot:   t.TempDir(),
		},
		SecretValues:                 []string{"onebot-runtime-secret"},
		RequireOwnedResourceManifest: true,
		Exercise: func(ctx context.Context, runtime adapterapi.AdapterRuntime, core *contracttest.CorePort) error {
			runDone := make(chan error, 1)
			go func() { runDone <- runtime.Run(ctx, core) }()
			if _, err := core.WaitForObservation(adapterapi.ObservedStateStarting, time.Second); err != nil {
				return err
			}
			if err := runtime.Stop(ctx); err != nil {
				return err
			}
			select {
			case err := <-runDone:
				return err
			case <-time.After(time.Second):
				return errors.New("runtime did not stop")
			}
		},
	})
}
