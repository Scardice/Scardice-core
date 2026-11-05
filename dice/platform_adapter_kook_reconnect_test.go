package dice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
)

const kookTestWait = 5 * time.Second

// fakeKookGateway is a controllable KOOK gateway: the HTTP API plus a
// websocket endpoint whose sessions are handed to the test, which decides what
// each one says (or does not say).
type fakeKookGateway struct {
	server        *httptest.Server
	upgrader      websocket.Upgrader
	sessions      chan *fakeKookSession
	indexHits     atomic.Int64
	indexFailures atomic.Int64 // upcoming gateway/index calls answered with HTTP 500
	skipHello     atomic.Bool
	lastQuery     atomic.Value // string: raw query of the latest websocket dial
}

type fakeKookSession struct {
	conn    *websocket.Conn
	frames  chan kookGatewayPayload // client -> server frames
	writeMu sync.Mutex
}

func newFakeKookGateway(t *testing.T) *fakeKookGateway {
	t.Helper()
	gateway := &fakeKookGateway{
		upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		sessions: make(chan *fakeKookSession, 16),
	}
	gateway.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v3/gateway/index":
			gateway.indexHits.Add(1)
			if gateway.indexFailures.Add(-1) >= 0 {
				http.Error(writer, "gateway unavailable", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"url": "ws" + strings.TrimPrefix(gateway.server.URL, "http") + "/gateway"}})
		case "/api/v3/user/me":
			_ = json.NewEncoder(writer).Encode(map[string]any{"code": 0, "data": map[string]string{"id": "bot-1", "nickname": "Scardice"}})
		case "/gateway":
			gateway.lastQuery.Store(request.URL.RawQuery)
			connection, err := gateway.upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			session := &fakeKookSession{conn: connection, frames: make(chan kookGatewayPayload, 256)}
			if !gateway.skipHello.Load() {
				session.send(map[string]any{"s": 1, "d": map[string]any{"code": 0, "session_id": "session"}})
			}
			go func() {
				for {
					_, data, err := connection.ReadMessage()
					if err != nil {
						close(session.frames)
						return
					}
					var frame kookGatewayPayload
					if json.Unmarshal(data, &frame) == nil {
						session.frames <- frame
					}
				}
			}()
			gateway.sessions <- session
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(func() {
		gateway.server.Close()
		for {
			select {
			case session := <-gateway.sessions:
				_ = session.conn.Close()
			default:
				return
			}
		}
	})
	return gateway
}

func (session *fakeKookSession) send(frame map[string]any) {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	_ = session.conn.WriteJSON(frame)
}

func (session *fakeKookSession) message(sn int64, messageID string) {
	session.send(map[string]any{"s": 0, "sn": sn, "d": map[string]any{"channel_type": "GROUP", "type": 1, "target_id": "channel-1", "author_id": "user-1", "content": "hello " + messageID, "msg_id": messageID, "msg_timestamp": 1_700_000_000_000, "extra": map[string]any{"guild_id": "guild-1", "author": map[string]any{"id": "user-1", "nickname": "alice"}}}})
}

// drop severs the transport without a close handshake.
func (session *fakeKookSession) drop() { _ = session.conn.UnderlyingConn().Close() }

// nextPing waits for the client's next heartbeat.
func (session *fakeKookSession) nextPing(t *testing.T) kookGatewayPayload {
	t.Helper()
	timeout := time.NewTimer(kookTestWait)
	defer timeout.Stop()
	for {
		select {
		case frame, ok := <-session.frames:
			if !ok {
				t.Fatal("client closed the connection while waiting for a ping")
			}
			if frame.Signal == 2 {
				return frame
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for a ping")
		}
	}
}

func (gateway *fakeKookGateway) nextSession(t *testing.T) *fakeKookSession {
	t.Helper()
	timeout := time.NewTimer(kookTestWait)
	defer timeout.Stop()
	select {
	case session := <-gateway.sessions:
		return session
	case <-timeout.C:
		t.Fatal("the adapter did not open a (new) gateway session")
		return nil
	}
}

// kookTestCore records observations and inbound messages without dropping any.
type kookTestCore struct {
	observations chan adapterapi.LifecycleObservation
	inbound      chan adapterapi.InboundMessage
	// handle, when set, decides the receipt of each delivery; only accepted
	// deliveries are recorded on inbound.
	handle func(adapterapi.InboundMessage) (adapterapi.IngressReceipt, error)
}

func newKookTestCore() *kookTestCore {
	return &kookTestCore{observations: make(chan adapterapi.LifecycleObservation, 256), inbound: make(chan adapterapi.InboundMessage, 256)}
}

func (core *kookTestCore) HandleInbound(_ context.Context, message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	if core.handle != nil {
		if receipt, err := core.handle(message); err != nil || receipt.Outcome != adapterapi.IngressAccepted {
			return receipt, err
		}
	}
	core.inbound <- message
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}

func (core *kookTestCore) ReportObservation(_ context.Context, observation adapterapi.LifecycleObservation) error {
	core.observations <- observation
	return nil
}

func (core *kookTestCore) waitState(t *testing.T, state adapterapi.ObservedState) adapterapi.LifecycleObservation {
	t.Helper()
	timeout := time.NewTimer(kookTestWait)
	defer timeout.Stop()
	for {
		select {
		case observation := <-core.observations:
			if observation.Kind == adapterapi.LifecycleObservationState && observation.State == state {
				return observation
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for observed state %v", state)
		}
	}
}

func (core *kookTestCore) waitInbound(t *testing.T) adapterapi.InboundMessage {
	t.Helper()
	timeout := time.NewTimer(kookTestWait)
	defer timeout.Stop()
	select {
	case message := <-core.inbound:
		return message
	case <-timeout.C:
		t.Fatal("timed out waiting for inbound")
		return adapterapi.InboundMessage{}
	}
}

// startKookReconnectRuntime runs a runtime against the fake gateway and stops
// it when the test ends.
func startKookReconnectRuntime(t *testing.T, gateway *fakeKookGateway, timing kookTiming) (*kookRuntime, *kookTestCore, <-chan error) {
	t.Helper()
	return startKookReconnectRuntimeWith(t, gateway, timing, newKookTestCore())
}

func startKookReconnectRuntimeWith(t *testing.T, gateway *fakeKookGateway, timing kookTiming, core *kookTestCore) (*kookRuntime, *kookTestCore, <-chan error) {
	t.Helper()
	runtime := &kookRuntime{
		config:     kookCanonicalConfig{APIBaseURL: gateway.server.URL},
		tokenRef:   adapterapi.SecretRef{Ref: "kook-token", Version: 1},
		resolver:   &onebotRuntimeResolver{bytes: []byte("runtime-token")},
		httpClient: gateway.server.Client(),
		dialer:     websocket.DefaultDialer,
		timing:     timing,
	}
	runDone := make(chan error, 1)
	go func() {
		runDone <- runtime.Run(context.Background(), core)
		close(runDone)
	}()
	t.Cleanup(func() {
		if err := runtime.Stop(context.Background()); err != nil {
			t.Errorf("stop Kook runtime: %v", err)
		}
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("Kook runtime stopped with an error: %v", err)
			}
		case <-time.After(kookTestWait):
			t.Error("Kook runtime did not stop")
		}
	})
	return runtime, core, runDone
}

// requireStillRunning fails when Run has already returned.
func requireStillRunning(t *testing.T, runDone <-chan error) {
	t.Helper()
	select {
	case err := <-runDone:
		t.Fatalf("Run returned (%v) instead of redialing", err)
	default:
	}
}

var fastKookTiming = kookTiming{
	heartbeatInterval: 5 * time.Millisecond,
	pongTimeout:       50 * time.Millisecond,
	helloTimeout:      50 * time.Millisecond,
	reconnectBase:     time.Millisecond,
	reconnectMax:      4 * time.Millisecond,
}

// requireNoFailureObserved fails when a failed state has been reported. The
// runtime reports from the Run goroutine, so anything it reported before the
// state the caller last waited for is already queued.
func (core *kookTestCore) requireNoFailureObserved(t *testing.T) {
	t.Helper()
	for {
		select {
		case observation := <-core.observations:
			if observation.Kind == adapterapi.LifecycleObservationState && observation.State == adapterapi.ObservedStateFailed {
				t.Fatalf("a gateway-directed reconnect was reported as a failure: %#v", observation)
			}
		default:
			return
		}
	}
}

// The gateway tells a healthy client to reconnect (an expired session, an
// invalid sn, a failed resume). That is an instruction, not an outage: the
// client redials at once, with a fresh gateway and no resume, and the Core is
// not told the endpoint failed. The backoff here is an hour, so a redial that
// waited for it would never reach the second session.
func TestKookRuntimeRedialsAtOnceWhenGatewayRequestsReconnect(t *testing.T) {
	for name, data := range map[string]any{
		"number code": map[string]any{"code": 40107, "err": "session expired"},
		"string code": map[string]any{"code": "40108", "err": "invalid sn"},
		"no payload":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			gateway := newFakeKookGateway(t)
			timing := fastKookTiming
			timing.reconnectBase, timing.reconnectMax = time.Hour, time.Hour
			timing.reconnectLoopWindow = time.Nanosecond
			_, core, runDone := startKookReconnectRuntime(t, gateway, timing)
			first := gateway.nextSession(t)
			core.waitState(t, adapterapi.ObservedStateConnected)

			frame := map[string]any{"s": 5}
			if data != nil {
				frame["d"] = data
			}
			first.send(frame)

			gateway.nextSession(t)
			core.waitState(t, adapterapi.ObservedStateConnected)
			core.requireNoFailureObserved(t)
			requireStillRunning(t, runDone)
			if hits := gateway.indexHits.Load(); hits != 2 {
				t.Fatalf("gateway/index hits = %d, want a fresh gateway for the new session", hits)
			}
			if query, _ := gateway.lastQuery.Load().(string); strings.Contains(query, "resume=1") {
				t.Fatalf("a reconnect signal must not be answered with resume: %q", query)
			}
		})
	}
}

// A gateway that orders a reconnect right after every connect would otherwise
// make the client spin: such a session is an ordinary failure, reported once
// and redialed with backoff.
func TestKookRuntimeBacksOffWhenGatewayKeepsRequestingReconnect(t *testing.T) {
	gateway := newFakeKookGateway(t)
	timing := fastKookTiming
	timing.reconnectLoopWindow = time.Hour
	_, core, runDone := startKookReconnectRuntime(t, gateway, timing)
	first := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)

	first.send(map[string]any{"s": 5, "d": map[string]any{"code": 40107, "err": "session expired"}})

	failed := core.waitState(t, adapterapi.ObservedStateFailed)
	if failed.Code != "reconnect_requested" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	requireStillRunning(t, runDone)
}

func TestKookRuntimeRedialsWhenConnectionDrops(t *testing.T) {
	gateway := newFakeKookGateway(t)
	_, core, runDone := startKookReconnectRuntime(t, gateway, fastKookTiming)
	first := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)

	first.drop()

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "remote_closed" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	requireStillRunning(t, runDone)
}

// A gateway that stays connected but never answers a ping (a half-open
// connection, or a silent gateway) must be abandoned after the pong timeout.
func TestKookRuntimeRedialsWhenPongNeverArrives(t *testing.T) {
	gateway := newFakeKookGateway(t)
	_, core, runDone := startKookReconnectRuntime(t, gateway, fastKookTiming)
	first := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	first.nextPing(t) // the heartbeat is sent; the gateway stays silent

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "heartbeat_timeout" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	requireStillRunning(t, runDone)
}

func TestKookRuntimeKeepsConnectionWhilePongsArrive(t *testing.T) {
	gateway := newFakeKookGateway(t)
	timing := fastKookTiming
	timing.pongTimeout = time.Minute // only a missing pong may end the session here
	_, core, runDone := startKookReconnectRuntime(t, gateway, timing)
	session := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)

	for range 5 {
		session.nextPing(t)
		session.send(map[string]any{"s": 3})
	}

	requireStillRunning(t, runDone)
	select {
	case <-gateway.sessions:
		t.Fatal("a healthy session was replaced")
	default:
	}
	if failures := len(core.observations); failures != 0 {
		for range failures {
			if o := <-core.observations; o.State == adapterapi.ObservedStateFailed {
				t.Fatalf("a healthy session reported %#v", o)
			}
		}
	}
}

// The gateway accepts the websocket but never sends the hello frame.
func TestKookRuntimeRedialsWhenHelloNeverArrives(t *testing.T) {
	gateway := newFakeKookGateway(t)
	gateway.skipHello.Store(true)
	_, core, runDone := startKookReconnectRuntime(t, gateway, fastKookTiming)
	gateway.nextSession(t)

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "hello_timeout" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.skipHello.Store(false)
	gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	requireStillRunning(t, runDone)
}

// An unreachable gateway is retried with backoff and reported once, however
// many attempts the outage takes.
func TestKookRuntimeBacksOffThroughGatewayOutageAndReportsOnce(t *testing.T) {
	gateway := newFakeKookGateway(t)
	gateway.indexFailures.Store(4)
	_, core, runDone := startKookReconnectRuntime(t, gateway, fastKookTiming)

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "connect_failed" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	requireStillRunning(t, runDone)
	if hits := gateway.indexHits.Load(); hits != 5 {
		t.Fatalf("gateway/index hits = %d, want 4 failures and 1 success", hits)
	}
	for len(core.observations) > 0 {
		if o := <-core.observations; o.Kind == adapterapi.LifecycleObservationState && o.State == adapterapi.ObservedStateFailed {
			t.Fatalf("one outage reported a second failure: %#v", o)
		}
	}
}

// A new session restarts the gateway's sequence numbers: the old high-water
// mark must not swallow its messages, and a repeated sn is dropped.
func TestKookRuntimeResetsSequenceAcrossSessionsAndDropsRepeatedSequence(t *testing.T) {
	gateway := newFakeKookGateway(t)
	timing := fastKookTiming
	timing.pongTimeout = time.Minute
	_, core, _ := startKookReconnectRuntime(t, gateway, timing)
	first := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)

	first.message(1, "message-1")
	first.message(1, "message-1-repeated")
	first.message(2, "message-2")
	for _, want := range []string{"message-1", "message-2"} {
		if got := core.waitInbound(t); string(got.MessageID) != want {
			t.Fatalf("inbound = %q, want %q (repeated sn must be dropped)", got.MessageID, want)
		}
	}
	for {
		if ping := first.nextPing(t); ping.Sequence == 2 {
			break
		}
	}

	first.send(map[string]any{"s": 5, "d": map[string]any{"code": 40107}})
	second := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)
	if ping := second.nextPing(t); ping.Sequence != 0 {
		t.Fatalf("first ping of a new session carries sn %d, want 0", ping.Sequence)
	}
	second.message(1, "message-3")
	if got := core.waitInbound(t); string(got.MessageID) != "message-3" {
		t.Fatalf("inbound of the new session = %q", got.MessageID)
	}
}

func TestKookRuntimeStopInterruptsBackoff(t *testing.T) {
	gateway := newFakeKookGateway(t)
	gateway.indexFailures.Store(1 << 20)
	timing := fastKookTiming
	timing.reconnectBase, timing.reconnectMax = time.Hour, time.Hour
	runtime, core, runDone := startKookReconnectRuntime(t, gateway, timing)
	core.waitState(t, adapterapi.ObservedStateFailed)

	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run after Stop = %v, want nil", err)
		}
	case <-time.After(kookTestWait):
		t.Fatal("Run did not return after Stop during the backoff")
	}
}

// A slow inbound handler must not stop the heartbeat or the reads: the gateway
// judges liveness by pings, so a session whose loop is parked in a Core call
// is dropped by the server while the adapter still believes it is connected.
func TestKookRuntimeKeepsHeartbeatAndReadsWhileInboundHandlerBlocks(t *testing.T) {
	gateway := newFakeKookGateway(t)
	timing := fastKookTiming
	timing.pongTimeout = time.Minute
	core := newKookTestCore()
	entered, release := make(chan struct{}, 1), make(chan struct{})
	core.handle = func(message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
		if message.MessageID == "message-1" {
			entered <- struct{}{}
			<-release
		}
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
	}
	_, _, runDone := startKookReconnectRuntimeWith(t, gateway, timing, core)
	session := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)

	session.message(1, "message-1")
	<-entered // Core is now parked inside HandleInbound
	session.message(2, "message-2")
	for range 3 {
		session.nextPing(t)
		session.send(map[string]any{"s": 3})
	}
	requireStillRunning(t, runDone)

	close(release)
	for _, want := range []string{"message-1", "message-2"} {
		if got := core.waitInbound(t); string(got.MessageID) != want {
			t.Fatalf("inbound = %q, want %q", got.MessageID, want)
		}
	}
	select {
	case <-gateway.sessions:
		t.Fatal("a slow handler caused a reconnect")
	default:
	}
}

// Core refusing one message (backpressure, a digest collision, an oversized
// payload, a plain rejection, a storage error) is a fact about that message,
// not about the gateway connection; the session must stay up and later
// messages must still arrive in order.
func TestKookRuntimeKeepsSessionWhenCoreRefusesMessages(t *testing.T) {
	gateway := newFakeKookGateway(t)
	timing := fastKookTiming
	timing.pongTimeout = time.Minute
	timing.inboundRetryDelay = time.Millisecond
	core := newKookTestCore()
	backpressure := 0
	core.handle = func(message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
		switch message.MessageID {
		case "backpressure-then-ok":
			if backpressure++; backpressure <= 2 {
				return adapterapi.IngressReceipt{}, messageflow.ErrIngressBackpressure
			}
		case "collision":
			return adapterapi.IngressReceipt{}, eventstore.ErrConflict
		case "too-large":
			return adapterapi.IngressReceipt{}, messageflow.ErrIngressPayload
		case "rejected":
			return adapterapi.IngressReceipt{Outcome: adapterapi.IngressRejected}, nil
		case "storage-error":
			return adapterapi.IngressReceipt{}, errors.New("disk I/O error")
		}
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
	}
	_, _, runDone := startKookReconnectRuntimeWith(t, gateway, timing, core)
	session := gateway.nextSession(t)
	core.waitState(t, adapterapi.ObservedStateConnected)

	ids := []string{"backpressure-then-ok", "collision", "too-large", "rejected", "storage-error", "last"}
	for index, id := range ids {
		session.message(int64(index+1), id)
	}
	for _, want := range []string{"backpressure-then-ok", "last"} {
		if got := core.waitInbound(t); string(got.MessageID) != want {
			t.Fatalf("delivered %q, want %q", got.MessageID, want)
		}
	}
	requireStillRunning(t, runDone)
	select {
	case <-gateway.sessions:
		t.Fatal("a refused message caused a reconnect")
	default:
	}
	for len(core.observations) > 0 {
		if o := <-core.observations; o.Kind == adapterapi.LifecycleObservationState && o.State == adapterapi.ObservedStateFailed {
			t.Fatalf("a refused message reported %#v", o)
		}
	}
}
