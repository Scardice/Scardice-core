package dice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

const discordTestWait = 5 * time.Second

// fakeDiscordGateway is a controllable Discord gateway: the REST discovery
// endpoint plus two websocket endpoints (/gateway for a new session, /resume
// for resume_gateway_url) whose connections are handed to the test.
type fakeDiscordGateway struct {
	server        *httptest.Server
	upgrader      websocket.Upgrader
	sessions      chan *fakeDiscordSession
	discoverHits  atomic.Int64
	discoverFails atomic.Int64 // upcoming discovery calls answered with HTTP 500
	skipHello     atomic.Bool
	helloInterval atomic.Int64 // milliseconds announced in hello
}

type fakeDiscordSession struct {
	conn     *websocket.Conn
	path     string
	frames   chan discordGatewayPayload // client -> server frames
	readDone chan error
	writeMu  sync.Mutex
	autoAck  atomic.Bool
}

func newFakeDiscordGateway(t *testing.T) *fakeDiscordGateway {
	t.Helper()
	gateway := &fakeDiscordGateway{
		upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		sessions: make(chan *fakeDiscordSession, 16),
	}
	gateway.helloInterval.Store(5)
	gateway.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v10/gateway":
			gateway.discoverHits.Add(1)
			if gateway.discoverFails.Add(-1) >= 0 {
				http.Error(writer, "gateway unavailable", http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{"url": gateway.wsURL("/gateway")})
		case "/gateway", "/resume":
			connection, err := gateway.upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			session := &fakeDiscordSession{
				conn: connection, path: request.URL.Path,
				frames: make(chan discordGatewayPayload, 256), readDone: make(chan error, 1),
			}
			session.autoAck.Store(true)
			if !gateway.skipHello.Load() {
				session.send(map[string]any{"op": 10, "d": map[string]any{"heartbeat_interval": gateway.helloInterval.Load()}})
			}
			go func() {
				defer connection.Close()
				for {
					_, data, err := connection.ReadMessage()
					if err != nil {
						session.readDone <- err
						close(session.frames)
						return
					}
					var frame discordGatewayPayload
					if json.Unmarshal(data, &frame) != nil {
						continue
					}
					if frame.Op == 1 && session.autoAck.Load() {
						session.send(map[string]any{"op": 11})
					}
					session.frames <- frame
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

func (gateway *fakeDiscordGateway) wsURL(path string) string {
	return "ws" + strings.TrimPrefix(gateway.server.URL, "http") + path
}

func (gateway *fakeDiscordGateway) nextSession(t *testing.T) *fakeDiscordSession {
	t.Helper()
	timeout := time.NewTimer(discordTestWait)
	defer timeout.Stop()
	select {
	case session := <-gateway.sessions:
		return session
	case <-timeout.C:
		t.Fatal("the adapter did not open a (new) gateway connection")
		return nil
	}
}

func (session *fakeDiscordSession) send(frame map[string]any) {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	_ = session.conn.WriteJSON(frame)
}

func (session *fakeDiscordSession) ready(seq int64, sessionID string, resumeURL string) {
	session.send(map[string]any{"op": 0, "t": "READY", "s": seq, "d": map[string]any{
		"user": map[string]any{"id": "bot-1", "username": "Scardice"}, "session_id": sessionID, "resume_gateway_url": resumeURL,
	}})
}

func (session *fakeDiscordSession) resumed(seq int64) {
	session.send(map[string]any{"op": 0, "t": "RESUMED", "s": seq, "d": map[string]any{}})
}

func (session *fakeDiscordSession) message(seq int64, messageID string) {
	session.send(map[string]any{"op": 0, "t": "MESSAGE_CREATE", "s": seq, "d": map[string]any{
		"id": messageID, "channel_id": "channel-1", "guild_id": "guild-1", "content": "hello " + messageID,
		"timestamp": "2023-11-14T22:13:20Z", "author": map[string]any{"id": "user-1", "username": "alice"},
	}})
}

// drop severs the transport without a close handshake.
func (session *fakeDiscordSession) drop() { _ = session.conn.UnderlyingConn().Close() }

// closeWith ends the connection with a close frame carrying code.
func (session *fakeDiscordSession) closeWith(code int, text string) {
	session.writeMu.Lock()
	_ = session.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(time.Second))
	session.writeMu.Unlock()
	_ = session.conn.Close()
}

// nextFrame waits for the client's next frame with the given opcode.
func (session *fakeDiscordSession) nextFrame(t *testing.T, op int) discordGatewayPayload {
	t.Helper()
	timeout := time.NewTimer(discordTestWait)
	defer timeout.Stop()
	for {
		select {
		case frame, ok := <-session.frames:
			if !ok {
				t.Fatalf("client closed the connection while waiting for opcode %d", op)
			}
			if frame.Op == op {
				return frame
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for a client frame with opcode %d", op)
		}
	}
}

type discordResumeFrame struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Seq       int64  `json:"seq"`
}

func (session *fakeDiscordSession) resumeFrame(t *testing.T) discordResumeFrame {
	t.Helper()
	var resume discordResumeFrame
	if err := json.Unmarshal(session.nextFrame(t, 6).Data, &resume); err != nil {
		t.Fatal(err)
	}
	return resume
}

type discordTestCore struct {
	observations chan adapterapi.LifecycleObservation
	inbound      chan adapterapi.InboundMessage
	handle       func(adapterapi.InboundMessage) (adapterapi.IngressReceipt, error)
}

func newDiscordTestCore() *discordTestCore {
	return &discordTestCore{observations: make(chan adapterapi.LifecycleObservation, 256), inbound: make(chan adapterapi.InboundMessage, 256)}
}

func (core *discordTestCore) HandleInbound(_ context.Context, message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	if core.handle != nil {
		if receipt, err := core.handle(message); err != nil || receipt.Outcome != adapterapi.IngressAccepted {
			return receipt, err
		}
	}
	core.inbound <- message
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}

func (core *discordTestCore) ReportObservation(_ context.Context, observation adapterapi.LifecycleObservation) error {
	core.observations <- observation
	return nil
}

func (core *discordTestCore) waitState(t *testing.T, state adapterapi.ObservedState) adapterapi.LifecycleObservation {
	t.Helper()
	timeout := time.NewTimer(discordTestWait)
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

func (core *discordTestCore) waitInbound(t *testing.T) adapterapi.InboundMessage {
	t.Helper()
	timeout := time.NewTimer(discordTestWait)
	defer timeout.Stop()
	select {
	case message := <-core.inbound:
		return message
	case <-timeout.C:
		t.Fatal("timed out waiting for inbound")
		return adapterapi.InboundMessage{}
	}
}

// requireNoFailureObserved fails when a failed state has been reported.
func (core *discordTestCore) requireNoFailureObserved(t *testing.T) {
	t.Helper()
	for {
		select {
		case observation := <-core.observations:
			if observation.Kind == adapterapi.LifecycleObservationState && observation.State == adapterapi.ObservedStateFailed {
				t.Fatalf("a failure was reported: %#v", observation)
			}
		default:
			return
		}
	}
}

var fastDiscordTiming = discordTiming{
	helloTimeout:       50 * time.Millisecond,
	reconnectBase:      time.Millisecond,
	reconnectMax:       4 * time.Millisecond,
	stableAfter:        time.Nanosecond,
	jitter:             func() float64 { return 0 },
	invalidSessionWait: func() time.Duration { return time.Millisecond },
}

func startDiscordReconnectRuntime(t *testing.T, gateway *fakeDiscordGateway, timing discordTiming, core *discordTestCore) (*discordRuntime, <-chan error) {
	t.Helper()
	runtime := &discordRuntime{
		config:     discordCanonicalConfig{ReverseProxyURL: gateway.server.URL},
		tokenRef:   adapterapi.SecretRef{Ref: "discord-token", Version: 1},
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
			t.Errorf("stop Discord runtime: %v", err)
		}
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("Discord runtime stopped with an error: %v", err)
			}
		case <-time.After(discordTestWait):
			t.Error("Discord runtime did not stop")
		}
	})
	return runtime, runDone
}

func requireDiscordStillRunning(t *testing.T, runDone <-chan error) {
	t.Helper()
	select {
	case err := <-runDone:
		t.Fatalf("Run returned (%v) instead of redialing", err)
	default:
	}
}

// connectFirstSession brings a session up as the gateway would: identify in,
// READY out, with the resume address pointing at /resume.
func connectFirstSession(t *testing.T, gateway *fakeDiscordGateway, core *discordTestCore) *fakeDiscordSession {
	t.Helper()
	session := gateway.nextSession(t)
	if session.path != "/gateway" {
		t.Fatalf("first connection used %s, want /gateway", session.path)
	}
	var identify struct {
		Token   string `json:"token"`
		Intents int    `json:"intents"`
	}
	if err := json.Unmarshal(session.nextFrame(t, 2).Data, &identify); err != nil || identify.Token != "runtime-token" || identify.Intents == 0 {
		t.Fatalf("identify = %+v (%v)", identify, err)
	}
	session.ready(1, "session-1", gateway.wsURL("/resume"))
	core.waitState(t, adapterapi.ObservedStateConnected)
	return session
}

// A dropped connection is redialed against the resume address and resumes the
// session from the last sequence handled, without discovering a gateway or
// identifying again (identify is limited to 1000 per day for the application).
func TestDiscordRuntimeResumesTheSessionWhenTheConnectionDrops(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
	first := connectFirstSession(t, gateway, core)
	first.message(2, "message-2")
	if got := core.waitInbound(t); string(got.MessageID) != "message-2" {
		t.Fatalf("inbound = %q", got.MessageID)
	}

	first.drop()

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "remote_closed" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	second := gateway.nextSession(t)
	if second.path != "/resume" {
		t.Fatalf("redial used %s, want the resume address", second.path)
	}
	if resume := second.resumeFrame(t); resume.Token != "runtime-token" || resume.SessionID != "session-1" || resume.Seq != 2 {
		t.Fatalf("resume = %+v, want session-1 at seq 2", resume)
	}
	second.resumed(3)
	core.waitState(t, adapterapi.ObservedStateConnected)
	second.message(4, "message-4")
	if got := core.waitInbound(t); string(got.MessageID) != "message-4" {
		t.Fatalf("inbound after resume = %q", got.MessageID)
	}
	requireDiscordStillRunning(t, runDone)
	if hits := gateway.discoverHits.Load(); hits != 1 {
		t.Fatalf("gateway discovered %d times, a resume must not rediscover", hits)
	}
}

// A heartbeat the gateway never acknowledges by the time the next one is due
// marks a zombied connection: it is abandoned and the session resumed.
func TestDiscordRuntimeAbandonsAConnectionThatStopsAcknowledgingHeartbeats(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
	first := connectFirstSession(t, gateway, core)
	first.autoAck.Store(false)

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "heartbeat_timeout" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	second := gateway.nextSession(t)
	if second.path != "/resume" {
		t.Fatalf("redial used %s, want the resume address", second.path)
	}
	second.resumeFrame(t)
	second.resumed(2)
	core.waitState(t, adapterapi.ObservedStateConnected)
	second.message(3, "after-heartbeat-timeout")
	if got := core.waitInbound(t); string(got.MessageID) != "after-heartbeat-timeout" {
		t.Fatalf("inbound after heartbeat recovery = %q", got.MessageID)
	}
	core.requireNoFailureObserved(t)
	requireDiscordStillRunning(t, runDone)
}

func TestDiscordRuntimeKeepsAConnectionThatAcknowledgesHeartbeats(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
	session := connectFirstSession(t, gateway, core)
	for range 12 {
		session.nextFrame(t, 1)
	}
	requireDiscordStillRunning(t, runDone)
	select {
	case <-gateway.sessions:
		t.Fatal("a healthy connection was redialed")
	default:
	}
}

// The gateway may ask for a heartbeat at any time (opcode 1); it must be sent
// at once, carrying the last sequence, even though the interval is an hour.
func TestDiscordRuntimeSendsAHeartbeatWhenTheGatewayAsksForOne(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	gateway.helloInterval.Store(int64(time.Hour / time.Millisecond))
	timing := fastDiscordTiming
	timing.jitter = func() float64 { return 1 }
	core := newDiscordTestCore()
	startDiscordReconnectRuntime(t, gateway, timing, core)
	session := connectFirstSession(t, gateway, core)
	session.message(5, "message-5")
	core.waitInbound(t)

	session.send(map[string]any{"op": 1})

	var sequence int64
	if err := json.Unmarshal(session.nextFrame(t, 1).Data, &sequence); err != nil || sequence != 5 {
		t.Fatalf("requested heartbeat carries %d (%v), want the last sequence 5", sequence, err)
	}
}

// Before any event has been received there is no sequence: the heartbeat
// carries null, not 0.
func TestDiscordRuntimeHeartbeatsWithNullBeforeAnyEvent(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	core := newDiscordTestCore()
	startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
	session := gateway.nextSession(t)
	if string(session.nextFrame(t, 1).Data) != "null" {
		t.Fatal("heartbeat before the first event must carry null")
	}
}

// Opcode 7 tells a healthy client to reconnect and resume. That is an
// instruction, not an outage: no failure is reported and no backoff is waited
// (the backoff here is an hour).
func TestDiscordRuntimeResumesAtOnceWhenTheGatewayRequestsReconnect(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	timing := fastDiscordTiming
	timing.reconnectBase, timing.reconnectMax = time.Hour, time.Hour
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, timing, core)
	first := connectFirstSession(t, gateway, core)

	first.send(map[string]any{"op": 7, "d": nil})

	second := gateway.nextSession(t)
	if second.path != "/resume" {
		t.Fatalf("redial used %s, want the resume address", second.path)
	}
	second.resumeFrame(t)
	second.resumed(2)
	core.waitState(t, adapterapi.ObservedStateConnected)
	core.requireNoFailureObserved(t)
	requireDiscordStillRunning(t, runDone)
}

// A gateway that orders a reconnect right after every connect would otherwise
// make the client spin and burn identify calls: such a session is an ordinary
// failure, reported once and backed off.
func TestDiscordRuntimeBacksOffWhenTheGatewayKeepsRequestingReconnect(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	timing := fastDiscordTiming
	timing.stableAfter = time.Hour
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, timing, core)
	first := connectFirstSession(t, gateway, core)

	first.send(map[string]any{"op": 7, "d": nil})

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "reconnect_requested" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.nextSession(t)
	requireDiscordStillRunning(t, runDone)
}

// Opcode 9 carries whether the session can still be resumed. A resumable one
// is resumed, any other is dropped and a new session identified.
func TestDiscordRuntimeFollowsTheInvalidSessionVerdict(t *testing.T) {
	for name, tc := range map[string]struct {
		resumable bool
		path      string
		opening   int
		discovers int64
	}{
		"resumable":     {resumable: true, path: "/resume", opening: 6, discovers: 1},
		"not resumable": {resumable: false, path: "/gateway", opening: 2, discovers: 2},
	} {
		t.Run(name, func(t *testing.T) {
			gateway := newFakeDiscordGateway(t)
			timing := fastDiscordTiming
			timing.reconnectBase, timing.reconnectMax = time.Hour, time.Hour
			core := newDiscordTestCore()
			_, runDone := startDiscordReconnectRuntime(t, gateway, timing, core)
			first := connectFirstSession(t, gateway, core)

			first.send(map[string]any{"op": 9, "d": tc.resumable})

			second := gateway.nextSession(t)
			if second.path != tc.path {
				t.Fatalf("redial used %s, want %s", second.path, tc.path)
			}
			second.nextFrame(t, tc.opening)
			core.requireNoFailureObserved(t)
			requireDiscordStillRunning(t, runDone)
			if hits := gateway.discoverHits.Load(); hits != tc.discovers {
				t.Fatalf("gateway discovered %d times, want %d", hits, tc.discovers)
			}
		})
	}
}

// Close codes the gateway documents as "do not reconnect" end the runtime with
// a failure that says why and is not retryable: reconnecting cannot succeed and
// every identify counts against the application's daily limit.
func TestDiscordRuntimeStopsOnCloseCodesThatForbidReconnecting(t *testing.T) {
	for name, tc := range map[string]struct {
		code      int
		reportAs  string
		mentioned string
	}{
		"authentication failed": {4004, "authentication_failed", "token"},
		"invalid shard":         {4010, "invalid_configuration", ""},
		"sharding required":     {4011, "invalid_configuration", ""},
		"disallowed intents":    {4014, "invalid_configuration", "Message Content Intent"},
		"invalid intents":       {4013, "invalid_configuration", ""},
		"invalid api version":   {4012, "invalid_configuration", ""},
	} {
		t.Run(name, func(t *testing.T) {
			gateway := newFakeDiscordGateway(t)
			core := newDiscordTestCore()
			_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
			first := gateway.nextSession(t)
			first.nextFrame(t, 2)

			first.closeWith(tc.code, "gateway says no")

			failed := core.waitState(t, adapterapi.ObservedStateFailed)
			if failed.Code != tc.reportAs || failed.Retryable || !strings.Contains(failed.Detail, tc.mentioned) ||
				!strings.Contains(failed.Detail, strconv.Itoa(tc.code)) || !strings.Contains(failed.Detail, "gateway says no") {
				t.Fatalf("failure observation = %#v", failed)
			}
			select {
			case err := <-runDone:
				if err == nil {
					t.Fatal("Run returned nil after a fatal close code")
				}
			case <-time.After(discordTestWait):
				t.Fatal("Run did not end after a fatal close code")
			}
			core.requireNoFailureObserved(t)
			select {
			case <-gateway.sessions:
				t.Fatal("the adapter redialed after a fatal close code")
			default:
			}
		})
	}
}

// Hold the session loop before its first heartbeat while the reader queues a
// requested heartbeat and acknowledges the gateway's close. The queued request
// then fails to write before the reader can publish its terminal CloseError.
func TestDiscordRuntimePreservesGatewayCloseWhenTheHeartbeatWriteFinishesFirst(t *testing.T) {
	for name, tc := range map[string]struct {
		code     int
		reportAs string
	}{
		"authentication failed": {4004, "authentication_failed"},
		"invalid api version":   {4012, "invalid_configuration"},
		"invalid intents":       {4013, "invalid_configuration"},
		"disallowed intents":    {4014, "invalid_configuration"},
	} {
		t.Run(name, func(t *testing.T) {
			gateway := newFakeDiscordGateway(t)
			gateway.helloInterval.Store(int64(time.Hour / time.Millisecond))
			heartbeatStarted, releaseHeartbeat := make(chan struct{}), make(chan struct{})
			var startOnce, releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseHeartbeat) }) }
			timing := fastDiscordTiming
			timing.jitter = func() float64 {
				startOnce.Do(func() {
					close(heartbeatStarted)
					<-releaseHeartbeat
				})
				return 1
			}
			core := newDiscordTestCore()
			_, runDone := startDiscordReconnectRuntime(t, gateway, timing, core)
			t.Cleanup(release)
			first := gateway.nextSession(t)
			first.nextFrame(t, 2)
			select {
			case <-heartbeatStarted:
			case <-time.After(discordTestWait):
				t.Fatal("session loop did not reach the heartbeat barrier")
			}

			first.send(map[string]any{"op": 1})
			first.writeMu.Lock()
			err := first.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(tc.code, "fatal gateway close"), time.Now().Add(time.Second))
			first.writeMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-first.readDone:
				var closeErr *websocket.CloseError
				if !errors.As(err, &closeErr) || closeErr.Code != tc.code {
					t.Fatalf("close acknowledgement = %v, want gateway code %d", err, tc.code)
				}
			case <-time.After(discordTestWait):
				t.Fatal("the reader did not acknowledge the gateway close")
			}
			release()

			failed := core.waitState(t, adapterapi.ObservedStateFailed)
			if failed.Code != tc.reportAs || failed.Retryable ||
				!strings.Contains(failed.Detail, strconv.Itoa(tc.code)) || !strings.Contains(failed.Detail, "fatal gateway close") {
				t.Fatalf("failure observation = %#v", failed)
			}
			select {
			case err := <-runDone:
				var failure *discordSessionError
				if !errors.As(err, &failure) || !failure.fatal || failure.code != tc.reportAs {
					t.Fatalf("Run returned %v, want the original fatal gateway classification", err)
				}
			case <-time.After(discordTestWait):
				t.Fatal("Run did not end after the competing heartbeat write")
			}
			core.requireNoFailureObserved(t)
			select {
			case <-gateway.sessions:
				t.Fatal("the adapter redialed after the competing heartbeat write")
			default:
			}
		})
	}
}

// A session-invalidating close code leaves nothing to resume: the next
// connection discovers a gateway and identifies.
func TestDiscordRuntimeIdentifiesAgainWhenTheCloseCodeInvalidatesTheSession(t *testing.T) {
	for _, code := range []int{4009, 4007} {
		gateway := newFakeDiscordGateway(t)
		core := newDiscordTestCore()
		_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
		first := connectFirstSession(t, gateway, core)

		first.closeWith(code, "")

		if failed := core.waitState(t, adapterapi.ObservedStateFailed); !failed.Retryable {
			t.Fatalf("close %d: failure observation = %#v", code, failed)
		}
		second := gateway.nextSession(t)
		if second.path != "/gateway" {
			t.Fatalf("close %d: redial used %s, want a new session", code, second.path)
		}
		second.nextFrame(t, 2)
		requireDiscordStillRunning(t, runDone)
		if hits := gateway.discoverHits.Load(); hits != 2 {
			t.Fatalf("close %d: gateway discovered %d times, want 2", code, hits)
		}
	}
}

// A slow inbound handler must not stop the heartbeat or the reads: the gateway
// judges liveness by heartbeats, so a connection whose loop is parked in a Core
// call is dropped as a zombie while the adapter still believes it is connected.
func TestDiscordRuntimeKeepsHeartbeatingWhileTheInboundHandlerBlocks(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	core := newDiscordTestCore()
	entered, release := make(chan struct{}, 1), make(chan struct{})
	core.handle = func(message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
		if message.MessageID == "message-1" {
			entered <- struct{}{}
			<-release
		}
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
	}
	_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
	session := connectFirstSession(t, gateway, core)

	session.message(2, "message-1")
	<-entered // Core is now parked inside HandleInbound
	session.message(3, "message-2")
	for range 6 {
		session.nextFrame(t, 1)
	}
	requireDiscordStillRunning(t, runDone)

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

// Core refusing one message is a fact about that message, not about the
// connection: the session stays up and later messages still arrive.
func TestDiscordRuntimeKeepsTheConnectionWhenCoreRefusesAMessage(t *testing.T) {
	for name, refuse := range map[string]func() (adapterapi.IngressReceipt, error){
		"error": func() (adapterapi.IngressReceipt, error) {
			return adapterapi.IngressReceipt{}, errors.New("storage failed")
		},
		"rejection": func() (adapterapi.IngressReceipt, error) {
			return adapterapi.IngressReceipt{Outcome: adapterapi.IngressRejected}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			gateway := newFakeDiscordGateway(t)
			core := newDiscordTestCore()
			core.handle = func(message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
				if message.MessageID == "message-1" {
					return refuse()
				}
				return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
			}
			_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
			session := connectFirstSession(t, gateway, core)

			session.message(2, "message-1")
			session.message(3, "message-2")

			if got := core.waitInbound(t); string(got.MessageID) != "message-2" {
				t.Fatalf("inbound = %q, want the message after the refused one", got.MessageID)
			}
			requireDiscordStillRunning(t, runDone)
			select {
			case <-gateway.sessions:
				t.Fatal("a refused message caused a reconnect")
			default:
			}
		})
	}
}

// The gateway accepts the websocket but never sends hello.
func TestDiscordRuntimeRedialsWhenHelloNeverArrives(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	gateway.skipHello.Store(true)
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)
	gateway.nextSession(t)

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "hello_timeout" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	gateway.skipHello.Store(false)
	gateway.nextSession(t)
	requireDiscordStillRunning(t, runDone)
}

// An unreachable gateway is retried with backoff and reported once, however
// many attempts the outage takes.
func TestDiscordRuntimeBacksOffThroughAGatewayOutageAndReportsOnce(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	gateway.discoverFails.Store(4)
	core := newDiscordTestCore()
	_, runDone := startDiscordReconnectRuntime(t, gateway, fastDiscordTiming, core)

	if failed := core.waitState(t, adapterapi.ObservedStateFailed); failed.Code != "connect_failed" || !failed.Retryable {
		t.Fatalf("failure observation = %#v", failed)
	}
	first := gateway.nextSession(t)
	first.nextFrame(t, 2)
	first.ready(1, "session-1", gateway.wsURL("/resume"))
	core.waitState(t, adapterapi.ObservedStateConnected)
	core.requireNoFailureObserved(t)
	requireDiscordStillRunning(t, runDone)
	if hits := gateway.discoverHits.Load(); hits != 5 {
		t.Fatalf("gateway discovery attempts = %d, want 4 failures and a success", hits)
	}
}

func TestDiscordRuntimeStopInterruptsTheBackoff(t *testing.T) {
	gateway := newFakeDiscordGateway(t)
	gateway.discoverFails.Store(1 << 20)
	timing := fastDiscordTiming
	timing.reconnectBase, timing.reconnectMax = time.Hour, time.Hour
	core := newDiscordTestCore()
	runtime, runDone := startDiscordReconnectRuntime(t, gateway, timing, core)
	core.waitState(t, adapterapi.ObservedStateFailed)

	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run after Stop = %v, want nil", err)
		}
	case <-time.After(discordTestWait):
		t.Fatal("Run did not return after Stop during the backoff")
	}
}
