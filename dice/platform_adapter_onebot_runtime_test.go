package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	socketio "github.com/PaienNate/pineutil/evsocket/v2"
	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
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
	if err := runtime.handleInbound(context.Background(), raw); err != nil { t.Fatal(err) }
	message := <-core.inboundCh
	if message.ProviderEventID != "onebot-message-42" { t.Fatalf("provider id = %q", message.ProviderEventID) }
}

func TestOnebotInboundWithoutMessageIDLeavesFallbackForCore(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"message","user_id":7,"message":"hello"}`)
	if err := runtime.handleInbound(context.Background(), raw); err != nil { t.Fatal(err) }
	message := <-core.inboundCh
	if message.ProviderEventID != "" { t.Fatalf("provider id = %q", message.ProviderEventID) }
	if !message.OccurredAt.IsZero() {
		t.Fatalf("missing provider time became non-deterministic: %v", message.OccurredAt)
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
	if runtime.RejectedInboundCount() != 1 { t.Fatalf("rejected count = %d", runtime.RejectedInboundCount()) }
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
	if err := runtime.Stop(context.Background()); err != nil { t.Fatal(err) }
	if runtime.BackpressureInboundCount() != 1 { t.Fatalf("backpressure count = %d", runtime.BackpressureInboundCount()) }
}

func TestOnebotRuntimeKeepsAliveOnRetryableInboundError(t *testing.T) {
	if !isRetryableOnebotInboundError(messageflow.ErrIngressBackpressure) {
		t.Fatal("ingress backpressure would terminate the runtime")
	}
	if isRetryableOnebotInboundError(adapterapi.ErrInvalidContract) {
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

	client, _, err := websocket.DefaultDialer.Dial("ws://"+address+"/ws", http.Header{"Authorization": []string{"Bearer runtime-token"}})
	if err != nil {
		t.Fatal(err)
	}
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
	inboundJSON := `{"post_type":"message","time":1700000000,"message_id":77,"user_id":42,"group_id":9,"message":[{"type":"text","data":{"text":"hello"}}]}`
	if err := client.WriteMessage(websocket.TextMessage, []byte(inboundJSON)); err != nil {
		t.Fatal(err)
	}
	select {
	case inbound := <-core.inboundCh:
		if inbound.Text != "hello" || inbound.Sender != "QQ:42" || inbound.Conversation != "QQ:group:9" {
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
	core.waitState(t, adapterapi.ObservedStateFailed)
	core.waitState(t, adapterapi.ObservedStateStopping)
	core.waitState(t, adapterapi.ObservedStateStopped)
	select {
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not terminate after remote close")
	case err := <-runDone:
		if err == nil || !strings.Contains(err.Error(), "remote") {
			t.Fatalf("remote close run error = %v", err)
		}
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	if runtime.manager != nil || runtime.conn != nil || runtime.server != nil || runtime.listener != nil || runtime.emitter != nil || runtime.tokenRef != nil || runtime.core != nil {
		t.Fatal("runtime retained resources after cleanup")
	}
	runtime.mu.Unlock()
}
func TestOnebotRuntimeUnauthorizedReverseTokenFailsClosed(t *testing.T) {
	config, address := onebotRuntimeServerConfig(t)
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{bytes: []byte("runtime-token")})
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	core.waitState(t, adapterapi.ObservedStateStarting)
	client, _, err := websocket.DefaultDialer.Dial("ws://"+address+"/ws", http.Header{"Authorization": []string{"wrong-token"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	failure := core.waitState(t, adapterapi.ObservedStateFailed)
	if failure.Code != "auth_failed" {
		t.Fatalf("failure code = %q", failure.Code)
	}
	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("unauthorized runtime returned nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unauthorized runtime did not terminate")
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

func TestOnebotRuntimeClientStartupFailure(t *testing.T) {
	config := OnebotConfig{Mode: "client", URL: "ws://127.0.0.1:1/ws"}
	runtime := newOnebotRuntime(config, nil)
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 8)}
	err := runtime.Run(context.Background(), core)
	if err == nil {
		t.Fatal("Run unexpectedly connected to unavailable client endpoint")
	}
	core.waitState(t, adapterapi.ObservedStateStarting)
	failure := core.waitState(t, adapterapi.ObservedStateFailed)
	if failure.Code != "connect_failed" {
		t.Fatalf("failure code = %q", failure.Code)
	}
	core.waitState(t, adapterapi.ObservedStateStopping)
	core.waitState(t, adapterapi.ObservedStateStopped)
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
	if !rehandoffOnebotInbound(event) || !rehandoffOnebotInbound(event) {
		t.Fatal("expected two bounded rehandoffs")
	}
	if event.attempt != maxOnebotInboundRetries {
		t.Fatalf("attempts = %d, want %d", event.attempt, maxOnebotInboundRetries)
	}
	if rehandoffOnebotInbound(event) {
		t.Fatal("unexpected rehandoff beyond bound")
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
		"inbound.rejected":     "Rejected inbound events: 3",
		"inbound.backpressure": "Inbound backpressure events: 2",
		"inbound.conflicts":    "Inbound identity conflicts: 1",
		"inbound.retries":      "Inbound bounded rehandoffs: 4",
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
	wrapper := &socketio.WebsocketWrapper{}
	runtime.accountTransportDropCount(wrapper, 3)
	runtime.accountTransportDropCount(wrapper, 5)
	if got := runtime.transportDropped.Load(); got != 5 {
		t.Fatalf("cumulative transport drops = %d, want 5", got)
	}
	runtime.connectionMu.Lock()
	runtime.connections[wrapper] = make(chan struct{})
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
