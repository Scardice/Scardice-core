package dice

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
)

func TestOnebotUnknownNoticeReachesCore(t *testing.T) {
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	runtime.core = core
	raw := []byte(`{"post_type":"notice","notice_type":"group_msg_emoji_like","time":1700000000,"self_id":3003,"group_id":2002,"user_id":1001,"vendor":{"id":9007199254740993}}`)
	if err := runtime.handleInbound(t.Context(), raw); err != nil {
		t.Fatalf("valid unknown notice was rejected: %v", err)
	}
	select {
	case message := <-core.inboundCh:
		if message.Conversation != "QQ-Group:2002" || message.Sender != "QQ:1001" {
			t.Fatalf("notice lost its activation scope: %#v", message)
		}
	default:
		t.Fatal("unknown notice was silently discarded")
	}
}

func startOnebotPassthroughPeer(t *testing.T) (*onebotRuntime, *websocket.Conn) {
	t.Helper()
	config, address := onebotRuntimeServerConfig(t)
	runtime := newOnebotRuntime(config, &onebotRuntimeResolver{bytes: []byte("passthrough-test-token")})
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 16)}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background(), core) }()
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := runtime.Stop(stopCtx); err != nil {
			t.Errorf("stop runtime: %v", err)
		}
		if err := <-runDone; err != nil {
			t.Errorf("runtime exited: %v", err)
		}
	})
	core.waitState(t, adapterapi.ObservedStateStarting)
	provider := dialOnebotRuntime(t, address, "passthrough-test-token")
	t.Cleanup(func() { _ = provider.Close() })
	answerOnebotLogin(t, provider, 3003)
	core.waitState(t, adapterapi.ObservedStateConnected)
	if err := provider.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return runtime, provider
}

func TestOnebotRawResponsePreservesCompleteJSON(t *testing.T) {
	runtime, provider := startOnebotPassthroughPeer(t)
	runtime.mu.Lock()
	outbound := runtime.emitter
	runtime.mu.Unlock()
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := outbound.Raw(t.Context(), "vendor_extension", map[string]any{"id": "9007199254740993"})
		done <- result{body: body, err: err}
	}()
	var request struct {
		Action string `json:"action"`
		Echo   string `json:"echo"`
	}
	if err := provider.ReadJSON(&request); err != nil {
		t.Fatal(err)
	}
	if request.Action != "vendor_extension" || request.Echo == "" {
		t.Fatalf("unexpected protocol request: %#v", request)
	}
	want := fmt.Sprintf("{\n  \"echo\":%q,\"status\":\"failed\",\"retcode\":1404,\"data\":{\"id\":9007199254740993},\"vendor\":{\"precision\":1.2300e+04}\n}", request.Echo)
	if err := provider.WriteMessage(websocket.TextMessage, []byte(want)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("protocol rejection became transport failure: %v", got.err)
		}
		if string(got.body) != want {
			t.Fatalf("protocol response was rewritten:\n got %s\nwant %s", got.body, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("protocol response was not correlated")
	}
}

func TestOnebotPassthroughClassifiesProviderOutcomesWithoutRetry(t *testing.T) {
	for _, test := range []struct {
		name, raw string
		want      adapterapi.EffectOutcome
	}{
		{"completed", `{"status":"ok","retcode":0}`, adapterapi.EffectSucceeded},
		{"rejected", `{"status":"failed","retcode":1404}`, adapterapi.EffectTerminal},
		{"async-ack-only", `{"status":"async","retcode":1}`, adapterapi.EffectAmbiguous},
		{"incomplete-response", `{"status":"ok"}`, adapterapi.EffectAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := onebotRawResult("vendor.call", adapterapi.EffectRetryNonIdempotent, []byte(test.raw))
			if got.Outcome != test.want {
				t.Fatalf("provider outcome = %#v, want %v", got, test.want)
			}
		})
	}
}
