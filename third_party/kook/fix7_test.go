package kook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestResumeStateRoundTrip(t *testing.T) {
	s := New("token", nopLogger{})
	s.Lock()
	s.gateway = "wss://example.invalid/gateway?compress=1"
	s.sessionID = "sess-1"
	s.Unlock()
	atomic.StoreInt64(s.sequence, 42)

	state := s.ResumeState()
	if state.Gateway == "" || state.SessionID != "sess-1" || state.SN != 42 {
		t.Fatalf("ResumeState() = %#v", state)
	}

	restored := New("token", nopLogger{})
	if !restored.RestoreResumeState(state) {
		t.Fatal("RestoreResumeState() failed")
	}
	if got := restored.ResumeState(); got != state {
		t.Fatalf("restored state = %#v, want %#v", got, state)
	}
}

// 文档要求两次心跳补发间隔为 2 秒、4 秒。这里缩短时钟，
// 验证两次补发的实际间隔约等于 4 秒，而不是等满一个 6 秒 ACK 超时。
func TestHeartbeatRetryUsesDocumentedSpacing(t *testing.T) {
	oldAck, oldFirst, oldSecond := getHeartbeatTiming()
	const (
		testAck    = 60 * time.Millisecond
		testFirst  = 20 * time.Millisecond
		testSecond = 50 * time.Millisecond
	)
	setHeartbeatTiming(testAck, testFirst, testSecond)
	t.Cleanup(func() {
		setHeartbeatTiming(oldAck, oldFirst, oldSecond)
	})

	var mu sync.Mutex
	var sent []time.Time
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			var msg pingSignal
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Signal != EventSignalPing {
				continue
			}
			mu.Lock()
			sent = append(sent, time.Now())
			mu.Unlock()
		}
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	s := New("token", nopLogger{})
	s.wsConn = conn
	listening := make(chan interface{})
	defer close(listening)

	start := time.Now().UTC()
	result := make(chan bool, 1)
	go func() {
		result <- s.retryHeartbeat(conn, listening, start)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(sent)
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d retry pings arrived", n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	first, second := sent[0], sent[1]
	mu.Unlock()
	if delay := first.Sub(start); delay < 15*time.Millisecond || delay > 2*testFirst {
		t.Fatalf("first retry delay = %v, want about %v", delay, testFirst)
	}
	if gap := second.Sub(first); gap < 40*time.Millisecond || gap > 2*testSecond {
		t.Fatalf("gap between retry pings = %v, want about %v", gap, testSecond)
	}

	select {
	case ok := <-result:
		if ok {
			t.Fatal("retryHeartbeat succeeded without any PONG")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retryHeartbeat did not finish")
	}
}
