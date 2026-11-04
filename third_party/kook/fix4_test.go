package kook

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestEmptyEventDataIsSkippedWithoutPanic(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)

	// d 为空对象时 EventDataGeneral 为 nil；旧代码会在这里 nil deref 并打崩进程。
	if _, err := s.onEvent(conn, websocket.TextMessage, []byte(`{"s":0,"sn":1,"d":{}}`)); err != nil {
		t.Fatalf("onEvent() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(s.sequence) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt64(s.sequence); got != 1 {
		t.Fatalf("sequence = %d, want 1 (malformed event should be skipped)", got)
	}
	select {
	case event := <-h.events:
		t.Fatalf("handler should not receive malformed event, got %q", event)
	default:
	}
}

func TestBadSystemBodyIsSkipped(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)

	bad := []byte(`{"s":0,"sn":1,"d":{"type":255,"channel_type":"GROUP","extra":{"type":"251","body":"not-an-object"}}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, bad); err != nil {
		t.Fatalf("onEvent() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(s.sequence) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt64(s.sequence); got != 1 {
		t.Fatalf("sequence = %d, want 1 (bad system body should be skipped)", got)
	}
	select {
	case event := <-h.events:
		t.Fatalf("handler should not run with a zero extra, got %q", event)
	default:
	}
}

func TestFinishEventDoesNotDeleteNewEpochInFlight(t *testing.T) {
	s := New("token", nopLogger{})
	oldEpoch := s.sessionEpoch.Load()
	if !s.beginEvent(oldEpoch, 1) {
		t.Fatal("beginEvent(old) failed")
	}

	s.resetSessionState(false)
	newEpoch := s.sessionEpoch.Load()
	if !s.beginEvent(newEpoch, 1) {
		t.Fatal("beginEvent(new) failed")
	}

	// 旧 session 的迟到回调不能删除新 session 的 inFlight 标记。
	s.finishEvent(oldEpoch, 1, true)
	if s.beginEvent(newEpoch, 1) {
		t.Fatal("stale finishEvent removed the new session inFlight marker")
	}
}

func TestExtractEventSequence(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
		want int64
		ok   bool
	}{
		{"event", []byte(`{"s":0,"sn":42,"d":"bad"}`), 42, true},
		{"missing signal", []byte(`{"sn":7}`), 7, true},
		{"control signal", []byte(`{"s":3,"sn":42}`), 0, false},
		{"zero sn", []byte(`{"s":0,"sn":0}`), 0, false},
		{"malformed", []byte(`{"s":0,"sn":42`), 0, false},
		{"string sn", []byte(`{"s":0,"sn":"9"}`), 9, true},
	}
	for _, tc := range cases {
		got, ok := extractEventSequence(websocket.TextMessage, tc.msg)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: extractEventSequence() = (%d, %v), want (%d, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write([]byte(`{"s":0,"sn":11,"d":"bad"}`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if got, ok := extractEventSequence(websocket.BinaryMessage, compressed.Bytes()); !ok || got != 11 {
		t.Fatalf("compressed extractEventSequence() = (%d, %v), want (11, true)", got, ok)
	}
}

func TestPermanentAuthErrorClassification(t *testing.T) {
	for _, code := range []EventStatusCode{
		EventStatusMissingArgument,
		EventStatusInvalidToken,
		EventStatusTokenAuthFailed,
		EventStatusTokenExpired,
	} {
		if !isPermanentAuthError(&helloStatusError{code: code}) {
			t.Errorf("status %d should be a permanent auth error", code)
		}
	}
	if isPermanentAuthError(&helloStatusError{code: EventStatusResumeFailed}) {
		t.Fatal("resume failure must not be treated as a permanent auth error")
	}
	if !isPermanentAuthError(&RestError{Code: int(EventStatusTokenExpired)}) {
		t.Fatal("REST token expiry must be treated as a permanent auth error")
	}
	if isPermanentAuthError(nil) {
		t.Fatal("nil must not be a permanent auth error")
	}
}

func TestFatalHandlerStopsReconnectOnAuthError(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var connections int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		atomic.AddInt32(&connections, 1)
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusTokenExpired},
		})
		_ = conn.Close()
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	s.gateway = wsURL
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)
	s.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"code":0,"data":{"url":"` + wsURL + `"}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	fatal := make(chan error, 1)
	s.SetFatalHandler(func(err error) {
		select {
		case fatal <- err:
		default:
		}
	})

	done := make(chan struct{})
	go func() {
		s.reconnect()
		close(done)
	}()

	select {
	case err := <-fatal:
		if err == nil {
			t.Fatal("fatal handler received nil error")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("fatal handler was not called for a permanent auth error")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect did not stop after a permanent auth error")
	}
	if got := atomic.LoadInt32(&connections); got != 2 {
		t.Fatalf("connections = %d, want 2 (one resume + one fresh attempt)", got)
	}
	if !s.isClosed() {
		_ = s.Close()
	}
}
