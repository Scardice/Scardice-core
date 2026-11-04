package kook

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type nopEntry struct{}

func (nopEntry) Bool(string, bool) Entry             { return nopEntry{} }
func (nopEntry) Bytes(string, []byte) Entry          { return nopEntry{} }
func (nopEntry) Caller(int) Entry                    { return nopEntry{} }
func (nopEntry) Dur(string, time.Duration) Entry     { return nopEntry{} }
func (nopEntry) Err(string, error) Entry             { return nopEntry{} }
func (nopEntry) Float64(string, float64) Entry       { return nopEntry{} }
func (nopEntry) IPAddr(string, net.IP) Entry         { return nopEntry{} }
func (nopEntry) Int(string, int) Entry               { return nopEntry{} }
func (nopEntry) Int64(string, int64) Entry           { return nopEntry{} }
func (nopEntry) Interface(string, interface{}) Entry { return nopEntry{} }
func (nopEntry) Msg(string)                          {}
func (nopEntry) Msgf(string, ...interface{})         {}
func (nopEntry) Str(string, string) Entry            { return nopEntry{} }
func (nopEntry) Strs(string, []string) Entry         { return nopEntry{} }
func (nopEntry) Time(string, time.Time) Entry        { return nopEntry{} }

type nopLogger struct{}

func (nopLogger) Trace() Entry { return nopEntry{} }
func (nopLogger) Debug() Entry { return nopEntry{} }
func (nopLogger) Info() Entry  { return nopEntry{} }
func (nopLogger) Warn() Entry  { return nopEntry{} }
func (nopLogger) Error() Entry { return nopEntry{} }
func (nopLogger) Fatal() Entry { return nopEntry{} }

func TestCloseIsIdempotentAndConcurrent(t *testing.T) {
	s := New("token", nopLogger{})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Close calls deadlocked")
	}
}

func TestReconnectStopsAfterClose(t *testing.T) {
	s := New("token", nopLogger{})
	s.gateway = "ws://127.0.0.1:1" // 必定连接失败

	done := make(chan struct{})
	go func() {
		s.reconnect()
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	_ = s.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnect kept retrying after user closed the session")
	}
}

func TestOpenAfterCloseReconnects(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk},
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")

	if err := s.Close(); err != nil {
		t.Fatalf("initial Close() error = %v", err)
	}
	if err := s.Open(); err != nil {
		t.Fatalf("Open() after Close() error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestResumeGatewayURLPreservesBasePathAndAddsResumeParams(t *testing.T) {
	got, err := resumeGatewayURL("wss://gateway.example/ws?compress=1&token=abc", 42, "session-id")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Host != "gateway.example" || parsed.Path != "/ws" {
		t.Fatalf("resume URL lost base fields: %s", got)
	}
	if query.Get("compress") != "1" || query.Get("token") != "abc" {
		t.Fatalf("resume URL lost existing params: %s", got)
	}
	if query.Get("resume") != "1" || query.Get("sn") != "42" || query.Get("session_id") != "session-id" {
		t.Fatalf("resume URL params = %s", parsed.RawQuery)
	}
}

func TestOnEventSkipsMalformedSequence(t *testing.T) {
	s := New("token", nopLogger{})

	okPayload := []byte(`{"s":0,"sn":42,"d":{"type":250}}`)
	if _, err := s.onEvent(nil, websocket.TextMessage, okPayload); err != nil {
		t.Fatalf("onEvent() error = %v", err)
	}
	if got := atomic.LoadInt64(s.sequence); got != 42 {
		t.Fatalf("sequence = %d, want 42", got)
	}

	// 同一 sn 重放应被丢弃，且不改变本地最大 sn。
	if _, err := s.onEvent(nil, websocket.TextMessage, okPayload); err != nil {
		t.Fatalf("duplicate onEvent() error = %v", err)
	}
	if got := atomic.LoadInt64(s.sequence); got != 42 {
		t.Fatalf("sequence after duplicate = %d, want 42", got)
	}

	// 解析失败的事件不能永久堵住后续 sn：记录并跳过，sequence 应推进到 43。
	failPayload := []byte(`{"s":0,"sn":43,"d":"not-an-event-data"}`)
	if _, err := s.onEvent(nil, websocket.TextMessage, failPayload); err != nil {
		t.Fatalf("malformed event should be skipped, not returned as error: %v", err)
	}
	if got := atomic.LoadInt64(s.sequence); got != 43 {
		t.Fatalf("sequence after malformed event = %d, want 43", got)
	}
}

func TestGuildUserListParsesItems(t *testing.T) {
	s := New("token", nopLogger{})
	s.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := `{"code":0,"data":{"items":[{"id":"u1","username":"tester"}],"meta":{"page":1,"page_total":1,"page_size":50,"total":1},"sort":{}}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	users, _, meta, err := s.GuildUserList("guild-id", nil)
	if err != nil {
		t.Fatalf("GuildUserList() error = %v", err)
	}
	if len(users) != 1 || users[0].ID != "u1" || users[0].Username != "tester" {
		t.Fatalf("GuildUserList() users = %#v", users)
	}
	if meta == nil || meta.Total != 1 {
		t.Fatalf("GuildUserList() meta = %#v", meta)
	}
}

func TestReconnectBacksOffAfterImmediateClose(t *testing.T) {
	var connections int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		atomic.AddInt32(&connections, 1)
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk, "session_id": "sess-1"},
		})
		_ = conn.Close()
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")
	go s.reconnect()
	time.Sleep(500 * time.Millisecond)
	_ = s.Close()

	if got := atomic.LoadInt32(&connections); got > 2 {
		t.Fatalf("connections in 500ms = %d, reconnect did not back off", got)
	}
}

func TestResumeFlowUsesLastProcessedSn(t *testing.T) {
	queries := make(chan url.Values, 4)
	var s *Session
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		queries <- r.URL.Query()
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk, "session_id": "sess-1"},
		})
		if atomic.LoadInt64(s.sequence) == 0 {
			_ = conn.WriteJSON(map[string]interface{}{
				"s":  EventSignalEvent,
				"sn": 5,
				"d":  map[string]interface{}{"type": 250},
			})
			deadline := time.Now().Add(2 * time.Second)
			for atomic.LoadInt64(s.sequence) < 5 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			// 跳过短连接退避，单独验证 resume 参数。
			s.Lock()
			s.lastConnectAt = time.Now().Add(-minStableConnection - time.Second)
			s.Unlock()
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
		_ = conn.Close()
	}))
	defer server.Close()

	s = New("token", nopLogger{})
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")
	if err := s.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	first := <-queries
	if first.Get("resume") != "" {
		t.Fatalf("first connection unexpectedly had resume params: %s", first.Encode())
	}

	var second url.Values
	select {
	case second = <-queries:
	case <-time.After(4 * time.Second):
		t.Fatal("no resume connection within 4s")
	}
	if second.Get("resume") != "1" || second.Get("sn") != "5" || second.Get("session_id") != "sess-1" {
		t.Fatalf("resume query = %s", second.Encode())
	}
}

func TestResumeWithNewSessionIDResetsSn(t *testing.T) {
	queries := make(chan url.Values, 4)
	var s *Session
	var connections int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		n := atomic.AddInt32(&connections, 1)
		queries <- r.URL.Query()
		if n == 1 {
			_ = conn.WriteJSON(map[string]interface{}{
				"s": EventSignalHello,
				"d": map[string]interface{}{"code": EventStatusOk, "session_id": "sess-1"},
			})
			_ = conn.WriteJSON(map[string]interface{}{
				"s":  EventSignalEvent,
				"sn": 5,
				"d":  map[string]interface{}{"type": 250},
			})
			deadline := time.Now().Add(2 * time.Second)
			for atomic.LoadInt64(s.sequence) < 5 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			s.Lock()
			s.lastConnectAt = time.Now().Add(-minStableConnection - time.Second)
			s.Unlock()
			_ = conn.Close()
			return
		}
		// resume 被服务器忽略，返回了一个全新 session。
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk, "session_id": "sess-2"},
		})
		time.Sleep(100 * time.Millisecond)
		_ = conn.Close()
	}))
	defer server.Close()

	s = New("token", nopLogger{})
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")
	if err := s.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()

	<-queries // first connection
	var second url.Values
	select {
	case second = <-queries:
	case <-time.After(4 * time.Second):
		t.Fatal("no resume connection within 4s")
	}
	if second.Get("resume") != "1" || second.Get("sn") != "5" || second.Get("session_id") != "sess-1" {
		t.Fatalf("resume query = %s", second.Encode())
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.RLock()
		seq := atomic.LoadInt64(s.sequence)
		sessionID := s.sessionID
		s.RUnlock()
		if seq == 0 && sessionID == "sess-2" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.RLock()
	seq := atomic.LoadInt64(s.sequence)
	sessionID := s.sessionID
	s.RUnlock()
	t.Fatalf("new session state = (seq=%d, session=%q), want (0, sess-2)", seq, sessionID)
}

func TestHeartbeatAckTimesOutWithoutPong(t *testing.T) {
	s := New("token", nopLogger{})
	sentAt := time.Now().UTC()
	if s.waitForHeartbeatAck(sentAt, 20*time.Millisecond, nil) {
		t.Fatal("heartbeat ACK should time out when no PONG arrives")
	}
}

func TestResumeRetryKeepsSessionOnTransientFailure(t *testing.T) {
	oldDelays := resumeRetryDelays
	resumeRetryDelays = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() { resumeRetryDelays = oldDelays })

	var resumeCount, freshCount int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if r.URL.Query().Get("resume") == "1" {
			n := atomic.AddInt32(&resumeCount, 1)
			if n <= 2 {
				_ = conn.Close()
				return
			}
			_ = conn.WriteJSON(map[string]interface{}{
				"s": EventSignalHello,
				"d": map[string]interface{}{"code": EventStatusOk, "session_id": "sess-1"},
			})
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}
		atomic.AddInt32(&freshCount, 1)
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk, "session_id": "fresh-session"},
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	s := New("token", nopLogger{})
	s.gateway = "ws" + strings.TrimPrefix(server.URL, "http")
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)

	done := make(chan struct{})
	go func() {
		s.reconnect()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect did not finish")
	}
	defer s.Close()

	if got := atomic.LoadInt32(&resumeCount); got != 3 {
		t.Fatalf("resume attempts = %d, want 3", got)
	}
	if got := atomic.LoadInt32(&freshCount); got != 0 {
		t.Fatalf("fresh connections = %d, want 0 (resume should be preserved)", got)
	}
	if got := atomic.LoadInt64(s.sequence); got != 5 {
		t.Fatalf("sequence = %d, want 5", got)
	}
	if s.sessionID != "sess-1" {
		t.Fatalf("session ID = %q, want sess-1", s.sessionID)
	}
}

func TestPermanentResumeErrors(t *testing.T) {
	for _, code := range []EventStatusCode{
		EventStatusMissingArgument,
		EventStatusInvalidToken,
		EventStatusTokenAuthFailed,
		EventStatusTokenExpired,
		EventStatusResumeFailed,
		EventStatusSessionExpired,
		EventStatusInvalidSequenceNumber,
	} {
		if !isPermanentResumeError(&helloStatusError{code: code}) {
			t.Errorf("status %d should be considered permanent", code)
		}
	}
	if isPermanentResumeError(errors.New("network down")) {
		t.Fatal("network error must not be considered permanent")
	}
}

func TestResumeFallsBackToFreshSessionAfterBudget(t *testing.T) {
	oldDelays := resumeRetryDelays
	resumeRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
	t.Cleanup(func() { resumeRetryDelays = oldDelays })

	var resumeCount, freshCount int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if r.URL.Query().Get("resume") == "1" {
			atomic.AddInt32(&resumeCount, 1)
			_ = conn.Close()
			return
		}
		atomic.AddInt32(&freshCount, 1)
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk, "session_id": "fresh-session"},
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
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

	done := make(chan struct{})
	go func() {
		s.reconnect()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconnect did not finish")
	}
	defer s.Close()

	if got := atomic.LoadInt32(&resumeCount); got != maxAmbiguousResumeAttempts {
		t.Fatalf("resume attempts = %d, want %d", got, maxAmbiguousResumeAttempts)
	}
	if got := atomic.LoadInt32(&freshCount); got != 1 {
		t.Fatalf("fresh connections = %d, want 1", got)
	}
	if got := atomic.LoadInt64(s.sequence); got != 0 {
		t.Fatalf("sequence = %d, want 0 after fresh session", got)
	}
}

func TestEventSignalValues(t *testing.T) {
	cases := []struct {
		name string
		got  EventSignal
		want EventSignal
	}{
		{"event", EventSignalEvent, 0},
		{"hello", EventSignalHello, 1},
		{"ping", EventSignalPing, 2},
		{"pong", EventSignalPong, 3},
		{"resume", EventSignalResume, 4},
		{"reconnect", EventSignalReconnect, 5},
		{"resume_ack", EventSignalResumeAck, 6},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestEventStatusCodeValues(t *testing.T) {
	cases := []struct {
		name string
		got  EventStatusCode
		want EventStatusCode
	}{
		{"ok", EventStatusOk, 0},
		{"missing_argument", EventStatusMissingArgument, 40100},
		{"invalid_token", EventStatusInvalidToken, 40101},
		{"token_auth_failed", EventStatusTokenAuthFailed, 40102},
		{"token_expired", EventStatusTokenExpired, 40103},
		{"resume_failed", EventStatusResumeFailed, 40106},
		{"session_expired", EventStatusSessionExpired, 40107},
		{"invalid_sn", EventStatusInvalidSequenceNumber, 40108},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}
