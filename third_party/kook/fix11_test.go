package kook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestPermanentResumeErrorClassification(t *testing.T) {
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
			t.Errorf("HELLO status %d should be a permanent resume error", code)
		}
		if !isPermanentResumeError(&RestError{Code: int(code)}) {
			t.Errorf("REST status %d should be a permanent resume error", code)
		}
	}
	if isPermanentResumeError(&helloStatusError{code: EventStatusOk}) {
		t.Fatal("HELLO status ok must not be a permanent resume error")
	}
	if isPermanentResumeError(&RestError{Code: 500}) {
		t.Fatal("REST 500 must not be a permanent resume error")
	}
	if isPermanentResumeError(nil) {
		t.Fatal("nil must not be a permanent resume error")
	}
	// RestError 的值类型也应当被识别（某些调用方可能返回非指针）。
	var valueErr error = RestError{Code: int(EventStatusTokenExpired)}
	if !isPermanentResumeError(valueErr) {
		t.Fatal("value RestError token expiry should be a permanent resume error")
	}
	// resume-only 错误不能当成永久认证错误，否则会过早停止重连。
	if isPermanentAuthError(&RestError{Code: int(EventStatusResumeFailed)}) {
		t.Fatal("resume failure must not be a permanent auth error")
	}
}

func TestApplyResumeAckSessionIDSessionCurrentOnly(t *testing.T) {
	s := New("token", nopLogger{})
	conn := &websocket.Conn{}
	other := &websocket.Conn{}
	s.wsConn = conn
	s.sessionID = "sess-1"

	s.applyResumeAckSessionID(conn, "sess-2")
	if got := s.ResumeState().SessionID; got != "sess-2" {
		t.Fatalf("session id = %q, want sess-2", got)
	}
	s.applyResumeAckSessionID(other, "sess-3")
	if got := s.ResumeState().SessionID; got != "sess-2" {
		t.Fatalf("stale connection changed session id to %q", got)
	}
	s.applyResumeAckSessionID(conn, "")
	if got := s.ResumeState().SessionID; got != "sess-2" {
		t.Fatalf("empty ack session id changed session id to %q", got)
	}
}

func TestResumeWithEmptySessionIDResetsSn(t *testing.T) {
	queries := make(chan string, 4)
	var s *Session
	var connections int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		n := atomic.AddInt32(&connections, 1)
		queries <- r.URL.RawQuery
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
		// resume 成功返回 HELLO，但缺少 session_id。
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk},
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
	select {
	case query := <-queries:
		if !strings.Contains(query, "resume=1") || !strings.Contains(query, "session_id=sess-1") {
			t.Fatalf("resume query = %q", query)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("no resume connection within 4s")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.RLock()
		seq := atomic.LoadInt64(s.sequence)
		sessionID := s.sessionID
		s.RUnlock()
		if seq == 0 && sessionID == "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.RLock()
	seq := atomic.LoadInt64(s.sequence)
	sessionID := s.sessionID
	s.RUnlock()
	t.Fatalf("state after empty-session resume = (seq=%d, session=%q), want (0, \"\")", seq, sessionID)
}

func TestResumeAckSessionChangeReplaysPreAckEvents(t *testing.T) {
	s := New("token", nopLogger{})
	conn := &websocket.Conn{}
	s.wsConn = conn
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)
	dispatcher := newEventDispatcher()
	s.dispatcher = dispatcher
	s.resumePending = true
	s.preAck = []*queuedEvent{
		{conn: conn, event: &Event{SequenceNumber: 2}},
		{conn: conn, event: &Event{SequenceNumber: 1}},
	}

	s.applyResumeAckSessionID(conn, "sess-2")

	if got := atomic.LoadInt64(s.sequence); got != 0 {
		t.Fatalf("sequence = %d, want 0 after a session change", got)
	}
	if s.sessionID != "sess-2" {
		t.Fatalf("session ID = %q, want sess-2", s.sessionID)
	}
	if s.resumePending || len(s.preAck) != 0 {
		t.Fatal("pre-ack state was not cleared")
	}
	if len(dispatcher.queue) != 2 {
		t.Fatalf("replayed %d events, want 2", len(dispatcher.queue))
	}
	if got := dispatcher.queue[0].event.SequenceNumber; got != 1 {
		t.Fatalf("first replayed sn = %d, want 1", got)
	}
	if got := dispatcher.queue[1].event.SequenceNumber; got != 2 {
		t.Fatalf("second replayed sn = %d, want 2", got)
	}
}

func TestResumeAckSameSessionDropsPreAckEvents(t *testing.T) {
	s := New("token", nopLogger{})
	conn := &websocket.Conn{}
	s.wsConn = conn
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)
	dispatcher := newEventDispatcher()
	s.dispatcher = dispatcher
	s.resumePending = true
	s.preAck = []*queuedEvent{{conn: conn, event: &Event{SequenceNumber: 3}}}

	s.applyResumeAckSessionID(conn, "sess-1")

	if got := atomic.LoadInt64(s.sequence); got != 5 {
		t.Fatalf("sequence = %d, want 5 for a same-session ack", got)
	}
	if len(dispatcher.queue) != 0 {
		t.Fatalf("replayed %d events for a same-session ack, want 0", len(dispatcher.queue))
	}
	if s.resumePending || len(s.preAck) != 0 {
		t.Fatal("pre-ack state was not cleared")
	}
}
