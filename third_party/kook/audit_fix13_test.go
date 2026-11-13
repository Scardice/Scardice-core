package kook

import (
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

// A RESUME ACK that reports a different session must invalidate the handlers
// still running for the old session. Otherwise the old handler's finishEvent
// restores the old high sn after the ACK reset it, and every replayed /
// new-session event is dropped as a duplicate again (online but silent).
func TestResumeAckSessionChangeInvalidatesInFlightOldSession(t *testing.T) {
	s := New("token", nopLogger{})
	conn := &websocket.Conn{}
	s.wsConn = conn
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 99)

	oldEpoch := s.sessionEpoch.Load()
	if !s.beginEvent(oldEpoch, 100) {
		t.Fatal("could not arm an in-flight event for the old session")
	}

	dispatcher := newEventDispatcher()
	s.dispatcher = dispatcher
	s.resumePending = true
	s.preAck = []*queuedEvent{
		{conn: conn, epoch: oldEpoch, event: &Event{SequenceNumber: 1}},
		{conn: conn, epoch: oldEpoch, event: &Event{SequenceNumber: 2}},
	}

	s.applyResumeAckSessionID(conn, "sess-2")

	// The slow old-session handler finally returns after the ACK.
	s.finishEvent(oldEpoch, 100, true)

	if got := atomic.LoadInt64(s.sequence); got != 0 {
		t.Fatalf("sequence = %d after the old handler finished, want 0 (session was replaced)", got)
	}
	if len(dispatcher.queue) != 2 {
		t.Fatalf("replayed %d pre-ack events, want 2", len(dispatcher.queue))
	}
	newEpoch := s.sessionEpoch.Load()
	if newEpoch == oldEpoch {
		t.Fatal("session epoch was not advanced on a session change")
	}
	for _, q := range dispatcher.queue {
		if q.epoch != newEpoch {
			t.Fatalf("replayed event epoch = %d, want %d", q.epoch, newEpoch)
		}
	}
	if len(s.inFlight) != 0 {
		t.Fatalf("in-flight markers from the old session were not cleared: %v", s.inFlight)
	}
}

// Some deployments/proxies ignore compress=1 and put plain JSON into a binary
// frame. That must be decoded instead of being treated as a broken connection.
func TestBinaryFrameWithoutZlibFallsBackToJSON(t *testing.T) {
	s := New("token", nopLogger{})
	_, err := s.onEvent(nil, websocket.BinaryMessage, []byte(`{"s":3}`))
	if err != nil {
		t.Fatalf("plain JSON binary frame returned error: %v", err)
	}
	if s.LastHeartbeatAck.IsZero() {
		t.Fatal("pong in a plain JSON binary frame was not processed")
	}
}

func TestRedactGatewayURLRemovesToken(t *testing.T) {
	got := redactGatewayURL("wss://gateway.kookapp.cn/gateway?compress=1&token=secret-token")
	if got != "wss://gateway.kookapp.cn/gateway" {
		t.Fatalf("redacted gateway = %q", got)
	}
	if redactGatewayURL("") != "" {
		t.Fatal("empty gateway must stay empty")
	}
	if redactGatewayURL("://bad") != "invalid-gateway-url" {
		t.Fatalf("invalid gateway was not redacted: %q", redactGatewayURL("://bad"))
	}
}

// extractEventSequence 必须和 onEvent 用同一套解码规则：compress=1 的部署里
// 仍可能出现未压缩 JSON 的 binary 帧，提取不到 sn 会让读循环白关一次连接。
func TestExtractEventSequenceFromPlainJSONBinaryFrame(t *testing.T) {
	sn, ok := extractEventSequence(websocket.BinaryMessage, []byte(`{"s":0,"sn":42,"d":{}}`))
	if !ok || sn != 42 {
		t.Fatalf("extractEventSequence = (%d,%v), want (42,true)", sn, ok)
	}
	// 控制信令不能推进事件序列。
	if _, ok := extractEventSequence(websocket.BinaryMessage, []byte(`{"s":2,"sn":7}`)); ok {
		t.Fatal("control signal must not yield an event sequence number")
	}
}
