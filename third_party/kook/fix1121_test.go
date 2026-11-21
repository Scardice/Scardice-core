package kook

import (
	"testing"

	"github.com/gorilla/websocket"
)

// TestGapTimeoutStreakForcesNewSession_1121fix1 锁定：同一个 expected sn
// 连续 maxGapResyncAttempts 次超时后必须要求转新 session；不同 expected
// 或真正补齐后计数要重置。
func TestGapTimeoutStreakForcesNewSession_1121fix1(t *testing.T) {
	s := New("token", nopLogger{})

	for i := 1; i < maxGapResyncAttempts; i++ {
		if s.noteGapTimeout(101) {
			t.Fatalf("attempt %d/%d must not force a new session", i, maxGapResyncAttempts)
		}
	}
	if !s.noteGapTimeout(101) {
		t.Fatalf("attempt %d must force a new session", maxGapResyncAttempts)
	}

	// 新的 expected 从 1 重新计数。
	if s.noteGapTimeout(102) {
		t.Fatal("a different expected sn must reset the streak")
	}
	// 显式补齐后也重置。
	s.noteGapTimeout(102)
	s.clearGapTimeout()
	if s.noteGapTimeout(102) {
		t.Fatal("clearGapTimeout must reset the streak")
	}
}

// TestPreAckOverflowMarksTruncated_1121fix1 锁定：preAck 满时除了丢弃新事件，
// 还必须留下截断标记；ACK 到达后才能立即补发尾部，而不是等下一个事件。
func TestPreAckOverflowMarksTruncated_1121fix1(t *testing.T) {
	s, conn, _ := newDispatchTestSession(t)
	s.sessionID = "sess-1"

	s.Lock()
	s.resumePending = true
	for i := 0; i < maxPreAckEvents; i++ {
		s.preAck = append(s.preAck, newPreAckTestEvent(conn, s.sessionEpoch.Load(), int64(i+1), "old"))
	}
	s.Unlock()

	payload := []byte(`{"s":0,"sn":99999,"d":{"type":251,"content":"overflow","extra":{}}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, payload); err != nil {
		t.Fatalf("onEvent: %v", err)
	}
	s.RLock()
	got := len(s.preAck)
	truncated := s.preAckTruncated
	s.RUnlock()
	if got != maxPreAckEvents {
		t.Fatalf("preAck len = %d, want %d", got, maxPreAckEvents)
	}
	if !truncated {
		t.Fatal("preAck overflow must set the truncated flag")
	}
}

// TestResumeAckTimeoutRequiresNoProgress_1121fix1 锁定：只有 sequence 和
// preAck 最大 sn 都不前进时连续超时才升级为转新 session；服务端仍在补发
// 时不能误判。
func TestResumeAckTimeoutRequiresNoProgress_1121fix1(t *testing.T) {
	s := New("token", nopLogger{})

	for i := 1; i <= maxResumeAckTimeouts; i++ {
		want := i == maxResumeAckTimeouts
		if got := s.noteResumeAckTimeout(); got != want {
			t.Fatalf("timeout %d = %v, want %v", i, got, want)
		}
	}

	// 有重放进展：preAck 最大 sn 前进后计数回到 1。
	s.Lock()
	s.preAckMaxSN = 10
	s.Unlock()
	if s.noteResumeAckTimeout() {
		t.Fatal("replay progress must reset the no-progress streak")
	}
	for i := 2; i <= maxResumeAckTimeouts; i++ {
		want := i == maxResumeAckTimeouts
		if got := s.noteResumeAckTimeout(); got != want {
			t.Fatalf("progress timeout %d = %v, want %v", i, got, want)
		}
	}
}

// TestReconnectSkipsWhenConnectionExists_1121fix1 锁定：已有活动连接时，
// 排队中的 reconnect 不能把端点状态改回 Connecting。
func TestReconnectSkipsWhenConnectionExists_1121fix1(t *testing.T) {
	s := New("token", nopLogger{})
	s.wsConn = &websocket.Conn{}
	s.reconnect()
	if s.reconnecting {
		t.Fatal("reconnect must not start while a connection exists")
	}
	if s.reconnectSeq != 0 {
		t.Fatalf("reconnectSeq = %d, want 0", s.reconnectSeq)
	}
}
