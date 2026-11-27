package kook

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type pendingSwitchRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (h *pendingSwitchRecorder) Type() string { return "251" }

func (h *pendingSwitchRecorder) Handle(i EventContext) {
	h.mu.Lock()
	h.seen = append(h.seen, i.GetCommon().Common.Content)
	h.mu.Unlock()
}

func (h *pendingSwitchRecorder) last() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.seen) == 0 {
		return ""
	}
	return h.seen[len(h.seen)-1]
}

// TestStalePendingDroppedAfterSessionSwitch 锁定换 session 时的暂存事件清理：
// 旧 session 在 sn 空洞期间缓存的 102，绝不能在新 session 走到 sn=102 时
// 被当成新会话事件执行（旧命令重放），也不能把新 session 的 102 静默吞掉。
func TestStalePendingDroppedAfterSessionSwitch(t *testing.T) {
	old, had := registeredEventHandler["251"]
	registeredEventHandler["251"] = &dispatchTestProvider{}
	t.Cleanup(func() {
		if had {
			registeredEventHandler["251"] = old
		} else {
			delete(registeredEventHandler, "251")
		}
	})

	s := New("token", nopLogger{})
	conn := &websocket.Conn{}
	d := newEventDispatcher()
	s.wsConn = conn
	s.dispatcher = d
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 100)

	h := &pendingSwitchRecorder{}
	s.addEventHandler(h)
	go s.dispatchEvents(d)
	t.Cleanup(d.close)

	mk := func(sn int64, content string) *queuedEvent {
		return &queuedEvent{
			conn:  conn,
			epoch: s.sessionEpoch.Load(),
			event: &Event{Signal: EventSignalEvent, SequenceNumber: sn},
			data: EventData{
				EventDataGeneral: &EventDataGeneral{Type: 251, Content: content},
				Extra:            []byte(`{}`),
			},
		}
	}

	// 旧 session：101 缺失，102 被放进重排缓冲。
	if !d.push(mk(102, "stale-102")) {
		t.Fatal("push failed")
	}
	time.Sleep(100 * time.Millisecond)

	// 同一连接上服务端换了 session（s=6 ACK 的 session_id 变化）。
	s.applyResumeAckSessionID(conn, "sess-2")
	if got := atomic.LoadInt64(s.sequence); got != 0 {
		t.Fatalf("sequence = %d after session switch, want 0", got)
	}

	for sn := int64(1); sn <= 102; sn++ {
		if !d.push(mk(sn, fmt.Sprintf("new-%d", sn))) {
			t.Fatalf("push sn=%d failed", sn)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(s.sequence) >= 102 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	if got := h.last(); got != "new-102" {
		t.Fatalf("last handled = %q, want new-102 (seq=%d)", got, atomic.LoadInt64(s.sequence))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, content := range h.seen {
		if content == "stale-102" {
			t.Fatalf("old-session event executed after session switch: %v", h.seen)
		}
	}
}
