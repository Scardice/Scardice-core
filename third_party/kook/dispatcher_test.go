package kook

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type dispatchTestCtx struct {
	common EventHandlerCommonContext
	extra  struct{}
}

func (c *dispatchTestCtx) GetExtra() interface{}                 { return &c.extra }
func (c *dispatchTestCtx) GetCommon() *EventHandlerCommonContext { return &c.common }

type dispatchTestProvider struct{}

func (p *dispatchTestProvider) Type() string      { return "251" }
func (p *dispatchTestProvider) New() EventContext { return &dispatchTestCtx{} }

type dispatchTestHandler struct {
	mu      sync.Mutex
	order   []string
	events  chan string
	count   *int32
	started chan struct{}
	block   <-chan struct{}
}

func (h *dispatchTestHandler) Type() string { return "251" }

func (h *dispatchTestHandler) Handle(i EventContext) {
	c := i.GetCommon()
	h.mu.Lock()
	h.order = append(h.order, c.Common.Content)
	h.mu.Unlock()
	if h.count != nil {
		atomic.AddInt32(h.count, 1)
	}
	if h.started != nil {
		select {
		case h.started <- struct{}{}:
		default:
		}
	}
	if h.events != nil {
		h.events <- c.Common.Content
	}
	if h.block != nil {
		<-h.block
	}
}

func newDispatchTestSession(t *testing.T) (*Session, *websocket.Conn, *dispatchTestHandler) {
	t.Helper()
	s := New("token", nopLogger{})
	conn := &websocket.Conn{}

	d := newEventDispatcher()

	s.wsConn = conn
	s.dispatcher = d
	go s.dispatchEvents(d)

	h := &dispatchTestHandler{events: make(chan string, 8)}
	old, had := registeredEventHandler["251"]
	registeredEventHandler["251"] = &dispatchTestProvider{}
	t.Cleanup(func() {
		d.close()
		if had {
			registeredEventHandler["251"] = old
		} else {
			delete(registeredEventHandler, "251")
		}
	})
	s.addEventHandler(h)
	return s, conn, h
}

func TestDispatcherProcessesOutOfOrderEventsInSNOrder(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)

	for _, sn := range []int64{1, 3, 2} {
		payload := []byte(fmt.Sprintf(`{"s":0,"sn":%d,"d":{"type":251,"content":"sn%d","extra":{}}}`, sn, sn))
		if _, err := s.onEvent(conn, websocket.TextMessage, payload); err != nil {
			t.Fatalf("onEvent(sn=%d): %v", sn, err)
		}
	}

	deadline := time.After(3 * time.Second)
	for _, want := range []string{"sn1", "sn2", "sn3"} {
		select {
		case got := <-h.events:
			if got != want {
				t.Fatalf("event order = %q, want %q", got, want)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q; sequence=%d", want, atomic.LoadInt64(s.sequence))
		}
	}
	if got := atomic.LoadInt64(s.sequence); got != 3 {
		t.Fatalf("sequence = %d, want 3", got)
	}
}

func TestBeginEventRejectsDuplicateInFlight(t *testing.T) {
	s := New("token", nopLogger{})
	epoch := s.sessionEpoch.Load()

	if !s.beginEvent(epoch, 7) {
		t.Fatal("first beginEvent should succeed")
	}
	if s.beginEvent(epoch, 7) {
		t.Fatal("duplicate in-flight sn should be rejected")
	}
	s.finishEvent(epoch, 7, true)
	if got := atomic.LoadInt64(s.sequence); got != 7 {
		t.Fatalf("sequence = %d, want 7", got)
	}
	if s.beginEvent(epoch, 7) {
		t.Fatal("already processed sn should be rejected")
	}
}

func TestBadSystemEventDoesNotStallDispatcher(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)
	atomic.StoreInt64(s.sequence, 41)

	// 坏 system extra 不能把 sn=42 永久卡住；分发器应跳过它并继续处理 sn=43。
	bad := []byte(`{"s":0,"sn":42,"d":{"type":255,"extra":"not-an-object"}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, bad); err != nil {
		t.Fatalf("onEvent(bad): %v", err)
	}
	good := []byte(`{"s":0,"sn":43,"d":{"type":251,"content":"after-bad","extra":{}}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, good); err != nil {
		t.Fatalf("onEvent(good): %v", err)
	}

	select {
	case got := <-h.events:
		if got != "after-bad" {
			t.Fatalf("event after bad packet = %q, want after-bad", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("dispatcher stalled after bad packet; sequence=%d", atomic.LoadInt64(s.sequence))
	}
	if got := atomic.LoadInt64(s.sequence); got != 43 {
		t.Fatalf("sequence = %d, want 43", got)
	}
}

func TestSlowHandlerDoesNotBlockPong(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)
	started := make(chan struct{}, 1)
	block := make(chan struct{})
	h.started = started
	h.block = block

	payload := []byte(`{"s":0,"sn":1,"d":{"type":251,"content":"slow","extra":{}}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, payload); err != nil {
		t.Fatalf("onEvent: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("slow handler did not start")
	}

	sentAt := time.Now().UTC()
	if _, err := s.onEvent(conn, websocket.TextMessage, []byte(`{"s":3}`)); err != nil {
		t.Fatalf("onEvent(PONG): %v", err)
	}
	s.RLock()
	ack := s.LastHeartbeatAck
	s.RUnlock()
	close(block)
	if ack.Before(sentAt) {
		t.Fatal("PONG was not processed while the event handler was blocked")
	}
}
