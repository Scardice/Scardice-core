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

func TestNullEventFrameIsRejected(t *testing.T) {
	s := New("token", nopLogger{})
	if _, err := s.onEvent(nil, websocket.TextMessage, []byte("null")); err == nil {
		t.Fatal("onEvent(null) should return an error")
	}
}

func TestGapWatcherUsesFirstMissingSN(t *testing.T) {
	oldTimeout := gapResyncTimeout
	gapResyncTimeout = 50 * time.Millisecond
	t.Cleanup(func() { gapResyncTimeout = oldTimeout })

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
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
	// Prevent the watcher from starting a real reconnect after it closes the test connection.
	s.closed = true
	atomic.StoreInt64(s.sequence, 4)

	dispatcher := newEventDispatcher()
	s.dispatcher = dispatcher
	go s.dispatchEvents(dispatcher)
	defer dispatcher.close()

	if !dispatcher.push(&queuedEvent{
		conn:  conn,
		epoch: s.sessionEpoch.Load(),
		event: &Event{Signal: EventSignalEvent, SequenceNumber: 6},
		data:  EventData{EventDataGeneral: &EventDataGeneral{Type: MessageTypeText}},
	}) {
		t.Fatal("failed to queue gap event")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.RLock()
		current := s.wsConn
		s.RUnlock()
		if current == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("gap watcher did not force resync after the missing sn timeout")
}

func TestNormalEventBadExtraIsSkipped(t *testing.T) {
	s, conn, h := newDispatchTestSession(t)

	payload := []byte(`{"s":0,"sn":1,"d":{"type":251,"content":"bad","extra":"not-an-object"}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, payload); err != nil {
		t.Fatalf("onEvent() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(s.sequence) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt64(s.sequence); got != 1 {
		t.Fatalf("sequence = %d, want 1", got)
	}
	select {
	case event := <-h.events:
		t.Fatalf("handler should not receive a zero-value extra, got %q", event)
	default:
	}
}
