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

func TestCloseWaitsForRunningHandler(t *testing.T) {
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
	s.listening = make(chan interface{})
	dispatcher := newEventDispatcher()
	s.dispatcher = dispatcher
	go s.dispatchEvents(dispatcher)

	block := make(chan struct{})
	h := &dispatchTestHandler{started: make(chan struct{}, 1), block: block}
	old, had := registeredEventHandler["251"]
	registeredEventHandler["251"] = &dispatchTestProvider{}
	t.Cleanup(func() {
		if had {
			registeredEventHandler["251"] = old
		} else {
			delete(registeredEventHandler, "251")
		}
	})
	s.addEventHandler(h)

	payload := []byte(`{"s":0,"sn":1,"d":{"type":251,"content":"slow","extra":{}}}`)
	if _, err := s.onEvent(conn, websocket.TextMessage, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	closed := make(chan struct{})
	go func() {
		_ = s.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while the handler was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(block)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after the handler finished")
	}
}

func TestOpenResumesExistingSessionInsteadOfResetting(t *testing.T) {
	var gotQuery string
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]interface{}{
			"s": EventSignalHello,
			"d": map[string]interface{}{"code": EventStatusOk, "session_id": "sess-1"},
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	s := New("token", nopLogger{})
	s.gateway = wsURL
	s.sessionID = "sess-1"
	atomic.StoreInt64(s.sequence, 5)

	if err := s.Open(); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer s.Close()
	if !strings.Contains(gotQuery, "resume=1") || !strings.Contains(gotQuery, "sn=5") || !strings.Contains(gotQuery, "session_id=sess-1") {
		t.Fatalf("Open() did not use resume parameters: %q", gotQuery)
	}
}
