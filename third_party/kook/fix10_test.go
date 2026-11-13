package kook

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRestoreResumeStateWithoutGateway(t *testing.T) {
	s := New("token", nopLogger{})
	if !s.RestoreResumeState(ResumeState{SessionID: "sess-1", SN: 7}) {
		t.Fatal("RestoreResumeState() should accept a state without gateway")
	}
	got := s.ResumeState()
	if got.SessionID != "sess-1" || got.SN != 7 || got.Gateway != "" {
		t.Fatalf("restored state = %#v", got)
	}
}

// 从持久化快照恢复时不再保存带 token 的网关地址；Open 必须先通过 REST
// 重新获取 gateway，再在连接 URL 上附加 resume 参数。
func TestOpenResumesAfterRestoreWithoutGateway(t *testing.T) {
	var resumeSeen, gatewayCalls int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if r.URL.Query().Get("resume") == "1" {
			atomic.AddInt32(&resumeSeen, 1)
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
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	s := New("token", nopLogger{})
	s.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&gatewayCalls, 1)
		body := `{"code":0,"data":{"url":"` + wsURL + `"}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	if !s.RestoreResumeState(ResumeState{SessionID: "sess-1", SN: 7}) {
		t.Fatal("RestoreResumeState() failed")
	}
	if err := s.Open(); err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer s.Close()

	if got := atomic.LoadInt32(&gatewayCalls); got == 0 {
		t.Fatal("Open() did not re-fetch gateway over REST")
	}
	if got := atomic.LoadInt32(&resumeSeen); got != 1 {
		t.Fatalf("resume connections = %d, want 1", got)
	}
	if got := atomic.LoadInt64(s.sequence); got != 7 {
		t.Fatalf("sequence = %d, want 7", got)
	}
}

func TestStaleEventDroppedAfterEpochChange(t *testing.T) {
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
	var calls int32
	s.addEventHandler(&dispatchTestHandler{count: &calls})

	epoch := s.sessionEpoch.Load()
	// 模拟事件在等待 handler 锁期间会话被替换。
	s.resetSessionState(false)

	ev := &Event{Signal: EventSignalEvent, SequenceNumber: 1}
	data := &EventData{EventDataGeneral: &EventDataGeneral{Type: 251}, Extra: []byte(`{}`)}
	if s.runEventHandlerChecked(ev, data, epoch) {
		t.Fatal("stale event should not be reported as success")
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("stale handler ran %d times", got)
	}
}

// 禁用后立即启用会创建新的 Session；适配器注入的共享锁必须让新旧会话的
// handler 互斥，否则旧长命令会和新命令并发修改同一份数据。
func TestSharedHandlerLockSerializesAcrossSessions(t *testing.T) {
	old, had := registeredEventHandler["251"]
	registeredEventHandler["251"] = &dispatchTestProvider{}
	t.Cleanup(func() {
		if had {
			registeredEventHandler["251"] = old
		} else {
			delete(registeredEventHandler, "251")
		}
	})

	shared := &sync.Mutex{}
	s1 := New("token", nopLogger{})
	s2 := New("token", nopLogger{})
	s1.SetHandlerLock(shared)
	s2.SetHandlerLock(shared)

	started := make(chan struct{}, 2)
	block := make(chan struct{})
	h := &dispatchTestHandler{started: started, block: block}
	s1.addEventHandler(h)
	s2.addEventHandler(h)

	ev := &Event{Signal: EventSignalEvent, SequenceNumber: 1}
	data := &EventData{EventDataGeneral: &EventDataGeneral{Type: 251}, Extra: []byte(`{}`)}
	firstDone := make(chan bool, 1)
	secondDone := make(chan bool, 1)
	go func() { firstDone <- s1.runEventHandler(ev, data) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first session handler did not start")
	}

	go func() { secondDone <- s2.runEventHandler(ev, data) }()
	select {
	case <-started:
		t.Fatal("second session handler ran concurrently with the first")
	case <-time.After(50 * time.Millisecond):
	}

	close(block)
	for _, done := range []chan bool{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handler did not finish after the shared lock was released")
		}
	}
}
