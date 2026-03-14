package sealws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/gorilla/websocket"
)

func startLoop(t *testing.T) *eventloop.EventLoop {
	t.Helper()
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	go loop.StartInForeground()
	time.Sleep(20 * time.Millisecond)
	t.Cleanup(func() {
		loop.Stop()
	})
	return loop
}

func runOnLoopSync(loop *eventloop.EventLoop, f func(*goja.Runtime)) {
	done := make(chan struct{})
	loop.RunOnLoop(func(vm *goja.Runtime) {
		f(vm)
		close(done)
	})
	<-done
}

func waitForCondition(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout waiting for condition")
}

func TestWebSocketBasicMessage(t *testing.T) {
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte("hello-ws"))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	loop := startLoop(t)
	GlobalConnManager.CloseAll()
	t.Cleanup(func() { GlobalConnManager.CloseAll() })

	runOnLoopSync(loop, func(vm *goja.Runtime) {
		Enable(vm, loop)
		_, err := vm.RunString(`globalThis.__wsMsg = ""; globalThis.__wsErr = "";`)
		if err != nil {
			t.Fatalf("init ws globals failed: %v", err)
		}

		script := `
			const ws = new WebSocket("` + wsURL + `");
			ws.onmessage = (ev) => { globalThis.__wsMsg = String(ev.data); ws.close(); };
			ws.onerror = (ev) => { globalThis.__wsErr = String(ev.error || "ws error"); };
		`
		_, err = vm.RunString(script)
		if err != nil {
			t.Fatalf("run websocket script failed: %v", err)
		}
	})

	waitForCondition(t, 3*time.Second, func() bool {
		done := false
		runOnLoopSync(loop, func(vm *goja.Runtime) {
			msg := vm.Get("__wsMsg").String()
			errText := vm.Get("__wsErr").String()
			if errText != "" {
				t.Fatalf("websocket failed: %s", errText)
			}
			done = msg == "hello-ws"
		})
		return done
	})
}
