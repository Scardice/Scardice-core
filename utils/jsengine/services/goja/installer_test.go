package gojaservices_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	"github.com/gorilla/websocket"

	"Scardice-core/utils/jsengine/services"
	gojaservices "Scardice-core/utils/jsengine/services/goja"
)

func TestInstallerPreservesCoreGojaServiceBehavior(t *testing.T) {
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	defer loop.Terminate()
	moduleRegistry := require.NewRegistry()
	installer := gojaservices.NewInstaller(gojaservices.Options{
		Registry: moduleRegistry,
		Loop:     loop,
		Proxy:    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		Filesystem: gojaservices.FilesystemHooks{
			Require: func(*goja.Runtime, *goja.Object) {},
			Enable:  func(*goja.Runtime) {},
		},
	})
	registry := services.NewRegistry()
	installation, err := registry.Install(installer)
	if err != nil {
		t.Fatalf("registry.Install() error = %v", err)
	}
	defer installation.Close()

	var runErr error
	loop.Run(func(vm *goja.Runtime) {
		runErr = installer.Enable(vm)
		if runErr != nil {
			return
		}
		_, runErr = vm.RunString(`
			const controller = new AbortController();
			let aborted = false;
			controller.signal.addEventListener("abort", () => { aborted = true; });
			controller.abort("stop");
			const cloned = structuredClone({ answer: 42, nested: [true] });
			const inspected = util.inspect({ answer: 42 });
			const required = require("@seal/structuredclone");
			globalThis.__serviceResult = [aborted, cloned.answer, cloned.nested[0], inspected, typeof required.structuredClone];
		`)
	})
	if runErr != nil {
		t.Fatalf("Goja service script error = %v", runErr)
	}
	loop.Run(func(vm *goja.Runtime) {
		value := vm.Get("__serviceResult").Export()
		result, ok := value.([]interface{})
		if !ok || len(result) != 5 {
			t.Fatalf("service result = %#v", value)
		}
		if result[0] != true || result[1] != int64(42) || result[2] != true || result[4] != "function" {
			t.Fatalf("service result = %#v", result)
		}
		if result[3] == "" {
			t.Fatal("util.inspect returned an empty string")
		}
	})

	for _, name := range []services.Name{
		services.Console, services.Crypto, services.Fetch, services.HTTP,
		services.WebSocket, services.Filesystem, services.Abort, services.StructuredClone, services.UtilInspect,
	} {
		if _, err := registry.Lookup(name); err != nil {
			t.Fatalf("Lookup(%q) error = %v", name, err)
		}
	}
}
func TestInstallerCloseOnlyClosesOwnedWebSockets(t *testing.T) {
	upgrader := websocket.Upgrader{}
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-hold
	}))
	defer srv.Close()
	defer close(hold)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	loop1 := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	loop2 := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	go loop1.StartInForeground()
	go loop2.StartInForeground()
	t.Cleanup(func() {
		loop1.Stop()
		loop2.Stop()
	})
	time.Sleep(20 * time.Millisecond)

	installer1 := gojaservices.NewInstaller(gojaservices.Options{
		Registry: require.NewRegistry(),
		Loop:     loop1,
	})
	installer2 := gojaservices.NewInstaller(gojaservices.Options{
		Registry: require.NewRegistry(),
		Loop:     loop2,
	})
	if err := installer1.Install(); err != nil {
		t.Fatalf("installer1.Install() error = %v", err)
	}
	if err := installer2.Install(); err != nil {
		t.Fatalf("installer2.Install() error = %v", err)
	}

	var scriptErr error
	runOnLoop := func(loop *eventloop.EventLoop, installer *gojaservices.Installer) {
		done := make(chan struct{})
		loop.RunOnLoop(func(vm *goja.Runtime) {
			if err := installer.Enable(vm); err != nil {
				scriptErr = err
			} else {
				_, scriptErr = vm.RunString(`globalThis.__ws = new WebSocket("` + wsURL + `");`)
			}
			close(done)
		})
		<-done
	}
	runOnLoop(loop1, installer1)
	if scriptErr != nil {
		t.Fatalf("installer1 WebSocket setup error = %v", scriptErr)
	}
	runOnLoop(loop2, installer2)
	if scriptErr != nil {
		t.Fatalf("installer2 WebSocket setup error = %v", scriptErr)
	}

	readyState := func(loop *eventloop.EventLoop) int {
		done := make(chan struct{})
		state := -1
		loop.RunOnLoop(func(vm *goja.Runtime) {
			state = int(vm.Get("__ws").ToObject(vm).Get("readyState").ToInteger())
			close(done)
		})
		<-done
		return state
	}
	waitForState := func(loop *eventloop.EventLoop, expected int) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if readyState(loop) == expected {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("WebSocket did not reach readyState %d", expected)
	}
	waitForState(loop1, 1)
	waitForState(loop2, 1)

	if err := installer1.Close(); err != nil {
		t.Fatalf("installer1.Close() error = %v", err)
	}
	if got := readyState(loop1); got != 3 {
		t.Fatalf("owner WebSocket readyState after close = %d, want 3", got)
	}
	if got := readyState(loop2); got != 1 {
		t.Fatalf("unrelated WebSocket readyState after owner close = %d, want 1", got)
	}
	_ = installer2.Close()
}
