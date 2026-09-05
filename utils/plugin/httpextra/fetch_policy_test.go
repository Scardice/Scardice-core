package sealhttp

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
)

func TestEnableFetchWithPolicyRejectsBeforeNetworkDispatch(t *testing.T) {
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	defer loop.Terminate()
	var requests int
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ })
	policyErr := errors.New("network denied")
	var runErr error
	loop.Run(func(vm *goja.Runtime) {
		runErr = EnableFetchWithPolicy(vm, loop, handler, func(string) error { return policyErr })
		if runErr != nil {
			return
		}
		_, runErr = vm.RunString(`fetch("https://example.test/blocked").then(() => { throw new Error("resolved"); }).catch(e => { globalThis.__fetchErr = String(e); });`)
	})
	if runErr != nil {
		t.Fatalf("fetch policy script error = %v", runErr)
	}
	loop.Run(func(vm *goja.Runtime) {
		if got := vm.Get("__fetchErr").String(); got == "" {
			t.Fatal("fetch policy rejection was not observed")
		}
	})
	if requests != 0 {
		t.Fatalf("network handler received %d requests, want 0", requests)
	}
}

func TestEnableFetchWithContextHooksRestoresRequestContext(t *testing.T) {
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	defer loop.Terminate()
	loop.Start()
	sentinel := &struct{}{}
	contextSeen := make(chan any, 1)
	resultSeen := make(chan string, 1)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	var runErr error
	runOnLoopSync(t, loop, func(vm *goja.Runtime) {
		runErr = EnableFetchWithPolicyAndLifecycleAndContext(
			vm,
			loop,
			handler,
			nil,
			nil,
			AsyncContextHooks{
				CurrentContext: func() any { return sentinel },
				// The completion hook must not wait for the loop; a fetch worker
				// may be resumed while the owner thread is still busy.
				ScheduleOnLoop: func(context any, run func(*goja.Runtime) error) error {
					contextSeen <- context
					if !loop.RunOnLoop(func(vm *goja.Runtime) { _ = run(vm) }) {
						return errors.New("event loop is closed")
					}
					return nil
				},
			},
		)
		if runErr != nil {
			return
		}
		if err := vm.Set("recordFetchResult", func(value string) {
			resultSeen <- value
		}); err != nil {
			runErr = err
			return
		}
		_, runErr = vm.RunString(`fetch("http://example.test/ok").then(() => recordFetchResult("ok"));`)
	})
	if runErr != nil {
		t.Fatalf("fetch script error = %v", runErr)
	}
	select {
	case context := <-contextSeen:
		if context != sentinel {
			t.Fatalf("fetch context = %#v, want request context", context)
		}
	case <-time.After(time.Second):
		t.Fatal("fetch completion did not run")
	}
	select {
	case result := <-resultSeen:
		if result != "ok" {
			t.Fatalf("fetch result = %q, want ok", result)
		}
	case <-time.After(time.Second):
		t.Fatal("fetch Promise continuation did not run")
	}
}

// runOnLoopSync enters the loop from the test goroutine, which is never the
// loop owner, so waiting for the callback is safe here.
func runOnLoopSync(t *testing.T, loop *eventloop.EventLoop, fn func(*goja.Runtime)) {
	t.Helper()
	done := make(chan struct{})
	if !loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		fn(vm)
	}) {
		t.Fatal("event loop rejected the callback")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for loop callback")
	}
}
