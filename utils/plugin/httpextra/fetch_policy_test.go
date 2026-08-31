package sealhttp

import (
	"errors"
	"net/http"
	"testing"

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
