package sealws

import (
	"errors"
	"testing"

	"github.com/dop251/goja"
)

func TestWebSocketPolicyRejectsBeforeDial(t *testing.T) {
	loop := startLoop(t)
	policyErr := errors.New("websocket denied")
	var scriptErr error
	runOnLoopSync(loop, func(vm *goja.Runtime) {
		EnableWithPolicy(vm, loop, func(string) error { return policyErr })
		_, scriptErr = vm.RunString(`
			globalThis.__wsPolicy = "";
			try { new WebSocket("ws://127.0.0.1:1"); } catch (e) { globalThis.__wsPolicy = String(e); }
		`)
	})
	if scriptErr != nil {
		t.Fatalf("policy script error = %v", scriptErr)
	}
	var message string
	runOnLoopSync(loop, func(vm *goja.Runtime) { message = vm.Get("__wsPolicy").String() })
	if message == "" {
		t.Fatal("WebSocket policy did not reject the constructor")
	}
}
