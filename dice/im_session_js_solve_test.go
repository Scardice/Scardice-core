package dice

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func TestResolveJSSolveValue_SyncObject(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`({ matched: true, solved: true, showHelp: false })`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case ret := <-done:
		if !ret.Matched || !ret.Solved || ret.ShowHelp {
			t.Fatalf("unexpected solve result: %#v", ret)
		}
	case err := <-fail:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_FulfilledPromise(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`Promise.resolve({ matched: true, solved: true, showHelp: true })`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case ret := <-done:
		if !ret.Matched || !ret.Solved || !ret.ShowHelp {
			t.Fatalf("unexpected solve result: %#v", ret)
		}
	case err := <-fail:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_MapUsesJSTruthiness(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`({ matched: 1, solved: "yes", showHelp: 0 })`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case ret := <-done:
		if !ret.Matched || !ret.Solved || ret.ShowHelp {
			t.Fatalf("unexpected solve result with JS truthiness: %#v", ret)
		}
	case err := <-fail:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_EmptyResultWithoutReplyFails(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`undefined`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case <-done:
		t.Fatal("unexpected done for empty result without reply")
	case err := <-fail:
		if err == nil || err.Error() != "solve returned empty result" {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_EmptyResultAfterReplyIsCompatible(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`undefined`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, &MsgContext{CommandReplied: true}, "test", v, done, fail)

	select {
	case ret := <-done:
		if !ret.Matched || !ret.Solved || ret.ShowHelp {
			t.Fatalf("unexpected solve result: %#v", ret)
		}
	case err := <-fail:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_RejectedPromise(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`Promise.reject(new Error("boom"))`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case <-done:
		t.Fatal("unexpected done for rejected promise")
	case err := <-fail:
		if !strings.Contains(err.Error(), "boom") {
			t.Fatalf("unexpected reject error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for rejected promise")
	}
}

func TestResolveJSSolveValue_FulfilledEmptyResultWithoutReplyFails(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`Promise.resolve(undefined)`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case <-done:
		t.Fatal("unexpected done for fulfilled empty result without reply")
	case err := <-fail:
		if err == nil || err.Error() != "solve returned empty result" {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_FulfilledEmptyResultAfterReplyIsCompatible(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`Promise.resolve(undefined)`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, &MsgContext{CommandReplied: true}, "test", v, done, fail)

	select {
	case ret := <-done:
		if !ret.Matched || !ret.Solved || ret.ShowHelp {
			t.Fatalf("unexpected solve result: %#v", ret)
		}
	case err := <-fail:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for solve result")
	}
}

func TestResolveJSSolveValue_PendingPromiseTimeout(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`new Promise(() => {})`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	_, err = waitJSSolveResult(done, fail, 30*time.Millisecond)
	if !errors.Is(err, errJSSolveTimeout) {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestResolveJSSolveValue_FulfilledInvalidResult(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`Promise.resolve(123)`)
	if err != nil {
		t.Fatalf("run js failed: %v", err)
	}

	done := make(chan CmdExecuteResult, 1)
	fail := make(chan error, 1)
	resolveJSSolveValue(vm, nil, "test", v, done, fail)

	select {
	case <-done:
		t.Fatal("unexpected done for invalid result")
	case err := <-fail:
		if err == nil {
			t.Fatal("expected parse error")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for invalid result failure")
	}
}

func TestWaitJSSolveResult(t *testing.T) {
	t.Run("done", func(t *testing.T) {
		done := make(chan CmdExecuteResult, 1)
		fail := make(chan error, 1)
		done <- CmdExecuteResult{Matched: true, Solved: true}
		ret, err := waitJSSolveResult(done, fail, 50*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ret.Matched || !ret.Solved {
			t.Fatalf("unexpected result: %#v", ret)
		}
	})

	t.Run("fail", func(t *testing.T) {
		done := make(chan CmdExecuteResult, 1)
		fail := make(chan error, 1)
		fail <- errors.New("x")
		_, err := waitJSSolveResult(done, fail, 50*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "x") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		done := make(chan CmdExecuteResult, 1)
		fail := make(chan error, 1)
		_, err := waitJSSolveResult(done, fail, 20*time.Millisecond)
		if !errors.Is(err, errJSSolveTimeout) {
			t.Fatalf("expected timeout error, got: %v", err)
		}
	})
}

func TestWaitForCommandReply(t *testing.T) {
	t.Run("reply arrives within grace window", func(t *testing.T) {
		ctx := &MsgContext{}
		go func() {
			time.Sleep(20 * time.Millisecond)
			ctx.CommandReplied = true
		}()

		if !waitForCommandReply(ctx, 80*time.Millisecond) {
			t.Fatal("expected grace window to observe late reply")
		}
	})

	t.Run("reply does not arrive within grace window", func(t *testing.T) {
		ctx := &MsgContext{}
		if waitForCommandReply(ctx, 30*time.Millisecond) {
			t.Fatal("expected grace window to expire without reply")
		}
	})
}
