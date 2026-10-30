package goja

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	g "github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

type deadlineRealm struct{ context.Context }

func (r deadlineRealm) ExecutionContext() context.Context { return r.Context }

func TestContextDeadlineInterruptsRunningJavaScript(t *testing.T) {
	loop := startedTestLoop(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var vm *g.Runtime
	if err := loop.Run(func(rt jsengine.Runtime) error { vm, _ = Raw(rt); return nil }); err != nil {
		t.Fatal(err)
	}
	// Always release the pre-fix infinite loop so RED cannot hang the suite.
	safety := time.AfterFunc(500*time.Millisecond, func() { vm.Interrupt(errors.New("test safety stop")) })
	err := jsengine.RunWithContext(loop, deadlineRealm{ctx}, func(rt jsengine.Runtime) error { _, err := rt.RunString("busy.js", "while (true) {}"); return err })
	safety.Stop()
	vm.ClearInterrupt()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("busy JS ignored invocation deadline: %v", err)
	}
	if err := loop.Run(func(rt jsengine.Runtime) error {
		v, err := rt.RunString("healthy.js", "6 * 7")
		if err == nil && v.Export() != int64(42) {
			t.Errorf("healthy result=%v", v.Export())
		}
		return err
	}); err != nil {
		t.Fatalf("interrupt leaked into next invocation: %v", err)
	}
}

func TestCanceledQueuedInvocationNeverExecutes(t *testing.T) {
	loop := startedTestLoop(t)
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_ = loop.Run(func(jsengine.Runtime) error { close(started); <-release; return nil })
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	var called atomic.Bool
	returned := make(chan error, 1)
	go func() {
		returned <- jsengine.RunWithContext(loop, deadlineRealm{ctx}, func(jsengine.Runtime) error { called.Store(true); return nil })
	}()
	cancel()
	var err error
	select {
	case err = <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Error("canceled admission waited for busy owner")
	}
	close(release)
	<-finished
	if err == nil {
		select {
		case err = <-returned:
		case <-time.After(time.Second):
			t.Fatal("queued invocation stuck")
		}
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("canceled admission err=%v", err)
	}
	if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if called.Load() {
		t.Fatal("expired queued callback executed")
	}
}
