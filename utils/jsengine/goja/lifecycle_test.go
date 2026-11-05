package goja

import (
	"context"
	"errors"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	g "github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
)

func TestCloseRejectsQueuedInvocationsWithoutRepublishingRealm(t *testing.T) {
	for _, attached := range []bool{false, true} {
		name := "before-first-entry"
		if attached {
			name = "after-first-entry"
		}
		t.Run(name, func(t *testing.T) {
			raw := eventloop.NewEventLoop(eventloop.EnableConsole(false))
			loop := WrapEventLoop(raw).(*eventLoop)
			var vm *g.Runtime
			if attached {
				if err := loop.Run(func(runtime jsengine.Runtime) error {
					vm, _ = Raw(runtime)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				raw.Run(func(runtime *g.Runtime) { vm = runtime })
			}
			invoked := false
			if err := loop.Schedule(func(jsengine.Runtime) error {
				invoked = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			drained := false
			if !raw.RunOnLoop(func(*g.Runtime) { drained = true }) {
				t.Fatal("raw cleanup job was not queued")
			}

			if err := loop.Close(); err != nil {
				t.Fatal(err)
			}
			if invoked {
				t.Error("queued user invocation ran during Close")
			}
			if _, retained := realms.Load(vm); retained {
				t.Error("closed VM remained published in the realm registry")
			}
			if !drained {
				t.Error("Close skipped the underlying event loop's cleanup drain")
			}
			if raw.RunOnLoop(func(*g.Runtime) {}) {
				t.Error("underlying event loop accepted work after Close")
			}
		})
	}
}

// Done is first consulted by RunWithContext after its RunOnLoop submission.
// The busy owner cannot dequeue that invocation until the test releases it.
// This acknowledges real queue admission without exposing a production hook.
type queuedGojaInvocationScope struct {
	context.Context
	queued chan struct{}
	once   sync.Once
}

func (s *queuedGojaInvocationScope) ExecutionContext() context.Context { return s }

func (s *queuedGojaInvocationScope) Done() <-chan struct{} {
	s.once.Do(func() { close(s.queued) })
	return s.Context.Done()
}

func TestCloseReturnsErrorForQueuedRunWithoutExecutingIt(t *testing.T) {
	raw := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	loop := WrapEventLoop(raw).(*eventLoop)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var vm *g.Runtime
	if !raw.RunOnLoop(func(runtime *g.Runtime) {
		vm = runtime
		close(blocked)
		<-release
	}) {
		t.Fatal("owner blocker was not queued")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- StartInForeground(loop) }()
	if err := WaitUntilStarted(loop); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("owner did not enter the blocking callback")
	}

	scope := &queuedGojaInvocationScope{Context: context.Background(), queued: make(chan struct{})}
	var invoked atomic.Bool
	result := make(chan error, 1)
	go func() {
		result <- loop.RunWithContext(scope, func(jsengine.Runtime) error {
			invoked.Store(true)
			return nil
		})
	}()
	select {
	case <-scope.queued:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWithContext did not submit its invocation")
	}
	closed := make(chan error, 1)
	go func() { closed <- loop.Close() }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for !loop.closed.Load() {
		select {
		case <-deadline.C:
			t.Fatal("Close did not close invocation admission")
		default:
			goruntime.Gosched()
		}
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if err == nil {
			t.Error("queued RunWithContext returned success after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued RunWithContext did not return during Close")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after releasing the owner")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event loop did not stop")
	}
	if invoked.Load() {
		t.Error("queued RunWithContext ran user work after Close")
	}
	if _, retained := realms.Load(vm); retained {
		t.Error("queued RunWithContext republished the closed VM")
	}
}

func TestCloseFromOwnerDoesNotDeadlockOrRunQueuedWork(t *testing.T) {
	for _, panicAfterClose := range []bool{false, true} {
		name := "return"
		if panicAfterClose {
			name = "panic"
		}
		t.Run(name, func(t *testing.T) {
			raw := eventloop.NewEventLoop(eventloop.EnableConsole(false))
			loop := WrapEventLoop(raw).(*eventLoop)
			stopped := make(chan error, 1)
			go func() { stopped <- StartInForeground(loop) }()
			if err := WaitUntilStarted(loop); err != nil {
				t.Fatal(err)
			}
			closed := make(chan error, 1)
			var invoked atomic.Bool
			if err := loop.Schedule(func(jsengine.Runtime) error {
				if err := loop.Schedule(func(jsengine.Runtime) error {
					invoked.Store(true)
					return nil
				}); err != nil {
					closed <- err
					return err
				}
				closed <- loop.Close()
				if panicAfterClose {
					panic("owner callback panic after Close")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Close blocked waiting for its own owner callback")
			}
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("owner-initiated Close did not stop the event loop")
			}
			if err := loop.Close(); err != nil {
				t.Fatal(err)
			}
			if invoked.Load() {
				t.Error("owner-initiated Close ran queued user work")
			}
			if raw.RunOnLoop(func(*g.Runtime) {}) {
				t.Error("owner-initiated Close did not terminate the underlying queue")
			}
		})
	}
}

func TestDirectRunPanicDoesNotStrandClose(t *testing.T) {
	raw := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	loop := WrapEventLoop(raw).(*eventLoop)
	if err := loop.Run(func(jsengine.Runtime) error { panic("direct invocation panic") }); err == nil {
		t.Fatal("panicking invocation returned success")
	}
	closed := make(chan error, 1)
	go func() { closed <- loop.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close was stranded by a panic before the raw loop could unwind")
	}
	if err := loop.Run(func(jsengine.Runtime) error { return errors.New("must not run") }); err == nil {
		t.Fatal("closed loop accepted another Run")
	}
}
