package goja

import (
	"context"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	g "github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

type timerLifetimeLease struct {
	released chan struct{}
	count    atomic.Int32
}

type timerLifetimeScope struct {
	context.Context
	lease *timerLifetimeLease
}

func (s *timerLifetimeScope) ExecutionContext() context.Context { return s.Context }

func (s *timerLifetimeScope) AsyncWorkContext() (context.Context, context.CancelFunc) {
	lease := s.lease
	return s.Context, func() {
		lease.count.Add(1)
		lease.released <- struct{}{}
	}
}

func waitForTimerLeaseRelease(t *testing.T, lease *timerLifetimeLease) {
	t.Helper()
	select {
	case <-lease.released:
	case <-time.After(2 * time.Second):
		t.Fatal("timer did not release its asynchronous lifetime")
	}
}

func TestCancelInvocationTimerClearsProviderJobAndReleasesOrigin(t *testing.T) {
	for _, kind := range []string{"setInterval", "setTimeout"} {
		t.Run(kind, func(t *testing.T) {
			loop := startedTestLoop(t).(*eventLoop)
			if err := InstallContextPropagation(loop); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lease := &timerLifetimeLease{released: make(chan struct{}, 2)}
			var origin weak.Pointer[timerLifetimeScope]
			func() {
				scope := &timerLifetimeScope{Context: ctx, lease: lease}
				origin = weak.Make(scope)
				if err := loop.RunWithContext(scope, func(runtime jsengine.Runtime) error {
					_, err := runtime.RunString("invocation-timer.js", kind+`(function () {}, 3600000);`)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}()

			cancel()
			waitForTimerLeaseRelease(t, lease)
			if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if remaining := loop.loop.Stop(); remaining != 0 {
				t.Errorf("provider kept %d timer jobs after invocation cancellation", remaining)
			}
			deadline := time.Now().Add(3 * time.Second)
			for origin.Value() != nil {
				if time.Now().After(deadline) {
					t.Fatal("cancelled provider timer retained its origin scope")
				}
				goruntime.GC()
				goruntime.Gosched()
			}
			if count := lease.count.Load(); count != 1 {
				t.Errorf("timer released its lifetime %d times, want once", count)
			}
			goruntime.KeepAlive(loop)
		})
	}
}

func TestTimerFireAndExplicitClearReleaseCancellationWatcher(t *testing.T) {
	for _, mode := range []string{"fire", "clear"} {
		t.Run(mode, func(t *testing.T) {
			loop := startedTestLoop(t).(*eventLoop)
			if err := InstallContextPropagation(loop); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lease := &timerLifetimeLease{released: make(chan struct{}, 2)}
			scope := &timerLifetimeScope{Context: ctx, lease: lease}
			var invoked atomic.Int32
			if err := loop.RunWithContext(scope, func(runtime jsengine.Runtime) error {
				vm, _ := Raw(runtime)
				if err := vm.Set("timerLifecycleFired", func() { invoked.Add(1) }); err != nil {
					return err
				}
				source := `setImmediate(function () { timerLifecycleFired(); });`
				if mode == "clear" {
					source = `var timerToClear = setInterval(function () { timerLifecycleFired(); }, 3600000); clearInterval(timerToClear); timerToClear = null;`
				}
				_, err := runtime.RunString("finish-timer.js", source)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			waitForTimerLeaseRelease(t, lease)
			cancel()
			if err := loop.Run(func(jsengine.Runtime) error { return nil }); err != nil {
				t.Fatal(err)
			}
			wantCalls := int32(0)
			if mode == "fire" {
				wantCalls = 1
			}
			if calls := invoked.Load(); calls != wantCalls {
				t.Errorf("timer callback calls = %d, want %d", calls, wantCalls)
			}
			if count := lease.count.Load(); count != 1 {
				t.Errorf("timer released its lifetime %d times, want once", count)
			}
			if remaining := loop.loop.Stop(); remaining != 0 {
				t.Errorf("provider kept %d jobs after timer %s", remaining, mode)
			}
		})
	}
}

func TestPersistentTimerSurvivesNormalRootHandoff(t *testing.T) {
	loop := startedTestLoop(t).(*eventLoop)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	origin := newHandoffScope(t)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	fired := make(chan struct{}, 1)
	if err := loop.RunWithContext(origin, func(runtime jsengine.Runtime) error {
		vm, _ := Raw(runtime)
		if err := vm.Set("timerAfterHandoff", func() { fired <- struct{}{} }); err != nil {
			return err
		}
		if !loop.loop.RunOnLoop(func(*g.Runtime) {
			close(blocked)
			<-release
		}) {
			t.Error("handoff blocker was not queued")
		}
		_, err := runtime.RunString("handoff-timer.js", `setImmediate(function () { timerAfterHandoff(); });`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("owner did not block before the persistent timer")
	}
	origin.rootCancel()
	releaseOnce.Do(func() { close(release) })
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("persistent timer was cancelled with its normally finished root")
	}
}

func TestOwnerCloseDiscardsQueuedImmediateAfterContextCleanup(t *testing.T) {
	loop := startedTestLoop(t).(*eventLoop)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var invoked atomic.Bool
	ownerClosed := make(chan error, 1)
	if err := loop.ScheduleWithContext(deadlineRealm{ctx}, func(runtime jsengine.Runtime) error {
		vm, _ := Raw(runtime)
		if err := vm.Set("lateOwnerImmediate", func() { invoked.Store(true) }); err != nil {
			ownerClosed <- err
			return err
		}
		if _, err := runtime.RunString("late-owner-immediate.js", `setImmediate(function () { lateOwnerImmediate(); });`); err != nil {
			ownerClosed <- err
			return err
		}
		err := loop.Close()
		ownerClosed <- err
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ownerClosed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner Close did not return")
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
	if invoked.Load() {
		t.Fatal("queued immediate ran after Close cleared the realm")
	}
}
