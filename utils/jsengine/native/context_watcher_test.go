//go:build cgo

package native

import (
	"context"
	"sync"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

// nativeTrackedCancellationContext observes registrations on a real cancellable
// context. Hiding the parent's private values makes context.AfterFunc use this
// context's AfterFunc method rather than bypassing the observable ownership.
// Cancellation and stop behavior still come from context.AfterFunc itself.
type nativeTrackedCancellationContext struct {
	context             context.Context
	mu                  sync.Mutex
	active              int
	stopped             int
	registered          int
	attached            chan struct{}
	registrationEntered chan struct{}
	registrationRelease <-chan struct{}
}

func newNativeTrackedCancellationContext(t *testing.T) (*nativeTrackedCancellationContext, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &nativeTrackedCancellationContext{context: ctx, attached: make(chan struct{}, 8)}, cancel
}

func (c *nativeTrackedCancellationContext) Deadline() (time.Time, bool) { return c.context.Deadline() }
func (c *nativeTrackedCancellationContext) Done() <-chan struct{}       { return c.context.Done() }
func (c *nativeTrackedCancellationContext) Err() error                  { return c.context.Err() }
func (c *nativeTrackedCancellationContext) Value(any) any               { return nil }

func (c *nativeTrackedCancellationContext) AfterFunc(run func()) func() bool {
	defer func() { c.attached <- struct{}{} }()
	c.mu.Lock()
	c.active++
	c.registered++
	c.mu.Unlock()
	stop := context.AfterFunc(c.context, func() {
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
		run()
	})
	if c.registrationEntered != nil {
		close(c.registrationEntered)
		<-c.registrationRelease
	}
	return func() bool {
		if !stop() {
			return false
		}
		c.mu.Lock()
		c.active--
		c.stopped++
		c.mu.Unlock()
		return true
	}
}

func (c *nativeTrackedCancellationContext) snapshot() (active, stopped, registered int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active, c.stopped, c.registered
}

func waitNativeContextSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("native context ownership signal did not arrive")
	}
}

func waitNativeContextCondition(t *testing.T, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("native context ownership did not reach the expected state")
		}
	}
}

func TestNativeCloseDetachesLiveContextWatcher(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	execution, _ := newNativeTrackedCancellationContext(t)
	scope := &persistentInvocationTestContext{context: execution, id: 101}
	if err := loop.RunWithContext(scope, func(runtime jsengine.Runtime) error {
		return runtime.Set("contextMarker", true)
	}); err != nil {
		t.Fatal(err)
	}
	if active, _, registered := execution.snapshot(); active != 1 || registered != 1 {
		t.Fatalf("live watcher registrations: active=%d registered=%d, want 1/1", active, registered)
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
	if active, stopped, _ := execution.snapshot(); active != 0 || stopped != 1 {
		t.Fatalf("Close left a context-owned watcher: active=%d stopped=%d, want 0/1", active, stopped)
	}
}

func TestNativeReplacingInternedContextTransfersWatcherOwnership(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	first, cancelFirst := newNativeTrackedCancellationContext(t)
	second, cancelSecond := newNativeTrackedCancellationContext(t)
	firstScope := &invocationTestContext{Context: first, id: 102}
	secondScope := &invocationTestContext{Context: second, id: 102}
	if err := loop.RunWithContext(firstScope, func(runtime jsengine.Runtime) error {
		return runtime.Set("contextMarker", "first")
	}); err != nil {
		t.Fatal(err)
	}
	loop.contextMu.RLock()
	token := loop.contextTokens[102]
	loop.contextMu.RUnlock()
	if err := loop.RunWithContext(secondScope, func(runtime jsengine.Runtime) error {
		return runtime.Set("contextMarker", "second")
	}); err != nil {
		t.Fatal(err)
	}
	if active, stopped, _ := first.snapshot(); active != 0 || stopped != 1 {
		t.Fatalf("replacement kept the old watcher: active=%d stopped=%d, want 0/1", active, stopped)
	}
	if active, _, registered := second.snapshot(); active != 1 || registered != 1 {
		t.Fatalf("replacement watcher: active=%d registered=%d, want 1/1", active, registered)
	}
	cancelFirst()
	loop.contextMu.RLock()
	retained := loop.contextTokens[102] == token && loop.contexts[token] == secondScope
	loop.contextMu.RUnlock()
	if !retained {
		t.Fatal("canceled prior context revoked the replacement token")
	}
	cancelSecond()
	waitNativeContextCondition(t, func() bool {
		loop.contextMu.RLock()
		defer loop.contextMu.RUnlock()
		_, retained := loop.contexts[token]
		return !retained
	})
}

func TestNativePersistentReplacementWatcherStopsAtCloseOrCancellation(t *testing.T) {
	for _, closeLoop := range []bool{true, false} {
		name := "cancel"
		if closeLoop {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			loop := openQuickJSJSONLoop(t).(*nativeLoop)
			loadContext, cancelLoad := newNativeTrackedCancellationContext(t)
			schedulerContext, cancelScheduler := newNativeTrackedCancellationContext(t)
			scope := &persistentInvocationTestContext{context: loadContext, id: 103}
			if err := loop.RunWithContext(scope, func(runtime jsengine.Runtime) error {
				return runtime.Set("contextMarker", "persistent")
			}); err != nil {
				t.Fatal(err)
			}
			scope.replaceExecutionContext(schedulerContext)
			cancelLoad()
			waitNativeContextSignal(t, schedulerContext.attached)
			if active, _, registered := schedulerContext.snapshot(); active != 1 || registered != 1 {
				t.Fatalf("scheduler watcher: active=%d registered=%d, want 1/1", active, registered)
			}
			if closeLoop {
				if err := loop.Close(); err != nil {
					t.Fatal(err)
				}
				if active, stopped, _ := schedulerContext.snapshot(); active != 0 || stopped != 1 {
					t.Fatalf("closed scheduler watcher: active=%d stopped=%d, want 0/1", active, stopped)
				}
			} else {
				cancelScheduler()
				waitNativeContextCondition(t, func() bool {
					loop.contextMu.RLock()
					defer loop.contextMu.RUnlock()
					return len(loop.contexts) == 0
				})
				if active, _, _ := schedulerContext.snapshot(); active != 0 {
					t.Fatalf("canceled scheduler has %d active watchers", active)
				}
				loop.contextMu.RLock()
				retained := len(loop.contexts) + len(loop.contextTokens)
				loop.contextMu.RUnlock()
				if retained != 0 {
					t.Fatalf("canceled scheduler retains %d provider context entries", retained)
				}
			}
		})
	}
}

func TestNativeClosingContextWatcherCannotRearmAfterShutdown(t *testing.T) {
	loop := openQuickJSJSONLoop(t).(*nativeLoop)
	loadContext, cancelLoad := newNativeTrackedCancellationContext(t)
	schedulerContext, _ := newNativeTrackedCancellationContext(t)
	registrationRelease := make(chan struct{})
	schedulerContext.registrationEntered = make(chan struct{})
	schedulerContext.registrationRelease = registrationRelease
	scope := &persistentInvocationTestContext{context: loadContext, id: 104}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(registrationRelease) }) }
	t.Cleanup(release)
	if err := loop.RunWithContext(scope, func(runtime jsengine.Runtime) error {
		return runtime.Set("contextMarker", "racing")
	}); err != nil {
		t.Fatal(err)
	}
	scope.replaceExecutionContext(schedulerContext)
	cancelLoad()
	waitNativeContextSignal(t, schedulerContext.registrationEntered)
	closed := make(chan error, 1)
	go func() { closed <- loop.Close() }()
	waitNativeContextCondition(t, loop.closed.Load)
	release()
	waitNativeContextSignal(t, schedulerContext.attached)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after the in-flight watcher registration")
	}
	if active, stopped, registered := schedulerContext.snapshot(); active != 0 || stopped != 1 || registered != 1 {
		t.Fatalf("shutdown lost the in-flight watcher: active=%d stopped=%d registered=%d, want 0/1/1", active, stopped, registered)
	}
}
