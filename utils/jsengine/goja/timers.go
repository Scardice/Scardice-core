package goja

import (
	"context"
	"fmt"
	"sync"

	g "github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

// Timer callbacks retain a revocable payload rather than their originating
// invocation. The registry also owns their cancellation hooks until fire,
// explicit clear, scope cancellation, or realm shutdown.
type asyncCallbackRegistry struct {
	mu        sync.Mutex
	closed    bool
	callbacks map[*scopedAsyncCallback]struct{}
	handles   map[*g.Object]*scopedAsyncCallback
}

type asyncCallbackPayload struct {
	origin   any
	callback g.Callable
	lifetime context.Context
}

type asyncCallbackCleanup struct {
	handle  *g.Object
	clear   g.Callable
	stop    func() bool
	release context.CancelFunc
}

type scopedAsyncCallback struct {
	loop     *eventLoop
	realm    *realm
	registry *asyncCallbackRegistry

	mu           sync.Mutex
	active       bool
	payload      asyncCallbackPayload
	cleanup      asyncCallbackCleanup
	watchVersion uint64
	handoff      bool
}

func (s *asyncCallbackRegistry) add(callback *scopedAsyncCallback) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.callbacks == nil {
		s.callbacks = make(map[*scopedAsyncCallback]struct{})
	}
	s.callbacks[callback] = struct{}{}
	return true
}

func (s *asyncCallbackRegistry) lookup(handle *g.Object) *scopedAsyncCallback {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handles[handle]
}

func (s *asyncCallbackRegistry) close() {
	s.mu.Lock()
	s.closed = true
	pending := s.callbacks
	s.callbacks = nil
	s.handles = nil
	s.mu.Unlock()
	for callback := range pending {
		callback.cancel()
	}
}

func (c *scopedAsyncCallback) bindHandle(handle *g.Object, clearTimer g.Callable) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return false
	}
	c.cleanup.handle, c.cleanup.clear = handle, clearTimer
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	if c.registry.closed {
		return false
	}
	if handle != nil && clearTimer != nil {
		if c.registry.handles == nil {
			c.registry.handles = make(map[*g.Object]*scopedAsyncCallback)
		}
		c.registry.handles[handle] = c
	}
	return true
}

func (c *scopedAsyncCallback) snapshot() asyncCallbackPayload {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payload
}

func (c *scopedAsyncCallback) retire() (asyncCallbackPayload, asyncCallbackCleanup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return asyncCallbackPayload{}, asyncCallbackCleanup{}
	}
	c.active = false
	payload, cleanup := c.payload, c.cleanup
	c.payload = asyncCallbackPayload{}
	c.cleanup = asyncCallbackCleanup{}
	c.registry.mu.Lock()
	delete(c.registry.callbacks, c)
	if c.registry.handles[cleanup.handle] == c {
		delete(c.registry.handles, cleanup.handle)
	}
	c.registry.mu.Unlock()
	return payload, cleanup
}

func (cleanup asyncCallbackCleanup) finish(loop *eventLoop, clearProvider bool) {
	if cleanup.stop != nil {
		cleanup.stop()
	}
	if clearProvider && cleanup.handle != nil && cleanup.clear != nil {
		// Only the provider handle and its intrinsic clearTimer operation cross to
		// the owner queue; the cancelled invocation payload is already gone.
		clearTimer, handle := cleanup.clear, cleanup.handle
		loop.loop.RunOnLoop(func(*g.Runtime) {
			_, _ = clearTimer(g.Undefined(), handle)
		})
	}
	if cleanup.release != nil {
		cleanup.release()
	}
}

func (c *scopedAsyncCallback) cancel() {
	_, cleanup := c.retire()
	cleanup.finish(c.loop, true)
}

func (c *scopedAsyncCallback) watch(execution context.Context) {
	c.mu.Lock()
	if !c.active {
		c.mu.Unlock()
		return
	}
	c.payload.lifetime = execution //nolint:fatcontext // Replaces the watched lifetime; it never derives a nested context.
	c.watchVersion++
	version := c.watchVersion
	previousStop := c.cleanup.stop
	c.cleanup.stop = nil
	c.mu.Unlock()
	if previousStop != nil {
		previousStop()
	}
	if execution.Done() == nil {
		return
	}
	stop := context.AfterFunc(execution, func() {
		payload := c.snapshot()
		if payload.callback == nil {
			return
		}
		if c.handoff {
			replacement := jsengine.ContextForExecution(payload.origin)
			if replacement != execution && replacement.Err() == nil {
				c.watch(replacement)
				return
			}
		}
		c.cancel()
	})
	c.mu.Lock()
	retired := !c.active || c.watchVersion != version
	if !retired {
		c.cleanup.stop = stop
	}
	c.mu.Unlock()
	if retired {
		stop()
	}
}

func (c *scopedAsyncCallback) invoke(repeating bool, call g.FunctionCall) g.Value {
	payload := c.snapshot()
	// The owner may reach a queued timer before the root's AfterFunc runs.
	// Resolve the same persistent handoff synchronously at that boundary.
	if payload.callback != nil && c.handoff && payload.lifetime.Err() != nil {
		replacement := jsengine.ContextForExecution(payload.origin)
		if replacement != payload.lifetime && replacement.Err() == nil {
			c.watch(replacement)
			payload = c.snapshot()
		}
	}
	if !repeating {
		var cleanup asyncCallbackCleanup
		payload, cleanup = c.retire()
		if cleanup.stop != nil {
			cleanup.stop()
		}
		if cleanup.release != nil {
			defer cleanup.release()
		}
	}
	if payload.callback == nil || c.loop.closed.Load() {
		return g.Undefined()
	}
	if payload.lifetime.Err() != nil || jsengine.ExecutionErr(payload.origin) != nil {
		c.cancel()
		return g.Undefined()
	}
	rootBoundary := c.realm.tracker.enterBoundary()
	defer c.realm.tracker.exitBoundary(rootBoundary)
	var result g.Value
	err := c.realm.state.with(payload.origin, func() error {
		return runWithExecutionContext(jsengine.ContextForExecution(payload.origin), c.realm.vm, func() error {
			return c.loop.observe(payload.origin, jsengine.InvocationReaction, func() error {
				var err error
				result, err = payload.callback(call.This, call.Arguments...)
				return err
			})
		})
	})
	if err != nil {
		if c.loop.closed.Load() || payload.lifetime.Err() != nil || jsengine.ExecutionErr(payload.origin) != nil {
			c.cancel()
			return g.Undefined()
		}
		panic(err)
	}
	return result
}

func (l *eventLoop) timerSetter(vm *g.Runtime, realm *realm, original, clearTimer g.Callable, repeating bool) func(g.FunctionCall) g.Value {
	return func(call g.FunctionCall) g.Value {
		callback, ok := g.AssertFunction(call.Argument(0))
		if !ok {
			result, err := original(call.This, call.Arguments...)
			if err != nil {
				panic(err)
			}
			return result
		}
		origin := l.CurrentContext()
		execution, release := jsengine.ContextForAsyncWork(origin)
		_, promoter := origin.(jsengine.PersistentAsyncPromoter)
		_, asyncLifetime := origin.(jsengine.AsyncWorkScope)
		cell := &scopedAsyncCallback{
			loop: l, realm: realm, registry: &realm.asyncCallbacks, active: true,
			payload: asyncCallbackPayload{origin: origin, callback: callback, lifetime: execution},
			cleanup: asyncCallbackCleanup{release: release},
			handoff: promoter && !asyncLifetime,
		}
		registered := false
		defer func() {
			if !registered {
				_, cleanup := cell.retire()
				cleanup.finish(l, false)
			}
		}()
		if !realm.asyncCallbacks.add(cell) {
			return g.Undefined()
		}
		arguments := make([]g.Value, len(call.Arguments))
		copy(arguments, call.Arguments)
		arguments[0] = vm.ToValue(func(callbackCall g.FunctionCall) g.Value {
			return cell.invoke(repeating, callbackCall)
		})
		handle, err := original(call.This, arguments...)
		if err != nil {
			panic(err)
		}
		objectHandle, _ := handle.(*g.Object)
		if !cell.bindHandle(objectHandle, clearTimer) {
			if clearTimer != nil && objectHandle != nil {
				_, _ = clearTimer(g.Undefined(), objectHandle)
			}
			return handle
		}
		cell.watch(execution)
		registered = true
		return handle
	}
}

func (l *eventLoop) installContextTimers(vm *g.Runtime, realm *realm) error {
	for _, timer := range [...]struct {
		set       string
		clear     string
		repeating bool
	}{
		{set: "setTimeout", clear: "clearTimeout"},
		{set: "setInterval", clear: "clearInterval", repeating: true},
		{set: "setImmediate", clear: "clearImmediate"},
		{set: "queueMicrotask"},
	} {
		original, ok := g.AssertFunction(vm.Get(timer.set))
		if !ok {
			continue
		}
		var clearTimer g.Callable
		if timer.clear != "" {
			clearTimer, ok = g.AssertFunction(vm.Get(timer.clear))
			if !ok {
				return fmt.Errorf("goja timer intrinsic %s is unavailable", timer.clear)
			}
			if err := vm.Set(timer.clear, func(call g.FunctionCall) g.Value {
				result, err := clearTimer(call.This, call.Arguments...)
				if err != nil {
					panic(err)
				}
				if handle, ok := call.Argument(0).(*g.Object); ok {
					if cell := realm.asyncCallbacks.lookup(handle); cell != nil {
						_, cleanup := cell.retire()
						cleanup.finish(l, false)
					}
				}
				return result
			}); err != nil {
				return err
			}
		}
		if err := vm.Set(timer.set, l.timerSetter(vm, realm, original, clearTimer, timer.repeating)); err != nil {
			return err
		}
	}
	return nil
}
