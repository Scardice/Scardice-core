package goja

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	g "github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
)

type awaitOwnershipScope struct {
	context.Context
	cancel context.CancelFunc
	name   string
	gate   sync.RWMutex
	active atomic.Int32
	enters atomic.Int32
}

func newAwaitOwnershipScope(t *testing.T, name string) *awaitOwnershipScope {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	scope := &awaitOwnershipScope{Context: ctx, cancel: cancel, name: name}
	t.Cleanup(cancel)
	return scope
}

func (s *awaitOwnershipScope) ExecutionContext() context.Context { return s.Context }

func (s *awaitOwnershipScope) EnterExecution() (func(), error) {
	if err := s.Err(); err != nil {
		return nil, err
	}
	s.gate.RLock()
	if err := s.Err(); err != nil {
		s.gate.RUnlock()
		return nil, err
	}
	s.enters.Add(1)
	s.active.Add(1)
	return func() {
		s.active.Add(-1)
		s.gate.RUnlock()
	}, nil
}

type awaitOwnershipObservation struct {
	owner  any
	active int32
}

func observeAwaitOwnership(loop jsengine.Loop) awaitOwnershipObservation {
	owner := jsengine.CurrentContext(loop)
	observation := awaitOwnershipObservation{owner: owner}
	if scope, ok := owner.(*awaitOwnershipScope); ok {
		observation.active = scope.active.Load()
	}
	return observation
}

type awaitMetadataScope struct {
	*awaitOwnershipScope
	key        string
	completion bool
}

func (s *awaitMetadataScope) ContextKey() any { return s.key }

func awaitAsyncTokenRevocation(t *testing.T, tracker *asyncContextTracker, token *asyncContextToken) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, revoked := tracker.resolveTrackingObject(token).(jsengine.RevokedExecutionScope); revoked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("async context token retained its canceled origin")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAsyncContextTrackerReusesAndRevokesCancellableToken(t *testing.T) {
	origin := newAwaitOwnershipScope(t, "origin")
	state := &contextState{}
	state.replaceContext(origin)
	tracker := &asyncContextTracker{state: state, vm: g.New()}

	first := tracker.Grab()
	token, ok := first.(*asyncContextToken)
	if !ok {
		t.Fatalf("Grab() = %T, want lightweight async context token", first)
	}
	if second := tracker.Grab(); second != token {
		t.Fatalf("same opaque context allocated another token: first=%p second=%p", token, second)
	}
	if resolved := tracker.resolveTrackingObject(token); resolved != origin {
		t.Fatalf("active token resolved as %v, want original context", resolved)
	}

	origin.cancel()
	awaitAsyncTokenRevocation(t, tracker, token)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if token.origin != nil || token.key != nil || token.stop != nil {
		t.Fatalf("revoked token retained payload: origin=%v key=%v hasStop=%t", token.origin, token.key, token.stop != nil)
	}
	if len(tracker.tokens) != 0 || len(tracker.allTokens) != 0 {
		t.Fatalf("revoked token remained interned: tokens=%d all=%d", len(tracker.tokens), len(tracker.allTokens))
	}
}

func TestAsyncContextTrackerPreservesOpaqueMetadataBeyondContextKey(t *testing.T) {
	state := &contextState{}
	tracker := &asyncContextTracker{state: state, vm: g.New()}
	origin := &awaitMetadataScope{
		awaitOwnershipScope: newAwaitOwnershipScope(t, "origin"),
		key:                 "shared",
	}
	completion := &awaitMetadataScope{
		awaitOwnershipScope: newAwaitOwnershipScope(t, "completion"),
		key:                 "shared",
		completion:          true,
	}

	state.replaceContext(origin)
	originToken := tracker.Grab()
	state.replaceContext(completion)
	completionToken := tracker.Grab()
	if originToken == completionToken {
		t.Fatal("opaque contexts with distinct metadata collapsed to one ContextKey token")
	}
	if resolved := tracker.resolveTrackingObject(originToken); resolved != origin {
		t.Fatalf("origin token resolved as %#v", resolved)
	}
	if resolved := tracker.resolveTrackingObject(completionToken); resolved != completion {
		t.Fatalf("completion token resolved as %#v", resolved)
	}
	tracker.close()
}

func TestAsyncContextTrackerCloseDropsRetainedTokenPayload(t *testing.T) {
	origin := newAwaitOwnershipScope(t, "origin")
	state := &contextState{}
	state.replaceContext(origin)
	tracker := &asyncContextTracker{state: state, vm: g.New()}
	token, ok := tracker.Grab().(*asyncContextToken)
	if !ok {
		t.Fatal("cancellable context was not tokenized")
	}

	tracker.close()
	if _, revoked := tracker.resolveTrackingObject(token).(jsengine.RevokedExecutionScope); !revoked {
		t.Fatal("closed tracker did not revoke pending reaction token")
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if token.origin != nil || token.key != nil || token.stop != nil {
		t.Fatalf("closed token retained payload: origin=%v key=%v hasStop=%t", token.origin, token.key, token.stop != nil)
	}
	if len(tracker.tokens) != 0 || len(tracker.allTokens) != 0 {
		t.Fatalf("closed tracker retained tokens: tokens=%d all=%d", len(tracker.tokens), len(tracker.allTokens))
	}
}

func installPendingNativeAwait(
	loop jsengine.Loop,
	origin *awaitOwnershipScope,
	bind func(jsengine.Runtime) error,
	source string,
) (func(interface{}) error, error) {
	var resolve func(interface{}) error
	err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
		if bind != nil {
			if err := bind(runtime); err != nil {
				return err
			}
		}
		vm, ok := Raw(runtime)
		if !ok {
			return errors.New("goja runtime unavailable")
		}
		promise, settle, _ := vm.NewPromise()
		resolve = settle
		if err := vm.Set("__pendingNativeAwait", promise); err != nil {
			return err
		}
		_, err := runtime.RunString("native-await.js", source)
		return err
	})
	return resolve, err
}

func TestPendingNativeAwaitResolvedUnderAnotherExecutionKeepsOrigin(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	origin := newAwaitOwnershipScope(t, "origin")
	resolver := newAwaitOwnershipScope(t, "resolver")
	var resumed awaitOwnershipObservation
	resolve, err := installPendingNativeAwait(loop, origin, func(runtime jsengine.Runtime) error {
		return runtime.Bind("captureNativeAwait", func() {
			resumed = observeAwaitOwnership(loop)
		})
	}, `(async function () {
		await __pendingNativeAwait;
		captureNativeAwait();
	})();`)
	if err != nil {
		t.Fatal(err)
	}
	if resolve == nil {
		t.Fatal("native promise resolver was not installed")
	}
	if origin.active.Load() != 0 {
		t.Fatalf("origin gate remained active after suspension: %d", origin.active.Load())
	}

	var restored awaitOwnershipObservation
	if err := jsengine.RunWithContext(loop, resolver, func(jsengine.Runtime) error {
		if err := resolve("done"); err != nil {
			return err
		}
		restored = observeAwaitOwnership(loop)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if resumed.owner != origin || resumed.active != 1 {
		t.Fatalf("native await resumed with owner=%v active=%d, want origin active=1", resumed.owner, resumed.active)
	}
	if restored.owner != resolver || restored.active != 1 {
		t.Fatalf("resolver execution restored as owner=%v active=%d, want resolver active=1", restored.owner, restored.active)
	}
	if origin.active.Load() != 0 || resolver.active.Load() != 0 {
		t.Fatalf("execution gates leaked: origin=%d resolver=%d", origin.active.Load(), resolver.active.Load())
	}
}

func TestPendingNativeAwaitResolvedWithoutExecutionKeepsOrigin(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	origin := newAwaitOwnershipScope(t, "origin")
	var resumed awaitOwnershipObservation
	resolve, err := installPendingNativeAwait(loop, origin, func(runtime jsengine.Runtime) error {
		return runtime.Bind("captureNativeAwait", func() {
			resumed = observeAwaitOwnership(loop)
		})
	}, `(async function () {
		await __pendingNativeAwait;
		captureNativeAwait();
	})();`)
	if err != nil {
		t.Fatal(err)
	}
	if resolve == nil {
		t.Fatal("native promise resolver was not installed")
	}

	var restored any
	if err := loop.Run(func(jsengine.Runtime) error {
		if err := resolve("done"); err != nil {
			return err
		}
		restored = jsengine.CurrentContext(loop)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if resumed.owner != origin || resumed.active != 1 {
		t.Fatalf("native await resumed with owner=%v active=%d, want origin active=1", resumed.owner, resumed.active)
	}
	if restored != nil {
		t.Fatalf("unbound resolver execution restored as %v, want nil", restored)
	}
	if origin.active.Load() != 0 {
		t.Fatalf("origin gate leaked after continuation: %d", origin.active.Load())
	}
}

func TestExpiredNativeAwaitCannotCommitEffectsOrPoisonLaterWork(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	origin := newAwaitOwnershipScope(t, "expired")
	resolver := newAwaitOwnershipScope(t, "resolver")
	later := newAwaitOwnershipScope(t, "later")
	type effectAttempt struct {
		label string
		awaitOwnershipObservation
	}
	var attempts []effectAttempt
	resolve, err := installPendingNativeAwait(loop, origin, func(runtime jsengine.Runtime) error {
		return runtime.Bind("commitEffect", func(label string) {
			attempts = append(attempts, effectAttempt{
				label:                     label,
				awaitOwnershipObservation: observeAwaitOwnership(loop),
			})
		})
	}, `globalThis.__staleContinuationRan = false;
	(async function () {
		await __pendingNativeAwait;
		globalThis.__staleContinuationRan = true;
		commitEffect("stale");
	})();`)
	if err != nil {
		t.Fatal(err)
	}
	origin.cancel()

	err = jsengine.RunWithContext(loop, resolver, func(jsengine.Runtime) error {
		return resolve("done")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expired continuation error = %v, want context cancellation", err)
	}
	if origin.active.Load() != 0 || resolver.active.Load() != 0 {
		t.Fatalf("canceled drain leaked execution gates: origin=%d resolver=%d", origin.active.Load(), resolver.active.Load())
	}
	if err := jsengine.RunWithContext(loop, later, func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("later-healthy.js", `
			if (globalThis.__staleContinuationRan) {
				throw new Error("expired continuation body executed");
			}
			commitEffect("healthy");
			21 * 2;
		`)
		if err != nil {
			return err
		}
		if value.Export() != int64(42) {
			t.Fatalf("later result = %v, want 42", value.Export())
		}
		return nil
	}); err != nil {
		t.Fatalf("healthy later execution failed: %v", err)
	}

	if len(attempts) != 1 || attempts[0].label != "healthy" || attempts[0].owner != later || attempts[0].active != 1 {
		t.Fatalf("effect attempts = %+v, want only healthy later effect", attempts)
	}
	if jsengine.CurrentContext(loop) != nil {
		t.Fatalf("loop context leaked after cancellation recovery: %v", jsengine.CurrentContext(loop))
	}
}

func TestNativeAwaitReentryRestoresResolverExecution(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	origin := newAwaitOwnershipScope(t, "origin")
	resolver := newAwaitOwnershipScope(t, "resolver")
	var outer, nested, afterReentry, resolverRestored awaitOwnershipObservation
	resolve, err := installPendingNativeAwait(loop, origin, func(runtime jsengine.Runtime) error {
		contextRuntime, ok := runtime.(jsengine.ContextAwareLoop)
		if !ok {
			return errors.New("goja runtime is not context-aware")
		}
		if err := runtime.Bind("reenterCurrentExecution", func() error {
			outer = observeAwaitOwnership(loop)
			return contextRuntime.RunWithContext(outer.owner, func(jsengine.Runtime) error {
				nested = observeAwaitOwnership(loop)
				return nil
			})
		}); err != nil {
			return err
		}
		return runtime.Bind("captureAfterReentry", func() {
			afterReentry = observeAwaitOwnership(loop)
		})
	}, `(async function () {
		await __pendingNativeAwait;
		reenterCurrentExecution();
		captureAfterReentry();
	})();`)
	if err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, resolver, func(jsengine.Runtime) error {
		if err := resolve("done"); err != nil {
			return err
		}
		resolverRestored = observeAwaitOwnership(loop)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for label, observation := range map[string]awaitOwnershipObservation{
		"continuation":   outer,
		"nested reentry": nested,
		"after reentry":  afterReentry,
	} {
		if observation.owner != origin || observation.active != 1 {
			t.Fatalf("%s owner=%v active=%d, want origin active=1", label, observation.owner, observation.active)
		}
	}
	if resolverRestored.owner != resolver || resolverRestored.active != 1 {
		t.Fatalf("resolver restored as owner=%v active=%d, want resolver active=1", resolverRestored.owner, resolverRestored.active)
	}
	if origin.enters.Load() != 2 {
		t.Fatalf("origin gate entered %d times, want initial execution plus resumed continuation", origin.enters.Load())
	}
	if origin.active.Load() != 0 || resolver.active.Load() != 0 {
		t.Fatalf("execution gates leaked: origin=%d resolver=%d", origin.active.Load(), resolver.active.Load())
	}
}

func TestCancelActiveNativeAwaitUnwindsAndKeepsLaterWorkHealthy(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	origin := newAwaitOwnershipScope(t, "origin")
	resolver := newAwaitOwnershipScope(t, "resolver")
	later := newAwaitOwnershipScope(t, "later")
	started := make(chan struct{})
	var startedOnce sync.Once
	var interrupt func(error)
	var clearInterrupt func()
	resolve, err := installPendingNativeAwait(loop, origin, func(runtime jsengine.Runtime) error {
		vm, ok := Raw(runtime)
		if !ok {
			return errors.New("goja runtime unavailable")
		}
		interrupt = func(err error) { vm.Interrupt(err) }
		clearInterrupt = vm.ClearInterrupt
		return runtime.Bind("activeAwaitStarted", func() {
			startedOnce.Do(func() { close(started) })
		})
	}, `(async function () {
		await __pendingNativeAwait;
		activeAwaitStarted();
		for (;;) {}
	})();`)
	if err != nil {
		t.Fatal(err)
	}

	returned := make(chan error, 1)
	go func() {
		returned <- jsengine.RunWithContext(loop, resolver, func(jsengine.Runtime) error {
			return resolve("done")
		})
	}()

	safetyErr := errors.New("active await safety interrupt")
	safetyDone := make(chan struct{})
	safety := time.AfterFunc(2*time.Second, func() {
		interrupt(safetyErr)
		close(safetyDone)
	})
	safetyStopped := false
	stopSafety := func() {
		if safetyStopped {
			return
		}
		safetyStopped = true
		if !safety.Stop() {
			<-safetyDone
		}
		clearInterrupt()
	}
	defer stopSafety()

	var resolveErr error
	returnedEarly := false
	select {
	case <-started:
		origin.cancel()
	case resolveErr = <-returned:
		returnedEarly = true
		origin.cancel()
	case <-safetyDone:
		origin.cancel()
	}
	if !returnedEarly {
		select {
		case resolveErr = <-returned:
		case <-time.After(2 * time.Second):
			t.Fatal("active continuation did not stop after cancellation and safety interrupt")
		}
	}
	stopSafety()

	if !errors.Is(resolveErr, context.Canceled) {
		t.Fatalf("active continuation error = %v, want context cancellation", resolveErr)
	}
	if errors.Is(resolveErr, safetyErr) {
		t.Fatalf("active continuation required safety interrupt: %v", resolveErr)
	}
	if origin.active.Load() != 0 || resolver.active.Load() != 0 {
		t.Fatalf("active cancellation leaked execution gates: origin=%d resolver=%d", origin.active.Load(), resolver.active.Load())
	}
	if jsengine.CurrentContext(loop) != nil {
		t.Fatalf("active cancellation leaked loop context: %v", jsengine.CurrentContext(loop))
	}
	if err := jsengine.RunWithContext(loop, later, func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("healthy-after-active-cancel.js", "6 * 7")
		if err != nil {
			return err
		}
		if value.Export() != int64(42) {
			t.Fatalf("later result = %v, want 42", value.Export())
		}
		return nil
	}); err != nil {
		t.Fatalf("later execution failed after active cancellation: %v", err)
	}
	if later.active.Load() != 0 {
		t.Fatalf("later execution gate leaked: %d", later.active.Load())
	}
}

func TestWrapAfterEventLoopReusesAsyncOwnershipRealm(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		vm, ok := Raw(runtime)
		if !ok {
			return errors.New("goja runtime unavailable")
		}
		if wrapped := Wrap(vm); wrapped.Engine() != jsengine.EngineGoja {
			return errors.New("wrapped runtime has wrong engine")
		}
		wrapped := WrapValue(vm, vm.ToValue("probe"))
		primitive, err := wrapped.ExportPrimitive()
		if err != nil {
			return err
		}
		if primitive != "probe" {
			return errors.New("wrapped value changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	origin := newAwaitOwnershipScope(t, "origin")
	resolver := newAwaitOwnershipScope(t, "resolver")
	var resumed awaitOwnershipObservation
	resolve, err := installPendingNativeAwait(loop, origin, func(runtime jsengine.Runtime) error {
		return runtime.Bind("captureWrappedAwait", func() {
			resumed = observeAwaitOwnership(loop)
		})
	}, `(async function () {
		await __pendingNativeAwait;
		captureWrappedAwait();
	})();`)
	if err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, resolver, func(jsengine.Runtime) error {
		return resolve("done")
	}); err != nil {
		t.Fatal(err)
	}
	if resumed.owner != origin || resumed.active != 1 {
		t.Fatalf("await after Wrap/WrapValue resumed with owner=%v active=%d, want origin active=1", resumed.owner, resumed.active)
	}
}

func TestEventLoopReusesRealmCreatedByEarlierWrapper(t *testing.T) {
	raw := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	var wrapped jsengine.Runtime
	var setupErr error
	raw.Run(func(vm *g.Runtime) {
		wrapped = Wrap(vm)
		value := WrapValue(vm, vm.ToValue("probe"))
		primitive, err := value.ExportPrimitive()
		if err != nil {
			setupErr = err
			return
		}
		if primitive != "probe" {
			setupErr = errors.New("wrapped value changed")
		}
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	wrappedLoop, ok := wrapped.(jsengine.ContextAwareLoop)
	if !ok {
		t.Fatal("wrapped runtime is not context-aware")
	}

	loop := WrapEventLoop(raw)
	go func() {
		_ = StartInForeground(loop)
	}()
	if err := WaitUntilStarted(loop); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = loop.Close()
	})
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}

	origin := newAwaitOwnershipScope(t, "origin")
	resolver := newAwaitOwnershipScope(t, "resolver")
	var resumed awaitOwnershipObservation
	var resolve func(interface{}) error
	if err := loop.Run(func(jsengine.Runtime) error {
		return wrappedLoop.RunWithContext(origin, func(runtime jsengine.Runtime) error {
			if err := runtime.Bind("capturePrewrappedAwait", func() {
				resumed = observeAwaitOwnership(loop)
			}); err != nil {
				return err
			}
			vm, ok := Raw(runtime)
			if !ok {
				return errors.New("goja runtime unavailable")
			}
			promise, settle, _ := vm.NewPromise()
			resolve = settle
			if err := vm.Set("__prewrappedPendingAwait", promise); err != nil {
				return err
			}
			_, err := runtime.RunString("prewrapped-await.js", `(async function () {
				await __prewrappedPendingAwait;
				capturePrewrappedAwait();
			})();`)
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	if resolve == nil {
		t.Fatal("native promise resolver was not installed")
	}
	if err := jsengine.RunWithContext(loop, resolver, func(jsengine.Runtime) error {
		return resolve("done")
	}); err != nil {
		t.Fatal(err)
	}
	if resumed.owner != origin || resumed.active != 1 {
		t.Fatalf("prewrapped await resumed with owner=%v active=%d, want origin active=1", resumed.owner, resumed.active)
	}
}

func TestWrapAcceptsRuntimeWithMissingPromiseIntrinsic(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*g.Runtime)
	}{
		{
			name: "null constructor",
			mutate: func(vm *g.Runtime) {
				_ = vm.Set("Promise", g.Null())
			},
		},
		{
			name: "null prototype",
			mutate: func(vm *g.Runtime) {
				promise := vm.NewObject()
				_ = promise.Set("prototype", g.Null())
				_ = vm.Set("Promise", promise)
			},
		},
		{
			name: "throwing constructor getter",
			mutate: func(vm *g.Runtime) {
				_, _ = vm.RunString(`Object.defineProperty(globalThis, "Promise", { configurable: true, get() { throw new Error("constructor getter"); } });`)
			},
		},
		{
			name: "throwing prototype getter",
			mutate: func(vm *g.Runtime) {
				_, _ = vm.RunString(`globalThis.Promise = {}; Object.defineProperty(Promise, "prototype", { get() { throw new Error("prototype getter"); } });`)
			},
		},
		{
			name: "throwing then getter",
			mutate: func(vm *g.Runtime) {
				_, _ = vm.RunString(`globalThis.Promise = { prototype: {} }; Object.defineProperty(Promise.prototype, "then", { get() { throw new Error("then getter"); } });`)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vm := g.New()
			test.mutate(vm)
			var wrapped jsengine.Runtime
			var recovered any
			func() {
				defer func() {
					recovered = recover()
				}()
				wrapped = Wrap(vm)
			}()
			if recovered != nil {
				t.Fatalf("Wrap() panicked: %v", recovered)
			}
			if wrapped == nil || wrapped.Engine() != jsengine.EngineGoja {
				t.Fatalf("Wrap() = %#v", wrapped)
			}
		})
	}
}
