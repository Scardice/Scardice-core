package dice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

type executionDrainObservation struct {
	realm *jsExecutionContext
	owner bool
	raw   any
}

// Run a real Promise reaction and keep its admitted Go host callback alive
// after cancellation. resolverRealm selects same-origin or independent entry.
func holdExecutionDrainContinuation(t *testing.T, d *Dice, loop jsengine.Loop, realm *jsExecutionContext, message *MsgContext, beforeAwait string, resolverRealm *jsExecutionContext) (<-chan executionDrainObservation, <-chan error, func()) {
	t.Helper()
	ready := make(chan struct{})
	entered := make(chan executionDrainObservation, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(open)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("__executionDrainReady", func() { close(ready) }); err != nil {
			return err
		}
		return runtime.Bind("__executionDrainHeldHost", func() {
			raw := jsengine.CurrentContext(loop)
			entered <- executionDrainObservation{realm: jsOpaqueExecutionContext(raw), owner: jsengine.InOwner(loop), raw: raw}
			<-release
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.ExtLoopManager.dispatchJSCallback(jsCallbackRequest{
		Generation: jsContextGeneration(realm),
		Realm:      realm,
		Message:    message,
		ValueCallback: func(runtime jsengine.Runtime) (jsengine.Value, error) {
			return runtime.RunString("execution-drain-continuation.js", `(async function () {
`+beforeAwait+`
  await new Promise(function (resolve) {
    globalThis.__executionDrainResolve = resolve;
    __executionDrainReady();
  });
  __executionDrainHeldHost();
})()`)
		},
		OnError: message.recordJSExecutionError,
	}, true); err != nil {
		t.Fatal(err)
	}
	awaitPersistentLifecycle(t, ready, "asynchronous callback to await its real Promise")
	resolved := make(chan error, 1)
	var resolverScope any
	if resolverRealm != nil {
		resolverScope = resolverRealm
	}
	go func() {
		resolved <- jsengine.RunWithContext(loop, resolverScope, func(runtime jsengine.Runtime) error {
			_, err := runtime.RunString("execution-drain-resolve.js", "__executionDrainResolve()")
			return err
		})
	}()
	return entered, resolved, open
}

func requireExecutionDrainHeld(t *testing.T, returned <-chan error, description string) (error, bool) {
	t.Helper()
	select {
	case err := <-returned:
		t.Errorf("%s returned while its admitted Go host callback was still running: %v", description, err)
		return err, true
	case <-time.After(100 * time.Millisecond):
	}
	return nil, false
}

func TestJSMessageCancellationJoinsAdmittedHostContinuation(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		for _, teardown := range []string{"stop", "release"} {
			t.Run(teardown, func(t *testing.T) {
				d, loop, script := persistentLifecycleFixture(t, runtimeID)
				parent, cancel := context.WithCancelCause(t.Context())
				defer cancel(context.Canceled)
				message := &MsgContext{Dice: d, executionContext: parent}
				t.Cleanup(message.releaseExecutionState)
				realm := jsContextForMessage(nil, message)
				realm.Script = script
				entered, resolved, open := holdExecutionDrainContinuation(t, d, loop, realm, message, "", realm)
				observation := awaitPersistentLifecycle(t, entered, "admitted Promise continuation to enter its Go host callback")
				if !observation.owner || observation.realm == nil || observation.realm.executionScope() != realm.executionScope() {
					open()
					t.Fatalf("Promise continuation lost its real message authority: owner=%v current=%T restored=%p want=%p", observation.owner, observation.raw, observation.realm.executionScope(), realm.executionScope())
				}
				cause := errors.New("message cancelled while host callback is running")
				cancel(cause)
				awaitPersistentLifecycle(t, realm.ExecutionContext().Done(), "cancellation to reach the blocked continuation promptly")
				returned := make(chan error, 1)
				go func() {
					if teardown == "release" {
						message.releaseExecutionState()
						returned <- context.Cause(realm.ExecutionContext())
						return
					}
					returned <- message.stopJSExecution()
				}()
				earlyErr, returnedEarly := requireExecutionDrainHeld(t, returned, "message "+teardown)
				if message.executionReleased.Load() {
					t.Error("message execution state was released before the admitted host callback returned")
				}
				open()
				// The canceled root's result below owns the failure; this only joins its resolver turn.
				_ = awaitPersistentLifecycle(t, resolved, "cancelled resolver owner to unwind")
				err := earlyErr
				if !returnedEarly {
					err = awaitPersistentLifecycle(t, returned, "message teardown to join the admitted host callback")
				}
				if !errors.Is(err, cause) && !errors.Is(err, context.Canceled) {
					t.Fatalf("message %s lost its cancellation cause: %v", teardown, err)
				}
			})
		}
	})
}

func TestJSFailedRootJoinsAdmittedHostContinuationBeforeDomainAbort(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		d, loop, script := persistentLifecycleFixture(t, runtimeID)
		type rootScope struct {
			realm   *jsExecutionContext
			message *MsgContext
		}
		started := make(chan rootScope, 1)
		fail := make(chan struct{})
		var failOnce sync.Once
		failRoot := func() { failOnce.Do(func() { close(fail) }) }
		t.Cleanup(failRoot)
		returned := make(chan error, 1)
		cause := errors.New("root failed while host callback is running")
		identity := d.DomainExecutionIdentity("js-test-failed-root-join", runtimeID)
		go func() {
			returned <- d.WithDomainExecution(t.Context(), identity, []byte(identity), func(transaction *DurableCallbackTransaction) error {
				realm := jsContextForRoot(transaction.executionContext, d, nil, script, transaction, false)
				message := &MsgContext{Dice: d, callbackTransaction: transaction, jsExecution: realm.execution}
				realm.Message = message
				return runJSExecutionRoot(realm, func() error {
					started <- rootScope{realm: realm, message: message}
					<-fail
					return cause
				})
			})
		}()
		scope := awaitPersistentLifecycle(t, started, "real durable root admission")
		entered, resolved, open := holdExecutionDrainContinuation(t, d, loop, scope.realm, scope.message,
			`__persistentLifecycleExt.storageSet("failed-root-join", "must-not-commit");`, scope.realm)
		observation := awaitPersistentLifecycle(t, entered, "admitted root continuation to enter its Go host callback")
		if !observation.owner || observation.realm == nil || observation.realm.executionScope() != scope.realm.executionScope() {
			open()
			t.Fatalf("Promise continuation lost its real root authority: owner=%v current=%T restored=%p want=%p", observation.owner, observation.raw, observation.realm.executionScope(), scope.realm.executionScope())
		}
		failRoot()
		awaitPersistentLifecycle(t, scope.realm.ExecutionContext().Done(), "failed root cancellation to reach its blocked continuation promptly")
		earlyErr, returnedEarly := requireExecutionDrainHeld(t, returned, "failed durable root/domain abort")
		open()
		_ = awaitPersistentLifecycle(t, resolved, "failed-root resolver owner to unwind")
		rootErr := earlyErr
		if !returnedEarly {
			rootErr = awaitPersistentLifecycle(t, returned, "failed durable root to join the admitted host callback")
		}
		if !errors.Is(rootErr, cause) {
			t.Fatalf("failed root lost its original failure: %v", rootErr)
		}
		repository, err := d.durablePluginKV()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repository.GetPluginKV(context.Background(), script.Name, "failed-root-join"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
			t.Fatalf("failed joined root committed its storage mutation: %v", err)
		}
	})
}

func TestJSIntrinsicAwaitRetainsMessageAuthorityAcrossResolverRoots(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		for _, resolverKind := range []string{"unbound", "independent-root"} {
			t.Run(resolverKind, func(t *testing.T) {
				d, loop, script := persistentLifecycleFixture(t, runtimeID)
				message := &MsgContext{Dice: d, executionContext: t.Context()}
				t.Cleanup(message.releaseExecutionState)
				realm := jsContextForMessage(nil, message)
				realm.Script = script
				var resolverRealm *jsExecutionContext
				if resolverKind == "independent-root" {
					resolverRealm = jsContextForRoot(t.Context(), d, nil, script, nil, false)
					t.Cleanup(func() { _ = resolverRealm.execution.stop() })
				}
				entered, resolved, open := holdExecutionDrainContinuation(t, d, loop, realm, message, "", resolverRealm)
				observation := awaitPersistentLifecycle(t, entered, "intrinsic await to resume from the independent resolver")
				open()
				if err := awaitPersistentLifecycle(t, resolved, "independent resolver owner to return"); err != nil {
					t.Fatal(err)
				}
				if !observation.owner || observation.realm == nil || observation.realm.executionScope() != realm.executionScope() {
					t.Fatalf("intrinsic await lost origin authority: owner=%v current=%T(%#v) restored=%p want=%p", observation.owner, observation.raw, observation.raw, observation.realm.executionScope(), realm.executionScope())
				}
			})
		}
	})
}

func TestNativeCancelledAwaitDoesNotAffectIndependentRoot(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	for _, state := range []string{"pending", "settled"} {
		t.Run(state, func(t *testing.T) {
			d, loop, script := persistentLifecycleFixture(t, "quickjs")
			parent, cancel := context.WithCancelCause(t.Context())
			defer cancel(context.Canceled)
			origin := jsContextForRoot(parent, d, nil, script, nil, false)
			t.Cleanup(func() { _ = origin.execution.stop() })
			independent := jsContextForRoot(t.Context(), d, nil, script, nil, false)
			t.Cleanup(func() { _ = independent.execution.stop() })
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				return runtime.Bind("__cancelAwaitOrigin", func() { cancel(context.Canceled) })
			}); err != nil {
				t.Fatal(err)
			}
			awaited := "new Promise(resolve => globalThis.__resolveCancelledAwait = resolve)"
			cancelNow := ""
			if state == "settled" {
				awaited = "Promise.resolve(1)"
				cancelNow = "__cancelAwaitOrigin();"
			}
			err := jsengine.RunWithContext(loop, origin, func(runtime jsengine.Runtime) error {
				_, err := runtime.RunString("cancelled-intrinsic-await.js",
					"globalThis.__cancelledAwaitRan = false;"+
						"(async function () { await "+awaited+"; __cancelledAwaitRan = true; })();"+
						cancelNow+"0")
				return err
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			cancel(context.Canceled)
			if err := jsengine.RunWithContext(loop, independent, func(runtime jsengine.Runtime) error {
				source := "6 * 7 === 42"
				if state == "pending" {
					source = "__resolveCancelledAwait(); " + source
				}
				value, err := runtime.RunString("independent-await-resolver.js", source)
				if err == nil && !value.ToBoolean() {
					t.Errorf("cancelled await contaminated independent root: %v", value)
				}
				return err
			}); err != nil {
				t.Fatalf("cancelled await failed independent resolver: %v", err)
			}
			requireJSGlobalFalse(t, loop, "__cancelledAwaitRan")
		})
	}
}

type executionWatcherHook struct {
	done chan struct{}
	once sync.Once
}

func (h *executionWatcherHook) finish() { h.once.Do(func() { close(h.done) }) }

// A distinct Done channel prevents context's private cancelCtx fast path from
// bypassing AfterFunc. The real context/cause is preserved; only delivery of
// its registered cancellation callbacks is delayed.
type executionWatcherGate struct {
	context.Context
	done    chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	hooks   []*executionWatcherHook
}

func gateExecutionWatchers(execution *jsMessageExecution) *executionWatcherGate {
	gate := &executionWatcherGate{Context: execution.ctx, done: make(chan struct{}), release: make(chan struct{})}
	execution.ctx = gate
	go func() {
		<-gate.Context.Done()
		close(gate.done)
	}()
	return gate
}

func (g *executionWatcherGate) Done() <-chan struct{} { return g.done }

func (g *executionWatcherGate) AfterFunc(run func()) func() bool {
	hook := &executionWatcherHook{done: make(chan struct{})}
	g.mu.Lock()
	g.hooks = append(g.hooks, hook)
	g.mu.Unlock()
	stop := context.AfterFunc(g.Context, func() {
		<-g.release
		run()
		hook.finish()
	})
	return func() bool {
		stopped := stop()
		if stopped {
			hook.finish()
		}
		return stopped
	}
}

func (g *executionWatcherGate) open() { g.once.Do(func() { close(g.release) }) }

func (g *executionWatcherGate) deliver(t *testing.T) {
	t.Helper()
	g.open()
	g.mu.Lock()
	hooks := append([]*executionWatcherHook(nil), g.hooks...)
	g.mu.Unlock()
	for _, hook := range hooks {
		awaitPersistentLifecycle(t, hook.done, "gated execution cancellation hook delivery")
	}
}

type executionContextDoneObserver struct {
	context.Context
	observed chan struct{}
}

func (c executionContextDoneObserver) Done() <-chan struct{} {
	select {
	case c.observed <- struct{}{}:
	default:
	}
	return c.Context.Done()
}

func TestJSPersistentTokenRetirementDoesNotBorrowConcurrentRootDeadline(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		d, loop, loaded := persistentLifecycleFixture(t, runtimeID)
		httpGate := newHostIOGate(t)
		continued := make(chan string, 1)
		receiver := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			continued <- request.URL.Query().Get("value")
			writer.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(receiver.Close)
		script := &JsScriptInfo{Name: "Token retirement " + runtimeID, Enable: true, runtimeGeneration: jsContextGeneration(&jsExecutionContext{Script: loaded})}
		first := jsContextForRoot(t.Context(), d, nil, script, nil, true)
		binding := first.binding
		t.Cleanup(binding.retire)
		bindingObserved := make(chan struct{}, 32)
		// This binding has not entered the VM or published a token yet.
		binding.context = executionContextDoneObserver{Context: binding.context, observed: bindingObserved}
		watchers := gateExecutionWatchers(first.execution)
		t.Cleanup(watchers.open)
		if err := runJSExecutionRoot(first, func() error {
			return jsengine.RunWithContext(loop, first, func(runtime jsengine.Runtime) error {
				return first.withRuntime(runtime, func() error {
					_, err := runtime.RunString("persistent-token-first-root.js", fmt.Sprintf(`
fetch(%q).then(function (response) { return response.text(); }).then(function (text) {
  return fetch(%q + "?value=" + encodeURIComponent(text));
});
`, httpGate.server.URL, receiver.URL))
					return err
				})
			})
		}); err != nil {
			t.Fatal(err)
		}
		script.replacePersistentBinding(binding)
		first.completePersistentBinding(nil)
		httpGate.waitArrived(t)

		blocked, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		open := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(open)
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			return runtime.Bind("__executionOtherRootHeldHost", func() {
				close(blocked)
				<-release
			})
		}); err != nil {
			t.Fatal(err)
		}
		deadline, cancelDeadline := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancelDeadline()
		second := jsContextForRoot(deadline, d, nil, script, nil, false)
		secondObserved := make(chan struct{}, 32)
		second.execution.ctx = executionContextDoneObserver{Context: second.execution.ctx, observed: secondObserved}
		secondDone := make(chan error, 1)
		go func() {
			secondDone <- runJSExecutionRoot(second, func() error {
				return jsengine.RunWithContext(loop, second, func(runtime jsengine.Runtime) error {
					return second.withRuntime(runtime, func() error {
						_, err := runtime.RunString("persistent-token-second-root.js", "__executionOtherRootHeldHost()")
						return err
					})
				})
			})
		}()
		awaitPersistentLifecycle(t, blocked, "same-binding second root to enter its real Go host callback")
		// Ignore context use during setup. Any following Done lookup comes
		// from the first root's delayed token watcher choosing its replacement.
		for len(bindingObserved) != 0 {
			<-bindingObserved
		}
		for len(secondObserved) != 0 {
			<-secondObserved
		}
		watchers.deliver(t)
		select {
		case <-bindingObserved:
		case <-secondObserved:
			t.Error("real token retirement watcher subscribed to the unrelated active root instead of its binding lifetime")
		case <-time.After(time.Second):
			open()
			t.Fatal("first root token watcher never resolved its replacement lifetime")
		}
		awaitPersistentLifecycle(t, deadline.Done(), "second root deadline while its admitted host callback remains blocked")
		open()
		if err := awaitPersistentLifecycle(t, secondDone, "expired second root to unwind"); err == nil {
			t.Fatal("second root deadline was incorrectly reported as success")
		}
		httpGate.open()
		if value := awaitPersistentLifecycle(t, continued, "first root's unawaited continuation to perform its real HTTP side effect"); value != "host-io-value" {
			t.Fatalf("continued fetch value = %q, want host-io-value", value)
		}
	})
}
