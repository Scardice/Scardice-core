package dice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	nativejs "Scardice-core/utils/jsengine/native"
	"Scardice-core/utils/jsengine/services"
)

type finalObservedFetchService struct {
	*nativeFetchService
	origin         chan *jsExecutionContext
	terminalQueued chan struct{}
}

func (s *finalObservedFetchService) Start(call services.AsyncCall) error {
	s.origin <- jsOpaqueExecutionContext(call.Call.Context)
	call.Sink = finalObservedFetchSink{AsyncSink: call.Sink, terminalQueued: s.terminalQueued}
	return s.nativeFetchService.Start(call)
}

type finalObservedFetchSink struct {
	services.AsyncSink
	terminalQueued chan struct{}
}

func (s finalObservedFetchSink) Complete(id services.RequestID, response services.Response) error {
	err := s.AsyncSink.Complete(id, response)
	s.terminalQueued <- struct{}{}
	return err
}

// The WeakRef observes the actual Promise returned by native fetch. While the
// provider owns resolve/reject, its native Promise's reaction owns this Promise.
// A terminal completion must release that last root, even when the invocation
// that started it failed and its JS continuations must not execute.
func TestNativeFailedTimerFetchTerminalReleasesPromise(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	d, loop, loaded := persistentLifecycleFixture(t, "quickjs")
	fetch := &finalObservedFetchService{
		nativeFetchService: newNativeFetchService(d, loop),
		origin:             make(chan *jsExecutionContext, 1), terminalQueued: make(chan struct{}, 1),
	}
	registry := services.NewRegistry()
	registry.SetPolicyProvider(func(call services.Call) services.Policy {
		return services.Policy{Authorizer: nativeServiceAuthorizer{dice: d, context: jsOpaqueExecutionContext(call.Context)}}
	})
	for _, factory := range nativeServiceFactories {
		service := factory.newService(d, loop)
		if factory.name == services.Fetch {
			service = fetch
		}
		if err := registry.Register(service); err != nil {
			t.Fatal(err)
		}
	}
	if err := nativejs.InstallServiceRegistry(loop, registry); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	store, ok := d.DurableStore.(*eventstore.GORMStore)
	if !ok {
		t.Fatalf("durable store = %T, want actual SQLite store", d.DurableStore)
	}
	for round, failure := range []string{"throw", "timeout", "throw"} {
		gate := newHostIOGate(t)
		extensionName := fmt.Sprintf("Final failed fetch %d %s", round, failure)
		script := &JsScriptInfo{
			Name: extensionName, Enable: true,
			runtimeGeneration: jsContextGeneration(&jsExecutionContext{Script: loaded}),
		}
		source := fmt.Sprintf(`
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
globalThis.__finalFailedFetchThen = false;
globalThis.__finalFailedFetchCatch = false;
globalThis.__finalFailedFetchRelease = null;
setTimeout(async function () {
  (function () {
    var request = fetch(%q);
    globalThis.__finalFailedFetchWeak = new WeakRef(request);
    request.then(function () {
      globalThis.__finalFailedFetchThen = true;
      ext.storageSet("revoked-fetch-then", "escaped");
    }, function () {
      globalThis.__finalFailedFetchCatch = true;
      ext.storageSet("revoked-fetch-catch", "escaped");
    });
  })();
  await new Promise(function (resolve) {
    globalThis.__finalFailedFetchRelease = resolve;
  });
  throw new Error("final promoted timer failed");
}, 0);
`, extensionName, gate.server.URL)
		if err := d.loadJSScriptInRoot(loop, script, fmt.Sprintf("final-failed-fetch-%d.js", round), []byte(source)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { script.replacePersistentBinding(nil) })
		gate.waitArrived(t)
		origin := awaitPersistentLifecycle(t, fetch.origin, "actual native fetch's promoted timer origin")
		if origin == nil || !origin.PersistentAsync || origin.binding != script.currentPersistentBinding() {
			t.Fatalf("native fetch origin is not the actual promoted timer root: %#v", origin)
		}
		if err := jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("final-pending-fetch-weak.js", "__finalFailedFetchWeak.deref() !== undefined")
			if err == nil && !value.ToBoolean() {
				t.Error("native fetch Promise was not retained while its real HTTP request was pending")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if failure == "timeout" {
			// Exercise the existing invocation deadline, without introducing a
			// shorter test-only timeout or changing the runtime configuration.
			select {
			case <-origin.execution.ctx.Done():
				if cause := context.Cause(origin.execution.ctx); !errors.Is(cause, context.DeadlineExceeded) {
					t.Fatalf("timer root ended with %v, want its actual invocation deadline", cause)
				}
			case <-time.After(jsSolveAwaitTimeout + 5*time.Second):
				t.Fatal("promoted timer root did not reach its existing invocation deadline")
			}
		} else {
			runHostIOResolverRoot(t, d, loop, fmt.Sprintf("final-failed-fetch-%d", round), "globalThis.__finalFailedFetchRelease()")
		}
		gate.waitAborted(t)
		awaitPersistentLifecycle(t, fetch.terminalQueued, "actual canceled HTTP terminal to enter native request pump")
		joined := make(chan struct{})
		go func() {
			origin.binding.roots.Wait()
			close(joined)
		}()
		awaitPersistentLifecycle(t, joined, "failed timer and terminal request pump to finish")
		settleJSLoop(t, loop)
		if err := jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
			value, err := runtime.RunString("final-retired-fetch-weak.js", "__finalFailedFetchWeak.deref() === undefined")
			if err == nil && !value.ToBoolean() {
				t.Errorf("round %d: provider still roots the failed timer's fetch Promise after terminal cleanup", round)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		requireJSGlobalFalse(t, loop, "__finalFailedFetchThen")
		requireJSGlobalFalse(t, loop, "__finalFailedFetchCatch")
		for _, key := range []string{"revoked-fetch-then", "revoked-fetch-catch"} {
			if _, err := store.GetPluginKV(context.Background(), extensionName, key); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
				t.Errorf("failed timer's revoked continuation committed %s: %v", key, err)
			}
		}
		script.replacePersistentBinding(nil)
	}
}

type finalRejectCompletionAdmissionStore struct {
	*eventstore.GORMStore
	entered chan struct{}
}

func (s *finalRejectCompletionAdmissionStore) AdmitExecution(context.Context, eventstore.ExecutionAdmissionRequest) (eventstore.ExecutionReceipt, error) {
	s.entered <- struct{}{}
	return eventstore.ExecutionReceipt{}, errors.New("test rejected completion admission")
}

func TestNativeRetiredBindingFetchTerminalReleasesPromise(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	for _, scenario := range []string{"failed-load-queued-terminal", "retired-loaded-binding", "failed-completion-admission"} {
		t.Run(scenario, func(t *testing.T) {
			d, loop, loaded := persistentLifecycleFixture(t, "quickjs")
			fetch := &finalObservedFetchService{
				nativeFetchService: newNativeFetchService(d, loop),
				origin:             make(chan *jsExecutionContext, 1), terminalQueued: make(chan struct{}, 1),
			}
			registry := services.NewRegistry()
			registry.SetPolicyProvider(func(call services.Call) services.Policy {
				return services.Policy{Authorizer: nativeServiceAuthorizer{dice: d, context: jsOpaqueExecutionContext(call.Context)}}
			})
			for _, factory := range nativeServiceFactories {
				service := factory.newService(d, loop)
				if factory.name == services.Fetch {
					service = fetch
				}
				if err := registry.Register(service); err != nil {
					t.Fatal(err)
				}
			}
			if err := nativejs.InstallServiceRegistry(loop, registry); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = registry.Close() })
			gate := newHostIOGate(t)
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				return runtime.Bind("__retiredBindingWaitTerminal", func() {
					gate.open()
					select {
					case <-fetch.terminalQueued:
					case <-time.After(3 * time.Second):
						t.Error("real HTTP terminal did not queue while the load owner was held")
					}
				})
			}); err != nil {
				t.Fatal(err)
			}
			script := &JsScriptInfo{
				Name: scenario, Enable: true,
				runtimeGeneration: jsContextGeneration(&jsExecutionContext{Script: loaded}),
			}
			source := fmt.Sprintf(`
globalThis.__retiredBindingThen = false;
globalThis.__retiredBindingCatch = false;
(function () {
  var request = fetch(%q);
  globalThis.__retiredBindingWeak = new WeakRef(request);
  request.then(() => { __retiredBindingThen = true; },
               () => { __retiredBindingCatch = true; });
})();`, gate.server.URL)
			failedLoad := scenario == "failed-load-queued-terminal"
			if failedLoad {
				source += `__retiredBindingWaitTerminal(); throw new Error("retired binding load failed");`
			}
			err := d.loadJSScriptInRoot(loop, script, scenario+".js", []byte(source))
			if failedLoad && err == nil {
				t.Fatal("failed load was reported as success")
			}
			if !failedLoad && err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { script.replacePersistentBinding(nil) })
			origin := awaitPersistentLifecycle(t, fetch.origin, "native fetch to capture its load binding")
			if !failedLoad {
				gate.waitArrived(t)
				if scenario == "failed-completion-admission" {
					base, ok := d.DurableStore.(*eventstore.GORMStore)
					if !ok {
						t.Fatalf("durable store = %T", d.DurableStore)
					}
					rejected := &finalRejectCompletionAdmissionStore{GORMStore: base, entered: make(chan struct{}, 1)}
					d.DurableStore = rejected
					gate.open()
					awaitPersistentLifecycle(t, fetch.terminalQueued, "completed fetch's real terminal event")
					awaitPersistentLifecycle(t, rejected.entered, "completion to reach real domain admission")
				} else {
					script.replacePersistentBinding(nil)
					gate.waitAborted(t)
					awaitPersistentLifecycle(t, fetch.terminalQueued, "retired binding's actual HTTP cancellation terminal")
				}
			}
			joined := make(chan struct{})
			go func() {
				origin.binding.roots.Wait()
				close(joined)
			}()
			awaitPersistentLifecycle(t, joined, "retired binding's request pump to finish")
			settleJSLoop(t, loop)
			if err := jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("retired-binding-promise-released.js", "__retiredBindingWeak.deref() === undefined")
				if err == nil && !value.ToBoolean() {
					t.Error("provider still retains fetch Promise after its binding was retired")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			requireJSGlobalFalse(t, loop, "__retiredBindingThen")
			requireJSGlobalFalse(t, loop, "__retiredBindingCatch")
		})
	}
}
