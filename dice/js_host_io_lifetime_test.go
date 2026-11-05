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

// hostIOGate is an HTTP server whose responses are released by the test, so
// every lifetime assertion is ordered by explicit signals instead of timing.
type hostIOGate struct {
	server  *httptest.Server
	arrived chan struct{}
	aborted chan struct{}
	release chan struct{}
	once    sync.Once
}

func newHostIOGate(t *testing.T) *hostIOGate {
	t.Helper()
	gate := &hostIOGate{
		arrived: make(chan struct{}, 8),
		aborted: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
	gate.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gate.arrived <- struct{}{}
		select {
		case <-gate.release:
			_, _ = writer.Write([]byte("host-io-value"))
		case <-request.Context().Done():
			gate.aborted <- struct{}{}
		}
	}))
	t.Cleanup(func() {
		gate.open()
		gate.server.Close()
	})
	return gate
}

func (g *hostIOGate) open() { g.once.Do(func() { close(g.release) }) }

func (g *hostIOGate) waitArrived(t *testing.T) {
	t.Helper()
	select {
	case <-g.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch request never reached the server")
	}
}

func (g *hostIOGate) waitAborted(t *testing.T) {
	t.Helper()
	select {
	case <-g.aborted:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch request was not aborted")
	}
}

// settleJSLoop proves every callback queued before it has been delivered: the
// owner loop handles queued work in order, and the barrier round-trips twice
// so a completion that schedules a continuation is covered as well.
func settleJSLoop(t *testing.T, loop jsengine.Loop) {
	t.Helper()
	for range 2 {
		if err := jsengine.RunWithContext(loop, nil, func(jsengine.Runtime) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
}

func requireJSGlobalFalse(t *testing.T, loop jsengine.Loop, name string) {
	t.Helper()
	if err := jsengine.RunWithContext(loop, nil, func(runtime jsengine.Runtime) error {
		if runtime.Get(name).ToBoolean() {
			t.Errorf("%s ran although its host I/O lifetime had ended", name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// runHostIOResolverRoot runs source in a fresh root, the way another callback
// resolves a Promise that an earlier root returned.
func runHostIOResolverRoot(t *testing.T, d *Dice, loop jsengine.Loop, runtimeID, source string) {
	t.Helper()
	identity := d.DomainExecutionIdentity("js-test-host-io-resolver", runtimeID)
	if err := d.WithDomainExecution(context.Background(), identity, []byte(identity+source), func(transaction *DurableCallbackTransaction) error {
		parent := context.Background()
		if transaction != nil && transaction.executionContext != nil {
			parent = transaction.executionContext
		}
		realm := jsContextForRoot(parent, d, nil, nil, transaction, false)
		return runJSExecutionRoot(realm, func() error {
			return jsengine.RunWithContext(loop, realm, func(runtime jsengine.Runtime) error {
				_, err := runtime.RunString("host-io-resolver.js", source)
				return err
			})
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func hostIOTimerFetchScript(runtimeID, extensionName, url string) string {
	return fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
globalThis.__hostIOThen = false;
globalThis.__hostIORejected = false;
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
setTimeout(function () {
  ext.storageSet("timer-root", "ended");
  fetch(%q).then(function (response) {
    return response.text();
  }).then(function (text) {
    ext.storageSet("timer-fetch", text);
    globalThis.__hostIOThen = true;
  }, function () {
    globalThis.__hostIORejected = true;
  });
}, 0);
`, runtimeID, extensionName, url)
}

func forEachHostIORuntime(t *testing.T, run func(t *testing.T, runtimeID string)) {
	t.Helper()
	for _, runtimeID := range []string{string(jsengine.EngineGoja), "quickjs"} {
		t.Run(runtimeID, func(t *testing.T) {
			if runtimeID == "quickjs" && os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
				t.Skip("native QuickJS package is not configured")
			}
			run(t, runtimeID)
		})
	}
}

// A fetch the timer callback neither awaits nor returns must outlive the timer
// root: the root only owns the synchronous callback, while the request follows
// the persistent binding. Its continuation is a new root, so its storage write
// commits independently of the already committed timer root.
func TestJSPersistentTimerUnawaitedFetchOutlivesTimerRoot(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		gate := newHostIOGate(t)
		extensionName := "Timer fetch outlives root " + runtimeID
		d, _, _, _, loop := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName,
			hostIOTimerFetchScript(runtimeID, extensionName, gate.server.URL))

		// The timer root commits when it ends; the fetch is still pending.
		waitPluginKV(t, d, extensionName, "timer-root", "ended")
		gate.waitArrived(t)
		gate.open()

		waitJSGlobalBoolean(t, loop, "__hostIOThen")
		waitPluginKV(t, d, extensionName, "timer-fetch", "host-io-value")
		requireJSGlobalFalse(t, loop, "__hostIORejected")
	})
}

// An awaited fetch is not unawaited work: the timer root stays open on the
// returned Promise, the continuation resumes inside that root, and both of its
// writes commit together once the response arrives.
func TestJSPersistentTimerAwaitedFetchStaysInTimerRoot(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		gate := newHostIOGate(t)
		extensionName := "Timer awaited fetch " + runtimeID
		scriptSource := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
setTimeout(async function () {
  ext.storageSet("awaited-before", "before");
  var response = await fetch(%q);
  ext.storageSet("awaited-after", await response.text());
}, 0);
`, runtimeID, extensionName, gate.server.URL)
		d, _, _, _, _ := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, scriptSource)

		gate.waitArrived(t)
		repository, err := d.durablePluginKV()
		if err != nil {
			t.Fatal(err)
		}
		if item, err := repository.GetPluginKV(context.Background(), extensionName, "awaited-before"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
			t.Fatalf("awaited-before committed while the awaited fetch was pending: value=%q err=%v", item.Value, err)
		}
		gate.open()
		waitPluginKV(t, d, extensionName, "awaited-before", "before")
		waitPluginKV(t, d, extensionName, "awaited-after", "host-io-value")
	})
}

// A timer armed by a timer callback outlives the callback's root the same way.
func TestJSPersistentTimerNestedTimerOutlivesTimerRoot(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		extensionName := "Nested timer outlives root " + runtimeID
		scriptSource := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
setTimeout(function () {
  ext.storageSet("outer-root", "ended");
  setTimeout(function () {
    ext.storageSet("nested-timer", "fired");
  }, 0);
}, 0);
`, runtimeID, extensionName)
		d, _, _, _, _ := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, scriptSource)

		waitPluginKV(t, d, extensionName, "outer-root", "ended")
		waitPluginKV(t, d, extensionName, "nested-timer", "fired")
	})
}

// Deactivating the binding is a lifecycle end: the request is aborted and its
// late completion never re-enters script.
func TestJSPersistentTimerFetchAbortedByBindingRetirement(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		gate := newHostIOGate(t)
		extensionName := "Timer fetch binding retirement " + runtimeID
		d, _, _, _, loop := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName,
			hostIOTimerFetchScript(runtimeID, extensionName, gate.server.URL))
		registered, ok := d.JsExtRegistry.Load(extensionName)
		if !ok || registered == nil || registered.GetRealExt() == nil || registered.GetRealExt().Source == nil {
			t.Fatal("registered extension has no script source")
		}

		waitPluginKV(t, d, extensionName, "timer-root", "ended")
		gate.waitArrived(t)
		JsDelete(d, registered.GetRealExt().Source)
		gate.waitAborted(t)
		settleJSLoop(t, loop)
		requireJSGlobalFalse(t, loop, "__hostIOThen")
		requireJSGlobalFalse(t, loop, "__hostIORejected")
	})
}

// A timer root that fails is an explicit cancellation of that invocation, not a
// normal end: the request it started is aborted and its continuation never runs.
func TestJSPersistentTimerFetchAbortedByTimerRootFailure(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		gate := newHostIOGate(t)
		extensionName := "Timer fetch root failure " + runtimeID
		scriptSource := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
globalThis.__hostIOThen = false;
globalThis.__hostIORelease = null;
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
setTimeout(async function () {
  fetch(%q).then(function () {
    globalThis.__hostIOThen = true;
  }, function () {});
  await new Promise(function (resolve) {
    globalThis.__hostIORelease = resolve;
  });
  throw new Error("timer root failed");
}, 0);
`, runtimeID, extensionName, gate.server.URL)
		d, _, _, _, loop := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, scriptSource)

		gate.waitArrived(t)
		runHostIOResolverRoot(t, d, loop, runtimeID, "globalThis.__hostIORelease()")
		gate.waitAborted(t)
		settleJSLoop(t, loop)
		requireJSGlobalFalse(t, loop, "__hostIOThen")
	})
}

// Closing the runtime aborts in-flight host I/O started by a timer root.
func TestJSPersistentTimerFetchAbortedByRuntimeShutdown(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		gate := newHostIOGate(t)
		extensionName := "Timer fetch runtime shutdown " + runtimeID
		d, _, _, _, _ := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName,
			hostIOTimerFetchScript(runtimeID, extensionName, gate.server.URL))

		waitPluginKV(t, d, extensionName, "timer-root", "ended")
		gate.waitArrived(t)
		d.JsShutdown()
		gate.waitAborted(t)
	})
}

// A Goja message callback owns its fetch through the message execution: once
// the message completes, an unawaited request is aborted and its continuation
// never runs, exactly as for message-scoped timers. Native QuickJS requests are
// not tied to the message and keep their runtime-level lifetime.
func TestJSMessageCallbackUnawaitedFetchIsMessageScoped(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		if runtimeID != string(jsengine.EngineGoja) {
			t.Skip("native QuickJS message-scoped fetch is not aborted by message completion")
		}
		gate := newHostIOGate(t)
		extensionName := "Message fetch scoped " + runtimeID
		scriptSource := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
globalThis.__hostIOThen = false;
globalThis.__hostIORejected = false;
globalThis.__hostIORelease = null;
var ext = seal.ext.new(%q, "test", "1.0.0");
ext.onMessagePreprocess = function (_ctx, msg) {
  if (msg.message !== "fetch-probe") return null;
  fetch(%q).then(function () {
    globalThis.__hostIOThen = true;
  }, function () {
    globalThis.__hostIORejected = true;
  });
  return new Promise(function (resolve) {
    globalThis.__hostIORelease = function () { resolve(null); };
  });
};
seal.ext.register(ext);
`, runtimeID, extensionName, gate.server.URL)
		d, ep, _, _, loop := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, scriptSource)

		done := make(chan error, 1)
		go func() {
			msg := newGroupMsg("QQ-Group:host-io-message-"+runtimeID, "QQ:999", "fetch-probe")
			done <- executeCanonicalTestMessage(t.Context(), d, ep, msg, messageExecutionOptions{parser: messageParserSegments}).err
		}()
		gate.waitArrived(t)

		runHostIOResolverRoot(t, d, loop, runtimeID, "globalThis.__hostIORelease()")
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("message execution failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("message execution did not finish")
		}

		gate.waitAborted(t)
		settleJSLoop(t, loop)
		requireJSGlobalFalse(t, loop, "__hostIOThen")
		requireJSGlobalFalse(t, loop, "__hostIORejected")
	})
}
