package dice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

// The real repository is held before admission, not replaced: a retired root
// must cancel this context and join the call before its owner can be closed.
type persistentRootAdmissionGate struct {
	*eventstore.GORMStore
	entered chan context.Context
	release chan struct{}
	once    sync.Once
}

func (s *persistentRootAdmissionGate) ExecutionRequestDigest(ctx context.Context, canonical []byte) ([]byte, error) {
	if bytes.HasPrefix(canonical, []byte("js-persistent-async\x00")) {
		s.entered <- ctx
		<-s.release
	}
	return s.GORMStore.ExecutionRequestDigest(ctx, canonical)
}

func (s *persistentRootAdmissionGate) open() { s.once.Do(func() { close(s.release) }) }

func persistentLifecycleFixture(t *testing.T, runtimeID string) (*Dice, jsengine.Loop, *JsScriptInfo) {
	t.Helper()
	extensionName := "Persistent lifecycle " + runtimeID
	source := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
globalThis.__persistentLifecycleExt = ext;
`, runtimeID, extensionName)
	d, _, _, logs, loop := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, source)
	t.Cleanup(func() {
		if t.Failed() {
			for _, entry := range logs.All() {
				t.Logf("JS runtime error: %s %v", entry.Message, entry.Context)
			}
		}
	})
	extension, ok := d.JsExtRegistry.Load(extensionName)
	if !ok || extension == nil || extension.GetRealExt() == nil || extension.GetRealExt().Source == nil {
		t.Fatal("registered extension has no script source")
	}
	return d, loop, extension.GetRealExt().Source
}

func awaitPersistentLifecycle[T any](t *testing.T, channel <-chan T, description string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}

func TestJSPersistentInfiniteLoadIsCancelledAndJoinedByStop(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		// An ABI that cannot interrupt executing native code must fail this
		// contract without pinning the entire test process in VM Close.
		const childEnvironment = "SCARDICE_TEST_PERSISTENT_INFINITE_LOAD_CHILD"
		if os.Getenv(childEnvironment) != runtimeID {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			childContext, cancelChild := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancelChild()
			command := exec.CommandContext(childContext, executable,
				"-test.run=^TestJSPersistentInfiniteLoadIsCancelledAndJoinedByStop$/^"+regexp.QuoteMeta(runtimeID)+"$",
				"-test.timeout=12s")
			command.Env = append(os.Environ(), childEnvironment+"="+runtimeID)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("infinite load stop/join failed in isolated %s runtime: %v\n%s", runtimeID, err, output)
			}
			return
		}
		d, loop, loaded := persistentLifecycleFixture(t, runtimeID)
		entered := make(chan *jsExecutionContext, 1)
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			return runtime.Bind("__persistentLoadEntered", func() {
				entered <- jsExecutionContextFor(loop)
			})
		}); err != nil {
			t.Fatal(err)
		}
		script := &JsScriptInfo{Name: "Infinite load", Enable: true, runtimeGeneration: jsContextGeneration(&jsExecutionContext{Script: loaded})}
		if !d.beginStartupJsLoad() {
			t.Fatal("startup load admission unexpectedly closed")
		}
		loadedDone := make(chan error, 1)
		go func() {
			defer d.finishStartupJsLoad()
			loadedDone <- d.loadJSScriptInRoot(loop, script, "infinite-load.js", []byte("__persistentLoadEntered(); while (true) {}"))
		}()
		realm := awaitPersistentLifecycle(t, entered, "actual infinite load to enter the VM")
		// Cancellation is a best-effort RED cleanup only; the subprocess
		// deadline also contains providers with no native interrupt support.
		t.Cleanup(func() { realm.binding.retire() })
		stopContext, cancelStop := context.WithTimeout(context.Background(), 2*time.Second)
		stopErr := d.StopJSRuntime(stopContext)
		cancelStop()
		if stopErr != nil {
			realm.binding.retire()
		}
		loadErr := awaitPersistentLifecycle(t, loadedDone, "cancelled infinite load to leave its owner")
		joinContext, cancelJoin := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelJoin()
		if err := d.StopJSRuntime(joinContext); err != nil {
			t.Fatalf("stop did not join after cancelling the load: %v", err)
		}
		if stopErr != nil {
			t.Fatalf("stop did not cancel the admitted infinite load: %v", stopErr)
		}
		if loadErr == nil {
			t.Fatal("cancelled infinite load reported success")
		}
	})
}

func TestJSPersistentLoadExecutionCancellationDoesNotCancelSuccessfulLoadIO(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		gate := newHostIOGate(t)
		extensionName := "Persistent load IO " + runtimeID
		source := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
fetch(%q).then(function (response) { return response.text(); }).then(function (text) {
  ext.storageSet("load-fetch", text);
});
`, runtimeID, extensionName, gate.server.URL)
		d, _, _, _, _ := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, source)
		gate.waitArrived(t)
		gate.open()
		waitPluginKV(t, d, extensionName, "load-fetch", "host-io-value")
	})
}

func TestJSPersistentBindingRetirementCancelsAndJoinsAdmittedRoot(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		d, loop, script := persistentLifecycleFixture(t, runtimeID)
		store, ok := d.DurableStore.(*eventstore.GORMStore)
		if !ok {
			t.Fatalf("durable store = %T, want real GORM store", d.DurableStore)
		}
		gate := &persistentRootAdmissionGate{GORMStore: store, entered: make(chan context.Context, 1), release: make(chan struct{})}
		d.DurableStore = gate
		t.Cleanup(gate.open)
		binding := script.currentPersistentBinding()
		origin := &jsExecutionContext{Dice: d, Script: script, PersistentBinding: true, binding: binding}
		if err := origin.PromotePersistentAsync(func() (jsengine.Value, error) {
			active := jsExecutionContextFor(loop)
			return active.activeRuntime.RunString("retired-root.js", `__persistentLifecycleExt.storageSet("retired-root", "must-not-commit")`)
		}); err != nil {
			t.Fatal(err)
		}
		rootContext := awaitPersistentLifecycle(t, gate.entered, "promoted root repository admission")
		retired := make(chan struct{})
		go func() {
			binding.retire()
			close(retired)
		}()
		returnedBeforeCancellation := false
		select {
		case <-rootContext.Done():
		case <-retired:
			returnedBeforeCancellation = true
		case <-time.After(5 * time.Second):
			gate.open()
			t.Fatal("binding retirement neither cancelled nor joined its admitted root")
		}
		if !returnedBeforeCancellation {
			select {
			case <-retired:
				t.Error("binding retired while its repository admission call was still running")
			default:
			}
		}
		gate.open()
		awaitPersistentLifecycle(t, retired, "binding retirement to join the admitted root")
		if returnedBeforeCancellation {
			t.Fatal("binding retirement returned without cancelling its admitted root")
		}
		if _, err := store.GetPluginKV(context.Background(), script.Name, "retired-root"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
			t.Fatalf("retired persistent root committed: %v", err)
		}
	})
}

func TestStopJSRuntimeCancelsAndJoinsPersistentRepositoryAdmission(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		d, loop, script := persistentLifecycleFixture(t, runtimeID)
		store, ok := d.DurableStore.(*eventstore.GORMStore)
		if !ok {
			t.Fatalf("durable store = %T, want real GORM store", d.DurableStore)
		}
		gate := &persistentRootAdmissionGate{GORMStore: store, entered: make(chan context.Context, 1), release: make(chan struct{})}
		d.DurableStore = gate
		t.Cleanup(gate.open)
		origin := &jsExecutionContext{Dice: d, Script: script, PersistentBinding: true, binding: script.currentPersistentBinding()}
		if err := origin.PromotePersistentAsync(func() (jsengine.Value, error) {
			active := jsExecutionContextFor(loop)
			return active.activeRuntime.RunString("stop-root.js", `__persistentLifecycleExt.storageSet("stopped-root", "must-not-commit")`)
		}); err != nil {
			t.Fatal(err)
		}
		rootContext := awaitPersistentLifecycle(t, gate.entered, "promoted root repository admission")
		stopped := make(chan error, 1)
		go func() { stopped <- d.StopJSRuntime(context.Background()) }()
		select {
		case <-rootContext.Done():
		case err := <-stopped:
			gate.open()
			t.Fatalf("runtime returned before cancelling its persistent root: %v", err)
		case <-time.After(5 * time.Second):
			gate.open()
			t.Fatal("runtime shutdown did not cancel the admitted persistent root")
		}
		select {
		case err := <-stopped:
			t.Errorf("runtime reported quiescence while repository admission was still running: %v", err)
		default:
		}
		gate.open()
		if err := awaitPersistentLifecycle(t, stopped, "runtime shutdown to join persistent roots"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestJSPersistentServiceRequestRootsDoNotBlockOtherRequests(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		d, loop, script := persistentLifecycleFixture(t, runtimeID)
		origin := &jsExecutionContext{Dice: d, Script: script, PersistentBinding: true, binding: script.currentPersistentBinding()}
		promoter, ok := any(origin).(interface {
			PromotePersistentAsyncRequest(request uint64, terminal bool, run func() (jsengine.Value, error)) error
		})
		if !ok {
			t.Fatal("persistent service completions have no request-owned scheduler")
		}
		firstStarted, secondRan := make(chan struct{}), make(chan struct{})
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			if err := runtime.Bind("__persistentFirstRequestStarted", func() { close(firstStarted) }); err != nil {
				return err
			}
			return runtime.Bind("__persistentSecondRequestRan", func() { close(secondRan) })
		}); err != nil {
			t.Fatal(err)
		}
		if err := promoter.PromotePersistentAsyncRequest(201, true, func() (jsengine.Value, error) {
			active := jsExecutionContextFor(loop)
			return active.activeRuntime.RunString("first-service-request.js", `(async function () {
  await new Promise(function (resolve) {
    globalThis.__persistentResolveFirstRequest = resolve;
    __persistentFirstRequestStarted();
  });
  __persistentLifecycleExt.storageSet("independent-request", "resumed");
})()`)
		}); err != nil {
			t.Fatal(err)
		}
		awaitPersistentLifecycle(t, firstStarted, "first actual service root to await a Promise")
		if err := promoter.PromotePersistentAsyncRequest(202, true, func() (jsengine.Value, error) {
			active := jsExecutionContextFor(loop)
			return active.activeRuntime.RunString("second-service-request.js", `__persistentResolveFirstRequest(); __persistentSecondRequestRan();`)
		}); err != nil {
			t.Fatal(err)
		}
		awaitPersistentLifecycle(t, secondRan, "independent service request to resolve the first root")
		waitPluginKV(t, d, script.Name, "independent-request", "resumed")
	})
}
