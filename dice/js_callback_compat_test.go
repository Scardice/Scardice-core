package dice

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestJSCallbackDispatchRejectsStaleGeneration(t *testing.T) {
	manager := NewJsLoopManager()
	first := gojaengine.New()
	firstVersion := manager.SetLoop(first)
	second := gojaengine.New()
	manager.SetLoop(second)
	called := false
	err := manager.dispatchJSCallback(jsCallbackRequest{
		Generation: firstVersion,
		Realm:      "plugin-a",
		Kind:       jsCallbackMessage,
		Callback:   func() { called = true },
	}, false)
	if !errors.Is(err, errJSCallbackStaleGeneration) || called {
		t.Fatalf("stale callback err=%v called=%v", err, called)
	}
}
func TestJSCallbackDispatchSuppressesReplayContext(t *testing.T) {
	manager := NewJsLoopManager()
	generation := manager.SetLoop(gojaengine.New())
	called := false
	err := manager.dispatchJSCallback(jsCallbackRequest{
		Generation: generation,
		Realm:      &jsExecutionContext{CompatibilityMode: JSCompatibilityReplay},
		Kind:       jsCallbackMessage,
		Callback:   func() { called = true },
	}, false)
	if !errors.Is(err, ErrJSCompatibilityReplaySuppressed) || called {
		t.Fatalf("replay callback err=%v called=%v", err, called)
	}
}

func TestJSCallbackDispatchRejectsWrongRealm(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	called := false
	if err := jsengine.RunWithContext(loop, "plugin-b", func(jsengine.Runtime) error {
		return manager.dispatchJSCallback(jsCallbackRequest{
			Generation: generation,
			Realm:      "plugin-a",
			Kind:       jsCallbackMessage,
			Callback:   func() { called = true },
		}, false)
	}); !errors.Is(err, errJSCallbackWrongRealm) {
		t.Fatalf("wrong realm err=%v", err)
	}
	if called {
		t.Fatal("wrong realm callback executed")
	}
}

func TestJSCallbackDispatchDeduplicatesOnlyWithinGeneration(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	var calls atomic.Int64
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	request := jsCallbackRequest{
		Generation:       generation,
		Realm:            "plugin-a",
		Kind:             jsCallbackMessage,
		ProviderEventID:  "event-1",
		CallbackIdentity: "plugin-a:message",
		Callback: func() {
			started <- struct{}{}
			<-release
			calls.Add(1)
		},
	}
	if err := manager.dispatchJSCallback(request, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduled callback did not start")
	}
	if err := manager.dispatchJSCallback(request, true); !errors.Is(err, errJSCallbackDuplicate) {
		t.Fatalf("duplicate err=%v", err)
	}
	close(release)
	waitForCallbackCount(t, &calls, 1)
	if err := manager.dispatchJSCallback(request, true); err != nil {
		t.Fatalf("reschedule after completion: %v", err)
	}
	waitForCallbackCount(t, &calls, 2)
	select {
	case <-started:
	default:
	}
	second := gojaengine.WrapEventLoop(startFsTestLoop(t))
	secondGeneration := manager.SetLoop(second)
	request.Generation = secondGeneration
	if err := manager.dispatchJSCallback(request, true); err != nil {
		t.Fatal(err)
	}
	waitForCallbackCount(t, &calls, 3)
}

func TestJSCallbackDispatchSynchronousReentryDoesNotDeadlock(t *testing.T) {
	manager := NewJsLoopManager()

	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	called := make(chan struct{}, 1)
	if err := jsengine.RunWithContext(loop, "plugin-a", func(jsengine.Runtime) error {
		return manager.dispatchJSCallback(jsCallbackRequest{
			Generation: generation,
			Realm:      "plugin-a",
			Kind:       jsCallbackCommand,
			Callback:   func() { called <- struct{}{} },
		}, false)
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("same-realm callback did not return")
	}
}
func TestJSCallbackDispatchBusyLoopDoesNotMisclassifyExternalCaller(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	busyStarted := make(chan struct{})
	releaseBusy := make(chan struct{})
	busyDone := make(chan error, 1)
	go func() {
		busyDone <- jsengine.RunWithContext(loop, "plugin-b", func(jsengine.Runtime) error {
			close(busyStarted)
			<-releaseBusy
			return nil
		})
	}()
	select {
	case <-busyStarted:
	case <-time.After(time.Second):
		t.Fatal("busy realm callback did not start")
	}
	called := make(chan struct{}, 1)
	dispatchDone := make(chan error, 1)
	go func() {
		dispatchDone <- manager.dispatchJSCallback(jsCallbackRequest{
			Generation: generation,
			Realm:      "plugin-a",
			Kind:       jsCallbackMessage,
			Callback:   func() { called <- struct{}{} },
		}, false)
	}()
	select {
	case err := <-dispatchDone:
		t.Fatalf("external dispatch returned while owner was busy: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseBusy)
	if err := <-busyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-dispatchDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("external callback did not execute after busy realm returned")
	}
}
func TestJSCallbackDispatchOwnerNilContextRejectsNonNilRealm(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	called := false
	if err := jsengine.RunWithContext(loop, nil, func(jsengine.Runtime) error {
		return manager.dispatchJSCallback(jsCallbackRequest{
			Generation: generation,
			Realm:      "plugin-a",
			Kind:       jsCallbackMessage,
			Callback:   func() { called = true },
		}, false)
	}); !errors.Is(err, errJSCallbackWrongRealm) {
		t.Fatalf("owner nil-context realm err=%v", err)
	}
	if called {
		t.Fatal("owner nil-context callback executed")
	}
}

func TestJSCallbackDispatchFromTimerAndPromiseReentry(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	var calls atomic.Int64
	errs := make(chan error, 2)
	if err := jsengine.RunWithContext(loop, "plugin-a", func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("dispatchCompatCallback", func() {
			err := manager.dispatchJSCallback(jsCallbackRequest{
				Generation: generation,
				Realm:      "plugin-a",
				Kind:       jsCallbackMessage,
				Callback:   func() { calls.Add(1) },
			}, false)
			if err != nil {
				errs <- err
			}
		}); err != nil {
			return err
		}
		_, err := runtime.RunString("reentry.js", `
			setTimeout(dispatchCompatCallback, 0);
			Promise.resolve().then(dispatchCompatCallback);
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waitForCallbackCount(t, &calls, 2)
	select {
	case err := <-errs:
		t.Fatalf("timer/promise reentry error: %v", err)
	default:
	}
}


func TestJSCallbackDispatchObservesAsyncCallbackError(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	observed := make(chan error, 1)
	if err := manager.dispatchJSCallback(jsCallbackRequest{
		Generation:       generation,
		Realm:            "plugin-a",
		Kind:             jsCallbackMessage,
		Callback:         func() { panic("callback failure") },
		OnError:          func(err error) { observed <- err },
	}, true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-observed:
		if err == nil {
			t.Fatal("async callback error was nil")
		}
	case <-time.After(time.Second):
		t.Fatal("async callback error was not observed")
	}
}

func TestJSCallbackDispatchNamespacesProviderEventsByEndpoint(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	msg := &Message{RawID: "event-1"}
	ctxA := &MsgContext{EndPoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: "endpoint-a"}}}
	ctxB := &MsgContext{EndPoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: "endpoint-b"}}}
	if callbackEventIDForMessage(ctxA, msg) == callbackEventIDForMessage(ctxB, msg) {
		t.Fatal("provider event IDs from distinct endpoints collided")
	}
	var calls atomic.Int64
	for _, ctx := range []*MsgContext{ctxA, ctxB} {
		if err := manager.dispatchJSCallback(jsCallbackRequest{
			Generation:       generation,
			Realm:            "plugin-a",
			Kind:             jsCallbackMessage,
			ProviderEventID:  callbackEventIDForMessage(ctx, msg),
			CallbackIdentity: "plugin-a:message",
			Callback:         func() { calls.Add(1) },
		}, true); err != nil {
			t.Fatal(err)
		}
	}
	waitForCallbackCount(t, &calls, 2)
}
func TestJSCallbackDispatchPreservesCallbackOrder(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	var order []jsCallbackKind
	for _, kind := range []jsCallbackKind{
		jsCallbackPreprocess, jsCallbackMessage, jsCallbackCommand,
		jsCallbackGroup, jsCallbackMember, jsCallbackActivation,
	} {
		kind := kind
		if err := manager.dispatchJSCallback(jsCallbackRequest{
			Generation: generation,
			Realm:      "plugin-a",
			Kind:       kind,
			Callback:   func() { order = append(order, kind) },
		}, false); err != nil {
			t.Fatalf("dispatch %s: %v", kind, err)
		}
	}
	want := []jsCallbackKind{
		jsCallbackPreprocess, jsCallbackMessage, jsCallbackCommand,
		jsCallbackGroup, jsCallbackMember, jsCallbackActivation,
	}
	if len(order) != len(want) {
		t.Fatalf("callback order=%v want=%v", order, want)
	}
	for index := range want {
		if order[index] != want[index] {
			t.Fatalf("callback order=%v want=%v", order, want)
		}
	}
}

func waitForCallbackCount(t *testing.T, calls *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.After(time.Second)
	for calls.Load() < want {
		select {
		case <-deadline:
			t.Fatalf("callback count=%d want=%d", calls.Load(), want)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
