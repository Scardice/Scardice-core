package goja

import (
	"slices"
	"sync"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

type observedInvocation struct {
	phase   jsengine.InvocationPhase
	context any
}

type recordingObserver struct {
	mu        sync.Mutex
	events    []observedInvocation
	active    int
	maxActive int
}

func (o *recordingObserver) ObserveInvocation(context any, phase jsengine.InvocationPhase, run func() error) error {
	o.mu.Lock()
	o.active++
	o.maxActive = max(o.maxActive, o.active)
	o.events = append(o.events, observedInvocation{phase: phase, context: context})
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.active--
		o.mu.Unlock()
	}()
	return run()
}

func (o *recordingObserver) snapshot() ([]observedInvocation, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.events), o.maxActive
}

func (o *recordingObserver) phases() []jsengine.InvocationPhase {
	events, _ := o.snapshot()
	phases := make([]jsengine.InvocationPhase, len(events))
	for i, event := range events {
		phases[i] = event.phase
	}
	return phases
}

type observedContext struct{ name string }

func observedLoop(t *testing.T) (jsengine.Loop, *recordingObserver) {
	t.Helper()
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	observer := &recordingObserver{}
	if !jsengine.SetInvocationObserver(loop, observer) {
		t.Fatal("goja event loop must accept an invocation observer")
	}
	return loop, observer
}

func waitFor(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestObserverNamesEveryWayTheEngineEntersTheRealm(t *testing.T) {
	loop, observer := observedLoop(t)
	ctx := &observedContext{name: "plugin"}

	if err := jsengine.LoadEntryWithContext(loop, ctx, jsengine.Entry{Filename: "a.js", Source: "var loaded = 1", Kind: jsengine.EntryScript}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, ctx, func(jsengine.Runtime) error { return nil }); err != nil {
		t.Fatal(err)
	}
	scheduled := make(chan struct{})
	if err := jsengine.ScheduleWithContext(loop, ctx, func(jsengine.Runtime) error { close(scheduled); return nil }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, scheduled, "the scheduled callback")

	timerFired := make(chan struct{})
	if err := jsengine.RunWithContext(loop, ctx, func(rt jsengine.Runtime) error {
		vm, _ := Raw(rt)
		if err := vm.Set("timerFired", func() { close(timerFired) }); err != nil {
			return err
		}
		_, err := rt.RunString("timer.js", "setTimeout(function () { timerFired(); }, 1)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, timerFired, "the timer")

	events, _ := observer.snapshot()
	var phases []jsengine.InvocationPhase
	for _, event := range events {
		phases = append(phases, event.phase)
		if event.context != ctx {
			t.Fatalf("%s invocation carried context %v, want the caller's", event.phase, event.context)
		}
	}
	want := []jsengine.InvocationPhase{
		jsengine.InvocationLoad, jsengine.InvocationRun, jsengine.InvocationSchedule,
		jsengine.InvocationRun, jsengine.InvocationReaction,
	}
	if !slices.Equal(phases, want) {
		t.Fatalf("observed phases = %v, want %v", phases, want)
	}
}

func TestObservedWindowsNeverNest(t *testing.T) {
	loop, observer := observedLoop(t)
	ctx := &observedContext{name: "plugin"}

	continued := make(chan struct{})
	if err := jsengine.RunWithContext(loop, ctx, func(rt jsengine.Runtime) error {
		vm, _ := Raw(rt)
		if err := vm.Set("continued", func() { close(continued) }); err != nil {
			return err
		}
		_, err := rt.RunString("chain.js", `Promise.resolve().then(function () { return 1; }).then(function () { setImmediate(function () { continued(); }); })`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, continued, "the Promise chain")

	events, maxActive := observer.snapshot()
	if maxActive != 1 {
		t.Fatalf("observed windows nested (max depth %d): a continuation drained inside a callback must stay in its window", maxActive)
	}
	if runs := slices.DeleteFunc(slices.Clone(observer.phases()), func(p jsengine.InvocationPhase) bool { return p != jsengine.InvocationRun }); len(runs) != 1 {
		t.Fatalf("observed %d run invocations among %v, want exactly 1", len(runs), observer.phases())
	}
	for _, event := range events {
		if event.phase != jsengine.InvocationRun && event.phase != jsengine.InvocationReaction {
			t.Fatalf("unexpected phase %s in %v", event.phase, observer.phases())
		}
	}
}

func TestObserverSurvivesPanickingCallbacks(t *testing.T) {
	loop, observer := observedLoop(t)
	ctx := &observedContext{name: "plugin"}

	if err := jsengine.RunWithContext(loop, ctx, func(jsengine.Runtime) error { panic("boom") }); err == nil {
		t.Fatal("a panicking callback must report an error")
	}
	if err := jsengine.RunWithContext(loop, ctx, func(jsengine.Runtime) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := observer.phases(); !slices.Equal(got, []jsengine.InvocationPhase{jsengine.InvocationRun, jsengine.InvocationRun}) {
		t.Fatalf("observed phases = %v: a panic must not leave the loop looking busy", got)
	}
}

func TestObserverCanBeDetachedAndIsolatedRealmsCannotHaveOne(t *testing.T) {
	loop, observer := observedLoop(t)
	ctx := &observedContext{name: "plugin"}
	if !jsengine.SetInvocationObserver(loop, nil) {
		t.Fatal("detaching must be accepted")
	}
	if err := jsengine.RunWithContext(loop, ctx, func(jsengine.Runtime) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := observer.phases(); len(got) != 0 {
		t.Fatalf("a detached observer still saw %v", got)
	}

	isolated := New()
	defer isolated.Close()
	if jsengine.SetInvocationObserver(isolated, observer) {
		t.Fatal("an isolated realm has no event loop and must report that it cannot be observed")
	}
}
