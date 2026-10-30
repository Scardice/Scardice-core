package dice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/utils/jsengine"
)

type shutdownGateLoop struct {
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeDone    chan struct{}
	startOnce    sync.Once
	doneOnce     sync.Once
	closeCalls   atomic.Int64
}

func newShutdownGateLoop() *shutdownGateLoop {
	return &shutdownGateLoop{
		closeStarted: make(chan struct{}),
		closeRelease: make(chan struct{}),
		closeDone:    make(chan struct{}),
	}
}

func (l *shutdownGateLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *shutdownGateLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineGoja}
}

func (l *shutdownGateLoop) Run(run func(jsengine.Runtime) error) error {
	return run(nil)
}

func (l *shutdownGateLoop) LoadEntry(jsengine.Entry) error { return nil }

func (l *shutdownGateLoop) Close() error {
	l.closeCalls.Add(1)
	l.startOnce.Do(func() { close(l.closeStarted) })
	<-l.closeRelease
	l.doneOnce.Do(func() { close(l.closeDone) })
	return nil
}

type shutdownCountingLoop struct {
	closeCalls atomic.Int64
}

func (l *shutdownCountingLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *shutdownCountingLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineGoja}
}

func (l *shutdownCountingLoop) Run(run func(jsengine.Runtime) error) error {
	return run(nil)
}

func (l *shutdownCountingLoop) LoadEntry(jsengine.Entry) error { return nil }

func (l *shutdownCountingLoop) Close() error {
	l.closeCalls.Add(1)
	return nil
}

type startupProviderCall struct{}

func (startupProviderCall) CallAPI(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
	return adapterapi.AdapterCallResult{}, nil
}

func waitJSShutdownTestClosed(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestStopJSRuntimeConcurrentCallJoinsInFlightStop(t *testing.T) {
	loop := newShutdownGateLoop()
	d := &Dice{ExtLoopManager: NewJsLoopManager()}
	d.ExtLoopManager.SetLoop(loop)

	firstDone := make(chan struct{})
	go func() {
		_ = d.StopJSRuntime(context.Background())
		close(firstDone)
	}()
	waitJSShutdownTestClosed(t, loop.closeStarted, "first JS stop to enter loop close")

	secondCalled := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		close(secondCalled)
		_ = d.StopJSRuntime(context.Background())
		close(secondDone)
	}()
	<-secondCalled
	secondReturnedEarly := false
	select {
	case <-secondDone:
		secondReturnedEarly = true
	case <-time.After(20 * time.Millisecond):
	}

	close(loop.closeRelease)
	waitJSShutdownTestClosed(t, firstDone, "first JS stop completion")
	waitJSShutdownTestClosed(t, secondDone, "second JS stop completion")
	waitJSShutdownTestClosed(t, loop.closeDone, "JS loop close completion")

	if secondReturnedEarly {
		t.Fatal("concurrent JS stop returned before the in-flight stop completed")
	}
	if calls := loop.closeCalls.Load(); calls != 1 {
		t.Fatalf("JS loop close calls = %d, want 1", calls)
	}
}

func TestStopJSRuntimeWaitsForAdmittedStartupLoad(t *testing.T) {
	d := &Dice{ExtLoopManager: NewJsLoopManager()}
	d.beginStartupJsLoad()

	stopCalled := make(chan struct{})
	stopDone := make(chan struct{})
	go func() {
		close(stopCalled)
		_ = d.StopJSRuntime(context.Background())
		close(stopDone)
	}()
	<-stopCalled
	returnedBeforeLoadFinished := false
	select {
	case <-stopDone:
		returnedBeforeLoadFinished = true
	case <-time.After(20 * time.Millisecond):
	}

	d.finishStartupJsLoad()
	waitJSShutdownTestClosed(t, stopDone, "JS stop after startup load completion")
	if returnedBeforeLoadFinished {
		t.Fatal("JS stop returned while an admitted startup load could still publish callbacks")
	}
}

func TestStopJSRuntimeRejectsLateLoopAdmission(t *testing.T) {
	manager := NewJsLoopManager()
	d := &Dice{ExtLoopManager: manager}
	if err := d.StopJSRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}

	late := &shutdownCountingLoop{}
	manager.AddLoop(late)
	current, _ := manager.CurrentLoop()
	closedBeforeCleanup := late.closeCalls.Load()
	manager.SetLoop(nil)

	if current != nil {
		t.Fatal("late runtime load revived the JS loop after process stop")
	}
	if closedBeforeCleanup != 1 {
		t.Fatalf("late runtime close calls before cleanup = %d, want 1", closedBeforeCleanup)
	}
}

func TestStopJSRuntimeTimeoutsReuseSingleClose(t *testing.T) {
	loop := newShutdownGateLoop()
	d := &Dice{ExtLoopManager: NewJsLoopManager()}
	d.ExtLoopManager.SetLoop(loop)

	firstCtx, firstCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer firstCancel()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- d.StopJSRuntime(firstCtx)
	}()
	waitJSShutdownTestClosed(t, loop.closeStarted, "timed JS stop to enter loop close")
	if err := <-firstDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first stop error = %v, want deadline exceeded", err)
	}

	for range 3 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := d.StopJSRuntime(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("repeated stop error = %v, want canceled", err)
		}
	}
	if calls := loop.closeCalls.Load(); calls != 1 {
		t.Fatalf("JS loop close calls during repeated timeouts = %d, want 1", calls)
	}

	close(loop.closeRelease)
	waitJSShutdownTestClosed(t, loop.closeDone, "shared JS close completion")
	if err := d.StopJSRuntime(context.Background()); err != nil {
		t.Fatalf("completed shared stop error = %v", err)
	}
}

func TestStartupJSLoadRemainsImmediateWithoutProductionDeferral(t *testing.T) {
	d := &Dice{}
	var calls atomic.Int64

	d.startStartupJsLoad(func() { calls.Add(1) })
	d.WaitStartupJsLoaded()

	if got := calls.Load(); got != 1 {
		t.Fatalf("startup load completion calls = %d, want 1", got)
	}
}

func TestDeferredStartupJSLoadWaitsForProductionReleaseAndStartsOnce(t *testing.T) {
	d := &Dice{}
	manager := &DiceManager{Dice: []*Dice{d}}
	if err := manager.DeferStartupJSLoad(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	portsReady := make(chan bool, 1)

	d.startStartupJsLoad(func() {
		calls.Add(1)
		portsReady <- d.OutboundBridge != nil && d.ProviderCall != nil
	})
	if got := calls.Load(); got != 0 {
		t.Fatalf("deferred startup load ran before production release: calls=%d", got)
	}

	d.OutboundBridge = NewFailClosedOutboundBridge()
	d.ProviderCall = startupProviderCall{}
	manager.StartDeferredStartupJSLoad()
	d.WaitStartupJsLoaded()
	if got := calls.Load(); got != 1 {
		t.Fatalf("startup load completion calls after release = %d, want 1", got)
	}
	if ready := <-portsReady; !ready {
		t.Fatal("startup evaluation did not observe published adapter ports")
	}

	manager.StartDeferredStartupJSLoad()
	if got := calls.Load(); got != 1 {
		t.Fatalf("repeated production release restarted startup load: calls=%d", got)
	}
}

func TestStopJSRuntimeCancelsDeferredStartupJSLoad(t *testing.T) {
	d := &Dice{}
	manager := &DiceManager{Dice: []*Dice{d}}
	if err := manager.DeferStartupJSLoad(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	d.startStartupJsLoad(func() { calls.Add(1) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.StopJSRuntime(ctx); err != nil {
		t.Fatalf("stop deferred JS runtime: %v", err)
	}

	manager.StartDeferredStartupJSLoad()
	d.WaitStartupJsLoaded()
	if got := calls.Load(); got != 0 {
		t.Fatalf("canceled startup load published effects: calls=%d", got)
	}
}
