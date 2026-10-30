package dice

import (
	"sync"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestJsLoopManagerStoresEngineLoopByVersion(t *testing.T) {
	manager := NewJsLoopManager()
	loop := gojaengine.New()
	defer loop.Close()

	version := manager.SetLoop(loop)
	got, err := manager.GetLoop(version)
	if err != nil {
		t.Fatalf("GetLoop() error = %v", err)
	}
	if got != loop {
		t.Fatal("GetLoop() returned a different loop")
	}
	if got.Engine() != jsengine.EngineGoja {
		t.Fatalf("GetLoop().Engine() = %q, want %q", got.Engine(), jsengine.EngineGoja)
	}
}

type closeCountingLoop struct {
	closeCount int
}

func (l *closeCountingLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }
func (l *closeCountingLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineGoja}
}
func (l *closeCountingLoop) Run(fn func(jsengine.Runtime) error) error {
	return fn(nil)
}
func (l *closeCountingLoop) LoadEntry(jsengine.Entry) error { return nil }
func (l *closeCountingLoop) Close() error {
	l.closeCount++
	return nil
}

type shutdownOrderingLoop struct {
	closeCountingLoop
	closed chan struct{}
}

func (l *shutdownOrderingLoop) Close() error {
	close(l.closed)
	return nil
}

func TestJsLoopManagerStopsCronJobsBeforeClosingRuntime(t *testing.T) {
	d := &Dice{ExtLoopManager: NewJsLoopManager()}
	d.startJSScriptCron()
	defer d.stopJSScriptCron()

	hookEntered := make(chan struct{})
	d.ExtLoopManager.SetShutdownHook(func() {
		close(hookEntered)
		d.stopJSScriptCron()
	})
	loop := &shutdownOrderingLoop{closed: make(chan struct{})}
	d.ExtLoopManager.SetLoop(loop)

	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	task := JsScriptTask{
		taskType: "cron",
		cron:     d.JsScriptCron,
		cronExpr: "@every 1ms",
		lock:     d.JsScriptCronLock,
		task: func(JsScriptTaskCtx) {
			startedOnce.Do(func() { close(started) })
			<-release
		},
	}
	if !task.On() {
		t.Fatal("register blocking JS cron task")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("JS cron task did not start")
	}

	shutdownDone := make(chan struct{})
	go func() {
		d.ExtLoopManager.SetLoop(nil)
		close(shutdownDone)
	}()
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime shutdown did not reach the cron stop boundary")
	}
	select {
	case <-loop.closed:
		t.Fatal("runtime loop closed before the in-flight cron task completed")
	default:
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime shutdown did not complete after the cron task returned")
	}
	select {
	case <-loop.closed:
	default:
		t.Fatal("runtime loop remained open after cron shutdown completed")
	}
}

func TestJsLoopManagerRejectsStaleGenerationAndClosesReplacedLoopOnce(t *testing.T) {
	manager := NewJsLoopManager()
	first := &closeCountingLoop{}
	version := manager.SetLoop(first)
	if _, err := manager.GetLoop(version - 1); err == nil {
		t.Fatal("GetLoop accepted a stale generation")
	}
	if got, err := manager.GetLoop(version); err != nil || got != first {
		t.Fatalf("GetLoop(current) = %v, %v", got, err)
	}

	manager.SetLoop(first)
	if first.closeCount != 0 {
		t.Fatalf("same loop was closed during replacement: %d", first.closeCount)
	}
	second := &closeCountingLoop{}
	manager.SetLoop(second)
	if first.closeCount != 1 {
		t.Fatalf("first loop close count = %d, want 1", first.closeCount)
	}
	manager.SetLoop(nil)
	if second.closeCount != 1 {
		t.Fatalf("second loop close count = %d, want 1", second.closeCount)
	}
}

type multiRuntimeTestLoop struct {
	engine     jsengine.EngineID
	closeCount int
}

func (l *multiRuntimeTestLoop) Engine() jsengine.EngineID { return l.engine }
func (l *multiRuntimeTestLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: l.engine}
}
func (l *multiRuntimeTestLoop) Run(fn func(jsengine.Runtime) error) error { return fn(nil) }
func (l *multiRuntimeTestLoop) LoadEntry(jsengine.Entry) error            { return nil }
func (l *multiRuntimeTestLoop) Close() error {
	l.closeCount++
	return nil
}

func TestJsLoopManagerRetainsScriptLoopsByEngine(t *testing.T) {
	manager := NewJsLoopManager()
	gojaLoop := &multiRuntimeTestLoop{engine: jsengine.EngineGoja}
	quickjsLoop := &multiRuntimeTestLoop{engine: "quickjs"}
	defaultVersion := manager.SetLoop(gojaLoop)
	quickjsVersion := manager.AddLoop(quickjsLoop)

	if got, version := manager.CurrentLoop(); got != gojaLoop || version != defaultVersion {
		t.Fatalf("CurrentLoop() = %v, %d; want Goja default", got, version)
	}
	if got, version := manager.LoopForEngine("quickjs"); got != quickjsLoop || version != quickjsVersion {
		t.Fatalf("LoopForEngine(quickjs) = %v, %d", got, version)
	}
	if got, err := manager.GetLoop(quickjsVersion); err != nil || got != quickjsLoop {
		t.Fatalf("GetLoop(quickjs) = %v, %v", got, err)
	}

	sameRuntimeLoop := &multiRuntimeTestLoop{engine: "quickjs"}
	if got := manager.AddLoop(sameRuntimeLoop); got != quickjsVersion {
		t.Fatalf("same-runtime generation = %d, want %d", got, quickjsVersion)
	}
	if sameRuntimeLoop.closeCount != 1 {
		t.Fatalf("duplicate same-runtime loop close count = %d, want 1", sameRuntimeLoop.closeCount)
	}

	manager.SetLoop(nil)
	if gojaLoop.closeCount != 1 || quickjsLoop.closeCount != 1 {
		t.Fatalf("close counts = Goja:%d QuickJS:%d", gojaLoop.closeCount, quickjsLoop.closeCount)
	}
}

func TestJsLoopManagerRebuildsEngineIndexAfterReload(t *testing.T) {
	manager := NewJsLoopManager()
	first := &multiRuntimeTestLoop{engine: "quickjs"}
	firstVersion := manager.AddLoop(first)

	manager.SetLoop(nil)
	if first.closeCount != 1 {
		t.Fatalf("first loop close count = %d, want 1", first.closeCount)
	}

	replacement := &multiRuntimeTestLoop{engine: "quickjs"}
	replacementVersion := manager.AddLoop(replacement)
	if replacementVersion == firstVersion {
		t.Fatalf("replacement generation reused stale version %d", replacementVersion)
	}
	if got, version := manager.LoopForEngine("quickjs"); got != replacement || version != replacementVersion {
		t.Fatalf("LoopForEngine(quickjs) = %v, %d; want replacement", got, version)
	}

	manager.SetLoop(nil)
	if replacement.closeCount != 1 {
		t.Fatalf("replacement loop close count = %d, want 1", replacement.closeCount)
	}
}
