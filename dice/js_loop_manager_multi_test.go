package dice

import (
	"testing"

	"Scardice-core/utils/jsengine"
)

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
