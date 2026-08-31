package dice

import (
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/quickjs"
)

func TestJsLoopManagerStoresEngineLoopByVersion(t *testing.T) {
	manager := NewJsLoopManager()
	loop, err := quickjs.New()
	if err != nil {
		t.Fatalf("quickjs.New() error = %v", err)
	}
	defer loop.Close()

	version := manager.SetLoop(loop)
	got, err := manager.GetLoop(version)
	if err != nil {
		t.Fatalf("GetLoop() error = %v", err)
	}
	if got != loop {
		t.Fatal("GetLoop() returned a different loop")
	}
	if got.Engine() != jsengine.EngineQuickJS {
		t.Fatalf("GetLoop().Engine() = %q, want %q", got.Engine(), jsengine.EngineQuickJS)
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
