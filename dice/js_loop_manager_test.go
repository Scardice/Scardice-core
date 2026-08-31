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
