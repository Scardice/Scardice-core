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

	version := manager.SetEngineLoop(loop)
	got, err := manager.GetEngineLoop(version)
	if err != nil {
		t.Fatalf("GetEngineLoop() error = %v", err)
	}
	if got != loop {
		t.Fatal("GetEngineLoop() returned a different loop")
	}
	if got.Engine() != jsengine.EngineQuickJS {
		t.Fatalf("GetEngineLoop().Engine() = %q, want %q", got.Engine(), jsengine.EngineQuickJS)
	}
}
