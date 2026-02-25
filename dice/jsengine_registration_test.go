package dice

import (
	"testing"

	"Scardice-core/dice/jsengine"
)

func TestQuickJSEngineRegisteredInRuntime(t *testing.T) {
	engine, err := jsengine.New(jsengine.Config{Name: jsengine.EngineQuickJS})
	if err != nil {
		t.Fatalf("QuickJS 引擎未注册到运行时: %v", err)
	}
	if engine == nil {
		t.Fatal("QuickJS 引擎创建结果为 nil")
	}
}
