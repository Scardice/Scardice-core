package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/dice/jsengine"
)

type mockScriptEngine struct {
	requireCalled  bool
	requiredModule string
	requireErr     error
}

func (m *mockScriptEngine) Name() jsengine.EngineName { return jsengine.EngineQuickJS }
func (m *mockScriptEngine) Init(context.Context, jsengine.Config) error {
	return nil
}
func (m *mockScriptEngine) Dispose() error { return nil }
func (m *mockScriptEngine) Eval(string) error {
	return nil
}
func (m *mockScriptEngine) Require(moduleID string) error {
	m.requireCalled = true
	m.requiredModule = moduleID
	return m.requireErr
}
func (m *mockScriptEngine) RegisterHostAPI(jsengine.HostAPI) error { return nil }
func (m *mockScriptEngine) Reset() error                           { return nil }

func TestJsRequireModuleUsesScriptEngineWhenQuickJSEffective(t *testing.T) {
	engine := &mockScriptEngine{}
	d := &Dice{
		JsEngineEffective: "quickjs",
		ScriptEngine:      engine,
	}

	err := d.jsRequireModule("./data/test.js")
	if err != nil {
		t.Fatalf("jsRequireModule 返回错误: %v", err)
	}
	if !engine.requireCalled {
		t.Fatal("未调用 ScriptEngine.Require")
	}
	if engine.requiredModule != "./data/test.js" {
		t.Fatalf("Require 参数不正确: %s", engine.requiredModule)
	}
}

func TestJsRequireModulePropagatesScriptEngineError(t *testing.T) {
	engine := &mockScriptEngine{requireErr: errors.New("require failed")}
	d := &Dice{
		JsEngineEffective: "quickjs",
		ScriptEngine:      engine,
	}

	err := d.jsRequireModule("./data/test.js")
	if err == nil {
		t.Fatal("预期返回错误，但得到 nil")
	}
	if err.Error() != "require failed" {
		t.Fatalf("错误信息不匹配: %v", err)
	}
}
