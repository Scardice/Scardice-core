package jsengine_test

import (
	"testing"

	"Scardice-core/dice/jsengine"
	_ "Scardice-core/dice/jsengine/quickjs"
)

func TestNewFactoryQuickJS(t *testing.T) {
	engine, err := jsengine.New(jsengine.Config{Name: jsengine.EngineQuickJS})
	if err != nil {
		t.Fatalf("创建 QuickJS 引擎失败: %v", err)
	}
	if engine == nil {
		t.Fatal("创建 QuickJS 引擎返回 nil")
	}
	if engine.Name() != jsengine.EngineQuickJS {
		t.Fatalf("引擎类型错误: got=%s want=%s", engine.Name(), jsengine.EngineQuickJS)
	}
}

func TestNewFactoryUnsupportedEngine(t *testing.T) {
	engine, err := jsengine.New(jsengine.Config{Name: jsengine.EngineGoja})
	if err == nil {
		t.Fatal("不支持的引擎类型应返回错误")
	}
	if engine != nil {
		t.Fatal("不支持的引擎类型不应返回实例")
	}

	ee, ok := err.(*jsengine.EngineError)
	if !ok {
		t.Fatalf("错误类型不正确: %T", err)
	}
	if ee.Kind != jsengine.ErrInit {
		t.Fatalf("错误分类不正确: got=%s want=%s", ee.Kind, jsengine.ErrInit)
	}
}
