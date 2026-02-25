package quickjs

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/dice/jsengine"
)

type fakeBackend struct {
	evalErr    error
	requireErr error
	resetErr   error
	apis       []string
}

func (f *fakeBackend) Dispose() error      { return nil }
func (f *fakeBackend) Eval(_ string) error { return f.evalErr }
func (f *fakeBackend) EvalWithResult(_ string) (any, error) {
	return "ok", f.evalErr
}
func (f *fakeBackend) Require(_ string) error { return f.requireErr }
func (f *fakeBackend) RegisterHostAPI(api jsengine.HostAPI) error {
	f.apis = append(f.apis, api.Name)
	return nil
}
func (f *fakeBackend) Reset() error { return f.resetErr }
func (f *fakeBackend) InvokeStoredSolve(_ string, _ string, _ map[string]any) (map[string]any, error) {
	return map[string]any{"matched": true, "solved": true}, nil
}
func (f *fakeBackend) InvokeStoredOnNotCommand(_ string, _ map[string]any) error { return nil }
func (f *fakeBackend) InvokeStoredTask(_ string, _ map[string]any) error         { return nil }

func TestAdapterLifecycle(t *testing.T) {
	oldFactory := newRuntimeBackend
	newRuntimeBackend = func(_ jsengine.Config, _ Options) (runtimeBackend, error) {
		return &fakeBackend{}, nil
	}
	defer func() {
		newRuntimeBackend = oldFactory
	}()

	a := NewAdapter()
	if a.Name() != jsengine.EngineQuickJS {
		t.Fatalf("引擎名称错误: got=%s want=%s", a.Name(), jsengine.EngineQuickJS)
	}

	if err := a.Init(context.Background(), jsengine.Config{Name: jsengine.EngineQuickJS}); err != nil {
		t.Fatalf("Init 失败: %v", err)
	}

	if err := a.Dispose(); err != nil {
		t.Fatalf("Dispose 失败: %v", err)
	}
	// 重复释放应幂等
	if err := a.Dispose(); err != nil {
		t.Fatalf("重复 Dispose 不应失败: %v", err)
	}
}

func TestAdapterEvalRequireResetSemantics(t *testing.T) {
	oldFactory := newRuntimeBackend
	newRuntimeBackend = func(_ jsengine.Config, _ Options) (runtimeBackend, error) {
		return &fakeBackend{}, nil
	}
	defer func() {
		newRuntimeBackend = oldFactory
	}()

	a := NewAdapter()

	// 未初始化前，核心执行能力应返回对应类别错误
	if err := a.Eval("1+1"); err == nil {
		t.Fatal("未初始化时 Eval 应失败")
	} else {
		ee, ok := err.(*jsengine.EngineError)
		if !ok || ee.Kind != jsengine.ErrEval {
			t.Fatalf("Eval 错误类型不正确: %T %v", err, err)
		}
	}

	if err := a.Require("./mod.js"); err == nil {
		t.Fatal("未初始化时 Require 应失败")
	} else {
		ee, ok := err.(*jsengine.EngineError)
		if !ok || ee.Kind != jsengine.ErrModule {
			t.Fatalf("Require 错误类型不正确: %T %v", err, err)
		}
	}

	if err := a.Reset(); err == nil {
		t.Fatal("未初始化时 Reset 应失败")
	} else {
		ee, ok := err.(*jsengine.EngineError)
		if !ok || ee.Kind != jsengine.ErrRuntime {
			t.Fatalf("Reset 错误类型不正确: %T %v", err, err)
		}
	}

	if err := a.Init(context.Background(), jsengine.Config{Name: jsengine.EngineQuickJS}); err != nil {
		t.Fatalf("Init 失败: %v", err)
	}
	if err := a.Eval("1+1"); err != nil {
		t.Fatalf("后端可用时 Eval 不应失败: %v", err)
	}

	if err := a.Require("./mod.js"); err != nil {
		t.Fatalf("后端可用时 Require 不应失败: %v", err)
	}

	if err := a.Reset(); err != nil {
		t.Fatalf("后端可用时 Reset 不应失败: %v", err)
	}
}

func TestAdapterRegisterHostAPI(t *testing.T) {
	oldFactory := newRuntimeBackend
	b := &fakeBackend{}
	newRuntimeBackend = func(_ jsengine.Config, _ Options) (runtimeBackend, error) {
		return b, nil
	}
	defer func() {
		newRuntimeBackend = oldFactory
	}()

	a := NewAdapter()
	if err := a.RegisterHostAPI(jsengine.HostAPI{Name: "test", Handler: func() {}}); err != nil {
		t.Fatalf("注册 HostAPI 失败: %v", err)
	}
	if err := a.Init(context.Background(), jsengine.Config{Name: jsengine.EngineQuickJS}); err != nil {
		t.Fatalf("Init 失败: %v", err)
	}
	if len(b.apis) != 1 || b.apis[0] != "test" {
		t.Fatalf("Init 时未注入预注册 API: %+v", b.apis)
	}

	if err := a.RegisterHostAPI(jsengine.HostAPI{Name: "test2", Handler: func() {}}); err != nil {
		t.Fatalf("运行期注册 HostAPI 失败: %v", err)
	}
	if len(b.apis) != 2 || b.apis[1] != "test2" {
		t.Fatalf("运行期未向后端注入 API: %+v", b.apis)
	}
}

func TestAdapterInitFailWhenBackendMissing(t *testing.T) {
	oldFactory := newRuntimeBackend
	newRuntimeBackend = func(_ jsengine.Config, _ Options) (runtimeBackend, error) {
		return nil, errors.New("missing")
	}
	defer func() {
		newRuntimeBackend = oldFactory
	}()

	a := NewAdapter()
	err := a.Init(context.Background(), jsengine.Config{Name: jsengine.EngineQuickJS})
	if err == nil {
		t.Fatal("后端缺失时 Init 应失败")
	}
	ee, ok := err.(*jsengine.EngineError)
	if !ok || ee.Kind != jsengine.ErrInit {
		t.Fatalf("错误类型不正确: %T %v", err, err)
	}
}
