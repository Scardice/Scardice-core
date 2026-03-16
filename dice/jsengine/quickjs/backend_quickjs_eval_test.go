//go:build quickjs

package quickjs

import (
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/dice/jsengine"
)

func TestNativeBackendEvalAwaitsPromise(t *testing.T) {
	backend, err := newNativeBackend(jsengine.Config{}, Options{})
	if err != nil {
		t.Fatalf("创建 QuickJS backend 失败: %v", err)
	}
	defer func() { _ = backend.Dispose() }()

	if err := backend.Eval(`(async () => {
		globalThis.__sd_eval_async_done = 0;
		await Promise.resolve(1);
		globalThis.__sd_eval_async_done = 1;
	})()`); err != nil {
		t.Fatalf("执行异步脚本失败: %v", err)
	}

	if err := backend.Eval(`if (globalThis.__sd_eval_async_done !== 1) { throw new Error("not done"); }`); err != nil {
		t.Fatalf("异步脚本未完成执行: %v", err)
	}
}

func TestNativeBackendRequireIsolatesModuleScope(t *testing.T) {
	dir := t.TempDir()
	mod1 := filepath.Join(dir, "m1.js")
	mod2 := filepath.Join(dir, "m2.js")
	if err := os.WriteFile(mod1, []byte(`const ext = 1; globalThis.__sd_req_m1 = ext;`), 0o644); err != nil {
		t.Fatalf("写入测试脚本失败: %v", err)
	}
	if err := os.WriteFile(mod2, []byte(`const ext = 2; globalThis.__sd_req_m2 = ext;`), 0o644); err != nil {
		t.Fatalf("写入测试脚本失败: %v", err)
	}

	backend, err := newNativeBackend(jsengine.Config{ModuleDir: dir}, Options{})
	if err != nil {
		t.Fatalf("创建 QuickJS backend 失败: %v", err)
	}
	defer func() { _ = backend.Dispose() }()

	if err := backend.Require(mod1); err != nil {
		t.Fatalf("Require 第一个脚本失败: %v", err)
	}
	if err := backend.Require(mod2); err != nil {
		t.Fatalf("Require 第二个脚本失败: %v", err)
	}
	if err := backend.Eval(`if (globalThis.__sd_req_m1 !== 1 || globalThis.__sd_req_m2 !== 2) { throw new Error("module eval mismatch"); }`); err != nil {
		t.Fatalf("脚本隔离验证失败: %v", err)
	}
}
