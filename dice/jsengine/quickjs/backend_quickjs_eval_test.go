//go:build quickjs

package quickjs

import (
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
