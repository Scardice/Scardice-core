package quickjs

import "Scardice-core/dice/jsengine"

// runtimeBackend 定义 QuickJS 运行时后端最小能力。
// 后续接入真实 QuickJS 绑定时，只需要实现该接口。
type runtimeBackend interface {
	Dispose() error
	Eval(code string) error
	EvalWithResult(code string) (any, error)
	Require(moduleID string) error
	RegisterHostAPI(api jsengine.HostAPI) error
	Reset() error
	InvokeStoredSolve(extName string, cmdName string, runtime map[string]any) (map[string]any, error)
	InvokeStoredOnNotCommand(extName string, runtime map[string]any) error
	InvokeStoredTask(fnRef string, taskCtx map[string]any) error
}

// newRuntimeBackend 用于创建具体后端实现。
// 具体实现由带构建标签的文件提供：
// - backend_noquickjs.go: 默认降级实现
// - backend_quickjs.go: quickjs (github.com/buke/quickjs-go) CGO 实现
var newRuntimeBackend func(cfg jsengine.Config, opt Options) (runtimeBackend, error)
