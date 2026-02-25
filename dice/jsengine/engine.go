package jsengine

import "context"

// EngineName 标识 JS 引擎实现类型。
type EngineName string

const (
	EngineQuickJS EngineName = "quickjs"
	EngineGoja    EngineName = "goja"
)

// Config 是引擎实现使用的最小运行配置。
// 该结构应保持小且与具体引擎无关，仅在需要时扩展字段。
type Config struct {
	Name      EngineName
	ModuleDir string
}

// HostAPI 表示宿主侧提供给脚本引擎的 API 注册项。
// 这里故意不约束具体函数签名，以避免该包与特定引擎值模型耦合。
type HostAPI struct {
	Name    string
	Handler any
}

// ErrorKind 定义脚本引擎层统一的错误类别。
type ErrorKind string

const (
	ErrInit     ErrorKind = "init"
	ErrEval     ErrorKind = "eval"
	ErrModule   ErrorKind = "module"
	ErrRuntime  ErrorKind = "runtime"
	ErrInternal ErrorKind = "internal"
)

// EngineError 是引擎适配层返回的统一错误结构。
type EngineError struct {
	Kind    ErrorKind
	Message string
	Stack   string
	Cause   error
}

func (e *EngineError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return string(e.Kind) + ": " + e.Message
	}
	return string(e.Kind)
}

func (e *EngineError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Engine 是 JS 运行时统一抽象接口。
// - 生命周期管理
// - 脚本/模块执行
// - 宿主 API 注册
// - 重置钩子
type Engine interface {
	Name() EngineName
	Init(ctx context.Context, cfg Config) error
	Dispose() error

	// Eval 执行脚本文本。
	Eval(code string) error
	// Require 按模块标识加载模块（路径或 ID 的解析策略由适配器决定）。
	Require(moduleID string) error

	RegisterHostAPI(api HostAPI) error
	Reset() error
}
