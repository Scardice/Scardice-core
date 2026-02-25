package quickjs

import (
	"context"
	"sync"

	"Scardice-core/dice/jsengine"
)

type Adapter struct {
	mu sync.RWMutex

	cfg jsengine.Config
	lc  *jsengine.Lifecycle

	apis    []jsengine.HostAPI
	opt     Options
	backend runtimeBackend
}

func init() {
	jsengine.Register(jsengine.EngineQuickJS, func() jsengine.Engine {
		return NewAdapter()
	})
}

// NewAdapter 创建 QuickJS 适配器实例。
func NewAdapter() *Adapter {
	return &Adapter{
		lc:   jsengine.NewLifecycle(),
		apis: make([]jsengine.HostAPI, 0, 8),
	}
}

func (a *Adapter) Name() jsengine.EngineName {
	return jsengine.EngineQuickJS
}

func (a *Adapter) Init(_ context.Context, cfg jsengine.Config) error {
	if !a.lc.CompareAndSwap(jsengine.StateNew, jsengine.StateIniting) {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInit,
			Message: "引擎初始化状态非法",
		}
	}

	a.mu.Lock()
	a.cfg = cfg
	apis := append([]jsengine.HostAPI(nil), a.apis...)
	a.mu.Unlock()

	backend, err := newRuntimeBackend(cfg, a.opt)
	if err != nil {
		a.lc.Store(jsengine.StateClosed)
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInit,
			Message: "QuickJS 后端初始化失败",
			Cause:   err,
		}
	}
	for _, api := range apis {
		if err := backend.RegisterHostAPI(api); err != nil {
			_ = backend.Dispose()
			a.lc.Store(jsengine.StateClosed)
			return &jsengine.EngineError{
				Kind:    jsengine.ErrInit,
				Message: "QuickJS 注入宿主API失败",
				Cause:   err,
			}
		}
	}

	a.mu.Lock()
	a.backend = backend
	a.mu.Unlock()

	a.lc.Store(jsengine.StateReady)
	return nil
}

func (a *Adapter) Dispose() error {
	st := a.lc.State()
	if st == jsengine.StateClosed {
		return nil
	}
	if st != jsengine.StateReady && st != jsengine.StateIniting {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "引擎未处于可释放状态",
		}
	}
	if !a.lc.CompareAndSwap(st, jsengine.StateDisposing) {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "引擎释放状态切换失败",
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backend != nil {
		if err := a.backend.Dispose(); err != nil {
			a.lc.Store(jsengine.StateReady)
			return &jsengine.EngineError{
				Kind:    jsengine.ErrRuntime,
				Message: "QuickJS 后端释放失败",
				Cause:   err,
			}
		}
		a.backend = nil
	}

	a.lc.Store(jsengine.StateClosed)
	return nil
}

func (a *Adapter) Eval(code string) error {
	if a.lc.State() != jsengine.StateReady {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrEval,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	if err := a.backend.Eval(code); err != nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrEval,
			Message: "QuickJS Eval 执行失败: " + err.Error(),
			Cause:   err,
		}
	}
	return nil
}

// EvalWithResult 执行脚本并返回表达式结果（JSON 兼容值）。
func (a *Adapter) EvalWithResult(code string) (any, error) {
	if a.lc.State() != jsengine.StateReady {
		return nil, &jsengine.EngineError{
			Kind:    jsengine.ErrEval,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return nil, &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	ret, err := a.backend.EvalWithResult(code)
	if err != nil {
		return nil, &jsengine.EngineError{
			Kind:    jsengine.ErrEval,
			Message: "QuickJS EvalWithResult 执行失败: " + err.Error(),
			Cause:   err,
		}
	}
	return ret, nil
}

func (a *Adapter) Require(moduleID string) error {
	if a.lc.State() != jsengine.StateReady {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrModule,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	if err := a.backend.Require(moduleID); err != nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrModule,
			Message: "QuickJS Require 执行失败: " + err.Error(),
			Cause:   err,
		}
	}
	return nil
}

func (a *Adapter) RegisterHostAPI(api jsengine.HostAPI) error {
	a.mu.Lock()
	backend := a.backend
	defer a.mu.Unlock()
	a.apis = append(a.apis, api)
	if backend != nil {
		if err := backend.RegisterHostAPI(api); err != nil {
			return &jsengine.EngineError{
				Kind:    jsengine.ErrRuntime,
				Message: "QuickJS 动态注册宿主API失败",
				Cause:   err,
			}
		}
	}
	return nil
}

func (a *Adapter) Reset() error {
	if a.lc.State() != jsengine.StateReady {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	if err := a.backend.Reset(); err != nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "QuickJS Reset 执行失败",
			Cause:   err,
		}
	}
	return nil
}

// InvokeStoredSolve 调用在 JS 侧缓存的命令 solve 函数。
func (a *Adapter) InvokeStoredSolve(extName string, cmdName string, runtime map[string]any) (map[string]any, error) {
	if a.lc.State() != jsengine.StateReady {
		return nil, &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return nil, &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	ret, err := a.backend.InvokeStoredSolve(extName, cmdName, runtime)
	if err != nil {
		return nil, &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "QuickJS 调用命令solve失败: " + err.Error(),
			Cause:   err,
		}
	}
	return ret, nil
}

// InvokeStoredOnNotCommand 调用在 JS 侧缓存的 onNotCommandReceived 回调。
func (a *Adapter) InvokeStoredOnNotCommand(extName string, runtime map[string]any) error {
	if a.lc.State() != jsengine.StateReady {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	if err := a.backend.InvokeStoredOnNotCommand(extName, runtime); err != nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "QuickJS 调用 onNotCommandReceived 失败: " + err.Error(),
			Cause:   err,
		}
	}
	return nil
}

// InvokeStoredTask 调用在 JS 侧缓存的任务回调函数。
func (a *Adapter) InvokeStoredTask(fnRef string, taskCtx map[string]any) error {
	if a.lc.State() != jsengine.StateReady {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "引擎未初始化完成",
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrInternal,
			Message: "QuickJS 后端不可用",
		}
	}
	if err := a.backend.InvokeStoredTask(fnRef, taskCtx); err != nil {
		return &jsengine.EngineError{
			Kind:    jsengine.ErrRuntime,
			Message: "QuickJS 调用任务回调失败: " + err.Error(),
			Cause:   err,
		}
	}
	return nil
}
