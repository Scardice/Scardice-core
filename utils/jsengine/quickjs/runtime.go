// Package quickjs adapts buke/quickjs-go to the engine-neutral runtime contract.
package quickjs

import (
	"errors"
	"sync"
	"sync/atomic"

	nodeeventloop "github.com/Scardice/quickjs_nodejs/eventloop"
	nodemodule "github.com/Scardice/quickjs_nodejs/module"
	quickjs "github.com/buke/quickjs-go"

	"Scardice-core/utils/jsengine"
)

type config struct {
	registry      *nodemodule.Registry
	globals       []nodeeventloop.GlobalInstaller
	logger        nodeeventloop.Logger
	runtimeLimits RuntimeLimits
}

// Option configures one qnode-backed QuickJS realm.
type Option func(*config)

// WithRegistry makes registered in-memory modules available to ESM and require.
func WithRegistry(registry *nodemodule.Registry) Option {
	return func(cfg *config) {
		cfg.registry = registry
	}
}

// WithGlobals installs globals in the owner-bound QuickJS context.
func WithGlobals(installers ...nodeeventloop.GlobalInstaller) Option {
	return func(cfg *config) {
		cfg.globals = append(cfg.globals, installers...)
	}
}

// WithLogger receives qnode asynchronous task failures.
func WithLogger(logger nodeeventloop.Logger) Option {
	return func(cfg *config) {
		cfg.logger = logger
	}
}

// RuntimeLimits configures one QuickJS runtime's resource boundaries. Values
// are in bytes; zero leaves the corresponding QuickJS default unchanged.
// GCThreshold may be -1 to disable automatic garbage collection.
type RuntimeLimits struct {
	MemoryLimit  uint64
	GCThreshold  int64
	MaxStackSize uint64
}

func (limits RuntimeLimits) configured() bool {
	return limits.MemoryLimit != 0 || limits.GCThreshold != 0 || limits.MaxStackSize != 0
}

// WithRuntimeLimits applies resource boundaries before user code runs.
func WithRuntimeLimits(limits RuntimeLimits) Option {
	return func(cfg *config) {
		cfg.runtimeLimits = limits
	}
}

type runtimeLoop struct {
	eventLoop    *nodeeventloop.EventLoop
	nextCallback uint64
	once         sync.Once
	started      atomic.Bool
}

var loopsByContext sync.Map

type value struct {
	runtime *runtime
	value   *quickjs.Value
}

type runtime struct {
	ctx     *quickjs.Context
	loop    *runtimeLoop
	objects []*quickjs.Value
	values  []*quickjs.Value
}

type object struct {
	runtime *runtime
	value   *quickjs.Value
}

// New creates an isolated qnode-backed realm. qnode remains the sole owner of
// the raw QuickJS runtime and its OS thread.
func New(options ...Option) (jsengine.Loop, error) {
	cfg := config{}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}

	eventLoopOptions := []nodeeventloop.Option{
		nodeeventloop.WithModuleImport(false),
	}
	if cfg.registry != nil {
		eventLoopOptions = append(eventLoopOptions, nodeeventloop.WithRegistry(cfg.registry))
	}
	if len(cfg.globals) > 0 {
		eventLoopOptions = append(eventLoopOptions, nodeeventloop.WithGlobals(cfg.globals...))
	}
	if cfg.logger != nil {
		eventLoopOptions = append(eventLoopOptions, nodeeventloop.WithLogger(cfg.logger))
	}

	eventLoop, err := nodeeventloop.New(eventLoopOptions...)
	if err != nil {
		return nil, err
	}
	loop := &runtimeLoop{eventLoop: eventLoop}
	if cfg.runtimeLimits.configured() {
		if err := eventLoop.ContextTask(func(ctx *nodeeventloop.Context) error {
			raw := ctx.Raw()
			if raw == nil {
				return errors.New("create QuickJS-Go context")
			}
			runtime := raw.Runtime()
			if runtime == nil {
				return errors.New("create QuickJS-Go runtime")
			}
			if cfg.runtimeLimits.MemoryLimit != 0 {
				runtime.SetMemoryLimit(cfg.runtimeLimits.MemoryLimit)
			}
			if cfg.runtimeLimits.GCThreshold != 0 {
				runtime.SetGCThreshold(cfg.runtimeLimits.GCThreshold)
			}
			if cfg.runtimeLimits.MaxStackSize != 0 {
				runtime.SetMaxStackSize(cfg.runtimeLimits.MaxStackSize)
			}
			return nil
		}); err != nil {
			_ = eventLoop.Close()
			return nil, err
		}
	}

	if err := eventLoop.ContextTask(func(ctx *nodeeventloop.Context) error {
		raw := ctx.Raw()
		if raw == nil {
			return errors.New("create QuickJS-Go context")
		}
		loopsByContext.Store(raw, loop)
		return nil
	}); err != nil {
		_ = eventLoop.Close()
		return nil, err
	}
	return loop, nil
}

func (r *runtimeLoop) Engine() jsengine.EngineID {
	return jsengine.EngineQuickJS
}

func (r *runtimeLoop) Run(run func(jsengine.Runtime) error) error {
	execute := func(ctx *nodeeventloop.Context) error {
		realm := &runtime{ctx: ctx.Raw(), loop: r}
		defer realm.close()
		return run(realm)
	}
	if r.started.Load() {
		return r.eventLoop.ContextTask(execute)
	}
	return r.eventLoop.RunContext(execute)
}

func (r *runtime) Engine() jsengine.EngineID {
	return jsengine.EngineQuickJS
}

func (r *runtime) RunString(filename, source string) (jsengine.Value, error) {
	result := eval(r, filename, source)
	return result.value, result.err
}

// LoadModule evaluates a QuickJS ESM entry. It is intentionally QuickJS
// specific so jsengine.Runtime keeps the shared Goja-compatible contract.
func LoadModule(current jsengine.Runtime, filename, source string) (jsengine.Value, error) {
	realm, ok := current.(*runtime)
	if !ok {
		return nil, errors.New("QuickJS-Go runtime is required")
	}
	result := realm.ctx.LoadModule(source, filename)
	if result == nil {
		return nil, errors.New("QuickJS-Go module evaluation failed")
	}
	if result.IsException() {
		result.Free()
		err := realm.ctx.Exception()
		if err == nil {
			err = errors.New("QuickJS-Go module evaluation failed")
		}
		return nil, err
	}
	realm.values = append(realm.values, result)
	return value{runtime: realm, value: result}, nil
}

func (r *runtime) LoadCommonJS(filename, source string) (jsengine.Value, error) {
	return r.RunString(filename, jsengine.CommonJSProgram(filename, source))
}

func (r *runtime) NewObject() jsengine.Object {
	value := r.ctx.NewObject()
	r.objects = append(r.objects, value)
	return &object{runtime: r, value: value}
}

func (r *runtime) Get(name string) jsengine.Value {
	rawValue := r.ctx.Globals().Get(name)
	if rawValue == nil {
		return nil
	}
	r.values = append(r.values, rawValue)
	return value{runtime: r, value: rawValue}
}

func (r *runtime) Set(name string, value interface{}) error {
	jsValue, release, err := r.coerce(value)
	if err != nil {
		return err
	}
	if release {
		defer jsValue.Free()
	}
	return setProperty(r.ctx.Globals(), name, jsValue)
}

func (o *object) Set(name string, value interface{}) error {
	jsValue, release, err := o.runtime.coerce(value)
	if err != nil {
		return err
	}
	if release {
		defer jsValue.Free()
	}
	return setProperty(o.value, name, jsValue)
}

func (o *object) Get(name string) jsengine.Value {
	rawValue := o.value.Get(name)
	if rawValue == nil {
		return nil
	}
	o.runtime.values = append(o.runtime.values, rawValue)
	return value{runtime: o.runtime, value: rawValue}
}

func (o *object) Has(name string) bool {
	return o.value.Has(name)
}
func (r *runtime) close() {
	for _, value := range r.values {
		value.Free()
	}
	for _, object := range r.objects {
		object.Free()
	}
}

func (r *runtime) Bind(name string, value interface{}) error {
	return bind(r.ctx, name, value)
}

func (r *runtimeLoop) Close() {
	r.once.Do(func() {
		_ = r.eventLoop.ContextTask(func(ctx *nodeeventloop.Context) error {
			raw := ctx.Raw()
			if raw != nil {
				releaseHostValues(raw)
				loopsByContext.Delete(raw)
			}
			return nil
		})
		_ = r.eventLoop.Close()
	})
}

// Start enables continuous Promise, timer, and asynchronous-resource pumping.
func Start(loop jsengine.Loop) error {
	runtimeLoop, ok := loop.(*runtimeLoop)
	if !ok {
		return errors.New("QuickJS-Go runtime is required")
	}
	if err := runtimeLoop.eventLoop.Start(); err != nil {
		return err
	}
	runtimeLoop.started.Store(true)
	return nil
}

func eval(r *runtime, filename, source string) struct {
	value jsengine.Value
	err   error
} {
	result := r.ctx.Eval(source, quickjs.EvalFileName(filename))
	if result == nil {
		return struct {
			value jsengine.Value
			err   error
		}{err: errors.New("QuickJS-Go evaluation failed")}
	}
	if result.IsException() {
		result.Free()
		err := r.ctx.Exception()
		if err == nil {
			err = errors.New("QuickJS-Go evaluation failed")
		}
		return struct {
			value jsengine.Value
			err   error
		}{err: err}
	}
	r.values = append(r.values, result)
	return struct {
		value jsengine.Value
		err   error
	}{value: value{runtime: r, value: result}}
}

func (v value) Export() interface{} {
	return export(v.value)
}

func (v value) ToBoolean() bool {
	return v.value != nil && v.value.ToBool()
}

func (v value) Object() jsengine.Object {
	if v.value == nil || !v.value.IsObject() {
		return nil
	}
	return &object{runtime: v.runtime, value: v.value}
}

func export(value *quickjs.Value) interface{} {
	switch {
	case value.IsUndefined(), value.IsNull():
		return nil
	case value.IsBool():
		return value.ToBool()
	case value.IsString():
		return value.ToString()
	case value.IsNumber():
		return value.ToFloat64()
	default:
		return value.JSONStringify()
	}
}
