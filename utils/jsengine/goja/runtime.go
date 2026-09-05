// Package goja adapts Goja to the engine-neutral runtime contract.
package goja

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
)

var realms sync.Map
var eventRealms sync.Map

type contextState struct {
	mu      sync.RWMutex
	current any
}

func (s *contextState) currentContext() any {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *contextState) with(context any, run func() error) (err error) {
	if s == nil {
		return run()
	}
	s.mu.Lock()
	previous := s.current
	s.current = context
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.current = previous
		s.mu.Unlock()
	}()
	return run()
}

type realm struct {
	vm    *goja.Runtime
	state *contextState
}

func realmFor(vm *goja.Runtime) *realm {
	if vm == nil {
		return &realm{state: &contextState{}}
	}
	if existing, ok := realms.Load(vm); ok {
		return existing.(*realm)
	}
	created := &realm{vm: vm, state: &contextState{}}
	actual, _ := realms.LoadOrStore(vm, created)
	return actual.(*realm)
}

type runtime struct {
	vm    *goja.Runtime
	realm *realm
}

type eventLoop struct {
	loop      *eventloop.EventLoop
	realm     *realm
	closed    atomic.Bool
	running   atomic.Bool
	once      sync.Once
	context   atomic.Bool
	started   chan struct{}
	startOnce sync.Once
}

type value struct {
	value goja.Value
	realm *realm
}

type object struct {
	value *goja.Object
	realm *realm
}

// New creates an isolated Goja realm.
func New() jsengine.Loop {
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("jsbind", true))
	return &runtime{vm: vm, realm: realmFor(vm)}
}

// Wrap adapts an existing Goja runtime for shared Host API installers.
// The caller retains ownership of the runtime and its event loop.
func Wrap(vm *goja.Runtime) jsengine.Runtime {
	return &runtime{vm: vm, realm: realmFor(vm)}
}

// WrapEventLoop adapts the legacy Goja event loop to jsengine.Loop.
// The event loop remains owned by the caller until Close is invoked.
func WrapEventLoop(loop *eventloop.EventLoop) jsengine.Loop {
	if existing, ok := eventRealms.Load(loop); ok {
		return existing.(*eventLoop)
	}
	created := &eventLoop{
		loop:    loop,
		realm:   realmFor(nil),
		started: make(chan struct{}),
	}
	actual, _ := eventRealms.LoadOrStore(loop, created)
	return actual.(*eventLoop)
}

// signalStarted releases callers waiting for StartInForeground to claim the
// adapter. It is separate from running so Open can close its setup/start race.
func (l *eventLoop) signalStarted() {
	if l == nil || l.started == nil {
		return
	}
	l.startOnce.Do(func() { close(l.started) })
}

// StartInForeground runs a wrapped event loop until it is closed.
func StartInForeground(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.closed.Load() {
		adapter.signalStarted()
		return errors.New("goja event loop is closed")
	}
	if !adapter.running.CompareAndSwap(false, true) {
		adapter.signalStarted()
		return errors.New("goja event loop is already running")
	}
	adapter.signalStarted()
	defer adapter.running.Store(false)
	var runErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				runErr = fmt.Errorf("goja event loop panic: %v", recovered)
			}
		}()
		adapter.loop.StartInForeground()
	}()
	return runErr
}

// WaitUntilStarted waits until StartInForeground has claimed loop ownership.
func WaitUntilStarted(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.started == nil {
		return errors.New("goja event loop start signal is unavailable")
	}
	<-adapter.started
	return nil
}

func (l *eventLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *eventLoop) Descriptor() jsengine.Descriptor {
	return (&runtime{}).Descriptor()
}

func (l *eventLoop) invoke(context any, run func(jsengine.Runtime) error, vm *goja.Runtime) error {
	return l.realm.state.with(context, func() error {
		return run(&runtime{vm: vm, realm: l.realm})
	})
}

func (l *eventLoop) runWithContext(context any, run func(jsengine.Runtime) error) (err error) {
	if run == nil {
		return errors.New("goja runtime callback is nil")
	}
	if l == nil || l.loop == nil || l.closed.Load() {
		return errors.New("goja event loop is closed")
	}
	if l.running.Load() {
		done := make(chan error, 1)
		if !l.loop.RunOnLoop(func(vm *goja.Runtime) {
			defer func() {
				if recovered := recover(); recovered != nil {
					done <- fmt.Errorf("goja runtime callback panic: %v", recovered)
				}
			}()
			done <- l.invoke(context, run, vm)
		}) {
			return errors.New("goja event loop is closed")
		}
		return <-done
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("goja runtime callback panic: %v", recovered)
		}
	}()
	l.loop.Run(func(vm *goja.Runtime) {
		err = l.invoke(context, run, vm)
	})
	return err
}

// scheduleWithContext queues a context-aware callback without waiting for it.
// Nothing observes the callback result, so a failure is contained instead of
// escaping into the event loop's panic accounting.
func (l *eventLoop) scheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("goja runtime callback is nil")
	}
	if l == nil || l.loop == nil || l.closed.Load() {
		return errors.New("goja event loop is closed")
	}
	if !l.loop.RunOnLoop(func(vm *goja.Runtime) {
		defer func() {
			_ = recover()
		}()
		_ = l.invoke(context, run, vm)
	}) {
		return errors.New("goja event loop is closed")
	}
	return nil
}

// ScheduleWithContext queues a context-aware callback on the owning event
// loop. It never waits for the callback, so it is the only entry point that is
// safe from inside a loop callback, a timer, a Promise continuation, or a host
// service completion.
func ScheduleWithContext(loop jsengine.Loop, context any, run func(jsengine.Runtime) error) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	return adapter.scheduleWithContext(context, run)
}

func (l *eventLoop) Run(run func(jsengine.Runtime) error) error {
	return l.runWithContext(l.CurrentContext(), run)
}

func (l *eventLoop) RunWithContext(context any, run func(jsengine.Runtime) error) error {
	return l.runWithContext(context, run)
}

func (l *eventLoop) Schedule(run func(jsengine.Runtime) error) error {
	return l.scheduleWithContext(l.CurrentContext(), run)
}

func (l *eventLoop) ScheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	return l.scheduleWithContext(context, run)
}

func (l *eventLoop) CurrentContext() any {
	if l == nil || l.realm == nil {
		return nil
	}
	return l.realm.state.currentContext()
}

func gojaLoadEntry(runtime jsengine.Runtime, entry jsengine.Entry) error {
	switch entry.Kind {
	case jsengine.EntryScript, jsengine.EntryExtension:
		_, err := runtime.RunString(entry.Filename, entry.Source)
		return err
	case jsengine.EntryCommonJS:
		_, err := runtime.LoadCommonJS(entry.Filename, entry.Source)
		return err
	case jsengine.EntryESModule:
		return errors.New("goja: ESM entries are unsupported")
	default:
		return errors.New("goja: unknown entry kind")
	}
}

func (l *eventLoop) LoadEntry(entry jsengine.Entry) error {
	return l.LoadEntryWithContext(l.CurrentContext(), entry)
}

func (l *eventLoop) LoadEntryWithContext(context any, entry jsengine.Entry) error {
	return l.runWithContext(context, func(runtime jsengine.Runtime) error {
		return gojaLoadEntry(runtime, entry)
	})
}

func (l *eventLoop) Close() error {
	if l == nil || l.loop == nil {
		return nil
	}
	l.once.Do(func() {
		l.closed.Store(true)
		eventRealms.Delete(l.loop)
		l.loop.Terminate()
	})
	return nil
}

func (r *runtime) Engine() jsengine.EngineID {
	return jsengine.EngineGoja
}

func (r *runtime) Run(run func(jsengine.Runtime) error) error {
	return run(r)
}

func (r *runtime) RunWithContext(context any, run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("goja runtime callback is nil")
	}
	return r.realm.state.with(context, func() error { return run(r) })
}

// Schedule runs the callback inline. An isolated realm has no job queue and no
// owner goroutine to block, so immediate execution is the deferred execution.
func (r *runtime) Schedule(run func(jsengine.Runtime) error) error {
	return r.ScheduleWithContext(r.CurrentContext(), run)
}

func (r *runtime) ScheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	return r.RunWithContext(context, run)
}

func (r *runtime) CurrentContext() any {
	if r == nil || r.realm == nil {
		return nil
	}
	return r.realm.state.currentContext()
}

func (r *runtime) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{
		ID:           jsengine.EngineGoja,
		Name:         "Goja",
		Version:      "builtin",
		Language:     "Go",
		Author:       "Scardice",
		Extensions:   []string{".js", ".ts"},
		Capabilities: jsengine.CapabilityScript.With(jsengine.CapabilityCommonJS, jsengine.CapabilityHostObject, jsengine.CapabilityHostFunction, jsengine.CapabilityContextPropagation),
		Builtin:      true,
	}
}

func (r *runtime) LoadEntry(entry jsengine.Entry) error {
	return r.LoadEntryWithContext(r.CurrentContext(), entry)
}

func (r *runtime) LoadEntryWithContext(context any, entry jsengine.Entry) error {
	return r.RunWithContext(context, func(runtime jsengine.Runtime) error {
		return gojaLoadEntry(runtime, entry)
	})
}

// Raw returns the underlying Goja runtime for legacy Goja-only integrations.
func Raw(engine jsengine.Runtime) (*goja.Runtime, bool) {
	runtime, ok := engine.(*runtime)
	if !ok {
		return nil, false
	}
	return runtime.vm, true
}

// WrapValue adapts a raw Goja value for engine-neutral Host installation.
func WrapValue(vm *goja.Runtime, raw goja.Value) jsengine.Value {
	return value{value: raw, realm: realmFor(vm)}
}

func (r *runtime) RunString(filename, source string) (jsengine.Value, error) {
	program, err := goja.Compile(filename, source, false)
	if err != nil {
		return nil, err
	}

	result, err := r.vm.RunProgram(program)
	if err != nil {
		return nil, err
	}
	return value{value: result, realm: r.realm}, nil
}

func (r *runtime) LoadCommonJS(filename, source string) (jsengine.Value, error) {
	return r.RunString(filename, jsengine.CommonJSProgram(filename, source))
}

func (r *runtime) NewObject() jsengine.Object {
	return object{value: r.vm.NewObject(), realm: r.realm}
}

func (r *runtime) Get(name string) jsengine.Value {
	return value{value: r.vm.Get(name), realm: r.realm}
}

func (r *runtime) Set(name string, raw interface{}) error {
	value, err := unwrapObject(raw, r.realm)
	if err != nil {
		return err
	}
	return r.vm.Set(name, value)
}

func (o object) Set(name string, raw interface{}) error {
	value, err := unwrapObject(raw, o.realm)
	if err != nil {
		return err
	}
	return o.value.Set(name, value)
}

func (o object) Get(name string) jsengine.Value {
	return value{value: o.value.Get(name), realm: o.realm}
}

func (o object) Has(name string) bool {
	for _, property := range o.value.GetOwnPropertyNames() {
		if property == name {
			return true
		}
	}
	return false
}

func unwrapObject(raw interface{}, owner *realm) (interface{}, error) {
	switch value := raw.(type) {
	case object:
		if value.realm != owner {
			return nil, errors.New("goja object belongs to another realm")
		}
		return value.value, nil
	case value:
		if value.realm != owner {
			return nil, errors.New("goja value belongs to another realm")
		}
		return value.value, nil
	default:
		return raw, nil
	}
}

func (r *runtime) Bind(name string, raw interface{}) error {
	value, err := unwrapObject(raw, r.realm)
	if err != nil {
		return err
	}
	return r.vm.Set(name, value)
}

func (r *runtime) Close() error { return nil }

func (v value) Export() interface{} {
	return v.value.Export()
}

func (v value) ExportPrimitive() (any, error) {
	if v.value == nil || goja.IsUndefined(v.value) || goja.IsNull(v.value) {
		return nil, nil
	}
	if _, ok := v.value.(*goja.Object); ok {
		return nil, fmt.Errorf("%w: object", jsengine.ErrPrimitiveExportUnsupported)
	}
	switch exported := v.value.Export().(type) {
	case bool, string, int64, uint64, float64:
		return exported, nil
	default:
		return nil, fmt.Errorf("%w: %T", jsengine.ErrPrimitiveExportUnsupported, exported)
	}
}

func (v value) ToBoolean() bool {
	return v.value != nil && v.value.ToBoolean()
}

func (v value) Object() jsengine.Object {
	if rawObject, ok := v.value.(*goja.Object); ok {
		return object{value: rawObject, realm: v.realm}
	}
	return nil
}

// InstallContextPropagation makes engine-owned timers and Promise callbacks
// restore the context that was active when each callback was registered.
func InstallContextPropagation(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.context.Load() {
		return nil
	}
	if err := adapter.Run(func(runtime jsengine.Runtime) error {
		vm, ok := Raw(runtime)
		if !ok {
			return errors.New("goja runtime is required")
		}
		if err := vm.Set("__scardiceWrapAsync", func(call goja.FunctionCall) goja.Value {
			callback, ok := goja.AssertFunction(call.Argument(0))
			if !ok {
				return call.Argument(0)
			}
			context := adapter.CurrentContext()
			return vm.ToValue(func(callbackCall goja.FunctionCall) goja.Value {
				var result goja.Value
				if err := adapter.realm.state.with(context, func() error {
					var err error
					result, err = callback(callbackCall.This, callbackCall.Arguments...)
					return err
				}); err != nil {
					panic(err)
				}
				return result
			})
		}); err != nil {
			return err
		}
		if _, err := vm.RunString(`(function () {
			var wrap = globalThis.__scardiceWrapAsync;
			for (var name of ["setTimeout", "setInterval", "setImmediate"]) {
				var original = globalThis[name];
				if (typeof original !== "function") continue;
				globalThis[name] = function (callback) {
					var args = Array.prototype.slice.call(arguments, 1);
					args.unshift(wrap(callback));
					return original.apply(this, args);
				};
			}
			if (typeof globalThis.queueMicrotask === "function") {
				var originalQueueMicrotask = globalThis.queueMicrotask;
				globalThis.queueMicrotask = function (callback) {
					return originalQueueMicrotask.call(this, wrap(callback));
				};
			}
			if (typeof globalThis.Promise === "function") {
				var originalThen = globalThis.Promise.prototype.then;
				globalThis.Promise.prototype.then = function (onFulfilled, onRejected) {
					return originalThen.call(this, wrap(onFulfilled), wrap(onRejected));
				};
			}
		})();`); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	adapter.context.Store(true)
	return nil
}

var _ jsengine.ContextAwareLoop = (*eventLoop)(nil)
var _ jsengine.ContextAwareLoop = (*runtime)(nil)
var _ jsengine.Runtime = (*runtime)(nil)
var _ jsengine.Value = value{}
var _ jsengine.Object = object{}
