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

type runtime struct {
	vm *goja.Runtime
}

type eventLoop struct {
	loop    *eventloop.EventLoop
	closed  atomic.Bool
	running atomic.Bool
	once    sync.Once
}

type value struct {
	value goja.Value
}

type object struct {
	value *goja.Object
}

// New creates an isolated Goja realm.
func New() jsengine.Loop {
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("jsbind", true))
	return &runtime{vm: vm}
}

// Wrap adapts an existing Goja runtime for shared Host API installers.
// The caller retains ownership of the runtime and its event loop.
func Wrap(vm *goja.Runtime) jsengine.Runtime {
	return &runtime{vm: vm}
}

// WrapEventLoop adapts the legacy Goja event loop to jsengine.Loop.
// The event loop remains owned by the caller until Close is invoked.
func WrapEventLoop(loop *eventloop.EventLoop) jsengine.Loop {
	return &eventLoop{loop: loop}
}

// StartInForeground runs a wrapped event loop until it is closed.
func StartInForeground(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.closed.Load() {
		return errors.New("goja event loop is closed")
	}
	if !adapter.running.CompareAndSwap(false, true) {
		return errors.New("goja event loop is already running")
	}
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

func (l *eventLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *eventLoop) Descriptor() jsengine.Descriptor {
	return (&runtime{}).Descriptor()
}

func (l *eventLoop) Run(run func(jsengine.Runtime) error) (err error) {
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
			done <- run(&runtime{vm: vm})
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
		err = run(&runtime{vm: vm})
	})
	return err
}

func (l *eventLoop) LoadEntry(entry jsengine.Entry) error {
	return l.Run(func(runtime jsengine.Runtime) error {
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
	})
}

func (l *eventLoop) Close() error {
	if l == nil || l.loop == nil {
		return nil
	}
	l.once.Do(func() {
		l.closed.Store(true)
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

func (r *runtime) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{
		ID:           jsengine.EngineGoja,
		Name:         "Goja",
		Version:      "builtin",
		Language:     "Go",
		Capabilities: jsengine.CapabilityScript.With(jsengine.CapabilityCommonJS, jsengine.CapabilityHostObject, jsengine.CapabilityHostFunction),
		Builtin:      true,
	}
}

func (r *runtime) LoadEntry(entry jsengine.Entry) error {
	return r.Run(func(runtime jsengine.Runtime) error {
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
func WrapValue(_ *goja.Runtime, raw goja.Value) jsengine.Value {
	return value{value: raw}
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
	return value{value: result}, nil
}

func (r *runtime) LoadCommonJS(filename, source string) (jsengine.Value, error) {
	return r.RunString(filename, jsengine.CommonJSProgram(filename, source))
}

func (r *runtime) NewObject() jsengine.Object {
	return object{value: r.vm.NewObject()}
}

func (r *runtime) Get(name string) jsengine.Value {
	return value{value: r.vm.Get(name)}
}

func (r *runtime) Set(name string, value interface{}) error {
	return r.vm.Set(name, unwrapObject(value))
}

func (o object) Set(name string, value interface{}) error {
	return o.value.Set(name, unwrapObject(value))
}

func (o object) Get(name string) jsengine.Value {
	return value{value: o.value.Get(name)}
}

func (o object) Has(name string) bool {
	for _, property := range o.value.GetOwnPropertyNames() {
		if property == name {
			return true
		}
	}
	return false
}

func unwrapObject(raw interface{}) interface{} {
	switch value := raw.(type) {
	case object:
		return value.value
	case value:
		return value.value
	default:
		return raw
	}
}

func (r *runtime) Bind(name string, value interface{}) error {
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
		return object{value: rawObject}
	}
	return nil
}
