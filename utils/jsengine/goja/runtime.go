// Package goja adapts Goja to the engine-neutral runtime contract.
package goja

import (
	"github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
)

type runtime struct {
	vm *goja.Runtime
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

func (r *runtime) Engine() jsengine.EngineID {
	return jsengine.EngineGoja
}

func (r *runtime) Run(run func(jsengine.Runtime) error) error {
	return run(r)
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

func (r *runtime) Close() {}

func (v value) Export() interface{} {
	return v.value.Export()
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
