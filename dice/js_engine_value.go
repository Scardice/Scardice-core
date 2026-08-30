package dice

import (
	"Scardice-core/utils/jsengine"

	"github.com/dop251/goja"
)

type gojaEngineValue struct {
	vm    *goja.Runtime
	value goja.Value
}

func (v gojaEngineValue) Export() interface{} {
	if v.value == nil {
		return nil
	}
	return v.value.Export()
}

func (v gojaEngineValue) ToBoolean() bool {
	return v.value != nil && !goja.IsUndefined(v.value) && !goja.IsNull(v.value) && v.value.ToBoolean()
}
func (v gojaEngineValue) Object() jsengine.Object {
	if v.value == nil || goja.IsUndefined(v.value) || goja.IsNull(v.value) {
		return nil
	}
	object, ok := v.value.(*goja.Object)
	if !ok {
		return nil
	}
	return gojaEngineObject{value: object, vm: v.vm}
}

type gojaEngineObject struct {
	vm    *goja.Runtime
	value *goja.Object
}

func (o gojaEngineObject) Set(name string, value interface{}) error {
	return o.value.Set(name, value)
}

func (o gojaEngineObject) Get(name string) jsengine.Value {
	return gojaEngineValue{vm: o.vm, value: o.value.Get(name)}
}

func (o gojaEngineObject) Has(name string) bool {
	for _, property := range o.value.GetOwnPropertyNames() {
		if property == name {
			return true
		}
	}
	return false
}
