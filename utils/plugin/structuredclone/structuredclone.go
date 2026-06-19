package sealsclone

import (
	"fmt"
	"strconv"

	"github.com/dop251/goja"
)

func Enable(rt *goja.Runtime) {
	_ = rt.Set("structuredClone", structuredCloneFn(rt))
}

func Require(rt *goja.Runtime, module *goja.Object) {
	exports := module.Get("exports").(*goja.Object)
	_ = exports.Set("structuredClone", structuredCloneFn(rt))
}

func structuredCloneFn(rt *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(rt.NewTypeError("structuredClone: value argument is required"))
		}
		val := call.Argument(0)
		seen := make(map[string]goja.Value)
		return cloneValue(rt, val, seen)
	}
}

func cloneValue(rt *goja.Runtime, v goja.Value, seen map[string]goja.Value) goja.Value {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return v
	}

	switch v.ExportType().String() {
	case "int", "int64", "uint", "uint64", "float32", "float64", "bool", "string":
		return v
	}

	obj, ok := v.(*goja.Object)
	if !ok {
		return v
	}

	id := fmt.Sprintf("%p", obj)
	if cached, ok := seen[id]; ok {
		return cached
	}

	switch obj.ClassName() {
	case "Array":
		n := int(obj.Get("length").ToInteger())
		arr := rt.NewArray()
		seen[id] = arr
		for i := range n {
			_ = arr.Set(strconv.Itoa(i), cloneValue(rt, obj.Get(strconv.Itoa(i)), seen))
		}
		return arr
	case "Object", "goja.Object":
		newObj := rt.NewObject()
		seen[id] = newObj
		for _, k := range obj.Keys() {
			_ = newObj.Set(k, cloneValue(rt, obj.Get(k), seen))
		}
		return newObj
	case "Map":
		newMap := rt.NewObject()
		seen[id] = newMap
		if entries, ok := goja.AssertFunction(obj.Get("entries")); ok {
			if iter, err := entries(goja.Undefined()); err == nil {
				if iterObj, ok := iter.(*goja.Object); ok {
					if next, ok := goja.AssertFunction(iterObj.Get("next")); ok {
						for {
							res, err := next(goja.Undefined())
							if err != nil {
								break
							}
							resObj := res.ToObject(rt)
							if resObj.Get("done").ToBoolean() {
								break
							}
							entryVal := resObj.Get("value")
							entryObj := entryVal.ToObject(rt)
							k := cloneValue(rt, entryObj.Get("0"), seen)
							clonedV := cloneValue(rt, entryObj.Get("1"), seen)
							if setFn, ok := goja.AssertFunction(newMap.Get("set")); ok {
								_, _ = setFn(goja.Undefined(), k, clonedV)
							}
						}
					}
				}
			}
		}
		return newMap
	case "Set":
		newSet := rt.NewObject()
		seen[id] = newSet
		if values, ok := goja.AssertFunction(obj.Get("values")); ok {
			if iter, err := values(goja.Undefined()); err == nil {
				if iterObj, ok := iter.(*goja.Object); ok {
					if next, ok := goja.AssertFunction(iterObj.Get("next")); ok {
						for {
							res, err := next(goja.Undefined())
							if err != nil {
								break
							}
							resObj := res.ToObject(rt)
							if resObj.Get("done").ToBoolean() {
								break
							}
							if addFn, ok := goja.AssertFunction(newSet.Get("add")); ok {
								_, _ = addFn(goja.Undefined(), cloneValue(rt, resObj.Get("value"), seen))
							}
						}
					}
				}
			}
		}
		return newSet
	case "Date":
		if getTime, ok := goja.AssertFunction(obj.Get("getTime")); ok {
			if t, err := getTime(goja.Undefined()); err == nil {
				dateCtor := rt.Get("Date")
				if ctor, ok := goja.AssertFunction(dateCtor); ok {
					if newObj, err := ctor(goja.Undefined(), t); err == nil {
						seen[id] = newObj
						return newObj
					}
				}
			}
		}
		return v
	}

	return jsonClone(rt, v)
}

func jsonClone(rt *goja.Runtime, v goja.Value) goja.Value {
	jsonObj := rt.Get("JSON").ToObject(rt)
	stringify, _ := goja.AssertFunction(jsonObj.Get("stringify"))
	parse, _ := goja.AssertFunction(jsonObj.Get("parse"))
	if stringify == nil || parse == nil {
		return v
	}
	raw, err := stringify(goja.Undefined(), v)
	if err != nil {
		return v
	}
	cloned, err := parse(goja.Undefined(), raw)
	if err != nil {
		return v
	}
	return cloned
}
