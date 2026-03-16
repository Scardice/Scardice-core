package dice

import (
	"reflect"
	"sort"
	"strings"

	"github.com/dop251/goja"
)

type dangerousExposeCacheKey struct {
	Type reflect.Type
	Ptr  uintptr
}

type dangerousExposeContext struct {
	vm    *goja.Runtime
	cache map[dangerousExposeCacheKey]goja.Value
}

func exposeDangerousJSValue(vm *goja.Runtime, value interface{}) goja.Value {
	ctx := &dangerousExposeContext{
		vm:    vm,
		cache: map[dangerousExposeCacheKey]goja.Value{},
	}
	return ctx.toValue(reflect.ValueOf(value))
}

func (ctx *dangerousExposeContext) toValue(value reflect.Value) goja.Value {
	value = unwrapDangerousReflectValue(value)
	if !value.IsValid() {
		return goja.Null()
	}

	if key, ok := dangerousExposeValueCacheKey(value); ok {
		if cached, exists := ctx.cache[key]; exists {
			return cached
		}
	}

	switch value.Kind() {
	case reflect.Ptr:
		if value.IsNil() {
			return goja.Null()
		}
		switch value.Elem().Kind() {
		case reflect.Struct:
			return ctx.wrapStruct(value)
		case reflect.Slice, reflect.Array:
			return ctx.wrapArray(value)
		case reflect.Map:
			if value.Elem().Type().Key().Kind() == reflect.String {
				return ctx.wrapMap(value)
			}
		}
	case reflect.Struct:
		return ctx.wrapStruct(value)
	case reflect.Slice, reflect.Array:
		return ctx.wrapArray(value)
	case reflect.Map:
		if value.Type().Key().Kind() == reflect.String {
			return ctx.wrapMap(value)
		}
	}

	if value.CanInterface() {
		return ctx.vm.ToValue(value.Interface())
	}
	return goja.Undefined()
}

func (ctx *dangerousExposeContext) wrapStruct(value reflect.Value) goja.Value {
	key, hasKey := dangerousExposeValueCacheKey(value)
	obj := ctx.vm.NewDynamicObject(newDangerousStructObject(ctx, value))
	if hasKey {
		ctx.cache[key] = obj
	}
	return obj
}

func (ctx *dangerousExposeContext) wrapMap(value reflect.Value) goja.Value {
	key, hasKey := dangerousExposeValueCacheKey(value)
	obj := ctx.vm.NewDynamicObject(&dangerousMapObject{
		ctx:   ctx,
		value: value,
	})
	if hasKey {
		ctx.cache[key] = obj
	}
	return obj
}

func (ctx *dangerousExposeContext) wrapArray(value reflect.Value) goja.Value {
	key, hasKey := dangerousExposeValueCacheKey(value)
	obj := ctx.vm.NewDynamicArray(&dangerousArrayObject{
		ctx:   ctx,
		value: value,
	})
	if hasKey {
		ctx.cache[key] = obj
	}
	return obj
}

type dangerousStructField struct {
	Index []int
}

type dangerousStructObject struct {
	ctx     *dangerousExposeContext
	value   reflect.Value
	fields  map[string]dangerousStructField
	methods map[string]string
	keys    []string
}

var dangerousExposeHiddenFields = map[string]struct{}{
	"JsSealInstExposed": {},
}

func newDangerousStructObject(ctx *dangerousExposeContext, value reflect.Value) *dangerousStructObject {
	fieldMap := map[string]dangerousStructField{}
	methodMap := map[string]string{}
	keySet := map[string]struct{}{}

	structType := dangerousStructValue(value).Type()
	for _, field := range reflect.VisibleFields(structType) {
		if field.PkgPath != "" {
			continue
		}
		if _, hidden := dangerousExposeHiddenFields[field.Name]; hidden {
			continue
		}
		desc := dangerousStructField{Index: append([]int(nil), field.Index...)}
		for _, alias := range dangerousFieldAliases(field) {
			if alias == "" {
				continue
			}
			if _, exists := fieldMap[alias]; exists {
				continue
			}
			fieldMap[alias] = desc
			keySet[alias] = struct{}{}
		}
	}

	methodTarget := dangerousMethodTarget(value)
	if methodTarget.IsValid() {
		methodType := methodTarget.Type()
		for i := 0; i < methodType.NumMethod(); i++ {
			method := methodType.Method(i)
			if method.PkgPath != "" {
				continue
			}
			for _, alias := range dangerousMethodAliases(method.Name) {
				if alias == "" {
					continue
				}
				if _, exists := methodMap[alias]; exists {
					continue
				}
				methodMap[alias] = method.Name
				keySet[alias] = struct{}{}
			}
		}
	}

	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return &dangerousStructObject{
		ctx:     ctx,
		value:   value,
		fields:  fieldMap,
		methods: methodMap,
		keys:    keys,
	}
}

func (o *dangerousStructObject) Get(key string) goja.Value {
	if field, ok := o.fields[key]; ok {
		value := dangerousLookupField(o.value, field.Index)
		if !value.IsValid() {
			return goja.Null()
		}
		return o.ctx.toValue(value)
	}
	if methodName, ok := o.methods[key]; ok {
		target := dangerousMethodTarget(o.value)
		if !target.IsValid() {
			return nil
		}
		method := target.MethodByName(methodName)
		if !method.IsValid() || !method.CanInterface() {
			return nil
		}
		return o.ctx.vm.ToValue(method.Interface())
	}
	return nil
}

func (o *dangerousStructObject) Set(key string, val goja.Value) bool {
	field, ok := o.fields[key]
	if !ok {
		return false
	}
	target := dangerousLookupField(o.value, field.Index)
	if !target.IsValid() || !target.CanSet() {
		return false
	}
	return assignDangerousJSValue(o.ctx.vm, val, target)
}

func (o *dangerousStructObject) Has(key string) bool {
	_, hasField := o.fields[key]
	_, hasMethod := o.methods[key]
	return hasField || hasMethod
}

func (o *dangerousStructObject) Delete(string) bool {
	return false
}

func (o *dangerousStructObject) Keys() []string {
	return append([]string(nil), o.keys...)
}

type dangerousMapObject struct {
	ctx   *dangerousExposeContext
	value reflect.Value
}

func (o *dangerousMapObject) Get(key string) goja.Value {
	value := dangerousMapValue(o.value)
	if !value.IsValid() || value.Type().Key().Kind() != reflect.String {
		return nil
	}
	item := value.MapIndex(reflect.ValueOf(key).Convert(value.Type().Key()))
	if !item.IsValid() {
		return nil
	}
	return o.ctx.toValue(item)
}

func (o *dangerousMapObject) Set(key string, val goja.Value) bool {
	value := dangerousMapValue(o.value)
	if !value.IsValid() || value.Type().Key().Kind() != reflect.String {
		return false
	}
	if value.IsNil() {
		if !value.CanSet() {
			return false
		}
		value.Set(reflect.MakeMap(value.Type()))
	}
	tmp := reflect.New(value.Type().Elem())
	if err := o.ctx.vm.ExportTo(val, tmp.Interface()); err != nil {
		return false
	}
	value.SetMapIndex(reflect.ValueOf(key).Convert(value.Type().Key()), tmp.Elem())
	return true
}

func (o *dangerousMapObject) Has(key string) bool {
	value := dangerousMapValue(o.value)
	if !value.IsValid() || value.Type().Key().Kind() != reflect.String {
		return false
	}
	return value.MapIndex(reflect.ValueOf(key).Convert(value.Type().Key())).IsValid()
}

func (o *dangerousMapObject) Delete(key string) bool {
	value := dangerousMapValue(o.value)
	if !value.IsValid() || value.Type().Key().Kind() != reflect.String || value.IsNil() {
		return true
	}
	value.SetMapIndex(reflect.ValueOf(key).Convert(value.Type().Key()), reflect.Value{})
	return true
}

func (o *dangerousMapObject) Keys() []string {
	value := dangerousMapValue(o.value)
	if !value.IsValid() || value.Type().Key().Kind() != reflect.String || value.IsNil() {
		return nil
	}
	keys := value.MapKeys()
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key.String())
	}
	sort.Strings(result)
	return result
}

type dangerousArrayObject struct {
	ctx   *dangerousExposeContext
	value reflect.Value
}

func (o *dangerousArrayObject) Len() int {
	value := dangerousArrayValue(o.value)
	if !value.IsValid() {
		return 0
	}
	return value.Len()
}

func (o *dangerousArrayObject) Get(idx int) goja.Value {
	value := dangerousArrayValue(o.value)
	if !value.IsValid() || idx < 0 || idx >= value.Len() {
		return goja.Undefined()
	}
	return o.ctx.toValue(value.Index(idx))
}

func (o *dangerousArrayObject) Set(idx int, val goja.Value) bool {
	if idx < 0 {
		return false
	}
	value := dangerousArrayValue(o.value)
	if !value.IsValid() {
		return false
	}
	if value.Kind() == reflect.Array {
		if idx >= value.Len() {
			return false
		}
		target := value.Index(idx)
		if !target.CanSet() {
			return false
		}
		return assignDangerousJSValue(o.ctx.vm, val, target)
	}
	if idx >= value.Len() {
		if !growDangerousSlice(value, idx+1) {
			return false
		}
	}
	target := value.Index(idx)
	if !target.CanSet() {
		return false
	}
	return assignDangerousJSValue(o.ctx.vm, val, target)
}

func (o *dangerousArrayObject) SetLen(length int) bool {
	value := dangerousArrayValue(o.value)
	if !value.IsValid() || length < 0 {
		return false
	}
	if value.Kind() == reflect.Array {
		return length == value.Len()
	}
	return growDangerousSlice(value, length)
}

func growDangerousSlice(value reflect.Value, length int) bool {
	if value.Kind() != reflect.Slice || !value.CanSet() {
		return false
	}
	if length <= value.Len() {
		value.SetLen(length)
		return true
	}
	if length <= value.Cap() {
		value.SetLen(length)
		return true
	}
	newCap := value.Cap() * 2
	if newCap < length {
		newCap = length
	}
	if newCap == 0 {
		newCap = length
	}
	expanded := reflect.MakeSlice(value.Type(), length, newCap)
	reflect.Copy(expanded, value)
	value.Set(expanded)
	return true
}

func assignDangerousJSValue(vm *goja.Runtime, src goja.Value, dst reflect.Value) bool {
	if !dst.IsValid() || !dst.CanSet() {
		return false
	}
	if src == nil || goja.IsNull(src) || goja.IsUndefined(src) {
		dst.SetZero()
		return true
	}
	tmp := reflect.New(dst.Type())
	if err := vm.ExportTo(src, tmp.Interface()); err != nil {
		return false
	}
	dst.Set(tmp.Elem())
	return true
}

func dangerousExposeValueCacheKey(value reflect.Value) (dangerousExposeCacheKey, bool) {
	value = unwrapDangerousReflectValue(value)
	if !value.IsValid() {
		return dangerousExposeCacheKey{}, false
	}
	switch value.Kind() {
	case reflect.Ptr:
		if value.IsNil() {
			return dangerousExposeCacheKey{}, false
		}
		return dangerousExposeCacheKey{Type: value.Type(), Ptr: value.Pointer()}, true
	case reflect.Map:
		if value.IsNil() {
			return dangerousExposeCacheKey{}, false
		}
		return dangerousExposeCacheKey{Type: value.Type(), Ptr: value.Pointer()}, true
	case reflect.Struct, reflect.Array, reflect.Slice:
		if !value.CanAddr() {
			return dangerousExposeCacheKey{}, false
		}
		return dangerousExposeCacheKey{Type: value.Type(), Ptr: value.Addr().Pointer()}, true
	default:
		return dangerousExposeCacheKey{}, false
	}
}

func unwrapDangerousReflectValue(value reflect.Value) reflect.Value {
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func dangerousStructValue(value reflect.Value) reflect.Value {
	value = unwrapDangerousReflectValue(value)
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return reflect.Value{}
		}
		return value.Elem()
	}
	return value
}

func dangerousMethodTarget(value reflect.Value) reflect.Value {
	value = unwrapDangerousReflectValue(value)
	if !value.IsValid() {
		return reflect.Value{}
	}
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return reflect.Value{}
		}
		return value
	}
	if value.CanAddr() {
		return value.Addr()
	}
	return value
}

func dangerousMapValue(value reflect.Value) reflect.Value {
	value = unwrapDangerousReflectValue(value)
	if !value.IsValid() {
		return reflect.Value{}
	}
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Map {
		return reflect.Value{}
	}
	return value
}

func dangerousArrayValue(value reflect.Value) reflect.Value {
	value = unwrapDangerousReflectValue(value)
	if !value.IsValid() {
		return reflect.Value{}
	}
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Array && value.Kind() != reflect.Slice {
		return reflect.Value{}
	}
	return value
}

func dangerousLookupField(value reflect.Value, index []int) reflect.Value {
	current := dangerousStructValue(value)
	if !current.IsValid() {
		return reflect.Value{}
	}
	for _, item := range index {
		if current.Kind() == reflect.Ptr {
			if current.IsNil() {
				return reflect.Value{}
			}
			current = current.Elem()
		}
		if current.Kind() != reflect.Struct || item < 0 || item >= current.NumField() {
			return reflect.Value{}
		}
		current = current.Field(item)
	}
	return current
}

func dangerousFieldAliases(field reflect.StructField) []string {
	aliases := []string{field.Name, lowerFirstDangerousName(field.Name)}
	aliases = append(aliases, dangerousTagAlias(field.Tag.Get("jsbind")))
	aliases = append(aliases, dangerousTagAlias(field.Tag.Get("json")))
	return uniqueDangerousNames(aliases)
}

func dangerousMethodAliases(name string) []string {
	return uniqueDangerousNames([]string{name, lowerFirstDangerousName(name)})
}

func dangerousTagAlias(tag string) string {
	if tag == "" {
		return ""
	}
	if idx := strings.IndexByte(tag, ','); idx >= 0 {
		tag = tag[:idx]
	}
	if tag == "-" {
		return ""
	}
	return tag
}

func lowerFirstDangerousName(name string) string {
	if name == "" {
		return ""
	}
	return strings.ToLower(name[:1]) + name[1:]
}

func uniqueDangerousNames(names []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}
