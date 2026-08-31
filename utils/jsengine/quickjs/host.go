package quickjs

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	quickjs "github.com/buke/quickjs-go"

	"Scardice-core/utils/jsengine"
)

var (
	errorType         = reflect.TypeFor[error]()
	runtimeType       = reflect.TypeFor[jsengine.Runtime]()
	jsengineValueType = reflect.TypeFor[jsengine.Value]()
)

const hostValueIDKey = "__scardiceHostValueID"

const callbackStoreKey = "__scardiceHostCallbacks"
const hostObjectStoreKey = "__scardiceHostObjects"

type hostIdentity struct {
	typeOf  reflect.Type
	pointer uintptr
}

var hostValues struct {
	sync.Mutex
	next       uint64
	values     map[uint64]reflect.Value
	contexts   map[*quickjs.Context]map[uint64]struct{}
	identities map[*quickjs.Context]map[hostIdentity]uint64
}

func bind(ctx *quickjs.Context, name string, target interface{}) error {
	if !isIdentifier(name) {
		return fmt.Errorf("invalid JavaScript global name %q", name)
	}

	object, err := bindStruct(ctx, reflect.ValueOf(target))
	if err != nil {
		return err
	}
	defer object.Free()
	return setProperty(ctx.Globals(), name, object)
}

func bindStruct(ctx *quickjs.Context, target reflect.Value) (*quickjs.Value, error) {
	return bindStructWithMode(ctx, target, false)
}

func bindStructWithMode(ctx *quickjs.Context, target reflect.Value, dangerous bool) (*quickjs.Value, error) {
	if !target.IsValid() || target.Kind() != reflect.Pointer || target.IsNil() || target.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("unsupported Host API binding type %T", valueInterface(target))
	}

	id := registerHostValue(ctx, target)
	if object, err := cachedHostObject(ctx, id); err != nil {
		return nil, err
	} else if object != nil {
		return object, nil
	}

	object := ctx.NewObject()
	if object == nil {
		return nil, errorsNew("create QuickJS host object")
	}
	if err := attachHostValue(ctx, object, id); err != nil {
		object.Free()
		return nil, err
	}

	structValue := target.Elem()
	structType := structValue.Type()
	definedNames := make(map[string]struct{})
	for _, fieldDef := range reflect.VisibleFields(structType) {
		field := hostFieldByIndex(structValue, fieldDef.Index)
		if !field.IsValid() {
			continue
		}
		names := []string{}
		if dangerous {
			names = dangerousBindNames(fieldDef)
		} else if name, ok := jsBindName(fieldDef); ok {
			names = []string{name}
		}
		for _, name := range names {
			if err := defineFieldWithMode(ctx, object, name, field, dangerous); err != nil {
				object.Free()
				return nil, err
			}
			definedNames[name] = struct{}{}
		}
	}
	for i := range target.Type().NumMethod() {
		methodDef := target.Type().Method(i)
		if !isIdentifier(methodDef.Name) {
			continue
		}
		names := []string{lowerFirst(methodDef.Name)}
		if dangerous {
			names = []string{methodDef.Name, lowerFirst(methodDef.Name)}
		}
		for _, name := range names {
			if _, exists := definedNames[name]; exists {
				continue
			}
			if err := defineMethod(ctx, object, name, target.Method(i)); err != nil {
				object.Free()
				return nil, err
			}
		}
	}
	if err := cacheHostObject(ctx, id, object); err != nil {
		object.Free()
		return nil, err
	}

	return object, nil
}

func hostFieldByIndex(value reflect.Value, index []int) reflect.Value {
	for _, item := range index {
		for value.IsValid() && value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return reflect.Value{}
			}
			value = value.Elem()
		}
		if !value.IsValid() || value.Kind() != reflect.Struct {
			return reflect.Value{}
		}
		value = value.Field(item)
	}
	return value
}
func jsBindName(field reflect.StructField) (string, bool) {
	if field.PkgPath != "" {
		return "", false
	}

	// Goja retains the legacy goja.Value callback fields. QuickJS-Go replaces
	// only these two public members with engine-neutral callbacks.
	switch field.Name {
	case "SolveEngine":
		return "solve", true
	case "OnMessagePreprocessEngine":
		return "onMessagePreprocess", true
	}

	tag, ok := field.Tag.Lookup("jsbind")
	if !ok || tag == "-" {
		return "", false
	}
	name := strings.Split(tag, ",")[0]
	return name, isIdentifier(name)
}
func dangerousBindNames(field reflect.StructField) []string {
	if field.PkgPath != "" || field.Name == "JsSealInstExposed" {
		return nil
	}
	names := []string{field.Name, lowerFirst(field.Name)}
	for _, tag := range []string{field.Tag.Get("jsbind"), field.Tag.Get("json")} {
		if name := strings.Split(tag, ",")[0]; name != "" && name != "-" {
			names = append(names, name)
		}
	}
	return uniqueHostNames(names)
}

func uniqueHostNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		if !isIdentifier(name) {
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
func defineField(ctx *quickjs.Context, object *quickjs.Value, name string, field reflect.Value) error {
	return defineFieldWithMode(ctx, object, name, field, false)
}

func defineFieldWithMode(ctx *quickjs.Context, object *quickjs.Value, name string, field reflect.Value, dangerous bool) error {
	getter := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, _ []*quickjs.Value) *quickjs.Value {
		return toJSWithMode(ctx, field, dangerous)
	})
	setter := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		if len(args) != 1 {
			return ctx.ThrowTypeError("%s requires one value", name)
		}
		if err := assignJS(field, args[0]); err != nil {
			return ctx.ThrowTypeError("%s: %v", name, err)
		}
		return ctx.NewUndefined()
	})
	defer getter.Free()
	defer setter.Free()

	flags := quickjs.PropConfigurable | quickjs.PropEnumerable | quickjs.PropHasConfigurable | quickjs.PropHasEnumerable
	if ok := object.DefinePropertyGetSet(name, getter, setter, flags); !ok {
		return fmt.Errorf("define Host API field %q", name)
	}
	return nil
}

func defineMethod(ctx *quickjs.Context, object *quickjs.Value, name string, method reflect.Value) error {
	function := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		methodType := method.Type()
		inputs, err := convertCallArguments(args, methodType)
		if err != nil {
			return ctx.ThrowTypeError("%s: %v", name, err)
		}
		outputs := method.Call(inputs)
		if len(outputs) > 0 && outputs[len(outputs)-1].Type() == errorType {
			errValue := outputs[len(outputs)-1]
			outputs = outputs[:len(outputs)-1]
			if !errValue.IsNil() {
				return ctx.ThrowError(errValue.Interface().(error))
			}
		}
		if len(outputs) == 0 {
			return ctx.NewUndefined()
		}
		return toJS(ctx, outputs[0])
	})
	defer function.Free()
	return setProperty(object, name, function)
}

func convertCallArguments(args []*quickjs.Value, functionType reflect.Type) ([]reflect.Value, error) {
	required := functionType.NumIn()
	if functionType.IsVariadic() {
		required--
		if len(args) < required {
			return nil, fmt.Errorf("expects at least %d arguments", required)
		}
	} else if len(args) != required {
		return nil, fmt.Errorf("expects %d arguments", required)
	}
	inputs := make([]reflect.Value, len(args))
	for i, arg := range args {
		var inputType reflect.Type
		if functionType.IsVariadic() && i >= required {
			inputType = functionType.In(required).Elem()
		} else {
			inputType = functionType.In(i)
		}
		input, err := toGo(arg, inputType)
		if err != nil {
			return nil, fmt.Errorf("argument %d: %w", i+1, err)
		}
		inputs[i] = input
	}
	return inputs, nil
}

func setProperty(object *quickjs.Value, name string, value *quickjs.Value) error {
	if value == nil {
		return fmt.Errorf("set %q: nil JavaScript value", name)
	}
	atom := value.Context().NewAtom(name)
	defer atom.Free()
	if ok := object.SetAtom(atom, value); !ok {
		return fmt.Errorf("set JavaScript property %q", name)
	}
	return nil
}

func (r *runtime) coerce(raw interface{}) (*quickjs.Value, bool, error) {
	if value, ok := raw.(value); ok {
		if value.runtime != r {
			return nil, false, fmt.Errorf("cannot mix QuickJS-Go realms")
		}
		return value.value, false, nil
	}
	if object, ok := raw.(*object); ok {
		if object.runtime != r {
			return nil, false, fmt.Errorf("cannot mix QuickJS-Go realms")
		}
		return object.value, false, nil
	}

	value := reflect.ValueOf(raw)
	if value.IsValid() && value.Kind() == reflect.Func {
		return bindFunction(r.ctx, value), true, nil
	}
	return toJS(r.ctx, value), true, nil
}

func bindFunction(ctx *quickjs.Context, function reflect.Value) *quickjs.Value {
	return ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		functionType := function.Type()
		inputs, err := convertCallArguments(args, functionType)
		if err != nil {
			return ctx.ThrowTypeError("%v", err)
		}
		outputs := function.Call(inputs)
		if len(outputs) > 0 && outputs[len(outputs)-1].Type() == errorType {
			errValue := outputs[len(outputs)-1]
			outputs = outputs[:len(outputs)-1]
			if !errValue.IsNil() {
				return ctx.ThrowError(errValue.Interface().(error))
			}
		}
		if len(outputs) == 0 {
			return ctx.NewUndefined()
		}
		return toJS(ctx, outputs[0])
	})
}

// ExposeDangerous exposes every exported field and method of target. It is
// reserved for seal.inst, whose use is guarded by the caller's explicit
// dangerous-exposure configuration.
func ExposeDangerous(engine jsengine.Runtime, target interface{}) (jsengine.Value, error) {
	r, ok := engine.(*runtime)
	if !ok {
		return nil, fmt.Errorf("QuickJS-Go runtime is required")
	}
	object, err := bindStructWithMode(r.ctx, reflect.ValueOf(target), true)
	if err != nil {
		return nil, err
	}
	r.objects = append(r.objects, object)
	return value{runtime: r, value: object}, nil
}

func toJS(ctx *quickjs.Context, value reflect.Value) *quickjs.Value {
	return toJSWithMode(ctx, value, false)
}

func toJSWithMode(ctx *quickjs.Context, value reflect.Value, dangerous bool) *quickjs.Value {
	if value.IsValid() && value.Kind() == reflect.Pointer && !value.IsNil() && value.Elem().Kind() == reflect.Struct {
		object, err := bindStructWithMode(ctx, value, dangerous)
		if err != nil {
			return ctx.NewUndefined()
		}
		return object
	}

	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return ctx.NewNull()
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return ctx.NewUndefined()
	}
	if value.Kind() == reflect.Struct {
		target := reflect.New(value.Type())
		target.Elem().Set(value)
		if dangerous && value.CanAddr() {
			target = value.Addr()
		}
		object, err := bindStructWithMode(ctx, target, dangerous)
		if err != nil {
			return ctx.NewUndefined()
		}
		return object
	}

	switch value.Kind() {
	case reflect.Bool:
		return ctx.NewBool(value.Bool())
	case reflect.String:
		return ctx.NewString(value.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return ctx.NewInt64(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return ctx.NewInt64(int64(value.Uint()))
	case reflect.Float32, reflect.Float64:
		return ctx.NewFloat64(value.Float())
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String || value.IsNil() {
			return ctx.NewUndefined()
		}
		return mapProxyWithMode(ctx, value, dangerous)
	case reflect.Slice:
		return sliceProxyWithMode(ctx, value, dangerous)
	default:
		return ctx.NewUndefined()
	}
}

func mapProxy(ctx *quickjs.Context, source reflect.Value) *quickjs.Value {
	return mapProxyWithMode(ctx, source, false)
}

func mapProxyWithMode(ctx *quickjs.Context, source reflect.Value, dangerous bool) *quickjs.Value {
	target := ctx.NewObject()
	handler := ctx.NewObject()
	if target == nil || handler == nil {
		if target != nil {
			target.Free()
		}
		if handler != nil {
			handler.Free()
		}
		return ctx.NewUndefined()
	}
	defer target.Free()
	defer handler.Free()

	getter := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		if len(args) < 2 || args[1].IsSymbol() {
			return ctx.NewUndefined()
		}
		item := source.MapIndex(reflect.ValueOf(args[1].ToString()).Convert(source.Type().Key()))
		if !item.IsValid() {
			return ctx.NewUndefined()
		}
		return toJSWithMode(ctx, item, dangerous)
	})
	defer getter.Free()
	if err := setProperty(handler, "get", getter); err != nil {
		return ctx.NewUndefined()
	}

	setter := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		if len(args) < 3 || args[1].IsSymbol() {
			return ctx.NewBool(false)
		}
		item, err := toGo(args[2], source.Type().Elem())
		if err != nil {
			return ctx.ThrowTypeError("map value: %v", err)
		}
		key := reflect.ValueOf(args[1].ToString()).Convert(source.Type().Key())
		source.SetMapIndex(key, item)
		return ctx.NewBool(true)
	})
	defer setter.Free()
	if err := setProperty(handler, "set", setter); err != nil {
		return ctx.NewUndefined()
	}

	ownKeys := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, _ []*quickjs.Value) *quickjs.Value {
		encoded, err := json.Marshal(mapKeys(source))
		if err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.ParseJSON(string(encoded))
	})
	defer ownKeys.Free()
	if err := setProperty(handler, "ownKeys", ownKeys); err != nil {
		return ctx.NewUndefined()
	}

	descriptor := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		if len(args) < 2 || args[1].IsSymbol() {
			return ctx.NewUndefined()
		}
		key := reflect.ValueOf(args[1].ToString()).Convert(source.Type().Key())
		if !source.MapIndex(key).IsValid() {
			return ctx.NewUndefined()
		}
		result := ctx.NewObject()
		enumerable := ctx.NewBool(true)
		defer enumerable.Free()
		configurable := ctx.NewBool(true)
		defer configurable.Free()
		if err := setProperty(result, "enumerable", enumerable); err != nil {
			result.Free()
			return ctx.NewUndefined()
		}
		if err := setProperty(result, "configurable", configurable); err != nil {
			result.Free()
			return ctx.NewUndefined()
		}
		return result
	})
	defer descriptor.Free()
	if err := setProperty(handler, "getOwnPropertyDescriptor", descriptor); err != nil {
		return ctx.NewUndefined()
	}

	proxy := ctx.NewProxy(target, handler)
	if proxy == nil {
		return ctx.NewUndefined()
	}
	return proxy
}

func mapKeys(source reflect.Value) []string {
	keys := make([]string, 0, source.Len())
	iterator := source.MapRange()
	for iterator.Next() {
		keys = append(keys, iterator.Key().String())
	}
	sort.Strings(keys)
	return keys
}

func sliceProxy(ctx *quickjs.Context, source reflect.Value) *quickjs.Value {
	return sliceProxyWithMode(ctx, source, false)
}

func sliceProxyWithMode(ctx *quickjs.Context, source reflect.Value, dangerous bool) *quickjs.Value {
	target := ctx.NewObject()
	handler := ctx.NewObject()
	if target == nil || handler == nil {
		if target != nil {
			target.Free()
		}
		if handler != nil {
			handler.Free()
		}
		return ctx.NewUndefined()
	}
	defer target.Free()
	defer handler.Free()

	getter := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		if len(args) < 2 || args[1].IsSymbol() {
			return ctx.NewUndefined()
		}
		key := args[1].ToString()
		switch key {
		case "length":
			return ctx.NewInt64(int64(source.Len()))
		case "push":
			return ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
				if !source.CanSet() {
					return ctx.ThrowTypeError("slice is read-only")
				}
				for _, arg := range args {
					item, err := toGo(arg, source.Type().Elem())
					if err != nil {
						return ctx.ThrowTypeError("slice value: %v", err)
					}
					source.Set(reflect.Append(source, item))
				}
				return ctx.NewInt64(int64(source.Len()))
			})
		}
		index, err := strconv.Atoi(key)
		if err != nil || index < 0 || index >= source.Len() {
			return ctx.NewUndefined()
		}
		return toJSWithMode(ctx, source.Index(index), dangerous)
	})
	defer getter.Free()
	if err := setProperty(handler, "get", getter); err != nil {
		return ctx.NewUndefined()
	}

	setter := ctx.NewFunction(func(ctx *quickjs.Context, _ *quickjs.Value, args []*quickjs.Value) *quickjs.Value {
		if len(args) < 3 || args[1].IsSymbol() {
			return ctx.NewBool(false)
		}
		index, err := strconv.Atoi(args[1].ToString())
		if err != nil || index < 0 || !source.CanSet() {
			return ctx.NewBool(false)
		}
		for range index - source.Len() + 1 {
			source.Set(reflect.Append(source, reflect.Zero(source.Type().Elem())))
		}
		if err := assignJS(source.Index(index), args[2]); err != nil {
			return ctx.ThrowTypeError("slice value: %v", err)
		}
		return ctx.NewBool(true)
	})
	defer setter.Free()
	if err := setProperty(handler, "set", setter); err != nil {
		return ctx.NewUndefined()
	}

	proxy := ctx.NewProxy(target, handler)
	if proxy == nil {
		return ctx.NewUndefined()
	}
	return proxy
}

func assignJS(destination reflect.Value, source *quickjs.Value) error {
	if !destination.CanSet() {
		return fmt.Errorf("read-only")
	}

	switch destination.Kind() {
	case reflect.Bool:
		destination.SetBool(source.ToBool())
	case reflect.String:
		destination.SetString(source.ToString())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		destination.SetInt(source.ToInt64())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		destination.SetUint(uint64(source.ToInt64()))
	case reflect.Float32, reflect.Float64:
		destination.SetFloat(source.ToFloat64())
	case reflect.Func:
		callback, err := toGo(source, destination.Type())
		if err != nil {
			return err
		}
		destination.Set(callback)
	default:
		return fmt.Errorf("unsupported %s", destination.Type())
	}
	return nil
}

func registerHostValue(ctx *quickjs.Context, target reflect.Value) uint64 {
	identity := hostIdentity{typeOf: target.Type(), pointer: target.Pointer()}

	hostValues.Lock()
	defer hostValues.Unlock()
	if hostValues.values == nil {
		hostValues.values = make(map[uint64]reflect.Value)
		hostValues.contexts = make(map[*quickjs.Context]map[uint64]struct{})
		hostValues.identities = make(map[*quickjs.Context]map[hostIdentity]uint64)
	}
	if id, ok := hostValues.identities[ctx][identity]; ok {
		return id
	}

	hostValues.next++
	id := hostValues.next
	hostValues.values[id] = target
	if hostValues.contexts[ctx] == nil {
		hostValues.contexts[ctx] = make(map[uint64]struct{})
		hostValues.identities[ctx] = make(map[hostIdentity]uint64)
	}
	hostValues.contexts[ctx][id] = struct{}{}
	hostValues.identities[ctx][identity] = id
	return id
}

func attachHostValue(ctx *quickjs.Context, object *quickjs.Value, id uint64) error {
	value := ctx.NewInt64(int64(id))
	defer value.Free()
	if ok := object.DefinePropertyValue(hostValueIDKey, value, quickjs.PropHasValue); !ok {
		return fmt.Errorf("define Host API identity")
	}
	return nil
}

func cachedHostObject(ctx *quickjs.Context, id uint64) (*quickjs.Value, error) {
	store, err := hostObjectStore(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Free()
	object := store.Get(strconv.FormatUint(id, 10))
	if object == nil || object.IsUndefined() {
		if object != nil {
			object.Free()
		}
		return nil, nil
	}
	return object, nil
}

func cacheHostObject(ctx *quickjs.Context, id uint64, object *quickjs.Value) error {
	store, err := hostObjectStore(ctx)
	if err != nil {
		return err
	}
	defer store.Free()
	return setProperty(store, strconv.FormatUint(id, 10), object)
}

func hostObjectStore(ctx *quickjs.Context) (*quickjs.Value, error) {
	store := ctx.Globals().Get(hostObjectStoreKey)
	if store != nil && !store.IsUndefined() && !store.IsNull() {
		return store, nil
	}
	if store != nil {
		store.Free()
	}

	store = ctx.NewObject()
	if store == nil {
		return nil, errorsNew("create QuickJS host object store")
	}
	if err := setProperty(ctx.Globals(), hostObjectStoreKey, store); err != nil {
		store.Free()
		return nil, err
	}
	return store, nil
}

func hostValue(value *quickjs.Value) (reflect.Value, bool) {
	if value == nil || !value.IsObject() {
		return reflect.Value{}, false
	}
	idValue := value.Get(hostValueIDKey)
	if idValue == nil {
		return reflect.Value{}, false
	}
	defer idValue.Free()
	if !idValue.IsNumber() {
		return reflect.Value{}, false
	}

	hostValues.Lock()
	defer hostValues.Unlock()
	host, ok := hostValues.values[uint64(idValue.ToInt64())]
	return host, ok
}

func releaseHostValues(ctx *quickjs.Context) {
	hostValues.Lock()
	defer hostValues.Unlock()
	for id := range hostValues.contexts[ctx] {
		delete(hostValues.values, id)
	}
	delete(hostValues.contexts, ctx)
	delete(hostValues.identities, ctx)
}

func newCallback(source *quickjs.Value, target reflect.Type) (reflect.Value, error) {
	if source == nil || !source.IsFunction() {
		return reflect.Value{}, fmt.Errorf("expected JavaScript function")
	}
	loop, ok := loopsByContext.Load(source.Context())
	if !ok {
		return reflect.Value{}, fmt.Errorf("QuickJS-Go callback context is closed")
	}
	callbackLoop := loop.(*runtimeLoop)
	id, err := callbackLoop.registerCallback(source)
	if err != nil {
		return reflect.Value{}, err
	}

	return reflect.MakeFunc(target, func(inputs []reflect.Value) []reflect.Value {
		outputs, err := callbackLoop.callCallback(id, target, inputs)
		if err == nil {
			return outputs
		}

		results := make([]reflect.Value, target.NumOut())
		for index := range results {
			results[index] = reflect.Zero(target.Out(index))
		}
		if target.NumOut() > 0 && target.Out(target.NumOut()-1) == errorType {
			results[target.NumOut()-1] = reflect.ValueOf(err)
			return results
		}
		panic(err)
	}), nil
}

func (r *runtimeLoop) registerCallback(source *quickjs.Value) (string, error) {
	r.nextCallback++
	id := strconv.FormatUint(r.nextCallback, 10)
	store, err := callbackStore(source.Context())
	if err != nil {
		return "", err
	}
	defer store.Free()
	if err := setProperty(store, id, source); err != nil {
		return "", err
	}
	return id, nil
}

func callbackStore(ctx *quickjs.Context) (*quickjs.Value, error) {
	store := ctx.Globals().Get(callbackStoreKey)
	if store != nil && !store.IsUndefined() && !store.IsNull() {
		return store, nil
	}
	if store != nil {
		store.Free()
	}

	store = ctx.NewObject()
	if store == nil {
		return nil, errorsNew("create QuickJS callback store")
	}
	if err := setProperty(ctx.Globals(), callbackStoreKey, store); err != nil {
		store.Free()
		return nil, err
	}
	return store, nil
}

func (r *runtimeLoop) callCallback(id string, functionType reflect.Type, inputs []reflect.Value) ([]reflect.Value, error) {
	if len(inputs) > 0 && inputs[0].Type() == runtimeType {
		if runtime, ok := inputs[0].Interface().(*runtime); ok && runtime.loop == r {
			return runtime.callCallback(id, functionType, inputs)
		}
	}

	var outputs []reflect.Value
	err := r.Run(func(current jsengine.Runtime) error {
		var err error
		outputs, err = current.(*runtime).callCallback(id, functionType, inputs)
		return err
	})
	return outputs, err
}

func (r *runtime) callCallback(id string, functionType reflect.Type, inputs []reflect.Value) ([]reflect.Value, error) {
	store, err := callbackStore(r.ctx)
	if err != nil {
		return nil, err
	}
	defer store.Free()

	callback := store.Get(id)
	if callback == nil {
		return nil, fmt.Errorf("JavaScript callback %s is unavailable", id)
	}
	defer callback.Free()
	if !callback.IsFunction() {
		return nil, fmt.Errorf("JavaScript callback %s is not callable", id)
	}

	inputOffset := 0
	if len(inputs) > 0 && inputs[0].Type() == runtimeType {
		inputOffset = 1
	}
	args := make([]*quickjs.Value, len(inputs)-inputOffset)
	for i := inputOffset; i < len(inputs); i++ {
		args[i-inputOffset] = toJS(r.ctx, inputs[i])
		defer args[i-inputOffset].Free()
	}
	this := r.ctx.NewUndefined()
	defer this.Free()
	result := callback.Execute(this, args...)
	if result == nil {
		return nil, errorsNew("execute JavaScript callback")
	}
	releaseResult := true
	defer func() {
		if releaseResult {
			result.Free()
		}
	}()
	if result.IsException() {
		err := r.ctx.Exception()
		if err == nil {
			err = errorsNew("JavaScript callback failed")
		}
		return nil, err
	}

	resultCount := functionType.NumOut()
	hasError := resultCount > 0 && functionType.Out(resultCount-1) == errorType
	if hasError {
		resultCount--
	}
	if resultCount > 1 {
		return nil, fmt.Errorf("unsupported JavaScript callback result count %d", resultCount)
	}
	outputs := make([]reflect.Value, functionType.NumOut())
	if resultCount == 1 {
		if functionType.Out(0) == jsengineValueType {
			r.values = append(r.values, result)
			releaseResult = false
			outputs[0] = reflect.ValueOf(value{runtime: r, value: result})
		} else {
			output, err := toGo(result, functionType.Out(0))
			if err != nil {
				return nil, err
			}
			outputs[0] = output
		}
	}
	if hasError {
		outputs[len(outputs)-1] = reflect.Zero(errorType)
	}
	return outputs, nil
}

func toGo(value *quickjs.Value, target reflect.Type) (reflect.Value, error) {
	if target.Kind() == reflect.Pointer {
		if host, ok := hostValue(value); ok {
			if host.Type().AssignableTo(target) {
				return host, nil
			}
			if host.Type().ConvertibleTo(target) {
				return host.Convert(target), nil
			}
		}
		return reflect.Value{}, fmt.Errorf("expected %s Host API object", target)
	}

	if target.Kind() == reflect.Func {
		return newCallback(value, target)
	}
	result := reflect.New(target).Elem()
	switch target.Kind() {
	case reflect.Bool:
		result.SetBool(value.ToBool())
	case reflect.String:
		result.SetString(value.ToString())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		result.SetInt(value.ToInt64())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		result.SetUint(uint64(value.ToInt64()))
	case reflect.Float32, reflect.Float64:
		result.SetFloat(value.ToFloat64())
	default:
		return reflect.Value{}, fmt.Errorf("unsupported %s", target)
	}
	return result, nil
}

func isIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		ch := name[i]
		if i == 0 {
			if !isIdentifierStart(ch) {
				return false
			}
			continue
		}
		if !isIdentifierStart(ch) && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

func isIdentifierStart(ch byte) bool {
	return ch == '$' || ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

func lowerFirst(name string) string {
	return strings.ToLower(name[:1]) + name[1:]
}

func valueInterface(value reflect.Value) interface{} {
	if !value.IsValid() {
		return nil
	}
	return value.Interface()
}

func errorsNew(message string) error {
	return fmt.Errorf("%s", message)
}
