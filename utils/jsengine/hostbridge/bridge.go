package hostbridge

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var errorType = reflect.TypeFor[error]()

func (s *Session) BindObject(target any) (HostRef, error) { return s.RegisterObject(target) }
func (s *Session) ExposeDangerous(target any) (HostRef, error) {
	return s.registerObject(target, true)
}

func (s *Session) Get(ref HostRef, name string) (Value, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil { return UndefinedValue(), err }
	obj := entry.value
	if obj.Kind() == reflect.Map { return s.mapGet(obj, name) }
	if obj.Kind() == reflect.Slice { return s.sliceGet(ref, obj, name) }
	if obj.Kind() == reflect.Pointer && obj.Elem().Kind() == reflect.Struct {
		field, lock, ok, err := s.structFieldMode(obj, name, entry.dangerous)
		if err != nil { return UndefinedValue(), err }
		if ok {
			if lock != nil { lock.RLock(); defer lock.RUnlock() }
			return s.toValue(field)
		}
		if method, ok := obj.Type().MethodByName(exportedMethod(name)); ok {
			function, err := s.registerOperation(ref, method.Name); if err != nil { return UndefinedValue(), err }
			return HostFunctionValue(function), nil
		}
	}
	return UndefinedValue(), nil
}

// HostFunctionValueForMethod is a marker useful to adapters inspecting a
// method property. Call still takes the owning HostRef and method name.
func HostFunctionValueForMethod(_ HostRef, _ string) Value { return Value{Kind: KindHostFunction} }

func (s *Session) Set(ref HostRef, name string, value Value) error {
	return s.set(ref, name, value, nil)
}
func (s *Session) SetWithCodec(ref HostRef, name string, value Value, codec RuntimeValueCodec) error {
	return s.set(ref, name, value, codec)
}
func (s *Session) set(ref HostRef, name string, value Value, codec RuntimeValueCodec) error {
	entry, err := s.lookupEntry(ref); if err != nil { return err }
	obj := entry.value
	if obj.Kind() == reflect.Map {
		if obj.IsNil() { return errors.New("nil map") }
		item, err := s.toGo(value, obj.Type().Elem(), codec); if err != nil { return fmt.Errorf("map value: %w", err) }
		obj.SetMapIndex(reflect.ValueOf(name).Convert(obj.Type().Key()), item); return nil
	}
	if obj.Kind() == reflect.Slice { return s.sliceSet(obj, name, value, codec) }
	if obj.Kind() == reflect.Pointer && obj.Elem().Kind() == reflect.Struct {
		field, lock, ok, err := s.structFieldMode(obj, name, entry.dangerous); if err != nil { return err }; if !ok { return fmt.Errorf("HostRef %d has no writable property %q", ref, name) }
		if lock != nil { lock.Lock(); defer lock.Unlock() }
		if !field.CanSet() { return fmt.Errorf("%s: read-only", name) }
		converted, err := s.toGo(value, field.Type(), codec); if err != nil { return fmt.Errorf("%s: %w", name, err) }; field.Set(converted); return nil
	}
	return fmt.Errorf("unsupported HostRef %d", ref)
}

func (s *Session) Has(ref HostRef, name string) (bool, error) {
	entry, err := s.lookupEntry(ref); if err != nil { return false, err }
	obj := entry.value
	switch obj.Kind() {
	case reflect.Map:
		return obj.MapIndex(reflect.ValueOf(name).Convert(obj.Type().Key())).IsValid(), nil
	case reflect.Slice:
		if name == "length" || name == "push" { return true, nil }; i, e := strconv.Atoi(name); return e == nil && i >= 0 && i < obj.Len(), nil
	case reflect.Pointer:
		if obj.Elem().Kind() == reflect.Struct { _, _, ok, err := s.structFieldMode(obj, name, entry.dangerous); if err != nil { return false, err }; if ok { return true, nil }; _, ok = obj.Type().MethodByName(exportedMethod(name)); return ok, nil }
	}
	return false, nil
}

func (s *Session) Delete(ref HostRef, name string) (bool, error) {
	obj, err := s.LookupObject(ref); if err != nil { return false, err }
	if obj.Kind() == reflect.Map { obj.SetMapIndex(reflect.ValueOf(name).Convert(obj.Type().Key()), reflect.Value{}); return true, nil }
	return false, nil
}

func (s *Session) Keys(ref HostRef) ([]string, error) {
	entry, err := s.lookupEntry(ref); if err != nil { return nil, err }
	obj := entry.value
	if obj.Kind() == reflect.Map { keys := make([]string, 0, obj.Len()); it := obj.MapRange(); for it.Next() { keys = append(keys, it.Key().String()) }; sort.Strings(keys); return keys, nil }
	if obj.Kind() == reflect.Slice { keys := make([]string, obj.Len()); for i := range keys { keys[i] = strconv.Itoa(i) }; return keys, nil }
	if obj.Kind() == reflect.Pointer && obj.Elem().Kind() == reflect.Struct {
		typ := obj.Elem().Type(); seen := map[string]bool{}; keys := []string{}
		for _, field := range reflect.VisibleFields(typ) { names := []string{}; if entry.dangerous { names = dangerousBindNames(field) } else if n, ok := jsBindName(field); ok { names = []string{n} }; for _, n := range names { if !seen[n] { keys = append(keys, n); seen[n] = true } } }
		for i := range obj.Type().NumMethod() { n := lowerFirst(obj.Type().Method(i).Name); if !seen[n] && isIdentifier(n) { keys = append(keys, n) } }
		sort.Strings(keys); return keys, nil
	}
	return nil, fmt.Errorf("unsupported HostRef %d", ref)
}

func (s *Session) Call(ref HostRef, name string, args []Value) (Value, error) { return s.call(ref, name, args, nil) }
func (s *Session) CallWithCodec(ref HostRef, name string, args []Value, codec RuntimeValueCodec) (Value, error) { return s.call(ref, name, args, codec) }
func (s *Session) call(ref HostRef, name string, args []Value, codec RuntimeValueCodec) (result Value, err error) {
	obj, err := s.LookupObject(ref); if err != nil { return UndefinedValue(), err }
	if obj.Kind() == reflect.Slice && name == "push" { var n int64 = int64(obj.Len()); for _, arg := range args { item, e := s.toGo(arg, obj.Type().Elem(), codec); if e != nil { return UndefinedValue(), fmt.Errorf("slice value: %w", e) }; if !obj.CanSet() { return UndefinedValue(), errors.New("slice is read-only") }; obj.Set(reflect.Append(obj, item)); n++ }; return IntValue(n), nil }
	if obj.Kind() != reflect.Pointer || obj.Elem().Kind() != reflect.Struct { return UndefinedValue(), fmt.Errorf("HostRef %d has no callable property %q", ref, name) }
	method, ok := obj.Type().MethodByName(exportedMethod(name)); if !ok { return UndefinedValue(), fmt.Errorf("HostRef %d has no callable property %q", ref, name) }
	return s.callReflect(method.Func, append([]Value{HostObjectValue(ref)}, args...), name, codec, true)
}

func (s *Session) CallFunction(ref HostFuncRef, args []Value) (Value, error) { return s.CallFunctionWithCodec(ref, args, nil) }
func (s *Session) CallFunctionWithCodec(ref HostFuncRef, args []Value, codec RuntimeValueCodec) (Value, error) {
	entry, err := s.lookupFunctionEntry(ref); if err != nil { return UndefinedValue(), err }
	if entry.operation != "" { return s.call(entry.owner, entry.operation, args, codec) }
	if !entry.value.IsValid() { return s.call(entry.owner, "push", args, codec) }
	return s.callReflect(entry.value, args, "function", codec, false)
}
func (s *Session) callReflect(fn reflect.Value, args []Value, label string, codec RuntimeValueCodec, receiver bool) (result Value, err error) {

	defer func() { if p := recover(); p != nil { result = UndefinedValue(); err = fmt.Errorf("%s panic: %v", label, p) } }()
	ft := fn.Type(); offset := 0; if receiver { offset = 1 }
	inputs := make([]reflect.Value, 0, len(args)-offset)
	required := ft.NumIn() - offset
	if ft.IsVariadic() { if len(args)-offset < required-1 { return UndefinedValue(), fmt.Errorf("%s expects at least %d arguments", label, required-1) } } else if len(args)-offset != required { return UndefinedValue(), fmt.Errorf("%s expects %d arguments", label, required) }
	for i := offset; i < len(args); i++ { idx := i-offset; target := ft.In(offset+idx); if ft.IsVariadic() && offset+idx >= ft.NumIn()-1 { target = ft.In(ft.NumIn()-1).Elem() }; in, e := s.toGo(args[i], target, codec); if e != nil { return UndefinedValue(), fmt.Errorf("argument %d: %w", idx+1, e) }; inputs = append(inputs, in) }
	callInputs := inputs; if offset > 0 { callInputs = append([]reflect.Value{argsToReceiver(args[0], ft.In(0), s)}, inputs...) }
	outs := fn.Call(callInputs); return s.outputs(outs)
}
func (s *Session) structField(obj reflect.Value, name string) (reflect.Value, *sync.RWMutex, bool, error) {
	return s.structFieldMode(obj, name, false)
}
func (s *Session) structFieldMode(obj reflect.Value, name string, dangerous bool) (reflect.Value, *sync.RWMutex, bool, error) {
	for _, def := range reflect.VisibleFields(obj.Elem().Type()) {
		names := []string{}
		if dangerous { names = dangerousBindNames(def) } else if n, ok := jsBindName(def); ok { names = []string{n} }
		for _, n := range names {
			if n != name { continue }
			field := hostFieldByIndex(obj.Elem(), def.Index)
			if !field.IsValid() { return reflect.Value{}, nil, false, fmt.Errorf("invalid field %q", name) }
			lock, err := fieldLock(obj, def)
			return field, lock, true, err
		}
	}
	return reflect.Value{}, nil, false, nil
}
func argsAreReceiver(args []Value, typ reflect.Type) bool { return len(args) > 0 && args[0].Kind == KindHostObject && typ.Kind() == reflect.Pointer }
func argsToReceiver(v Value, typ reflect.Type, s *Session) reflect.Value {
	r, err := s.LookupObject(v.Host)
	if err != nil { return reflect.Zero(typ) }
	if r.Type().AssignableTo(typ) { return r }
	if r.Type().ConvertibleTo(typ) { return r.Convert(typ) }
	return reflect.Zero(typ)
}
func dangerousBindNames(field reflect.StructField) []string {
	if field.PkgPath != "" || field.Name == "JsSealInstExposed" { return nil }
	names := []string{field.Name, lowerFirst(field.Name)}
	for _, tag := range []string{field.Tag.Get("jsbind"), field.Tag.Get("json")} {
		if n := strings.Split(tag, ",")[0]; n != "" && n != "-" { names = append(names, n) }
	}
	seen := map[string]bool{}; result := []string{}
	for _, n := range names { if isIdentifier(n) && !seen[n] { seen[n] = true; result = append(result, n) } }
	return result
}
func (s *Session) outputs(outs []reflect.Value) (Value, error) { if len(outs) > 0 && outs[len(outs)-1].Type() == errorType { e := outs[len(outs)-1]; outs = outs[:len(outs)-1]; if !e.IsNil() { return UndefinedValue(), e.Interface().(error) } }; if len(outs) == 0 { return UndefinedValue(), nil }; return s.toValue(outs[0]) }

func fieldLock(obj reflect.Value, def reflect.StructField) (*sync.RWMutex, error) { name := def.Tag.Get("jsbindlock"); if name == "" { return nil, nil }; method := obj.MethodByName(name); if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 { return nil, fmt.Errorf("invalid jsbindlock %q on %s", name, def.Name) }; out := method.Call(nil)[0]; lock, ok := out.Interface().(*sync.RWMutex); if !ok || lock == nil { return nil, fmt.Errorf("jsbindlock %q on %s must return *sync.RWMutex", name, def.Name) }; return lock, nil }
func hostFieldByIndex(value reflect.Value, index []int) reflect.Value { for _, i := range index { for value.Kind() == reflect.Pointer { if value.IsNil() { return reflect.Value{} }; value = value.Elem() }; if value.Kind() != reflect.Struct { return reflect.Value{} }; value = value.Field(i) }; return value }
func jsBindName(field reflect.StructField) (string, bool) { if field.PkgPath != "" { return "", false }; tag, ok := field.Tag.Lookup("jsbind"); if !ok || tag == "-" { return "", false }; n := strings.Split(tag, ",")[0]; return n, isIdentifier(n) }
func exportedMethod(name string) string { if name == "" { return "" }; return strings.ToUpper(name[:1]) + name[1:] }
func isIdentifier(name string) bool { if name == "" { return false }; for i, c := range name { if i == 0 && !(c == '_' || c == '$' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') { return false }; if i > 0 && !(c == '_' || c == '$' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') { return false } }; return true }
func lowerFirst(name string) string { if name == "" { return "" }; return strings.ToLower(name[:1]) + name[1:] }

func (s *Session) toValue(v reflect.Value) (Value, error) {
	for v.IsValid() && v.Kind() == reflect.Interface { if v.IsNil() { return NullValue(), nil }; v = v.Elem() }
	if !v.IsValid() { return UndefinedValue(), nil }
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && v.IsNil() { return NullValue(), nil }
	switch v.Kind() {
	case reflect.Bool: return BoolValue(v.Bool()), nil
	case reflect.String: return StringValue(v.String()), nil
	case reflect.Func:
		ref, err := s.RegisterFunction(v.Interface()); if err != nil { return UndefinedValue(), err }; return HostFunctionValue(ref), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64: return IntValue(v.Int()), nil
	case reflect.Float32, reflect.Float64: return FloatValue(v.Float()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr: return UintValue(v.Uint()), nil
	case reflect.Pointer, reflect.Struct, reflect.Map, reflect.Slice:
		ref, err := s.RegisterObject(v.Interface()); if err != nil { return UndefinedValue(), err }; return HostObjectValue(ref), nil
	default: return UndefinedValue(), fmt.Errorf("unsupported %s", v.Type())
	}
}
func (s *Session) toGo(v Value, target reflect.Type, codec RuntimeValueCodec) (reflect.Value, error) {
	if v.Kind == KindNull || v.Kind == KindUndefined {
		switch target.Kind() { case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface: return reflect.Zero(target), nil }
	}
	if target.Kind() == reflect.Interface {
		if v.Kind == KindHostObject {
			obj, err := s.LookupObject(v.Host); if err != nil { return reflect.Value{}, err }
			return obj, nil
		}
		switch v.Kind { case KindNull, KindUndefined: return reflect.Zero(target), nil; default: raw, err := s.valuePrimitive(v); if err != nil { return reflect.Value{}, err }; return reflect.ValueOf(raw), nil }
	}
	if target.Kind() == reflect.Pointer || target.Kind() == reflect.Map || target.Kind() == reflect.Slice {
		if v.Kind != KindHostObject { return reflect.Value{}, fmt.Errorf("expected %s Host API object", target) }; obj, err := s.LookupObject(v.Host); if err != nil { return reflect.Value{}, err }; if obj.Type().AssignableTo(target) { return obj, nil }; if obj.Type().ConvertibleTo(target) { return obj.Convert(target), nil }; return reflect.Value{}, fmt.Errorf("expected %s Host API object", target)
	}
	if target.Kind() == reflect.Func { if codec == nil { return reflect.Value{}, errors.New("JavaScript callback codec is required") }; return codec.Decode(v, target) }
	out := reflect.New(target).Elem(); switch target.Kind() {
	case reflect.Bool: if v.Kind != KindBool { return reflect.Value{}, fmt.Errorf("expected bool") }; out.SetBool(v.Bool)
	case reflect.String: if v.Kind != KindString { return reflect.Value{}, fmt.Errorf("expected string") }; out.SetString(v.String)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Kind == KindInt { out.SetInt(v.Int) } else if v.Kind == KindUint && v.Uint <= uint64(1)<<(target.Bits()-1)-1 { out.SetInt(int64(v.Uint)) } else { return reflect.Value{}, fmt.Errorf("expected integer") }
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if v.Kind == KindUint { out.SetUint(v.Uint) } else if v.Kind == KindInt && v.Int >= 0 { out.SetUint(uint64(v.Int)) } else { return reflect.Value{}, fmt.Errorf("expected unsigned integer") }
	case reflect.Float32, reflect.Float64:
		if v.Kind == KindFloat { out.SetFloat(v.Float) } else if v.Kind == KindInt { out.SetFloat(float64(v.Int)) } else if v.Kind == KindUint { out.SetFloat(float64(v.Uint)) } else { return reflect.Value{}, fmt.Errorf("expected number") }
	default: return reflect.Value{}, fmt.Errorf("unsupported %s", target)
	}; return out, nil
}
func (s *Session) valuePrimitive(v Value) (any, error) { switch v.Kind { case KindBool: return v.Bool, nil; case KindString: return v.String, nil; case KindInt: return v.Int, nil; case KindUint: return v.Uint, nil; case KindFloat: return v.Float, nil; case KindNull, KindUndefined: return nil, nil; default: return nil, fmt.Errorf("cannot convert kind %d", v.Kind) } }

func (s *Session) mapGet(obj reflect.Value, name string) (Value, error) { item := obj.MapIndex(reflect.ValueOf(name).Convert(obj.Type().Key())); if !item.IsValid() { return UndefinedValue(), nil }; return s.toValue(item) }
func (s *Session) sliceGet(ref HostRef, obj reflect.Value, name string) (Value, error) {
	if name == "length" { return IntValue(int64(obj.Len())), nil }
	if name == "push" { function, err := s.registerOperation(ref, "push"); if err != nil { return UndefinedValue(), err }; return HostFunctionValue(function), nil }
	i, err := strconv.Atoi(name); if err != nil || i < 0 || i >= obj.Len() { return UndefinedValue(), nil }; return s.toValue(obj.Index(i))
}
func (s *Session) sliceSet(obj reflect.Value, name string, v Value, codec RuntimeValueCodec) error {
	if !obj.CanSet() { return errors.New("slice is read-only") }
	i, err := strconv.Atoi(name); if err != nil || i < 0 { return fmt.Errorf("invalid slice index %q", name) }
	for obj.Len() <= i { obj.Set(reflect.Append(obj, reflect.Zero(obj.Type().Elem()))) }
	item, err := s.toGo(v, obj.Type().Elem(), codec); if err != nil { return err }; obj.Index(i).Set(item); return nil
}

// Callback creates a generation-checked reflect trampoline from an explicit
// runtime codec. Calls after Teardown return the declared error or panic when
// the function has no error result, matching normal Go callback conventions.
func (s *Session) Callback(codec RuntimeValueCodec, source Value, target reflect.Type) (reflect.Value, error) {
	if codec == nil { return reflect.Value{}, errors.New("nil callback codec") }; if source.Kind != KindCallback { return reflect.Value{}, errors.New("expected JavaScript callback value") }; if target.Kind() != reflect.Func { return reflect.Value{}, errors.New("callback target must be func") }
	fn, err := codec.Decode(source, target); if err != nil { return reflect.Value{}, err }; generation := s.Generation()
	return reflect.MakeFunc(target, func(inputs []reflect.Value) []reflect.Value {
		if s.Generation() != generation { return staleResults(target) }
		return fn.Call(inputs)
	}), nil
}
func staleResults(target reflect.Type) []reflect.Value { result := make([]reflect.Value, target.NumOut()); for i := range result { result[i] = reflect.Zero(target.Out(i)) }; if len(result) > 0 && target.Out(len(result)-1) == errorType { result[len(result)-1] = reflect.ValueOf(ErrStaleRuntimeCallback) } else { panic(ErrStaleRuntimeCallback) }; return result }
