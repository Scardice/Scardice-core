package hostbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	errorType            = reflect.TypeFor[error]()
	ErrInvalidSliceIndex = errors.New("invalid slice index")
	ErrNoPrimitiveValue  = errors.New("host value has no primitive representation")
)

// callbackHandoff lets codecs keep decoded callbacks provisional until the
// bridge actually gives them to Go. Each commit covers only values decoded
// since the prior commit, so a partially successful slice push keeps its prefix.
type callbackHandoff interface {
	CommitCallbacks()
}

func commitCallbacks(codec RuntimeValueCodec) {
	if handoff, ok := codec.(callbackHandoff); ok {
		handoff.CommitCallbacks()
	}
}

func (s *Session) BindObject(target any) (HostRef, error) { return s.RegisterObject(target) }
func (s *Session) ExposeDangerous(target any) (HostRef, error) {
	return s.registerObject(target, true)
}

func (s *Session) Get(ref HostRef, name string) (Value, error) {
	return s.get(ref, name, nil)
}

func (s *Session) GetWithCodec(ref HostRef, name string, codec RuntimeValueCodec) (Value, error) {
	return s.get(ref, name, codec)
}

func (s *Session) get(ref HostRef, name string, codec RuntimeValueCodec) (Value, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return UndefinedValue(), err
	}
	if entry.controlled != nil {
		raw, exists, err := entry.controlled.HostGet(name)
		if err != nil {
			return UndefinedValue(), err
		}
		if !exists {
			return UndefinedValue(), nil
		}
		// A controlled function is an operation of its owner: one live entry
		// per owner and name, released with the owner's last proxy, and
		// resolved through HostGet again at call time.
		if fn := reflect.ValueOf(raw); fn.IsValid() && fn.Kind() == reflect.Func && !fn.IsNil() {
			function, opErr := s.registerOperation(ref, name)
			if opErr != nil {
				return UndefinedValue(), opErr
			}
			return HostFunctionValue(function), nil
		}
		return s.encodeAny(raw, false, codec)
	}
	obj := entry.value
	if obj.Kind() == reflect.Map {
		return s.mapGet(obj, name, entry.dangerous, codec)
	}
	if obj.Kind() == reflect.Slice {
		return s.sliceGet(ref, obj, name, entry.dangerous, codec)
	}
	if obj.Kind() == reflect.Pointer && obj.Elem().Kind() == reflect.Struct {
		field, lock, ok, err := s.structFieldMode(obj, name, entry.dangerous)
		if err != nil {
			return UndefinedValue(), err
		}
		if ok {
			if lock != nil {
				lock.RLock()
				defer lock.RUnlock()
			}
			return s.encodeReflect(field, entry.dangerous, codec)
		}
		if method, ok := obj.Type().MethodByName(exportedMethod(name)); ok {
			function, err := s.registerOperation(ref, method.Name)
			if err != nil {
				return UndefinedValue(), err
			}
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

// SetRuntimeNative lets a runtime store an engine-native value directly into a
// struct field whose declared type only that runtime can represent (for
// example a live Goja value). accept receives the field type and reports
// whether the runtime owns it; when it does not, nothing is written and the
// caller falls back to the portable SetWithCodec path.
func (s *Session) SetRuntimeNative(ref HostRef, name string, accept func(reflect.Type) (reflect.Value, bool, error)) (bool, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return false, err
	}
	if entry.controlled != nil {
		return false, nil
	}
	obj := entry.value
	if obj.Kind() != reflect.Pointer || obj.IsNil() || obj.Elem().Kind() != reflect.Struct {
		return false, nil
	}
	field, lock, ok, err := s.structFieldMode(obj, name, entry.dangerous)
	if err != nil || !ok {
		return false, err
	}
	if !field.CanSet() {
		return false, nil
	}
	converted, owned, err := accept(field.Type())
	if err != nil || !owned {
		return false, err
	}
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	field.Set(converted)
	return true, nil
}

// GetRuntimeNative is the read counterpart of SetRuntimeNative. accept runs
// while the field lock is held and may return an engine-native value so a live
// runtime object is handed back unchanged instead of a portable snapshot.
func (s *Session) GetRuntimeNative(ref HostRef, name string, accept func(reflect.Value) (any, bool, error)) (any, bool, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return nil, false, err
	}
	if entry.controlled != nil {
		return nil, false, nil
	}
	obj := entry.value
	if obj.Kind() != reflect.Pointer || obj.IsNil() || obj.Elem().Kind() != reflect.Struct {
		return nil, false, nil
	}
	field, lock, ok, err := s.structFieldMode(obj, name, entry.dangerous)
	if err != nil || !ok {
		return nil, false, err
	}
	if lock != nil {
		lock.RLock()
		defer lock.RUnlock()
	}
	return accept(field)
}
func (s *Session) set(ref HostRef, name string, value Value, codec RuntimeValueCodec) error {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return err
	}
	if entry.controlled != nil {
		if value.Kind == KindNull || value.Kind == KindUndefined {
			return entry.controlled.HostSet(name, nil)
		}
		decoded, err := s.toHostAny(value)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return entry.controlled.HostSet(name, decoded)
	}
	obj := entry.value
	if obj.Kind() == reflect.Map {
		if obj.IsNil() {
			return errors.New("nil map")
		}
		item, err := s.toGo(value, obj.Type().Elem(), codec)
		if err != nil {
			return fmt.Errorf("map value: %w", err)
		}
		commitCallbacks(codec)
		obj.SetMapIndex(reflect.ValueOf(name).Convert(obj.Type().Key()), item)
		return nil
	}
	if obj.Kind() == reflect.Slice {
		return s.sliceSet(obj, name, value, codec)
	}
	if obj.Kind() == reflect.Pointer && obj.Elem().Kind() == reflect.Struct {
		field, lock, ok, err := s.structFieldMode(obj, name, entry.dangerous)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("HostRef %d has no writable property %q", ref, name)
		}
		if lock != nil {
			lock.Lock()
			defer lock.Unlock()
		}
		if !field.CanSet() {
			return fmt.Errorf("%s: read-only", name)
		}
		converted, err := s.toGo(value, field.Type(), codec)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		commitCallbacks(codec)
		field.Set(converted)
		return nil
	}
	return fmt.Errorf("unsupported HostRef %d", ref)
}

func (s *Session) Has(ref HostRef, name string) (bool, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return false, err
	}
	if entry.controlled != nil {
		_, exists, err := entry.controlled.HostGet(name)
		return exists, err
	}
	obj := entry.value
	switch obj.Kind() {
	case reflect.Map:
		return obj.MapIndex(reflect.ValueOf(name).Convert(obj.Type().Key())).IsValid(), nil
	case reflect.Slice:
		if name == "length" || name == "push" {
			return true, nil
		}
		i, e := strconv.Atoi(name)
		return e == nil && i >= 0 && i < obj.Len(), nil
	case reflect.Pointer:
		if obj.Elem().Kind() == reflect.Struct {
			_, _, ok, err := s.structFieldMode(obj, name, entry.dangerous)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
			_, ok = obj.Type().MethodByName(exportedMethod(name))
			return ok, nil
		}
		return false, nil
	default:
		return false, nil
	}
}

func (s *Session) Delete(ref HostRef, name string) (bool, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return false, err
	}
	if entry.controlled != nil {
		// ControlledObject intentionally has no delete mutation. Never fall
		// through to reflection for a domain handle.
		return false, nil
	}
	obj := entry.value
	if obj.Kind() == reflect.Map {
		obj.SetMapIndex(reflect.ValueOf(name).Convert(obj.Type().Key()), reflect.Value{})
		return true, nil
	}
	return false, nil
}

func (s *Session) Keys(ref HostRef) ([]string, error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return nil, err
	}
	if entry.controlled != nil {
		return append([]string(nil), entry.controlled.HostKeys()...), nil
	}
	obj := entry.value
	if obj.Kind() == reflect.Map {
		keys := make([]string, 0, obj.Len())
		it := obj.MapRange()
		for it.Next() {
			keys = append(keys, it.Key().String())
		}
		sort.Strings(keys)
		return keys, nil
	}
	if obj.Kind() == reflect.Slice {
		keys := make([]string, obj.Len())
		for i := range keys {
			keys[i] = strconv.Itoa(i)
		}
		return keys, nil
	}
	if obj.Kind() == reflect.Pointer && obj.Elem().Kind() == reflect.Struct {
		typ := obj.Elem().Type()
		seen := map[string]bool{}
		keys := []string{}
		for _, field := range reflect.VisibleFields(typ) {
			names := s.fieldBindNames(typ, field, entry.dangerous)
			for _, n := range names {
				if !seen[n] {
					keys = append(keys, n)
					seen[n] = true
				}
			}
		}
		for i := range obj.Type().NumMethod() {
			n := lowerFirst(obj.Type().Method(i).Name)
			if !seen[n] && isIdentifier(n) {
				keys = append(keys, n)
			}
		}
		sort.Strings(keys)
		return keys, nil
	}
	return nil, fmt.Errorf("unsupported HostRef %d", ref)
}

func (s *Session) Call(ref HostRef, name string, args []Value) (Value, error) {
	return s.call(ref, name, args, nil)
}

// ResizeSlice changes the length of a slice HostRef for adapters that expose
// native array semantics. A non-addressable slice may still retain its length
// and mutate existing elements, but its header cannot be resized.
func (s *Session) ResizeSlice(ref HostRef, length int) error {
	if length < 0 {
		return errors.New("slice length must not be negative")
	}
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return err
	}
	if entry.controlled != nil || entry.value.Kind() != reflect.Slice {
		return fmt.Errorf("HostRef %d is not a slice", ref)
	}
	obj := entry.value
	if obj.Len() == length {
		return nil
	}
	if !obj.CanSet() {
		return errors.New("slice length is read-only")
	}
	if length < obj.Len() {
		obj.Set(obj.Slice(0, length))
		return nil
	}
	obj.Set(reflect.AppendSlice(obj, reflect.MakeSlice(obj.Type(), length-obj.Len(), length-obj.Len())))
	return nil
}
func (s *Session) CallWithCodec(ref HostRef, name string, args []Value, codec RuntimeValueCodec) (Value, error) {
	return s.call(ref, name, args, codec)
}
func (s *Session) call(ref HostRef, name string, args []Value, codec RuntimeValueCodec) (result Value, err error) {
	entry, err := s.lookupEntry(ref)
	if err != nil {
		return UndefinedValue(), err
	}
	if entry.controlled != nil {
		raw, exists, err := entry.controlled.HostGet(name)
		if err != nil {
			return UndefinedValue(), err
		}
		if !exists {
			return UndefinedValue(), fmt.Errorf("HostRef %d has no callable property %q", ref, name)
		}
		fn := reflect.ValueOf(raw)
		if !fn.IsValid() || fn.Kind() != reflect.Func || fn.IsNil() {
			return UndefinedValue(), fmt.Errorf("HostRef %d property %q is not callable", ref, name)
		}
		return s.callReflect(fn, args, name, codec, false)
	}
	obj := entry.value
	if obj.Kind() == reflect.Slice && name == "push" {
		var n = int64(obj.Len())
		for _, arg := range args {
			item, e := s.toGo(arg, obj.Type().Elem(), codec)
			if e != nil {
				return UndefinedValue(), fmt.Errorf("slice value: %w", e)
			}
			if !obj.CanSet() {
				return UndefinedValue(), errors.New("slice is read-only")
			}
			commitCallbacks(codec)
			obj.Set(reflect.Append(obj, item))
			n++
		}
		return IntValue(n), nil
	}
	if obj.Kind() != reflect.Pointer || obj.Elem().Kind() != reflect.Struct {
		return UndefinedValue(), fmt.Errorf("HostRef %d has no callable property %q", ref, name)
	}
	method, ok := obj.Type().MethodByName(exportedMethod(name))
	if !ok {
		return UndefinedValue(), fmt.Errorf("HostRef %d has no callable property %q", ref, name)
	}
	return s.callReflect(method.Func, append([]Value{HostObjectValue(ref)}, args...), name, codec, true)
}

func (s *Session) CallFunction(ref HostFuncRef, args []Value) (Value, error) {
	return s.CallFunctionWithCodec(ref, args, nil)
}
func (s *Session) CallFunctionWithCodec(ref HostFuncRef, args []Value, codec RuntimeValueCodec) (Value, error) {
	entry, err := s.lookupFunctionEntry(ref)
	if err != nil {
		return UndefinedValue(), err
	}
	if entry.operation != "" {
		return s.call(entry.owner, entry.operation, args, codec)
	}
	if !entry.value.IsValid() {
		return s.call(entry.owner, "push", args, codec)
	}
	return s.callReflect(entry.value, args, "function", codec, false)
}
func (s *Session) callReflect(fn reflect.Value, args []Value, label string, codec RuntimeValueCodec, receiver bool) (result Value, err error) {
	defer func() {
		if p := recover(); p != nil {
			result = UndefinedValue()
			err = fmt.Errorf("%s panic: %v", label, p)
		}
	}()
	ft := fn.Type()
	offset := 0
	if receiver {
		offset = 1
	}
	inputs := make([]reflect.Value, 0, len(args)-offset)
	required := ft.NumIn() - offset
	if ft.IsVariadic() {
		if len(args)-offset < required-1 {
			return UndefinedValue(), fmt.Errorf("%s expects at least %d arguments", label, required-1)
		}
	} else if len(args)-offset != required {
		return UndefinedValue(), fmt.Errorf("%s expects %d arguments", label, required)
	}
	for i := offset; i < len(args); i++ {
		idx := i - offset
		var target reflect.Type
		if ft.IsVariadic() && offset+idx >= ft.NumIn()-1 {
			target = ft.In(ft.NumIn() - 1).Elem()
		} else {
			target = ft.In(offset + idx)
		}
		in, e := s.toGo(args[i], target, codec)
		if e != nil {
			return UndefinedValue(), fmt.Errorf("argument %d: %w", idx+1, e)
		}
		inputs = append(inputs, in)
	}
	callInputs := inputs
	if offset > 0 {
		callInputs = append([]reflect.Value{argsToReceiver(args[0], ft.In(0), s)}, inputs...)
	}
	commitCallbacks(codec)
	outs := fn.Call(callInputs)
	return s.outputs(outs, codec)
}
func (s *Session) structFieldMode(obj reflect.Value, name string, dangerous bool) (reflect.Value, *sync.RWMutex, bool, error) {
	typ := obj.Elem().Type()
	for _, def := range reflect.VisibleFields(typ) {
		names := s.fieldBindNames(typ, def, dangerous)
		for _, n := range names {
			if n != name {
				continue
			}
			field := hostFieldByIndex(obj.Elem(), def.Index)
			if !field.IsValid() {
				return reflect.Value{}, nil, false, fmt.Errorf("invalid field %q", name)
			}
			lockName := def.Tag.Get("jsbindlock")
			if lockName == "" {
				return field, nil, true, nil
			}
			method := obj.MethodByName(lockName)
			if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
				return reflect.Value{}, nil, false, fmt.Errorf("invalid jsbindlock %q on %s", lockName, def.Name)
			}
			out := method.Call(nil)[0]
			lock, ok := out.Interface().(*sync.RWMutex)
			if !ok || lock == nil {
				return reflect.Value{}, nil, false, fmt.Errorf("jsbindlock %q on %s must return *sync.RWMutex", lockName, def.Name)
			}
			return field, lock, true, nil
		}
	}
	return reflect.Value{}, nil, false, nil
}
func argsToReceiver(v Value, typ reflect.Type, s *Session) reflect.Value {
	r, err := s.LookupObject(v.Host)
	if err != nil {
		return reflect.Zero(typ)
	}
	if r.Type().AssignableTo(typ) {
		return r
	}
	if r.Type().ConvertibleTo(typ) {
		return r.Convert(typ)
	}
	return reflect.Zero(typ)
}
func dangerousBindNames(field reflect.StructField) []string {
	if field.PkgPath != "" || field.Name == "JsSealInstExposed" {
		return nil
	}
	names := []string{field.Name, lowerFirst(field.Name)}
	for _, tag := range []string{field.Tag.Get("jsbind"), field.Tag.Get("json")} {
		if n := strings.Split(tag, ",")[0]; n != "" && n != "-" {
			names = append(names, n)
		}
	}
	seen := map[string]bool{}
	result := []string{}
	for _, n := range names {
		if isIdentifier(n) && !seen[n] {
			seen[n] = true
			result = append(result, n)
		}
	}
	return result
}
func (s *Session) outputs(outs []reflect.Value, codec RuntimeValueCodec) (Value, error) {
	if len(outs) > 0 && outs[len(outs)-1].Type() == errorType {
		e := outs[len(outs)-1]
		outs = outs[:len(outs)-1]
		if !e.IsNil() {
			return UndefinedValue(), e.Interface().(error)
		}
	}
	if len(outs) == 0 {
		return UndefinedValue(), nil
	}
	return s.encodeReflect(outs[0], false, codec)
}

func hostFieldByIndex(value reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		for value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return reflect.Value{}
			}
			value = value.Elem()
		}
		if value.Kind() != reflect.Struct {
			return reflect.Value{}
		}
		value = value.Field(i)
	}
	return value
}
func (s *Session) fieldBindNames(typ reflect.Type, field reflect.StructField, dangerous bool) []string {
	if dangerous {
		return dangerousBindNames(field)
	}
	if !s.gojaFields {
		if name, ok := jsBindName(field); ok {
			return []string{name}
		}
		return nil
	}
	if field.PkgPath != "" {
		return nil
	}
	if tag, ok := field.Tag.Lookup("jsbindgoja"); ok {
		name := strings.Split(tag, ",")[0]
		if name != "-" && isIdentifier(name) {
			return []string{name}
		}
		return nil
	}
	name, ok := jsBindName(field)
	if !ok {
		return nil
	}
	for _, candidate := range reflect.VisibleFields(typ) {
		tag, exists := candidate.Tag.Lookup("jsbindgoja")
		if !exists {
			continue
		}
		if legacyName := strings.Split(tag, ",")[0]; legacyName == name {
			return nil
		}
	}
	return []string{name}
}

func jsBindName(field reflect.StructField) (string, bool) {
	if field.PkgPath != "" {
		return "", false
	}
	tag, ok := field.Tag.Lookup("jsbind")
	if !ok || tag == "-" {
		return "", false
	}
	n := strings.Split(tag, ",")[0]
	return n, isIdentifier(n)
}
func exportedMethod(name string) string {
	if name == "" {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}
func isIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if i == 0 && (c != '_' && c != '$' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z')) {
			return false
		}
		if i > 0 && (c != '_' && c != '$' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9')) {
			return false
		}
	}
	return true
}
func lowerFirst(name string) string {
	if name == "" {
		return ""
	}
	return strings.ToLower(name[:1]) + name[1:]
}

func (s *Session) encodeAny(raw any, dangerous bool, codec RuntimeValueCodec) (Value, error) {
	if raw == nil {
		return NullValue(), nil
	}
	return s.encodeReflect(reflect.ValueOf(raw), dangerous, codec)
}

func (s *Session) encodeReflect(value reflect.Value, dangerous bool, codec RuntimeValueCodec) (Value, error) {
	if codec != nil && !dangerous {
		return codec.Encode(value)
	}
	return s.toValueMode(value, dangerous)
}

func (s *Session) toValueMode(v reflect.Value, dangerous bool) (Value, error) {
	for v.IsValid() && v.Kind() == reflect.Interface {
		if v.IsNil() {
			return NullValue(), nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return UndefinedValue(), nil
	}
	kind := v.Kind()
	if kind == reflect.Slice && v.IsNil() {
		v = reflect.MakeSlice(v.Type(), 0, 0)
	}
	if kind == reflect.Map && v.IsNil() {
		v = reflect.MakeMap(v.Type())
	}
	if kind == reflect.Pointer && v.IsNil() {
		return NullValue(), nil
	}
	if kind == reflect.Func && v.IsNil() {
		return UndefinedValue(), nil
	}
	if v.CanInterface() {
		if _, controlled := v.Interface().(ControlledObject); controlled {
			ref, err := s.registerObject(v.Interface(), false)
			if err != nil {
				return UndefinedValue(), err
			}
			return HostObjectValue(ref), nil
		}
	}
	switch kind {
	case reflect.Bool:
		return BoolValue(v.Bool()), nil
	case reflect.String:
		return StringValue(v.String()), nil
	case reflect.Func:
		ref, err := s.RegisterFunction(v.Interface())
		if err != nil {
			return UndefinedValue(), err
		}
		return HostFunctionValue(ref), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return IntValue(v.Int()), nil
	case reflect.Float32, reflect.Float64:
		return FloatValue(v.Float()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return UintValue(v.Uint()), nil
	case reflect.Struct:
		target := v.Interface()
		if v.CanAddr() {
			target = v.Addr().Interface()
		}
		ref, err := s.registerObject(target, dangerous)
		if err != nil {
			return UndefinedValue(), err
		}
		return HostObjectValue(ref), nil
	case reflect.Slice:
		target := v.Interface()
		if v.CanAddr() {
			target = v.Addr().Interface()
		}
		ref, err := s.registerObject(target, dangerous)
		if err != nil {
			return UndefinedValue(), err
		}
		return HostObjectValue(ref), nil
	case reflect.Pointer, reflect.Map:
		ref, err := s.registerObject(v.Interface(), dangerous)
		if err != nil {
			return UndefinedValue(), err
		}
		return HostObjectValue(ref), nil
	default:
		return UndefinedValue(), fmt.Errorf("unsupported %s", v.Type())
	}
}
func (s *Session) toGo(v Value, target reflect.Type, codec RuntimeValueCodec) (reflect.Value, error) {
	if v.Kind == KindNull || v.Kind == KindUndefined {
		switch target.Kind() {
		case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface:
			return reflect.Zero(target), nil
		default:
		}
	}
	if v.Kind == KindJSON {
		switch target.Kind() {
		case reflect.Map, reflect.Slice, reflect.Interface, reflect.Struct, reflect.Pointer:
			decoded := reflect.New(target)
			if err := json.Unmarshal([]byte(v.String), decoded.Interface()); err != nil {
				return reflect.Value{}, fmt.Errorf("decode JSON snapshot into %s: %w", target, err)
			}
			return decoded.Elem(), nil
		default:
			return reflect.Value{}, fmt.Errorf("JSON snapshot cannot be assigned to %s", target)
		}
	}
	if v.Kind == KindHostObject {
		entry, err := s.lookupEntry(v.Host)
		if err != nil {
			return reflect.Value{}, err
		}
		if entry.controlled != nil {
			raw, err := entry.controlled.HostUnwrap(target)
			if err != nil {
				return reflect.Value{}, fmt.Errorf("HostRef %d cannot unwrap as %s: %w", v.Host, target, err)
			}
			return checkedUnwrapValue(raw, target)
		}
		obj := entry.value
		if obj.Type().AssignableTo(target) {
			return obj, nil
		}
		if obj.Type().ConvertibleTo(target) {
			return obj.Convert(target), nil
		}
		if obj.Kind() == reflect.Pointer && !obj.IsNil() {
			elem := obj.Elem()
			if elem.Type().AssignableTo(target) {
				return elem, nil
			}
			if elem.Type().ConvertibleTo(target) {
				return elem.Convert(target), nil
			}
		}
		return reflect.Value{}, fmt.Errorf("expected %s Host API object", target)
	}
	if target.Kind() == reflect.Interface {
		switch v.Kind {
		case KindNull, KindUndefined:
			return reflect.Zero(target), nil
		default:
			raw, err := s.valuePrimitive(v)
			if err != nil {
				return reflect.Value{}, err
			}
			value := reflect.ValueOf(raw)
			if !value.Type().AssignableTo(target) {
				return reflect.Value{}, fmt.Errorf("%T is not assignable to %s", raw, target)
			}
			return value, nil
		}
	}
	if target.Kind() == reflect.Pointer || target.Kind() == reflect.Map || target.Kind() == reflect.Slice || target.Kind() == reflect.Struct {
		return reflect.Value{}, fmt.Errorf("expected %s Host API object", target)
	}
	if target.Kind() == reflect.Func {
		if codec == nil {
			return reflect.Value{}, errors.New("JavaScript callback codec is required")
		}
		return codec.Decode(v, target)
	}
	out := reflect.New(target).Elem()
	switch target.Kind() {
	case reflect.Bool:
		if v.Kind != KindBool {
			return reflect.Value{}, errors.New("expected bool")
		}
		out.SetBool(v.Bool)
	case reflect.String:
		if v.Kind != KindString {
			return reflect.Value{}, errors.New("expected string")
		}
		out.SetString(v.String)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if v.Kind == KindInt {
			out.SetInt(v.Int)
		} else if v.Kind == KindUint && v.Uint <= uint64(1)<<(target.Bits()-1)-1 {
			out.SetInt(int64(v.Uint))
		} else {
			return reflect.Value{}, errors.New("expected integer")
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if v.Kind == KindUint {
			out.SetUint(v.Uint)
		} else if v.Kind == KindInt && v.Int >= 0 {
			out.SetUint(uint64(v.Int))
		} else {
			return reflect.Value{}, errors.New("expected unsigned integer")
		}
	case reflect.Float32, reflect.Float64:
		switch v.Kind {
		case KindFloat:
			out.SetFloat(v.Float)
		case KindInt:
			out.SetFloat(float64(v.Int))
		case KindUint:
			out.SetFloat(float64(v.Uint))
		default:
			return reflect.Value{}, errors.New("expected number")
		}
	default:
		return reflect.Value{}, fmt.Errorf("unsupported %s", target)
	}
	return out, nil
}
func checkedUnwrapValue(raw any, target reflect.Type) (reflect.Value, error) {
	if raw == nil {
		if isNilable(target.Kind()) {
			return reflect.Zero(target), nil
		}
		return reflect.Value{}, fmt.Errorf("HostUnwrap returned nil for %s", target)
	}
	value := reflect.ValueOf(raw)
	if !value.Type().AssignableTo(target) {
		return reflect.Value{}, fmt.Errorf("HostUnwrap returned %s, not assignable to %s", value.Type(), target)
	}
	return value, nil
}

func (s *Session) toHostAny(value Value) (any, error) {
	switch value.Kind {
	case KindBool:
		return value.Bool, nil
	case KindString:
		return value.String, nil
	case KindInt:
		return value.Int, nil
	case KindUint:
		return value.Uint, nil
	case KindFloat:
		return value.Float, nil
	case KindJSON:
		var decoded any
		if err := json.Unmarshal([]byte(value.String), &decoded); err != nil {
			return nil, fmt.Errorf("decode JSON host value: %w", err)
		}
		return decoded, nil
	case KindHostObject:
		entry, err := s.lookupEntry(value.Host)
		if err != nil {
			return nil, err
		}
		if entry.controlled != nil {
			return entry.controlled, nil
		}
		if !entry.value.IsValid() || !entry.value.CanInterface() {
			return nil, fmt.Errorf("HostRef %d cannot be exported", value.Host)
		}
		return entry.value.Interface(), nil
	case KindHostFunction:
		entry, err := s.lookupFunctionEntry(value.Function)
		if err != nil {
			return nil, err
		}
		if !entry.value.IsValid() || !entry.value.CanInterface() {
			return nil, fmt.Errorf("HostFuncRef %d cannot be exported without a target type", value.Function)
		}
		return entry.value.Interface(), nil
	default:
		return nil, fmt.Errorf("unsupported controlled setter value kind %d", value.Kind)
	}
}

func (s *Session) valuePrimitive(v Value) (any, error) {
	switch v.Kind {
	case KindBool:
		return v.Bool, nil
	case KindString:
		return v.String, nil
	case KindInt:
		return v.Int, nil
	case KindUint:
		return v.Uint, nil
	case KindFloat:
		return v.Float, nil
	case KindNull, KindUndefined:
		return nil, ErrNoPrimitiveValue
	default:
		return nil, fmt.Errorf("cannot convert kind %d", v.Kind)
	}
}

func (s *Session) mapGet(obj reflect.Value, name string, dangerous bool, codec RuntimeValueCodec) (Value, error) {
	item := obj.MapIndex(reflect.ValueOf(name).Convert(obj.Type().Key()))
	if !item.IsValid() {
		return UndefinedValue(), nil
	}
	return s.encodeReflect(item, dangerous, codec)
}

func (s *Session) sliceGet(ref HostRef, obj reflect.Value, name string, dangerous bool, codec RuntimeValueCodec) (Value, error) {
	if name == "length" {
		return IntValue(int64(obj.Len())), nil
	}
	if name == "push" {
		function, err := s.registerOperation(ref, "push")
		if err != nil {
			return UndefinedValue(), err
		}
		return HostFunctionValue(function), nil
	}
	i, err := strconv.Atoi(name)
	if err != nil || i < 0 {
		return UndefinedValue(), fmt.Errorf("%w %q", ErrInvalidSliceIndex, name)
	}
	if i >= obj.Len() {
		return UndefinedValue(), nil
	}
	return s.encodeReflect(obj.Index(i), dangerous, codec)
}
func (s *Session) sliceSet(obj reflect.Value, name string, v Value, codec RuntimeValueCodec) error {
	i, err := strconv.Atoi(name)
	if err != nil || i < 0 {
		return fmt.Errorf("invalid slice index %q", name)
	}
	item, err := s.toGo(v, obj.Type().Elem(), codec)
	if err != nil {
		return err
	}
	if !obj.CanSet() {
		return errors.New("slice is read-only")
	}
	if i < obj.Len() {
		// The addressable slice header is the mutation authority. Slice
		// elements alone report CanSet even when the header was bound by value.
		commitCallbacks(codec)
		obj.Index(i).Set(item)
		return nil
	}
	if !obj.CanSet() {
		return errors.New("slice is read-only")
	}
	for obj.Len() <= i {
		obj.Set(reflect.Append(obj, reflect.Zero(obj.Type().Elem())))
	}
	commitCallbacks(codec)
	obj.Index(i).Set(item)
	return nil
}

// DecodeValue converts an engine value through the session-owned codec.
func (s *Session) DecodeValue(value Value, target reflect.Type, codec RuntimeValueCodec) (reflect.Value, error) {
	if s == nil {
		return reflect.Value{}, ErrSessionClosed
	}
	decoded, err := s.toGo(value, target, codec)
	if err == nil {
		commitCallbacks(codec)
	}
	return decoded, err
}

// Callback creates a generation-checked reflect trampoline from an explicit
// runtime codec. Calls after Teardown return the declared error or panic when
// the function has no error result, matching normal Go callback conventions.
func (s *Session) Callback(codec RuntimeValueCodec, source Value, target reflect.Type) (reflect.Value, error) {
	if codec == nil {
		return reflect.Value{}, errors.New("nil callback codec")
	}
	if source.Kind != KindCallback {
		return reflect.Value{}, errors.New("expected JavaScript callback value")
	}
	if target.Kind() != reflect.Func {
		return reflect.Value{}, errors.New("callback target must be func")
	}
	fn, err := codec.Decode(source, target)
	if err != nil {
		return reflect.Value{}, err
	}
	generation := s.Generation()
	callback := reflect.MakeFunc(target, func(inputs []reflect.Value) []reflect.Value {
		if s.Generation() != generation {
			return staleResults(target)
		}
		return fn.Call(inputs)
	})
	commitCallbacks(codec)
	return callback, nil
}
func staleResults(target reflect.Type) []reflect.Value {
	result := make([]reflect.Value, target.NumOut())
	for i := range result {
		result[i] = reflect.Zero(target.Out(i))
	}
	if len(result) > 0 && target.Out(len(result)-1) == errorType {
		result[len(result)-1] = reflect.ValueOf(ErrStaleRuntimeCallback)
	} else {
		panic(ErrStaleRuntimeCallback)
	}
	return result
}
