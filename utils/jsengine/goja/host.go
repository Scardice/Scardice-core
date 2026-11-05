package goja

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"strconv"
	"sync"
	"weak"

	g "github.com/dop251/goja"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
)

var (
	gojaValueType       = reflect.TypeFor[g.Value]()
	gojaObjectType      = reflect.TypeFor[*g.Object]()
	engineHostValueType = reflect.TypeFor[jsengine.Value]()
	hostErrorType       = reflect.TypeFor[error]()
)

type gojaHostState struct {
	vm      *g.Runtime
	realm   *realm
	session *hostbridge.Session

	mu            sync.Mutex
	active        []*runtime
	hostObjects   map[gojaHostObjectKey]weak.Pointer[g.Object]
	hostArrays    map[gojaHostObjectKey]weak.Pointer[g.Object]
	hostFunctions map[gojaHostFunctionKey]weak.Pointer[g.Object]
	callbacks     map[uint64]gojaCallback
	nextCallback  uint64
	closed        bool
}

func newGojaHostState(vm *g.Runtime, owner *realm) *gojaHostState {
	return &gojaHostState{
		vm: vm, realm: owner, session: hostbridge.NewGojaSession(),
		hostObjects:   make(map[gojaHostObjectKey]weak.Pointer[g.Object]),
		hostArrays:    make(map[gojaHostObjectKey]weak.Pointer[g.Object]),
		hostFunctions: make(map[gojaHostFunctionKey]weak.Pointer[g.Object]),
		callbacks:     make(map[uint64]gojaCallback),
	}
}

func (s *gojaHostState) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.active = nil
	s.hostObjects = make(map[gojaHostObjectKey]weak.Pointer[g.Object])
	s.hostArrays = make(map[gojaHostObjectKey]weak.Pointer[g.Object])
	s.hostFunctions = make(map[gojaHostFunctionKey]weak.Pointer[g.Object])
	s.callbacks = make(map[uint64]gojaCallback)
	session := s.session
	s.mu.Unlock()
	if session != nil {
		session.Teardown()
	}
}

func (s *gojaHostState) enter(owner *runtime) {
	if s == nil || owner == nil {
		return
	}
	s.mu.Lock()
	if !s.closed {
		s.active = append(s.active, owner)
	}
	s.mu.Unlock()
}

func (s *gojaHostState) leave(owner *runtime) {
	if s == nil || owner == nil {
		return
	}
	s.mu.Lock()
	for index := len(s.active) - 1; index >= 0; index-- {
		if s.active[index] != owner {
			continue
		}
		copy(s.active[index:], s.active[index+1:])
		s.active[len(s.active)-1] = nil
		s.active = s.active[:len(s.active)-1]
		break
	}
	s.mu.Unlock()
}

func (s *gojaHostState) live() bool {
	if s == nil || s.realm == nil || s.realm.closed.Load() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed
}

func (s *gojaHostState) currentRuntime() *runtime {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.active) == 0 {
		return nil
	}
	return s.active[len(s.active)-1]
}

func (s *gojaHostState) currentScope(fallback hostbridge.ControlledObjectScope) hostbridge.ControlledObjectScope {
	if s != nil && s.realm != nil && s.realm.state != nil {
		if current := hostbridge.Scope(s.realm.state.currentContext()); current != nil {
			return current
		}
	}
	return fallback
}

func (s *gojaHostState) objectValue(object hostbridge.ControlledObject, scope hostbridge.ControlledObjectScope) (*g.Object, error) {
	if object == nil {
		return nil, errors.New("goja controlled object is nil")
	}
	ref, err := s.session.BindObject(object)
	if err != nil {
		return nil, err
	}
	return s.hostObjectValue(ref, scope)
}

func (s *gojaHostState) coerce(raw any, scope hostbridge.ControlledObjectScope) (any, error) {
	switch handler := raw.(type) {
	case *gojaHostObject:
		if handler == nil || handler.state != s {
			return nil, errors.New("goja HostRef belongs to another realm")
		}
		return s.hostObjectValue(handler.ref, handler.scope)
	case *gojaHostArray:
		if handler == nil || handler.state != s {
			return nil, errors.New("goja HostRef belongs to another realm")
		}
		return s.hostObjectValue(handler.ref, handler.scope)
	}
	if _, ok := raw.(g.Value); ok {
		return raw, nil
	}
	object, wrapped, err := hostbridge.Wrap(scope, raw)
	if err != nil {
		return nil, err
	}
	if wrapped {
		return s.objectValue(object, scope)
	}
	value := reflect.ValueOf(raw)
	if value.IsValid() && value.Kind() == reflect.Func && !isNativeGojaFunction(raw) {
		return s.functionValue(value, scope), nil
	}
	if shouldBridgeGojaObject(value) {
		ref, err := s.session.BindObject(raw)
		if err != nil {
			return nil, err
		}
		return s.hostObjectValue(ref, scope)
	}
	return raw, nil
}

func shouldBridgeGojaObject(value reflect.Value) bool {
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice:
		return value.Kind() != reflect.Map || value.Type().Key().Kind() == reflect.String
	case reflect.Pointer:
		return !value.IsNil() && (value.Elem().Kind() == reflect.Struct || value.Elem().Kind() == reflect.Slice)
	default:
		return false
	}
}
func prepareGojaHostValue(raw any, ownerRealm *realm, owner *runtime, valueScope uint64) (any, error) {
	value, err := unwrapObject(raw, ownerRealm, owner, valueScope)
	if err != nil {
		return nil, err
	}
	if ownerRealm == nil || ownerRealm.host == nil {
		return value, nil
	}
	return ownerRealm.host.coerce(value, hostbridge.Scope(ownerRealm.state.currentContext()))
}

func isNativeGojaFunction(raw any) bool {
	switch raw.(type) {
	case func(g.FunctionCall) g.Value,
		func(g.FunctionCall, *g.Runtime) g.Value,
		func(g.ConstructorCall) *g.Object,
		func(g.ConstructorCall, *g.Runtime) *g.Object,
		g.Callable:
		return true
	default:
		return false
	}
}

func (s *gojaHostState) functionValue(function reflect.Value, scope hostbridge.ControlledObjectScope) g.Value {
	return s.vm.ToValue(func(call g.FunctionCall) g.Value {
		owner := s.currentRuntime()
		if owner == nil {
			owner = &runtime{vm: s.vm, realm: s.realm}
		}
		return s.callReflect(owner, function, call, s.currentScope(scope))
	})
}

func (s *gojaHostState) callReflect(owner *runtime, function reflect.Value, call g.FunctionCall, scope hostbridge.ControlledObjectScope) g.Value {
	typ := function.Type()
	nargs := typ.NumIn()
	var inputs []reflect.Value
	if length := len(call.Arguments); length < nargs {
		required := nargs
		if typ.IsVariadic() {
			required--
		}
		inputs = make([]reflect.Value, required)
		for index := length; index < required; index++ {
			inputs[index] = reflect.Zero(typ.In(index))
		}
	} else {
		length := len(call.Arguments)
		if length > nargs && !typ.IsVariadic() {
			length = nargs
		}
		inputs = make([]reflect.Value, length)
	}
	for index, argument := range call.Arguments {
		parameter := index
		var target reflect.Type
		if parameter >= nargs-1 && typ.IsVariadic() {
			if parameter > nargs-1 {
				parameter = nargs - 1
			}
			target = typ.In(parameter).Elem()
		} else if parameter >= nargs {
			break
		} else {
			target = typ.In(parameter)
		}
		converted, err := s.decodeValue(owner, argument, target, scope)
		if err != nil {
			panic(s.vm.NewTypeError("could not convert function call parameter %d: %v", index, err))
		}
		inputs[index] = converted
	}

	outputs := function.Call(inputs)
	if len(outputs) > 0 && outputs[len(outputs)-1].Type() == hostErrorType {
		last := outputs[len(outputs)-1]
		outputs = outputs[:len(outputs)-1]
		if !last.IsNil() {
			panic(s.vm.NewGoError(last.Interface().(error)))
		}
	}
	switch len(outputs) {
	case 0:
		return g.Undefined()
	case 1:
		value, err := s.encodeReflect(owner, outputs[0], scope)
		if err != nil {
			panic(s.vm.NewGoError(err))
		}
		return value
	default:
		values := make([]any, len(outputs))
		for index, output := range outputs {
			value, err := s.encodeReflect(owner, output, scope)
			if err != nil {
				panic(s.vm.NewGoError(err))
			}
			values[index] = value
		}
		return s.vm.NewArray(values...)
	}
}

func (s *gojaHostState) decodeValue(owner *runtime, value g.Value, target reflect.Type, scope hostbridge.ControlledObjectScope) (reflect.Value, error) {
	if target == gojaValueType {
		return reflect.ValueOf(value), nil
	}
	if target == gojaObjectType {
		object, ok := value.(*g.Object)
		if !ok {
			return reflect.Value{}, fmt.Errorf("expected Goja object, got %T", value)
		}
		return reflect.ValueOf(object), nil
	}
	if target == engineHostValueType {
		if owner == nil {
			return reflect.Value{}, errors.New("controlled function has no active Goja runtime")
		}
		active, valueScope := owner.valueScope()
		if active == nil {
			return reflect.Value{}, errGojaStaleValue
		}
		wrapped := valueAdapter(value, s.realm, active, valueScope)
		return reflect.ValueOf(wrapped), nil
	}
	if object, ok := value.(*g.Object); ok {
		switch handler := object.Export().(type) {
		case *gojaHostObject:
			if handler == nil || handler.state != s {
				return reflect.Value{}, errors.New("goja HostRef belongs to another realm")
			}
			return s.session.DecodeValue(
				hostbridge.HostObjectValue(handler.ref),
				target,
				s.codec(owner, scope),
			)
		case *gojaHostArray:
			if handler == nil || handler.state != s {
				return reflect.Value{}, errors.New("goja HostRef belongs to another realm")
			}
			return s.session.DecodeValue(
				hostbridge.HostObjectValue(handler.ref),
				target,
				s.codec(owner, scope),
			)
		}
	}
	if target.Kind() == reflect.Func {
		callable, ok := g.AssertFunction(value)
		if !ok {
			return reflect.Value{}, errors.New("expected JavaScript callback value")
		}
		return s.callbackValue(owner, callable, target, scope), nil
	}
	if target.Kind() == reflect.Slice && target.Elem().Kind() != reflect.Uint8 {
		if array, ok := value.(*g.Object); ok && array.ClassName() == "Array" {
			length := int(array.Get("length").ToInteger())
			decoded := reflect.MakeSlice(target, length, length)
			for index := range length {
				item := array.Get(strconv.Itoa(index))
				if item == nil || g.IsUndefined(item) {
					continue
				}
				element, err := s.decodeValue(owner, item, target.Elem(), scope)
				if err != nil {
					return reflect.Value{}, fmt.Errorf("array element %d: %w", index, err)
				}
				decoded.Index(index).Set(element)
			}
			return decoded, nil
		}
	}
	destination := reflect.New(target)
	if err := s.vm.ExportTo(value, destination.Interface()); err != nil {
		return reflect.Value{}, err
	}
	return destination.Elem(), nil
}

func (s *gojaHostState) callbackValue(owner *runtime, callable g.Callable, target reflect.Type, scope hostbridge.ControlledObjectScope) reflect.Value {
	return reflect.MakeFunc(target, func(inputs []reflect.Value) []reflect.Value {
		if !s.live() {
			return callbackErrorResults(target, hostbridge.ErrStaleRuntimeCallback)
		}
		invocationOwner := s.currentRuntime()
		if invocationOwner == nil {
			invocationOwner = owner
		}
		arguments := make([]g.Value, 0, len(inputs))
		fixed := inputs
		if target.IsVariadic() && len(inputs) > 0 {
			variadic := inputs[len(inputs)-1]
			fixed = inputs[:len(inputs)-1]
			arguments = make([]g.Value, 0, len(fixed)+variadic.Len())
			for _, input := range fixed {
				value, err := s.encodeReflect(invocationOwner, input, scope)
				if err != nil {
					return callbackErrorResults(target, err)
				}
				arguments = append(arguments, value)
			}
			for index := range variadic.Len() {
				value, err := s.encodeReflect(invocationOwner, variadic.Index(index), scope)
				if err != nil {
					return callbackErrorResults(target, err)
				}
				arguments = append(arguments, value)
			}
		} else {
			for _, input := range fixed {
				value, err := s.encodeReflect(invocationOwner, input, scope)
				if err != nil {
					return callbackErrorResults(target, err)
				}
				arguments = append(arguments, value)
			}
		}

		result, err := callable(g.Undefined(), arguments...)
		if err != nil {
			return callbackErrorResults(target, err)
		}
		outputs := make([]reflect.Value, target.NumOut())
		resultCount := target.NumOut()
		if resultCount > 0 && target.Out(resultCount-1) == hostErrorType {
			resultCount--
		}
		if resultCount > 0 {
			outputs[0], err = s.decodeValue(invocationOwner, result, target.Out(0), scope)
			if err != nil {
				return callbackErrorResults(target, err)
			}
		}
		for index := range outputs {
			if !outputs[index].IsValid() {
				outputs[index] = reflect.Zero(target.Out(index))
			}
		}
		return outputs
	})
}

func callbackErrorResults(target reflect.Type, err error) []reflect.Value {
	outputs := make([]reflect.Value, target.NumOut())
	for index := range outputs {
		outputs[index] = reflect.Zero(target.Out(index))
	}
	if len(outputs) > 0 && target.Out(len(outputs)-1) == hostErrorType {
		outputs[len(outputs)-1] = reflect.ValueOf(err)
		return outputs
	}
	panic(err)
}

func valueAdapter(raw g.Value, owner *realm, runtimeOwner *runtime, scope uint64) jsengine.Value {
	return value{value: raw, realm: owner, owner: runtimeOwner, scope: scope}
}

func (s *gojaHostState) encodeReflect(owner *runtime, value reflect.Value, scope hostbridge.ControlledObjectScope) (g.Value, error) {
	if !value.IsValid() {
		return g.Undefined(), nil
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return g.Null(), nil
		}
		if abstract, ok := value.Interface().(jsengine.Value); ok {
			return s.unwrapEngineValue(abstract)
		}
		value = value.Elem()
	}
	if value.CanInterface() {
		if abstract, ok := value.Interface().(jsengine.Value); ok {
			return s.unwrapEngineValue(abstract)
		}
		if raw, ok := value.Interface().(g.Value); ok {
			return raw, nil
		}
	}
	if kind := value.Kind(); kind == reflect.Slice && value.IsNil() {
		value = reflect.MakeSlice(value.Type(), 0, 0)
	} else if kind == reflect.Map && value.IsNil() {
		value = reflect.MakeMap(value.Type())
	} else if (kind == reflect.Pointer || kind == reflect.Func) && value.IsNil() {
		return g.Null(), nil
	}
	if value.CanInterface() {
		object, wrapped, err := hostbridge.Wrap(scope, value.Interface())
		if err != nil {
			return nil, err
		}
		if wrapped {
			return s.objectValue(object, scope)
		}
	}
	if value.Kind() == reflect.Func {
		return s.functionValue(value, scope), nil
	}
	if !value.CanInterface() {
		return nil, fmt.Errorf("goja cannot expose %s", value.Type())
	}
	if shouldBridgeGojaObject(value) {
		ref, err := s.session.BindObject(gojaHostTarget(value))
		if err != nil {
			return nil, err
		}
		return s.hostObjectValue(ref, scope)
	}
	return s.vm.ToValue(value.Interface()), nil
}

func gojaHostTarget(value reflect.Value) any {
	if (value.Kind() == reflect.Struct || value.Kind() == reflect.Slice) && value.CanAddr() {
		return value.Addr().Interface()
	}
	return value.Interface()
}

func (s *gojaHostState) unwrapEngineValue(abstract jsengine.Value) (g.Value, error) {
	wrapped, ok := abstract.(value)
	if !ok || wrapped.realm == nil || wrapped.value == nil {
		return nil, errors.New("goja value is required")
	}
	if wrapped.realm != s.realm || s.realm.vm != s.vm {
		return nil, errors.New("goja value belongs to another realm")
	}
	if !wrapped.usable() {
		return nil, errGojaStaleValue
	}
	return wrapped.value, nil
}

type gojaHostObjectKey struct {
	ref   hostbridge.HostRef
	scope any
}

type gojaHostFunctionKey struct {
	ref   hostbridge.HostFuncRef
	scope any
}

type gojaCallback struct {
	value    g.Value
	callable g.Callable
	owner    *runtime
	scope    hostbridge.ControlledObjectScope
}

func scopeCacheIdentity(scope hostbridge.ControlledObjectScope) (any, bool) {
	if scope == nil {
		return nil, true
	}
	identity := any(scope)
	if identifier, ok := scope.(hostbridge.ScopeIdentifier); ok {
		identity = identifier.HostScopeIdentity()
		if identity == nil {
			return nil, false
		}
	}
	if !reflect.TypeOf(identity).Comparable() {
		return nil, false
	}
	return identity, true
}

type gojaHostObjectRelease struct {
	state     *gojaHostState
	session   *hostbridge.Session
	ref       hostbridge.HostRef
	key       gojaHostObjectKey
	cacheable bool
	array     bool
}

func releaseGojaHostObject(release gojaHostObjectRelease) {
	if release.cacheable && release.state != nil {
		release.state.mu.Lock()
		if release.array {
			if release.state.hostArrays[release.key].Value() == nil {
				delete(release.state.hostArrays, release.key)
			}
		} else if release.state.hostObjects[release.key].Value() == nil {
			delete(release.state.hostObjects, release.key)
		}
		release.state.mu.Unlock()
	}
	if release.session != nil {
		_ = release.session.ReleaseObject(release.ref)
	}
}

type gojaHostFunctionRelease struct {
	state     *gojaHostState
	session   *hostbridge.Session
	ref       hostbridge.HostFuncRef
	owner     hostbridge.HostRef
	key       gojaHostFunctionKey
	cacheable bool
}

func releaseGojaHostFunction(release gojaHostFunctionRelease) {
	if release.cacheable && release.state != nil {
		release.state.mu.Lock()
		if release.state.hostFunctions[release.key].Value() == nil {
			delete(release.state.hostFunctions, release.key)
		}
		release.state.mu.Unlock()
	}
	if release.session != nil {
		_ = release.session.ReleaseFunction(release.ref)
		if release.owner != 0 {
			_ = release.session.ReleaseObject(release.owner)
		}
	}
}

func (s *gojaHostState) hostObjectValue(ref hostbridge.HostRef, scope hostbridge.ControlledObjectScope) (*g.Object, error) {
	if s == nil || s.vm == nil || s.realm == nil || s.realm.closed.Load() {
		return nil, errors.New("goja HostRef realm is closed")
	}
	raw, err := s.session.LookupObject(ref)
	if err != nil {
		return nil, err
	}
	if raw.Kind() == reflect.Slice {
		return s.hostArrayValue(ref, scope)
	}
	scopeIdentity, cacheable := scopeCacheIdentity(scope)
	key := gojaHostObjectKey{ref: ref, scope: scopeIdentity}
	if cacheable {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return nil, errors.New("goja HostRef realm is closed")
		}
		if existing := s.hostObjects[key].Value(); existing != nil {
			return existing, nil
		}
	}
	handler := &gojaHostObject{state: s, ref: ref, scope: scope}
	value := s.vm.NewDynamicObject(handler)
	if err := s.session.RetainObject(ref); err != nil {
		return nil, err
	}
	goruntime.AddCleanup(handler, releaseGojaHostObject, gojaHostObjectRelease{
		state: s, session: s.session, ref: ref, key: key, cacheable: cacheable,
	})
	if cacheable {
		s.hostObjects[key] = weak.Make(value)
	}
	return value, nil
}

func (s *gojaHostState) hostArrayValue(ref hostbridge.HostRef, scope hostbridge.ControlledObjectScope) (*g.Object, error) {
	scopeIdentity, cacheable := scopeCacheIdentity(scope)
	key := gojaHostObjectKey{ref: ref, scope: scopeIdentity}
	if cacheable {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return nil, errors.New("goja HostRef realm is closed")
		}
		if existing := s.hostArrays[key].Value(); existing != nil {
			return existing, nil
		}
	}
	handler := &gojaHostArray{state: s, ref: ref, scope: scope}
	value := s.vm.NewDynamicArray(handler)
	if err := s.session.RetainObject(ref); err != nil {
		return nil, err
	}
	goruntime.AddCleanup(handler, releaseGojaHostObject, gojaHostObjectRelease{
		state: s, session: s.session, ref: ref, key: key, cacheable: cacheable, array: true,
	})
	if cacheable {
		s.hostArrays[key] = weak.Make(value)
	}
	return value, nil
}

func (s *gojaHostState) hostFunctionValue(ref hostbridge.HostFuncRef, scope hostbridge.ControlledObjectScope) (g.Value, error) {
	if s == nil || s.vm == nil || s.realm == nil || s.realm.closed.Load() {
		return nil, errors.New("goja HostFuncRef realm is closed")
	}
	if _, err := s.session.LookupFunction(ref); err != nil {
		return nil, err
	}
	scopeIdentity, cacheable := scopeCacheIdentity(scope)
	key := gojaHostFunctionKey{ref: ref, scope: scopeIdentity}
	if cacheable {
		s.mu.Lock()
		defer s.mu.Unlock()
		if existing := s.hostFunctions[key].Value(); existing != nil {
			return existing, nil
		}
	}
	handler := &gojaHostFunction{state: s, ref: ref, scope: scope}
	value := s.vm.ToValue(func(call g.FunctionCall) g.Value {
		return handler.call(call)
	})
	object, ok := value.(*g.Object)
	if !ok {
		return nil, errors.New("goja host function did not produce an object")
	}
	ownerRef, err := s.session.FunctionOwner(ref)
	if err != nil {
		return nil, err
	}
	if err := s.session.RetainFunction(ref); err != nil {
		return nil, err
	}
	if ownerRef != 0 {
		if err := s.session.RetainObject(ownerRef); err != nil {
			_ = s.session.ReleaseFunction(ref)
			return nil, err
		}
	}
	goruntime.AddCleanup(handler, releaseGojaHostFunction, gojaHostFunctionRelease{
		state: s, session: s.session, ref: ref, owner: ownerRef, key: key, cacheable: cacheable,
	})
	if cacheable {
		s.hostFunctions[key] = weak.Make(object)
	}
	return value, nil
}

func (s *gojaHostState) registerCallback(value g.Value, callable g.Callable, owner *runtime, scope hostbridge.ControlledObjectScope) hostbridge.CallbackRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextCallback++
	ref := s.nextCallback
	s.callbacks[ref] = gojaCallback{value: value, callable: callable, owner: owner, scope: scope}
	return hostbridge.CallbackRef(ref)
}

func (s *gojaHostState) takeCallback(ref uint64) (gojaCallback, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return gojaCallback{}, hostbridge.ErrStaleRuntimeCallback
	}
	callback, ok := s.callbacks[ref]
	if !ok {
		return gojaCallback{}, hostbridge.ErrStaleRuntimeCallback
	}
	delete(s.callbacks, ref)
	return callback, nil
}

func (s *gojaHostState) discardCallbacks(values []hostbridge.Value) {
	s.mu.Lock()
	for _, value := range values {
		if value.Kind == hostbridge.KindCallback {
			delete(s.callbacks, value.Callback)
		}
	}
	s.mu.Unlock()
}

func (s *gojaHostState) discardCallback(value hostbridge.Value) {
	if value.Kind != hostbridge.KindCallback {
		return
	}
	s.mu.Lock()
	delete(s.callbacks, value.Callback)
	s.mu.Unlock()
}

func (s *gojaHostState) codec(owner *runtime, scope hostbridge.ControlledObjectScope) hostbridge.RuntimeValueCodec {
	return gojaBridgeCodec{state: s, owner: owner, scope: scope}
}

type gojaBridgeCodec struct {
	state *gojaHostState
	owner *runtime
	scope hostbridge.ControlledObjectScope
}

func (c gojaBridgeCodec) Decode(value hostbridge.Value, target reflect.Type) (reflect.Value, error) {
	if value.Kind != hostbridge.KindCallback {
		return reflect.Value{}, fmt.Errorf("goja runtime value kind %d cannot decode into %s", value.Kind, target)
	}
	callback, err := c.state.takeCallback(value.Callback)
	if err != nil {
		return reflect.Value{}, err
	}
	if callback.callable == nil {
		return reflect.Value{}, errors.New("goja runtime value is not callable")
	}
	if target.Kind() != reflect.Func {
		return reflect.Value{}, fmt.Errorf("goja callback cannot decode into %s", target)
	}
	return c.state.callbackValue(callback.owner, callback.callable, target, callback.scope), nil
}

func (c gojaBridgeCodec) Encode(value reflect.Value) (hostbridge.Value, error) {
	return c.state.encodeBridgeReflect(value, c.owner, c.scope)
}

func (c gojaBridgeCodec) CallCallback(callback hostbridge.Value, args []hostbridge.Value) (hostbridge.Value, error) {
	if callback.Kind != hostbridge.KindCallback {
		return hostbridge.UndefinedValue(), errors.New("goja callback value is required")
	}
	entry, err := c.state.takeCallback(callback.Callback)
	if err != nil {
		return hostbridge.UndefinedValue(), err
	}
	if entry.callable == nil {
		return hostbridge.UndefinedValue(), errors.New("goja runtime value is not callable")
	}
	arguments := make([]g.Value, len(args))
	for index, argument := range args {
		arguments[index], err = c.state.fromBridgeValue(argument, entry.owner, entry.scope)
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
	}
	result, err := entry.callable(g.Undefined(), arguments...)
	if err != nil {
		return hostbridge.UndefinedValue(), err
	}
	return c.state.toBridgeValue(result, entry.owner, entry.scope)
}

func (s *gojaHostState) encodeBridgeReflect(value reflect.Value, owner *runtime, scope hostbridge.ControlledObjectScope) (hostbridge.Value, error) {
	if !value.IsValid() {
		return hostbridge.UndefinedValue(), nil
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return hostbridge.NullValue(), nil
		}
		if value.CanInterface() {
			if abstract, ok := value.Interface().(jsengine.Value); ok {
				raw, err := s.unwrapEngineValue(abstract)
				if err != nil {
					return hostbridge.UndefinedValue(), err
				}
				return s.toBridgeValue(raw, owner, scope)
			}
			if raw, ok := value.Interface().(g.Value); ok {
				return s.toBridgeValue(raw, owner, scope)
			}
		}
		value = value.Elem()
	}
	if kind := value.Kind(); kind == reflect.Slice && value.IsNil() {
		value = reflect.MakeSlice(value.Type(), 0, 0)
	} else if kind == reflect.Map && value.IsNil() {
		value = reflect.MakeMap(value.Type())
	} else if (kind == reflect.Pointer || kind == reflect.Func) && value.IsNil() {
		return hostbridge.NullValue(), nil
	}
	if value.CanInterface() {
		if abstract, ok := value.Interface().(jsengine.Value); ok {
			raw, err := s.unwrapEngineValue(abstract)
			if err != nil {
				return hostbridge.UndefinedValue(), err
			}
			return s.toBridgeValue(raw, owner, scope)
		}
		if raw, ok := value.Interface().(g.Value); ok {
			return s.toBridgeValue(raw, owner, scope)
		}
		object, wrapped, err := hostbridge.Wrap(scope, value.Interface())
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
		if wrapped {
			ref, err := s.session.BindObject(object)
			if err != nil {
				return hostbridge.UndefinedValue(), err
			}
			return hostbridge.HostObjectValue(ref), nil
		}
	}
	switch value.Kind() {
	case reflect.Bool:
		return hostbridge.BoolValue(value.Bool()), nil
	case reflect.String:
		return hostbridge.StringValue(value.String()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return hostbridge.IntValue(value.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return hostbridge.UintValue(value.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return hostbridge.FloatValue(value.Float()), nil
	case reflect.Func:
		ref, err := s.session.RegisterFunction(value.Interface())
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.HostFunctionValue(ref), nil
	case reflect.Struct, reflect.Map, reflect.Slice, reflect.Pointer:
		if !value.CanInterface() {
			return hostbridge.UndefinedValue(), fmt.Errorf("goja cannot expose %s", value.Type())
		}
		ref, err := s.session.BindObject(gojaHostTarget(value))
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.HostObjectValue(ref), nil
	default:
		return hostbridge.UndefinedValue(), fmt.Errorf("goja cannot encode %s", value.Type())
	}
}

func (s *gojaHostState) toBridgeValue(value g.Value, owner *runtime, scope hostbridge.ControlledObjectScope) (hostbridge.Value, error) {
	if value == nil || g.IsUndefined(value) {
		return hostbridge.UndefinedValue(), nil
	}
	if g.IsNull(value) {
		return hostbridge.NullValue(), nil
	}
	if callable, ok := g.AssertFunction(value); ok {
		ref := s.registerCallback(value, callable, owner, scope)
		return hostbridge.CallbackValue(ref), nil
	}
	if object, ok := value.(*g.Object); ok {
		switch handler := object.Export().(type) {
		case *gojaHostObject:
			if handler == nil || handler.state != s {
				return hostbridge.UndefinedValue(), errors.New("goja HostRef belongs to another realm")
			}
			return hostbridge.HostObjectValue(handler.ref), nil
		case *gojaHostArray:
			if handler == nil || handler.state != s {
				return hostbridge.UndefinedValue(), errors.New("goja HostRef belongs to another realm")
			}
			return hostbridge.HostObjectValue(handler.ref), nil
		}
	}
	switch raw := value.Export().(type) {
	case nil:
		return hostbridge.NullValue(), nil
	case bool:
		return hostbridge.BoolValue(raw), nil
	case string:
		return hostbridge.StringValue(raw), nil
	case int64:
		return hostbridge.IntValue(raw), nil
	case int32:
		return hostbridge.IntValue(int64(raw)), nil
	case int:
		return hostbridge.IntValue(int64(raw)), nil
	case uint64:
		return hostbridge.UintValue(raw), nil
	case uint32:
		return hostbridge.UintValue(uint64(raw)), nil
	case uint:
		return hostbridge.UintValue(uint64(raw)), nil
	case float64:
		return hostbridge.FloatValue(raw), nil
	case float32:
		return hostbridge.FloatValue(float64(raw)), nil
	default:
		encoded, err := json.Marshal(raw)
		if err != nil {
			return hostbridge.UndefinedValue(), fmt.Errorf("encode Goja value %T: %w", raw, err)
		}
		return hostbridge.Value{Kind: hostbridge.KindJSON, String: string(encoded)}, nil
	}
}

func (s *gojaHostState) fromBridgeValue(value hostbridge.Value, owner *runtime, scope hostbridge.ControlledObjectScope) (g.Value, error) {
	switch value.Kind {
	case hostbridge.KindUndefined:
		return g.Undefined(), nil
	case hostbridge.KindNull:
		return g.Null(), nil
	case hostbridge.KindBool:
		return s.vm.ToValue(value.Bool), nil
	case hostbridge.KindString:
		return s.vm.ToValue(value.String), nil
	case hostbridge.KindInt:
		return s.vm.ToValue(value.Int), nil
	case hostbridge.KindUint:
		return s.vm.ToValue(value.Uint), nil
	case hostbridge.KindFloat:
		return s.vm.ToValue(value.Float), nil
	case hostbridge.KindHostObject:
		return s.hostObjectValue(value.Host, scope)
	case hostbridge.KindHostFunction:
		return s.hostFunctionValue(value.Function, scope)
	case hostbridge.KindCallback:
		callback, err := s.takeCallback(value.Callback)
		if err != nil {
			return nil, err
		}
		if callback.value == nil {
			return nil, hostbridge.ErrStaleRuntimeCallback
		}
		return callback.value, nil
	case hostbridge.KindJSON:
		var decoded any
		if err := json.Unmarshal([]byte(value.String), &decoded); err != nil {
			return nil, fmt.Errorf("decode Goja JSON value: %w", err)
		}
		return s.vm.ToValue(decoded), nil
	default:
		return nil, fmt.Errorf("unsupported Host bridge value kind %d", value.Kind)
	}
}

type gojaHostFunction struct {
	state *gojaHostState
	ref   hostbridge.HostFuncRef
	scope hostbridge.ControlledObjectScope
}

func (f *gojaHostFunction) call(call g.FunctionCall) g.Value {
	owner := f.state.currentRuntime()
	if owner == nil {
		owner = &runtime{vm: f.state.vm, realm: f.state.realm}
	}
	activeScope := f.state.currentScope(f.scope)
	codec := f.state.codec(owner, activeScope)
	arguments := make([]hostbridge.Value, len(call.Arguments))
	defer f.state.discardCallbacks(arguments)
	for index, argument := range call.Arguments {
		converted, err := f.state.toBridgeValue(argument, owner, activeScope)
		if err != nil {
			panic(f.state.vm.NewTypeError("could not convert function call parameter %d: %v", index, err))
		}
		arguments[index] = converted
	}
	result, err := f.state.session.CallFunctionWithCodec(f.ref, arguments, codec)
	if err != nil {
		panic(f.state.vm.NewGoError(err))
	}
	converted, err := f.state.fromBridgeValue(result, owner, activeScope)
	if err != nil {
		panic(f.state.vm.NewGoError(err))
	}
	return converted
}

type gojaHostArray struct {
	state *gojaHostState
	ref   hostbridge.HostRef
	scope hostbridge.ControlledObjectScope
}

func (a *gojaHostArray) fail(err error) {
	if err != nil {
		panic(a.state.vm.NewGoError(err))
	}
}

func (a *gojaHostArray) Len() int {
	value, err := a.state.session.Get(a.ref, "length")
	a.fail(err)
	return int(value.Int)
}

func (a *gojaHostArray) Get(index int) g.Value {
	if index < 0 {
		return nil
	}
	owner := a.state.currentRuntime()
	if owner == nil {
		owner = &runtime{vm: a.state.vm, realm: a.state.realm}
	}
	scope := a.state.currentScope(a.scope)
	value, err := a.state.session.GetWithCodec(a.ref, strconv.Itoa(index), a.state.codec(owner, scope))
	a.fail(err)
	if value.Kind == hostbridge.KindUndefined {
		return nil
	}
	converted, err := a.state.fromBridgeValue(value, owner, scope)
	a.fail(err)
	return converted
}

func (a *gojaHostArray) Set(index int, value g.Value) bool {
	if index < 0 {
		return false
	}
	if g.IsUndefined(value) {
		raw, err := a.state.session.LookupObject(a.ref)
		a.fail(err)
		if !raw.CanSet() || index >= raw.Len() || !raw.Index(index).CanSet() {
			return false
		}
		raw.Index(index).Set(reflect.Zero(raw.Type().Elem()))
		return true
	}
	owner := a.state.currentRuntime()
	if owner == nil {
		owner = &runtime{vm: a.state.vm, realm: a.state.realm}
	}
	scope := a.state.currentScope(a.scope)
	converted, err := a.state.toBridgeValue(value, owner, scope)
	a.fail(err)
	defer a.state.discardCallback(converted)
	a.fail(a.state.session.SetWithCodec(a.ref, strconv.Itoa(index), converted, a.state.codec(owner, scope)))
	return true
}

func (a *gojaHostArray) SetLen(length int) bool {
	if length < 0 {
		return false
	}
	if err := a.state.session.ResizeSlice(a.ref, length); err != nil {
		return false
	}
	return true
}

type gojaHostObject struct {
	state *gojaHostState
	ref   hostbridge.HostRef
	scope hostbridge.ControlledObjectScope
}

func (o *gojaHostObject) fail(err error) {
	if err != nil {
		panic(o.state.vm.NewGoError(err))
	}
}

func (o *gojaHostObject) Get(key string) g.Value {
	owner := o.state.currentRuntime()
	if owner == nil {
		owner = &runtime{vm: o.state.vm, realm: o.state.realm}
	}
	live, found, err := o.state.session.GetRuntimeNative(o.ref, key, func(field reflect.Value) (any, bool, error) {
		if field.Type() != gojaValueType || field.IsNil() {
			return nil, false, nil
		}
		object, ok := field.Interface().(*g.Object)
		if !ok || object == nil {
			return nil, false, nil
		}
		if _, callable := g.AssertFunction(object); callable {
			return nil, false, nil
		}
		return object, true, nil
	})
	o.fail(err)
	if found {
		return live.(*g.Object)
	}
	scope := o.state.currentScope(o.scope)
	value, err := o.state.session.GetWithCodec(o.ref, key, o.state.codec(owner, scope))
	o.fail(err)
	if value.Kind == hostbridge.KindUndefined {
		return nil
	}
	converted, err := o.state.fromBridgeValue(value, owner, scope)
	o.fail(err)
	return converted
}

func (o *gojaHostObject) Set(key string, value g.Value) bool {
	owner := o.state.currentRuntime()
	if owner == nil {
		owner = &runtime{vm: o.state.vm, realm: o.state.realm}
	}
	native, err := o.state.session.SetRuntimeNative(o.ref, key, func(target reflect.Type) (reflect.Value, bool, error) {
		if target != gojaValueType || value == nil || g.IsUndefined(value) || g.IsNull(value) {
			return reflect.Value{}, false, nil
		}
		return reflect.ValueOf(&value).Elem(), true, nil
	})
	o.fail(err)
	if native {
		return true
	}
	scope := o.state.currentScope(o.scope)
	converted, err := o.state.toBridgeValue(value, owner, scope)
	o.fail(err)
	defer o.state.discardCallback(converted)
	o.fail(o.state.session.SetWithCodec(o.ref, key, converted, o.state.codec(owner, scope)))
	return true
}

func (o *gojaHostObject) Has(key string) bool {
	exists, err := o.state.session.Has(o.ref, key)
	o.fail(err)
	return exists
}

func (o *gojaHostObject) Delete(key string) bool {
	deleted, err := o.state.session.Delete(o.ref, key)
	o.fail(err)
	return deleted
}

func (o *gojaHostObject) Keys() []string {
	keys, err := o.state.session.Keys(o.ref)
	o.fail(err)
	return keys
}

var _ g.DynamicArray = (*gojaHostArray)(nil)
var _ g.DynamicObject = (*gojaHostObject)(nil)
var _ hostbridge.RuntimeValueCodec = gojaBridgeCodec{}
