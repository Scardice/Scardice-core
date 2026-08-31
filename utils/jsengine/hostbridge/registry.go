package hostbridge

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
)

type HostRef uint64
type HostFuncRef uint64
type Generation uint64
type CallbackRef uint64
type ValueKind uint8

const (
	KindUndefined ValueKind = iota
	KindNull
	KindBool
	KindString
	KindInt
	KindUint
	KindFloat
	KindHostObject
	KindHostFunction
	KindCallback
)

type Value struct {
	Kind ValueKind
	Bool bool
	String string
	Int int64
	Uint uint64
	Float float64
	Host HostRef
	Function HostFuncRef
	Callback uint64
}

func UndefinedValue() Value { return Value{Kind: KindUndefined} }
func NullValue() Value { return Value{Kind: KindNull} }
func BoolValue(v bool) Value { return Value{Kind: KindBool, Bool: v} }
func StringValue(v string) Value { return Value{Kind: KindString, String: v} }
func IntValue(v int64) Value { return Value{Kind: KindInt, Int: v} }
func UintValue(v uint64) Value { return Value{Kind: KindUint, Uint: v} }
func FloatValue(v float64) Value { return Value{Kind: KindFloat, Float: v} }
func HostObjectValue(v HostRef) Value { return Value{Kind: KindHostObject, Host: v} }
func HostFunctionValue(v HostFuncRef) Value { return Value{Kind: KindHostFunction, Function: v} }
func CallbackValue(v CallbackRef) Value { return Value{Kind: KindCallback, Callback: uint64(v)} }

var (
	ErrStaleRuntimeCallback = errors.New("stale runtime callback")
	ErrSessionClosed = errors.New("host session is closed")
)

// RuntimeValueCodec is the explicit adapter seam for values outside Value,
// especially JavaScript function callbacks. It is never an ABI representation.
type RuntimeValueCodec interface {
	Decode(Value, reflect.Type) (reflect.Value, error)
	Encode(reflect.Value) (Value, error)
	CallCallback(Value, []Value) (Value, error)
}

type objectEntry struct {
	value reflect.Value
	dangerous bool
}
type functionEntry struct {
	value reflect.Value
	owner HostRef
	operation string
}
type identity struct { typ reflect.Type; pointer string }

// Session owns host identities and a callback generation. Registry operations
// are mutex protected and Teardown clears every entry deterministically.
type Session struct {
	mu sync.RWMutex
	nextHost HostRef
	nextFunc HostFuncRef
	generation Generation
	closed bool
	objects map[HostRef]objectEntry
	functions map[HostFuncRef]functionEntry
	identities map[identity]HostRef
}

type Registry = Session

func NewSession() *Session {
	return &Session{generation: 1, objects: make(map[HostRef]objectEntry), functions: make(map[HostFuncRef]functionEntry), identities: make(map[identity]HostRef)}
}
func NewRegistry() *Registry { return NewSession() }
func (s *Session) Generation() Generation { s.mu.RLock(); defer s.mu.RUnlock(); return s.generation }

func (s *Session) RegisterObject(target any) (HostRef, error) { return s.registerObject(target, false) }
func (s *Session) registerObject(target any, dangerous bool) (HostRef, error) {
	v := reflect.ValueOf(target)
	if !v.IsValid() { return 0, errors.New("unsupported nil Host API object") }
	if v.Kind() == reflect.Pointer && v.IsNil() { return 0, fmt.Errorf("unsupported nil Host API object of type %s", v.Type()) }
	v, err := normalizeObject(v)
	if err != nil { return 0, err }
	key, hasIdentity := objectIdentity(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { return 0, ErrSessionClosed }
	if hasIdentity {
		if ref, exists := s.identities[key]; exists {
			if dangerous { entry := s.objects[ref]; entry.dangerous = true; s.objects[ref] = entry }
			return ref, nil
		}
	}
	s.nextHost++
	ref := s.nextHost
	s.objects[ref] = objectEntry{value: v, dangerous: dangerous}
	if hasIdentity { s.identities[key] = ref }
	return ref, nil
}

func normalizeObject(v reflect.Value) (reflect.Value, error) {
	for v.Kind() == reflect.Interface {
		if v.IsNil() { return reflect.Value{}, errors.New("unsupported nil Host API object") }
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() { return reflect.Value{}, fmt.Errorf("unsupported nil Host API object of type %s", v.Type()) }
		if v.Elem().Kind() == reflect.Struct { return v, nil }
		if v.Elem().Kind() == reflect.Slice { return v.Elem(), nil }
	case reflect.Struct:
		copy := reflect.New(v.Type())
		copy.Elem().Set(v)
		return copy, nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String { return reflect.Value{}, fmt.Errorf("unsupported map key type %s", v.Type()) }
		if v.IsNil() { return reflect.Value{}, fmt.Errorf("unsupported nil map %s", v.Type()) }
		return v, nil
	case reflect.Slice:
		return v, nil
	}
	return reflect.Value{}, fmt.Errorf("unsupported Host API binding type %s", v.Type())
}

func objectIdentity(v reflect.Value) (identity, bool) {
	switch v.Kind() {
	case reflect.Pointer:
		return identity{v.Type(), fmt.Sprintf("%x", v.Pointer())}, true
	case reflect.Map:
		return identity{v.Type(), fmt.Sprintf("%p", v.Interface())}, true
	case reflect.Slice:
		if v.Pointer() != 0 { return identity{v.Type(), fmt.Sprintf("%x", v.Pointer())}, true }
	}
	return identity{}, false
}

func (s *Session) RegisterFunction(fn any) (HostFuncRef, error) {
	v := reflect.ValueOf(fn)
	if !v.IsValid() || v.Kind() != reflect.Func || v.IsNil() { return 0, fmt.Errorf("unsupported Host function %T", fn) }
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { return 0, ErrSessionClosed }
	s.nextFunc++
	ref := s.nextFunc
	s.functions[ref] = functionEntry{value: v}
	return ref, nil
}
func (s *Session) registerOperation(owner HostRef, operation string) (HostFuncRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { return 0, ErrSessionClosed }
	if _, ok := s.objects[owner]; !ok { return 0, fmt.Errorf("invalid HostRef %d", owner) }
	s.nextFunc++
	ref := s.nextFunc
	s.functions[ref] = functionEntry{owner: owner, operation: operation}
	return ref, nil
}
func (s *Session) LookupObject(ref HostRef) (reflect.Value, error) { s.mu.RLock(); defer s.mu.RUnlock(); entry, ok := s.objects[ref]; if !ok { return reflect.Value{}, fmt.Errorf("invalid HostRef %d", ref) }; return entry.value, nil }
func (s *Session) LookupFunction(ref HostFuncRef) (reflect.Value, error) { s.mu.RLock(); defer s.mu.RUnlock(); entry, ok := s.functions[ref]; if !ok { return reflect.Value{}, fmt.Errorf("invalid HostFuncRef %d", ref) }; return entry.value, nil }
func (s *Session) ReleaseObject(ref HostRef) error { s.mu.Lock(); defer s.mu.Unlock(); if _, ok := s.objects[ref]; !ok { return fmt.Errorf("invalid HostRef %d", ref) }; delete(s.objects, ref); for key, value := range s.identities { if value == ref { delete(s.identities, key) } }; return nil }
func (s *Session) ReleaseFunction(ref HostFuncRef) error { s.mu.Lock(); defer s.mu.Unlock(); if _, ok := s.functions[ref]; !ok { return fmt.Errorf("invalid HostFuncRef %d", ref) }; delete(s.functions, ref); return nil }
func (s *Session) Teardown() { s.mu.Lock(); defer s.mu.Unlock(); s.objects = make(map[HostRef]objectEntry); s.functions = make(map[HostFuncRef]functionEntry); s.identities = make(map[identity]HostRef); s.generation++; s.closed = true }
func (s *Session) lookupFunctionEntry(ref HostFuncRef) (functionEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.functions[ref]
	if !ok { return functionEntry{}, fmt.Errorf("invalid HostFuncRef %d", ref) }
	return entry, nil
}
func (s *Session) ObjectCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.objects) }
func (s *Session) FunctionCount() int { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.functions) }
func (s *Session) lookupEntry(ref HostRef) (objectEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.objects[ref]
	if !ok {
		return objectEntry{}, fmt.Errorf("invalid HostRef %d", ref)
	}
	return entry, nil
}
