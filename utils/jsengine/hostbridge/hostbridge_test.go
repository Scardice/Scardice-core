package hostbridge

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type childHost struct { Value int `jsbind:"value"` }
type demoHost struct {
	Name string `jsbind:"name"`
	Locked int `jsbind:"locked" jsbindlock:"Lock"`
	Hidden string
	Skip string `jsbind:"-"`
	Child childHost `jsbind:"child"`
	Callback func(int) (int, error) `jsbind:"callback"`
	mu sync.RWMutex
}
func (h *demoHost) Lock() *sync.RWMutex { return &h.mu }
func (h *demoHost) Add(value int) (int, error) { return h.Locked + value, nil }
func (h *demoHost) Fail() (int, error) { return 0, errors.New("failed") }
func (h *demoHost) Boom() int { panic("boom") }

type fakeCodec struct { callbacks map[uint64]func([]Value) (Value, error) }
func (f fakeCodec) Decode(v Value, target reflect.Type) (reflect.Value, error) {
	if v.Kind != KindCallback { return reflect.Value{}, errors.New("expected callback") }
	return reflect.MakeFunc(target, func(args []reflect.Value) []reflect.Value {
		in := make([]Value, len(args)); for i, arg := range args { in[i] = IntValue(arg.Int()) }
		out, err := f.callbacks[v.Callback](in); if err != nil { return []reflect.Value{reflect.Zero(target.Out(0)), reflect.ValueOf(err)} }
		result := reflect.New(target.Out(0)).Elem(); result.SetInt(out.Int); return []reflect.Value{result, reflect.Zero(target.Out(1))}
	}), nil
}
func (f fakeCodec) Encode(v reflect.Value) (Value, error) { return IntValue(v.Int()), nil }
func (f fakeCodec) CallCallback(v Value, args []Value) (Value, error) { return f.callbacks[v.Callback](args) }

func TestHostBridgeStructFieldsTagsMethodsAndCopy(t *testing.T) {
	s := NewSession()
	h := &demoHost{Name: "before", Locked: 2, Child: childHost{Value: 4}}
	ref, err := s.RegisterObject(h); if err != nil { t.Fatal(err) }
	v, err := s.Get(ref, "name"); if err != nil || v.String != "before" { t.Fatalf("get = %#v, %v", v, err) }
	if err := s.Set(ref, "name", StringValue("after")); err != nil { t.Fatal(err) }
	if h.Name != "after" { t.Fatalf("setter did not update host: %q", h.Name) }
	if ok, _ := s.Has(ref, "hidden"); ok { t.Fatal("unbound field exposed") }
	if ok, _ := s.Has(ref, "skip"); ok { t.Fatal("dash field exposed") }
	if ok, _ := s.Has(ref, "add"); !ok { t.Fatal("lower-camel method missing") }
	result, err := s.Call(ref, "add", []Value{IntValue(3)}); if err != nil || result.Int != 5 { t.Fatalf("method = %#v, %v", result, err) }
	child, err := s.Get(ref, "child"); if err != nil || child.Kind != KindHostObject { t.Fatalf("child = %#v, %v", child, err) }
	missing, err := s.Get(ref, "missing"); if err != nil || missing.Kind != KindUndefined { t.Fatalf("missing property = %#v, %v", missing, err) }
	copyRef, err := s.RegisterObject(demoHost{Name: "copy"}); if err != nil { t.Fatal(err) }
	copyName, _ := s.Get(copyRef, "name"); if copyName.String != "copy" { t.Fatalf("copy = %#v", copyName) }
}

func TestHostBridgeMapAndSliceState(t *testing.T) {
	s := NewSession(); m := map[string]int{"b": 2, "a": 1}; mr, _ := s.RegisterObject(m)
	got, err := s.Get(mr, "a"); if err != nil || got.Int != 1 { t.Fatalf("map get %#v %v", got, err) }
	if err := s.Set(mr, "c", IntValue(3)); err != nil || m["c"] != 3 { t.Fatalf("map set: %v %#v", err, m) }
	if ok, err := s.Delete(mr, "b"); err != nil || !ok || len(m) != 2 { t.Fatalf("map delete: %v %v", ok, err) }
	keys, err := s.Keys(mr); if err != nil || !reflect.DeepEqual(keys, []string{"a", "c"}) { t.Fatalf("keys=%v err=%v", keys, err) }
	items := []int{1, 2}; sr, _ := s.RegisterObject(&items)
	v, _ := s.Get(sr, "length"); if v.Int != 2 { t.Fatalf("length=%#v", v) }
	if err := s.Set(sr, "1", IntValue(7)); err != nil || items[1] != 7 { t.Fatalf("slice set: %v %v", err, items) }
	pushed, err := s.Call(sr, "push", []Value{IntValue(9)}); if err != nil || pushed.Int != 3 || !reflect.DeepEqual(items, []int{1, 7, 9}) { t.Fatalf("push=%#v err=%v items=%v", pushed, err, items) }
}

func TestHostBridgeIdentityGenerationTeardownAndDiagnostics(t *testing.T) {
	s := NewSession(); h := &demoHost{}; first, _ := s.RegisterObject(h); second, _ := s.RegisterObject(h)
	if first != second { t.Fatalf("pointer identity refs differ: %d %d", first, second) }
	if _, err := s.RegisterObject((*demoHost)(nil)); err == nil || !strings.Contains(err.Error(), "nil") { t.Fatalf("nil diagnostic: %v", err) }
	if _, err := s.Get(HostRef(999), "name"); err == nil { t.Fatal("invalid ref accepted") }
	old := s.Generation(); s.Teardown(); if _, err := s.Get(first, "name"); err == nil { t.Fatal("released object accepted") }
	if s.Generation() == old { t.Fatal("generation did not advance") }
}

func TestHostBridgeFunctionErrorsPanicsAndCallbackCodec(t *testing.T) {
	s := NewSession(); h := &demoHost{}; ref, _ := s.RegisterObject(h)
	if _, err := s.Call(ref, "fail", nil); err == nil || !strings.Contains(err.Error(), "failed") { t.Fatalf("error return: %v", err) }
	if _, err := s.Call(ref, "boom", nil); err == nil || !strings.Contains(err.Error(), "boom") { t.Fatalf("panic recovery: %v", err) }
	fref, err := s.RegisterFunction(func(a int) (int, error) { return a + 1, nil }); if err != nil { t.Fatal(err) }
	out, err := s.CallFunction(fref, []Value{IntValue(4)}); if err != nil || out.Int != 5 { t.Fatalf("function=%#v err=%v", out, err) }
	codec := fakeCodec{callbacks: map[uint64]func([]Value)(Value,error){7: func(args []Value)(Value,error) { return IntValue(args[0].Int * 2), nil }}}
	cb, err := s.Callback(codec, CallbackValue(7), reflect.TypeFor[func(int) (int,error)]()); if err != nil { t.Fatal(err) }
	results := cb.Call([]reflect.Value{reflect.ValueOf(3)}); if results[0].Int() != 6 || !results[1].IsNil() { t.Fatalf("callback=%v", results) }
	s.Teardown(); results = cb.Call([]reflect.Value{reflect.ValueOf(3)}); if results[0].Int() != 0 || !errors.Is(results[1].Interface().(error), ErrStaleRuntimeCallback) { t.Fatalf("stale callback=%v", results) }
}

type invalidLockHost struct { Value int `jsbind:"value" jsbindlock:"Lock"` }
func (*invalidLockHost) Lock() int { return 1 }

func TestHostBridgeDangerousExposureAndLockValidation(t *testing.T) {
	s := NewSession(); ref, err := s.ExposeDangerous(&demoHost{Hidden: "secret"}); if err != nil { t.Fatal(err) }
	if ok, err := s.Has(ref, "hidden"); err != nil || !ok { t.Fatalf("dangerous field missing: %v %v", ok, err) }
	v, err := s.Get(ref, "Hidden"); if err != nil || v.String != "secret" { t.Fatalf("dangerous field: %#v %v", v, err) }
	if _, err := s.RegisterObject(&invalidLockHost{}); err != nil { t.Fatal("registration should defer lock validation", err) }
	bad, _ := s.RegisterObject(&invalidLockHost{}); if _, err := s.Get(bad, "value"); err == nil || !strings.Contains(err.Error(), "jsbindlock") { t.Fatalf("lock validation: %v", err) }
}

func TestHostBridgeCallbackFieldUsesExplicitCodec(t *testing.T) {
	s := NewSession(); h := &demoHost{}; ref, _ := s.RegisterObject(h)
	codec := fakeCodec{callbacks: map[uint64]func([]Value) (Value, error){9: func(args []Value) (Value, error) { return IntValue(args[0].Int + 10), nil }}}
	if err := s.SetWithCodec(ref, "callback", CallbackValue(9), codec); err != nil { t.Fatal(err) }
	if h.Callback == nil { t.Fatal("callback was not assigned") }
	result, err := h.Callback(2); if err != nil || result != 12 { t.Fatalf("callback result=%d err=%v", result, err) }
}

func TestHostBridgeRejectsInvalidObjectTypes(t *testing.T) {
	s := NewSession(); for _, value := range []any{nil, 4, map[int]int{1: 2}, (*demoHost)(nil)} {
		if _, err := s.RegisterObject(value); err == nil { t.Fatalf("accepted invalid object %#v", value) }
	}
}
