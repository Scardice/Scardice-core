package hostbridge

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type childHost struct {
	Value int `jsbind:"value"`
}
type demoHost struct {
	Name     string `jsbind:"name"`
	Locked   int    `jsbind:"locked" jsbindlock:"Lock"`
	Hidden   string
	Skip     string                 `jsbind:"-"`
	Child    childHost              `jsbind:"child"`
	Callback func(int) (int, error) `jsbind:"callback"`
	mu       sync.RWMutex
}

func (h *demoHost) Lock() *sync.RWMutex        { return &h.mu }
func (h *demoHost) Add(value int) (int, error) { return h.Locked + value, nil }
func (h *demoHost) Fail() (int, error)         { return 0, errors.New("failed") }
func (h *demoHost) Boom() int                  { panic("boom") }

type fakeCodec struct {
	callbacks map[uint64]func([]Value) (Value, error)
}

func (f fakeCodec) Decode(v Value, target reflect.Type) (reflect.Value, error) {
	if v.Kind != KindCallback {
		return reflect.Value{}, errors.New("expected callback")
	}
	return reflect.MakeFunc(target, func(args []reflect.Value) []reflect.Value {
		in := make([]Value, len(args))
		for i, arg := range args {
			in[i] = IntValue(arg.Int())
		}
		out, err := f.callbacks[v.Callback](in)
		if err != nil {
			return []reflect.Value{reflect.Zero(target.Out(0)), reflect.ValueOf(err)}
		}
		result := reflect.New(target.Out(0)).Elem()
		result.SetInt(out.Int)
		return []reflect.Value{result, reflect.Zero(target.Out(1))}
	}), nil
}
func (f fakeCodec) Encode(v reflect.Value) (Value, error) { return IntValue(v.Int()), nil }
func (f fakeCodec) CallCallback(v Value, args []Value) (Value, error) {
	return f.callbacks[v.Callback](args)
}

func TestHostBridgeStructFieldsTagsMethodsAndCopy(t *testing.T) {
	s := NewSession()
	h := &demoHost{Name: "before", Locked: 2, Child: childHost{Value: 4}}
	ref, err := s.RegisterObject(h)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Get(ref, "name")
	if err != nil || v.String != "before" {
		t.Fatalf("get = %#v, %v", v, err)
	}
	if err := s.Set(ref, "name", StringValue("after")); err != nil {
		t.Fatal(err)
	}
	if h.Name != "after" {
		t.Fatalf("setter did not update host: %q", h.Name)
	}
	if ok, _ := s.Has(ref, "hidden"); ok {
		t.Fatal("unbound field exposed")
	}
	if ok, _ := s.Has(ref, "skip"); ok {
		t.Fatal("dash field exposed")
	}
	if ok, _ := s.Has(ref, "add"); !ok {
		t.Fatal("lower-camel method missing")
	}
	result, err := s.Call(ref, "add", []Value{IntValue(3)})
	if err != nil || result.Int != 5 {
		t.Fatalf("method = %#v, %v", result, err)
	}
	child, err := s.Get(ref, "child")
	if err != nil || child.Kind != KindHostObject {
		t.Fatalf("child = %#v, %v", child, err)
	}
	missing, err := s.Get(ref, "missing")
	if err != nil || missing.Kind != KindUndefined {
		t.Fatalf("missing property = %#v, %v", missing, err)
	}
	copyRef, err := s.RegisterObject(demoHost{Name: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	copyName, _ := s.Get(copyRef, "name")
	if copyName.String != "copy" {
		t.Fatalf("copy = %#v", copyName)
	}
}

func TestHostBridgeMapAndSliceState(t *testing.T) {
	s := NewSession()
	m := map[string]int{"b": 2, "a": 1}
	mr, _ := s.RegisterObject(m)
	got, err := s.Get(mr, "a")
	if err != nil || got.Int != 1 {
		t.Fatalf("map get %#v %v", got, err)
	}
	if err := s.Set(mr, "c", IntValue(3)); err != nil || m["c"] != 3 {
		t.Fatalf("map set: %v %#v", err, m)
	}
	if ok, err := s.Delete(mr, "b"); err != nil || !ok || len(m) != 2 {
		t.Fatalf("map delete: %v %v", ok, err)
	}
	keys, err := s.Keys(mr)
	if err != nil || !reflect.DeepEqual(keys, []string{"a", "c"}) {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	items := []int{1, 2}
	sr, _ := s.RegisterObject(&items)
	v, _ := s.Get(sr, "length")
	if v.Int != 2 {
		t.Fatalf("length=%#v", v)
	}
	if err := s.Set(sr, "1", IntValue(7)); err != nil || items[1] != 7 {
		t.Fatalf("slice set: %v %v", err, items)
	}
	pushed, err := s.Call(sr, "push", []Value{IntValue(9)})
	if err != nil || pushed.Int != 3 || !reflect.DeepEqual(items, []int{1, 7, 9}) {
		t.Fatalf("push=%#v err=%v items=%v", pushed, err, items)
	}
	if _, err := s.Get(sr, "invalid"); !errors.Is(err, ErrInvalidSliceIndex) {
		t.Fatalf("invalid slice index error = %v, want ErrInvalidSliceIndex", err)
	}
	missing, err := s.Get(sr, "99")
	if err != nil || missing.Kind != KindUndefined {
		t.Fatalf("out-of-range slice value = %#v, %v", missing, err)
	}
}

func TestHostBridgeIdentityGenerationTeardownAndDiagnostics(t *testing.T) {
	s := NewSession()
	h := &demoHost{}
	first, _ := s.RegisterObject(h)
	second, _ := s.RegisterObject(h)
	if first != second {
		t.Fatalf("pointer identity refs differ: %d %d", first, second)
	}
	if _, err := s.RegisterObject((*demoHost)(nil)); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil diagnostic: %v", err)
	}
	if _, err := s.Get(HostRef(999), "name"); err == nil {
		t.Fatal("invalid ref accepted")
	}
	old := s.Generation()
	s.Teardown()
	if _, err := s.Get(first, "name"); err == nil {
		t.Fatal("released object accepted")
	}
	if s.Generation() == old {
		t.Fatal("generation did not advance")
	}
}
func TestHostBridgeObjectProxyReferencesReleaseOnLastProxy(t *testing.T) {
	s := NewSession()
	host := &demoHost{}
	ref, err := s.BindObject(host)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RetainObject(ref); err != nil {
		t.Fatal(err)
	}
	if err := s.RetainObject(ref); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseObject(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupObject(ref); err != nil {
		t.Fatalf("object released while a proxy still owns it: %v", err)
	}
	if err := s.ReleaseObject(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupObject(ref); err == nil {
		t.Fatal("object retained after the last proxy was released")
	}
	if next, err := s.BindObject(host); err != nil || next == ref {
		t.Fatalf("released identity was not re-registered: ref=%d err=%v", next, err)
	}
	if err := s.ReleaseObject(ref); err == nil {
		t.Fatal("release underflow accepted")
	}
}

func TestHostBridgeMethodFunctionOwnerKeepsHostRefAlive(t *testing.T) {
	session := NewSession()
	host := &demoHost{Locked: 40}
	owner, err := session.BindObject(host)
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.Get(owner, "Add")
	if err != nil || value.Kind != KindHostFunction {
		t.Fatalf("Get(Add) = %#v, %v", value, err)
	}
	function := value.Function
	functionOwner, err := session.FunctionOwner(function)
	if err != nil || functionOwner != owner {
		t.Fatalf("FunctionOwner() = %d, %v; want %d", functionOwner, err, owner)
	}
	repeated, err := session.Get(owner, "Add")
	if err != nil || repeated.Kind != KindHostFunction || repeated.Function != function {
		t.Fatalf("repeated Get(Add) = %#v, %v; want existing HostFuncRef %d", repeated, err, function)
	}
	if got := session.FunctionCount(); got != 1 {
		t.Fatalf("function count after duplicate method reads = %d, want 1", got)
	}
	if err := session.ReleaseFunction(function); err != nil {
		t.Fatal(err)
	}
	recreated, err := session.Get(owner, "Add")
	if err != nil || recreated.Kind != KindHostFunction || recreated.Function == function {
		t.Fatalf("Get(Add) after ReleaseFunction = %#v, %v; want a fresh owner operation", recreated, err)
	}
	function = recreated.Function
	if got := session.FunctionCount(); got != 1 {
		t.Fatalf("function count after recreating released owner operation = %d, want 1", got)
	}
	if err := session.RetainObject(owner); err != nil {
		t.Fatal(err)
	}
	if err := session.RetainObject(owner); err != nil {
		t.Fatal(err)
	}
	if err := session.ReleaseObject(owner); err != nil {
		t.Fatal(err)
	}
	if _, err := session.LookupObject(owner); err != nil {
		t.Fatalf("method owner released while function proxy remains: %v", err)
	}
	result, err := session.CallFunction(function, []Value{IntValue(2)})
	if err != nil || result.Kind != KindInt || result.Int != 42 {
		t.Fatalf("CallFunction() = %#v, %v; want 42", result, err)
	}
	if err := session.ReleaseObject(owner); err != nil {
		t.Fatal(err)
	}
	if _, err := session.LookupObject(owner); err == nil {
		t.Fatal("method owner remained after parent and function proxies were released")
	}
	if got := session.FunctionCount(); got != 0 {
		t.Fatalf("owner function entries remained after last proxy release: %d", got)
	}
	if _, err := session.LookupFunction(function); err == nil {
		t.Fatal("method function remained callable after its last owner proxy was released")
	}
}

func TestHostBridgeFunctionErrorsPanicsAndCallbackCodec(t *testing.T) {
	s := NewSession()
	h := &demoHost{}
	ref, _ := s.RegisterObject(h)
	if _, err := s.Call(ref, "fail", nil); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("error return: %v", err)
	}
	if _, err := s.Call(ref, "boom", nil); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("panic recovery: %v", err)
	}
	fref, err := s.RegisterFunction(func(a int) (int, error) { return a + 1, nil })
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.CallFunction(fref, []Value{IntValue(4)})
	if err != nil || out.Int != 5 {
		t.Fatalf("function=%#v err=%v", out, err)
	}
	codec := fakeCodec{callbacks: map[uint64]func([]Value) (Value, error){7: func(args []Value) (Value, error) { return IntValue(args[0].Int * 2), nil }}}
	cb, err := s.Callback(codec, CallbackValue(7), reflect.TypeFor[func(int) (int, error)]())
	if err != nil {
		t.Fatal(err)
	}
	results := cb.Call([]reflect.Value{reflect.ValueOf(3)})
	if results[0].Int() != 6 || !results[1].IsNil() {
		t.Fatalf("callback=%v", results)
	}
	s.Teardown()
	results = cb.Call([]reflect.Value{reflect.ValueOf(3)})
	if results[0].Int() != 0 || !errors.Is(results[1].Interface().(error), ErrStaleRuntimeCallback) {
		t.Fatalf("stale callback=%v", results)
	}
}

type invalidLockHost struct {
	Value int `jsbind:"value" jsbindlock:"Lock"`
}

func (*invalidLockHost) Lock() int { return 1 }

func TestHostBridgeDangerousExposureAndLockValidation(t *testing.T) {
	s := NewSession()
	ref, err := s.ExposeDangerous(&demoHost{Hidden: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Has(ref, "hidden"); err != nil || !ok {
		t.Fatalf("dangerous field missing: %v %v", ok, err)
	}
	v, err := s.Get(ref, "Hidden")
	if err != nil || v.String != "secret" {
		t.Fatalf("dangerous field: %#v %v", v, err)
	}
	if _, err := s.RegisterObject(&invalidLockHost{}); err != nil {
		t.Fatal("registration should defer lock validation", err)
	}
	bad, _ := s.RegisterObject(&invalidLockHost{})
	if _, err := s.Get(bad, "value"); err == nil || !strings.Contains(err.Error(), "jsbindlock") {
		t.Fatalf("lock validation: %v", err)
	}
}

func TestHostBridgeCallbackFieldUsesExplicitCodec(t *testing.T) {
	s := NewSession()
	h := &demoHost{}
	ref, _ := s.RegisterObject(h)
	codec := fakeCodec{callbacks: map[uint64]func([]Value) (Value, error){9: func(args []Value) (Value, error) { return IntValue(args[0].Int + 10), nil }}}
	if err := s.SetWithCodec(ref, "callback", CallbackValue(9), codec); err != nil {
		t.Fatal(err)
	}
	if h.Callback == nil {
		t.Fatal("callback was not assigned")
	}
	result, err := h.Callback(2)
	if err != nil || result != 12 {
		t.Fatalf("callback result=%d err=%v", result, err)
	}
}

func TestHostBridgeRejectsInvalidObjectTypes(t *testing.T) {
	s := NewSession()
	for _, value := range []any{nil, 4, map[int]int{1: 2}, (*demoHost)(nil)} {
		if _, err := s.RegisterObject(value); err == nil {
			t.Fatalf("accepted invalid object %#v", value)
		}
	}
}
func TestHostBridgeGetReturnsCallableFunctionHandles(t *testing.T) {
	s := NewSession()
	h := &demoHost{Locked: 2}
	ref, _ := s.RegisterObject(h)
	method, err := s.Get(ref, "add")
	if err != nil || method.Kind != KindHostFunction || method.Function == 0 {
		t.Fatalf("method handle=%#v err=%v", method, err)
	}
	result, err := s.CallFunction(method.Function, []Value{IntValue(3)})
	if err != nil || result.Int != 5 {
		t.Fatalf("method call=%#v err=%v", result, err)
	}
	items := []int{1}
	sr, _ := s.RegisterObject(&items)
	push, err := s.Get(sr, "push")
	if err != nil || push.Kind != KindHostFunction || push.Function == 0 {
		t.Fatalf("push handle=%#v err=%v", push, err)
	}
	result, err = s.CallFunction(push.Function, []Value{IntValue(4)})
	if err != nil || result.Int != 2 || !reflect.DeepEqual(items, []int{1, 4}) {
		t.Fatalf("push call=%#v err=%v items=%v", result, err, items)
	}
}

func TestHostBridgeReadOnlySliceRejectsWrites(t *testing.T) {
	s := NewSession()
	items := []int{1}
	ref, _ := s.RegisterObject(items)
	if err := s.Set(ref, "0", IntValue(2)); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only slice set: %v", err)
	}
}

func TestHostBridgePreservesUint64Values(t *testing.T) {
	s := NewSession()
	values := map[string]uint64{"max": ^uint64(0)}
	ref, _ := s.RegisterObject(values)
	got, err := s.Get(ref, "max")
	if err != nil || got.Kind != KindUint || got.Uint != ^uint64(0) {
		t.Fatalf("uint64 value=%#v err=%v", got, err)
	}
	floatValues := map[string]float64{"small": math.SmallestNonzeroFloat64}
	floatRef, _ := s.RegisterObject(floatValues)
	floatValue, err := s.Get(floatRef, "small")
	if err != nil || floatValue.Kind != KindFloat || floatValue.Float != math.SmallestNonzeroFloat64 {
		t.Fatalf("float64 value=%#v err=%v", floatValue, err)
	}
}

type jsonHostItem struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Count    int      `json:"count"`
	Ratio    float64  `json:"ratio"`
	Labels   []string `json:"labels"`
	Optional *string  `json:"optional"`
}

type jsonConversionHost struct {
	Mapping map[string]jsonHostItem `jsbind:"mapping"`
	Items   []jsonHostItem          `jsbind:"items"`
	Dynamic any                     `jsbind:"dynamic"`
	Name    string                  `jsbind:"name"`
}

func TestHostBridgeDecodesJSONSnapshotsIntoExplicitTargets(t *testing.T) {
	s := NewSession()
	host := &jsonConversionHost{}
	ref, err := s.RegisterObject(host)
	if err != nil {
		t.Fatal(err)
	}

	mappingJSON := Value{Kind: KindJSON, String: `{"first":{"name":"alpha","enabled":true,"count":7,"ratio":1.5,"labels":["one","two"],"optional":null}}`}
	if err := s.Set(ref, "mapping", mappingJSON); err != nil {
		t.Fatal(err)
	}
	wantMapping := map[string]jsonHostItem{
		"first": {Name: "alpha", Enabled: true, Count: 7, Ratio: 1.5, Labels: []string{"one", "two"}},
	}
	if !reflect.DeepEqual(host.Mapping, wantMapping) {
		t.Fatalf("mapping = %#v, want %#v", host.Mapping, wantMapping)
	}

	itemsJSON := Value{Kind: KindJSON, String: `[{"name":"beta","enabled":false,"count":-2,"ratio":0.25,"labels":[],"optional":null}]`}
	if err := s.Set(ref, "items", itemsJSON); err != nil {
		t.Fatal(err)
	}
	wantItems := []jsonHostItem{{Name: "beta", Count: -2, Ratio: 0.25, Labels: []string{}}}
	if !reflect.DeepEqual(host.Items, wantItems) {
		t.Fatalf("items = %#v, want %#v", host.Items, wantItems)
	}

	dynamicJSON := Value{Kind: KindJSON, String: `{"text":"value","enabled":true,"count":3,"nothing":null,"nested":["item",2,false,null]}`}
	if err := s.Set(ref, "dynamic", dynamicJSON); err != nil {
		t.Fatal(err)
	}
	wantDynamic := map[string]any{
		"text":    "value",
		"enabled": true,
		"count":   float64(3),
		"nothing": nil,
		"nested":  []any{"item", float64(2), false, nil},
	}
	if !reflect.DeepEqual(host.Dynamic, wantDynamic) {
		t.Fatalf("dynamic = %#v, want %#v", host.Dynamic, wantDynamic)
	}
}

func TestHostBridgeJSONSnapshotsRejectIncompatibleOrMalformedData(t *testing.T) {
	s := NewSession()
	original := map[string]jsonHostItem{"kept": {Name: "original"}}
	host := &jsonConversionHost{Mapping: original, Name: "unchanged"}
	ref, err := s.RegisterObject(host)
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]Value{
		"wrong nested scalar type": {Kind: KindJSON, String: `{"bad":{"name":42}}`},
		"malformed JSON":           {Kind: KindJSON, String: `{"bad":`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.Set(ref, "mapping", value); err == nil {
				t.Fatal("invalid JSON snapshot was accepted")
			}
			if !reflect.DeepEqual(host.Mapping, original) {
				t.Fatalf("failed conversion changed mapping to %#v", host.Mapping)
			}
		})
	}

	if err := s.Set(ref, "name", Value{Kind: KindJSON, String: `"replacement"`}); err == nil {
		t.Fatal("JSON snapshot escaped into a scalar target")
	}
	if host.Name != "unchanged" {
		t.Fatalf("failed scalar conversion changed name to %q", host.Name)
	}
}

func TestHostBridgeJSONNullClearsNullableTargets(t *testing.T) {
	s := NewSession()
	host := &jsonConversionHost{
		Mapping: map[string]jsonHostItem{"value": {}},
		Items:   []jsonHostItem{{Name: "value"}},
		Dynamic: map[string]any{"value": true},
	}
	ref, err := s.RegisterObject(host)
	if err != nil {
		t.Fatal(err)
	}
	nullJSON := Value{Kind: KindJSON, String: "null"}
	for _, field := range []string{"mapping", "items", "dynamic"} {
		if err := s.Set(ref, field, nullJSON); err != nil {
			t.Fatalf("clear %s: %v", field, err)
		}
	}
	if host.Mapping != nil || host.Items != nil || host.Dynamic != nil {
		t.Fatalf("JSON null did not clear nullable targets: %#v", host)
	}
}
