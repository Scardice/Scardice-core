package hostbridge

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

var errProtocolRevoked = errors.New("controlled object is revoked")

type protocolTarget struct {
	ID string
}

type protocolControlled struct {
	ReflectOnly string `jsbind:"reflectOnly"`

	alive  bool
	value  int64
	target *protocolTarget
	child  *protocolControlled
	set    map[string]any
}

func (o *protocolControlled) HostGet(name string) (any, bool, error) {
	if !o.alive {
		return nil, false, errProtocolRevoked
	}
	switch name {
	case "value":
		return o.value, true, nil
	case "child":
		return o.child, o.child != nil, nil
	case "increment":
		return func(delta int64) int64 {
			o.value += delta
			return o.value
		}, true, nil
	default:
		return nil, false, nil
	}
}

func (o *protocolControlled) HostSet(name string, value any) error {
	if !o.alive {
		return errProtocolRevoked
	}
	if o.set == nil {
		o.set = make(map[string]any)
	}
	o.set[name] = value
	if name == "value" {
		number, ok := value.(int64)
		if !ok {
			return fmt.Errorf("value expects int64, got %T", value)
		}
		o.value = number
	}
	return nil
}

func (o *protocolControlled) HostKeys() []string {
	if !o.alive {
		return nil
	}
	return []string{"value", "child", "increment"}
}

func (o *protocolControlled) HostUnwrap(target reflect.Type) (any, error) {
	if !o.alive {
		return nil, errProtocolRevoked
	}
	if target == reflect.TypeFor[*protocolTarget]() {
		return o.target, nil
	}
	return nil, fmt.Errorf("cannot unwrap controlled object into %s", target)
}

func TestControlledObjectUsesOnlyExplicitPropertyProtocol(t *testing.T) {
	session := NewSession()
	controlled := &protocolControlled{alive: true, value: 40, target: &protocolTarget{ID: "root"}}
	ref, err := session.RegisterObject(controlled)
	if err != nil {
		t.Fatal(err)
	}

	value, err := session.Get(ref, "value")
	if err != nil || value.Kind != KindInt || value.Int != 40 {
		t.Fatalf("Get(value) = %#v, %v", value, err)
	}
	if err := session.Set(ref, "value", IntValue(41)); err != nil {
		t.Fatal(err)
	}
	if controlled.value != 41 || controlled.set["value"] != int64(41) {
		t.Fatalf("HostSet did not observe decoded value: %#v", controlled.set)
	}
	if exists, err := session.Has(ref, "value"); err != nil || !exists {
		t.Fatalf("Has(value) = %v, %v", exists, err)
	}
	if exists, err := session.Has(ref, "missing"); err != nil || exists {
		t.Fatalf("Has(missing) = %v, %v", exists, err)
	}
	if reflected, err := session.Get(ref, "reflectOnly"); err != nil || reflected.Kind != KindUndefined {
		t.Fatalf("reflection-only field escaped protocol: %#v, %v", reflected, err)
	}
	if deleted, err := session.Delete(ref, "value"); err != nil || deleted {
		t.Fatalf("Delete(value) = %v, %v; controlled properties are not deletable", deleted, err)
	}
	if controlled.value != 41 {
		t.Fatalf("delete changed controlled state to %d", controlled.value)
	}
	keys, err := session.Keys(ref)
	if err != nil || !reflect.DeepEqual(keys, controlled.HostKeys()) {
		t.Fatalf("Keys() = %#v, %v", keys, err)
	}

	method, err := session.Get(ref, "increment")
	if err != nil || method.Kind != KindHostFunction {
		t.Fatalf("Get(increment) = %#v, %v", method, err)
	}
	result, err := session.CallFunction(method.Function, []Value{IntValue(1)})
	if err != nil || result.Kind != KindInt || result.Int != 42 {
		t.Fatalf("detached increment = %#v, %v", result, err)
	}
}

func TestControlledObjectSetPreservesNullishValuesAndSetterErrors(t *testing.T) {
	for _, test := range []struct {
		name  string
		value Value
	}{
		{name: "null", value: NullValue()},
		{name: "undefined", value: UndefinedValue()},
		{name: "JSON null", value: Value{Kind: KindJSON, String: "null"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := NewSession()
			controlled := &protocolControlled{alive: true}
			ref, err := session.RegisterObject(controlled)
			if err != nil {
				t.Fatal(err)
			}
			if err := session.Set(ref, "direct", test.value); err != nil {
				t.Fatal(err)
			}
			if err := session.SetWithCodec(ref, "codec", test.value, fakeCodec{}); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"direct", "codec"} {
				value, exists := controlled.set[name]
				if !exists || value != nil {
					t.Fatalf("HostSet(%s) received %#v (present=%v), want an explicit nil", name, value, exists)
				}
			}

			controlled.alive = false
			if err := session.Set(ref, "direct", test.value); !errors.Is(err, errProtocolRevoked) {
				t.Fatalf("Set revoked object error = %v, want original setter error", err)
			}
			if err := session.SetWithCodec(ref, "codec", test.value, fakeCodec{}); !errors.Is(err, errProtocolRevoked) {
				t.Fatalf("SetWithCodec revoked object error = %v, want original setter error", err)
			}
		})
	}
}

func TestControlledObjectUnwrapsOnlyThroughHostUnwrap(t *testing.T) {
	session := NewSession()
	target := &protocolTarget{ID: "facade"}
	controlled := &protocolControlled{alive: true, target: target}
	ref, err := session.RegisterObject(controlled)
	if err != nil {
		t.Fatal(err)
	}
	accept, err := session.RegisterFunction(func(value *protocolTarget) bool { return value == target })
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.CallFunction(accept, []Value{HostObjectValue(ref)})
	if err != nil || result.Kind != KindBool || !result.Bool {
		t.Fatalf("typed controlled argument = %#v, %v", result, err)
	}

	wrong, err := session.RegisterFunction(func(value *protocolControlled) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.CallFunction(wrong, []Value{HostObjectValue(ref)}); err == nil {
		t.Fatal("controlled wrapper was exposed through reflection instead of HostUnwrap")
	}

	controlled.alive = false
	if _, err := session.CallFunction(accept, []Value{HostObjectValue(ref)}); !errors.Is(err, errProtocolRevoked) {
		t.Fatalf("stale HostUnwrap error = %v", err)
	}
	if _, err := session.Get(ref, "value"); !errors.Is(err, errProtocolRevoked) {
		t.Fatalf("stale HostGet error = %v", err)
	}
	if err := session.Set(ref, "value", IntValue(1)); !errors.Is(err, errProtocolRevoked) {
		t.Fatalf("stale HostSet error = %v", err)
	}
}

func TestControlledNestedObjectsKeepSessionIdentity(t *testing.T) {
	session := NewSession()
	child := &protocolControlled{alive: true, target: &protocolTarget{ID: "child"}}
	root := &protocolControlled{alive: true, child: child, target: &protocolTarget{ID: "root"}}
	rootRef, err := session.RegisterObject(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.Get(rootRef, "child")
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.Get(rootRef, "child")
	if err != nil {
		t.Fatal(err)
	}
	if first.Kind != KindHostObject || second.Kind != KindHostObject || first.Host != second.Host {
		t.Fatalf("nested controlled identity changed: %#v then %#v", first, second)
	}
	if err := session.Set(rootRef, "child", second); err != nil {
		t.Fatal(err)
	}
	if got := root.set["child"]; got != child {
		t.Fatalf("controlled HostRef setter decoded to %#v (%T), want child wrapper", got, got)
	}
}

type gojaTaggedHost struct {
	Neutral string `jsbind:"value"`
	Legacy  string `jsbindgoja:"value"`
}

func TestGojaSessionPrefersJsbindgojaField(t *testing.T) {
	session := NewGojaSession()
	host := &gojaTaggedHost{Neutral: "neutral", Legacy: "legacy"}
	ref, err := session.RegisterObject(host)
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.Get(ref, "value")
	if err != nil {
		t.Fatal(err)
	}
	if value.String != "legacy" {
		t.Fatalf("value = %#v, want jsbindgoja field", value)
	}
	if err := session.Set(ref, "value", StringValue("changed")); err != nil {
		t.Fatal(err)
	}
	if host.Legacy != "changed" || host.Neutral != "neutral" {
		t.Fatalf("wrong field selected: %#v", host)
	}
}
