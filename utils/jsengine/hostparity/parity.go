package hostparity

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"Scardice-core/utils/jsengine"
)

// Engine opens one runtime implementation and optionally exposes its explicit
// dangerous-host operation. The assertions below are intentionally shared by
// legacy QuickJS-Go and native QuickJS so their observable contracts cannot
// drift silently.
type Engine struct {
	Name           string
	Open           func(*testing.T) jsengine.Loop
	ExposeDangerous func(jsengine.Runtime, any) (jsengine.Value, error)
}

type nestedHost struct {
	Value  string         `jsbind:"value"`
	Values map[string]int  `jsbind:"values"`
	Items  *[]int          `jsbind:"items"`
}
type host struct {
	Name     string         `jsbind:"name"`
	Count    int            `jsbind:"count"`
	Locked   int            `jsbind:"locked" jsbindlock:"Lock"`
	Nested   *nestedHost    `jsbind:"nested"`
	Values   map[string]int `jsbind:"values"`
	Items    *[]int         `jsbind:"items"`
	Callback func(int) int  `jsbind:"callback"`
	Hidden   string         `jsbind:"-"`
	lock     sync.RWMutex
}

func (h *host) Lock() *sync.RWMutex { return &h.lock }
func (h *host) Add(delta int) int { return h.Count + delta }
func (h *host) Apply(callback func(int) int) int { return callback(5) + 1 }
func (h *host) Fail() (int, error) { return 0, errors.New("host failure") }
func (h *host) Variadic(prefix string, values ...string) int { return len(prefix) + len(values) }
func (h *host) ReadOnlyItems() []int { return []int{7} }

func newHost() *host {
	items := []int{3}
	nestedItems := []int{4}
	return &host{
		Name: "before", Count: 40, Locked: 1, Hidden: "secret",
		Nested: &nestedHost{Value: "nested-before", Values: map[string]int{"entry": 5}, Items: &nestedItems},
		Values: map[string]int{"bar": 2, "foo": 1}, Items: &items,
	}
}

// Run executes every host-proxy assertion against one engine.
func Run(t *testing.T, engine Engine) {
	t.Helper()
	t.Run(engine.Name, func(t *testing.T) {
		t.Helper()
		loop := engine.Open(t)
		defer func() { _ = loop.Close() }()
		h := newHost()
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			if err := runtime.Bind("host", h); err != nil {
				return err
			}
			return assertContract(runtime, h)
		}); err != nil {
			t.Fatal(err)
		}
		if h.Name != "after" || h.Count != 41 || h.Locked != 9 ||
			h.Values["foo"] != 0 || h.Values["added"] != 11 ||
			(*h.Items)[0] != 8 || len(*h.Items) != 3 ||
			h.Nested.Value != "nested-after" || h.Nested.Values["entry"] != 6 ||
			(*h.Nested.Items)[0] != 12 {
			t.Fatalf("host mutations differ: %#v items=%#v nested=%#v nestedItems=%#v", h, *h.Items, h.Nested, *h.Nested.Items)
		}
		if h.Callback == nil {
			t.Fatalf("callback assignment did not survive runtime")
		}

		if engine.ExposeDangerous == nil {
			t.Fatal("engine does not provide dangerous exposure adapter")
		}
		dangerous := newHost()
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			value, err := engine.ExposeDangerous(runtime, dangerous)
			if err != nil {
				return err
			}
			if err := runtime.Set("dangerous", value); err != nil {
				return err
			}
			return assertDangerousContract(runtime)
		}); err != nil {
			t.Fatal(err)
		}
		if dangerous.Hidden != "revealed" {
			t.Fatalf("dangerous field mutation = %q, want revealed", dangerous.Hidden)
		}
	})
}

func assertContract(runtime jsengine.Runtime, h *host) error {
	cases := []struct {
		name   string
		source string
		check  func(any) error
	}{
		{"struct read/write", `host.name = "after"; host.count = host.count + 1; host.locked = 9; host.name + ":" + host.count`, func(value any) error { return want(value, "after:41") }},
		{"struct keys and lower-camel methods", `Object.keys(host).sort().join(",")`, func(value any) error {
			return want(value, "add,apply,callback,count,fail,items,lock,locked,name,nested,readOnlyItems,values,variadic")
		}},
		{"map read/write/delete/missing", `const mapBefore = Object.keys(host.values).sort().join(","); host.values.added = 11; delete host.values.foo; [mapBefore, host.values.added, host.values.foo === undefined, Object.keys(host.values).sort().join(",")].join("|")`, func(value any) error {
			return want(value, "bar,foo|11|true|added,bar")
		}},
		{"slice index/assignment/length/push", `const sliceBefore = host.items[0]; host.items[0] = 8; host.items.push(9, 10); [sliceBefore, host.items[0], host.items.length].join("|")`, func(value any) error {
			return want(value, "3|8|3")
		}},
		{"method and this-bound state", `host.add(2) + host.count`, func(value any) error { return wantNumber(value, 84) }},
		{"variadic Go method", `host.variadic("a", "b", "c")`, func(value any) error { return wantNumber(value, 3) }},
		{"callback assignment", `host.callback = value => value * 2; true`, func(value any) error { return want(value, true) }},
		{"nested pointer/map/slice", `host.nested.value = "nested-after"; host.nested.values.entry = 6; host.nested.items[0] = 12; [host.nested.value, host.nested.values.entry, host.nested.items[0]].join("|")`, func(value any) error {
			return want(value, "nested-after|6|12")
		}},
		{"missing and undefined", `host.noSuch === undefined && host.values.noSuch === undefined && host.items[99] === undefined`, func(value any) error { return want(value, true) }},
		{"read-only returned slice", `(() => { "use strict"; const readOnly = host.readOnlyItems(); const readOnlyBefore = readOnly[0]; let assignmentError = false; try { readOnly[0] = 8 } catch (_) { assignmentError = true }; let pushed = false; try { readOnly.push(9); pushed = true } catch (_) {} return [readOnlyBefore, readOnly[0], assignmentError, pushed].join("|") })()`, func(value any) error {
			return want(value, "7|7|true|false")
		}},
	}
	for _, test := range cases {
		value, err := runtime.RunString(test.name+".js", test.source)
		if err != nil {
			return fmt.Errorf("%s: %w", test.name, err)
		}
		primitive, err := value.ExportPrimitive()
		if err != nil {
			return fmt.Errorf("%s export: %w", test.name, err)
		}
		if err := test.check(primitive); err != nil {
			return fmt.Errorf("%s: %w", test.name, err)
		}
	}

	value, err := runtime.RunString("method-error-value.js", `try { host.fail(); "missing" } catch (error) { error.message }`)
	if err != nil {
		return err
	}
	message, err := value.ExportPrimitive()
	if err != nil || message != "host failure" {
		return fmt.Errorf("method error = %#v (%v)", message, err)
	}

	if err := runtime.Set("fn", func(prefix string, values ...string) (int, error) {
		return len(prefix) + len(values), nil
	}); err != nil {
		return err
	}
	value, err = runtime.RunString("function.js", `fn("a", "b", "c")`)
	if err != nil {
		return err
	}
	primitive, err := value.ExportPrimitive()
	if err != nil {
		return fmt.Errorf("variadic function export: %w", err)
	}
	if err := wantNumber(primitive, 3); err != nil {
		return fmt.Errorf("variadic function: %w", err)
	}
	if err := runtime.Set("failingFn", func() (int, error) { return 0, errors.New("function failure") }); err != nil {
		return err
	}
	value, err = runtime.RunString("function-error.js", `try { failingFn() } catch (error) { error.message }`)
	if err != nil {
		return err
	}
	primitive, err = value.ExportPrimitive()
	if err != nil || primitive != "function failure" {
		return fmt.Errorf("function error = %#v (%v)", primitive, err)
	}
	_ = h
	return nil
}

func assertDangerousContract(runtime jsengine.Runtime) error {
	value, err := runtime.RunString("dangerous.js", `dangerous.Hidden = "revealed"; [dangerous.hidden, dangerous.Hidden, dangerous.name, dangerous.add(1)].join("|")`)
	if err != nil {
		return err
	}
	primitive, err := value.ExportPrimitive()
	if err != nil || primitive != "revealed|revealed|before|41" {
		return fmt.Errorf("dangerous values = %#v (%v)", primitive, err)
	}
	value, err = runtime.RunString("dangerous-keys.js", `Object.keys(dangerous).sort().join(",")`)
	if err != nil {
		return err
	}
	primitive, err = value.ExportPrimitive()
	if err != nil {
		return err
	}
	keys, ok := primitive.(string)
	if !ok || !strings.Contains(keys, "Hidden") || !strings.Contains(keys, "hidden") || !strings.Contains(keys, "name") {
		return fmt.Errorf("dangerous keys = %#v", primitive)
	}
	if keys != sortedCSV(keys) {
		return fmt.Errorf("dangerous keys are not deterministic: %q", keys)
	}
	return nil
}

func sortedCSV(value string) string {
	parts := strings.Split(value, ",")
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func want(got any, expected any) error {
	if !reflect.DeepEqual(got, expected) {
		return fmt.Errorf("got %#v (%T), want %#v (%T)", got, got, expected, expected)
	}
	return nil
}
func wantNumber(got any, expected float64) error {
	switch value := got.(type) {
	case int:
		if float64(value) == expected {
			return nil
		}
	case int64:
		if float64(value) == expected {
			return nil
		}
	case uint64:
		if float64(value) == expected {
			return nil
		}
	case float64:
		if value == expected {
			return nil
		}
	}
	return fmt.Errorf("got %#v (%T), want numeric %v", got, got, expected)
}
