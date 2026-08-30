package quickjs_test

import (
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/quickjs"
)

type dangerousNested struct {
	Value string
}

type dangerousHost struct {
	Name        string
	Nested      *dangerousNested
	Values      map[string]string
	Children    map[string]*dangerousNested
	NestedItems []dangerousNested
}

func TestExposeDangerousPreservesMutableNestedObjects(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	host := &dangerousHost{
		Name:   "before",
		Nested: &dangerousNested{Value: "nested-before"},
		Values: map[string]string{"entry": "map-before"},
		Children: map[string]*dangerousNested{
			"first": {Value: "child-before"},
		},
		NestedItems: []dangerousNested{{Value: "slice-before"}},
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := quickjs.ExposeDangerous(runtime, host)
		if err != nil {
			return err
		}
		if err := runtime.Set("host", value); err != nil {
			return err
		}
		_, err = runtime.RunString("dangerous.js", `
			host.name = "after";
			host.nested.value = "nested-after";
			host.values.entry = "map-after";
			host.children.first.value = "child-after";
			host.nestedItems[0].value = "slice-after";
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if host.Name != "after" || host.Nested.Value != "nested-after" || host.Values["entry"] != "map-after" ||
		host.Children["first"].Value != "child-after" || host.NestedItems[0].Value != "slice-after" {
		t.Fatalf("host was not mutated: %#v", host)
	}
}

func TestRuntimeCallsVariadicHostFunction(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("count", func(prefix string, values ...string) int {
			return len(prefix) + len(values)
		}); err != nil {
			return err
		}
		value, err := runtime.RunString("variadic.js", `count("a", "b", "c") === 3`)
		if err != nil {
			return err
		}
		if !value.ToBoolean() {
			t.Fatal("variadic Host function did not receive every argument")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeEvaluatesScript(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer loop.Close()

	var got interface{}
	err = loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("plugin.js", "'scardice'")
		if err != nil {
			return err
		}
		got = value.Export()
		return nil
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got != "scardice" {
		t.Fatalf("RunString() = %#v, want scardice", got)
	}
	if got := loop.Engine(); got != jsengine.EngineQuickJS {
		t.Fatalf("Engine() = %q, want %q", got, jsengine.EngineQuickJS)
	}
}

func TestRuntimeDrainsPromiseJobsBetweenExecutions(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer loop.Close()

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("plugin.js", "globalThis.answer = 0; Promise.resolve(41).then(value => { globalThis.answer = value + 1 });")
		return err
	}); err != nil {
		t.Fatalf("Run() schedule promise error = %v", err)
	}

	var got interface{}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("plugin.js", "globalThis.answer")
		if err != nil {
			return err
		}
		got = value.Export()
		return nil
	}); err != nil {
		t.Fatalf("Run() read answer error = %v", err)
	}
	if got != float64(42) {
		t.Fatalf("globalThis.answer = %#v, want 42", got)
	}
}

func TestRuntimeLoadsESMAndPumpsAfterStart(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	if err := quickjs.Start(loop); err != nil {
		t.Fatal(err)
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := quickjs.LoadModule(runtime, "entry.mjs", `
			export const answer = 42;
			Promise.resolve().then(() => { globalThis.ready = answer });
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var ready interface{}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("check.js", "globalThis.ready")
		if err != nil {
			return err
		}
		ready = value.Export()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ready != float64(42) {
		t.Fatalf("globalThis.ready = %#v, want 42", ready)
	}
}

type callbackHost struct {
	Callback func() (string, error) `jsbind:"callback"`
}

func TestRuntimeRejectsCallbackAfterClose(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	host := &callbackHost{}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		_, err := runtime.RunString("callback.js", `host.callback = () => "ready"`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if value, err := host.Callback(); err != nil || value != "ready" {
		t.Fatalf("callback before close = %q, %v", value, err)
	}
	loop.Close()
	if _, err := host.Callback(); err == nil {
		t.Fatal("callback unexpectedly invoked after loop close")
	}
}
