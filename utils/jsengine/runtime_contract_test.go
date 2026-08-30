package jsengine_test

import (
	"errors"
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
	"Scardice-core/utils/jsengine/quickjs"
)

type bindCounter struct {
	Count  int `jsbind:"count"`
	Hidden string
}

func (c *bindCounter) Increment(delta int) int {
	c.Count += delta
	return c.Count
}

func TestRuntimeBindUsesGojaHostNamingAndMutatesTarget(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{
			name: "goja",
			new: func(t *testing.T) jsengine.Loop {
				return gojaengine.New()
			},
		},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			counter := &bindCounter{Count: 40, Hidden: "secret"}
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("counter", counter); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "counter.count = counter.increment(2); `${counter.count}:${typeof counter.hidden}`")
				if err != nil {
					return err
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "42:undefined" {
				t.Fatalf("RunString() = %#v, want 42:undefined", got)
			}
			if counter.Count != 42 {
				t.Fatalf("counter.Count = %d, want 42", counter.Count)
			}
		})
	}
}

type bindSettings struct {
	Values map[string]int `jsbind:"values"`
}

func TestRuntimeBindMutatesLiveStringMap(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			settings := &bindSettings{Values: map[string]int{}}
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("settings", settings); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "settings.values.answer = 42; String(settings.values.answer) + ':' + Object.keys(settings.values).join(',')")
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "42:answer" {
				t.Fatalf("RunString() = %#v, want 42:answer", got)
			}
			if got := settings.Values["answer"]; got != 42 {
				t.Fatalf("settings.Values[answer] = %d, want 42", got)
			}
		})
	}
}

func TestRuntimeLoadsCachedCommonJSModule(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if _, err := runtime.LoadCommonJS("/plugins/counter.js", `
					globalThis.__moduleLoads = (globalThis.__moduleLoads || 0) + 1;
					module.exports = { answer: 42 };
				`); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js",
					"const first = require(\"/plugins/counter.js\");\n"+
						"const second = require(\"/plugins/counter.js\");\n"+
						"String(first.answer) + ':' + String(globalThis.__moduleLoads) + ':' + String(first === second);",
				)
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "42:1:true" {
				t.Fatalf("CommonJS result = %#v, want 42:1:true", got)
			}
		})
	}
}

func TestRuntimeResolvesRelativeCommonJSModules(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if _, err := runtime.LoadCommonJS("/plugins/math.js", "module.exports = 40"); err != nil {
					return err
				}
				if _, err := runtime.LoadCommonJS("/plugins/entry.js", "module.exports = require('./math') + 2"); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "String(require('/plugins/entry.js'))")
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "42" {
				t.Fatalf("CommonJS result = %#v, want 42", got)
			}
		})
	}
}

type bindHolder struct {
	Counter *bindCounter `jsbind:"counter"`
}

func TestRuntimeBindExposesNestedStructPointers(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			holder := &bindHolder{Counter: &bindCounter{Count: 40}}
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("holder", holder); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "String(holder.counter === holder.counter) + ':' + String(holder.counter.increment(2))")
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "true:42" {
				t.Fatalf("RunString() = %#v, want true:42", got)
			}
			if got := holder.Counter.Count; got != 42 {
				t.Fatalf("holder.Counter.Count = %d, want 42", got)
			}
		})
	}
}

type bindList struct {
	Values []string `jsbind:"values"`
}

func TestRuntimeBindMutatesLiveSlice(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			list := &bindList{Values: []string{"one"}}
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("list", list); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "list.values.push('two'); list.values[1]")
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "two" {
				t.Fatalf("RunString() = %#v, want two", got)
			}
			if got := list.Values; len(got) != 2 || got[1] != "two" {
				t.Fatalf("list.Values = %#v, want [one two]", got)
			}
		})
	}
}

type bindCatalog struct {
	Commands map[string]*bindCounter `jsbind:"commands"`
}

func (c *bindCatalog) NewCounter(start int) *bindCounter {
	return &bindCounter{Count: start}
}

func TestRuntimeBindAssignsReturnedHostObjectToMap(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			catalog := &bindCatalog{Commands: map[string]*bindCounter{}}
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("catalog", catalog); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "catalog.commands.primary = catalog.newCounter(40); String(catalog.commands.primary.increment(2))")
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "42" {
				t.Fatalf("RunString() = %#v, want 42", got)
			}
			if got := catalog.Commands["primary"]; got == nil || got.Count != 42 {
				t.Fatalf("catalog.Commands[primary] = %#v, want counter with 42", got)
			}
		})
	}
}

type bindCallback struct {
	Call func(int) int `jsbind:"call"`
}

func TestRuntimeBindAssignsJavaScriptFunctionToGoCallback(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			callback := &bindCallback{}
			loop := engine.new(t)
			defer loop.Close()

			if err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("callback", callback); err != nil {
					return err
				}
				_, err := runtime.RunString("plugin.js", "callback.call = value => value + 1")
				return err
			}); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if callback.Call == nil {
				t.Fatal("callback.Call = nil, want JavaScript callback")
			}
			if got := callback.Call(41); got != 42 {
				t.Fatalf("callback.Call(41) = %d, want 42", got)
			}
		})
	}
}

func TestRuntimeBuildsObjectsFromGoFunctions(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			var got interface{}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				api := runtime.NewObject()
				if err := api.Set("answer", 40); err != nil {
					return err
				}
				if err := api.Set("increment", func(value int) int { return value + 2 }); err != nil {
					return err
				}
				if err := runtime.Set("api", api); err != nil {
					return err
				}
				value, err := runtime.RunString("plugin.js", "String(api.increment(api.answer))")
				if err != nil {
					return err
				}
				if value == nil {
					return errors.New("RunString() returned nil value")
				}
				got = value.Export()
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got != "42" {
				t.Fatalf("RunString() = %#v, want 42", got)
			}
		})
	}
}

func TestRuntimeReadsObjectValuesInsideOwnerLoop(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return loop
			},
		},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			err := loop.Run(func(runtime jsengine.Runtime) error {
				value, err := runtime.RunString("plugin.js", "({ matched: 1, solved: 0 })")
				if err != nil {
					return err
				}
				object := value.Object()
				if object == nil || !object.Has("matched") {
					return errors.New("matched property is missing")
				}
				if !object.Get("matched").ToBoolean() {
					return errors.New("matched property is not truthy")
				}
				if object.Get("solved").ToBoolean() {
					return errors.New("solved property is truthy")
				}
				return nil
			})
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
		})
	}
}

func TestQuickJSCallbackReturnsLiveValueOnOwnerLoop(t *testing.T) {
	type callbackTarget struct {
		Solve func(jsengine.Runtime, int) (jsengine.Value, error) `jsbind:"solve"`
	}

	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	target := &callbackTarget{}
	err = loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("target", target); err != nil {
			return err
		}
		if _, err := runtime.RunString("callback.js", `target.solve = value => ({ value })`); err != nil {
			return err
		}
		result, err := target.Solve(runtime, 42)
		if err != nil {
			return err
		}
		if result.Object() == nil || result.Object().Get("value").Export() != float64(42) {
			t.Fatal("callback did not return a live JavaScript value")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
