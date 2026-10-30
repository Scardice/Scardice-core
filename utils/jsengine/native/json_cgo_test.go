//go:build cgo

package native

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"Scardice-core/utils/jsengine"
)

type nativeJSONItem struct {
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Count    int      `json:"count"`
	Ratio    float64  `json:"ratio"`
	Labels   []string `json:"labels"`
	Optional *string  `json:"optional"`
}

type nativeJSONHost struct {
	Mapping map[string]nativeJSONItem `jsbind:"mapping"`
	Items   []nativeJSONItem          `jsbind:"items"`
	Dynamic any                       `jsbind:"dynamic"`
}

type nativeJSONCallbackHost struct {
	body jsengine.Value
}

func (h *nativeJSONCallbackHost) Apply(callback func(jsengine.Value) (string, error)) (string, error) {
	return callback(h.body)
}

func openQuickJSJSONLoop(t *testing.T) jsengine.Loop {
	t.Helper()
	root := os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	if root == "" {
		t.Skip("SCARDICE_QUICKJS_PACKAGE is not set; live native JSON conversion is unavailable")
	}
	candidates, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("Discover returned %d candidates, want one", len(candidates))
	}
	provider, err := candidates[0].Load()
	if err != nil {
		t.Fatal(err)
	}
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loop.Close() })
	return loop
}

func TestNativeHostJSONCompatibleObjectsRoundTripIntoTypedTargets(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	host := &nativeJSONHost{}

	err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		_, err := runtime.RunString("host-json.js", `
			host.mapping = {
				first: {
					name: "alpha",
					enabled: true,
					count: 7,
					ratio: 1.5,
					labels: ["one", "two"],
					optional: null
				}
			};
			host.items = [{
				name: "beta",
				enabled: false,
				count: -2,
				ratio: 0.25,
				labels: [],
				optional: null
			}];
			host.dynamic = {
				text: "value",
				enabled: true,
				count: 3,
				nothing: null,
				nested: ["item", 2, false, null]
			};
		`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	wantMapping := map[string]nativeJSONItem{
		"first": {Name: "alpha", Enabled: true, Count: 7, Ratio: 1.5, Labels: []string{"one", "two"}},
	}
	if !reflect.DeepEqual(host.Mapping, wantMapping) {
		t.Fatalf("mapping = %#v, want %#v", host.Mapping, wantMapping)
	}
	wantItems := []nativeJSONItem{{Name: "beta", Count: -2, Ratio: 0.25, Labels: []string{}}}
	if !reflect.DeepEqual(host.Items, wantItems) {
		t.Fatalf("items = %#v, want %#v", host.Items, wantItems)
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

func TestNativeHostJSONConversionCapturesJSONStringifyBeforePluginMutation(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	host := &nativeJSONHost{}

	err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		_, err := runtime.RunString("host-json-intrinsic.js", `
			JSON.stringify = function () { throw new Error("replacement called"); };
			host.dynamic = { actual: true };
		`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"actual": true}
	if !reflect.DeepEqual(host.Dynamic, want) {
		t.Fatalf("dynamic = %#v, want %#v", host.Dynamic, want)
	}
}

func TestNativeHostJSONConversionRejectsCircularThrowingAndUnsupportedSnapshots(t *testing.T) {
	for name, source := range map[string]string{
		"circular": `
			const cycle = {};
			cycle.self = cycle;
			host.dynamic = cycle;
		`,
		"throwing getter": `
			host.dynamic = {
				get value() { throw new Error("getter exploded"); }
			};
		`,
		"undefined snapshot": `
			host.dynamic = {
				toJSON() { return undefined; }
			};
		`,
		"undefined nested predicate": `
			host.dynamic = {where: {notice_type: undefined}};
		`,
		"function nested predicate": `
			host.dynamic = {where: {notice_type: function () { return "poke"; }}};
		`,
		"nonfinite nested predicate": `
			host.dynamic = {where: {value: Infinity}};
		`,
		"boxed nonfinite nested predicate": `
			host.dynamic = {where: {value: new Number(Infinity)}};
		`,
		"strict nested scalar type": `
			host.mapping = {
				bad: {
					name: 42,
					enabled: true,
					count: 1,
					ratio: 1,
					labels: [],
					optional: null
				}
			};
		`,
	} {
		t.Run(name, func(t *testing.T) {
			loop := openQuickJSJSONLoop(t)
			host := &nativeJSONHost{Dynamic: "unchanged"}
			err := loop.Run(func(runtime jsengine.Runtime) error {
				if err := runtime.Bind("host", host); err != nil {
					return err
				}
				_, err := runtime.RunString("host-json-error.js", source)
				return err
			})
			if err == nil {
				t.Fatal("unsupported JSON snapshot was accepted")
			}
			if host.Dynamic != "unchanged" {
				t.Fatalf("failed conversion changed host value to %#v", host.Dynamic)
			}
			if host.Mapping != nil {
				t.Fatalf("failed typed conversion changed mapping to %#v", host.Mapping)
			}
		})
	}
}

func TestNativeHostJSONConversionRejectsStaleObjectValues(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	var stale jsengine.Value
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		var err error
		stale, err = runtime.RunString("stale-object.js", `({ value: 1 })`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	host := &nativeJSONHost{Dynamic: "unchanged"}
	err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		object := runtime.Get("host").Object()
		if object == nil {
			return errors.New("native host object is unavailable")
		}
		return object.Set("dynamic", stale)
	})
	if err == nil {
		t.Fatal("stale native object was accepted by a host binding")
	}
	if host.Dynamic != "unchanged" {
		t.Fatalf("stale conversion changed host value to %#v", host.Dynamic)
	}
}

func TestNativeParseJSONUsesCapturedIntrinsicAndPassesNativeArraysToCallbacks(t *testing.T) {
	loop := openQuickJSJSONLoop(t)

	var got any
	err := loop.Run(func(runtime jsengine.Runtime) error {
		if _, err := runtime.RunString("replace-json-parse.js", `
			JSON.parse = function () { throw new Error("replacement called"); };
		`); err != nil {
			return err
		}
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("native runtime does not implement jsengine.JSONParser")
		}
		body, err := parser.ParseJSON(`{"items":[{"n":1},{"n":2}],"nested":{"ok":true},"large":9007199254740993}`)
		if err != nil {
			return err
		}
		if err := runtime.Bind("host", &nativeJSONCallbackHost{body: body}); err != nil {
			return err
		}
		result, err := runtime.RunString("inspect-native-parsed-json.js", `
			const first = host.apply(body => {
				let sum = 0;
				for (const item of body.items) sum += item.n;
				const shape = [
					Array.isArray(body.items),
					Object.getPrototypeOf(body.items) === Array.prototype,
					body.items.map(item => item.n).join(","),
					[...body.items].map(item => item.n).join(","),
					sum,
					body.large === 9007199254740992
				].join("|");
				body.items[0].n = 7;
				return shape + "|" + JSON.stringify(body);
			});
			const second = host.apply(body => String(Array.isArray(body.items)) + ":" + body.items.length);
			first + "#" + second;
		`)
		if err != nil {
			return err
		}
		got = result.Export()
		return nil
	})
	if err != nil {
		t.Fatalf("native ParseJSON callback error = %v", err)
	}
	const want = `true|true|1,2|1,2|3|true|{"items":[{"n":7},{"n":2}],"nested":{"ok":true},"large":9007199254740992}#true:2`
	if got != want {
		t.Fatalf("native parsed JSON behavior = %q, want %q", got, want)
	}
}

func TestNativeParseJSONValuesExpireWithCallbackScope(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	var parsed jsengine.Value
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("native runtime does not implement jsengine.JSONParser")
		}
		var err error
		parsed, err = parser.ParseJSON(`{"value":1}`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	err := loop.Run(func(runtime jsengine.Runtime) error {
		event := runtime.NewObject()
		if event == nil {
			return errors.New("native runtime returned a nil event object")
		}
		return event.Set("body", parsed)
	})
	if err == nil {
		t.Fatal("parsed native value was accepted outside its callback scope")
	}
}

func TestNativeCallbackRejectsParsedValueFromExpiredScope(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	var parsed jsengine.Value
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("native runtime does not implement jsengine.JSONParser")
		}
		var err error
		parsed, err = parser.ParseJSON(`{"value":1}`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("host", &nativeJSONCallbackHost{body: parsed}); err != nil {
			return err
		}
		_, err := runtime.RunString("stale-native-callback-argument.js", `
			host.apply(body => JSON.stringify(body));
		`)
		return err
	})
	if err == nil {
		t.Fatal("native callback accepted a parsed value from an expired owner scope")
	}
}

func TestNativeParseJSONDoesNotRetainPerCallHandles(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	nativeLoop, ok := loop.(*nativeLoop)
	if !ok {
		t.Fatal("native loop has an unexpected implementation")
	}
	if nativeLoop.jsonParse == nil {
		t.Fatal("native JSON.parse intrinsic was not captured during startup")
	}
	persistentCount := func() uint32 {
		nativeLoop.persistentMu.Lock()
		defer nativeLoop.persistentMu.Unlock()
		var count uint32
		for _, references := range nativeLoop.persistent {
			count += references
		}
		return count
	}
	before := persistentCount()

	for range 32 {
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			parser, ok := runtime.(jsengine.JSONParser)
			if !ok {
				return errors.New("native runtime does not implement jsengine.JSONParser")
			}
			_, err := parser.ParseJSON(`[1,{"nested":[true,null]}]`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if after := persistentCount(); after != before {
		t.Fatalf("persistent native handles after ParseJSON = %d, want %d", after, before)
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
	if nativeLoop.jsonParse != nil {
		t.Fatal("native JSON.parse intrinsic remained reachable after close")
	}
	if afterClose := persistentCount(); afterClose != 0 {
		t.Fatalf("persistent native handles after close = %d, want 0", afterClose)
	}
}

func TestNativeParseJSONRejectsMalformedInput(t *testing.T) {
	loop := openQuickJSJSONLoop(t)
	err := loop.Run(func(runtime jsengine.Runtime) error {
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("native runtime does not implement jsengine.JSONParser")
		}
		if _, err := parser.ParseJSON(`{"missing":`); err == nil {
			return errors.New("native ParseJSON accepted malformed JSON")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
