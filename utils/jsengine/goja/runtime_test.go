package goja_test

import (
	"errors"
	"testing"

	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestRuntimeEvaluatesScript(t *testing.T) {
	t.Parallel()

	var loop = gojaengine.New()
	defer loop.Close()

	var got interface{}
	err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("plugin.js", "40 + 2")
		if err != nil {
			return err
		}
		got = value.Export()
		return nil
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got != int64(42) {
		t.Fatalf("RunString() = %#v, want 42", got)
	}
	if got := loop.Engine(); got != jsengine.EngineGoja {
		t.Fatalf("Engine() = %q, want %q", got, jsengine.EngineGoja)
	}
}

func TestScopedPrimitiveExportSurvivesCallbackWithoutPermittingReuse(t *testing.T) {
	t.Parallel()

	loop := gojaengine.New()
	defer loop.Close()

	var primitive jsengine.Value
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		var err error
		primitive, err = runtime.RunString("primitive.js", "1 + 2")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if got := primitive.Export(); got != int64(3) && got != float64(3) {
		t.Fatalf("legacy primitive export = %#v (%T), want 3", got, got)
	}
	if got, err := primitive.ExportPrimitive(); err != nil || got != int64(3) && got != float64(3) {
		t.Fatalf("primitive export = %#v (%T), %v, want 3", got, got, err)
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if _, err := gojaengine.UnwrapValueForRuntime(runtime, primitive); err == nil {
			return errors.New("expired primitive was unwrapped into a later runtime callback")
		}
		if err := runtime.Set("expiredPrimitive", primitive); err == nil {
			return errors.New("expired primitive was rebound into a later runtime callback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionEntriesHaveFileLocalLexicalScope(t *testing.T) {
	t.Parallel()

	loop := gojaengine.New()
	defer loop.Close()

	for _, entry := range []jsengine.Entry{
		{Filename: "first.js", Source: `let ext = "first"; globalThis.loadedExtensions = [ext];`, Kind: jsengine.EntryExtension},
		{Filename: "second.js", Source: `let ext = "second"; globalThis.loadedExtensions.push(ext);`, Kind: jsengine.EntryExtension},
	} {
		if err := loop.LoadEntry(entry); err != nil {
			t.Fatalf("LoadEntry(%q) error = %v", entry.Filename, err)
		}
	}

	var got any
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("verify.js", `globalThis.loadedExtensions.join(",")`)
		if err != nil {
			return err
		}
		got = value.Export()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != "first,second" {
		t.Fatalf("loaded extensions = %#v", got)
	}
}

func TestParseJSONUsesCapturedIntrinsicAndReturnsNativeValues(t *testing.T) {
	t.Parallel()

	loop := gojaengine.New()
	defer loop.Close()

	var (
		got    any
		parsed jsengine.Value
	)
	err := loop.Run(func(runtime jsengine.Runtime) error {
		if _, err := runtime.RunString("replace-json-parse.js", `
			JSON.parse = function () { throw new Error("replacement called"); };
		`); err != nil {
			return err
		}
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("Goja runtime does not implement jsengine.JSONParser")
		}
		var err error
		parsed, err = parser.ParseJSON(`{"items":[{"n":1},{"n":2}],"nested":{"ok":true},"large":9007199254740993}`)
		if err != nil {
			return err
		}
		raw, err := gojaengine.UnwrapValueForRuntime(runtime, parsed)
		if err != nil {
			return err
		}
		if raw == nil {
			return errors.New("ParseJSON returned a nil Goja value")
		}
		event := runtime.NewObject()
		if event == nil {
			return errors.New("Goja runtime returned a nil event object")
		}
		if err := event.Set("body", parsed); err != nil {
			return err
		}
		if err := runtime.Set("__adapterEvent", event); err != nil {
			return err
		}
		result, err := runtime.RunString("inspect-parsed-json.js", `
			const body = __adapterEvent.body;
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
			shape + "|" + JSON.stringify(body);
		`)
		if err != nil {
			return err
		}
		got = result.Export()
		return nil
	})
	if err != nil {
		t.Fatalf("ParseJSON callback error = %v", err)
	}
	const want = `true|true|1,2|1,2|3|true|{"items":[{"n":7},{"n":2}],"nested":{"ok":true},"large":9007199254740992}`
	if got != want {
		t.Fatalf("parsed JSON behavior = %q, want %q", got, want)
	}
	if exported := parsed.Export(); exported != nil {
		t.Fatalf("expired parsed object exported as %#v", exported)
	}
	if parsed.Object() != nil {
		t.Fatal("expired parsed object remained accessible")
	}
	if _, err := parsed.ExportPrimitive(); err == nil {
		t.Fatal("expired parsed object was treated as a detached primitive")
	}

	err = loop.Run(func(runtime jsengine.Runtime) error {
		if _, err := gojaengine.UnwrapValueForRuntime(runtime, parsed); err == nil {
			return errors.New("Goja value was accepted outside its owner callback")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	other := gojaengine.New()
	defer other.Close()
	err = other.Run(func(runtime jsengine.Runtime) error {
		if _, err := gojaengine.UnwrapValueForRuntime(runtime, parsed); err == nil {
			return errors.New("Goja value was accepted by the wrong runtime")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseJSONRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	loop := gojaengine.New()
	defer loop.Close()
	err := loop.Run(func(runtime jsengine.Runtime) error {
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("Goja runtime does not implement jsengine.JSONParser")
		}
		if _, err := parser.ParseJSON(`{"missing":`); err == nil {
			return errors.New("ParseJSON accepted malformed JSON")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWrappedEventLoopCapturesJSONParseBeforeFirstEntry(t *testing.T) {
	raw := eventloop.NewEventLoop()
	loop := gojaengine.WrapEventLoop(raw)
	stopped := make(chan error, 1)
	go func() {
		stopped <- gojaengine.StartInForeground(loop)
	}()
	if err := gojaengine.WaitUntilStarted(loop); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = loop.Close()
		<-stopped
	})

	if err := loop.LoadEntry(jsengine.Entry{
		Filename: "first-plugin.js",
		Source:   `JSON.parse = function () { throw new Error("replacement called"); };`,
		Kind:     jsengine.EntryExtension,
	}); err != nil {
		t.Fatal(err)
	}
	err := loop.Run(func(runtime jsengine.Runtime) error {
		parser, ok := runtime.(jsengine.JSONParser)
		if !ok {
			return errors.New("wrapped Goja runtime does not implement jsengine.JSONParser")
		}
		parsed, err := parser.ParseJSON(`{"items":[1,2]}`)
		if err != nil {
			return err
		}
		object := parsed.Object()
		if object == nil || !object.Has("items") {
			return errors.New("captured JSON.parse did not create an object")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
