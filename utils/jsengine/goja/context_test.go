package goja

import (
	"testing"

	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
)

func TestAsyncCallbacksPreserveExecutionContext(t *testing.T) {
	raw := eventloop.NewEventLoop()
	loop := WrapEventLoop(raw)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatalf("InstallContextPropagation() error = %v", err)
	}

	var seen []any
	if err := jsengine.RunWithContext(loop, "plugin-a", func(runtime jsengine.Runtime) error {
		return runtime.Bind("captureContext", func() {
			seen = append(seen, jsengine.CurrentContext(loop))
		})
	}); err != nil {
		t.Fatalf("install capture callback: %v", err)
	}
	if err := jsengine.RunWithContext(loop, "plugin-a", func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("context.js", `
			setTimeout(captureContext, 0);
			Promise.resolve().then(captureContext);
			(async () => { await Promise.resolve(); captureContext(); })();
		`)
		return err
	}); err != nil {
		t.Fatalf("schedule async callbacks: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("captured contexts = %d, want 3: %#v", len(seen), seen)
	}
	for _, context := range seen {
		if context != "plugin-a" {
			t.Fatalf("captured context = %#v, want plugin-a", context)
		}
	}
}

func TestGojaRejectsValuesFromAnotherRealm(t *testing.T) {
	first := New()
	second := New()
	var exported jsengine.Value
	var exportedObject jsengine.Object
	if err := first.Run(func(runtime jsengine.Runtime) error {
		exported = runtime.Get("undefined")
		exportedObject = runtime.NewObject()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := second.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Set("foreign", exported); err == nil {
			t.Fatal("runtime.Set() accepted a value owned by another realm")
		}
		if err := runtime.Set("foreignObject", exportedObject); err == nil {
			t.Fatal("runtime.Set() accepted an object owned by another realm")
		}
		if err := runtime.Bind("foreignObject", exportedObject); err == nil {
			t.Fatal("runtime.Bind() accepted an object owned by another realm")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	_ = second.Close()
}
