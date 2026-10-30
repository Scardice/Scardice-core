package goja

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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

func TestDefaultRunFromNonOwnerDoesNotInheritBlockedOwnerContext(t *testing.T) {
	loop := startedTestLoop(t)
	adapter, ok := loop.(*eventLoop)
	if !ok {
		t.Fatal("started Goja loop has an unexpected implementation")
	}
	origin := newAwaitOwnershipScope(t, "blocked-owner")
	ownerEntered := make(chan struct{})
	releaseOwner := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseOwner) })
	defer release()
	ownerResult := make(chan error, 1)
	go func() {
		ownerResult <- jsengine.RunWithContext(loop, origin, func(jsengine.Runtime) error {
			close(ownerEntered)
			<-releaseOwner
			return nil
		})
	}()
	waitFor(t, ownerEntered, "the owning invocation")

	runStarted := make(chan struct{})
	runResult := make(chan error, 1)
	runContext := make(chan any, 1)
	go func() {
		close(runStarted)
		runResult <- loop.Run(func(runtime jsengine.Runtime) error {
			runContext <- jsengine.CurrentContext(loop)
			_, err := runtime.RunString("unbound-after-cancel.js", "globalThis.__unboundHealthy = true")
			return err
		})
	}()
	waitFor(t, runStarted, "the unrelated default Run submission")

	loadStarted := make(chan struct{})
	loadResult := make(chan error, 1)
	go func() {
		close(loadStarted)
		loadResult <- loop.LoadEntry(jsengine.Entry{
			Filename: "unbound-load-after-cancel.js",
			Source:   "globalThis.__unboundLoaded = true",
			Kind:     jsengine.EntryScript,
		})
	}()
	waitFor(t, loadStarted, "the unrelated default LoadEntry submission")

	scheduledContext := make(chan any, 1)
	if err := adapter.Schedule(func(jsengine.Runtime) error {
		scheduledContext <- jsengine.CurrentContext(loop)
		return nil
	}); err != nil {
		t.Fatalf("unrelated default Schedule() error = %v", err)
	}

	origin.cancel()
	release()
	select {
	case err := <-ownerResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("owning invocation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the owning invocation")
	}
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("unrelated default Run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for unrelated default Run")
	}
	select {
	case err := <-loadResult:
		if err != nil {
			t.Fatalf("unrelated default LoadEntry() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for unrelated default LoadEntry")
	}
	select {
	case inherited := <-runContext:
		if inherited != nil {
			t.Fatalf("default Run context = %#v, want nil", inherited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unrelated default Run did not execute")
	}
	select {
	case inherited := <-scheduledContext:
		if inherited != nil {
			t.Fatalf("default Schedule context = %#v, want nil", inherited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unrelated default Schedule did not execute")
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if !runtime.Get("__unboundHealthy").ToBoolean() ||
			!runtime.Get("__unboundLoaded").ToBoolean() {
			return errors.New("healthy unbound work did not persist")
		}
		return nil
	}); err != nil {
		t.Fatalf("later default Run() error = %v", err)
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
