package native

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"testing"

	"Scardice-core/utils/jsengine"
)

type adapterHost struct {
	Answer int `jsbind:"answer"`
	lock   sync.RWMutex
}

func (h *adapterHost) Add(delta int) int {
	h.Answer += delta
	return h.Answer
}

func echoCandidate(t *testing.T) Candidate {
	t.Helper()
	library := os.Getenv("SCARDICE_ECHO_RUNTIME")
	if library == "" {
		t.Skip("SCARDICE_ECHO_RUNTIME is not set")
	}
	return Candidate{LibraryPath: library, Manifest: Manifest{
		Schema: 1, ID: "echo-runtime", Name: "Echo Runtime", Version: "1.0.0", Language: "javascript",
		RuntimeABI: ABIRequirement{Major: 1}, HostABI: ABIRequirement{Major: 1},
	}}
}

func openEcho(t *testing.T) jsengine.Loop {
	t.Helper()
	provider, err := echoCandidate(t).Load()
	if err != nil {
		t.Fatal(err)
	}
	loop, err := provider.Open(t.Context(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return loop
}

func TestNativeAdapterEchoContract(t *testing.T) {
	loop := openEcho(t)
	defer func() {
		if err := loop.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	if got := loop.Descriptor(); got.ID != "echo-runtime" || got.ABIMajor != 1 {
		t.Fatalf("Descriptor() = %#v", got)
	}

	var host adapterHost
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("eval.js", "1 + 2")
		if err != nil {
			return err
		}
		if got := value.Export(); got != int64(3) {
			return fmt.Errorf("eval export = %#v", got)
		}
		if err := runtime.Set("u64", uint64(math.MaxUint64)); err != nil {
			return err
		}
		if got := runtime.Get("u64").Export(); got != uint64(math.MaxUint64) {
			return fmt.Errorf("u64 export = %#v", got)
		}
		if err := runtime.Set("f64", math.Pi); err != nil {
			return err
		}
		if got := runtime.Get("f64").Export(); got != math.Pi {
			return fmt.Errorf("f64 export = %#v", got)
		}
		object := runtime.NewObject()
		if object == nil {
			return errors.New("native NewObject returned nil")
		}
		if err := object.Set("answer", value); err != nil {
			return err
		}
		if !object.Has("answer") {
			return errors.New("object does not have answer")
		}
		if got := object.Get("answer").Export(); got != int64(3) {
			return fmt.Errorf("object answer = %#v", got)
		}
		if got := object.Get("missing").Export(); got != nil {
			return fmt.Errorf("missing object property = %#v, want undefined", got)
		}
		if err := runtime.Bind("host", &host); err != nil {
			return err
		}
		hostObject := runtime.Get("host").Object()
		if hostObject == nil || !hostObject.Has("answer") || !hostObject.Has("add") {
			return errors.New("host object did not expose expected members")
		}
		if got := hostObject.Get("answer").Export(); got != int64(0) {
			return fmt.Errorf("host answer = %#v", got)
		}
		if err := hostObject.Set("answer", int64(7)); err != nil {
			return err
		}
		if host.Answer != 7 {
			return fmt.Errorf("host.Answer = %d, want 7", host.Answer)
		}
		function, ok := hostObject.Get("add").Export().(*nativeFunction)
		if !ok {
			return errors.New("host method did not produce a native function")
		}
		result, err := function.Call(nil, int64(2))
		if err != nil {
			return err
		}
		if got := result.Export(); got != int64(9) || host.Answer != 9 {
			return fmt.Errorf("host function result = %#v, answer = %d", got, host.Answer)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("error.js", "throw echo error")
		return err
	}); err == nil || !strings.Contains(err.Error(), "echo eval error") {
		t.Fatalf("error = %v, want echo eval diagnostic", err)
	}
}

func TestNativeAdapterRetainedValueAndClose(t *testing.T) {
	loop := openEcho(t)
	defer func() { _ = loop.Close() }()
	var retained *nativeValue
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("retain.js", "1 + 2")
		if err != nil {
			return err
		}
		var ok bool
		retained, ok = value.(*nativeValue)
		if !ok {
			return errors.New("native eval returned a non-native value")
		}
		return retained.retain()
	}); err != nil {
		t.Fatal(err)
	}
	if got := retained.Export(); got != int64(3) {
		t.Fatalf("retained export = %#v", got)
	}
	if err := retained.releasePersistent(); err != nil {
		t.Fatal(err)
	}
	if err := loop.Close(); err != nil {
		t.Fatal(err)
	}
	if err := loop.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := loop.Run(func(jsengine.Runtime) error { return nil }); !errors.Is(err, ErrNativeClosed) {
		t.Fatalf("Run after Close error = %v, want ErrNativeClosed", err)
	}
	if retained.Export() != nil {
		t.Fatal("closed value still exported a native value")
	}
}

func TestNativeAdapterLoadEntryForwardsKinds(t *testing.T) {
	loop := openEcho(t)
	defer loop.Close()
	for _, kind := range []jsengine.EntryKind{jsengine.EntryScript, jsengine.EntryCommonJS, jsengine.EntryESModule, jsengine.EntryExtension} {
		entry := jsengine.Entry{Filename: "entry.js", Source: "1 + 2", Kind: kind}
		if err := loop.LoadEntry(entry); err != nil {
			t.Fatalf("LoadEntry kind %d: %v", kind, err)
		}
	}
	if err := loop.LoadEntry(jsengine.Entry{Filename: "bad.js", Source: "1 + 2", Kind: jsengine.EntryKind(99)}); err == nil {
		t.Fatal("LoadEntry accepted an unknown entry kind")
	}
}
