package quickjs_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/native"
)

type testHost struct {
	Answer int `jsbind:"answer"`
}

func (h *testHost) Add(delta int) int { return h.Answer + delta }

type callbackHost struct {
	Calls int
}

func (h *callbackHost) Apply(callback func(int) int) int {
	h.Calls++
	return callback(5) + 1
}
func quickJSProvider(t *testing.T) (*native.Provider, jsengine.Loop) {
	t.Helper()
	root := os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	if root == "" {
		t.Skip("SCARDICE_QUICKJS_PACKAGE is not set")
	}
	candidates, err := native.Discover(root)
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
	return provider, loop
}

func TestQuickJSProviderEvalObjectAndHostFunction(t *testing.T) {
	provider, loop := quickJSProvider(t)
	if provider.Descriptor().ID != "quickjs" {
		t.Fatalf("provider ID = %q", provider.Descriptor().ID)
	}
	host := &testHost{Answer: 40}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("eval.js", "1 + 2")
		if err != nil {
			return err
		}
		primitive, err := value.ExportPrimitive()
		if err != nil || primitive != int64(3) {
			return fmt.Errorf("unexpected QuickJS primitive: %#v (%T), %v", primitive, primitive, err)
		}
		objectValue, err := runtime.RunString("object.js", "({ answer: 41 })")
		if err != nil {
			return err
		}
		object := objectValue.Object()
		answer, err := object.Get("answer").ExportPrimitive()
		if err != nil || answer != int64(41) {
			return fmt.Errorf("unexpected QuickJS object result: %#v (%T), %v", answer, answer, err)
		}
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		result, err := runtime.RunString("host.js", "host.answer = 41; host.add(1)")
		if err != nil {
			return err
		}
		got, err := result.ExportPrimitive()
		if err != nil || got != int64(42) || host.Answer != 41 {
			return fmt.Errorf("unexpected QuickJS host result: got=%#v (%T), err=%v, answer=%d", got, got, err, host.Answer)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQuickJSProviderHostProxyParity(t *testing.T) {
	_, loop := quickJSProvider(t)
	hostMap := map[string]int{"foo": 1, "bar": 2}
	hostSlice := []int{3}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("hostMap", hostMap); err != nil {
			return err
		}
		if err := runtime.Bind("hostSlice", &hostSlice); err != nil {
			return err
		}
		keys, err := runtime.RunString("keys.js", "Object.keys(hostMap).sort().join(',')")
		if err != nil {
			return err
		}
		if got, err := keys.ExportPrimitive(); err != nil || got != "bar,foo" {
			return fmt.Errorf("map keys = %#v, %v", got, err)
		}
		if _, err := runtime.RunString("delete.js", "delete hostMap.foo; hostSlice[0] = 4; hostSlice.push(5)"); err != nil {
			return err
		}
		if _, ok := hostMap["foo"]; ok {
			return errors.New("delete did not remove map property")
		}
		if len(hostSlice) != 2 || hostSlice[0] != 4 || hostSlice[1] != 5 {
			return fmt.Errorf("slice after JavaScript mutation = %#v", hostSlice)
		}
		length, err := runtime.RunString("length.js", "hostSlice.length")
		if err != nil {
			return err
		}
		if got, err := length.ExportPrimitive(); err != nil || got != int64(2) {
			return fmt.Errorf("slice length = %#v, %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQuickJSProviderReentrantCallback(t *testing.T) {
	_, loop := quickJSProvider(t)
	host := &callbackHost{}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("host", host); err != nil {
			return err
		}
		result, err := runtime.RunString("callback.js", "host.apply(value => value * 2)")
		if err != nil {
			return err
		}
		got, err := result.ExportPrimitive()
		if err != nil || got != int64(11) {
			return fmt.Errorf("reentrant callback result = %#v (%T), %v", got, got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if host.Calls != 1 {
		t.Fatalf("callback host calls = %d, want one", host.Calls)
	}
}

func TestQuickJSProviderEntryKinds(t *testing.T) {
	_, loop := quickJSProvider(t)
	entries := []struct {
		kind   jsengine.EntryKind
		name   string
		source string
	}{
		{kind: jsengine.EntryScript, name: "script.js", source: "globalThis.scriptValue = 7"},
		{kind: jsengine.EntryCommonJS, name: "module.js", source: "module.exports = { answer: 8 }"},
		{kind: jsengine.EntryESModule, name: "entry.js", source: "globalThis.moduleValue = 9; export const answer = 9"},
		{kind: jsengine.EntryExtension, name: "extension.js", source: "globalThis.extensionValue = 10"},
	}
	for _, entry := range entries {
		if err := loop.LoadEntry(jsengine.Entry{Kind: entry.kind, Filename: entry.name, Source: entry.source}); err != nil {
			t.Fatalf("LoadEntry(%d): %v", entry.kind, err)
		}
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		for name, want := range map[string]int64{"scriptValue": 7, "moduleValue": 9, "extensionValue": 10} {
			value := runtime.Get(name)
			got, err := value.ExportPrimitive()
			if err != nil || got != want {
				return errors.New("entry did not update global value")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
