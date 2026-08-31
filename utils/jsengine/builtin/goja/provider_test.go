package goja_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"Scardice-core/utils/jsengine"
	builtin "Scardice-core/utils/jsengine/builtin/goja"
)

func TestProviderDescriptorIdentifiesBuiltinGoja(t *testing.T) {
	provider := builtin.Provider()
	descriptor := provider.Descriptor()
	if descriptor.ID != jsengine.EngineGoja {
		t.Fatalf("Descriptor().ID = %q, want %q", descriptor.ID, jsengine.EngineGoja)
	}
	if !descriptor.Builtin {
		t.Fatal("Descriptor().Builtin = false, want true")
	}
	if descriptor.Name == "" {
		t.Fatal("Descriptor().Name is empty")
	}
}

func TestProviderOpensExistingGojaAdapter(t *testing.T) {
	loop, err := builtin.Provider().Open(context.Background(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer loop.Close()

	var result jsengine.Value
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		var err error
		result, err = runtime.RunString("provider-test.js", "1 + 2")
		return err
	}); err != nil {
		t.Fatalf("Loop.Run() error = %v", err)
	}
	if got := result.Export(); got != int64(3) && got != float64(3) {
		t.Fatalf("RunString() exported %v (%T), want 3", got, got)
	}
	if loop.Engine() != jsengine.EngineGoja {
		t.Fatalf("Loop.Engine() = %q, want %q", loop.Engine(), jsengine.EngineGoja)
	}
}

func TestProviderRejectsUnsupportedOptionsWithoutDroppingThem(t *testing.T) {
	_, err := builtin.Provider().Open(context.Background(), jsengine.RuntimeOptions{
		OptionsJSON: json.RawMessage(`{"unsupported":true}`),
	})
	if err == nil {
		t.Fatal("Open() error = nil, want unsupported-options error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		t.Fatalf("Open() error = %q, want unsupported-options diagnostic", err)
	}
}

func TestProviderAcceptsEmptyOptions(t *testing.T) {
	for _, optionsJSON := range []json.RawMessage{nil, []byte(" \n\t"), []byte("{}")} {
		loop, err := builtin.Provider().Open(context.Background(), jsengine.RuntimeOptions{OptionsJSON: optionsJSON})
		if err != nil {
			t.Fatalf("Open(%q) error = %v, want success", optionsJSON, err)
		}
		loop.Close()
	}
}