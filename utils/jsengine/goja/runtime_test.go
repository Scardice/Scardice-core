package goja_test

import (
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestRuntimeEvaluatesScript(t *testing.T) {
	t.Parallel()

	var loop jsengine.Loop = gojaengine.New()
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
