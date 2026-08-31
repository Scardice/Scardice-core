package quickjs_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/native"
)

func TestQuickJSProviderAppliesTimeoutOption(t *testing.T) {
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
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{
		OptionsJSON: []byte(`{"version":1,"runtime":{"executionTimeoutMillis":10}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	started := time.Now()
	err = loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("timeout.js", "for (;;) {}")
		return err
	})
	if err == nil || !errors.Is(err, native.ErrNativeTimeout) {
		t.Fatalf("infinite script error = %v, want native timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s, watchdog exceeded", elapsed)
	}
}
