package quickjs_test

import (
	"context"
	"os"
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostparity"
	"Scardice-core/utils/jsengine/native"
)

func TestNativeQuickJSHostProxyParityContract(t *testing.T) {
	hostparity.Run(t, hostparity.Engine{
		Name: "native-quickjs",
		Open: func(t *testing.T) jsengine.Loop {
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
			return loop
		},
		ExposeDangerous: native.ExposeDangerous,
	})
}
