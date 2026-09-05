//go:build cgo

package native

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"Scardice-core/utils/jsengine"
)

func TestNativeContextCapabilityRequiresValidExtension(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler is unavailable")
	}
	abiRoot, err := filepath.Abs("../../../runtimeabi")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		kind  int
		valid bool
	}{
		{"context-extension", 0, true},
		{"missing-extension", 1, false},
		{"incompatible-extension", 2, false},
		{"short-context-table", 3, false},
		{"missing-set-context", 4, false},
		{"missing-get-context", 5, false},
		{"generic-provider-without-context", 6, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			library := filepath.Join(t.TempDir(), "context-fixture.so")
			args := []string{"-std=c11", "-shared"}
			if runtime.GOOS != "windows" {
				args = append(args, "-fPIC")
			}
			args = append(args, fmt.Sprintf("-DFIXTURE_CASE=%d", test.kind),
				"-I"+filepath.Join(abiRoot, "include"),
				filepath.Join(abiRoot, "testdata", "echo-runtime", "context_capability.c"), "-o", library)
			if output, err := exec.Command(compiler, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile context fixture: %v\n%s", err, output)
			}
			candidate := Candidate{LibraryPath: library, Manifest: Manifest{
				Schema: 1, ID: "echo-runtime", Name: "Echo Runtime", Version: "1.0.0", Language: "echo",
				RuntimeABI: ABIRequirement{Major: 1}, HostABI: ABIRequirement{Major: 1, MinMinor: 1},
			}}
			provider, err := candidate.Load()
			if !test.valid {
				if !errors.Is(err, ErrCorruptVTable) {
					t.Fatalf("Load() error = %v, want invalid capability declaration", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			loop, err := provider.Open(t.Context(), jsengine.RuntimeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer loop.Close()
			if err := loop.Run(func(rt jsengine.Runtime) error {
				value, err := rt.RunString("context-fixture.js", "1 + 2")
				if err != nil {
					return err
				}
				if got := value.Export(); got != int64(3) {
					return fmt.Errorf("ordinary execution returned %#v, want 3", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
