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
		name string
		kind int
		want error
	}{
		{"context-extension", 0, nil},
		{"missing-extension", 1, ErrCorruptVTable},
		{"incompatible-extension", 2, ErrCorruptVTable},
		{"short-context-table", 3, ErrCorruptVTable},
		{"missing-set-context", 4, ErrCorruptVTable},
		{"missing-get-context", 5, ErrCorruptVTable},
		{"generic-provider-without-context", 6, nil},
		{"async-service-with-short-table", 7, ErrTooSmallStruct},
		{"nonzero-runtime-minor", 8, ErrRuntimeABIMismatch},
		{"unsupported-host-minor", 9, ErrHostABIMismatch},
		{"nonzero-extension-minor", 10, ErrCorruptVTable},
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
				RuntimeABI: ABIRequirement{Major: 1}, HostABI: ABIRequirement{Major: 1},
			}}
			provider, err := candidate.Load()
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("Load() error = %v, want %v", err, test.want)
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
