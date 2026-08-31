package native

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"Scardice-core/utils/jsengine"
)
func TestDiscoverManifestIsLazyAndResolvesArchitectureLibrary(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "echo")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"id":"echo","name":"Echo","version":"1.0.0","language":"javascript","runtimeAbi":{"major":1,"minMinor":0},"hostAbi":{"major":1,"minMinor":0},"libraries":{"` + runtime.GOOS + `-` + runtime.GOARCH + `":"libecho.so"}}`
	if err := os.WriteFile(filepath.Join(pkg, "runtime.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	candidates, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Manifest.ID != "echo" {
		t.Fatalf("candidates = %#v", candidates)
	}
	if got, want := candidates[0].LibraryPath, filepath.Join(pkg, "libecho.so"); got != want {
		t.Fatalf("library path = %q, want %q", got, want)
	}
	if candidates[0].Loaded() {
		t.Fatal("discovery eagerly loaded native library")
	}
}

func TestDiscoverRejectsUnsupportedArchitecture(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "echo")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"id":"echo","name":"Echo","version":"1.0.0","language":"javascript","runtimeAbi":{"major":1,"minMinor":0},"hostAbi":{"major":1,"minMinor":0},"libraries":{"unknown-os-unknown-arch":"libecho.so"}}`
	if err := os.WriteFile(filepath.Join(pkg, "runtime.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Discover(root)
	if !errors.Is(err, ErrUnsupportedArchitecture) {
		t.Fatalf("Discover() error = %v, want ErrUnsupportedArchitecture", err)
	}
}

func TestMissingLibraryIsDiagnosable(t *testing.T) {
	candidate := Candidate{LibraryPath: filepath.Join(t.TempDir(), "missing.so"), Manifest: Manifest{ID: "echo", Version: "1.0.0"}}
	_, err := candidate.Load()
	if !errors.Is(err, ErrMissingLibrary) {
		t.Fatalf("Load() error = %v, want ErrMissingLibrary", err)
	}
}

func TestMissingQuerySymbolIsDiagnosable(t *testing.T) {
	library := "/usr/lib/libc.so.6"
	if _, err := os.Stat(library); err != nil {
		t.Skip("system libc is not available at /usr/lib/libc.so.6")
	}
	candidate := Candidate{LibraryPath: library, Manifest: Manifest{ID: "libc", Version: "1.0.0"}}
	_, err := candidate.Load()
	if !errors.Is(err, ErrMissingQuerySymbol) {
		t.Fatalf("Load() error = %v, want ErrMissingQuerySymbol", err)
	}
}
func TestRepeatedLoadKeepsTransientPathOwnershipBounded(t *testing.T) {
	library := os.Getenv("SCARDICE_ECHO_RUNTIME")
	if library == "" {
		t.Skip("SCARDICE_ECHO_RUNTIME is not set")
	}
	candidate := Candidate{LibraryPath: library, Manifest: Manifest{
		Schema: 1, ID: "echo-runtime", Name: "Echo Runtime", Version: "1.0.0", Language: "javascript",
		RuntimeABI: ABIRequirement{Major: 1}, HostABI: ABIRequirement{Major: 1},
	}}
	for i := 0; i < 8; i++ {
		if _, err := candidate.Load(); err != nil {
			t.Fatalf("Load() iteration %d error = %v", i, err)
		}
	}
}


func TestRegisterCandidatesKeepsCandidateMetadataSeparateFromBuiltin(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "echo")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema":1,"id":"goja","name":"Native Collision","version":"1.0.0","language":"javascript","runtimeAbi":{"major":1,"minMinor":0},"hostAbi":{"major":1,"minMinor":0},"libraries":{"` + runtime.GOOS + `-` + runtime.GOARCH + `":"missing.so"}}`
	if err := os.WriteFile(filepath.Join(pkg, "runtime.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	loader := NewLoader(root)
	registry := jsengine.NewRegistry()
	if err := registry.RegisterBuiltin(testProvider{}); err != nil {
		t.Fatal(err)
	}
	if err := loader.RegisterCandidates(registry); !errors.Is(err, jsengine.ErrDuplicateProvider) {
		t.Fatalf("RegisterCandidates() error = %v, want duplicate builtin diagnostic", err)
	}
	provider, err := registry.Resolve(jsengine.EngineGoja)
	if err != nil || provider == nil {
		t.Fatalf("builtin provider was replaced: provider=%v error=%v", provider, err)
	}
}

type testProvider struct{}

func (testProvider) Descriptor() jsengine.Descriptor { return jsengine.Descriptor{ID: jsengine.EngineGoja, Builtin: true} }
func (testProvider) Open(context.Context, jsengine.RuntimeOptions) (jsengine.Loop, error) {
	return nil, errors.New("test provider cannot open")
}


func TestLoadRejectsManifestDescriptorIdentityMismatch(t *testing.T) {
	library := os.Getenv("SCARDICE_ECHO_RUNTIME")
	if library == "" {
		t.Skip("SCARDICE_ECHO_RUNTIME is not set")
	}
	candidate := Candidate{LibraryPath: library, Manifest: Manifest{
		Schema: 1, ID: "wrong-id", Name: "Echo Runtime", Version: "9.9.9", Language: "javascript",
		RuntimeABI: ABIRequirement{Major: 1}, HostABI: ABIRequirement{Major: 1},
	}}
	_, err := candidate.Load()
	if !errors.Is(err, ErrManifestMismatch) || !errors.Is(err, ErrDescriptorMismatch) {
		t.Fatalf("Load() error = %v, want manifest and descriptor mismatch categories", err)
	}
}
func TestCreateFailureRetainsDiagnosticCategory(t *testing.T) {
	library := os.Getenv("SCARDICE_ECHO_RUNTIME")
	if library == "" {
		t.Skip("SCARDICE_ECHO_RUNTIME is not set")
	}
	candidate := Candidate{LibraryPath: library, Manifest: Manifest{
		Schema: 1, ID: "echo-runtime", Name: "Echo Runtime", Version: "1.0.0", Language: "javascript",
		RuntimeABI: ABIRequirement{Major: 1}, HostABI: ABIRequirement{Major: 1},
	}}
	provider, err := candidate.Load()
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.Open(t.Context(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, err = provider.Open(t.Context(), jsengine.RuntimeOptions{})
	if !errors.Is(err, ErrPluginCreateFailure) {
		t.Fatalf("second Open() error = %v, want ErrPluginCreateFailure", err)
	}
}

func TestLoadEchoProviderDescriptorAndResidentLifecycle(t *testing.T) {
	library := os.Getenv("SCARDICE_ECHO_RUNTIME")
	if library == "" {
		t.Skip("SCARDICE_ECHO_RUNTIME is not set")
	}
	candidate := Candidate{
		LibraryPath: library,
		Manifest: Manifest{
			Schema: 1, ID: "echo-runtime", Name: "Echo Runtime", Version: "1.0.0", Language: "javascript",
			RuntimeABI: ABIRequirement{Major: 1, MinMinor: 0},
			HostABI: ABIRequirement{Major: 1, MinMinor: 0},
		},
	}
	provider, err := candidate.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := provider.Descriptor(); got.ID != "echo-runtime" || got.Version != "1.0.0" {
		t.Fatalf("Descriptor() = %#v", got)
	}
	loop, err := provider.Open(t.Context(), structRuntimeOptions())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	loop.Close()
	if ResidentLibraryCount() == 0 {
		t.Fatal("native loader did not retain resident library identity")
	}
}

func structRuntimeOptions() jsengine.RuntimeOptions {
	return jsengine.RuntimeOptions{}
}