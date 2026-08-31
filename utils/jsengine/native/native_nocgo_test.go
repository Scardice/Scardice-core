//go:build !cgo

package native

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/utils/jsengine"
)

func TestNoCgoLoadAndOpenRejectNativeRuntime(t *testing.T) {
	library := filepath.Join(t.TempDir(), "runtime.so")
	if err := os.WriteFile(library, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{LibraryPath: library, Manifest: Manifest{ID: "native", Version: "1.0.0"}}

	provider, err := candidate.Load()
	if provider != nil {
		t.Fatal("Load returned a provider without cgo")
	}
	if !errors.Is(err, ErrNativeRuntimeUnsupported) {
		t.Fatalf("Load() error = %v, want ErrNativeRuntimeUnsupported", err)
	}

	provider = &Provider{candidate: candidate}
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{})
	if loop != nil {
		t.Fatal("Open returned a loop without cgo")
	}
	if !errors.Is(err, ErrNativeRuntimeUnsupported) {
		t.Fatalf("Open() error = %v, want ErrNativeRuntimeUnsupported", err)
	}
}

func TestNoCgoMissingLibraryKeepsSpecificDiagnostic(t *testing.T) {
	candidate := Candidate{LibraryPath: filepath.Join(t.TempDir(), "missing.so"), Manifest: Manifest{ID: "native", Version: "1.0.0"}}
	provider, err := candidate.Load()
	if provider != nil {
		t.Fatal("Load returned a provider for a missing library")
	}
	if !errors.Is(err, ErrMissingLibrary) {
		t.Fatalf("Load() error = %v, want ErrMissingLibrary", err)
	}
	if !errors.Is(err, ErrNativeRuntimeUnsupported) {
		t.Fatalf("Load() error = %v, want ErrNativeRuntimeUnsupported", err)
	}
}
func TestNoCgoExposeDangerousReturnsUnsupported(t *testing.T) {
	value, err := ExposeDangerous(nil, struct{}{})
	if value != nil {
		t.Fatal("ExposeDangerous returned a value without cgo")
	}
	if err != ErrNativeRuntimeUnsupported {
		t.Fatalf("ExposeDangerous() error = %v, want ErrNativeRuntimeUnsupported", err)
	}
}
