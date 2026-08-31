package jsengine_test

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/utils/jsengine"
	builtin "Scardice-core/utils/jsengine/builtin/goja"
	adapter "Scardice-core/utils/jsengine/goja"
)

type testProvider struct {
	descriptor jsengine.Descriptor
}

func (p testProvider) Descriptor() jsengine.Descriptor { return p.descriptor }

func (p testProvider) Open(context.Context, jsengine.RuntimeOptions) (jsengine.Loop, error) {
	return adapter.New(), nil
}

func TestRegistryResolvesDefaultGojaAndNormalizesIDs(t *testing.T) {
	registry := jsengine.NewRegistry()
	if err := registry.RegisterBuiltin(builtin.Provider()); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}

	for _, raw := range []string{"", " goja ", "GOJA"} {
		provider, err := registry.Resolve(jsengine.EngineID(raw))
		if err != nil {
			t.Fatalf("Resolve(%q) error = %v", raw, err)
		}
		if got := provider.Descriptor().ID; got != jsengine.EngineGoja {
			t.Fatalf("Resolve(%q) descriptor ID = %q, want %q", raw, got, jsengine.EngineGoja)
		}
	}
}

func TestNormalizeEngineIDIsDeterministic(t *testing.T) {
	if got := jsengine.NormalizeEngineID("  MiXeD.Runtime  "); got != jsengine.EngineID("mixed.runtime") {
		t.Fatalf("NormalizeEngineID() = %q, want mixed.runtime", got)
	}
}

func TestRegistryUnknownProviderIsDiagnosable(t *testing.T) {
	registry := jsengine.NewRegistry()
	_, err := registry.Resolve("missing")
	if !errors.Is(err, jsengine.ErrProviderNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrProviderNotFound", err)
	}
}

func TestRegistryRejectsDuplicateBuiltinIDs(t *testing.T) {
	registry := jsengine.NewRegistry()
	provider := builtin.Provider()
	if err := registry.RegisterBuiltin(provider); err != nil {
		t.Fatalf("first RegisterBuiltin() error = %v", err)
	}
	if err := registry.RegisterBuiltin(provider); !errors.Is(err, jsengine.ErrDuplicateProvider) {
		t.Fatalf("second RegisterBuiltin() error = %v, want ErrDuplicateProvider", err)
	}
}

func TestRegistryRejectsDuplicateCandidateAndBuiltinIDs(t *testing.T) {
	registry := jsengine.NewRegistry()
	manifest := jsengine.RuntimeManifest{ID: "Native.Runtime", Name: "Native Runtime", Path: "runtimes/native"}
	if err := registry.RegisterCandidate(manifest); err != nil {
		t.Fatalf("first RegisterCandidate() error = %v", err)
	}
	if err := registry.RegisterCandidate(manifest); !errors.Is(err, jsengine.ErrDuplicateProvider) {
		t.Fatalf("second RegisterCandidate() error = %v, want ErrDuplicateProvider", err)
	}

	if err := registry.RegisterBuiltin(builtin.Provider()); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}
	builtinManifest := jsengine.RuntimeManifest{ID: jsengine.EngineGoja, Name: "candidate"}
	if err := registry.RegisterCandidate(builtinManifest); !errors.Is(err, jsengine.ErrDuplicateProvider) {
		t.Fatalf("builtin/candidate RegisterCandidate() error = %v, want ErrDuplicateProvider", err)
	}
}

func TestRegistryCandidateRegistrationKeepsMetadataLazy(t *testing.T) {
	registry := jsengine.NewRegistry()
	manifest := jsengine.RuntimeManifest{
		ID:           "native",
		Name:         "Native",
		Version:      "1.2",
		Language:     "C++",
		Capabilities: jsengine.CapabilityScript,
		Path:         "/tmp/native.so",
	}
	if err := registry.RegisterCandidate(manifest); err != nil {
		t.Fatalf("RegisterCandidate() error = %v", err)
	}
	descriptor, found := registry.Descriptor("native")
	if !found {
		t.Fatal("Descriptor() did not find registered candidate")
	}
	if descriptor.Builtin || descriptor.Path != manifest.Path || descriptor.Version != manifest.Version {
		t.Fatalf("candidate descriptor = %#v, want manifest metadata", descriptor)
	}
	if !descriptor.Capabilities.Has(jsengine.CapabilityScript) {
		t.Fatalf("candidate capabilities = %v, want script capability", descriptor.Capabilities)
	}
	if _, err := registry.Resolve("native"); !errors.Is(err, jsengine.ErrProviderNotFound) {
		t.Fatalf("Resolve(candidate) error = %v, want ErrProviderNotFound until a loader is provided", err)
	}
}

func TestRegistryDescriptorsAreStableSnapshots(t *testing.T) {
	registry := jsengine.NewRegistry()
	if err := registry.RegisterBuiltin(builtin.Provider()); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}
	if err := registry.RegisterCandidate(jsengine.RuntimeManifest{ID: "native", Name: "Native", Version: "1.2", Path: "/tmp/native"}); err != nil {
		t.Fatalf("RegisterCandidate() error = %v", err)
	}

	first := registry.Descriptors()
	if len(first) != 2 {
		t.Fatalf("Descriptors() length = %d, want 2", len(first))
	}
	first[0].Name = "mutated"
	first[1].Path = "mutated"
	second := registry.Descriptors()
	if second[0].Name == "mutated" || second[1].Path == "mutated" {
		t.Fatal("Descriptors() returned mutable registry metadata")
	}
	if second[0].ID != jsengine.EngineGoja || second[1].ID != "native" {
		t.Fatalf("Descriptors() order/IDs = %#v, want goja then native", second)
	}
}

type lookupRegistry interface {
	Descriptor(jsengine.EngineID) (jsengine.Descriptor, bool)
}

func TestRegistryDescriptorLookupReturnsSnapshot(t *testing.T) {
	registry := jsengine.NewRegistry()
	if err := registry.RegisterBuiltin(builtin.Provider()); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}
	lookup, ok := any(registry).(lookupRegistry)
	if !ok {
		t.Fatal("NewRegistry() does not expose descriptor lookup")
	}

	descriptor, found := lookup.Descriptor(" GOJA ")
	if !found || descriptor.ID != jsengine.EngineGoja {
		t.Fatalf("Descriptor() = %#v, %v; want Goja descriptor", descriptor, found)
	}
	descriptor.Name = "mutated"
	again, found := lookup.Descriptor(jsengine.EngineGoja)
	if !found || again.Name == "mutated" {
		t.Fatal("Descriptor() returned mutable registry metadata")
	}
}
