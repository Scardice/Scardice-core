package jsengine_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"Scardice-core/utils/jsengine"
	builtin "Scardice-core/utils/jsengine/builtin/goja"
)

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
	err := registry.RegisterCandidate(manifest)
	if !errors.Is(err, jsengine.ErrDuplicateProvider) {
		t.Fatalf("second RegisterCandidate() error = %v, want ErrDuplicateProvider", err)
	}
	if !strings.Contains(err.Error(), `duplicate provider ID "native.runtime"`) {
		t.Fatalf("second RegisterCandidate() error = %q, want normalized conflicting ID", err)
	}

	if err := registry.RegisterBuiltin(builtin.Provider()); err != nil {
		t.Fatalf("RegisterBuiltin() error = %v", err)
	}
	builtinManifest := jsengine.RuntimeManifest{ID: jsengine.EngineGoja, Name: "candidate"}
	err = registry.RegisterCandidate(builtinManifest)
	if !errors.Is(err, jsengine.ErrDuplicateProvider) {
		t.Fatalf("builtin/candidate RegisterCandidate() error = %v, want ErrDuplicateProvider", err)
	}
	if !strings.Contains(err.Error(), `duplicate provider ID "goja"`) {
		t.Fatalf("builtin/candidate error = %q, want conflicting builtin ID", err)
	}
}

func TestRegistryCandidateRegistrationKeepsMetadataLazy(t *testing.T) {
	registry := jsengine.NewRegistry()
	loads := 0
	provider := &candidateProvider{descriptor: jsengine.Descriptor{
		ID: "native", Name: "Native", Version: "1.2", Language: "C++",
	}}
	manifest := jsengine.RuntimeManifest{
		ID:           "native",
		Name:         "Native",
		Version:      "1.2",
		Language:     "C++",
		Capabilities: jsengine.CapabilityScript,
		Path:         "/tmp/native.so",
		Load: func() (jsengine.Provider, error) {
			loads++
			return provider, nil
		},
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
	if loads != 0 {
		t.Fatalf("candidate loaded during registration: %d", loads)
	}
	resolved, err := registry.Resolve("native")
	if err != nil || resolved.Descriptor().ID != "native" {
		t.Fatalf("Resolve(candidate) = %#v, %v", resolved, err)
	}
	if again, err := registry.Resolve("native"); err != nil || again != resolved {
		t.Fatalf("second Resolve(candidate) = %#v, %v; want cached provider", again, err)
	}
	if loads != 1 {
		t.Fatalf("candidate load count = %d, want 1", loads)
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

func TestRegistryManifestABIFieldsOverrideEmbeddedDescriptor(t *testing.T) {
	registry := jsengine.NewRegistry()
	manifest := jsengine.RuntimeManifest{
		ID: "native",
		Descriptor: jsengine.Descriptor{
			ID:           "embedded",
			ABIMajor:     1,
			HostABIMajor: 1,
		},
		ABIMajor:     2,
		HostABIMajor: 4,
	}
	if err := registry.RegisterCandidate(manifest); err != nil {
		t.Fatalf("RegisterCandidate() error = %v", err)
	}
	descriptor, found := registry.Descriptor(manifest.ID)
	if !found {
		t.Fatal("Descriptor() did not find candidate")
	}
	if descriptor.ID != manifest.ID || descriptor.ABIMajor != 2 ||
		descriptor.HostABIMajor != 4 {
		t.Fatalf("candidate descriptor ABI = %#v, want runtime v2 host v4", descriptor)
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

type candidateProvider struct {
	descriptor jsengine.Descriptor
}

func (p candidateProvider) Descriptor() jsengine.Descriptor {
	return p.descriptor
}

func (candidateProvider) Open(context.Context, jsengine.RuntimeOptions) (jsengine.Loop, error) {
	return nil, errors.New("candidate provider is not opened by registry tests")
}
