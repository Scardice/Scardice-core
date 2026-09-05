package jsengine

import (
	"errors"
	"fmt"
)

var (
	// ErrProviderNotFound indicates that no usable provider is registered for
	// an engine ID. It can be inspected with errors.Is.
	ErrProviderNotFound = errors.New("provider not found")
	// ErrDuplicateProvider indicates an ID collision between providers or
	// discovery candidates.
	ErrDuplicateProvider = errors.New("duplicate provider")
	// ErrInvalidProvider indicates malformed or nil provider registration.
	ErrInvalidProvider = errors.New("invalid provider")
	// ErrInvalidManifest indicates a candidate manifest without an ID.
	ErrInvalidManifest = errors.New("invalid runtime manifest")
)

// Registry discovers providers and retains candidate metadata without loading
// candidate runtimes.
type Registry interface {
	RegisterBuiltin(Provider) error
	RegisterCandidate(RuntimeManifest) error
	Resolve(EngineID) (Provider, error)
	Descriptors() []Descriptor
}

type registry struct {
	providers   map[EngineID]Provider
	descriptors map[EngineID]Descriptor
	candidates  map[EngineID]struct{}
	order       []EngineID
}

// NewRegistry creates an empty registry. Builtins are registered explicitly by
// the caller, which keeps the core package independent of provider packages.
func NewRegistry() *registry {
	return &registry{
		providers:   make(map[EngineID]Provider),
		descriptors: make(map[EngineID]Descriptor),
		candidates:  make(map[EngineID]struct{}),
	}
}

func (r *registry) RegisterBuiltin(provider Provider) error {
	if provider == nil {
		return ErrInvalidProvider
	}
	descriptor := provider.Descriptor()
	descriptor.ID = NormalizeEngineID(string(descriptor.ID))
	if descriptor.ID == "" {
		return fmt.Errorf("%w: provider ID is empty", ErrInvalidProvider)
	}
	descriptor.Extensions = NormalizeExtensions(descriptor.Extensions)
	descriptor.Services = append([]string(nil), descriptor.Services...)
	if _, exists := r.descriptors[descriptor.ID]; exists {
		return fmt.Errorf("%w: duplicate provider ID %q", ErrDuplicateProvider, descriptor.ID)
	}
	descriptor.Builtin = true
	r.providers[descriptor.ID] = provider
	r.descriptors[descriptor.ID] = descriptor
	r.order = append(r.order, descriptor.ID)
	return nil
}

func (r *registry) RegisterCandidate(manifest RuntimeManifest) error {
	descriptor := manifest.descriptor()
	descriptor.ID = NormalizeEngineID(string(descriptor.ID))
	if descriptor.ID == "" {
		return fmt.Errorf("%w: runtime ID is empty", ErrInvalidManifest)
	}
	descriptor.Extensions = NormalizeExtensions(descriptor.Extensions)
	descriptor.Services = append([]string(nil), descriptor.Services...)
	if _, exists := r.descriptors[descriptor.ID]; exists {
		return fmt.Errorf("%w: duplicate provider ID %q", ErrDuplicateProvider, descriptor.ID)
	}
	descriptor.Builtin = false
	r.descriptors[descriptor.ID] = descriptor
	r.candidates[descriptor.ID] = struct{}{}
	r.order = append(r.order, descriptor.ID)
	return nil
}

func (r *registry) Resolve(id EngineID) (Provider, error) {
	id = NormalizeEngineID(string(id))
	if id == "" {
		id = EngineGoja
	}
	if provider, ok := r.providers[id]; ok {
		return provider, nil
	}
	if _, ok := r.candidates[id]; ok {
		return nil, fmt.Errorf("%w: candidate %q is not loadable", ErrProviderNotFound, id)
	}
	return nil, fmt.Errorf("%w: engine ID %q", ErrProviderNotFound, id)
}

// Descriptors returns registration-order metadata snapshots. Mutating the
// returned slice or its descriptors does not mutate the registry.
func (r *registry) Descriptors() []Descriptor {
	descriptors := make([]Descriptor, 0, len(r.order))
	for _, id := range r.order {
		descriptor := r.descriptors[id]
		descriptor.Services = append([]string(nil), descriptor.Services...)
		descriptor.Extensions = append([]string(nil), descriptor.Extensions...)
		descriptors = append(descriptors, descriptor)
	}
	return descriptors
}

// Descriptor looks up one metadata snapshot by normalized engine ID.
func (r *registry) Descriptor(id EngineID) (Descriptor, bool) {
	id = NormalizeEngineID(string(id))
	if id == "" {
		id = EngineGoja
	}
	descriptor, ok := r.descriptors[id]
	if !ok {
		return Descriptor{}, false
	}
	descriptor.Services = append([]string(nil), descriptor.Services...)
	descriptor.Extensions = append([]string(nil), descriptor.Extensions...)
	return descriptor, true
}

// Lookup is an alias for Descriptor for callers that prefer lookup semantics.
func (r *registry) Lookup(id EngineID) (Descriptor, bool) {
	return r.Descriptor(id)
}
