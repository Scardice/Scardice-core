package jsengine

import (
	"errors"
	"fmt"
	"sync"
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

// Registry owns builtin providers and lazy runtime candidates.
type Registry interface {
	RegisterBuiltin(Provider) error
	RegisterCandidate(RuntimeManifest) error
	Resolve(EngineID) (Provider, error)
	Descriptors() []Descriptor
}

type candidateEntry struct {
	mu       sync.Mutex
	load     func() (Provider, error)
	provider Provider
}

func (entry *candidateEntry) resolve(id EngineID) (Provider, error) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.provider != nil {
		return entry.provider, nil
	}
	if entry.load == nil {
		return nil, fmt.Errorf("%w: candidate %q has no loader", ErrProviderNotFound, id)
	}
	provider, err := entry.load()
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, fmt.Errorf("%w: candidate %q returned nil", ErrInvalidProvider, id)
	}
	if resolvedID := NormalizeEngineID(string(provider.Descriptor().ID)); resolvedID != id {
		return nil, fmt.Errorf("%w: candidate %q loaded provider %q", ErrInvalidProvider, id, resolvedID)
	}
	entry.provider = provider
	return provider, nil
}

type registry struct {
	mu          sync.RWMutex
	providers   map[EngineID]Provider
	descriptors map[EngineID]Descriptor
	candidates  map[EngineID]*candidateEntry
	order       []EngineID
}

// NewRegistry creates an empty registry. Builtins are registered explicitly by
// the caller, which keeps the core package independent of provider packages.
func NewRegistry() *registry {
	return &registry{
		providers:   make(map[EngineID]Provider),
		descriptors: make(map[EngineID]Descriptor),
		candidates:  make(map[EngineID]*candidateEntry),
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
	r.mu.Lock()
	defer r.mu.Unlock()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.descriptors[descriptor.ID]; exists {
		return fmt.Errorf("%w: duplicate provider ID %q", ErrDuplicateProvider, descriptor.ID)
	}
	descriptor.Builtin = false
	r.descriptors[descriptor.ID] = descriptor
	r.candidates[descriptor.ID] = &candidateEntry{load: manifest.Load}
	r.order = append(r.order, descriptor.ID)
	return nil
}

func (r *registry) Resolve(id EngineID) (Provider, error) {
	id = NormalizeEngineID(string(id))
	if id == "" {
		id = EngineGoja
	}
	r.mu.RLock()
	if provider, ok := r.providers[id]; ok {
		r.mu.RUnlock()
		return provider, nil
	}
	candidate := r.candidates[id]
	r.mu.RUnlock()
	if candidate == nil {
		return nil, fmt.Errorf("%w: engine ID %q", ErrProviderNotFound, id)
	}
	provider, err := candidate.resolve(id)
	if err != nil {
		return nil, err
	}
	descriptor := provider.Descriptor()
	descriptor.ID = id
	descriptor.Builtin = false
	descriptor.Extensions = NormalizeExtensions(descriptor.Extensions)
	descriptor.Services = append([]string(nil), descriptor.Services...)
	r.mu.Lock()
	r.providers[id] = provider
	r.descriptors[id] = descriptor
	r.mu.Unlock()
	return provider, nil
}

// Descriptors returns registration-order metadata snapshots. Mutating the
// returned slice or its descriptors does not mutate the registry.
func (r *registry) Descriptors() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
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
	r.mu.RLock()
	defer r.mu.RUnlock()
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
