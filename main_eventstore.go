package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

// legacyStatePresent only inspects legacy file presence. It never opens a
// legacy database or invokes a legacy loader; eventsourcing owns that read.
func legacyStatePresent() bool {
	for _, path := range []string{
		filepath.Join("data", "dice.yaml"),
		filepath.Join("data", "default", "serve.yaml"),
		filepath.Join("data", "default", "advanced.yaml"),
		filepath.Join("data", "default", "data.db"),
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	entries, err := os.ReadDir("data")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join("data", entry.Name(), "data.db")); err == nil {
			return true
		}
	}
	return false
}

type eventEndpointResolver struct {
	service  *endpoint.Service
	registry *endpoint.Registry
	store    *eventstore.GORMStore
}

func newEventEndpointResolver(service *endpoint.Service, registry *endpoint.Registry, store *eventstore.GORMStore) *eventEndpointResolver {
	return &eventEndpointResolver{service: service, registry: registry, store: store}
}

func (r *eventEndpointResolver) Resolve(ctx context.Context, id adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	if r == nil || r.service == nil || r.registry == nil || r.store == nil || !id.Valid() {
		return messageflow.EndpointSnapshot{}, endpoint.ErrNotFound
	}
	view, err := r.service.Get(ctx, id)
	if err != nil {
		return messageflow.EndpointSnapshot{}, err
	}
	descriptor, ok := r.registry.Lookup(ctx, view.AdapterKey)
	if !ok || descriptor == nil {
		return messageflow.EndpointSnapshot{}, endpoint.ErrUnknownAdapter
	}
	_, rootID, err := r.store.KeyedDigest(ctx, "endpoint-snapshot/v1", string(id))
	if err != nil {
		return messageflow.EndpointSnapshot{}, err
	}
	capabilities := adapterapi.CapabilityLifecycle
	if provider, ok := descriptor.(interface {
		Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet
	}); ok {
		capabilities = provider.Capabilities(view.Config)
	}
	actions := descriptor.SupportedActions(view.Config)
	if actions != 0 {
		capabilities |= adapterapi.CapabilityActions
	}
	if view.AdapterKey == adapterapi.AdapterKey("pureonebot") {
		capabilities |= adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages
	}
	return messageflow.EndpointSnapshot{
		EndpointID:    view.EndpointID,
		DesiredState:  string(view.DesiredState),
		ObservedState: view.ObservedState,
		Capabilities:  capabilities,
		Actions:       actions,
		IndexRootID:   rootID,
		IndexSigner:   r.store,
	}, nil
}

func runEventEffectDispatcher(ctx context.Context, dispatcher *endpoint.EffectDispatcher) {
	if dispatcher == nil {
		return
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := dispatcher.DispatchOnce(ctx); err != nil && !errors.Is(err, eventstore.ErrNotFound) && !errors.Is(err, eventstore.ErrPayloadExpired) {
			if ctx.Err() != nil {
				return
			}
			logger.M().Warnf("durable outbound dispatch failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
