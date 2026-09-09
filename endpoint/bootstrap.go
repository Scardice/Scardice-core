package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

var (
	ErrBootstrapInvalid       = errors.New("endpoint: invalid bootstrap")
	ErrBootstrapNoStore       = errors.New("endpoint: bootstrap store is required")
	ErrBootstrapNoDescriptor  = errors.New("endpoint: bootstrap descriptor is required")
	ErrBootstrapDuplicateKey  = errors.New("endpoint: duplicate descriptor key")
)

// Registry is the process-local descriptor registry owned by endpoint
// composition. Registering a descriptor is inert: validation and runtime
// construction happen only when Service/Supervisor needs them.
type Registry struct {
	mu          sync.RWMutex
	descriptors map[adapterapi.AdapterKey]adapterapi.Descriptor
}

func NewRegistry() *Registry {
	return &Registry{descriptors: make(map[adapterapi.AdapterKey]adapterapi.Descriptor)}
}

func NewDescriptorRegistry() *Registry { return NewRegistry() }

func (r *Registry) Register(descriptor adapterapi.Descriptor) error {
	if r == nil || descriptor == nil || !descriptor.Key().Valid() {
		return ErrBootstrapNoDescriptor
	}
	key := descriptor.Key()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.descriptors == nil {
		r.descriptors = make(map[adapterapi.AdapterKey]adapterapi.Descriptor)
	}
	if _, exists := r.descriptors[key]; exists {
		return fmt.Errorf("%w: %s", ErrBootstrapDuplicateKey, key)
	}
	r.descriptors[key] = descriptor
	return nil
}

func (r *Registry) Lookup(ctx context.Context, key adapterapi.AdapterKey) (adapterapi.Descriptor, bool) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, false
	}
	r.mu.RLock()
	descriptor, ok := r.descriptors[key]
	r.mu.RUnlock()
	return descriptor, ok
}
type projectionStartupSource struct {
	rows interface {
		ListProjectionRows(context.Context, string) ([]eventstore.ProjectionRow, error)
	}
}

func (s projectionStartupSource) ValidateReadiness(ctx context.Context) error {
	if store, ok := s.rows.(interface{ ValidateReadiness(context.Context) error }); ok {
		return store.ValidateReadiness(ctx)
	}
	return nil
}

func (s projectionStartupSource) ListEndpointViews(ctx context.Context) ([]EndpointView, error) {
	rows, err := s.rows.ListProjectionRows(ctx, EndpointProjectionName)
	if err != nil {
		return nil, err
	}
	views := make([]EndpointView, 0, len(rows))
	for _, row := range rows {
		var view EndpointView
		if err := json.Unmarshal(row.Payload, &view); err != nil {
			return nil, fmt.Errorf("endpoint: decode startup projection %q: %w", row.RowKey, err)
		}
		views = append(views, view)
	}
	return views, nil
}

// Bootstrap owns the event-store-backed endpoint composition. Store is passed
// in by the application because eventstore.Database/Store ownership must not
// be borrowed from the legacy data DB. Shutdown drains Supervisor workers and
// then closes this independently-owned store through EndpointLifecycle.
type Bootstrap struct {
	Store      eventstore.Store
	Registry   *Registry
	Service    *Service
	Supervisor *Supervisor
	Lifecycle  *EndpointLifecycle
}

func NewBootstrap(store eventstore.Store, source any, descriptors ...adapterapi.Descriptor) (*Bootstrap, error) {
	if store == nil {
		return nil, ErrBootstrapNoStore
	}
	registry := NewRegistry()
	for _, descriptor := range descriptors {
		if err := registry.Register(descriptor); err != nil {
			return nil, err
		}
	}
	service := NewService(store, registry)
	if service.InitError != nil {
		return nil, service.InitError
	}
	lifecycleSink := &serviceLifecycleSink{service: service}
	supervisorOptions := []SupervisorOption{WithDescriptorRegistry(registry), WithLifecycleSink(lifecycleSink)}
	if resolver, ok := store.(eventstore.SecretResolver); ok {
		supervisorOptions = append(supervisorOptions, WithSecretResolver(eventStoreSecretResolver{resolver: resolver}))
	}
	supervisorArgs := make([]any, 0, len(supervisorOptions)+1)
	supervisorArgs = append(supervisorArgs, service)
	for _, option := range supervisorOptions {
		supervisorArgs = append(supervisorArgs, option)
	}
	supervisor := NewSupervisor(supervisorArgs...)
	lifecycle := NewEndpointLifecycle(supervisor, source)
	if source == nil {
		if rows, ok := store.(interface {
			ListProjectionRows(context.Context, string) ([]eventstore.ProjectionRow, error)
		}); ok {
			lifecycle.Source = projectionStartupSource{rows: rows}
		}
	}
	lifecycle.Service = service
	lifecycle.Store = store
	return &Bootstrap{Store: store, Registry: registry, Service: service, Supervisor: supervisor, Lifecycle: lifecycle}, nil
}

func NewEndpointBootstrap(store eventstore.Store, source any, descriptors ...adapterapi.Descriptor) (*Bootstrap, error) {
	return NewBootstrap(store, source, descriptors...)
}

// SetInboundSink installs the Core ingress bridge before Startup. Bootstrap
// itself cannot import the Dice package without inverting the endpoint leaf;
// the application supplies the provider-neutral bridge at composition time.
func (b *Bootstrap) SetInboundSink(v any) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	sink := inboundSink(v)
	if sink == nil {
		return ErrSupervisorNoInboundSink
	}
	b.Supervisor.mu.Lock()
	b.Supervisor.inbound = sink
	b.Supervisor.mu.Unlock()
	return nil
}
func (b *Bootstrap) InboundSink() InboundSink {
	if b == nil || b.Supervisor == nil {
		return nil
	}
	b.Supervisor.mu.Lock()
	defer b.Supervisor.mu.Unlock()
	return b.Supervisor.inbound
}

// Execute commits an application command and immediately applies every
// resulting lifecycle effect through the Supervisor. Replay commands return
// without effects, preserving idempotent worker ownership.
func (b *Bootstrap) Execute(ctx context.Context, command Command) (Result, error) {
	if b == nil || b.Service == nil || b.Supervisor == nil { return Result{}, ErrBootstrapInvalid }
	result, err := b.Service.Execute(ctx, command)
	if err != nil { return Result{}, err }
	for _, effect := range result.Effects {
		if err := b.Supervisor.Reconcile(ctx, result.State, effect); err != nil { return result, err }
	}
	return result, nil
}

func (b *Bootstrap) ExecuteCommand(ctx context.Context, command Command) (Result, error) {
	return b.Execute(ctx, command)
}
func (b *Bootstrap) Startup(ctx context.Context, options ...StartupOption) (StartupResult, error) {
	if b == nil || b.Lifecycle == nil {
		return StartupResult{}, ErrBootstrapInvalid
	}
	return b.Lifecycle.Startup(ctx, options...)
}

func (b *Bootstrap) ReconcileAll(ctx context.Context) (ReconcileResult, error) {
	if b == nil || b.Lifecycle == nil {
		return ReconcileResult{}, ErrBootstrapInvalid
	}
	return b.Lifecycle.ReconcileAll(ctx)
}

func (b *Bootstrap) Shutdown(ctx context.Context) error {
	if b == nil || b.Lifecycle == nil {
		return ErrBootstrapInvalid
	}
	return b.Lifecycle.Shutdown(ctx)
}

// serviceLifecycleSink turns terminal provider observations into the aggregate's
// completion command. Starting/stopping are runtime facts needed by the
// Supervisor but are not operation completion and therefore do not advance the
// aggregate. A missing state is tolerated for replay-only test stores and for
// providers removed before an observation arrives; it never creates a fallback
// legacy runtime.
type serviceLifecycleSink struct{ service *Service }

func (s *serviceLifecycleSink) RecordLifecycle(ctx context.Context, update LifecycleUpdate) error {
	if s == nil || s.service == nil || update.ObservedState == adapterapi.ObservedStateStarting || update.ObservedState == adapterapi.ObservedStateStopping {
		return nil
	}
	state, err := s.service.Repository.Load(ctx, update.EndpointID)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, eventstore.ErrNotFound) {
			return nil
		}
		return err
	}
	if state.Generation != update.Generation { return nil }
	if state.OperationState == OperationStateSucceeded && state.DesiredState == DesiredStateRemoving && update.ObservedState == adapterapi.ObservedStateStopped {
		resolveID := fmt.Sprintf("supervisor:resolve:%s:%d:%d", update.EndpointID, update.Generation, update.DesiredVersion)
		_, err = s.service.Resolve(ctx, Command{CommandID: resolveID, CorrelationID: resolveID, OperationID: state.OperationID, EndpointID: update.EndpointID, Generation: update.Generation})
		return err
	}
	if state.OperationState != OperationStatePending && state.OperationState != OperationStateFailed && state.OperationState != OperationStateAmbiguous && state.OperationState != OperationStateSucceeded { return nil }
	completion := OperationStateSucceeded
	if state.OperationState != OperationStateSucceeded {
		if update.Ambiguous || update.ObservedState == adapterapi.ObservedStateAmbiguous {
			completion = OperationStateAmbiguous
		} else if update.ObservedState == adapterapi.ObservedStateFailed {
			completion = OperationStateFailed
		}
	}
	commandID := fmt.Sprintf("supervisor:%s:%d:%d:observed:%d", update.EndpointID, update.Generation, update.DesiredVersion, update.ObservedState)
	completed, err := s.service.Complete(ctx, Command{
		CommandID:      commandID,
		CorrelationID:  commandID,
		OperationID:    state.OperationID,
		EndpointID:     update.EndpointID,
		Generation:     update.Generation,
		ObservedState:  update.ObservedState,
		CompletionState: completion,
	})
	if err != nil { return err }
	if completion == OperationStateSucceeded && completed.State.DesiredState == DesiredStateRemoving {
		resolveID := fmt.Sprintf("supervisor:resolve:%s:%d:%d", update.EndpointID, update.Generation, update.DesiredVersion)
		_, err = s.service.Resolve(ctx, Command{CommandID: resolveID, CorrelationID: resolveID, OperationID: completed.State.OperationID, EndpointID: update.EndpointID, Generation: update.Generation})
	}
	return err
}
type eventStoreSecretResolver struct {
	resolver eventstore.SecretResolver
}

func (r eventStoreSecretResolver) Resolve(ctx context.Context, ref adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	if r.resolver == nil {
		return adapterapi.SecretValue{}, eventstore.ErrKeyUnavailable
	}
	resolved, err := r.resolver.ResolveSecret(ctx, ref.Ref, ref.Version)
	if err != nil {
		return adapterapi.SecretValue{}, err
	}
	value := adapterapi.SecretValue{Bytes: append([]byte(nil), resolved.Plaintext...), Version: resolved.SecretVersion}
	for index := range resolved.Plaintext {
		resolved.Plaintext[index] = 0
	}
	return value, nil
}
