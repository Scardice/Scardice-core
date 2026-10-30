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
	ErrBootstrapInvalid      = errors.New("endpoint: invalid bootstrap")
	ErrBootstrapNoStore      = errors.New("endpoint: bootstrap store is required")
	ErrBootstrapNoDescriptor = errors.New("endpoint: bootstrap descriptor is required")
	ErrBootstrapDuplicateKey = errors.New("endpoint: duplicate descriptor key")
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
		ListProjectionRows(ctx context.Context, projectionName string) ([]eventstore.ProjectionRow, error)
	}
}

func (s projectionStartupSource) ValidateReadiness(ctx context.Context) error {
	if store, ok := s.rows.(interface {
		ValidateReadiness(ctx context.Context) error
	}); ok {
		return store.ValidateReadiness(ctx)
	}
	return nil
}

func (s projectionStartupSource) ListEndpointStates(ctx context.Context) ([]State, error) {
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
	return statesFromViews(views), nil
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

func NewBootstrap(store eventstore.Store, source EndpointStateLister, descriptors ...adapterapi.Descriptor) (*Bootstrap, error) {
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
	supervisorOptions := []SupervisorOption{WithLifecycleSink(lifecycleSink)}
	if resolver, ok := store.(eventstore.SecretOwnerResolver); ok {
		factory := func(endpointID adapterapi.EndpointID, adapterID adapterapi.AdapterKey) adapterapi.SecretResolver {
			return eventStoreSecretResolver{resolver: resolver, endpointID: string(endpointID), adapterID: string(adapterID)}
		}
		supervisorOptions = append(supervisorOptions, WithSecretResolverFactory(factory))
	}
	supervisor := NewSupervisor(registry, supervisorOptions...)
	lifecycle := NewEndpointLifecycle(supervisor, source)
	if source == nil {
		if rows, ok := store.(interface {
			ListProjectionRows(ctx context.Context, projectionName string) ([]eventstore.ProjectionRow, error)
		}); ok {
			lifecycle.Source = projectionStartupSource{rows: rows}
		}
	}
	lifecycle.Service = service
	lifecycle.Store = store
	return &Bootstrap{Store: store, Registry: registry, Service: service, Supervisor: supervisor, Lifecycle: lifecycle}, nil
}

// SetResourceRoot configures the filesystem root for process-owned adapter
// resources before Startup starts any enabled endpoint.
func (b *Bootstrap) SetResourceRoot(root string) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	b.Supervisor.SetResourceRoot(root)
	return nil
}

// SetResourceAccessToken supplies the process-local token used by providers
// when retrieving shared resources from the core HTTP service.
func (b *Bootstrap) SetResourceAccessToken(token string) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	b.Supervisor.SetResourceAccessToken(token)
	return nil
}

// SetResourceServeAddress supplies the core HTTP listen address used to build
// provider-reachable shared resource URLs.
func (b *Bootstrap) SetResourceServeAddress(address string) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	b.Supervisor.SetResourceServeAddress(address)
	return nil
}

// SetInboundSink installs the Core ingress bridge before Startup. Bootstrap
func (b *Bootstrap) SetInboundSink(sink InboundSink) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
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

// SetAdapterEventSink installs the optional Core bridge for protocol events
// which have no recoverable conversation and therefore bypass durable ingress.
func (b *Bootstrap) SetAdapterEventSink(sink AdapterEventSink) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	if sink == nil {
		return ErrSupervisorNoAdapterEventSink
	}
	b.Supervisor.mu.Lock()
	b.Supervisor.adapterEvent = sink
	b.Supervisor.mu.Unlock()
	return nil
}

func (b *Bootstrap) AdapterEventSink() AdapterEventSink {
	if b == nil || b.Supervisor == nil {
		return nil
	}
	b.Supervisor.mu.Lock()
	defer b.Supervisor.mu.Unlock()
	return b.Supervisor.adapterEvent
}

// SetCharacterSink installs the Core-owned character-sheet service bridge
// before Startup. Provider runtimes reach it through the optional
// adapterapi.CharacterCorePort implemented by Supervisor's CorePort.
func (b *Bootstrap) SetCharacterSink(sink CharacterSink) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	if sink == nil {
		return ErrSupervisorNoCharacterSink
	}
	b.Supervisor.mu.Lock()
	b.Supervisor.character = sink
	b.Supervisor.mu.Unlock()
	return nil
}

func (b *Bootstrap) CharacterSink() CharacterSink {
	if b == nil || b.Supervisor == nil {
		return nil
	}
	b.Supervisor.mu.Lock()
	defer b.Supervisor.mu.Unlock()
	return b.Supervisor.character
}

// SetIdentityObservationSink installs the Core-owned identity journal bridge
// before Startup. Provider runtimes retain only DTO-level identity facts.
func (b *Bootstrap) SetIdentityObservationSink(sink IdentityObservationSink) error {
	if b == nil || b.Supervisor == nil {
		return ErrBootstrapInvalid
	}
	if sink == nil {
		return ErrSupervisorNoIdentitySink
	}
	b.Supervisor.mu.Lock()
	b.Supervisor.identity = sink
	b.Supervisor.mu.Unlock()
	return nil
}

func (b *Bootstrap) IdentityObservationSink() IdentityObservationSink {
	if b == nil || b.Supervisor == nil {
		return nil
	}
	b.Supervisor.mu.Lock()
	defer b.Supervisor.mu.Unlock()
	return b.Supervisor.identity
}

// Execute commits an application command and immediately applies every
// resulting lifecycle effect through the Supervisor. Replay commands return
// without effects, preserving idempotent worker ownership.
func (b *Bootstrap) Execute(ctx context.Context, command Command) (Result, error) {
	if b == nil || b.Service == nil || b.Supervisor == nil {
		return Result{}, ErrBootstrapInvalid
	}
	result, err := b.Service.Execute(ctx, command)
	if err != nil {
		return Result{}, err
	}
	for _, effect := range result.Effects {
		if err := b.Supervisor.Reconcile(ctx, result.State, effect); err != nil {
			return result, err
		}
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
	if state.Generation != update.Generation || state.DesiredVersion != update.DesiredVersion {
		return nil
	}
	if state.OperationState == OperationStateSucceeded && state.DesiredState == DesiredStateRemoving && update.ObservedState == adapterapi.ObservedStateStopped {
		resolveID := fmt.Sprintf("supervisor:resolve:%s:%d:%d", update.EndpointID, update.Generation, update.DesiredVersion)
		_, err = s.service.Resolve(ctx, Command{CommandID: resolveID, CorrelationID: resolveID, OperationID: state.OperationID, EndpointID: update.EndpointID, Generation: update.Generation})
		return err
	}
	// A runtime that reconnects on its own reports the same state again; only
	// an operation still in progress needs it.
	if state.ObservedState == update.ObservedState && state.OperationState != OperationStatePending && state.OperationState != OperationStateAmbiguous {
		return nil
	}
	if state.OperationState != OperationStatePending && state.OperationState != OperationStateFailed && state.OperationState != OperationStateAmbiguous && state.OperationState != OperationStateSucceeded {
		return nil
	}
	completion := OperationStateSucceeded
	if state.OperationState != OperationStateSucceeded {
		if update.Ambiguous || update.ObservedState == adapterapi.ObservedStateAmbiguous {
			completion = OperationStateAmbiguous
		} else if update.ObservedState == adapterapi.ObservedStateFailed {
			completion = OperationStateFailed
		}
	}
	// The aggregate version tells apart transitions a long-lived runtime makes
	// more than once, while a redelivered publication keeps its command ID.
	commandID := fmt.Sprintf("supervisor:%s:%d:%d:runtime:%s:observed:%d:at:%d", update.EndpointID, update.Generation, update.DesiredVersion, update.RuntimeID, update.ObservedState, state.Version)
	completed, err := s.service.Complete(ctx, Command{
		CommandID:       commandID,
		CorrelationID:   commandID,
		OperationID:     state.OperationID,
		EndpointID:      update.EndpointID,
		Generation:      update.Generation,
		DesiredVersion:  update.DesiredVersion,
		ObservedState:   update.ObservedState,
		CompletionState: completion,
	})
	if err != nil {
		// A command can advance the fence between the initial read and Complete.
		// Discard only proven obsolete observations, not current-fence failures.
		current, loadErr := s.service.Repository.Load(ctx, update.EndpointID)
		if loadErr == nil && (current.Generation != update.Generation || current.DesiredVersion != update.DesiredVersion) {
			return nil
		}
		return err
	}
	if completion == OperationStateSucceeded && completed.State.DesiredState == DesiredStateRemoving {
		resolveID := fmt.Sprintf("supervisor:resolve:%s:%d:%d", update.EndpointID, update.Generation, update.DesiredVersion)
		_, err = s.service.Resolve(ctx, Command{CommandID: resolveID, CorrelationID: resolveID, OperationID: completed.State.OperationID, EndpointID: update.EndpointID, Generation: update.Generation})
	}
	return err
}

type eventStoreSecretResolver struct {
	resolver   eventstore.SecretOwnerResolver
	endpointID string
	adapterID  string
}

func (r eventStoreSecretResolver) Resolve(ctx context.Context, ref adapterapi.SecretRef) (adapterapi.SecretValue, error) {
	if r.resolver == nil || r.endpointID == "" || r.adapterID == "" {
		return adapterapi.SecretValue{}, eventstore.ErrKeyUnavailable
	}
	resolved, err := r.resolver.ResolveSecretForOwner(ctx, r.endpointID, r.adapterID, ref.Ref, ref.Version)
	if err != nil {
		return adapterapi.SecretValue{}, err
	}
	value := adapterapi.SecretValue{Bytes: append([]byte(nil), resolved.Plaintext...), Version: resolved.SecretVersion}
	for index := range resolved.Plaintext {
		resolved.Plaintext[index] = 0
	}
	return value, nil
}
