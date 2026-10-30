package endpoint

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"Scardice-core/eventstore"
)

var (
	ErrEndpointLifecycleUnavailable = errors.New("endpoint: lifecycle unavailable")
	ErrEndpointNotReady             = errors.New("endpoint: store is not ready")
	ErrEndpointListerUnavailable    = errors.New("endpoint: endpoint lister is required")
	ErrEndpointLifecycleClosed      = errors.New("endpoint: lifecycle is closed")
	ErrStartupNotReady              = ErrEndpointNotReady
)

// EndpointStateLister is the replay-only source used by startup. It must read
// durable state and must not construct adapter runtimes.
type EndpointStateLister interface {
	ListEndpointStates(ctx context.Context) ([]State, error)
}

type StartupOption func(*StartupOptions)

type StartupOptions struct {
	Rebuild          bool
	ProjectorVersion string
	Lister           EndpointStateLister
}

func WithProjectionRebuild(enabled bool) StartupOption {
	return func(options *StartupOptions) { options.Rebuild = enabled }
}

func WithProjectorVersion(version string) StartupOption {
	return func(options *StartupOptions) { options.ProjectorVersion = strings.TrimSpace(version) }
}

func WithEndpointLister(lister EndpointStateLister) StartupOption {
	return func(options *StartupOptions) { options.Lister = lister }
}

type StartupResult struct {
	Rebuilt   bool
	Rebuild   eventstore.RebuildResult
	Reconcile ReconcileResult
}

type ReconcileResult struct {
	Considered int
	Reconciled int
	Skipped    int
}

// EndpointLifecycle sequences event-store readiness, projection rebuild, and
// runtime reconciliation. A rebuild completes before the first Supervisor
// call, which makes replay runtime-free by construction.
type EndpointLifecycle struct {
	Supervisor       *Supervisor
	Service          *Service
	Store            eventstore.Store
	Source           EndpointStateLister
	Rebuilder        eventstore.ProjectionRebuilder
	ProjectorVersion string
	shutdownMu       sync.Mutex
	storeClosed      bool
	shutdownResult   error
	opMu             sync.Mutex
	opDone           chan struct{}
	activeOps        int
	closing          bool
}

func NewEndpointLifecycle(supervisor *Supervisor, source EndpointStateLister, rebuilders ...eventstore.ProjectionRebuilder) *EndpointLifecycle {
	lifecycle := &EndpointLifecycle{Supervisor: supervisor, Source: source, ProjectorVersion: EndpointProjectionVersion}
	lifecycle.opDone = make(chan struct{})
	close(lifecycle.opDone)
	if store, ok := source.(eventstore.Store); ok {
		lifecycle.Store = store
	}
	for _, rebuilder := range rebuilders {
		if rebuilder != nil {
			lifecycle.Rebuilder = rebuilder
			break
		}
	}
	if lifecycle.Rebuilder == nil {
		if rebuilder, ok := source.(eventstore.ProjectionRebuilder); ok {
			lifecycle.Rebuilder = rebuilder
		}
	}
	return lifecycle
}

func (l *EndpointLifecycle) beginOperation() error {
	if l == nil {
		return ErrEndpointLifecycleUnavailable
	}
	l.opMu.Lock()
	defer l.opMu.Unlock()
	if l.closing || l.storeClosed {
		return ErrEndpointLifecycleClosed
	}
	if l.activeOps == 0 {
		l.opDone = make(chan struct{})
	}
	l.activeOps++
	return nil
}

func (l *EndpointLifecycle) endOperation() {
	l.opMu.Lock()
	if l.activeOps > 0 {
		l.activeOps--
		if l.activeOps == 0 {
			close(l.opDone)
		}
	}
	l.opMu.Unlock()
}

func (l *EndpointLifecycle) beginClosing() <-chan struct{} {
	l.opMu.Lock()
	defer l.opMu.Unlock()
	l.closing = true
	if l.activeOps == 0 {
		select {
		case <-l.opDone:
		default:
			close(l.opDone)
		}
	}
	return l.opDone
}

func (l *EndpointLifecycle) Startup(ctx context.Context, options ...StartupOption) (StartupResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l == nil || l.Supervisor == nil {
		return StartupResult{}, ErrEndpointLifecycleUnavailable
	}
	if err := l.beginOperation(); err != nil {
		return StartupResult{}, err
	}
	defer l.endOperation()
	settings := StartupOptions{ProjectorVersion: l.ProjectorVersion, Lister: l.Source}
	for _, option := range options {
		if option != nil {
			option(&settings)
		}
	}
	if settings.ProjectorVersion == "" {
		settings.ProjectorVersion = EndpointProjectionVersion
	}
	if err := l.requireReady(ctx); err != nil {
		return StartupResult{}, err
	}
	result := StartupResult{}
	if settings.Rebuild {
		rebuilder := l.Rebuilder
		if rebuilder == nil {
			if candidate, ok := l.Store.(eventstore.ProjectionRebuilder); ok {
				rebuilder = candidate
			}
		}
		if rebuilder == nil {
			return StartupResult{}, fmt.Errorf("%w: projection rebuilder", ErrEndpointLifecycleUnavailable)
		}
		rebuild, err := rebuilder.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: settings.ProjectorVersion})
		if err != nil {
			return StartupResult{}, err
		}
		result.Rebuilt = true
		result.Rebuild = rebuild
	}
	states, err := l.listStates(ctx, settings.Lister)
	if err != nil {
		return StartupResult{}, err
	}
	reconciled, err := l.reconcileStates(ctx, states)
	if err != nil {
		return StartupResult{}, err
	}
	result.Reconcile = reconciled
	return result, nil
}

func (l *EndpointLifecycle) ReconcileAll(ctx context.Context) (ReconcileResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l == nil || l.Supervisor == nil {
		return ReconcileResult{}, ErrEndpointLifecycleUnavailable
	}
	if err := l.beginOperation(); err != nil {
		return ReconcileResult{}, err
	}
	defer l.endOperation()
	states, err := l.listStates(ctx, l.Source)
	if err != nil {
		return ReconcileResult{}, err
	}
	return l.reconcileStates(ctx, states)
}

func (l *EndpointLifecycle) reconcileStates(ctx context.Context, states []State) (ReconcileResult, error) {
	result := ReconcileResult{}
	for _, state := range states {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !state.EndpointID.Valid() {
			return result, fmt.Errorf("%w: invalid endpoint state", ErrEndpointLifecycleUnavailable)
		}
		if state.DesiredState != DesiredStateEnabled {
			result.Skipped++
			continue
		}
		if state.DesiredVersion == 0 {
			return result, fmt.Errorf("%w: endpoint %s has no desired version", ErrEndpointLifecycleUnavailable, state.EndpointID)
		}
		result.Considered++
		effect := LifecycleEffect{
			ID:             fmt.Sprintf("startup:%s:%d:%d", state.EndpointID, state.Generation, state.DesiredVersion),
			EffectID:       fmt.Sprintf("startup:%s:%d:%d", state.EndpointID, state.Generation, state.DesiredVersion),
			Kind:           EffectStart,
			EndpointID:     state.EndpointID,
			Generation:     state.Generation,
			DesiredState:   DesiredStateEnabled,
			DesiredVersion: state.DesiredVersion,
			OperationID:    state.OperationID,
			CorrelationID:  state.CorrelationID,
		}
		if err := l.Supervisor.Reconcile(ctx, state, effect); err != nil {
			return result, err
		}
		result.Reconciled++
	}
	return result, nil
}

func (l *EndpointLifecycle) Shutdown(ctx context.Context) error {
	if l == nil || l.Supervisor == nil {
		return ErrEndpointLifecycleUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.shutdownMu.Lock()
	defer l.shutdownMu.Unlock()
	l.opMu.Lock()
	alreadyClosed := l.storeClosed
	l.opMu.Unlock()
	if alreadyClosed {
		return nil
	}
	activeDone := l.beginClosing()
	l.Supervisor.BeginShutdown()
	select {
	case <-activeDone:
	case <-ctx.Done():
		l.shutdownResult = ctx.Err()
		return ctx.Err()
	}
	if err := l.Supervisor.Shutdown(ctx); err != nil {
		// Keep the store open while an ambiguous owner remains. A later
		// resolver needs the durable lifecycle sink to publish convergence.
		l.shutdownResult = err
		return err
	}
	if l.Store == nil {
		l.opMu.Lock()
		l.storeClosed = true
		l.opMu.Unlock()
		l.shutdownResult = nil
		return nil
	}
	if err := l.Store.Close(); err != nil {
		l.shutdownResult = err
		return err
	}
	l.opMu.Lock()
	l.storeClosed = true
	l.opMu.Unlock()
	l.shutdownResult = nil
	return nil
}

func (l *EndpointLifecycle) requireReady(ctx context.Context) error {
	if l == nil {
		return ErrEndpointLifecycleUnavailable
	}
	if getter, ok := l.Source.(eventstore.ReadinessMetadataRepository); ok {
		if _, err := getter.GetReadinessMetadata(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrEndpointNotReady, err)
		}
		return nil
	}
	if getter, ok := l.Store.(eventstore.ReadinessMetadataRepository); ok {
		if _, err := getter.GetReadinessMetadata(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrEndpointNotReady, err)
		}
		return nil
	}
	if getter, ok := l.Source.(eventstore.ReadinessRepository); ok {
		if _, err := getter.GetReadiness(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrEndpointNotReady, err)
		}
		return nil
	}
	if getter, ok := l.Store.(eventstore.ReadinessRepository); ok {
		if _, err := getter.GetReadiness(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrEndpointNotReady, err)
		}
		return nil
	}
	if checker, ok := l.Source.(interface {
		ValidateReadiness(ctx context.Context) error
	}); ok {
		if err := checker.ValidateReadiness(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrEndpointNotReady, err)
		}
		return nil
	}
	if checker, ok := l.Store.(interface {
		ValidateReadiness(ctx context.Context) error
	}); ok {
		if err := checker.ValidateReadiness(ctx); err != nil {
			return fmt.Errorf("%w: %w", ErrEndpointNotReady, err)
		}
		return nil
	}
	return fmt.Errorf("%w: readiness checker unavailable", ErrEndpointNotReady)
}

func (l *EndpointLifecycle) listStates(ctx context.Context, source EndpointStateLister) ([]State, error) {
	if source == nil {
		source = l.Source
	}
	if source == nil {
		return nil, ErrEndpointListerUnavailable
	}
	return source.ListEndpointStates(ctx)
}

func statesFromViews(views []EndpointView) []State {
	states := make([]State, 0, len(views))
	for _, view := range views {
		states = append(states, State{EndpointID: view.EndpointID, DisplayName: view.DisplayName, Statistics: view.Statistics, AdapterKey: view.AdapterKey, Config: view.Config.Clone(), DesiredState: view.DesiredState, ObservedState: view.ObservedState, OperationState: view.OperationState, DesiredVersion: view.DesiredVersion, ProviderID: view.ProviderID, Generation: view.Generation, OperationID: view.OperationID, CorrelationID: view.CorrelationID, Version: view.Version})
	}
	return states
}
