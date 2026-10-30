package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type lifecycleStartupSource struct {
	mu     sync.Mutex
	states []State
	ready  error
}

func (s *lifecycleStartupSource) ValidateReadiness(context.Context) error { return s.ready }
func (s *lifecycleStartupSource) ListEndpointStates(context.Context) ([]State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]State(nil), s.states...), nil
}

type lifecycleMetadataStartupSource struct {
	lifecycleStartupSource
	metadataCalls   int
	validationCalls int
}

func (s *lifecycleMetadataStartupSource) GetReadinessMetadata(context.Context) (eventstore.Readiness, error) {
	s.metadataCalls++
	return eventstore.Readiness{Mode: "import"}, nil
}

func (s *lifecycleMetadataStartupSource) ValidateReadiness(context.Context) error {
	s.validationCalls++
	return errors.New("exhaustive validation must be opt-in")
}

type lifecycleTestRebuilder struct {
	called  chan struct{}
	release chan struct{}
}

func (r *lifecycleTestRebuilder) Rebuild(context.Context, eventstore.RebuildRequest) (eventstore.RebuildResult, error) {
	close(r.called)
	<-r.release
	return eventstore.RebuildResult{GenerationID: "startup-rebuild"}, nil
}

func TestStartupReplayBuildsProjectionBeforeAnyRuntime(t *testing.T) {
	id := adapterapi.EndpointID("startup-enabled")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	source := &lifecycleStartupSource{states: []State{
		validFakeState(t, id, key, DesiredStateEnabled, 1, 2),
		validFakeState(t, adapterapi.EndpointID("startup-disabled"), key, DesiredStateDisabled, 1, 2),
		validFakeState(t, adapterapi.EndpointID("startup-removing"), key, DesiredStateRemoving, 1, 2),
		validFakeState(t, adapterapi.EndpointID("startup-deleted"), key, DesiredStateDeleted, 1, 2),
	}}
	rebuilder := &lifecycleTestRebuilder{called: make(chan struct{}), release: make(chan struct{})}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	lifecycle := NewEndpointLifecycle(sup, source, rebuilder)
	started := make(chan error, 1)
	go func() { _, err := lifecycle.Startup(context.Background(), WithProjectionRebuild(true)); started <- err }()
	select {
	case <-rebuilder.called:
	case <-time.After(time.Second):
		t.Fatal("startup did not rebuild projection")
	}
	if got := descriptor.RuntimeCount(); got != 0 {
		t.Fatalf("runtime constructed during projection replay: %d", got)
	}
	close(rebuilder.release)
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup did not reconcile")
	}
	if got := descriptor.RuntimeCount(); got != 1 {
		t.Fatalf("runtime count after reconcile = %d, want 1", got)
	}
	if _, err := lifecycle.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := descriptor.RuntimeCount(); got != 1 {
		t.Fatalf("reconcile-all duplicated runtime: %d", got)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	runtime.allowStopNow()
	if err := lifecycle.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStartupRequiresStoreReadinessBeforeReplay(t *testing.T) {
	id := adapterapi.EndpointID("startup-not-ready")
	key := adapterapi.AdapterKey("fake")
	source := &lifecycleStartupSource{ready: errors.New("quarantined"), states: []State{validFakeState(t, id, key, DesiredStateEnabled, 1, 2)}}
	descriptor := &fakeDescriptor{key: key}
	lifecycle := NewEndpointLifecycle(NewSupervisor(fakeDescriptorRegistry{key: descriptor}), source)
	if _, err := lifecycle.Startup(context.Background()); !errors.Is(err, ErrEndpointNotReady) {
		t.Fatalf("startup readiness error = %v", err)
	}
	if got := descriptor.RuntimeCount(); got != 0 {
		t.Fatalf("runtime constructed before readiness: %d", got)
	}
}

func TestStartupUsesLightweightReadinessMetadataByDefault(t *testing.T) {
	source := &lifecycleMetadataStartupSource{}
	lifecycle := NewEndpointLifecycle(NewSupervisor(nil), source)
	if _, err := lifecycle.Startup(context.Background()); err != nil {
		t.Fatalf("startup with valid metadata: %v", err)
	}
	if source.metadataCalls != 1 || source.validationCalls != 0 {
		t.Fatalf("readiness calls: metadata=%d exhaustive=%d", source.metadataCalls, source.validationCalls)
	}
}

func TestShutdownRejectsReconcileAndRetainsAmbiguousOwner(t *testing.T) {
	id := adapterapi.EndpointID("shutdown-ambiguous-owner")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	sink := &fakeLifecycleSink{}
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(sink), WithStopTimeout(10*time.Millisecond))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not start")
	}
	if err := sup.Shutdown(context.Background()); err != nil && !errors.Is(err, ErrSupervisorAmbiguous) {
		t.Fatal(err)
	}
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); !errors.Is(err, ErrSupervisorClosed) {
		t.Fatalf("post-shutdown reconcile error = %v", err)
	}
	inspection, ok := sup.Worker(id)
	if !ok || !inspection.Ambiguous {
		t.Fatalf("shutdown lost ambiguous worker: %#v, present=%v", inspection, ok)
	}
}

type lifecycleCloseStore struct {
	lifecycleStartupSource
	mu     sync.Mutex
	closes int
}

func (s *lifecycleCloseStore) Commit(context.Context, eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}
func (s *lifecycleCloseStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, eventstore.ErrNotFound
}
func (s *lifecycleCloseStore) Close() error {
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	return nil
}

func TestLifecycleConcurrentShutdownClosesStoreOnce(t *testing.T) {
	source := &lifecycleCloseStore{}
	lifecycle := NewEndpointLifecycle(NewSupervisor(nil), source)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- lifecycle.Shutdown(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	source.mu.Lock()
	closes := source.closes
	source.mu.Unlock()
	if closes != 1 {
		t.Fatalf("store close count = %d, want 1", closes)
	}
}

type blockingLifecycleStore struct {
	lifecycleCloseStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingLifecycleStore) ValidateReadiness(context.Context) error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return nil
}

func TestLifecycleShutdownWaitsForStartupAndRejectsAfterClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	source := &blockingLifecycleStore{lifecycleCloseStore: lifecycleCloseStore{}, entered: entered, release: release}
	lifecycle := NewEndpointLifecycle(NewSupervisor(nil), source)
	startupDone := make(chan error, 1)
	go func() {
		_, err := lifecycle.Startup(context.Background())
		startupDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("startup did not enter readiness")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := lifecycle.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown while startup is active = %v", err)
	}
	source.mu.Lock()
	closes := source.closes
	source.mu.Unlock()
	if closes != 0 {
		t.Fatalf("store closed while startup remained active: %d", closes)
	}
	if _, err := lifecycle.Startup(context.Background()); !errors.Is(err, ErrEndpointLifecycleClosed) {
		t.Fatalf("startup admitted after shutdown timeout: %v", err)
	}
	if _, err := lifecycle.ReconcileAll(context.Background()); !errors.Is(err, ErrEndpointLifecycleClosed) {
		t.Fatalf("reconcile admitted after shutdown timeout: %v", err)
	}
	close(release)
	select {
	case err := <-startupDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup did not finish after release")
	}
	if err := lifecycle.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Startup(context.Background()); !errors.Is(err, ErrEndpointLifecycleClosed) {
		t.Fatalf("startup after shutdown = %v", err)
	}
	if _, err := lifecycle.ReconcileAll(context.Background()); !errors.Is(err, ErrEndpointLifecycleClosed) {
		t.Fatalf("reconcile after shutdown = %v", err)
	}
}
