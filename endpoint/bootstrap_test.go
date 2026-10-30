package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
)

func TestBootstrapRegistersDescriptorAndReconcilesReplayState(t *testing.T) {
	id := adapterapi.EndpointID("bootstrap-enabled")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	source := &lifecycleStartupSource{states: []State{validFakeState(t, id, key, DesiredStateEnabled, 1, 2)}}
	bootstrap, err := NewBootstrap(&lifecycleCloseStore{}, source, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bootstrap.Registry.Lookup(context.Background(), key); !ok {
		t.Fatal("bootstrap did not register descriptor")
	}
	result, err := bootstrap.Startup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Reconcile.Reconciled != 1 || descriptor.RuntimeCount() != 1 {
		t.Fatalf("startup result=%+v runtime count=%d", result.Reconcile, descriptor.RuntimeCount())
	}
	if _, err := bootstrap.Lifecycle.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if descriptor.RuntimeCount() != 1 || bootstrap.Supervisor.WorkerCount() != 1 {
		t.Fatalf("reconcile duplicated owner: runtimes=%d workers=%d", descriptor.RuntimeCount(), bootstrap.Supervisor.WorkerCount())
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	runtime.allowStopNow()
	if err := bootstrap.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapPassesResourceContextToRuntime(t *testing.T) {
	id := adapterapi.EndpointID("bootstrap-resource-context")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	source := &lifecycleStartupSource{states: []State{validFakeState(t, id, key, DesiredStateEnabled, 1, 2)}}
	bootstrap, err := NewBootstrap(&lifecycleCloseStore{}, source, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.SetResourceRoot("data/default"); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.SetResourceAccessToken("asset-token"); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.SetResourceServeAddress("0.0.0.0:3049"); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	if runtime.init.ResourceRoot != "data/default" ||
		runtime.init.ResourceAccessToken != "asset-token" ||
		runtime.init.ResourceServeAddress != "0.0.0.0:3049" {
		t.Fatalf("runtime init=%#v", runtime.init)
	}
	runtime.allowStart()
	runtime.allowStopNow()
	if err := bootstrap.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapSkipsDisabledAndDeletedReplayState(t *testing.T) {
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	source := &lifecycleStartupSource{states: []State{
		validFakeState(t, adapterapi.EndpointID("bootstrap-disabled"), key, DesiredStateDisabled, 1, 2),
		validFakeState(t, adapterapi.EndpointID("bootstrap-removing"), key, DesiredStateRemoving, 1, 2),
		validFakeState(t, adapterapi.EndpointID("bootstrap-deleted"), key, DesiredStateDeleted, 1, 2),
	}}
	bootstrap, err := NewBootstrap(&lifecycleCloseStore{}, source, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bootstrap.Startup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Reconcile.Skipped != 3 || descriptor.RuntimeCount() != 0 || bootstrap.Supervisor.WorkerCount() != 0 {
		t.Fatalf("inactive replay states started: result=%+v runtimes=%d workers=%d", result.Reconcile, descriptor.RuntimeCount(), bootstrap.Supervisor.WorkerCount())
	}
	if err := bootstrap.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapInstallsIdentityObservationSink(t *testing.T) {
	bootstrap := &Bootstrap{Supervisor: NewSupervisor(nil)}
	sink := IdentityObservationSinkFunc(func(context.Context, FencedIdentityObservation) error { return nil })
	if err := bootstrap.SetIdentityObservationSink(sink); err != nil {
		t.Fatalf("set identity sink: %v", err)
	}
	if bootstrap.IdentityObservationSink() == nil {
		t.Fatal("identity sink was not installed")
	}
	if err := bootstrap.SetIdentityObservationSink(nil); !errors.Is(err, ErrSupervisorNoIdentitySink) {
		t.Fatalf("nil identity sink error = %v", err)
	}
}

func TestLifecycleSinkIgnoresStaleDesiredVersionWithinGeneration(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}}, &lifecycleCodec{})
	id := adapterapi.EndpointID("bootstrap-stale-version")
	if _, err := service.Create(ctx, Command{CommandID: "create", CorrelationID: "create", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
		t.Fatal(err)
	}
	enabled, err := service.Enable(ctx, Command{CommandID: "enable", CorrelationID: "enable", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(ctx, Command{
		CommandID: "enable-complete", CorrelationID: "enable-complete", EndpointID: id,
		OperationID: enabled.State.OperationID, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion,
		ObservedState: adapterapi.ObservedStateConnected, CompletionState: OperationStateSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	disabled, err := service.Disable(ctx, Command{CommandID: "disable", CorrelationID: "disable", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	sink := &serviceLifecycleSink{service: service}
	if err := sink.RecordLifecycle(ctx, LifecycleUpdate{
		EndpointID: id, Generation: disabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion,
		ObservedState: adapterapi.ObservedStateConnected,
	}); err != nil {
		t.Fatal(err)
	}
	current, err := service.Repository.Load(ctx, id)
	if err != nil {
		t.Fatalf("load state after stale terminal: %v", err)
	}
	if current.Version != disabled.State.Version || current.DesiredState != DesiredStateDisabled || current.OperationState != OperationStatePending {
		t.Fatalf("stale terminal changed current operation: %#v", current)
	}
	if err := sink.RecordLifecycle(ctx, LifecycleUpdate{
		EndpointID: id, Generation: disabled.State.Generation, DesiredVersion: disabled.State.DesiredVersion,
		ObservedState: adapterapi.ObservedStateStopped,
	}); err != nil {
		t.Fatal(err)
	}
	current, err = service.Repository.Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if current.OperationState != OperationStateSucceeded || current.ObservedState != adapterapi.ObservedStateStopped {
		t.Fatalf("matching terminal did not complete operation: %#v", current)
	}
}
func TestLifecycleSinkPersistsRepeatedObservedStateTransition(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}}, &lifecycleCodec{})
	id := adapterapi.EndpointID("bootstrap-repeated-observation")
	if _, err := service.Create(ctx, Command{CommandID: "create", CorrelationID: "create", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
		t.Fatal(err)
	}
	enabled, err := service.Enable(ctx, Command{CommandID: "enable", CorrelationID: "enable", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	sink := &serviceLifecycleSink{service: service}
	updates := []LifecycleUpdate{
		{EndpointID: id, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion, RuntimeID: "runtime-1", ObservedState: adapterapi.ObservedStateConnected},
		{EndpointID: id, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion, RuntimeID: "runtime-1", ObservedState: adapterapi.ObservedStateStopped},
		{EndpointID: id, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion, RuntimeID: "runtime-2", ObservedState: adapterapi.ObservedStateConnected},
	}
	for _, update := range updates {
		if err := sink.RecordLifecycle(ctx, update); err != nil {
			t.Fatal(err)
		}
	}
	current, err := service.Repository.Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if current.ObservedState != adapterapi.ObservedStateConnected {
		t.Fatalf("repeated transition observed=%d, want connected", current.ObservedState)
	}
}

// A runtime that reconnects on its own reports the same states again; each
// change must reach the aggregate, while a redelivered publication must not.
func TestLifecycleSinkPersistsReconnectionWithinOneRuntime(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}}, &lifecycleCodec{})
	id := adapterapi.EndpointID("bootstrap-runtime-reconnection")
	if _, err := service.Create(ctx, Command{CommandID: "create", CorrelationID: "create", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
		t.Fatal(err)
	}
	enabled, err := service.Enable(ctx, Command{CommandID: "enable", CorrelationID: "enable", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	sink := &serviceLifecycleSink{service: service}
	observe := func(state adapterapi.ObservedState) State {
		t.Helper()
		update := LifecycleUpdate{EndpointID: id, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion, RuntimeID: "runtime-1", ObservedState: state}
		if err := sink.RecordLifecycle(ctx, update); err != nil {
			t.Fatal(err)
		}
		current, err := service.Repository.Load(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return current
	}

	// The protocol end is not up when the runtime starts.
	if current := observe(adapterapi.ObservedStateFailed); current.OperationState != OperationStateFailed {
		t.Fatalf("startup failure state = %#v", current)
	}
	failedVersion := observe(adapterapi.ObservedStateFailed).Version
	if current := observe(adapterapi.ObservedStateFailed); current.Version != failedVersion {
		t.Fatalf("a repeated failure appended events: version %d, want %d", current.Version, failedVersion)
	}
	for round := range 3 {
		if current := observe(adapterapi.ObservedStateConnected); current.ObservedState != adapterapi.ObservedStateConnected || current.OperationState != OperationStateSucceeded {
			t.Fatalf("round %d reconnection = observed %d operation %s", round, current.ObservedState, current.OperationState)
		}
		connectedVersion := observe(adapterapi.ObservedStateConnected).Version
		if current := observe(adapterapi.ObservedStateConnected); current.Version != connectedVersion {
			t.Fatalf("round %d: a repeated connection appended events", round)
		}
		if current := observe(adapterapi.ObservedStateFailed); current.ObservedState != adapterapi.ObservedStateFailed {
			t.Fatalf("round %d disconnection = observed %d", round, current.ObservedState)
		}
	}
}

func TestIdentityObservationSinkPersistsEveryProviderBehindFence(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("identity-sink")
	created, err := service.Create(ctx, Command{
		CommandID: "identity-sink-create", CorrelationID: "identity-sink-create", EndpointID: id, AdapterKey: key,
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := NewIdentityObservationSink(service)
	if err := sink.HandleIdentityObservation(ctx, FencedIdentityObservation{
		EndpointID: id, Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion,
		Observation: adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: "telegram:bot-1"},
	}); err != nil {
		t.Fatal(err)
	}
	view, err := service.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if view.ProviderID != "telegram:bot-1" {
		t.Fatalf("identity view = %#v", view)
	}
	if err := sink.HandleIdentityObservation(ctx, FencedIdentityObservation{
		EndpointID: id, Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion - 1,
		Observation: adapterapi.LifecycleObservation{Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected, ProviderID: "telegram:bot-2"},
	}); err != nil {
		t.Fatal(err)
	}
	view, err = service.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if view.ProviderID != "telegram:bot-1" {
		t.Fatalf("stale identity changed view = %#v", view)
	}
}

func TestIdentityObservationSinkPersistsRuntimeNickname(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("identity-display-name")
	created, err := service.Create(ctx, Command{
		CommandID: "identity-display-name-create", CorrelationID: "identity-display-name-create", EndpointID: id, AdapterKey: key,
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := NewIdentityObservationSink(service)
	if err := sink.HandleIdentityObservation(ctx, FencedIdentityObservation{
		EndpointID: id, Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion,
		Observation: adapterapi.LifecycleObservation{
			Kind: adapterapi.LifecycleObservationIdentity, State: adapterapi.ObservedStateConnected,
			ProviderID: "QQ:3824044251", Code: "identity", Detail: "Runtime Dice Bot",
		},
	}); err != nil {
		t.Fatal(err)
	}
	view, err := service.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if view.ProviderID != "QQ:3824044251" || view.DisplayName != "Runtime Dice Bot" {
		t.Fatalf("endpoint identity view = %#v", view)
	}
}
