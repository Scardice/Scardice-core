package endpoint

import (
	"context"
	"testing"

	"Scardice-core/adapterapi"
)

func TestBootstrapRegistersDescriptorAndReconcilesReplayState(t *testing.T) {
	id := adapterapi.EndpointID("bootstrap-enabled")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	source := &task5StartupSource{states: []State{validFakeState(t, id, key, DesiredStateEnabled, 1, 2)}}
	bootstrap, err := NewBootstrap(&task5CloseStore{}, source, descriptor)
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

func TestBootstrapSkipsDisabledAndDeletedReplayState(t *testing.T) {
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	source := &task5StartupSource{states: []State{
		validFakeState(t, adapterapi.EndpointID("bootstrap-disabled"), key, DesiredStateDisabled, 1, 2),
		validFakeState(t, adapterapi.EndpointID("bootstrap-removing"), key, DesiredStateRemoving, 1, 2),
		validFakeState(t, adapterapi.EndpointID("bootstrap-deleted"), key, DesiredStateDeleted, 1, 2),
	}}
	bootstrap, err := NewBootstrap(&task5CloseStore{}, source, descriptor)
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
