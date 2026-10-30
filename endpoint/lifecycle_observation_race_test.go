package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type lifecycleLoadBoundaryStore struct {
	*eventstore.GORMStore
	afterLoad func()
}

func (s *lifecycleLoadBoundaryStore) Load(ctx context.Context, stream eventstore.StreamID, afterVersion uint64) ([]eventstore.Envelope, error) {
	envelopes, err := s.GORMStore.Load(ctx, stream, afterVersion)
	if err == nil && s.afterLoad != nil {
		after := s.afterLoad
		s.afterLoad = nil
		after()
	}
	return envelopes, err
}

func TestLifecycleSinkFencesObservationAcrossConcurrentCommand(t *testing.T) {
	for _, scenario := range []string{"generation", "desired_version", "same_fence_invalid_observation"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			store, db := serviceStore(t)
			defer db.Close()
			key := adapterapi.AdapterKey("fake")
			service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}}, &lifecycleCodec{})
			id := adapterapi.EndpointID("lifecycle-read-boundary")
			if _, err := service.Create(ctx, Command{CommandID: "create", CorrelationID: "create", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
				t.Fatal(err)
			}
			enabled, err := service.Enable(ctx, Command{CommandID: "enable", CorrelationID: "enable", EndpointID: id})
			if err != nil {
				t.Fatal(err)
			}
			sink := &serviceLifecycleSink{service: service}
			if err := sink.RecordLifecycle(ctx, LifecycleUpdate{EndpointID: id, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion, ObservedState: adapterapi.ObservedStateConnected}); err != nil {
				t.Fatal(err)
			}
			before, err := service.Repository.Load(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			expected := before
			observed := adapterapi.ObservedStateStopped
			completionObserved := adapterapi.ObservedStateConnected
			if scenario == "same_fence_invalid_observation" {
				observed = adapterapi.ObservedState(255)
			} else {
				kind := CommandRelogin
				if scenario == "desired_version" {
					kind = CommandDisable
					completionObserved = adapterapi.ObservedStateStopped
				}
				service.Repository.Store = &lifecycleLoadBoundaryStore{GORMStore: store, afterLoad: func() {
					next, err := service.Execute(ctx, Command{Kind: kind, CommandID: "advance", CorrelationID: "advance", EndpointID: id})
					if err != nil {
						t.Fatal(err)
					}
					expected = next.State
				}}
			}
			err = sink.RecordLifecycle(ctx, LifecycleUpdate{EndpointID: id, Generation: before.Generation, DesiredVersion: before.DesiredVersion, ObservedState: observed})
			if scenario == "same_fence_invalid_observation" {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("invalid current-fence observation error=%v", err)
				}
			} else if err != nil {
				t.Fatalf("obsolete observation poisoned handoff: %v", err)
			}
			current, err := service.Repository.Load(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if current.Version != expected.Version || current.OperationID != expected.OperationID || current.OperationState != expected.OperationState || current.Generation != expected.Generation || current.DesiredVersion != expected.DesiredVersion {
				t.Fatalf("old observation changed current operation: got=%+v want=%+v", current, expected)
			}
			if scenario != "same_fence_invalid_observation" {
				if err := sink.RecordLifecycle(ctx, LifecycleUpdate{EndpointID: id, Generation: current.Generation, DesiredVersion: current.DesiredVersion, ObservedState: completionObserved}); err != nil {
					t.Fatal(err)
				}
				view, err := service.Get(ctx, id)
				if err != nil || view.OperationState != OperationStateSucceeded || view.ObservedState != completionObserved || view.OperationID != expected.OperationID {
					t.Fatalf("new operation did not complete under its own fence: view=%+v err=%v", view, err)
				}
			}
		})
	}
}

type lifecycleTerminalBoundarySink struct {
	LifecycleSink
	connected   chan struct{}
	stopped     chan struct{}
	release     chan struct{}
	connectOnce sync.Once
	stopOnce    sync.Once
}

func (s *lifecycleTerminalBoundarySink) RecordLifecycle(ctx context.Context, update LifecycleUpdate) error {
	if err := s.LifecycleSink.RecordLifecycle(ctx, update); err != nil {
		return err
	}
	if update.ObservedState == adapterapi.ObservedStateConnected {
		s.connectOnce.Do(func() { close(s.connected) })
	}
	if update.ObservedState == adapterapi.ObservedStateStopped {
		s.stopOnce.Do(func() { close(s.stopped) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestReloginDuringTerminalPublicationRemainsPendingUntilConnected(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	bootstrap, err := NewBootstrap(store, nil, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	boundary := &lifecycleTerminalBoundarySink{LifecycleSink: bootstrap.Supervisor.lifecycle, connected: make(chan struct{}), stopped: make(chan struct{}), release: make(chan struct{})}
	bootstrap.Supervisor.lifecycle = boundary
	defer func() {
		closeOnce(boundary.release)
		for index := range descriptor.RuntimeCount() {
			descriptor.Runtime(index).allowStart()
			descriptor.Runtime(index).allowStopNow()
		}
		if err := bootstrap.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	id := adapterapi.EndpointID("relogin-terminal-boundary")
	if _, err := bootstrap.Execute(ctx, Command{Kind: CommandCreate, CommandID: "create", CorrelationID: "create", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Execute(ctx, Command{Kind: CommandEnable, CommandID: "enable", CorrelationID: "enable", EndpointID: id}); err != nil {
		t.Fatal(err)
	}
	first := descriptor.Runtime(0)
	first.allowStart()
	first.allowStopNow()
	select {
	case <-boundary.connected:
	case <-time.After(5 * time.Second):
		t.Fatal("first runtime did not connect")
	}
	worker := bootstrap.Supervisor.current(id)
	closeOnce(first.exit)
	select {
	case <-boundary.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("terminal observation was not committed")
	}
	relogin := make(chan error, 1)
	go func() {
		_, err := bootstrap.Execute(ctx, Command{Kind: CommandRelogin, CommandID: "relogin", CorrelationID: "relogin", EndpointID: id})
		relogin <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		worker.mu.Lock()
		pending := worker.pending != nil
		worker.mu.Unlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relogin did not reach old-worker cleanup")
		}
		time.Sleep(time.Millisecond)
	}
	closeOnce(boundary.release)
	select {
	case err := <-relogin:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relogin did not finish cleanup")
	}
	view, err := bootstrap.Service.Get(ctx, id)
	if err != nil || view.OperationState != OperationStatePending {
		t.Fatalf("old cleanup completed a runtime that has not connected: view=%+v err=%v", view, err)
	}
	if descriptor.RuntimeCount() != 2 {
		t.Fatalf("replacement runtime count=%d", descriptor.RuntimeCount())
	}
	descriptor.Runtime(1).allowStart()
	deadline = time.Now().Add(5 * time.Second)
	for {
		connected, err := bootstrap.Service.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if connected.OperationID == view.OperationID && connected.OperationState == OperationStateSucceeded && connected.ObservedState == adapterapi.ObservedStateConnected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement did not complete after its own connection")
		}
		time.Sleep(time.Millisecond)
	}
}
