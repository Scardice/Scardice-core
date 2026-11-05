package endpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func TestEndpointBaselinePreservesCurrentStateWithoutTransientOperationsAcrossReopen(t *testing.T) {
	for _, desired := range []DesiredState{DesiredStateDisabled, DesiredStateEnabled, DesiredStateRemoving, DesiredStateDeleted} {
		t.Run(string(desired), func(t *testing.T) {
			ctx := context.Background()
			config := eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "baseline.db"), DatabaseIdentity: "endpoint-baseline"}
			db, err := eventstore.OpenDatabase(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if db != nil {
					_ = db.Close()
				}
			})
			store := eventstore.NewStore(db)
			service := NewService(store, serviceRegistry{})
			if service.InitError != nil {
				t.Fatal(service.InitError)
			}
			view := EndpointView{
				EndpointID: "imported-endpoint", AdapterKey: "fake", DisplayName: "Imported Bot",
				Statistics:   Statistics{GroupCount: 4, CommandCount: 17, LastCommandAt: 123, OnlineSeconds: 456},
				Config:       adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"channel":"preserved"}`), SecretRefs: []adapterapi.SecretRef{{Ref: "vault:imported-token", Version: 3}}},
				DesiredState: desired, ProviderID: "QQ:9001", ObservedState: adapterapi.ObservedStateConnected,
				OperationState: OperationStateAmbiguous, Generation: 99, DesiredVersion: 73,
				OperationID: "discarded-operation", CorrelationID: "discarded-correlation", Version: 88,
			}
			event, err := NewBaselineImported(view, "baseline-command", "baseline-correlation")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = service.Repository.Commit(ctx, State{}, Decision{Events: []Event{event}}); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = eventstore.OpenDatabase(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			store = eventstore.NewStore(db)
			service = NewService(store, serviceRegistry{})
			state, err := service.Repository.Load(ctx, view.EndpointID)
			if err != nil {
				t.Fatal(err)
			}
			projected, err := service.Get(ctx, view.EndpointID)
			if err != nil {
				t.Fatal(err)
			}
			if state.DesiredState != desired || projected.DesiredState != desired || state.ProviderID != view.ProviderID || projected.ProviderID != view.ProviderID ||
				state.DisplayName != view.DisplayName || projected.DisplayName != view.DisplayName || state.Statistics != view.Statistics || projected.Statistics != view.Statistics ||
				!bytes.Equal(state.Config.Canonical, view.Config.Canonical) || !reflect.DeepEqual(state.Config.SecretRefs, view.Config.SecretRefs) ||
				!bytes.Equal(projected.Config.Canonical, view.Config.Canonical) || !reflect.DeepEqual(projected.Config.SecretRefs, view.Config.SecretRefs) {
				t.Fatalf("baseline lost durable state: state=%#v projection=%#v", state, projected)
			}
			if state.Version != 1 || state.DesiredVersion != 1 || state.Generation != 0 || state.ObservedState != adapterapi.ObservedStateStopped ||
				state.OperationState != OperationStateIdle || state.OperationID != "" || state.PendingEffectID != "" || state.PendingCommandID != "" ||
				projected.Generation != 0 || projected.OperationID != "" || projected.OperationState != OperationStateIdle {
				t.Fatalf("baseline retained transient state: state=%#v projection=%#v", state, projected)
			}
			for _, table := range []string{"operations", "outbox_effects", "operation_artifacts"} {
				var count int64
				if err := db.GORM().Table(table).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("baseline transient table %s: rows=%d err=%v", table, count, err)
				}
			}
			rows, err := store.ListProjectionRows(ctx, OperationProjectionName)
			if err != nil || len(rows) != 0 {
				t.Fatalf("baseline created operation projections: rows=%#v err=%v", rows, err)
			}
		})
	}
}

func TestEnabledEndpointBaselineCreatesFreshLifecycleFenceBeforeRuntime(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	t.Cleanup(func() { _ = db.Close() })
	descriptor := &fakeDescriptor{key: "fake"}
	bootstrap, err := NewBootstrap(store, nil, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewBaselineImported(EndpointView{
		EndpointID: "enabled-baseline", AdapterKey: "fake", DesiredState: DesiredStateEnabled,
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"channel":"restored"}`)},
	}, "enabled-baseline-command", "enabled-baseline-correlation")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.Service.Repository.Commit(ctx, State{}, Decision{Events: []Event{event}}); err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	if runtime == nil {
		t.Fatal("enabled baseline did not start a runtime")
	}
	t.Cleanup(func() {
		runtime.allowStart()
		runtime.allowStopNow()
		_ = bootstrap.Shutdown(context.Background())
	})
	state, err := bootstrap.Service.Repository.Load(ctx, "enabled-baseline")
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 1 || runtime.init.Generation != state.Generation || runtime.init.DesiredVersion != state.DesiredVersion ||
		state.OperationState != OperationStatePending || state.OperationID == "" || state.OperationID == event.OperationID {
		t.Fatalf("runtime started without a new durable lifecycle fence: state=%#v init=%#v", state, runtime.init)
	}
	runtime.allowStart()
	deadline := time.Now().Add(3 * time.Second)
	for {
		state, err = bootstrap.Service.Repository.Load(ctx, "enabled-baseline")
		if err != nil {
			t.Fatal(err)
		}
		if state.ObservedState == adapterapi.ObservedStateConnected && state.OperationState == OperationStateSucceeded {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("fresh runtime observation did not persist: %#v", state)
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = bootstrap.Lifecycle.ReconcileAll(ctx); err != nil {
		t.Fatal(err)
	}
	if descriptor.RuntimeCount() != 1 {
		t.Fatal("reconciliation duplicated the imported endpoint runtime")
	}
}

func TestRemovingEndpointBaselineFinishesWithoutResurrectingAnOldOperation(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	t.Cleanup(func() { _ = db.Close() })
	bootstrap, err := NewBootstrap(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bootstrap.Shutdown(context.Background()) })
	event, err := NewBaselineImported(EndpointView{
		EndpointID: "removing-baseline", AdapterKey: "fake", DesiredState: DesiredStateRemoving,
		Config:      adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"channel":"removed"}`)},
		OperationID: "discarded-operation", OperationState: OperationStateAmbiguous, Generation: 29,
	}, "removing-baseline-command", "removing-baseline-correlation")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.Service.Repository.Commit(ctx, State{}, Decision{Events: []Event{event}}); err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := bootstrap.Service.Repository.Load(ctx, "removing-baseline")
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredState != DesiredStateDeleted || state.OperationID == "" || state.OperationID == "discarded-operation" ||
		state.Generation != 0 || bootstrap.Supervisor.WorkerCount() != 0 {
		t.Fatalf("removal baseline resumed stale work or lost deletion intent: %#v", state)
	}
	if _, err := store.GetOperation(ctx, "discarded-operation"); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("old removal operation reappeared: %v", err)
	}
}
