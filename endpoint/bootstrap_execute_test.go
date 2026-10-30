package endpoint

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func TestBootstrapExecuteReconcilesEnableEffectOnce(t *testing.T) {
	source := &endpointKeySource{}
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "bootstrap.db"), KeySource: source})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	bootstrap, err := NewBootstrap(store, nil, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	id := adapterapi.EndpointID("bootstrap-command")
	created, err := bootstrap.Execute(context.Background(), Command{Kind: CommandCreate, Type: CommandCreate, CommandID: "create", CorrelationID: "create", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := bootstrap.Execute(context.Background(), Command{Kind: CommandEnable, Type: CommandEnable, CommandID: "enable", CorrelationID: "enable", EndpointID: id, ExpectedVersion: created.State.Version, ExpectedVersionSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled.Effects) != 1 || descriptor.RuntimeCount() != 1 || bootstrap.Supervisor.WorkerCount() != 1 {
		t.Fatalf("enable effects=%d runtimes=%d workers=%d", len(enabled.Effects), descriptor.RuntimeCount(), bootstrap.Supervisor.WorkerCount())
	}
	if _, err := bootstrap.Execute(context.Background(), Command{Kind: CommandEnable, Type: CommandEnable, CommandID: "enable", CorrelationID: "enable", EndpointID: id, ExpectedVersion: created.State.Version, ExpectedVersionSet: true}); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	runtime.allowStopNow()
	if descriptor.RuntimeCount() != 1 || bootstrap.Supervisor.WorkerCount() != 1 {
		t.Fatalf("replayed enable duplicated runtime=%d workers=%d", descriptor.RuntimeCount(), bootstrap.Supervisor.WorkerCount())
	}
	if err := bootstrap.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
