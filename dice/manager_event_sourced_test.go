package dice

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/core/configstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/eventstore"
)

func TestEventSourcedManagerRestoresAndPersistsAuth(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	rootsDir := filepath.Join(root, "roots")
	if err := os.MkdirAll(rootsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.key")
	if err := os.WriteFile(indexPath, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootsDir, "root-v1.key"), bytes.Repeat([]byte{2}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := eventstore.NewLocalFileKeySource(indexPath, rootsDir)
	keys.CurrentID = "root-v1"
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(root, "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys), eventstore.WithProjection(managerstate.Projection()), eventstore.WithProjection(configstate.ConfigProjection()))
	if err = store.SetReadiness(ctx, eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "manager-runtime", IndexRootID: filepath.Base(indexPath), EncryptionRootIDs: []string{"root-v1"}}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	manager := &DiceManager{}
	var initializationEvents []eventSourcedInitializationEvent
	observer := func(event eventSourcedInitializationEvent) {
		initializationEvents = append(initializationEvents, event)
	}
	if err = manager.InitializeRuntime(); err != nil {
		t.Fatal(err)
	}
	defer manager.Cron.Stop()
	if err = manager.restoreEventSourcedManager(ctx, store, observer); err != nil {
		t.Fatal(err)
	}
	if err = manager.RestoreEventSourcedDice(ctx, store); err != nil {
		t.Fatal(err)
	}
	if len(manager.Dice) != 1 || manager.Dice[0].BaseConfig.Name != "default" || manager.Dice[0].BaseConfig.DataDir != "./data/default" {
		t.Fatalf("fresh Dice shells = %#v", manager.Dice)
	}
	manager.Dice[0].BaseConfig.DataDir = "./custom/default"
	if err = manager.prepareEventSourcedState(ctx, observer); err != nil {
		t.Fatal(err)
	}
	if len(initializationEvents) != 2 ||
		initializationEvents[0].Resource != eventSourcedInitializationResourceManagerConfig ||
		initializationEvents[1].Resource != eventSourcedInitializationResourceDiceConfig {
		t.Fatalf("initialization events = %#v", initializationEvents)
	}
	manager.Dice[0].Config.EndpointIDs = []string{"endpoint-1"}
	manager.Dice[0].Save(false)
	projectedConfig, err := configstate.ReadProjected(ctx, store, "default")
	if err != nil || len(projectedConfig.PublicDice.EndpointIDs) != 1 || projectedConfig.PublicDice.EndpointIDs[0] != "endpoint-1" {
		t.Fatalf("projected config = %#v, err=%v", projectedConfig, err)
	}
	manager.ServeAddress = "127.0.0.1:4321"
	manager.UIPasswordSalt = "new-salt"
	manager.UIPasswordHash = "new-hash"
	manager.AccessTokens.Store("new-token", true)
	manager.Save()

	repository, err := managerstate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	loaded, loadedAuth, err := repository.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 2 || loaded.Public.ServeAddress != "127.0.0.1:4321" ||
		loaded.Public.DiceDataDirs["default"] != "./custom/default" ||
		loadedAuth.UIPasswordSalt != "new-salt" || loadedAuth.UIPasswordHash != "new-hash" ||
		len(loadedAuth.AccessTokens) != 1 || loadedAuth.AccessTokens[0] != "new-token" {
		t.Fatalf("loaded=%#v auth=%#v", loaded, loadedAuth)
	}
}
