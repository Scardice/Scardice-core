package dice

import (
	"context"
	"path/filepath"
	"testing"

	"Scardice-core/core/configstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/eventstore"
)

func TestEventSourcedManagerRestoresAndPersistsAuth(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(root, "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithProjection(managerstate.Projection()), eventstore.WithProjection(configstate.ConfigProjection()))
	if err = store.SetReadiness(ctx, eventstore.Readiness{Mode: "fresh", SchemaVersion: 2, DatabaseIdentity: "manager-runtime"}); err != nil {
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
	if err = manager.prepareEventSourcedState(ctx, observer); err != nil {
		t.Fatal(err)
	}
	if len(initializationEvents) != 2 ||
		initializationEvents[0].Resource != eventSourcedInitializationResourceManagerConfig ||
		initializationEvents[1].Resource != eventSourcedInitializationResourceDiceConfig {
		t.Fatalf("initialization events = %#v", initializationEvents)
	}
	runtime := manager.Dice[0]
	runtime.Parent = manager
	if err = runtime.DurableMutateConfig(ctx, "test-endpoint", "endpoint-1", func(config *Config) error {
		config.EndpointIDs = []string{"endpoint-1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	projectedConfig, err := configstate.ReadProjected(ctx, store, "default")
	if err != nil || len(projectedConfig.PublicDice.EndpointIDs) != 1 || projectedConfig.PublicDice.EndpointIDs[0] != "endpoint-1" {
		t.Fatalf("projected config = %#v, err=%v", projectedConfig, err)
	}
	if err = manager.DurableMutateManagerConfig(ctx, "test-public", "127.0.0.1:4321", func(public *managerstate.PublicConfig) error {
		public.ServeAddress = "127.0.0.1:4321"
		public.DiceDataDirs["default"] = "./custom/default"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	passwordHash := "new-hash"
	if err = runtime.DurableCommitConfigRequest(ctx, DurableConfigRequest{Manager: &DurableManagerConfigPatch{
		UIPasswordHash: &passwordHash,
	}}); err != nil {
		t.Fatal(err)
	}
	authenticated, authErr := manager.DurableAuthenticateAndStoreAccessToken(ctx, passwordHash, "new-token")
	if authErr != nil || !authenticated {
		t.Fatalf("store access token: authenticated=%v err=%v", authenticated, authErr)
	}

	repository, err := managerstate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	loaded, loadedAuth, err := repository.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 4 || loaded.Public.ServeAddress != "127.0.0.1:4321" ||
		loaded.Public.DiceDataDirs["default"] != "./custom/default" ||
		loadedAuth.UIPasswordHash != "new-hash" ||
		len(loadedAuth.AccessTokens) != 1 || loadedAuth.AccessTokens[0] != "new-token" {
		t.Fatalf("loaded=%#v auth=%#v", loaded, loadedAuth)
	}
}

func TestManagerRuntimePublicationRejectsOlderCandidate(t *testing.T) {
	manager := &DiceManager{}
	newer := managerstate.State{
		Version: 2,
		Public: managerstate.PublicConfig{
			ServeAddress: "newer",
			DiceDataDirs: map[string]string{"default": "./newer"},
		},
	}
	newerAuth := managerstate.Auth{UIPasswordHash: "newer-hash", AccessTokens: []string{"newer-token"}}
	if !manager.publishManagerRuntime(newer, newerAuth) {
		t.Fatal("new manager candidate was not published")
	}
	older := managerstate.State{
		Version: 1,
		Public: managerstate.PublicConfig{
			ServeAddress: "older",
			DiceDataDirs: map[string]string{"default": "./older"},
		},
	}
	if manager.publishManagerRuntime(older, managerstate.Auth{UIPasswordHash: "older-hash"}) {
		t.Fatal("older manager candidate replaced the current runtime state")
	}
	public, passwordConfigured := manager.ManagerPublicConfigSnapshot()
	if public.ServeAddress != "newer" || public.DiceDataDirs["default"] != "./newer" ||
		!passwordConfigured || manager.UIPasswordHash != "newer-hash" || !manager.AccessTokens.Exists("newer-token") {
		t.Fatalf("published manager runtime = %#v password=%v hash=%q", public, passwordConfigured, manager.UIPasswordHash)
	}
	public.DiceDataDirs["default"] = "./mutated"
	again, _ := manager.ManagerPublicConfigSnapshot()
	if again.DiceDataDirs["default"] != "./newer" {
		t.Fatalf("manager snapshot leaked mutable data dirs: %#v", again.DiceDataDirs)
	}
}
