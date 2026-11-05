package managerstate

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"Scardice-core/eventstore"
)

func TestRepositoryPersistsPublicConfigAndAuth(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(root, "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithProjection(Projection()))
	if err = store.SetReadiness(ctx, eventstore.Readiness{Mode: "fresh", SchemaVersion: 2, DatabaseIdentity: "manager-state-test"}); err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	repository, err := NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	wantPublic := PublicConfig{ServeAddress: "127.0.0.1:3211", TrayTooltip: "legacy", HelpDocEngineType: 2, DiceRandomMode: "crypto", AutoBackupEnable: true, AutoBackupTime: "@every 1h", AutoBackupSelection: 7, BackupClean: BackupCleanConfig{Strategy: 1, KeepCount: 3, KeepDuration: 4, Trigger: 2, Cron: "@daily"}, ServiceName: "scardice-test", ConfigVersion: 9914, DiceDataDirs: map[string]string{"default": "./data/default"}}
	wantAuth := Auth{UIPasswordSalt: "salt-value", UIPasswordHash: "hash-value", AccessTokens: []string{"token-b", "token-a"}}
	state, err := repository.Save(ctx, State{}, wantPublic, wantAuth)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 || state.AuthSecretVersion != 1 {
		t.Fatalf("saved state = %#v", state)
	}
	projected, err := ReadProjected(ctx, store)
	if err != nil || !reflect.DeepEqual(projected.Public, wantPublic) {
		t.Fatalf("projected=%#v err=%v", projected, err)
	}
	loaded, auth, err := repository.Load(ctx)
	if err != nil || !reflect.DeepEqual(loaded, projected) || auth.UIPasswordSalt != wantAuth.UIPasswordSalt || auth.UIPasswordHash != wantAuth.UIPasswordHash || len(auth.AccessTokens) != 2 || auth.AccessTokens[0] != "token-a" || auth.AccessTokens[1] != "token-b" {
		t.Fatalf("loaded=%#v auth=%#v err=%v", loaded, auth, err)
	}
}
