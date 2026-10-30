package managerstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"Scardice-core/eventstore"
)

func TestRepositoryPersistsPublicConfigAndEncryptedAuth(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	keysDir := filepath.Join(root, "keys")
	rootsDir := filepath.Join(keysDir, "roots")
	if err := os.MkdirAll(rootsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(keysDir, "index.key")
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
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys), eventstore.WithProjection(Projection()))
	if err = store.SetReadiness(ctx, eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "manager-state-test", IndexRootID: filepath.Base(indexPath), EncryptionRootIDs: []string{"root-v1"}}); err != nil {
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
	var rows [][]byte
	if err = database.GORM().Table("adapter_secrets").Pluck("ciphertext", &rows).Error; err != nil {
		t.Fatal(err)
	}
	for _, ciphertext := range rows {
		if bytes.Contains(ciphertext, []byte("hash-value")) || bytes.Contains(ciphertext, []byte("token-a")) {
			t.Fatal("plaintext auth material leaked into ciphertext")
		}
	}
}
