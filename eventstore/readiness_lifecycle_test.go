package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessRejectsUnsupportedSchemaAndWrongIdentity(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "readiness.db"), DatabaseIdentity: "db-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db)
	defer db.Close()
	ctx := context.Background()
	valid := Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "db-1", CompletedAt: time.Unix(1, 0).UTC()}
	for _, mutate := range []func(*Readiness){
		func(r *Readiness) { r.SchemaVersion = 1 },
		func(r *Readiness) { r.SchemaVersion = 3 },
		func(r *Readiness) { r.Mode = "other" },
		func(r *Readiness) { r.CompletedAt = time.Time{} },
	} {
		r := valid
		mutate(&r)
		if err := store.SetReadiness(ctx, r); !errors.Is(err, ErrReadinessInvalid) {
			t.Fatalf("invalid readiness %+v: %v", r, err)
		}
	}
	wrong := valid
	wrong.DatabaseIdentity = "other"
	if err := store.SetReadiness(ctx, wrong); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("identity mismatch=%v", err)
	}
}

func TestReadinessRemainsValidAfterWritesAndReopen(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "empty", EndpointID: "e", AdapterID: "a", Value: []byte{}}); err != nil {
		t.Fatal(err)
	}
	r, err := store.GetReadiness(ctx)
	if err != nil || r.SchemaVersion != 2 || r.Mode != "import" {
		t.Fatalf("readiness=%+v err=%v", r, err)
	}
	reopened := NewStore(db)
	if got, err := reopened.GetReadiness(ctx); err != nil || got != r {
		t.Fatalf("reopened=%+v err=%v", got, err)
	}
}

func TestReadinessDoesNotScanPayloadTables(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	if err := db.GORM().Exec("DROP TABLE plugin_kv").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetReadiness(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReadinessPersistsOnlyTheFourBusinessFields(t *testing.T) {
	_, db := openPlainTestStore(t)
	defer db.Close()
	var columns []struct{ Name string }
	if err := db.GORM().Raw("PRAGMA table_info(store_readiness)").Scan(&columns).Error; err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{"singleton_id": true, "mode": true, "schema_version": true, "database_identity": true, "completed_at": true}
	if len(columns) != len(expected) {
		t.Fatalf("readiness columns=%+v", columns)
	}
	for _, column := range columns {
		if !expected[column.Name] {
			t.Fatalf("unexpected readiness column %q", column.Name)
		}
	}
}
