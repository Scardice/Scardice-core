package eventstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// openPlainTestStore opens a published import-mode SQLite test database.
func openPlainTestStore(t *testing.T) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task6.db")})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db)
	if err := store.SetReadiness(context.Background(), Readiness{
		Mode: "import", SchemaVersion: supportedReadinessSchemaVersion, DatabaseIdentity: "db-1",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return store, db
}
