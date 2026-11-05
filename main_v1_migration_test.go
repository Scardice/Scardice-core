package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/eventstore"
)

func TestDetectV1StoreRecognisesSQLiteDSNsBeforeOpening(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("migrate", "eventsourcing", "v1reader", "testdata", "v1", "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events with space.db")
	if err = os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{path, path + "?_pragma=busy_timeout(1000)", "file:" + path, "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(1000)", "file://" + filepath.ToSlash(path), "file://localhost" + filepath.ToSlash(path)} {
		got, err := detectV1Store(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn})
		if err != nil || !got {
			t.Fatalf("DSN %q detected=%v err=%v", dsn, got, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(fixture) {
		t.Fatalf("detection modified original: %v", err)
	}
}

func TestDetectV1StoreFailsClosedForUnknownSQLiteSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`CREATE TABLE domain_events (payload BLOB)`); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = detectV1Store(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: path}); err == nil {
		t.Fatal("unknown schema was allowed to reach AutoMigrate")
	}
}

func TestPlainSQLitePathRejectsMemoryAndForeignAuthorities(t *testing.T) {
	for _, dsn := range []string{"", ":memory:", "file::memory:", "file:shared?mode=memory", "file://foreign/events.db"} {
		if _, ok := plainSQLitePath(eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn}); ok {
			t.Fatalf("unsafe conversion path accepted: %q", dsn)
		}
	}
}

func TestV1KeyPathsDefaultNextToTheDatabaseAndHonourTheOldVariables(t *testing.T) {
	index, roots := v1KeyPaths(filepath.Join("/srv", "data", "endpoint", "events.db"), func(string) string { return "" })
	if index != filepath.Join("/srv", "data", "endpoint", "keys", "index.key") || roots != filepath.Join("/srv", "data", "endpoint", "keys", "roots") {
		t.Fatalf("key paths = %q/%q", index, roots)
	}
	env := func(name string) string {
		return map[string]string{"SCARDICE_ENDPOINT_KEY_INDEX": " /etc/scardice/index ", "SCARDICE_ENDPOINT_KEY_ROOTS": "/etc/scardice/roots"}[name]
	}
	index, roots = v1KeyPaths("/srv/events.db", env)
	if index != "/etc/scardice/index" || roots != "/etc/scardice/roots" {
		t.Fatalf("key paths = %q/%q", index, roots)
	}
}
