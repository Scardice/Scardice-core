package eventstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDatabaseSQLiteEffectiveSettings(t *testing.T) {
	datadir := t.TempDir()
	t.Setenv("DATADIR", datadir)

	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite"})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(filepath.Join(datadir, "events.db")); err != nil {
		t.Fatalf("default sqlite database path: %v", err)
	}

	var journalMode string
	if err := db.SQLDB().QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}

	checks := map[string]int{"foreign_keys": 1, "busy_timeout": 15000, "synchronous": 2}
	for pragma, want := range checks {
		var got int
		if err := db.SQLDB().QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", pragma, err)
		}
		if pragma == "busy_timeout" && got < want {
			t.Fatalf("%s = %d, want at least %d", pragma, got, want)
		} else if pragma != "busy_timeout" && got != want {
			t.Fatalf("%s = %d, want %d", pragma, got, want)
		}
	}
	if got := db.SQLDB().Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}
}

func TestEventStoreSchemaAndMigrationAreIdempotent(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "events.db")
	config := DatabaseConfig{Type: "sqlite", DSN: dsn}

	db, err := OpenDatabase(context.Background(), config)
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	assertEventStoreSchema(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	db, err = OpenDatabase(context.Background(), config)
	if err != nil {
		t.Fatalf("reopen sqlite database: %v", err)
	}
	defer db.Close()
	assertEventStoreSchema(t, db)
}

func TestOpenDatabaseRejectsInvalidRemoteConfigWithoutSecrets(t *testing.T) {
	secret := "super-secret-password"
	config := DatabaseConfig{
		Type: "postgres",
		DSN:  "postgres://alice:" + secret + "@127.0.0.1:1/events?sslmode=disable&token=" + secret,
	}
	_, err := OpenDatabase(context.Background(), config)
	if err == nil {
		t.Fatal("OpenDatabase() error = nil, want invalid TLS/config error")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected context error: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error contains DSN secret: %v", err)
	}
	if strings.Contains(err.Error(), "alice:") {
		t.Fatalf("error contains DSN userinfo: %v", err)
	}
}

func TestDatabaseCloseIsIdempotent(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func assertEventStoreSchema(t *testing.T, db *Database) {
	t.Helper()
	rows, err := db.SQLDB().QueryContext(context.Background(), `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table: %v", err)
		}
		got[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	for _, table := range requiredEventStoreTables {
		if !got[table] {
			t.Errorf("missing table %q", table)
		}
	}
	for _, singleton := range []string{"event_global_sequence", "projection_control", "store_readiness"} {
		var count int
		if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+singleton).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", singleton, err)
		}
		if count != 1 {
			t.Errorf("%s row count = %d, want 1", singleton, count)
		}
	}
	for name, wantUnique := range requiredEventStoreIndexes {
		var unique int
		if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT [unique] FROM pragma_index_list(?) WHERE name = ?", name[:strings.IndexByte(name, ':')], name[strings.IndexByte(name, ':')+1:]).Scan(&unique); err != nil {
			t.Errorf("missing index %q: %v", name, err)
			continue
		}
		if wantUnique && unique != 1 {
			t.Errorf("index %q unique = %d, want unique", name, unique)
		}
	}
	assertIndexColumns(t, db, "domain_events", "ix_domain_events_global_position", []string{"global_position"})
	assertIndexColumns(t, db, "inbox_messages", "ix_inbox_status_lease", []string{"status", "lease_expiry"})
	assertIndexColumns(t, db, "outbox_effects", "ix_outbox_status_attempt", []string{"status", "next_attempt_at", "lease_expiry"})
}

func assertIndexColumns(t *testing.T, db *Database, table, index string, want []string) {
	t.Helper()
	rows, err := db.SQLDB().QueryContext(context.Background(), "SELECT seqno, name FROM pragma_index_info(?) ORDER BY seqno", index)
	if err != nil {
		t.Fatalf("inspect index %s: %v", index, err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var seq int
		var name string
		if err := rows.Scan(&seq, &name); err != nil {
			t.Fatalf("scan index %s: %v", index, err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("inspect index %s: %v", index, err)
	}
	if len(got) != len(want) {
		t.Fatalf("%s.%s columns = %v, want %v", table, index, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s.%s column %d = %q, want %q", table, index, i, got[i], want[i])
		}
	}
}

func TestEventStoreSchemaForeignKeys(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()
	var onDelete, onUpdate string
	if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT on_delete, on_update FROM pragma_foreign_key_list(?) WHERE \"table\" = ?", "operation_artifacts", "operations").Scan(&onDelete, &onUpdate); err != nil {
		t.Fatalf("inspect operation artifact foreign key: %v", err)
	}
	if !strings.EqualFold(onDelete, "RESTRICT") {
		t.Fatalf("artifact operation foreign key on_delete = %q, want RESTRICT", onDelete)
	}
	if !strings.EqualFold(onUpdate, "RESTRICT") {
		t.Fatalf("artifact operation foreign key on_update = %q, want RESTRICT", onUpdate)
	}
	_, err = db.SQLDB().ExecContext(context.Background(), `INSERT INTO operation_artifacts (artifact_id, operation_id, owner_principal_id, media_type, size, status, expires_at) VALUES ('artifact', 'missing-operation', 'owner', 'text/plain', 0, 'available', CURRENT_TIMESTAMP)`)
	if err == nil {
		t.Fatal("orphan operation artifact insert succeeded")
	}
}

func TestOpenDatabaseRejectsUnverifiedMySQLTLSModes(t *testing.T) {
	for _, mode := range []string{"preferred", "custom"} {
		_, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type: "mysql",
			DSN: "alice:secret@tcp(db.example:3306)/events?tls=" + mode,
			TLSVerify: true,
		})
		if err == nil {
			t.Fatalf("TLS mode %q accepted, want fail-closed rejection", mode)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("TLS mode %q leaked DSN secret: %v", mode, err)
		}
	}
}

func TestLoopbackTLSExceptionRejectsMixedPostgresHosts(t *testing.T) {
	for _, dsn := range []string{
		"host=127.0.0.1,db.remote dbname=events",
		"host=/tmp/pg,db.remote dbname=events",
		"postgres:///events",
	} {
		if isLoopbackOrUnixDSN("postgres", dsn) {
			t.Errorf("DSN %q incorrectly qualifies for insecure loopback exception", dsn)
		}
	}
	if !isLoopbackOrUnixDSN("postgres", "host=127.0.0.1,localhost dbname=events") {
		t.Error("all-loopback PostgreSQL host list was rejected")
	}
}
