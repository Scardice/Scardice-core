package eventstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		if !wantUnique && unique == 1 {
			t.Errorf("index %q is unexpectedly unique", name)
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

func TestEventStoreSchemaHasAllRestrictiveForeignKeys(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()

	assertForeignKeyAction(t, db, "operations", "operation_artifacts", "RESTRICT")
	assertForeignKeyAction(t, db, "subject_fences", "operations", "RESTRICT")
	if _, err := db.SQLDB().ExecContext(context.Background(), `INSERT INTO operations (operation_id, version, status, kind, principal_id, idempotency_scope, idempotency_key, artifact_id, created_at, updated_at) VALUES ('op', 1, 'pending', 'test', 'principal', 'scope', 'key', 'missing-artifact', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("orphan operation artifact reference insert succeeded")
	}
	if _, err := db.SQLDB().ExecContext(context.Background(), `INSERT INTO subject_fences (subject_key, scope, purge_operation_id, created_at) VALUES (x'01', 'subject', 'missing-operation', CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("orphan subject fence operation reference insert succeeded")
	}
}

func assertForeignKeyAction(t *testing.T, db *Database, table, target, wantDelete string) {
	t.Helper()
	var onDelete string
	if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT on_delete FROM pragma_foreign_key_list(?) WHERE \"table\" = ?", table, target).Scan(&onDelete); err != nil {
		t.Fatalf("inspect %s -> %s foreign key: %v", table, target, err)
	}
	if !strings.EqualFold(onDelete, wantDelete) {
		t.Fatalf("%s -> %s on_delete = %q, want %s", table, target, onDelete, wantDelete)
	}
}

func TestLoopbackTLSExceptionRejectsURLQueryHostOverride(t *testing.T) {
	if isLoopbackOrUnixDSN("postgres", "postgres://localhost/events?host=evil.example") {
		t.Fatal("URL query host override incorrectly qualified for insecure loopback exception")
	}
}

func TestLoopbackTLSExceptionRejectsAmbiguousPostgresWhitespace(t *testing.T) {
	for _, dsn := range []string{
		"host='localhost db.remote' dbname=events",
		"host=localhost db.remote dbname=events",
	} {
		if isLoopbackOrUnixDSN("postgres", dsn) {
			t.Errorf("ambiguous DSN %q qualified for insecure loopback exception", dsn)
		}
	}
}

func TestSQLiteImmediateWriterContentionIsBounded(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "events.db")
	first, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("open first database: %v", err)
	}
	defer first.Close()
	second, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("open second database: %v", err)
	}
	defer second.Close()

	if _, err := first.SQLDB().ExecContext(context.Background(), "CREATE TABLE IF NOT EXISTS writer_lock_probe (id INTEGER)"); err != nil {
		t.Fatalf("create writer probe: %v", err)
	}
	tx, err := first.SQLDB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin first writer: %v", err)
	}
	defer tx.Rollback()
	if _, err := second.SQLDB().ExecContext(context.Background(), "PRAGMA busy_timeout = 100"); err != nil {
		t.Fatalf("set contention timeout: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := second.SQLDB().ExecContext(ctx, "INSERT INTO writer_lock_probe (id) VALUES (1)"); err == nil {
		t.Fatal("second writer unexpectedly succeeded while first writer held lock")
	}
}

func TestOpenDatabaseRejectsFailedSQLiteInitialization(t *testing.T) {
	root := t.TempDir()
	dsn := filepath.Join(root, "missing", "events.db")
	if _, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: dsn}); err == nil {
		t.Fatal("open with unavailable SQLite parent unexpectedly succeeded")
	}
	if err := os.Mkdir(filepath.Dir(dsn), 0o700); err != nil {
		t.Fatalf("create SQLite parent: %v", err)
	}
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatalf("open after fixing SQLite parent: %v", err)
	}
	defer db.Close()
}
