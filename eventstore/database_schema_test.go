package eventstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

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
	db, openErr := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if openErr != nil {
		t.Fatalf("open sqlite database: %v", openErr)
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
	assertForeignKeyAction(t, db, "subject_fences", "operations", "RESTRICT")
	_, openErr = db.SQLDB().ExecContext(context.Background(), `INSERT INTO operation_artifacts (artifact_id, version, operation_id, owner_principal_id, media_type, size, status, expires_at) VALUES ('artifact', 1, 'missing-operation', 'owner', 'text/plain', 0, 'available', CURRENT_TIMESTAMP)`)
	if openErr == nil {
		t.Fatal("orphan operation artifact insert succeeded")
	}
	_, openErr = db.SQLDB().ExecContext(context.Background(), `INSERT INTO subject_fences (subject_key, scope, version, purge_operation_id, created_at) VALUES (x'01', 'subject', 1, 'missing-operation', CURRENT_TIMESTAMP)`)
	if openErr == nil {
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
func TestEventStoreDomainEventPayloadColumn(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()
	var columnType string
	var notNull int
	if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT type, \"notnull\" FROM pragma_table_info(?) WHERE name = ?", tableDomainEvents, "payload").Scan(&columnType, &notNull); err != nil {
		t.Fatalf("inspect domain event payload column: %v", err)
	}
	if !strings.EqualFold(columnType, "blob") || notNull != 0 {
		t.Fatalf("payload column type/notnull = %q/%d, want blob/0", columnType, notNull)
	}
}
func TestEventStoreDomainEventMetadataColumns(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()
	rows, err := db.SQLDB().QueryContext(context.Background(), "SELECT name FROM pragma_table_info(?)", tableDomainEvents)
	if err != nil {
		t.Fatalf("inspect domain event columns: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan domain event column: %v", err)
		}
		got[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate domain event columns: %v", err)
	}
	for _, column := range []string{"event_id", "aggregate_type", "aggregate_id", "aggregate_version", "global_position", "event_type", "schema_version", "payload", "command_id", "correlation_id", "causation_id", "principal_id", "producer", "occurred_at_unix_nano_utc", "checksum", "created_at"} {
		if !got[column] {
			t.Errorf("missing domain event column %q", column)
		}
	}
}
func TestOperationArtifactForeignKeysAllowNullableFirstLinking(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()
	if _, err := db.SQLDB().ExecContext(context.Background(), `INSERT INTO operations (operation_id, version, status, kind, principal_id, idempotency_scope, idempotency_key, created_at, updated_at) VALUES ('op-link', 1, 'pending', 'test', 'principal', 'scope', 'key-link', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("insert operation before artifact: %v", err)
	}
	if _, err := db.SQLDB().ExecContext(context.Background(), `INSERT INTO operation_artifacts (artifact_id, version, operation_id, owner_principal_id, media_type, size, status, expires_at) VALUES ('artifact-link', 1, 'op-link', 'principal', 'text/plain', 0, 'available', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	if _, err := db.SQLDB().ExecContext(context.Background(), "UPDATE operations SET artifact_id = 'artifact-link' WHERE operation_id = 'op-link'"); err != nil {
		t.Fatalf("link operation to artifact: %v", err)
	}
	if _, err := db.SQLDB().ExecContext(context.Background(), "DELETE FROM operations WHERE operation_id = 'op-link'"); err == nil {
		t.Fatal("operation delete bypassed restrictive artifact reference")
	}
}
func TestEventStoreSensitiveSchemaColumns(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()
	for table, columns := range map[string][]string{
		tableOperations:         {"request_id", "private_context", "private_nonce", "private_key_id"},
		tableOperationArtifacts: {"size", "version"},
		tableOutboxEffects:      {"risk_class", "content_digest_key_id", "completed_at", "payload_expires_at"},
		tableAdapterSecrets:     {"adapter_id"},
		tablePluginKV:           {"key_nonce", "value_nonce"},
		tableSubjectFences:      {"version"},
	} {
		for _, column := range columns {
			assertSQLiteColumn(t, db, table, column)
		}
	}
}
func assertSQLiteColumn(t *testing.T, db *Database, table, column string) {
	t.Helper()
	var name string
	if err := db.SQLDB().QueryRowContext(context.Background(), "SELECT name FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&name); err != nil {
		t.Fatalf("missing %s.%s: %v", table, column, err)
	}
}
