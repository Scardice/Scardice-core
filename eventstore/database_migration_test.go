package eventstore

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	modernsqlite "github.com/glebarez/go-sqlite"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

const databaseMigrationDelayFunction = "eventstore_test_migration_delay"

type databaseMigrationDelayControl struct {
	delay    time.Duration
	cancelAt int64
	cancel   context.CancelFunc
}

var (
	databaseMigrationDelayCalls atomic.Int64
	databaseMigrationDelayState atomic.Pointer[databaseMigrationDelayControl]
)

var registerDatabaseMigrationDelay = sync.OnceValue(func() error {
	return modernsqlite.RegisterScalarFunction(
		databaseMigrationDelayFunction,
		0,
		func(_ *modernsqlite.FunctionContext, _ []driver.Value) (driver.Value, error) {
			control := databaseMigrationDelayState.Load()
			if control == nil {
				return int64(0), nil
			}
			call := databaseMigrationDelayCalls.Add(1)
			time.Sleep(control.delay)
			if control.cancel != nil && call == control.cancelAt {
				control.cancel()
			}
			return int64(0), nil
		},
	)
})

func TestEventStoreSchemaAndMigrationAreIdempotent(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "events.db")
	config := DatabaseConfig{Type: "sqlite", DSN: dsn}

	db, databaseErr := OpenDatabase(context.Background(), config)
	if databaseErr != nil {
		t.Fatalf("open sqlite database: %v", databaseErr)
	}
	assertEventStoreSchema(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	db, databaseErr = OpenDatabase(context.Background(), config)
	if databaseErr != nil {
		t.Fatalf("reopen sqlite database: %v", databaseErr)
	}
	defer db.Close()
	assertEventStoreSchema(t, db)
}
func TestOpenDatabaseQueryTimeoutAppliesPerStatementAcrossLongMigration(t *testing.T) {
	// Virtual time separates per-statement deadlines from SQLite execution cost.
	synctest.Test(t, func(t *testing.T) {
		const (
			rowCount     = 8 * queueSchedulingBatchSize
			queryTimeout = 400 * time.Millisecond
		)
		path := createDelayedQueueMigrationFixture(t, rowCount)
		databaseMigrationDelayCalls.Store(0)
		databaseMigrationDelayState.Store(&databaseMigrationDelayControl{delay: 75 * time.Millisecond})
		t.Cleanup(func() { databaseMigrationDelayState.Store(nil) })

		started := time.Now()
		db, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type: "sqlite", DSN: path, QueryTimeout: queryTimeout,
		})
		elapsed := time.Since(started)
		if err != nil {
			t.Fatalf("open across multi-statement migration lasting %s: %v", elapsed, err)
		}
		if elapsed <= queryTimeout {
			_ = db.Close()
			t.Fatalf("migration elapsed %s, want longer than per-statement timeout %s", elapsed, queryTimeout)
		}
		if calls := databaseMigrationDelayCalls.Load(); calls != 8 {
			_ = db.Close()
			t.Fatalf("delayed migration batches = %d, want 8", calls)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close migrated database: %v", err)
		}
		if pending := queueSchedulingPendingRows(t, path); pending != 0 {
			t.Fatalf("pending rows after migration = %d, want 0", pending)
		}

		callsBeforeReopen := databaseMigrationDelayCalls.Load()
		reopened, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type: "sqlite", DSN: path, QueryTimeout: queryTimeout,
		})
		if err != nil {
			t.Fatalf("reopen completed migration: %v", err)
		}
		defer reopened.Close()
		if calls := databaseMigrationDelayCalls.Load(); calls != callsBeforeReopen {
			t.Fatalf("reopen repeated queue migration: delay calls %d -> %d", callsBeforeReopen, calls)
		}
	})
}
func TestOpenDatabaseQueryTimeoutStillBoundsOneMigrationStatement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := createDelayedQueueMigrationFixture(t, queueSchedulingBatchSize)
		databaseMigrationDelayCalls.Store(0)
		databaseMigrationDelayState.Store(&databaseMigrationDelayControl{delay: 200 * time.Millisecond})
		t.Cleanup(func() { databaseMigrationDelayState.Store(nil) })

		failed, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type: "sqlite", DSN: path, QueryTimeout: 50 * time.Millisecond,
		})
		if failed != nil {
			_ = failed.Close()
			t.Fatal("statement-timeout migration returned a database")
		}
		if err == nil {
			t.Fatal("migration with one over-time statement succeeded")
		}
		if !strings.Contains(err.Error(), "queue scheduling inbox rows") {
			t.Fatalf("statement-timeout error lacks specific stage: %v", err)
		}
		if pending := queueSchedulingPendingRows(t, path); pending != queueSchedulingBatchSize {
			t.Fatalf("pending rows after statement timeout = %d, want %d", pending, queueSchedulingBatchSize)
		}

		databaseMigrationDelayState.Store(nil)
		recovered, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type: "sqlite", DSN: path, QueryTimeout: 500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("resume statement-timeout migration: %v", err)
		}
		defer recovered.Close()
		if pending := queueSchedulingPendingRows(t, path); pending != 0 {
			t.Fatalf("pending rows after statement-timeout recovery = %d, want 0", pending)
		}
	})
}
func TestOpenDatabaseCallerCancellationLeavesQueueMigrationResumable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rowCount = 6 * queueSchedulingBatchSize
		path := createDelayedQueueMigrationFixture(t, rowCount)
		ctx, cancel := context.WithCancel(context.Background())
		databaseMigrationDelayCalls.Store(0)
		databaseMigrationDelayState.Store(&databaseMigrationDelayControl{
			delay: 25 * time.Millisecond, cancelAt: 3, cancel: cancel,
		})
		t.Cleanup(func() {
			cancel()
			databaseMigrationDelayState.Store(nil)
		})

		failed, err := OpenDatabase(ctx, DatabaseConfig{
			Type: "sqlite", DSN: path, QueryTimeout: 500 * time.Millisecond,
		})
		if failed != nil {
			_ = failed.Close()
			t.Fatal("canceled migration returned a database")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled migration error = %v, want context.Canceled", err)
		}
		if !strings.Contains(err.Error(), "queue scheduling inbox rows") {
			t.Fatalf("canceled migration error lacks specific stage: %v", err)
		}
		pending := queueSchedulingPendingRows(t, path)
		if pending <= 0 || pending >= rowCount {
			t.Fatalf("pending rows after cancellation = %d, want a resumable partial migration", pending)
		}

		databaseMigrationDelayCalls.Store(0)
		databaseMigrationDelayState.Store(&databaseMigrationDelayControl{delay: 25 * time.Millisecond})
		recovered, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type: "sqlite", DSN: path, QueryTimeout: 500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("resume canceled queue migration: %v", err)
		}
		defer recovered.Close()
		if pending := queueSchedulingPendingRows(t, path); pending != 0 {
			t.Fatalf("pending rows after recovery = %d, want 0", pending)
		}
	})
}
func createDelayedQueueMigrationFixture(t *testing.T, rowCount int) string {
	t.Helper()
	if err := registerDatabaseMigrationDelay(); err != nil {
		t.Fatalf("register migration delay function: %v", err)
	}
	path := filepath.Join(t.TempDir(), "delayed-queue-migration.db")
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatalf("create delayed migration fixture: %v", err)
	}
	lane := []byte{1}
	rows := make([]inboxMessageRow, rowCount)
	for i := range rows {
		number := i + 1
		rows[i] = inboxMessageRow{
			InboxID:           fmt.Sprintf("delayed-%08d", number),
			EndpointID:        "delayed-endpoint",
			ProviderEventKey:  fmt.Sprintf("delayed-provider-%08d", number),
			LaneHMAC:          lane,
			OrderingSequence:  uint64(number),
			Status:            InboxStatusConfirmedConsumed,
			Version:           1,
			PayloadVersion:    1,
			SchedulingVersion: 0,
		}
	}
	if err := db.GORM().CreateInBatches(&rows, queueSchedulingBatchSize).Error; err != nil {
		_ = db.Close()
		t.Fatalf("seed delayed migration rows: %v", err)
	}
	if err := db.GORM().Create(&laneHeadRow{
		Kind: inboxLaneKind, LaneHMAC: lane, NextSequence: uint64(rowCount + 1),
		SchedulingVersion: 0, UpdatedAt: time.Unix(0, 0).UTC(),
	}).Error; err != nil {
		_ = db.Close()
		t.Fatalf("seed delayed migration lane: %v", err)
	}
	trigger := fmt.Sprintf(`CREATE TRIGGER delay_queue_scheduling_migration
		BEFORE UPDATE OF scheduling_version ON inbox_messages
		WHEN OLD.scheduling_version < %d
		  AND NEW.scheduling_version = %d
		  AND CAST(substr(NEW.inbox_id, -8) AS INTEGER) %% %d = 1
		BEGIN
			SELECT %s();
		END`,
		queueSchedulingVersion, queueSchedulingVersion, queueSchedulingBatchSize, databaseMigrationDelayFunction,
	)
	if err := db.GORM().Exec(trigger).Error; err != nil {
		_ = db.Close()
		t.Fatalf("create delayed migration trigger: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close delayed migration fixture: %v", err)
	}
	return path
}
func queueSchedulingPendingRows(t *testing.T, path string) int64 {
	t.Helper()
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open queue migration inspection: %v", err)
	}
	defer db.Close()
	var pending int64
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM inbox_messages WHERE scheduling_version < ?",
		queueSchedulingVersion,
	).Scan(&pending); err != nil {
		t.Fatalf("inspect queue migration progress: %v", err)
	}
	return pending
}
func TestSQLiteProjectionPayloadPresenceMigrationIsAtomic(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-projections.db")
	legacy := deriveProjectionReadModelFixture(t, path, false)
	if _, err := legacy.ExecContext(ctx, `INSERT INTO projection_read_models
		(projection_generation, projection_name, row_key, payload, updated_at)
		VALUES ('initial', 'events', 'nil', NULL, CURRENT_TIMESTAMP),
		       ('initial', 'events', 'empty', zeroblob(0), CURRENT_TIMESTAMP),
		       ('initial', 'events', 'value', CAST('legacy-payload' AS BLOB), CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("insert legacy projection rows: %v", err)
	}
	if _, err := legacy.ExecContext(ctx, `CREATE TRIGGER reject_payload_presence_backfill
		BEFORE UPDATE OF payload_present ON projection_read_models
		BEGIN
			SELECT RAISE(ABORT, 'forced payload presence backfill failure');
		END`); err != nil {
		t.Fatalf("create targeted migration fault: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy fixture: %v", err)
	}

	failed, migrationErr := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path})
	if failed != nil {
		_ = failed.Close()
	}
	if migrationErr == nil {
		t.Fatal("fault-injected projection migration succeeded")
	}

	check, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen failed migration fixture: %v", err)
	}
	var payloadPresentColumns int
	if err := check.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('projection_read_models') WHERE name = 'payload_present'`).Scan(&payloadPresentColumns); err != nil {
		_ = check.Close()
		t.Fatalf("inspect failed projection migration: %v", err)
	}
	if payloadPresentColumns != 0 {
		_ = check.Close()
		t.Fatalf("payload_present columns after failed migration = %d, want 0", payloadPresentColumns)
	}
	if _, err := check.ExecContext(ctx, `DROP TRIGGER reject_payload_presence_backfill`); err != nil {
		_ = check.Close()
		t.Fatalf("remove targeted migration fault: %v", err)
	}
	if err := check.Close(); err != nil {
		t.Fatalf("close failed migration inspection: %v", err)
	}

	migrated, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatalf("migrate projection schema after removing fault: %v", err)
	}
	defer migrated.Close()
	assertMigratedProjectionPayloads(t, migrated)
}
func TestSQLiteProjectionPayloadPresenceMigrationRecoversInterruptedBackfillOnce(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "interrupted-projections.db")
	legacy := deriveProjectionReadModelFixture(t, path, true)
	if _, err := legacy.ExecContext(ctx, `INSERT INTO projection_read_models
		(projection_generation, projection_name, row_key, payload, payload_present, updated_at)
		VALUES ('initial', 'events', 'nil', NULL, FALSE, CURRENT_TIMESTAMP),
		       ('initial', 'events', 'empty', zeroblob(0), FALSE, CURRENT_TIMESTAMP),
		       ('initial', 'events', 'value', CAST('legacy-payload' AS BLOB), FALSE, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("insert interrupted projection rows: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close interrupted fixture: %v", err)
	}

	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatalf("recover interrupted projection migration: %v", err)
	}
	assertMigratedProjectionPayloads(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("close recovered database: %v", err)
	}

	guard, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open completed migration fixture: %v", err)
	}
	if _, err := guard.ExecContext(ctx, `CREATE TRIGGER reject_repeated_payload_presence_backfill
		BEFORE UPDATE OF payload_present ON projection_read_models
		BEGIN
			SELECT RAISE(ABORT, 'payload presence backfill repeated');
		END`); err != nil {
		_ = guard.Close()
		t.Fatalf("create repeated-backfill guard: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatalf("close repeated-backfill guard: %v", err)
	}

	reopened, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatalf("reopen after completed projection migration: %v", err)
	}
	defer reopened.Close()
}
func assertMigratedProjectionPayloads(t *testing.T, db *Database) {
	t.Helper()
	ctx := context.Background()
	store := NewStore(db)
	for _, check := range []struct {
		rowKey  string
		want    []byte
		wantNil bool
	}{
		{rowKey: "nil", wantNil: true},
		{rowKey: "empty", want: []byte{}},
		{rowKey: "value", want: []byte("legacy-payload")},
	} {
		row, err := store.ReadProjectionRow(ctx, "events", check.rowKey)
		if err != nil {
			t.Fatalf("read migrated projection %q: %v", check.rowKey, err)
		}
		if check.wantNil {
			if row.Payload != nil {
				t.Fatalf("migrated projection %q payload = %#v, want nil", check.rowKey, row.Payload)
			}
		} else if row.Payload == nil || !bytes.Equal(row.Payload, check.want) {
			t.Fatalf("migrated projection %q payload = %#v, want %#v", check.rowKey, row.Payload, check.want)
		}
	}
}
func deriveProjectionReadModelFixture(t *testing.T, targetPath string, includePayloadPresent bool) *sql.DB {
	t.Helper()
	ctx := context.Background()
	seedPath := filepath.Join(t.TempDir(), "current-schema.db")
	seed, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: seedPath})
	if err != nil {
		t.Fatalf("create public current-schema fixture: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close public current-schema fixture: %v", err)
	}

	current, err := sql.Open("sqlite", seedPath)
	if err != nil {
		t.Fatalf("inspect public current-schema fixture: %v", err)
	}
	defer func() {
		if err := current.Close(); err != nil {
			t.Errorf("close current-schema inspection: %v", err)
		}
	}()
	var tableDDL string
	if err := current.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'projection_read_models'`).Scan(&tableDDL); err != nil {
		t.Fatalf("read current projection schema: %v", err)
	}
	indexRows, err := current.QueryContext(ctx, `SELECT sql FROM sqlite_master
		WHERE type = 'index' AND tbl_name = 'projection_read_models' AND sql IS NOT NULL ORDER BY name`)
	if err != nil {
		t.Fatalf("read current projection indexes: %v", err)
	}
	defer func() {
		if err := indexRows.Close(); err != nil {
			t.Errorf("close current projection indexes: %v", err)
		}
	}()
	var indexDDLs []string
	for indexRows.Next() {
		var indexDDL string
		if err := indexRows.Scan(&indexDDL); err != nil {
			t.Fatalf("scan current projection index: %v", err)
		}
		indexDDLs = append(indexDDLs, indexDDL)
	}
	if err := indexRows.Err(); err != nil {
		t.Fatalf("iterate current projection indexes: %v", err)
	}

	target, err := sql.Open("sqlite", targetPath)
	if err != nil {
		t.Fatalf("open derived projection fixture: %v", err)
	}
	if _, err := target.ExecContext(ctx, tableDDL); err != nil {
		_ = target.Close()
		t.Fatalf("create derived current projection schema: %v", err)
	}
	for _, indexDDL := range indexDDLs {
		if _, err := target.ExecContext(ctx, indexDDL); err != nil {
			_ = target.Close()
			t.Fatalf("create derived current projection index: %v", err)
		}
	}
	if !includePayloadPresent {
		if _, err := target.ExecContext(ctx, `ALTER TABLE projection_read_models DROP COLUMN payload_present`); err != nil {
			_ = target.Close()
			t.Fatalf("derive pre-payload-presence schema: %v", err)
		}
	}
	return target
}
func TestSQLiteLegacyOperationArtifactsUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, migrationErr := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if migrationErr != nil {
		t.Fatalf("open legacy sqlite database: %v", migrationErr)
	}
	if err := legacy.AutoMigrate(&operationRow{}); err != nil {
		t.Fatalf("create legacy operations table: %v", err)
	}
	if err := legacy.Exec(`CREATE TABLE operation_artifacts (
		artifact_id TEXT NOT NULL PRIMARY KEY,
		operation_id TEXT NOT NULL,
		owner_principal_id TEXT NOT NULL,
		media_type TEXT NOT NULL,
		safe_filename TEXT,
		size INTEGER NOT NULL,
		status TEXT NOT NULL,
		ciphertext BLOB,
		nonce BLOB,
		encryption_key_id TEXT,
		expires_at DATETIME NOT NULL,
		consumed_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create legacy artifact table: %v", err)
	}
	if err := legacy.Exec(`INSERT INTO operations (operation_id, version, status, kind, principal_id, idempotency_scope, idempotency_key, created_at, updated_at) VALUES ('legacy-op', 1, 'pending', 'test', 'principal', 'scope', 'legacy-key', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatalf("insert legacy operation: %v", err)
	}
	if err := legacy.Exec(`INSERT INTO operation_artifacts (artifact_id, operation_id, owner_principal_id, media_type, size, status, expires_at) VALUES ('legacy-artifact', 'legacy-op', 'principal', 'text/plain', 7, 'available', CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatalf("insert legacy artifact: %v", err)
	}
	if err := legacy.Exec(`CREATE UNIQUE INDEX ux_operation_artifacts_artifact_id ON operation_artifacts(artifact_id)`).Error; err != nil {
		t.Fatalf("create legacy artifact index: %v", err)
	}
	legacySQL, migrationErr := legacy.DB()
	if migrationErr != nil {
		t.Fatalf("get legacy sql database: %v", migrationErr)
	}
	if err := legacySQL.Close(); err != nil {
		t.Fatalf("close legacy sqlite database: %v", err)
	}

	db, migrationErr := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
	if migrationErr != nil {
		t.Fatalf("upgrade legacy sqlite database: %v", migrationErr)
	}
	defer db.Close()
	assertIndexColumns(t, db, tableOperationArtifacts, "ux_operation_artifacts_artifact_id", []string{"artifact_id"})
	var version int
	if err := db.SQLDB().QueryRowContext(context.Background(), `SELECT version FROM operation_artifacts WHERE artifact_id = 'legacy-artifact'`).Scan(&version); err != nil {
		t.Fatalf("read upgraded artifact version: %v", err)
	}
	if version != 1 {
		t.Fatalf("upgraded artifact version = %d, want 1", version)
	}
	assertForeignKeyAction(t, db, "operation_artifacts", "operations", "RESTRICT")
	if _, err := db.SQLDB().ExecContext(context.Background(), `INSERT INTO operation_artifacts (artifact_id, version, operation_id, owner_principal_id, media_type, size, status, expires_at) VALUES ('legacy-orphan', 1, 'missing-operation', 'principal', 'text/plain', 0, 'available', CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("upgraded artifact table accepted orphan operation reference")
	}
	orphanPath := filepath.Join(t.TempDir(), "legacy-orphan.db")
	orphanLegacy, migrationErr := gorm.Open(sqlite.Open(orphanPath), &gorm.Config{})
	if migrationErr != nil {
		t.Fatalf("open orphan legacy sqlite database: %v", migrationErr)
	}
	if err := orphanLegacy.AutoMigrate(&operationRow{}); err != nil {
		t.Fatalf("create orphan legacy operations table: %v", err)
	}
	if err := orphanLegacy.Exec(`CREATE TABLE operation_artifacts (
		artifact_id TEXT NOT NULL PRIMARY KEY,
		operation_id TEXT NOT NULL,
		owner_principal_id TEXT NOT NULL,
		media_type TEXT NOT NULL,
		safe_filename TEXT,
		size INTEGER NOT NULL,
		status TEXT NOT NULL,
		ciphertext BLOB,
		nonce BLOB,
		encryption_key_id TEXT,
		expires_at DATETIME NOT NULL,
		consumed_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create orphan legacy artifact table: %v", err)
	}
	if err := orphanLegacy.Exec(`INSERT INTO operation_artifacts (artifact_id, operation_id, owner_principal_id, media_type, size, status, expires_at) VALUES ('orphan-artifact', 'missing-operation', 'principal', 'text/plain', 0, 'available', CURRENT_TIMESTAMP)`).Error; err != nil {
		t.Fatalf("insert orphan legacy artifact: %v", err)
	}
	orphanSQL, migrationErr := orphanLegacy.DB()
	if migrationErr != nil {
		t.Fatalf("get orphan legacy sql database: %v", migrationErr)
	}
	if err := orphanSQL.Close(); err != nil {
		t.Fatalf("close orphan legacy sqlite database: %v", err)
	}
	if _, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: orphanPath}); err == nil {
		t.Fatal("legacy orphan artifact database opened successfully")
	}
}
func TestSQLiteLegacyMigrationRejectsForeignIndexOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-index-owner.db")
	legacy, migrationErr := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if migrationErr != nil {
		t.Fatalf("open legacy sqlite database: %v", migrationErr)
	}
	if err := legacy.AutoMigrate(&operationRow{}); err != nil {
		t.Fatalf("create legacy operations table: %v", err)
	}
	if err := legacy.Exec(`CREATE TABLE operation_artifacts (
		artifact_id TEXT NOT NULL PRIMARY KEY,
		operation_id TEXT NOT NULL,
		owner_principal_id TEXT NOT NULL,
		media_type TEXT NOT NULL,
		safe_filename TEXT,
		size INTEGER NOT NULL,
		status TEXT NOT NULL,
		ciphertext BLOB,
		nonce BLOB,
		encryption_key_id TEXT,
		expires_at DATETIME NOT NULL,
		consumed_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create legacy artifact table: %v", err)
	}
	if err := legacy.Exec(`CREATE TABLE unrelated_index_owner (id INTEGER PRIMARY KEY, value TEXT)`).Error; err != nil {
		t.Fatalf("create unrelated table: %v", err)
	}
	if err := legacy.Exec(`CREATE UNIQUE INDEX ux_operation_artifacts_artifact_id ON unrelated_index_owner(value)`).Error; err != nil {
		t.Fatalf("create unrelated index: %v", err)
	}
	legacySQL, migrationErr := legacy.DB()
	if migrationErr != nil {
		t.Fatalf("get legacy sql database: %v", migrationErr)
	}
	if err := legacySQL.Close(); err != nil {
		t.Fatalf("close legacy sqlite database: %v", err)
	}
	if _, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path}); err == nil {
		t.Fatal("legacy database with foreign index owner opened successfully")
	}

	check, migrationErr := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if migrationErr != nil {
		t.Fatalf("reopen rejected legacy database: %v", migrationErr)
	}
	var owner string
	if err := check.Raw(`SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?`, "ux_operation_artifacts_artifact_id").Scan(&owner).Error; err != nil {
		t.Fatalf("inspect preserved unrelated index: %v", err)
	}
	if owner != "unrelated_index_owner" {
		t.Fatalf("index owner = %q, want unrelated_index_owner", owner)
	}
	checkSQL, migrationErr := check.DB()
	if migrationErr != nil {
		t.Fatalf("get check sql database: %v", migrationErr)
	}
	_ = checkSQL.Close()
}
