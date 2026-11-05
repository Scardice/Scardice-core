package eventstore

import (
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
	lane := "lane-one"
	rows := make([]inboxMessageRow, rowCount)
	for i := range rows {
		number := i + 1
		rows[i] = inboxMessageRow{
			InboxID:           fmt.Sprintf("delayed-%08d", number),
			EndpointID:        "delayed-endpoint",
			ProviderEventKey:  fmt.Sprintf("delayed-provider-%08d", number),
			Lane:              lane,
			OrderingSequence:  uint64(number),
			Status:            InboxStatusConfirmedConsumed,
			Version:           1,
			SchedulingVersion: 0,
		}
	}
	if err := db.GORM().CreateInBatches(&rows, queueSchedulingBatchSize).Error; err != nil {
		_ = db.Close()
		t.Fatalf("seed delayed migration rows: %v", err)
	}
	if err := laneQuery(db.GORM().Model(&laneHeadRow{}), inboxLaneKind, lane).Updates(map[string]any{
		"next_sequence": uint64(rowCount + 1), "scheduling_version": uint8(0), "updated_at": time.Unix(0, 0).UTC(),
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
func TestRuntimeRefusesOldSchemaBeforeAutoMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`CREATE TABLE store_readiness (singleton_id TEXT PRIMARY KEY, schema_version TEXT NOT NULL)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := old.Exec(`INSERT INTO store_readiness(singleton_id,schema_version) VALUES ('default','1')`).Error; err != nil {
		t.Fatal(err)
	}
	pool, err := old.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path}); err == nil {
		db.Close()
		t.Fatal("runtime accepted schema version one")
	}
	check, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	pool, err = check.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var count int64
	if err := check.Raw(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&count).Error; err != nil || count != 1 {
		t.Fatalf("runtime migrated old tables: count=%d err=%v", count, err)
	}
	var columns int64
	if err := check.Raw(`SELECT COUNT(*) FROM pragma_table_info('store_readiness')`).Scan(&columns).Error; err != nil || columns != 2 {
		t.Fatalf("runtime modified old readiness schema: columns=%d err=%v", columns, err)
	}
}
