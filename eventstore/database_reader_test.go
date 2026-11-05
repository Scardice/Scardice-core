package eventstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"gorm.io/gorm"
)

func openReaderPoolProjectionStore(t *testing.T, dsn string) (*GORMStore, *Database) {
	t.Helper()
	database, err := OpenDatabase(context.Background(), DatabaseConfig{
		Type: "sqlite",
		DSN:  dsn,
	})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	projector := ProjectionDescriptor{
		Name:    "reader-pool",
		Version: "1",
		Apply: func(_ context.Context, tx *gorm.DB, events []Envelope) error {
			for _, event := range events {
				if err := UpsertProjectionRow(tx, "reader-pool", event.EventID, event.Payload); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return NewStore(database, WithProjection(projector)), database
}

func seedReaderPoolProjection(t *testing.T, store *GORMStore, eventID string, payload []byte) {
	t.Helper()
	_, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{
		Stream: StreamID{AggregateType: "reader-pool", AggregateID: "fixture"},
		Events: []NewEvent{{
			EventType:     "reader-pool.saved",
			SchemaVersion: 1,
			Payload:       payload,
			Metadata: Metadata{
				EventID:               eventID,
				CommandID:             "command-" + eventID,
				CorrelationID:         "correlation-" + eventID,
				OccurredAtUnixNanoUTC: 1,
				OccurredAtUnixNanoSet: true,
			},
		}},
	}}})
	if err != nil {
		t.Fatalf("seed projection: %v", err)
	}
}

func TestOpenDatabaseSQLiteReaderPreservesLiteralFilenameCharacters(t *testing.T) {
	for _, tc := range []struct {
		name        string
		filename    string
		uriFilename string
	}{
		{name: "literal percent escape", filename: "events%20copy.db"},
		{name: "literal malformed percent", filename: "events%bad.db"},
		{name: "literal hash", filename: "events#copy.db"},
		{name: "literal percent and hash", filename: "events%20#copy.db"},
		{name: "existing escaped file URI", filename: "events copy#one.db", uriFilename: "events%20copy%23one.db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, tc.filename)
			dsn := path
			if tc.uriFilename != "" {
				dsn = "file:" + filepath.ToSlash(filepath.Join(directory, tc.uriFilename))
			}
			dsn += "?cache=shared&_pragma=cache_size%28-1234%29"
			store, database := openReaderPoolProjectionStore(t, dsn)
			t.Cleanup(func() { _ = database.Close() })
			seedReaderPoolProjection(t, store, "literal-filename", []byte("persisted in the requested file"))

			if _, err := os.Stat(path); err != nil {
				t.Fatalf("literal database filename was not opened: %v", err)
			}
			readerSQL, err := database.ReadGORM().DB()
			if err != nil {
				t.Fatalf("acquire reader pool: %v", err)
			}
			if readerSQL == database.SQLDB() {
				t.Fatal("file-backed SQLite did not open a separate reader pool")
			}
			var cacheSize int
			if err := readerSQL.QueryRowContext(context.Background(), "PRAGMA cache_size").Scan(&cacheSize); err != nil || cacheSize != -1234 {
				t.Fatalf("reader query option cache_size = %d, error = %v", cacheSize, err)
			}
			row, err := store.ReadProjectionRow(context.Background(), "reader-pool", "literal-filename")
			if err != nil || string(row.Payload) != "persisted in the requested file" {
				t.Fatalf("reader did not see the writer's literal-path row: %+v, error = %v", row, err)
			}
			if err := database.Close(); err != nil {
				t.Fatalf("close literal-path database: %v", err)
			}

			reopened, reopenedDatabase := openReaderPoolProjectionStore(t, dsn)
			defer reopenedDatabase.Close()
			row, err = reopened.ReadProjectionRow(context.Background(), "reader-pool", "literal-filename")
			if err != nil || string(row.Payload) != "persisted in the requested file" {
				t.Fatalf("literal-path row was not preserved after reopen: %+v, error = %v", row, err)
			}
		})
	}
}

func TestOpenDatabaseSQLiteReaderSupportsRelativePaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
		path string
	}{
		{name: "ordinary path", dsn: "data/endpoint/events.db", path: "data/endpoint/events.db"},
		{name: "file URI", dsn: "file:data/endpoint/events%20copy.db", path: "data/endpoint/events copy.db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.MkdirAll(filepath.FromSlash("data/endpoint"), 0o700); err != nil {
				t.Fatal(err)
			}
			store, database := openReaderPoolProjectionStore(t, tc.dsn)
			defer database.Close()
			seedReaderPoolProjection(t, store, "relative-path", []byte("same database"))
			if _, err := os.Stat(filepath.FromSlash(tc.path)); err != nil {
				t.Fatalf("requested relative database missing: %v", err)
			}
			row, err := store.ReadProjectionRow(context.Background(), "reader-pool", "relative-path")
			if err != nil || string(row.Payload) != "same database" {
				t.Fatalf("relative-path reader row=%+v err=%v", row, err)
			}
		})
	}
}

func TestProjectionReadUsesCommittedSnapshotWhileWriterConnectionIsHeld(t *testing.T) {
	store, database := openReaderPoolProjectionStore(t, "file:"+filepath.Join(t.TempDir(), "reader.db")+"?cache=shared")
	defer database.Close()
	seedReaderPoolProjection(t, store, "held-writer", []byte("committed"))

	writer := database.GORM().Begin()
	if writer.Error != nil {
		t.Fatalf("begin held writer: %v", writer.Error)
	}
	defer writer.Rollback()
	if err := writer.Model(&projectionReadModelRow{}).
		Where("projection_generation = ? AND projection_name = ? AND row_key = ?", "initial", "reader-pool", "held-writer").
		Update("payload", []byte("uncommitted")).Error; err != nil {
		t.Fatalf("stage uncommitted projection update: %v", err)
	}
	if err := writer.Model(&projectionControlRow{}).
		Where("singleton_id = ?", "default").
		Updates(map[string]any{"publication_state": "building", "terminal_position": 99}).Error; err != nil {
		t.Fatalf("stage uncommitted publication update: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	row, err := store.ReadProjectionRow(ctx, "reader-pool", "held-writer")
	if err != nil {
		t.Fatalf("read committed projection while writer held: %v", err)
	}
	if got := string(row.Payload); got != "committed" {
		t.Fatalf("projection payload = %q, want last committed value", got)
	}
	rows, err := store.ListProjectionRows(ctx, "reader-pool")
	if err != nil {
		t.Fatalf("list committed projections while writer held: %v", err)
	}
	if len(rows) != 1 || rows[0].RowKey != "held-writer" || string(rows[0].Payload) != "committed" {
		t.Fatalf("projection list exposed uncommitted state: %+v", rows)
	}
	page, err := store.ListProjectionRowsPage(ctx, ProjectionPageRequest{ProjectionName: "reader-pool", Limit: 10})
	if err != nil {
		t.Fatalf("page committed projections while writer held: %v", err)
	}
	if page.Done || page.Snapshot.TerminalPosition != 1 || len(page.Rows) != 1 || page.Rows[0].RowKey != "held-writer" || string(page.Rows[0].Payload) != "committed" {
		t.Fatalf("projection page exposed uncommitted state: %+v", page)
	}
	if _, err := store.DigestProjection(ctx, "initial"); err != nil {
		t.Fatalf("digest committed projection while writer held: %v", err)
	}
	heads, err := store.ListStreamHeads(ctx, "reader-pool")
	if err != nil {
		t.Fatalf("list committed stream heads while writer held: %v", err)
	}
	if len(heads) != 1 || heads[0].Stream.AggregateID != "fixture" || heads[0].Version != 1 {
		t.Fatalf("stream heads = %+v, want committed fixture version 1", heads)
	}
	var count int64
	if err := database.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		return tx.Model(&projectionReadModelRow{}).Count(&count).Error
	}); err != nil {
		t.Fatalf("read direct snapshot while writer held: %v", err)
	}
	if count != 1 {
		t.Fatalf("projection snapshot row count = %d, want 1", count)
	}
}

func TestSQLiteReaderPoolIsQueryOnlyAndCannotMutateProjection(t *testing.T) {
	store, database := openReaderPoolProjectionStore(t, filepath.Join(t.TempDir(), "query-only.db"))
	defer database.Close()
	seedReaderPoolProjection(t, store, "query-only", []byte("original"))

	result := database.ReadGORM().Model(&projectionReadModelRow{}).
		Where("projection_generation = ? AND projection_name = ? AND row_key = ?", "initial", "reader-pool", "query-only").
		Update("payload", []byte("mutated"))
	if result.Error == nil {
		t.Fatal("query-only reader accepted an update")
	}

	var row projectionReadModelRow
	if err := database.GORM().
		Where("projection_generation = ? AND projection_name = ? AND row_key = ?", "initial", "reader-pool", "query-only").
		First(&row).Error; err != nil {
		t.Fatalf("read projection through writer: %v", err)
	}
	if got := string(row.Payload); got != "original" {
		t.Fatalf("projection payload = %q after rejected reader update", got)
	}
}

func TestProjectionReaderRejectsCommittedUnpublishedState(t *testing.T) {
	store, database := openReaderPoolProjectionStore(t, filepath.Join(t.TempDir(), "unpublished.db"))
	defer database.Close()
	seedReaderPoolProjection(t, store, "unpublished", []byte("private-until-published"))
	if err := database.GORM().Model(&projectionControlRow{}).
		Where("singleton_id = ?", "default").
		Update("publication_state", "building").Error; err != nil {
		t.Fatalf("mark projection unpublished: %v", err)
	}

	if _, err := store.ReadProjectionRow(context.Background(), "reader-pool", "unpublished"); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unpublished row read error = %v, want ErrReadinessQuarantined", err)
	}
	if rows, err := store.ListProjectionRows(context.Background(), "reader-pool"); !errors.Is(err, ErrReadinessQuarantined) || rows != nil {
		t.Fatalf("unpublished list = %+v, error = %v", rows, err)
	}
	if page, err := store.ListProjectionRowsPage(context.Background(), ProjectionPageRequest{ProjectionName: "reader-pool", Limit: 10}); !errors.Is(err, ErrReadinessQuarantined) || len(page.Rows) != 0 {
		t.Fatalf("unpublished page = %+v, error = %v", page, err)
	}
}

func sqliteConnectionSettings(t *testing.T, ctx context.Context, conn *sql.Conn) string {
	t.Helper()
	var journalMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read reader journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("reader journal_mode = %q, want wal", journalMode)
	}
	var lockingMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA locking_mode").Scan(&lockingMode); err != nil {
		t.Fatalf("read reader locking_mode: %v", err)
	}
	if lockingMode != "normal" {
		t.Fatalf("reader locking_mode = %q, want normal", lockingMode)
	}
	for _, check := range []struct {
		name string
		want int
	}{
		{name: "foreign_keys", want: 1},
		{name: "busy_timeout", want: 15000},
		{name: "synchronous", want: 2},
		{name: "read_uncommitted", want: 0},
		{name: "query_only", want: 1},
	} {
		var got int
		if err := conn.QueryRowContext(ctx, "PRAGMA "+check.name).Scan(&got); err != nil {
			t.Fatalf("read reader %s: %v", check.name, err)
		}
		if check.name == "busy_timeout" {
			if got < check.want {
				t.Fatalf("reader %s = %d, want at least %d", check.name, got, check.want)
			}
		} else if got != check.want {
			t.Fatalf("reader %s = %d, want %d", check.name, got, check.want)
		}
	}

	rows, err := conn.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		t.Fatalf("list reader databases: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sequence int
		var name, path string
		if err := rows.Scan(&sequence, &name, &path); err != nil {
			t.Fatalf("scan reader database identity: %v", err)
		}
		if name == "main" {
			return path
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate reader databases: %v", err)
	}
	t.Fatal("reader has no main database")
	return ""
}

func TestSQLiteReaderConnectionsKeepPragmasIdentityAndCloseWithDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	database, err := OpenDatabase(context.Background(), DatabaseConfig{
		Type:             "sqlite",
		DSN:              path,
		DatabaseIdentity: "reader-identity",
		MaxOpenConns:     2,
		MaxIdleConns:     2,
	})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	readerSQL, err := database.ReadGORM().DB()
	if err != nil {
		t.Fatalf("acquire reader pool: %v", err)
	}
	if readerSQL == database.SQLDB() {
		t.Fatal("file SQLite reader aliases the single writer pool")
	}
	ctx := context.Background()
	first, err := readerSQL.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire first reader connection: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := readerSQL.Conn(ctx)
	if err != nil {
		first.Close()
		t.Fatalf("acquire second reader connection: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	firstPath := sqliteConnectionSettings(t, ctx, first)
	secondPath := sqliteConnectionSettings(t, ctx, second)
	if firstPath == "" || firstPath != secondPath {
		t.Fatalf("reader database identities differ: first=%q second=%q", firstPath, secondPath)
	}
	writerPath := ""
	writerConn, err := database.SQLDB().Conn(ctx)
	if err != nil {
		t.Fatalf("acquire writer connection: %v", err)
	}
	t.Cleanup(func() { _ = writerConn.Close() })
	rows, err := writerConn.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		t.Fatalf("list writer databases: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("close writer database list: %v", err)
		}
	}()
	for rows.Next() {
		var sequence int
		var name, reportedPath string
		if err := rows.Scan(&sequence, &name, &reportedPath); err != nil {
			t.Fatalf("scan writer database identity: %v", err)
		}
		if name == "main" {
			writerPath = reportedPath
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate writer databases: %v", err)
	}
	if writerPath == "" || writerPath != firstPath {
		t.Fatalf("writer database %q differs from reader database %q", writerPath, firstPath)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first reader connection: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second reader connection: %v", err)
	}
	if err := writerConn.Close(); err != nil {
		t.Fatalf("close writer connection: %v", err)
	}

	writerSQL := database.SQLDB()
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if err := writerSQL.PingContext(ctx); err == nil {
		t.Fatal("writer pool remained usable after Database.Close")
	}
	if err := readerSQL.PingContext(ctx); err == nil {
		t.Fatal("reader pool remained usable after Database.Close")
	}
	if err := database.Close(); err != nil {
		t.Fatalf("repeat close: %v", err)
	}
}

func TestSQLiteMemoryDatabaseKeepsOneIdentityForReadsAndWrites(t *testing.T) {
	database, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: ":memory:"})
	if err != nil {
		t.Fatalf("open memory database: %v", err)
	}
	defer database.Close()

	if err := database.GORM().Exec("CREATE TABLE memory_reader_probe (value TEXT NOT NULL)").Error; err != nil {
		t.Fatalf("create memory probe: %v", err)
	}
	if err := database.GORM().Exec("INSERT INTO memory_reader_probe (value) VALUES (?)", "shared").Error; err != nil {
		t.Fatalf("write memory probe: %v", err)
	}
	var value string
	if err := database.ReadSnapshot(context.Background(), func(tx *gorm.DB) error {
		return tx.Raw("SELECT value FROM memory_reader_probe").Scan(&value).Error
	}); err != nil {
		t.Fatalf("read memory snapshot: %v", err)
	}
	if value != "shared" {
		t.Fatalf("memory snapshot value = %q, want shared", value)
	}
	if err := database.GORM().Exec("INSERT INTO memory_reader_probe (value) VALUES (?)", "writer-still-enabled").Error; err != nil {
		t.Fatalf("memory writer became query-only: %v", err)
	}
}

func TestDatabaseCloseContextCanCancelWaitingWithoutOrphaningPools(t *testing.T) {
	database, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "cancel-close.db")})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	writerSQL := database.SQLDB()
	readerSQL, err := database.ReadGORM().DB()
	if err != nil {
		t.Fatalf("acquire reader pool: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := database.CloseContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled close error = %v, want context.Canceled", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("wait for initiated close: %v", err)
	}
	if err := writerSQL.PingContext(context.Background()); err == nil {
		t.Fatal("writer pool survived canceled close")
	}
	if err := readerSQL.PingContext(context.Background()); err == nil {
		t.Fatal("reader pool survived canceled close")
	}
}

func TestSQLiteDatabaseFilePathResolvesFileURIs(t *testing.T) {
	for _, tc := range []struct{ dsn, want string }{
		{"file:relative%20name.db?cache=private", "relative name.db"},
		{"/tmp/a%20b.db", filepath.FromSlash("/tmp/a%20b.db")},
		{"/tmp/a%bad.db", filepath.FromSlash("/tmp/a%bad.db")},
		{"relative.db?cache=private", "relative.db"},
		{"file:///tmp/events%20name.db?mode=rw", filepath.FromSlash("/tmp/events name.db")},
		{"file://localhost/tmp/events.db", filepath.FromSlash("/tmp/events.db")},
		{"file:/tmp/events.db", filepath.FromSlash("/tmp/events.db")},
		{"file:memory-db?mode=memory", ""},
		{"file::memory:?cache=shared", ""},
		{":memory:", ""},
		{"file://remote.example/tmp/events.db", ""},
	} {
		if got := sqliteDatabaseFilePath(tc.dsn); got != tc.want {
			t.Errorf("path(%q)=%q, want %q", tc.dsn, got, tc.want)
		}
	}
	if runtime.GOOS == "windows" {
		if got := sqliteDatabaseFilePath("file:///C:/events.db"); got != filepath.FromSlash("C:/events.db") {
			t.Fatalf("Windows file URI=%q", got)
		}
	}
}
