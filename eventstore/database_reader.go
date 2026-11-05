package eventstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// ReadGORM returns the Database-owned query handle. File-backed SQLite uses a
// distinct query-only pool; remote and in-memory engines retain their existing
// pool because their connection or engine semantics already define the limit.
func (db *Database) ReadGORM() *gorm.DB {
	if db == nil {
		return nil
	}
	return db.readerGORM
}

// ReadSnapshot runs read inside one short, read-only transaction. SQLite starts
// a deferred transaction on the reader DSN; remote engines use repeatable read
// so metadata and rows are selected from the same logical snapshot.
func (db *Database) ReadSnapshot(ctx context.Context, read func(*gorm.DB) error) error {
	if db == nil || db.readerGORM == nil {
		return errors.New("eventstore: database reader unavailable")
	}
	if read == nil {
		return errors.New("eventstore: database read callback required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	options := &sql.TxOptions{ReadOnly: true}
	if db.readerGORM.Name() != "sqlite" {
		options.Isolation = sql.LevelRepeatableRead
	}
	return db.readerGORM.WithContext(ctx).Transaction(read, options)
}

func openSQLiteReader(
	ctx context.Context,
	dsn string,
	databasePath string,
	config DatabaseConfig,
	connectTimeout time.Duration,
	queryTimeout time.Duration,
) (*gorm.DB, *sql.DB, error) {
	readerDSN, err := sqliteReaderDSN(dsn)
	if err != nil {
		return nil, nil, err
	}
	readerGORM, err := gorm.Open(sqlite.Open(readerDSN), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}
	readerSQL, err := readerGORM.DB()
	if err != nil {
		return nil, nil, err
	}
	maxOpen := config.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = defaultDatabaseMaxOpenConns
	}
	maxIdle := config.MaxIdleConns
	if maxIdle <= 0 || maxIdle > maxOpen {
		maxIdle = defaultDatabaseMaxIdleConns
		if maxIdle > maxOpen {
			maxIdle = maxOpen
		}
	}
	readerSQL.SetMaxOpenConns(maxOpen)
	// Reader validation must not leave a physical read-only connection pinned:
	// SQLite journal-mode transitions require every other handle closed. Restore
	// the configured idle capacity only after startup validation completes.
	readerSQL.SetMaxIdleConns(0)
	readerSQL.SetConnMaxLifetime(max(config.ConnMaxLifetime, 0))
	readerGORM.DefaultContextTimeout = queryTimeout

	connectCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := readerSQL.PingContext(connectCtx); err != nil {
		_ = readerSQL.Close()
		return nil, nil, err
	}
	if err := validateSQLiteReader(connectCtx, readerSQL, databasePath); err != nil {
		_ = readerSQL.Close()
		return nil, nil, err
	}
	readerSQL.SetMaxIdleConns(maxIdle)
	return readerGORM, readerSQL, nil
}

func sqliteReaderDSN(dsn string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if sqliteDatabaseFilePath(dsn) == "" {
		return "", errors.New("eventstore: SQLite reader requires a file database")
	}
	base, rawQuery, _ := strings.Cut(dsn, "?")
	if !strings.HasPrefix(strings.ToLower(base), "file:") {
		absolutePath, err := filepath.Abs(base)
		if err != nil {
			return "", fmt.Errorf("eventstore: resolve SQLite reader path: %w", err)
		}
		base = (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolutePath)}).String()
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("eventstore: parse SQLite reader DSN: %w", err)
	}

	pragmas := make([]string, 0, len(query["_pragma"])+4)
	for key, values := range query {
		switch strings.ToLower(key) {
		case "mode", "cache", "immutable", "_txlock":
			query.Del(key)
		case "_pragma":
			query.Del(key)
			for _, pragma := range values {
				switch sqlitePragmaName(pragma) {
				case "journal_mode", "foreign_keys", "busy_timeout", "synchronous", "query_only", "locking_mode", "read_uncommitted":
					continue
				default:
					pragmas = append(pragmas, pragma)
				}
			}
		}
	}
	query.Set("mode", "ro")
	query.Set("cache", "private")
	pragmas = append(pragmas,
		"foreign_keys(ON)",
		"busy_timeout(15000)",
		"synchronous(FULL)",
		"locking_mode(NORMAL)",
		"read_uncommitted(OFF)",
		"query_only(ON)",
	)
	query["_pragma"] = pragmas
	return base + "?" + query.Encode(), nil
}

func sqlitePragmaName(pragma string) string {
	pragma = strings.ToLower(strings.TrimSpace(pragma))
	if boundary := strings.IndexAny(pragma, "=("); boundary >= 0 {
		pragma = pragma[:boundary]
	}
	return strings.TrimSpace(pragma)
}

func validateSQLiteReader(ctx context.Context, reader *sql.DB, expectedPath string) error {
	conn, err := reader.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	var journalMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return errors.New("reader journal mode is not WAL")
	}
	var lockingMode string
	if err := conn.QueryRowContext(ctx, "PRAGMA locking_mode").Scan(&lockingMode); err != nil {
		return err
	}
	if !strings.EqualFold(lockingMode, "normal") {
		return errors.New("reader SQLite locking mode is not normal")
	}
	for _, check := range []struct {
		name string
		want int
	}{
		{name: "foreign_keys", want: 1},
		{name: "busy_timeout", want: int(minimumSQLiteBusyTimeout / time.Millisecond)},
		{name: "synchronous", want: 2},
		{name: "read_uncommitted", want: 0},
		{name: "query_only", want: 1},
	} {
		var value int
		if err := conn.QueryRowContext(ctx, "PRAGMA "+check.name).Scan(&value); err != nil {
			return err
		}
		if check.name == "busy_timeout" {
			if value < check.want {
				return errors.New("reader SQLite busy timeout is unsafe")
			}
		} else if value != check.want {
			return fmt.Errorf("reader SQLite %s setting is unsafe", check.name)
		}
	}
	actualPath, err := sqliteMainDatabasePath(ctx, conn)
	if err != nil {
		return err
	}
	if !sameSQLiteDatabaseFile(expectedPath, actualPath) {
		return errors.New("reader and writer SQLite database identities differ")
	}
	return nil
}

func sqliteMainDatabasePath(ctx context.Context, conn *sql.Conn) (string, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var sequence int
		var name, path string
		if err := rows.Scan(&sequence, &name, &path); err != nil {
			return "", err
		}
		if name == "main" {
			return path, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", errors.New("reader SQLite main database identity is missing")
}

func sameSQLiteDatabaseFile(expectedPath, actualPath string) bool {
	expectedInfo, expectedErr := os.Stat(expectedPath)
	actualInfo, actualErr := os.Stat(actualPath)
	if expectedErr == nil && actualErr == nil {
		return os.SameFile(expectedInfo, actualInfo)
	}
	expectedAbsolute, expectedErr := filepath.Abs(expectedPath)
	actualAbsolute, actualErr := filepath.Abs(actualPath)
	return expectedErr == nil && actualErr == nil && filepath.Clean(expectedAbsolute) == filepath.Clean(actualAbsolute)
}

// Close releases both owned pools. It is safe to call more than once.
func (db *Database) Close() error {
	return db.CloseContext(context.Background())
}

// CloseContext initiates closure of every owned pool and allows the caller to
// stop waiting. Cancellation never abandons a pool: a later Close waits for the
// same in-flight close operation.
func (db *Database) CloseContext(ctx context.Context) error {
	if db == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	done := db.startClose()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-done:
		return db.completedCloseError()
	default:
	}
	select {
	case <-done:
		return db.completedCloseError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (db *Database) startClose() <-chan struct{} {
	db.mu.Lock()
	if !db.closed {
		db.closed = true
		db.closeDone = make(chan struct{})
		done := db.closeDone
		writer := db.sqlDB
		reader := db.readerSQLDB
		ownsReader := db.ownsReaderPool
		go func() {
			closeErr := closeDatabasePools(writer, reader, ownsReader)
			db.mu.Lock()
			db.closeErr = closeErr
			close(done)
			db.mu.Unlock()
		}()
	}
	done := db.closeDone
	db.mu.Unlock()
	return done
}

func (db *Database) completedCloseError() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.closeErr
}

func closeDatabasePools(writer, reader *sql.DB, ownsReader bool) error {
	var readerErr, writerErr error
	if ownsReader && reader != nil && reader != writer {
		if err := reader.Close(); err != nil {
			readerErr = fmt.Errorf("close database reader: %w", err)
		}
	}
	if writer != nil {
		if err := writer.Close(); err != nil {
			writerErr = fmt.Errorf("close database writer: %w", err)
		}
	}
	return errors.Join(readerErr, writerErr)
}
