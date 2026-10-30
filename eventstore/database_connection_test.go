package eventstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type databaseLogCapture struct {
	messages []string
}

func (c *databaseLogCapture) Infof(format string, args ...any) {
	c.messages = append(c.messages, fmt.Sprintf(format, args...))
}

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

func TestOpenDatabaseSQLitePragmasSurviveBadConnectionReplacement(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()

	conn, err := db.SQLDB().Conn(ctx)
	if err != nil {
		t.Fatalf("acquire sqlite connection: %v", err)
	}
	if err := conn.Raw(func(any) error { return driver.ErrBadConn }); !errors.Is(err, driver.ErrBadConn) {
		t.Fatalf("discard sqlite connection error = %v, want driver.ErrBadConn", err)
	}
	if err := conn.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("close discarded sqlite connection: %v", err)
	}

	var journalMode string
	if err := db.SQLDB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read replacement journal_mode: %v", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("replacement journal_mode = %q, want wal", journalMode)
	}
	for _, check := range []struct {
		pragma string
		want   int
	}{
		{pragma: "foreign_keys", want: 1},
		{pragma: "busy_timeout", want: 15000},
		{pragma: "synchronous", want: 2},
	} {
		var got int
		if err := db.SQLDB().QueryRowContext(ctx, "PRAGMA "+check.pragma).Scan(&got); err != nil {
			t.Fatalf("read replacement %s: %v", check.pragma, err)
		}
		if check.pragma == "busy_timeout" && got < check.want {
			t.Fatalf("replacement %s = %d, want at least %d", check.pragma, got, check.want)
		}
		if check.pragma != "busy_timeout" && got != check.want {
			t.Fatalf("replacement %s = %d, want %d", check.pragma, got, check.want)
		}
	}
}

func TestLogDatabaseFileStateReportsCreationAndReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	capture := &databaseLogCapture{}

	if err := os.WriteFile(path, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	logDatabaseFileState(capture, "sqlite", path, false)
	if len(capture.messages) != 1 || !strings.Contains(capture.messages[0], "自动创建") {
		t.Fatalf("creation log = %#v, want one creation message", capture.messages)
	}

	logDatabaseFileState(capture, "sqlite", path, true)
	if len(capture.messages) != 2 || !strings.Contains(capture.messages[1], "复用") {
		t.Fatalf("reuse log = %#v, want one reuse message", capture.messages)
	}
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

func TestSafeDatabaseErrorPreservesSQLiteConstraintClass(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	defer db.Close()

	_, constraintErr := db.SQLDB().ExecContext(ctx, `INSERT INTO event_global_sequence
		(singleton_id, next_position, updated_at) VALUES ('default', 1, CURRENT_TIMESTAMP)`)
	if constraintErr == nil {
		t.Fatal("duplicate singleton insert succeeded")
	}
	type sqliteCodedError interface {
		error
		Code() int
	}
	var rawCode sqliteCodedError
	if !errors.As(constraintErr, &rawCode) {
		t.Fatalf("constraint error has no SQLite code: %T %v", constraintErr, constraintErr)
	}

	safeErr := safeDatabaseError("write singleton", "sqlite", constraintErr)
	var preservedCode sqliteCodedError
	if !errors.As(safeErr, &preservedCode) {
		t.Fatalf("safe error discarded SQLite constraint class: %v", safeErr)
	}
	if preservedCode.Code() != rawCode.Code() {
		t.Fatalf("safe SQLite code = %d, want %d", preservedCode.Code(), rawCode.Code())
	}
	for _, fragment := range []string{"write singleton", "sqlite", "constraint"} {
		if !strings.Contains(strings.ToLower(safeErr.Error()), fragment) {
			t.Fatalf("safe SQLite error %q lacks diagnostic fragment %q", safeErr, fragment)
		}
	}
}

func TestSafeDatabaseErrorRedactsRemoteDSNAndPreservesCause(t *testing.T) {
	const (
		password = "db-password-redact-me"
		token    = "api-token-redact-me"
	)
	remoteDSN := "postgres://alice:" + password + "@db.example/events?sslmode=require&token=" + token
	cause := &url.Error{Op: "dial", URL: remoteDSN, Err: syscall.ECONNREFUSED}

	safeErr := safeDatabaseError("connect", "postgres", cause)
	if !errors.Is(safeErr, syscall.ECONNREFUSED) {
		t.Fatalf("safe remote error discarded connection cause: %v", safeErr)
	}
	lower := strings.ToLower(safeErr.Error())
	for _, fragment := range []string{"connect", "postgres", "refused"} {
		if !strings.Contains(lower, fragment) {
			t.Fatalf("safe remote error %q lacks diagnostic fragment %q", safeErr, fragment)
		}
	}
	for _, forbidden := range []string{remoteDSN, password, token, "alice:"} {
		if strings.Contains(safeErr.Error(), forbidden) {
			t.Fatalf("safe remote error leaked %q: %v", forbidden, safeErr)
		}
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

func TestOpenDatabaseRejectsUnverifiedMySQLTLSModes(t *testing.T) {
	for _, mode := range []string{"preferred", "custom"} {
		_, err := OpenDatabase(context.Background(), DatabaseConfig{
			Type:      "mysql",
			DSN:       "alice:secret@tcp(db.example:3306)/events?tls=" + mode,
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
	first, lockErr := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: dsn})
	if lockErr != nil {
		t.Fatalf("open first database: %v", lockErr)
	}
	defer first.Close()
	second, lockErr := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: dsn})
	if lockErr != nil {
		t.Fatalf("open second database: %v", lockErr)
	}
	defer second.Close()

	if _, err := first.SQLDB().ExecContext(context.Background(), "CREATE TABLE IF NOT EXISTS writer_lock_probe (id INTEGER)"); err != nil {
		t.Fatalf("create writer probe: %v", err)
	}
	tx, lockErr := first.SQLDB().BeginTx(context.Background(), nil)
	if lockErr != nil {
		t.Fatalf("begin first writer: %v", lockErr)
	}
	defer func() {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			t.Errorf("rollback first writer: %v", rollbackErr)
		}
	}()
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

func TestDatabaseTLSAndHostDuplicateSettingsFailClosed(t *testing.T) {
	if dsnDeclaresVerifiedTLS("mysql", "user:pass@tcp(db:3306)/events?tls=true&tls=skip-verify") {
		t.Fatal("duplicate MySQL TLS settings accepted")
	}

	if dsnDeclaresVerifiedTLS("postgres", "postgres://db/events?sslmode=verify-full&sslmode=disable") {
		t.Fatal("duplicate PostgreSQL URL sslmode settings accepted")
	}
	if dsnDeclaresVerifiedTLS("postgres", "sslmode=verify-full sslmode=disable host=localhost") {
		t.Fatal("duplicate PostgreSQL keyword sslmode settings accepted")
	}
	if isLoopbackOrUnixDSN("postgres", "host=localhost host=evil.example dbname=events") {
		t.Fatal("duplicate PostgreSQL keyword host settings accepted")
	}
	if isLoopbackOrUnixDSN("postgres", "postgres://localhost/events?host=/tmp/pg,evil.example") {
		t.Fatal("mixed PostgreSQL URL host list accepted")
	}
	if !isLoopbackOrUnixDSN("postgres", "postgres://localhost/events?host=127.0.0.1,localhost") {
		t.Fatal("all-loopback PostgreSQL URL host list rejected")
	}
	if dsnDeclaresVerifiedTLS("postgres", "postgres://db/events?foo=1 sslmode=verify-full") {
		t.Fatal("hybrid PostgreSQL URL/keyword TLS settings accepted")
	}
	if dsnDeclaresVerifiedTLS("postgres", "postgres://db/events sslmode=verify-full") {
		t.Fatal("URL DSN with keyword TLS fragment accepted")
	}
	if isLoopbackOrUnixDSN("postgres", "postgres://localhost/events host=evil.example") {
		t.Fatal("URL DSN with keyword host fragment accepted")
	}
	if isLoopbackOrUnixDSN("mysql", "user:pass@tcp(evil.example:3306)/events?marker=@unix(/tmp/mysql.sock)") {
		t.Fatal("MySQL DSN marker text incorrectly qualified as loopback")
	}
	if !isLoopbackOrUnixDSN("mysql", "user:pass@tcp(127.0.0.1:3306)/events") {
		t.Fatal("loopback MySQL TCP DSN rejected")
	}
}
