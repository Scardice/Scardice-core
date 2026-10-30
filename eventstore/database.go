package eventstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sealdicelogger "Scardice-core/logger"

	"github.com/glebarez/sqlite"
	mysqlDriver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const (
	defaultDatabaseConnectTimeout = 15 * time.Second
	defaultDatabaseQueryTimeout   = 15 * time.Second
	defaultDatabaseMaxOpenConns   = 8
	defaultDatabaseMaxIdleConns   = 4
	defaultDatabaseMaxLifetime    = 30 * time.Minute
	minimumSQLiteBusyTimeout      = 15 * time.Second
)

// DatabaseConfig controls one independently owned event database. Remote
// databases require TLSVerify unless AllowInsecureLoopback is explicitly set
// for a loopback or Unix-socket deployment.
type DatabaseConfig struct {
	Type string
	DSN  string

	// KeySource is required for remote databases and is carried to stores
	// opened from this database. SQLite callers may supply it explicitly when
	// using A6 encrypted repositories.
	KeySource        KeySource
	DatabaseIdentity string

	TLSVerify             bool
	AllowInsecureLoopback bool

	ConnectTimeout  time.Duration
	QueryTimeout    time.Duration
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// Database owns exactly one GORM database and its underlying SQL pool.
type Database struct {
	gormDB           *gorm.DB
	sqlDB            *sql.DB
	databaseIdentity string
	keySource        KeySource

	mu       sync.Mutex
	closed   bool
	closeErr error
}

// GORM returns the database handle owned by this instance.
func (db *Database) GORM() *gorm.DB {
	if db == nil {
		return nil
	}
	return db.gormDB
}

// SQLDB returns the underlying pool for settings and dialect-specific work.
func (db *Database) SQLDB() *sql.DB {
	if db == nil {
		return nil
	}
	return db.sqlDB
}

// Close releases the pool. It is safe to call more than once on the same
// Database; only the first call closes the owned pool.
func (db *Database) Close() error {
	if db == nil {
		return nil
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return db.closeErr
	}
	db.closed = true
	if db.sqlDB == nil {
		return nil
	}
	db.closeErr = db.sqlDB.Close()
	return db.closeErr
}

// statementTimeoutParent preserves caller cancellation and values while hiding
// its lifecycle deadline from GORM. GORM can then derive a fresh QueryTimeout
// for every statement instead of treating one timeout as the whole migration.
type statementTimeoutParent struct {
	context.Context
}

func (statementTimeoutParent) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func databaseLifecycleError(ctx context.Context, cause error) error {
	if ctx == nil || ctx.Err() == nil || errors.Is(cause, ctx.Err()) {
		return cause
	}
	return errors.Join(cause, ctx.Err())
}

// OpenDatabase opens, migrates, initializes, and validates one event database.
func OpenDatabase(ctx context.Context, config DatabaseConfig) (*Database, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dbType := strings.ToLower(strings.TrimSpace(config.Type))
	if dbType == "" {
		dbType = "sqlite"
	}
	if dbType != "sqlite" && dbType != "sqlite3" && config.KeySource == nil {
		return nil, ErrKeySourceUnavailable
	}
	connectTimeout := config.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultDatabaseConnectTimeout
	}
	queryTimeout := config.QueryTimeout
	if queryTimeout <= 0 {
		queryTimeout = defaultDatabaseQueryTimeout
	}

	var (
		gormDB       *gorm.DB
		err          error
		sqlitePath   string
		sqliteExists bool
	)
	switch dbType {
	case "sqlite", "sqlite3":
		dsn := config.DSN
		if dsn == "" {
			dataDir := os.Getenv("DATADIR")
			if dataDir == "" {
				dataDir = "."
			}
			dsn = filepath.Join(dataDir, "events.db")
		}
		sqlitePath = sqliteDatabaseFilePath(dsn)
		sqliteExists = databaseFileExists(sqlitePath)
		gormDB, err = gorm.Open(sqlite.Open(sqliteDSN(dsn)), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Silent),
		})
	case "mysql":
		if err = validateRemoteConfig(dbType, config); err == nil {
			gormDB, err = gorm.Open(mysql.New(mysql.Config{DSN: config.DSN, SkipInitializeWithVersion: true}), &gorm.Config{
				Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
				DisableAutomaticPing:                     true,
				DisableForeignKeyConstraintWhenMigrating: true,
			})
		}
	case "postgres", "postgresql":
		if err = validateRemoteConfig(dbType, config); err == nil {
			gormDB, err = gorm.Open(postgres.Open(config.DSN), &gorm.Config{
				Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
				DisableAutomaticPing:                     true,
				DisableForeignKeyConstraintWhenMigrating: true,
			})
		}
	default:
		return nil, fmt.Errorf("event database: unsupported type %q", dbType)
	}
	if err != nil {
		return nil, safeDatabaseError("open", dbType, err)
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, safeDatabaseError("acquire pool", dbType, err)
	}
	owned := &Database{gormDB: gormDB, sqlDB: sqlDB, keySource: config.KeySource, databaseIdentity: config.DatabaseIdentity}
	if dbType == "sqlite" || dbType == "sqlite3" {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
	} else {
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
		lifetime := config.ConnMaxLifetime
		if lifetime <= 0 {
			lifetime = defaultDatabaseMaxLifetime
		}
		sqlDB.SetMaxOpenConns(maxOpen)
		sqlDB.SetMaxIdleConns(maxIdle)
		sqlDB.SetConnMaxLifetime(lifetime)
	}

	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("connect", dbType, err)
	}
	if dbType == "sqlite" || dbType == "sqlite3" {
		if err := configureAndValidateSQLite(pingCtx, sqlDB); err != nil {
			_ = sqlDB.Close()
			return nil, safeDatabaseError("configure sqlite", dbType, err)
		}
	}
	schemaDB := gormDB.Session(&gorm.Session{Context: statementTimeoutParent{Context: ctx}})
	schemaDB.DefaultContextTimeout = queryTimeout
	if err := migrateSchema(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("migrate schema", dbType, databaseLifecycleError(ctx, err))
	}
	if err := initializeSingletons(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("initialize schema", dbType, databaseLifecycleError(ctx, err))
	}
	if err := validateSchema(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("validate schema", dbType, databaseLifecycleError(ctx, err))
	}
	if err := validateRequiredIndexes(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("validate indexes", dbType, databaseLifecycleError(ctx, err))
	}
	if sqlitePath != "" {
		logDatabaseFileState(sealdicelogger.M(), dbType, sqlitePath, sqliteExists)
	} else {
		sealdicelogger.M().Infof("事件数据库连接与 schema 初始化完成：type=%s", dbType)
	}
	return owned, nil
}

func sqliteDSN(dsn string) string {
	if dsn == ":memory:" {
		dsn = "file::memory:?cache=shared"
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	return dsn + separator +
		"_pragma=journal_mode%28WAL%29" +
		"&_pragma=foreign_keys%28ON%29" +
		"&_pragma=busy_timeout%2815000%29" +
		"&_pragma=synchronous%28FULL%29" +
		"&_txlock=immediate"
}

type databaseInitializationLogger interface {
	Infof(format string, args ...any)
}

func sqliteDatabaseFilePath(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" || dsn == ":memory:" {
		return ""
	}
	dsn = strings.TrimPrefix(dsn, "file:")
	if queryIndex := strings.IndexByte(dsn, '?'); queryIndex >= 0 {
		dsn = dsn[:queryIndex]
	}
	if dsn == "" || strings.HasPrefix(dsn, ":memory:") {
		return ""
	}
	return filepath.Clean(dsn)
}

func databaseFileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func logDatabaseFileState(log databaseInitializationLogger, dbType, path string, existed bool) {
	if log == nil || path == "" {
		return
	}
	if !existed {
		if !databaseFileExists(path) {
			return
		}
		log.Infof("自动创建%s事件数据库文件：path=%s", dbType, path)
		return
	}
	log.Infof("复用%s事件数据库文件：path=%s", dbType, path)
}

func configureAndValidateSQLite(ctx context.Context, sqlDB *sql.DB) error {
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 15000",
		"PRAGMA synchronous = FULL",
	} {
		if _, err := sqlDB.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	var journalMode string
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return errors.New("journal mode is not WAL")
	}
	var foreignKeys, busyTimeout, synchronous int
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return err
	}
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return err
	}
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return err
	}
	if foreignKeys != 1 || busyTimeout < int(minimumSQLiteBusyTimeout/time.Millisecond) || synchronous != 2 {
		return errors.New("effective SQLite PRAGMA settings are unsafe")
	}
	return nil
}

func validateRemoteConfig(dbType string, config DatabaseConfig) error {
	if strings.TrimSpace(config.DSN) == "" {
		return errors.New("remote event database requires an explicit DSN")
	}
	if config.AllowInsecureLoopback {
		if !isLoopbackOrUnixDSN(dbType, config.DSN) {
			return errors.New("insecure TLS exception is limited to loopback or Unix-socket DSNs")
		}
		return nil
	}
	if !config.TLSVerify {
		return errors.New("remote event database requires explicit TLS verification")
	}
	if !dsnDeclaresVerifiedTLS(dbType, config.DSN) {
		return errors.New("remote event database DSN does not declare verified TLS")
	}
	return nil
}

// ValidateRemoteDatabaseConfig applies the same TLS and host checks used by
// OpenDatabase without opening or mutating the remote database.
func ValidateRemoteDatabaseConfig(config DatabaseConfig) error {
	dbType := strings.ToLower(strings.TrimSpace(config.Type))
	if dbType != "mysql" && dbType != "postgres" && dbType != "postgresql" {
		return fmt.Errorf("event database: unsupported remote type %q", dbType)
	}
	return validateRemoteConfig(dbType, config)
}
func dsnDeclaresVerifiedTLS(dbType, dsn string) bool {
	if dbType == "mysql" {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return false
		}
		values := parsed.Query()["tls"]
		return len(values) == 1 && strings.EqualFold(values[0], "true")
	}
	if strings.Contains(dsn, "://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return false
		}
		values := parsed.Query()["sslmode"]
		if len(values) != 1 {
			return false
		}
		mode := strings.ToLower(values[0])
		return mode == "verify-full" || mode == "verify-ca"
	}
	if !validKeywordDSN(dsn) {
		return false
	}
	mode := ""
	count := 0
	for _, field := range strings.Fields(dsn) {
		key, value, _ := strings.Cut(field, "=")
		if key != "sslmode" {
			continue
		}
		mode = strings.ToLower(value)
		count++
	}
	if count != 1 {
		return false
	}
	return mode == "verify-full" || mode == "verify-ca"
}

func validKeywordDSN(dsn string) bool {
	fields := strings.Fields(dsn)
	if len(fields) == 0 {
		return false
	}
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" || value == "" || strings.ContainsAny(key+value, "'\"") {
			return false
		}
	}
	return true
}

func isLoopbackOrUnixDSN(dbType, dsn string) bool {
	if dbType == "mysql" {
		cfg, err := mysqlDriver.ParseDSN(dsn)
		if err != nil {
			return false
		}
		switch cfg.Net {
		case "unix":
			return cfg.Addr != ""
		case "tcp":
			host, _, err := net.SplitHostPort(cfg.Addr)
			if err != nil {
				host = cfg.Addr
			}
			if host == "" {
				return false
			}
			ip := net.ParseIP(host)
			return host == "localhost" || (ip != nil && ip.IsLoopback())
		default:
			return false
		}
	}
	if strings.Contains(dsn, "://") {
		if strings.ContainsAny(dsn, " \t\r\n") {
			return false
		}
		parsed, err := url.Parse(dsn)
		if err != nil {
			return false
		}
		values := parsed.Query()["host"]
		if len(values) > 1 {
			return false
		}
		if len(values) == 1 {
			return allLoopbackOrUnixHosts(strings.Split(values[0], ","))
		}
		return allLoopbackOrUnixHosts([]string{parsed.Hostname()})
	}
	if strings.Contains(dsn, "host=") {
		if !validKeywordDSN(dsn) {
			return false
		}
		fields := strings.Fields(dsn)
		hostValue := ""
		hostCount := 0
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if key != "host" || !ok || value == "" {
				continue
			}
			hostValue = value
			hostCount++
		}
		return hostCount == 1 && allLoopbackOrUnixHosts(strings.Split(hostValue, ","))
	}
	return false
}

func allLoopbackOrUnixHosts(hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	for _, host := range hosts {
		host = strings.Trim(host, "'\"")
		if host == "" {
			return false
		}
		if strings.HasPrefix(host, "/") {
			continue
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return false
		}
	}
	return true
}

type databaseStageError struct {
	stage string
	cause error
}

func (e *databaseStageError) Error() string {
	return e.stage + ": " + e.cause.Error()
}

func (e *databaseStageError) Unwrap() error {
	return e.cause
}

func databaseStage(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	return &databaseStageError{stage: stage, cause: cause}
}

type databaseFailureError struct {
	operation string
	dbType    string
	class     string
	detail    string
	cause     error
}

func (e *databaseFailureError) Error() string {
	message := fmt.Sprintf("event database %s failed for %s", e.operation, e.dbType)
	if e.class != "" {
		message += " [" + e.class + "]"
	}
	if e.detail != "" {
		message += ": " + e.detail
	}
	return message
}

func (e *databaseFailureError) Unwrap() error {
	return e.cause
}

var (
	databaseURLCredentialsPattern   = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s]+@`)
	databaseMySQLCredentialsPattern = regexp.MustCompile(`(?i)(\b[^\s:/@]+:)[^@\s]+(@(?:tcp|unix)\()`)
	databaseSecretPattern           = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|access_token|secret)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)`)
)

func safeDatabaseError(operation, dbType string, cause error) error {
	class, detail := databaseErrorDiagnostic(dbType, cause)
	return &databaseFailureError{
		operation: operation,
		dbType:    dbType,
		class:     class,
		detail:    detail,
		cause:     cause,
	}
}

func databaseErrorDiagnostic(dbType string, cause error) (string, string) {
	if cause == nil {
		return "unknown cause", ""
	}
	var stageErr *databaseStageError
	if errors.As(cause, &stageErr) {
		class, detail := databaseErrorDiagnostic(dbType, stageErr.cause)
		stage := "stage=" + stageErr.stage
		if detail == "" {
			return class, stage
		}
		return class, stage + ": " + detail
	}
	type sqliteCodedError interface {
		error
		Code() int
	}
	var sqliteErr sqliteCodedError
	if (dbType == "sqlite" || dbType == "sqlite3") && errors.As(cause, &sqliteErr) {
		code := sqliteErr.Code()
		class := fmt.Sprintf("sqlite %s code=%d", sqliteErrorClass(code), code)
		return class, redactDatabaseErrorText(sqliteErr.Error())
	}

	var urlErr *url.Error
	if errors.As(cause, &urlErr) {
		class := "remote URL error"
		if operation := strings.TrimSpace(urlErr.Op); operation != "" {
			class = "remote " + operation + " error"
		}
		if urlErr.Err == nil {
			return class, ""
		}
		return class, redactDatabaseErrorText(urlErr.Err.Error())
	}

	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(cause, &mysqlErr) {
		class := fmt.Sprintf("mysql code=%d", mysqlErr.Number)
		if mysqlErr.SQLState != [5]byte{} {
			class += " sqlstate=" + string(mysqlErr.SQLState[:])
		}
		return class, redactDatabaseErrorText(mysqlErr.Message)
	}

	type sqlStateError interface {
		error
		SQLState() string
	}
	var stateErr sqlStateError
	if errors.As(cause, &stateErr) {
		return "sqlstate=" + stateErr.SQLState(), redactDatabaseErrorText(stateErr.Error())
	}
	switch {
	case errors.Is(cause, context.Canceled):
		return "context canceled", ""
	case errors.Is(cause, context.DeadlineExceeded):
		return "context deadline", ""
	}
	var networkErr net.Error
	if errors.As(cause, &networkErr) {
		class := "network error"
		if networkErr.Timeout() {
			class = "network timeout"
		}
		return class, redactDatabaseErrorText(networkErr.Error())
	}
	return fmt.Sprintf("cause %T", cause), redactDatabaseErrorText(cause.Error())
}

func sqliteErrorClass(code int) string {
	switch code & 0xff {
	case 1:
		return "error"
	case 5:
		return "busy"
	case 6:
		return "locked"
	case 8:
		return "readonly"
	case 9:
		return "interrupted"
	case 10:
		return "I/O error"
	case 11:
		return "corrupt"
	case 13:
		return "full"
	case 14:
		return "cannot open"
	case 19:
		return "constraint"
	case 23:
		return "authorization"
	case 26:
		return "not a database"
	default:
		return "error"
	}
}

func redactDatabaseErrorText(message string) string {
	message = databaseURLCredentialsPattern.ReplaceAllString(message, "${1}[REDACTED]@")
	message = databaseMySQLCredentialsPattern.ReplaceAllString(message, "${1}[REDACTED]${2}")
	message = databaseSecretPattern.ReplaceAllString(message, "${1}${2}[REDACTED]")
	message = strings.TrimSpace(message)
	if !utf8.ValidString(message) {
		message = strings.ToValidUTF8(message, "\uFFFD")
	}
	const maximumDatabaseErrorDetailBytes = 512
	if len(message) <= maximumDatabaseErrorDetailBytes {
		return message
	}
	end := maximumDatabaseErrorDetailBytes
	for end > 0 && !utf8.RuneStart(message[end]) {
		end--
	}
	return message[:end] + "..."
}

const sqliteOperationArtifactsDDL = `CREATE TABLE operation_artifacts (
	artifact_id TEXT NOT NULL PRIMARY KEY,
	version INTEGER NOT NULL,
	operation_id TEXT NOT NULL,
	owner_principal_id TEXT NOT NULL,
	media_type TEXT NOT NULL,
	safe_filename TEXT,
	size INTEGER NOT NULL,
	status TEXT NOT NULL,
	ciphertext BLOB,
	nonce BLOB,
	encryption_key_id TEXT,
	payload_version INTEGER NOT NULL DEFAULT 1,
	expires_at DATETIME NOT NULL,
	consumed_at DATETIME,
	FOREIGN KEY(operation_id) REFERENCES operations(operation_id) ON UPDATE RESTRICT ON DELETE RESTRICT
)`

func ensureSQLiteOperationArtifacts(db *gorm.DB) error {
	var tableCount int
	if err := db.Raw(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'operation_artifacts'`,
	).Scan(&tableCount).Error; err != nil {
		return err
	}
	if tableCount == 0 {
		return db.Exec(sqliteOperationArtifactsDDL).Error
	}

	type columnRow struct {
		Name    string
		NotNull int `gorm:"column:notnull"`
	}
	var columnRows []columnRow
	if err := db.Raw(
		`SELECT name, "notnull" FROM pragma_table_info('operation_artifacts')`,
	).Scan(&columnRows).Error; err != nil {
		return err
	}
	type columnInfo struct{ notNull int }
	columns := make(map[string]columnInfo, len(columnRows))
	for _, column := range columnRows {
		columns[column.Name] = columnInfo{notNull: column.NotNull}
	}
	required := []string{"artifact_id", "operation_id", "owner_principal_id", "media_type", "safe_filename", "size", "status", "ciphertext", "nonce", "encryption_key_id", "payload_version", "expires_at", "consumed_at"}
	for _, column := range required {
		if _, ok := columns[column]; !ok {
			if column == "payload_version" {
				continue
			}
			return fmt.Errorf("SQLite operation_artifacts schema is missing %s", column)
		}
	}
	versionPresent := false
	versionNotNull := false
	if info, ok := columns["version"]; ok {
		versionPresent = true
		versionNotNull = info.notNull == 1
	}

	type foreignKeyRow struct {
		Table    string `gorm:"column:table"`
		From     string `gorm:"column:from"`
		To       string `gorm:"column:to"`
		OnUpdate string `gorm:"column:on_update"`
		OnDelete string `gorm:"column:on_delete"`
	}
	var foreignKeys []foreignKeyRow
	if err := db.Raw(
		`SELECT "table", "from", "to", on_update, on_delete FROM pragma_foreign_key_list('operation_artifacts')`,
	).Scan(&foreignKeys).Error; err != nil {
		return err
	}
	fkReady := false
	for _, foreignKey := range foreignKeys {
		if foreignKey.Table == tableOperations && foreignKey.From == "operation_id" && foreignKey.To == "operation_id" &&
			strings.EqualFold(foreignKey.OnUpdate, "RESTRICT") && strings.EqualFold(foreignKey.OnDelete, "RESTRICT") {
			fkReady = true
			break
		}
	}
	payloadVersionPresent := false
	if info, ok := columns["payload_version"]; ok {
		payloadVersionPresent = info.notNull == 1
	}
	if versionPresent && versionNotNull && payloadVersionPresent && fkReady {
		return nil
	}

	var indexOwner struct {
		Table string `gorm:"column:tbl_name"`
	}
	indexQuery := db.Raw(
		`SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?`,
		"ux_operation_artifacts_artifact_id",
	).Scan(&indexOwner)
	if indexQuery.Error != nil {
		return indexQuery.Error
	}
	if indexQuery.RowsAffected != 0 && indexOwner.Table != tableOperationArtifacts {
		return fmt.Errorf("SQLite index name ux_operation_artifacts_artifact_id is owned by %s", indexOwner.Table)
	}
	if versionPresent && !versionNotNull {
		var nullVersions int
		if err := db.Raw(
			`SELECT COUNT(*) FROM operation_artifacts WHERE version IS NULL`,
		).Scan(&nullVersions).Error; err != nil {
			return err
		}
		if nullVersions != 0 {
			return errors.New("SQLite operation_artifacts contains NULL versions")
		}
	}
	var orphanCount int
	if err := db.Raw(
		`SELECT COUNT(*) FROM operation_artifacts AS a LEFT JOIN operations AS o ON o.operation_id = a.operation_id WHERE o.operation_id IS NULL`,
	).Scan(&orphanCount).Error; err != nil {
		return err
	}
	if orphanCount != 0 {
		return errors.New("SQLite operation_artifacts contains orphan operation references")
	}

	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	rollback := func(cause error) error {
		_ = tx.Rollback().Error
		return cause
	}
	if err := tx.Exec(`DROP INDEX IF EXISTS ux_operation_artifacts_artifact_id`).Error; err != nil {
		return rollback(err)
	}
	if err := tx.Exec(`ALTER TABLE operation_artifacts RENAME TO operation_artifacts_legacy`).Error; err != nil {
		return rollback(err)
	}
	if err := tx.Exec(sqliteOperationArtifactsDDL).Error; err != nil {
		return rollback(err)
	}
	selectColumns := make([]string, 0, len(required)+1)
	for _, column := range required {
		if column == "payload_version" && !payloadVersionPresent {
			selectColumns = append(selectColumns, "1")
		} else {
			selectColumns = append(selectColumns, `"`+column+`"`)
		}
	}
	if versionPresent {
		selectColumns = append([]string{`"version"`}, selectColumns...)
	} else {
		selectColumns = append([]string{"1"}, selectColumns...)
	}
	if err := tx.Exec(`INSERT INTO operation_artifacts (` + strings.Join(append([]string{"version"}, required...), ", ") + `) SELECT ` + strings.Join(selectColumns, ", ") + ` FROM operation_artifacts_legacy`).Error; err != nil {
		return rollback(err)
	}
	if err := tx.Exec(`DROP TABLE operation_artifacts_legacy`).Error; err != nil {
		return rollback(err)
	}
	if err := tx.Exec(`CREATE UNIQUE INDEX ux_operation_artifacts_artifact_id ON operation_artifacts(artifact_id)`).Error; err != nil {
		return rollback(err)
	}
	if err := tx.Commit().Error; err != nil {
		return err
	}
	return nil
}

const (
	sqliteSchemaMigrationsTable           = "eventstore_schema_migrations"
	projectionPayloadPresenceMigrationKey = "projection_payload_presence_v1"
	sqliteSchemaMigrationsDDL             = `CREATE TABLE IF NOT EXISTS eventstore_schema_migrations (
		migration_key TEXT NOT NULL PRIMARY KEY,
		completed_at DATETIME NOT NULL
	)`
	projectionPayloadPresenceBackfillStatement = `UPDATE projection_read_models
		SET payload_present = CASE WHEN payload IS NULL THEN FALSE ELSE TRUE END
		WHERE (payload IS NULL AND payload_present <> FALSE)
		   OR (payload IS NOT NULL AND payload_present <> TRUE)`
)

func sqliteSchemaMigrationCompleted(db *gorm.DB, migrationKey string) (bool, error) {
	var tableCount int
	if err := db.Raw(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
		sqliteSchemaMigrationsTable,
	).Scan(&tableCount).Error; err != nil {
		return false, err
	}
	if tableCount == 0 {
		return false, nil
	}
	var completed bool
	if err := db.Raw(
		`SELECT EXISTS(SELECT 1 FROM eventstore_schema_migrations WHERE migration_key = ?)`,
		migrationKey,
	).Scan(&completed).Error; err != nil {
		return false, err
	}
	return completed, nil
}

func migrateSQLiteProjectionPayloadPresence(db *gorm.DB) error {
	if !db.Migrator().HasTable(&projectionReadModelRow{}) {
		return nil
	}
	completed, err := sqliteSchemaMigrationCompleted(db, projectionPayloadPresenceMigrationKey)
	if err != nil {
		return err
	}
	if completed && db.Migrator().HasColumn(&projectionReadModelRow{}, "payload_present") {
		return nil
	}

	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	rollback := func(cause error) error {
		_ = tx.Rollback().Error
		return cause
	}
	completed, err = sqliteSchemaMigrationCompleted(tx, projectionPayloadPresenceMigrationKey)
	if err != nil {
		return rollback(err)
	}
	columnPresent := tx.Migrator().HasColumn(&projectionReadModelRow{}, "payload_present")
	if completed && columnPresent {
		return tx.Rollback().Error
	}
	if err := tx.Exec(sqliteSchemaMigrationsDDL).Error; err != nil {
		return rollback(err)
	}
	if !columnPresent {
		if err := tx.Migrator().AddColumn(&projectionReadModelRow{}, "PayloadPresent"); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Exec(projectionPayloadPresenceBackfillStatement).Error; err != nil {
		return rollback(err)
	}
	if err := tx.Exec(
		`INSERT INTO eventstore_schema_migrations (migration_key, completed_at)
		 VALUES (?, CURRENT_TIMESTAMP)
		 ON CONFLICT(migration_key) DO UPDATE SET completed_at = excluded.completed_at`,
		projectionPayloadPresenceMigrationKey,
	).Error; err != nil {
		return rollback(err)
	}
	return tx.Commit().Error
}

func sqliteQueueSchedulingSchemaUpgradeNeeded(db *gorm.DB) bool {
	if !db.Migrator().HasTable(&inboxMessageRow{}) ||
		!db.Migrator().HasTable(&outboxEffectRow{}) ||
		!db.Migrator().HasTable(&laneHeadRow{}) {
		return false
	}
	for _, check := range []struct {
		model  any
		column string
		index  string
	}{
		{model: &inboxMessageRow{}, column: "scheduling_version", index: "ix_inbox_scheduling_version"},
		{model: &outboxEffectRow{}, column: "scheduling_version", index: "ix_outbox_scheduling_version"},
		{model: &laneHeadRow{}, column: "scheduling_version", index: "ix_lane_heads_scheduling_version"},
	} {
		if !db.Migrator().HasColumn(check.model, check.column) ||
			!db.Migrator().HasIndex(check.model, check.index) {
			return true
		}
	}
	return false
}

func migrateSchema(db *gorm.DB) error {
	sqliteProjectionMigrationDeferred := false
	projectionPayloadPresenceMigrationNeeded := false
	queueSchemaUpgradeNeeded := false
	if db.Name() == "sqlite" {
		queueSchemaUpgradeNeeded = sqliteQueueSchedulingSchemaUpgradeNeeded(db)
		if err := db.AutoMigrate(&operationRow{}); err != nil {
			return databaseStage("operations schema", err)
		}
		if err := ensureSQLiteOperationArtifacts(db); err != nil {
			return databaseStage("operation artifacts schema", err)
		}
		if db.Migrator().HasTable(&projectionReadModelRow{}) {
			if err := migrateSQLiteProjectionPayloadPresence(db); err != nil {
				return databaseStage("projection payload presence migration", err)
			}
		} else {
			sqliteProjectionMigrationDeferred = true
		}
	} else {
		projectionPayloadPresenceMigrationNeeded = db.Migrator().HasTable(&projectionReadModelRow{}) &&
			!db.Migrator().HasColumn(&projectionReadModelRow{}, "payload_present")
	}

	models := schemaModels()
	if db.Name() == "sqlite" {
		models = schemaModelsWithoutOperationArtifacts()
	}
	schemaUpgradeStarted := time.Now()
	if queueSchemaUpgradeNeeded {
		sealdicelogger.M().Info("事件数据库 schema 升级开始：phase=queue-schema")
	}
	if err := db.AutoMigrate(models...); err != nil {
		return databaseStage("table and index schema", err)
	}
	if queueSchemaUpgradeNeeded {
		sealdicelogger.M().Infof(
			"事件数据库 schema 升级完成：phase=queue-schema elapsed=%s",
			time.Since(schemaUpgradeStarted).Round(time.Millisecond),
		)
	}
	if sqliteProjectionMigrationDeferred {
		if err := migrateSQLiteProjectionPayloadPresence(db); err != nil {
			return databaseStage("deferred projection payload presence migration", err)
		}
	} else if projectionPayloadPresenceMigrationNeeded {
		if err := db.Exec(projectionPayloadPresenceBackfillStatement).Error; err != nil {
			return databaseStage("projection payload presence backfill", err)
		}
	}
	if err := db.AutoMigrate(&privacyAuditRow{}); err != nil {
		return databaseStage("privacy audit schema", err)
	}
	if err := migrateQueueScheduling(db); err != nil {
		return databaseStage("queue scheduling migration", err)
	}
	if db.Name() == "sqlite" {
		if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS ux_operation_artifacts_artifact_id ON operation_artifacts(artifact_id)").Error; err != nil {
			return databaseStage("operation artifacts unique index", err)
		}
		return nil
	}
	for _, constraint := range []struct {
		model     any
		name      string
		statement string
	}{
		{
			model: &operationArtifactRow{},
			name:  "fk_operation_artifacts_operation",
			statement: "ALTER TABLE operation_artifacts ADD CONSTRAINT fk_operation_artifacts_operation " +
				"FOREIGN KEY (operation_id) REFERENCES operations(operation_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
		},
		{
			model: &subjectFenceRow{},
			name:  "fk_subject_fences_purge_operation",
			statement: "ALTER TABLE subject_fences ADD CONSTRAINT fk_subject_fences_purge_operation " +
				"FOREIGN KEY (purge_operation_id) REFERENCES operations(operation_id) ON UPDATE RESTRICT ON DELETE RESTRICT",
		},
	} {
		if !db.Migrator().HasConstraint(constraint.model, constraint.name) {
			if err := db.Exec(constraint.statement).Error; err != nil {
				return fmt.Errorf("create constraint %s: %w", constraint.name, err)
			}
		}
	}
	return nil
}

func initializeSingletons(db *gorm.DB) error {
	now := time.Now().UTC()
	if err := db.Where("singleton_id = ?", "default").FirstOrCreate(&eventGlobalSequenceRow{SingletonID: "default", NextPosition: 1, UpdatedAt: now}).Error; err != nil {
		return err
	}
	if err := db.Where("singleton_id = ?", "default").FirstOrCreate(&projectionControlRow{SingletonID: "default", ActiveGeneration: "initial", ProjectorSetVersion: "initial", PublicationState: "published", UpdatedAt: now}).Error; err != nil {
		return err
	}
	if err := db.Where("singleton_id = ?", "default").FirstOrCreate(&storeReadinessRow{SingletonID: "default", Mode: "fresh", SchemaVersion: "1", DatabaseIdentity: "eventstore", IndexRootID: "unconfigured", EncryptionRootIDs: []byte("[]")}).Error; err != nil {
		return err
	}
	return nil
}

func validateSchema(db *gorm.DB) error {
	for _, model := range schemaModels() {
		if !db.Migrator().HasTable(model) {
			return errors.New("missing table")
		}
	}
	var sequence, control, readiness int64
	if err := db.Model(&eventGlobalSequenceRow{}).Count(&sequence).Error; err != nil || sequence != 1 {
		return errors.New("event global sequence singleton invariant failed")
	}
	if err := db.Model(&projectionControlRow{}).Count(&control).Error; err != nil || control != 1 {
		return errors.New("projection control singleton invariant failed")
	}
	if err := db.Model(&storeReadinessRow{}).Count(&readiness).Error; err != nil || readiness != 1 {
		return errors.New("store readiness singleton invariant failed")
	}
	return nil
}

func validateRequiredIndexes(db *gorm.DB) error {
	db = db.Session(&gorm.Session{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	models := map[string]any{
		tableDomainEvents:        &domainEventRow{},
		tableAggregateHeads:      &aggregateHeadRow{},
		tableProjectionReadModel: &projectionReadModelRow{},
		tableOperations:          &operationRow{},
		tableOperationArtifacts:  &operationArtifactRow{},
		tableLaneHeads:           &laneHeadRow{},
		tableInboxMessages:       &inboxMessageRow{},
		tableOutboxEffects:       &outboxEffectRow{},
		tableAdapterSecrets:      &adapterSecretRow{},
		tableSubjectFences:       &subjectFenceRow{},
		tableManagementActivity:  &managementActivityRow{},
		tableStoryLogSessions:    &storyLogSessionRow{},
		tableStoryLogStates:      &storyLogStateRow{},
		tableStoryLogEntries:     &logArchiveEntryRow{},
		tableStoryLogIntents:     &logArchiveIntentRow{},
		tableStoryLogImports:     &storyLogImportRow{},
	}
	for table, model := range models {
		indexes, err := db.Migrator().GetIndexes(model)
		if err != nil {
			return fmt.Errorf("inspect indexes for %s: %w", table, err)
		}
		got := make(map[string]gorm.Index, len(indexes))
		for _, index := range indexes {
			got[index.Name()] = index
		}
		for key, wantColumns := range requiredEventStoreIndexColumns {
			if !strings.HasPrefix(key, table+":") {
				continue
			}
			name := strings.TrimPrefix(key, table+":")
			index, ok := got[name]
			if !ok {
				return fmt.Errorf("missing index %s.%s", table, name)
			}
			unique, uniqueOK := index.Unique()
			if requiredEventStoreIndexes[key] && (!uniqueOK || !unique) {
				return fmt.Errorf("required unique index %s.%s is not unique", table, name)
			}
			if !requiredEventStoreIndexes[key] && uniqueOK && unique {
				return fmt.Errorf("required non-unique index %s.%s is unique", table, name)
			}
			columns, columnsErr := orderedIndexColumns(db, table, name, index)
			if columnsErr != nil {
				return fmt.Errorf("inspect columns for %s.%s: %w", table, name, columnsErr)
			}
			if !sameStrings(columns, wantColumns) {
				return fmt.Errorf("index columns do not match contract for %s.%s", table, name)
			}
		}
	}
	return nil
}

func orderedIndexColumns(db *gorm.DB, table, name string, index gorm.Index) ([]string, error) {
	if db.Name() != "postgres" {
		return index.Columns(), nil
	}
	var columns []string
	err := db.Raw(`
		SELECT attribute.attname
		FROM pg_class AS table_class
		JOIN pg_index AS index_info ON table_class.oid = index_info.indrelid
		JOIN pg_class AS index_class ON index_class.oid = index_info.indexrelid
		JOIN LATERAL unnest(index_info.indkey) WITH ORDINALITY AS key_column(attnum, position) ON true
		JOIN pg_attribute AS attribute
			ON attribute.attrelid = table_class.oid AND attribute.attnum = key_column.attnum
		WHERE table_class.relname = ? AND index_class.relname = ?
		ORDER BY key_column.position`, table, name).Scan(&columns).Error
	return columns, err
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
