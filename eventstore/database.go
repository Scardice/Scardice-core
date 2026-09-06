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
	"strings"
	"sync"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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

	TLSVerify             bool
	AllowInsecureLoopback bool

	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
	MaxOpenConns   int
	MaxIdleConns   int
	ConnMaxLifetime time.Duration
}

// Database owns exactly one GORM database and its underlying SQL pool.
type Database struct {
	gormDB *gorm.DB
	sqlDB  *sql.DB

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

// OpenDatabase opens, migrates, initializes, and validates one event database.
func OpenDatabase(ctx context.Context, config DatabaseConfig) (*Database, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dbType := strings.ToLower(strings.TrimSpace(config.Type))
	if dbType == "" {
		dbType = "sqlite"
	}
	connectTimeout := config.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultDatabaseConnectTimeout
	}

	var (
		gormDB *gorm.DB
		err    error
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
		gormDB, err = gorm.Open(sqlite.Open(sqliteDSN(dsn)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	case "mysql":
		if err = validateRemoteConfig(dbType, config); err == nil {
			gormDB, err = gorm.Open(mysql.Open(config.DSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		}
	case "postgres", "postgresql":
		if err = validateRemoteConfig(dbType, config); err == nil {
			gormDB, err = gorm.Open(postgres.Open(config.DSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
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
	owned := &Database{gormDB: gormDB, sqlDB: sqlDB}
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
		if err := configureAndValidateSQLite(sqlDB); err != nil {
			_ = sqlDB.Close()
			return nil, safeDatabaseError("configure sqlite", dbType, err)
		}
	}
	if err := migrateSchema(gormDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("migrate schema", dbType, err)
	}
	if err := initializeSingletons(gormDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("initialize schema", dbType, err)
	}
	if err := validateSchema(gormDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("validate schema", dbType, err)
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
	return dsn + separator + "_journal_mode=WAL&_foreign_keys=on&_busy_timeout=15000&_synchronous=FULL&_txlock=immediate"
}

func configureAndValidateSQLite(sqlDB *sql.DB) error {
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 15000",
		"PRAGMA synchronous = FULL",
	} {
		if _, err := sqlDB.Exec(statement); err != nil {
			return err
		}
	}
	var journalMode string
	if err := sqlDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("journal mode is not WAL")
	}
	var foreignKeys, busyTimeout, synchronous int
	if err := sqlDB.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return err
	}
	if err := sqlDB.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return err
	}
	if err := sqlDB.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		return err
	}
	if foreignKeys != 1 || busyTimeout < int(minimumSQLiteBusyTimeout/time.Millisecond) || synchronous != 2 {
		return fmt.Errorf("effective SQLite PRAGMA settings are unsafe")
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

func dsnDeclaresVerifiedTLS(dbType, dsn string) bool {
	if dbType == "mysql" {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return false
		}
		tls := strings.ToLower(parsed.Query().Get("tls"))
		return tls != "" && tls != "false" && tls != "skip-verify"
	}
	parsed, err := url.Parse(dsn)
	if err == nil {
		sslmode := strings.ToLower(parsed.Query().Get("sslmode"))
		if sslmode == "verify-full" || sslmode == "verify-ca" {
			return true
		}
	}
	for _, field := range strings.Fields(dsn) {
		key, value, ok := strings.Cut(field, "=")
		if key == "sslmode" && ok {
			value = strings.ToLower(value)
			return value == "verify-full" || value == "verify-ca"
		}
	}
	return false
}

func isLoopbackOrUnixDSN(dbType, dsn string) bool {
	if dbType == "mysql" {
		lower := strings.ToLower(dsn)
		if strings.Contains(lower, "@unix(") {
			return true
		}
		if start := strings.Index(lower, "@tcp("); start >= 0 {
			end := strings.IndexByte(lower[start+len("@tcp("):], ')')
			if end < 0 {
				return false
			}
			hostPort := dsn[start+len("@tcp(") : start+len("@tcp(")+end]
			host, _, err := net.SplitHostPort(hostPort)
			if err != nil {
				host = hostPort
			}
			ip := net.ParseIP(host)
			return host == "localhost" || (ip != nil && ip.IsLoopback())
		}
		return false
	}
	if strings.HasPrefix(dsn, "host=/") || strings.HasPrefix(dsn, "postgres:///") {
		return true
	}
	if strings.Contains(dsn, "host=") {
		for _, field := range strings.Fields(dsn) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			if key == "host" && strings.HasPrefix(value, "/") {
				return true
			}
			if key == "host" {
				ip := net.ParseIP(value)
				if value == "localhost" || (ip != nil && ip.IsLoopback()) {
					return true
				}
			}
		}
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func safeDatabaseError(operation, dbType string, _ error) error {
	return fmt.Errorf("event database %s failed for %s", operation, dbType)
}

func migrateSchema(db *gorm.DB) error {
	return db.AutoMigrate(schemaModels()...)
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
			return fmt.Errorf("missing table")
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
