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
			gormDB, err = gorm.Open(mysql.New(mysql.Config{DSN: config.DSN, SkipInitializeWithVersion: true}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), DisableAutomaticPing: true, DisableForeignKeyConstraintWhenMigrating: true})
		}
	case "postgres", "postgresql":
		if err = validateRemoteConfig(dbType, config); err == nil {
			gormDB, err = gorm.Open(postgres.Open(config.DSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), DisableAutomaticPing: true, DisableForeignKeyConstraintWhenMigrating: true})
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
	queryTimeout := config.QueryTimeout
	if queryTimeout <= 0 {
		queryTimeout = defaultDatabaseQueryTimeout
	}
	schemaCtx, cancelSchema := context.WithTimeout(ctx, queryTimeout)
	defer cancelSchema()
	schemaDB := gormDB.WithContext(schemaCtx)
	if err := migrateSchema(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("migrate schema", dbType, err)
	}
	if err := initializeSingletons(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("initialize schema", dbType, err)
	}
	if err := validateSchema(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("validate schema", dbType, err)
	}
	if err := validateRequiredIndexes(schemaDB); err != nil {
		_ = sqlDB.Close()
		return nil, safeDatabaseError("validate indexes", dbType, err)
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
		values := parsed.Query()["tls"]
		return len(values) == 1 && strings.EqualFold(values[0], "true")
	}
	parsed, err := url.Parse(dsn)
	if err == nil {
		values := parsed.Query()["sslmode"]
		if len(values) == 1 {
			mode := strings.ToLower(values[0])
			return mode == "verify-full" || mode == "verify-ca"
		}
		if len(values) > 1 {
			return false
		}
	}
	mode := ""
	count := 0
	for _, field := range strings.Fields(dsn) {
		key, value, ok := strings.Cut(field, "=")
		if key != "sslmode" || !ok {
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
	if strings.Contains(dsn, "://") {
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
		fields := strings.Fields(dsn)
		for _, field := range fields {
			if !strings.Contains(field, "=") {
				return false
			}
		}
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

func safeDatabaseError(operation, dbType string, _ error) error {
	return fmt.Errorf("event database %s failed for %s", operation, dbType)
}

func migrateSchema(db *gorm.DB) error {
	if err := db.AutoMigrate(schemaModels()...); err != nil {
		return err
	}
	if db.Dialector.Name() == "sqlite" {
		return nil
	}
	for _, constraint := range []struct {
		model any
		name  string
	}{
		{&operationRow{}, "Artifact"},
		{&operationArtifactRow{}, "Operation"},
		{&subjectFenceRow{}, "PurgeOperation"},
	} {
		if !db.Migrator().HasConstraint(constraint.model, constraint.name) {
			if err := db.Migrator().CreateConstraint(constraint.model, constraint.name); err != nil {
				return err
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

func validateRequiredIndexes(db *gorm.DB) error {
	db = db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
	models := map[string]any{
		tableDomainEvents:        &domainEventRow{},
		tableAggregateHeads:      &aggregateHeadRow{},
		tableProjectionReadModel: &projectionReadModelRow{},
		tableOperations:          &operationRow{},
		tableOperationArtifacts:  &operationArtifactRow{},
		tableLaneHeads:           &laneHeadRow{},
		tableInboxMessages:        &inboxMessageRow{},
		tableOutboxEffects:       &outboxEffectRow{},
		tableAdapterSecrets:      &adapterSecretRow{},
		tablePluginKV:            &pluginKVRow{},
		tableSubjectFences:       &subjectFenceRow{},
	}
	for table, model := range models {
		indexes, err := db.Migrator().GetIndexes(model)
		if err != nil {
			return err
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
				return fmt.Errorf("missing index")
			}
			unique, uniqueOK := index.Unique()
			if requiredEventStoreIndexes[key] && (!uniqueOK || !unique) {
				return fmt.Errorf("required unique index is not unique")
			}
			if !requiredEventStoreIndexes[key] && uniqueOK && unique {
				return fmt.Errorf("required non-unique index is unique")
			}
			if !sameStrings(index.Columns(), wantColumns) {
				return fmt.Errorf("index columns do not match contract")
			}
		}
	}
	return nil
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
