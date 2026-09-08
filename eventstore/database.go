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

	mysqlDriver "github.com/go-sql-driver/mysql"
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

	// KeySource is required for remote databases and is carried to stores
	// opened from this database. SQLite callers may supply it explicitly when
	// using A6 encrypted repositories.
	KeySource KeySource
	DatabaseIdentity string

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
	databaseIdentity string
	keySource KeySource

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
	if dbType != "sqlite" && dbType != "sqlite3" && config.KeySource == nil {
		return nil, ErrKeySourceUnavailable
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
		return fmt.Errorf("journal mode is not WAL")
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

func safeDatabaseError(operation, dbType string, _ error) error {
	return fmt.Errorf("event database %s failed for %s", operation, dbType)
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
	ctx := context.Background()
	if db.Statement != nil && db.Statement.Context != nil {
		ctx = db.Statement.Context
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	var tableName string
	err = sqlDB.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'operation_artifacts'`).Scan(&tableName)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = sqlDB.ExecContext(ctx, sqliteOperationArtifactsDDL)
		return err
	}
	if err != nil {
		return err
	}

	type columnInfo struct{ notNull int }
	columns := make(map[string]columnInfo)
	rows, err := sqlDB.QueryContext(ctx, `SELECT name, "notnull" FROM pragma_table_info('operation_artifacts')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		var notNull int
		if err := rows.Scan(&name, &notNull); err != nil {
			rows.Close()
			return err
		}
		columns[name] = columnInfo{notNull: notNull}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
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

	fkReady := false
	fkRows, err := sqlDB.QueryContext(ctx, `SELECT "table", "from", "to", on_update, on_delete FROM pragma_foreign_key_list('operation_artifacts')`)
	if err != nil {
		return err
	}
	for fkRows.Next() {
		var table, from, to, onUpdate, onDelete string
		if err := fkRows.Scan(&table, &from, &to, &onUpdate, &onDelete); err != nil {
			fkRows.Close()
			return err
		}
		if table == tableOperations && from == "operation_id" && to == "operation_id" &&
			strings.EqualFold(onUpdate, "RESTRICT") && strings.EqualFold(onDelete, "RESTRICT") {
			fkReady = true
		}
	}
	if err := fkRows.Err(); err != nil {
		fkRows.Close()
		return err
	}
	fkRows.Close()
	payloadVersionPresent := false
	if info, ok := columns["payload_version"]; ok {
		payloadVersionPresent = info.notNull == 1
	}
	if versionPresent && versionNotNull && payloadVersionPresent && fkReady {
		return nil
	}
	var indexOwner string
	err = sqlDB.QueryRowContext(ctx, `SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?`, "ux_operation_artifacts_artifact_id").Scan(&indexOwner)
	if err == nil {
		if indexOwner != tableOperationArtifacts {
			return fmt.Errorf("SQLite index name ux_operation_artifacts_artifact_id is owned by %s", indexOwner)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if versionPresent && !versionNotNull {
		var nullVersions int
		if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_artifacts WHERE version IS NULL`).Scan(&nullVersions); err != nil {
			return err
		}
		if nullVersions != 0 {
			return fmt.Errorf("SQLite operation_artifacts contains NULL versions")
		}
	}
	var orphanCount int
	if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_artifacts AS a LEFT JOIN operations AS o ON o.operation_id = a.operation_id WHERE o.operation_id IS NULL`).Scan(&orphanCount); err != nil {
		return err
	}
	if orphanCount != 0 {
		return fmt.Errorf("SQLite operation_artifacts contains orphan operation references")
	}

	tx := db.WithContext(ctx).Begin()
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
	if err := tx.Exec(`INSERT INTO operation_artifacts (`+strings.Join(append([]string{"version"}, required...), ", ")+`) SELECT `+strings.Join(selectColumns, ", ")+` FROM operation_artifacts_legacy`).Error; err != nil {
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

func migrateSchema(db *gorm.DB) error {
	if db.Dialector.Name() == "sqlite" {
		if err := db.AutoMigrate(&operationRow{}); err != nil {
			return err
		}
		if err := ensureSQLiteOperationArtifacts(db); err != nil {
			return err
		}
	}
	models := schemaModels()
	if db.Dialector.Name() == "sqlite" {
		models = schemaModelsWithoutOperationArtifacts()
	}
	if err := db.AutoMigrate(models...); err != nil { return err }
	if err := db.AutoMigrate(&privacyAuditRow{}); err != nil { return err }
	if db.Dialector.Name() == "sqlite" {
		if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS ux_operation_artifacts_artifact_id ON operation_artifacts(artifact_id)").Error; err != nil {
			return err
		}
		return nil
	}
	for _, constraint := range []struct {
		model any
		name  string
	}{
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
