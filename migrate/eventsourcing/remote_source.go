package eventsourcing

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"Scardice-core/eventstore"
)

// RemoteSQLSource snapshots a stopped legacy installation whose owned SQL
// tables live in MySQL or PostgreSQL. The remote transaction is read-only and
// repeatable-read; the importer consumes only the resulting owner-only local
// SQLite snapshot.
type RemoteSQLSource struct {
	Root      string
	Config    eventstore.DatabaseConfig
	keySource eventstore.KeySource

	open func(context.Context, eventstore.DatabaseConfig) (*sql.DB, error)
}

func NewRemoteSQLSource(root string, config eventstore.DatabaseConfig) *RemoteSQLSource {
	return &RemoteSQLSource{Root: filepath.Clean(root), Config: config}
}

func NewRemoteSQLSourceWithKeySource(root string, config eventstore.DatabaseConfig, keySource eventstore.KeySource) *RemoteSQLSource {
	return &RemoteSQLSource{Root: filepath.Clean(root), Config: config, keySource: keySource}
}

func (s *RemoteSQLSource) Inventory(ctx context.Context) (SourceInventory, error) {
	metadata, err := s.currentMetadata(ctx)
	if err != nil {
		return SourceInventory{}, err
	}
	return SourceInventory{
		Kind: SourceKindRemoteSQL, Identity: metadata.Identity, Metadata: metadata,
		LegacyOwnershipComplete: true,
	}, nil
}

func (s *RemoteSQLSource) Snapshot(ctx context.Context, target string) (result SnapshotResult, snapshotErr error) {
	_, root, instances, paths, err := s.layout(ctx)
	if err != nil {
		return result, err
	}
	defer root.Close()
	filesystemBefore, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return result, err
	}
	database, err := s.openDatabase(ctx)
	if err != nil {
		return result, err
	}
	defer database.Close()
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer func() {
		if snapshotErr != nil {
			snapshotErr = errors.Join(snapshotErr, transaction.Rollback())
		}
	}()
	if err = validateRemoteLegacySchema(ctx, transaction); err != nil {
		return result, err
	}
	remoteFile, err := remoteLegacyMetadata(ctx, transaction)
	if err != nil {
		return result, err
	}
	metadata := combineRemoteMetadata(filesystemBefore, remoteFile)
	if err = secureDestination(DefaultFileSystem(), target); err != nil {
		return result, err
	}
	files := make([]string, 0, len(paths)+len(instances))
	for _, sourcePath := range paths {
		relative, relativeErr := root.relative(sourcePath)
		if relativeErr != nil || relative == "." {
			return result, ErrSourceMutation
		}
		destination := filepath.Join(target, relative)
		if err = os.MkdirAll(filepath.Dir(destination), SnapshotTreeMode); err != nil {
			return result, err
		}
		if err = copyLegacyFileAt(ctx, root, sourcePath, destination); err != nil {
			return result, err
		}
		files = append(files, destination)
	}
	for _, instance := range instances {
		relative, relativeErr := root.relative(instance.dir)
		if relativeErr != nil || relative == "." {
			return result, ErrSourceMutation
		}
		destination := filepath.Join(target, relative, "data.db")
		if err = writeRemoteLegacySQLiteSnapshot(ctx, transaction, destination); err != nil {
			return result, err
		}
		files = append(files, destination)
	}
	if err = transaction.Commit(); err != nil {
		return result, err
	}
	filesystemAfter, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return result, err
	}
	if !filesystemBefore.Equal(filesystemAfter) {
		return result, ErrSourceDrift
	}
	snapshotSource, err := newLegacySnapshotSource(target, s.keySource, root, instances)
	if err != nil {
		return result, err
	}
	return SnapshotResult{Root: target, Metadata: metadata, Files: files, Source: snapshotSource}, nil
}

func (s *RemoteSQLSource) Recheck(ctx context.Context, before SourceMetadata) error {
	after, err := s.currentMetadata(ctx)
	if err != nil {
		return err
	}
	if !before.Equal(after) {
		return ErrSourceDrift
	}
	return nil
}

func (s *RemoteSQLSource) currentMetadata(ctx context.Context) (SourceMetadata, error) {
	_, root, _, paths, err := s.layout(ctx)
	if err != nil {
		return SourceMetadata{}, err
	}
	defer root.Close()
	filesystem, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return SourceMetadata{}, err
	}
	database, err := s.openDatabase(ctx)
	if err != nil {
		return SourceMetadata{}, err
	}
	defer database.Close()
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return SourceMetadata{}, err
	}
	defer func() { _ = transaction.Rollback() }()
	if err = validateRemoteLegacySchema(ctx, transaction); err != nil {
		return SourceMetadata{}, err
	}
	remoteFile, err := remoteLegacyMetadata(ctx, transaction)
	if err != nil {
		return SourceMetadata{}, err
	}
	if err = transaction.Commit(); err != nil {
		return SourceMetadata{}, err
	}
	return combineRemoteMetadata(filesystem, remoteFile), nil
}

func (s *RemoteSQLSource) layout(ctx context.Context) (*LegacySource, *legacySourceRoot, []legacyInstance, []string, error) {
	if s == nil || strings.TrimSpace(s.Root) == "" || s.Root == "." {
		return nil, nil, nil, nil, ErrSourceRequired
	}
	legacy := NewLegacySourceWithKeySource(s.Root, s.keySource)
	root, err := openLegacySourceRoot(legacy.Root)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	instances, paths, err := legacy.layoutWithRoot(ctx, false, root)
	if err != nil {
		return nil, nil, nil, nil, errors.Join(err, root.Close())
	}
	return legacy, root, instances, paths, nil
}

func (s *RemoteSQLSource) openDatabase(ctx context.Context) (*sql.DB, error) {
	if s == nil {
		return nil, ErrSourceRequired
	}
	if s.open != nil {
		return s.open(ctx, s.Config)
	}
	if err := eventstore.ValidateRemoteDatabaseConfig(s.Config); err != nil {
		return nil, err
	}
	databaseType := strings.ToLower(strings.TrimSpace(s.Config.Type))
	driver := "mysql"
	if databaseType == "postgres" || databaseType == "postgresql" {
		driver = "pgx"
	}
	database, err := sql.Open(driver, s.Config.DSN)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if err = database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func validateRemoteLegacySchema(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}) error {
	queries := map[string]string{
		"group_info":        "SELECT id, created_at, data FROM group_info WHERE 1=0",
		"group_player_info": "SELECT name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id FROM group_player_info WHERE 1=0",
		"attrs":             "SELECT id, data, attrs_type, binding_sheet_id, name, owner_id, sheet_type, is_hidden, created_at, updated_at FROM attrs WHERE 1=0",
		"ban_info":          "SELECT id, data FROM ban_info WHERE 1=0",
	}
	tables := make([]string, 0, len(queries))
	for table := range queries {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		if err := func() (resultErr error) {
			rows, err := queryer.QueryContext(ctx, queries[table])
			if err != nil {
				return &UnsupportedPreflightError{Feature: "remote legacy SQL schema " + table}
			}
			defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
			return rows.Err()
		}(); err != nil {
			return err
		}
	}
	return nil
}

func remoteLegacyMetadata(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}) (FileMetadata, error) {
	digest := sha256.New()
	var size int64
	if err := digestRemoteGroups(ctx, queryer, digest, &size); err != nil {
		return FileMetadata{}, err
	}
	if err := digestRemotePlayers(ctx, queryer, digest, &size); err != nil {
		return FileMetadata{}, err
	}
	if err := digestRemoteAttrs(ctx, queryer, digest, &size); err != nil {
		return FileMetadata{}, err
	}
	if err := digestRemoteBans(ctx, queryer, digest, &size); err != nil {
		return FileMetadata{}, err
	}
	var value [sha256.Size]byte
	copy(value[:], digest.Sum(nil))
	return FileMetadata{Name: "remote-sql", Size: size, Mode: SnapshotFileMode, Digest: value}, nil
}

func combineRemoteMetadata(filesystem SourceMetadata, remote FileMetadata) SourceMetadata {
	files := append([]FileMetadata(nil), filesystem.Files...)
	files = append(files, remote)
	digest := sha256.New()
	writeDigestField(digest, []byte(filesystem.Identity), nil)
	writeDigestField(digest, remote.Digest[:], nil)
	return SourceMetadata{Identity: "legacy-remote-" + hex.EncodeToString(digest.Sum(nil)), Files: files}
}

const (
	remoteLegacyGroupsQuery  = "SELECT id, COALESCE(created_at, 0), data FROM group_info ORDER BY id"
	remoteLegacyPlayersQuery = "SELECT COALESCE(name, ''), COALESCE(user_id, ''), COALESCE(last_command_time, 0), COALESCE(auto_set_name_template, ''), COALESCE(dice_side_num, 0), COALESCE(group_id, '') FROM group_player_info ORDER BY group_id, user_id"
)

func digestRemoteGroups(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, digest hash.Hash, size *int64) (resultErr error) {
	rows, err := queryer.QueryContext(ctx, remoteLegacyGroupsQuery)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	writeDigestField(digest, []byte("group_info"), size)
	for rows.Next() {
		var id string
		var createdAt int64
		var data []byte
		if err = rows.Scan(&id, &createdAt, &data); err != nil {
			return err
		}
		writeDigestField(digest, []byte(id), size)
		writeDigestField(digest, []byte(strconv.FormatInt(createdAt, 10)), size)
		writeDigestField(digest, data, size)
	}
	return rows.Err()
}

func digestRemotePlayers(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, digest hash.Hash, size *int64) (resultErr error) {
	rows, err := queryer.QueryContext(ctx, remoteLegacyPlayersQuery)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	writeDigestField(digest, []byte("group_player_info"), size)
	for rows.Next() {
		var name, userID, template, groupID string
		var lastCommand, diceSide int64
		if err = rows.Scan(&name, &userID, &lastCommand, &template, &diceSide, &groupID); err != nil {
			return err
		}
		for _, value := range []string{name, userID, strconv.FormatInt(lastCommand, 10), template, strconv.FormatInt(diceSide, 10), groupID} {
			writeDigestField(digest, []byte(value), size)
		}
	}
	return rows.Err()
}

func digestRemoteAttrs(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, digest hash.Hash, size *int64) (resultErr error) {
	rows, err := queryer.QueryContext(ctx, "SELECT id, data, COALESCE(attrs_type, ''), COALESCE(binding_sheet_id, ''), COALESCE(name, ''), COALESCE(owner_id, ''), COALESCE(sheet_type, ''), COALESCE(is_hidden, false), COALESCE(created_at, 0), COALESCE(updated_at, 0) FROM attrs ORDER BY id")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	writeDigestField(digest, []byte("attrs"), size)
	for rows.Next() {
		var id, attrsType, bindingSheetID, name, ownerID, sheetType string
		var data []byte
		var hidden bool
		var createdAt, updatedAt int64
		if err = rows.Scan(&id, &data, &attrsType, &bindingSheetID, &name, &ownerID, &sheetType, &hidden, &createdAt, &updatedAt); err != nil {
			return err
		}
		writeDigestField(digest, []byte(id), size)
		writeDigestField(digest, data, size)
		for _, value := range []string{attrsType, bindingSheetID, name, ownerID, sheetType, strconv.FormatBool(hidden), strconv.FormatInt(createdAt, 10), strconv.FormatInt(updatedAt, 10)} {
			writeDigestField(digest, []byte(value), size)
		}
	}
	return rows.Err()
}

func isMissingBanUpdatedAtColumn(err error) bool {
	if err == nil {
		return false
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1054
	}
	var postgresErr *pgconn.PgError
	if errors.As(err, &postgresErr) {
		return postgresErr.Code == "42703"
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "ban_updated_at") &&
		(strings.Contains(message, "no such column") ||
			strings.Contains(message, "unknown column") ||
			strings.Contains(message, "does not exist"))
}

func queryRemoteBanRows(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}) (*sql.Rows, bool, error) {
	rows, err := queryer.QueryContext(ctx, "SELECT id, COALESCE(ban_updated_at, 0), data FROM ban_info ORDER BY id")
	if err == nil {
		return rows, true, nil
	}
	if !isMissingBanUpdatedAtColumn(err) {
		return nil, false, err
	}
	rows, err = queryer.QueryContext(ctx, "SELECT id, data FROM ban_info ORDER BY id")
	if err != nil {
		return nil, false, err
	}
	return rows, false, nil
}

func digestRemoteBans(ctx context.Context, queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, digest hash.Hash, size *int64) (resultErr error) {
	rows, hasUpdatedAt, err := queryRemoteBanRows(ctx, queryer)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	writeDigestField(digest, []byte("ban_info"), size)
	for rows.Next() {
		var (
			id           string
			data         []byte
			banUpdatedAt int64
		)
		if hasUpdatedAt {
			err = rows.Scan(&id, &banUpdatedAt, &data)
		} else {
			err = rows.Scan(&id, &data)
		}
		if err != nil {
			return err
		}
		writeDigestField(digest, []byte(id), size)
		writeDigestField(digest, []byte(strconv.FormatInt(banUpdatedAt, 10)), size)
		writeDigestField(digest, data, size)
	}
	return rows.Err()
}

func writeDigestField(digest hash.Hash, value []byte, size *int64) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
	if size != nil {
		*size += int64(len(length) + len(value))
	}
}

func writeRemoteLegacySQLiteSnapshot(ctx context.Context, source *sql.Tx, path string) (resultErr error) {
	if err := os.MkdirAll(filepath.Dir(path), SnapshotTreeMode); err != nil {
		return err
	}
	reserved, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, SnapshotFileMode)
	if err != nil {
		return err
	}
	if err = reserved.Close(); err != nil {
		return err
	}
	destination, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, destination.Close()) }()
	for _, statement := range []string{
		`CREATE TABLE group_info (id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER DEFAULT 0, data BLOB NOT NULL)`,
		`CREATE TABLE group_player_info (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, user_id TEXT, last_command_time INTEGER, auto_set_name_template TEXT, dice_side_num INTEGER, group_id TEXT)`,
		`CREATE TABLE attrs (id TEXT, data BLOB, attrs_type TEXT, binding_sheet_id TEXT, name TEXT, owner_id TEXT, sheet_type TEXT, is_hidden INTEGER, created_at INTEGER, updated_at INTEGER)`,
		`CREATE TABLE ban_info (id TEXT PRIMARY KEY, data BLOB NOT NULL, ban_updated_at INTEGER NOT NULL DEFAULT 0)`,
	} {
		if _, err = destination.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	transaction, err := destination.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, transaction.Rollback())
		}
	}()
	if err = copyRemoteGroups(ctx, source, transaction); err != nil {
		return err
	}
	if err = copyRemotePlayers(ctx, source, transaction); err != nil {
		return err
	}
	if err = copyRemoteAttrs(ctx, source, transaction); err != nil {
		return err
	}
	if err = copyRemoteBans(ctx, source, transaction); err != nil {
		return err
	}
	return transaction.Commit()
}

func copyRemoteGroups(ctx context.Context, source *sql.Tx, destination *sql.Tx) (resultErr error) {
	rows, err := source.QueryContext(ctx, remoteLegacyGroupsQuery)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	statement, err := destination.PrepareContext(ctx, "INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, statement.Close()) }()
	for rows.Next() {
		var id string
		var createdAt int64
		var data []byte
		if err = rows.Scan(&id, &createdAt, &data); err != nil {
			return err
		}
		if _, err = statement.ExecContext(ctx, id, createdAt, data); err != nil {
			return err
		}
	}
	return rows.Err()
}

func copyRemotePlayers(ctx context.Context, source *sql.Tx, destination *sql.Tx) (resultErr error) {
	rows, err := source.QueryContext(ctx, remoteLegacyPlayersQuery)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	statement, err := destination.PrepareContext(ctx, "INSERT INTO group_player_info (name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, statement.Close()) }()
	for rows.Next() {
		var name, userID, template, groupID string
		var lastCommand, diceSide int64
		if err = rows.Scan(&name, &userID, &lastCommand, &template, &diceSide, &groupID); err != nil {
			return err
		}
		if _, err = statement.ExecContext(ctx, name, userID, lastCommand, template, diceSide, groupID); err != nil {
			return err
		}
	}
	return rows.Err()
}

func copyRemoteAttrs(ctx context.Context, source *sql.Tx, destination *sql.Tx) (resultErr error) {
	rows, err := source.QueryContext(ctx, "SELECT id, data, COALESCE(attrs_type, ''), COALESCE(binding_sheet_id, ''), COALESCE(name, ''), COALESCE(owner_id, ''), COALESCE(sheet_type, ''), COALESCE(is_hidden, false), COALESCE(created_at, 0), COALESCE(updated_at, 0) FROM attrs ORDER BY id")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	statement, err := destination.PrepareContext(ctx, "INSERT INTO attrs (id, data, attrs_type, binding_sheet_id, name, owner_id, sheet_type, is_hidden, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, statement.Close()) }()
	for rows.Next() {
		var id, attrsType, bindingSheetID, name, ownerID, sheetType string
		var data []byte
		var hidden bool
		var createdAt, updatedAt int64
		if err = rows.Scan(&id, &data, &attrsType, &bindingSheetID, &name, &ownerID, &sheetType, &hidden, &createdAt, &updatedAt); err != nil {
			return err
		}
		if _, err = statement.ExecContext(ctx, id, data, attrsType, bindingSheetID, name, ownerID, sheetType, hidden, createdAt, updatedAt); err != nil {
			return err
		}
	}
	return rows.Err()
}

func copyRemoteBans(ctx context.Context, source *sql.Tx, destination *sql.Tx) (resultErr error) {
	rows, hasUpdatedAt, err := queryRemoteBanRows(ctx, source)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	statement, err := destination.PrepareContext(ctx, "INSERT INTO ban_info (id, data, ban_updated_at) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, statement.Close()) }()
	for rows.Next() {
		var (
			id           string
			data         []byte
			banUpdatedAt int64
		)
		if hasUpdatedAt {
			err = rows.Scan(&id, &banUpdatedAt, &data)
		} else {
			err = rows.Scan(&id, &data)
		}
		if err != nil {
			return err
		}
		if _, err = statement.ExecContext(ctx, id, data, banUpdatedAt); err != nil {
			return err
		}
	}
	return rows.Err()
}
