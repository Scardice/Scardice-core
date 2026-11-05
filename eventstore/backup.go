package eventstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrSnapshotUnsupported = errors.New("eventstore: consistent backup snapshot unsupported")

// SnapshotSQLite writes a consistent SQLite snapshot, including committed WAL
// transactions, using SQLite's VACUUM INTO operation.
func (s *GORMStore) SnapshotSQLite(ctx context.Context, destination string) error {
	if s == nil || s.db == nil || s.db.gormDB == nil || s.db.sqlDB == nil {
		return errors.New("eventstore: backup database unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialect := s.db.gormDB.Name()
	if dialect != "sqlite" {
		return fmt.Errorf("%w: %s", ErrSnapshotUnsupported, dialect)
	}
	if destination == "" || strings.ContainsRune(destination, '\x00') {
		return errors.New("eventstore: invalid snapshot destination")
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("eventstore: resolve snapshot destination: %w", err)
	}
	if _, err := os.Lstat(absolute); err == nil {
		return errors.New("eventstore: snapshot destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("eventstore: inspect snapshot destination: %w", err)
	}
	parent, err := os.Stat(filepath.Dir(absolute))
	if err != nil || !parent.IsDir() {
		if err == nil {
			err = errors.New("parent is not a directory")
		}
		return fmt.Errorf("eventstore: inspect snapshot directory: %w", err)
	}

	conn, err := s.db.sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("eventstore: acquire SQLite snapshot connection: %w", err)
	}
	_, snapshotErr := conn.ExecContext(ctx, "VACUUM INTO ?", absolute)
	closeErr := conn.Close()
	if snapshotErr != nil || closeErr != nil {
		_ = os.Remove(absolute)
		if snapshotErr != nil {
			return fmt.Errorf("eventstore: create SQLite snapshot: %w", snapshotErr)
		}
		return fmt.Errorf("eventstore: release SQLite snapshot connection: %w", closeErr)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		_ = os.Remove(absolute)
		if err == nil {
			err = errors.New("snapshot is not a non-empty regular file")
		}
		return fmt.Errorf("eventstore: validate SQLite snapshot: %w", err)
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		_ = os.Remove(absolute)
		return fmt.Errorf("eventstore: secure SQLite snapshot: %w", err)
	}
	file, err := os.OpenFile(absolute, os.O_RDWR, 0)
	if err != nil {
		_ = os.Remove(absolute)
		return fmt.Errorf("eventstore: open SQLite snapshot for sync: %w", err)
	}
	syncErr := file.Sync()
	closeErr = file.Close()
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(absolute)
		if syncErr != nil {
			return fmt.Errorf("eventstore: sync SQLite snapshot: %w", syncErr)
		}
		return fmt.Errorf("eventstore: close SQLite snapshot: %w", closeErr)
	}
	return nil
}
