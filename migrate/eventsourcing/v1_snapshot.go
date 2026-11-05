package eventsourcing

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"Scardice-core/migrate/eventsourcing/v1reader"
)

// A source is never opened by a writable SQLite connection. Its WAL and SHM
// are copied as opaque bytes; SQLite recovery/checkpoint touches only scratch.
func snapshotV1SQLite(ctx context.Context, active string) (string, SourceMetadata, func() error, error) {
	dir, err := os.MkdirTemp("", "scardice-v1-reader-")
	if err != nil {
		return "", SourceMetadata{}, nil, err
	}
	cleanup := func() error { return os.RemoveAll(dir) }
	metadata, err := v1SQLiteMetadata(ctx, active)
	if err != nil {
		return "", metadata, nil, errors.Join(err, cleanup())
	}
	for _, item := range metadata.Files {
		if err = ctx.Err(); err != nil {
			return "", metadata, nil, errors.Join(err, cleanup())
		}
		in, openErr := openReadOnlyNoFollow(filepath.Join(filepath.Dir(active), item.Name))
		if openErr != nil {
			return "", metadata, nil, errors.Join(openErr, cleanup())
		}
		out, createErr := os.OpenFile(filepath.Join(dir, item.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, SnapshotFileMode)
		if createErr != nil {
			return "", metadata, nil, errors.Join(createErr, in.Close(), cleanup())
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(out, hash), in)
		closeErr := errors.Join(in.Close(), out.Close())
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		if copyErr != nil || closeErr != nil || written != item.Size || digest != item.Digest {
			return "", metadata, nil, errors.Join(ErrSourceDrift, copyErr, closeErr, cleanup())
		}
	}
	if err = recheckV1SQLite(ctx, active, metadata); err != nil {
		return "", metadata, nil, errors.Join(err, cleanup())
	}
	path := filepath.Join(dir, filepath.Base(active))
	// The copied WAL index is volatile; rebuilding this private copy is safe.
	if err = os.Remove(path + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", metadata, nil, errors.Join(err, cleanup())
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rw"}).String()
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return "", metadata, nil, errors.Join(err, cleanup())
	}
	database.SetMaxOpenConns(1)
	var busy, frames, checkpointed int
	err = database.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &checkpointed)
	err = errors.Join(err, database.Close())
	if err != nil || busy != 0 || frames != checkpointed {
		return "", metadata, nil, errors.Join(ErrSourceDrift, err, cleanup())
	}
	return path, metadata, cleanup, nil
}

func v1SQLiteMetadata(ctx context.Context, active string) (SourceMetadata, error) {
	metadata := SourceMetadata{Identity: filepath.Base(active)}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := ctx.Err(); err != nil {
			return metadata, err
		}
		path := active + suffix
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && suffix != "" {
			continue
		}
		if err != nil {
			return metadata, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return metadata, ErrSourceMutation
		}
		file, err := openReadOnlyNoFollow(path)
		if err != nil {
			return metadata, err
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, file)
		if err = errors.Join(copyErr, file.Close()); err != nil {
			return metadata, err
		}
		if n != info.Size() {
			return metadata, ErrSourceDrift
		}
		var digest [sha256.Size]byte
		copy(digest[:], hash.Sum(nil))
		metadata.Files = append(metadata.Files, FileMetadata{Name: filepath.Base(path), Size: n, Mode: info.Mode(), ModTimeUnixNano: info.ModTime().UnixNano(), Digest: digest})
	}
	return metadata, nil
}

func recheckV1SQLite(ctx context.Context, active string, before SourceMetadata) error {
	after, err := v1SQLiteMetadata(ctx, active)
	if err != nil {
		return err
	}
	if !before.Equal(after) {
		return ErrSourceDrift
	}
	return nil
}

// DetectSQLiteFormat never lets SQLite acquire locks on a source WAL index.
// A settled database can be probed immutably without copying its large body.
func DetectSQLiteFormat(ctx context.Context, path string) (v1reader.Format, error) {
	if err := CheckUnfinishedV1Publication(path); err != nil {
		return v1reader.FormatUnknown, err
	}
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return v1reader.FormatNone, nil
	} else if err != nil {
		return v1reader.FormatUnknown, err
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return v1reader.FormatUnknown, ErrSourceMutation
	}
	if info, err := os.Lstat(path + "-wal"); err == nil && info.Size() != 0 {
		snapshot, _, cleanup, snapshotErr := snapshotV1SQLite(ctx, path)
		if snapshotErr != nil {
			return v1reader.FormatUnknown, snapshotErr
		}
		format, detectErr := v1reader.Detect(ctx, snapshot)
		return format, errors.Join(detectErr, cleanup())
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return v1reader.FormatUnknown, err
	}
	return v1reader.Detect(ctx, path)
}

// publishV1Candidate retains the original byte-for-byte, including any WAL.
// A durable intent precedes every original rename. A killed publisher leaves
// that guard in place, so restart cannot mistake missing active for fresh.
func publishV1Candidate(ctx context.Context, opts V1ConvertOptions, candidate, active, stamp string, proof SourceMetadata) (string, error) {
	if err := CheckUnfinishedV1Publication(active); err != nil {
		return "", err
	}
	if err := recheckV1SQLite(ctx, active, proof); err != nil {
		return "", err
	}
	backup := active + ".v1." + stamp + ".bak"
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Lstat(backup + suffix); !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("v1 backup destination exists or is inaccessible: %w", ErrPublication)
		}
	}
	if err := opts.inject("backup"); err != nil {
		return "", err
	}
	intent := v1SwapIntent{Version: 1, Active: active, Candidate: candidate, Backup: backup, Source: proof}
	if err := persistV1SwapIntent(intent); err != nil {
		return "", err
	}
	var moved []string
	installed := false
	rollback := func(cause error) (string, error) {
		var restoreErr error
		if installed {
			restoreErr = os.Remove(active)
		}
		for i := len(moved) - 1; i >= 0; i-- {
			restoreErr = errors.Join(restoreErr, os.Rename(backup+moved[i], active+moved[i]))
		}
		restoreErr = errors.Join(restoreErr, syncSQLiteDatabaseParent(filepath.Dir(active)))
		if restoreErr == nil {
			restoreErr = removeOwnedV1SwapIntent(active)
		}
		return "", errors.Join(cause, restoreErr)
	}
	if err := opts.inject("swap-intent"); err != nil {
		return rollback(err)
	}
	for _, item := range proof.Files {
		suffix := item.Name[len(filepath.Base(active)):]
		if err := os.Rename(active+suffix, backup+suffix); err != nil {
			return rollback(err)
		}
		moved = append(moved, suffix)
		phase := "backup-main"
		switch suffix {
		case "-wal":
			phase = "backup-wal"
		case "-shm":
			phase = "backup-shm"
		}
		if err := opts.inject(phase); err != nil {
			return rollback(err)
		}
	}
	if err := syncSQLiteDatabaseParent(filepath.Dir(active)); err != nil {
		return rollback(err)
	}
	if err := opts.inject("activate"); err != nil {
		return rollback(err)
	}
	if err := ctx.Err(); err != nil {
		return rollback(err)
	}
	if err := replaceSQLiteDatabase(candidate, active); err != nil {
		return rollback(err)
	}
	installed = true
	if err := opts.inject("activated"); err != nil {
		return rollback(err)
	}
	if err := syncSQLiteDatabaseParent(filepath.Dir(active)); err != nil {
		return rollback(err)
	}
	if err := removeOwnedV1SwapIntent(active); err != nil {
		// If unlink succeeded but directory sync failed, re-establish the
		// durable guard before any rollback can again make active absent.
		if guardErr := CheckUnfinishedV1Publication(active); guardErr == nil {
			if guardErr = persistV1SwapIntent(intent); guardErr != nil {
				return "", errors.Join(err, guardErr)
			}
		}
		return rollback(err)
	}
	return backup, nil
}
