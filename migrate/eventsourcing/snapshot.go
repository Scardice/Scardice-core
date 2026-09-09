package eventsourcing

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// FileSystem is the small filesystem seam used for publication and quarantine.
// Implementations must preserve the requested permissions and must not follow
// untrusted symlinks.
type FileSystem interface {
	MkdirAll(string, os.FileMode) error
	Lstat(string) (os.FileInfo, error)
	Open(string) (io.ReadCloser, error)
	OpenFile(string, int, os.FileMode) (io.WriteCloser, error)
	Chmod(string, os.FileMode) error
	WriteFile(string, []byte, os.FileMode) error
}

type osFileSystem struct{}
func (osFileSystem) MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func (osFileSystem) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }
func (osFileSystem) Open(path string) (io.ReadCloser, error) { return os.Open(path) }
func (osFileSystem) OpenFile(path string, flags int, mode os.FileMode) (io.WriteCloser, error) { return os.OpenFile(path, flags, mode) }
func (osFileSystem) Chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
func (osFileSystem) WriteFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil { return err }
	if err := file.Chmod(mode); err != nil { _ = file.Close(); return err }
	if _, err := file.Write(data); err != nil { _ = file.Close(); return err }
	return file.Close()
}

func DefaultFileSystem() FileSystem { return osFileSystem{} }

func snapshotSQLiteFiles(ctx context.Context, mainPath, target string) ([]string, error) {
	return copySQLiteFiles(ctx, osFileSystem{}, mainPath, target)
}

// CopySQLiteSnapshot copies the SQLite main file and present -wal/-shm files
// byte-for-byte. It opens every source only for reading and never invokes a
// SQLite driver, which prevents accidental writes to the source database.
func CopySQLiteSnapshot(ctx context.Context, fs FileSystem, mainPath, target string) ([]string, error) {
	if fs == nil { fs = osFileSystem{} }
	return copySQLiteFiles(ctx, fs, mainPath, target)
}

func copySQLiteFiles(ctx context.Context, fs FileSystem, mainPath, target string) ([]string, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	if strings.TrimSpace(mainPath) == "" || strings.TrimSpace(target) == "" { return nil, ErrSourceRequired }
	if err := secureDestination(fs, target); err != nil { return nil, err }
	if err := fs.MkdirAll(target, SnapshotTreeMode); err != nil { return nil, err }
	if err := fs.Chmod(target, SnapshotTreeMode); err != nil { return nil, err }

	clean := filepath.Clean(mainPath)
	sources := []string{clean}
	for _, suffix := range []string{"-wal", "-shm"} {
		candidate := clean + suffix
		if _, err := fs.Lstat(candidate); err == nil {
			sources = append(sources, candidate)
		} else if !errors.Is(err, os.ErrNotExist) { return nil, err }
	}
	var total int64
	copied := make([]string, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil { return nil, err }
		info, err := fs.Lstat(source)
		if err != nil { return nil, err }
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() { return nil, ErrSourceMutation }
		if info.Size() > MaxSnapshotFileBytes || total > MaxSnapshotBytes-info.Size() { return nil, ErrBatchLimit }
		in, err := fs.Open(source)
		if err != nil { return nil, err }
		name := filepath.Base(source)
		out, err := fs.OpenFile(filepath.Join(target, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, SnapshotFileMode)
		if err != nil { _ = in.Close(); return nil, err }
		written, copyErr := io.CopyN(out, in, MaxSnapshotFileBytes+1)
		closeInErr := in.Close()
		closeOutErr := out.Close()
		if written > MaxSnapshotFileBytes { return nil, ErrBatchLimit }
		if copyErr != nil && !errors.Is(copyErr, io.EOF) { return nil, copyErr }
		if closeInErr != nil { return nil, closeInErr }
		if closeOutErr != nil { return nil, closeOutErr }
		if err := fs.Chmod(filepath.Join(target, name), SnapshotFileMode); err != nil { return nil, err }
		copied = append(copied, name)
		total += info.Size()
	}
	return copied, nil
}

func secureDestination(fs FileSystem, target string) error {
	absolute, err := filepath.Abs(target)
	if err != nil { return err }
	clean := filepath.Clean(absolute)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, part := range parts {
		if part == "" { continue }
		current = filepath.Join(current, part)
		info, statErr := fs.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 { return ErrSourceMutation }
			continue
		}
		if !errors.Is(statErr, os.ErrNotExist) { return statErr }
		break
	}
	return nil
}
