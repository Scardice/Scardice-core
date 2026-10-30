package eventsourcing

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// legacySourceRoot keeps reads anchored to the caller-selected source tree.
// Root methods confine every operation even if a path component is replaced
// after its no-symlink check.
type legacySourceRoot struct {
	requested string
	path      string
	dir       *os.Root
}

func openLegacySourceRoot(path string) (*legacySourceRoot, error) {
	requested, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := os.OpenRoot(requested)
	if err != nil {
		return nil, err
	}
	openedInfo, err := dir.Stat(".")
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	resolved, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	pathInfo, err := os.Stat(resolved)
	if err != nil || !os.SameFile(openedInfo, pathInfo) {
		if err == nil {
			err = ErrSourceMutation
		}
		return nil, errors.Join(err, dir.Close())
	}
	return &legacySourceRoot{requested: filepath.Clean(requested), path: filepath.Clean(resolved), dir: dir}, nil
}

func (r *legacySourceRoot) Close() error {
	if r == nil || r.dir == nil {
		return nil
	}
	return r.dir.Close()
}

func (r *legacySourceRoot) relative(path string) (string, error) {
	if r == nil || r.dir == nil || strings.TrimSpace(path) == "" {
		return "", ErrSourceRequired
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for _, base := range []string{r.path, r.requested} {
		relative, relErr := filepath.Rel(base, absolute)
		if relErr != nil {
			continue
		}
		if relative == "." {
			return ".", nil
		}
		if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.Clean(relative), nil
		}
	}
	return "", ErrSourceMutation
}

func (r *legacySourceRoot) canonicalPath(path string) (string, error) {
	relative, err := r.relative(path)
	if err != nil {
		return "", err
	}
	if relative == "." {
		return r.path, nil
	}
	return filepath.Join(r.path, relative), nil
}

func (r *legacySourceRoot) Lstat(path string) (os.FileInfo, error) {
	relative, err := r.relative(path)
	if err != nil {
		return nil, err
	}
	if relative == "." {
		return r.dir.Stat(".")
	}
	parts := strings.Split(relative, string(filepath.Separator))
	current := ""
	var info os.FileInfo
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, ErrSourceMutation
		}
		current = filepath.Join(current, part)
		info, err = r.dir.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) {
			return nil, ErrSourceMutation
		}
	}
	return info, nil
}

func (r *legacySourceRoot) Open(path string) (*os.File, error) {
	relative, err := r.relative(path)
	if err != nil {
		return nil, err
	}
	if relative == "." {
		return nil, ErrSourceMutation
	}
	if _, err = r.Lstat(path); err != nil {
		return nil, err
	}
	file, err := r.dir.Open(relative)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (r *legacySourceRoot) ReadDir(path string) ([]os.DirEntry, error) {
	file, err := r.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, ErrSourceMutation
	}
	return file.ReadDir(-1)
}

func (r *legacySourceRoot) ReadFile(path string) ([]byte, error) {
	file, err := r.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSnapshotFileBytes {
		return nil, ErrSourceMutation
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxSnapshotFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxSnapshotFileBytes {
		return nil, ErrBatchLimit
	}
	return data, nil
}

func copySQLiteFilesFromLegacyRoot(ctx context.Context, root *legacySourceRoot, mainPath, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if root == nil || strings.TrimSpace(mainPath) == "" || strings.TrimSpace(target) == "" {
		return ErrSourceRequired
	}
	if err := secureDestination(DefaultFileSystem(), target); err != nil {
		return err
	}
	if err := os.MkdirAll(target, SnapshotTreeMode); err != nil {
		return err
	}
	if err := os.Chmod(target, SnapshotTreeMode); err != nil {
		return err
	}
	sources := []string{mainPath}
	for _, suffix := range []string{"-wal", "-shm"} {
		path := mainPath + suffix
		if _, err := root.Lstat(path); err == nil {
			sources = append(sources, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	var total int64
	for _, sourcePath := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.Lstat(sourcePath)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return ErrSourceMutation
		}
		if info.Size() > MaxSnapshotFileBytes || total > MaxSnapshotBytes-info.Size() {
			return ErrBatchLimit
		}
		in, err := root.Open(sourcePath)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, filepath.Base(sourcePath))
		out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, SnapshotFileMode)
		if err != nil {
			_ = in.Close()
			return err
		}
		written, copyErr := io.CopyN(out, in, MaxSnapshotFileBytes+1)
		closeInErr := in.Close()
		closeOutErr := out.Close()
		if written > MaxSnapshotFileBytes {
			return ErrBatchLimit
		}
		if copyErr != nil && !errors.Is(copyErr, io.EOF) {
			return copyErr
		}
		if closeInErr != nil {
			return closeInErr
		}
		if closeOutErr != nil {
			return closeOutErr
		}
		if err := os.Chmod(destination, SnapshotFileMode); err != nil {
			return err
		}
		total += info.Size()
	}
	return nil
}
