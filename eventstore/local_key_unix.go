//go:build !windows

package eventstore

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func CreateLocalKeyFile(path string, material []byte) error {
	if len(material) != 32 {
		return ErrKeyUnavailable
	}
	if err := ensureSecurePath(filepath.Dir(path)); err != nil {
		return err
	}
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrKeyUnavailable
	}
	if _, err = fd.Write(material); err == nil {
		err = fd.Sync()
	}
	return errorsJoinKeyFile(err, fd.Close())
}

func ensureSecurePath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ErrKeyUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrKeyUnavailable
		}
	}
	return nil
}

func readCurrentRootID(path string) (string, error) {
	raw, err := readSecureFile(path, 256)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func readSecureFile(path string, maxBytes int) ([]byte, error) {
	if maxBytes < 0 || ensureSecurePath(path) != nil {
		return nil, ErrKeyUnavailable
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrKeyUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, ErrKeyUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return nil, ErrKeyUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(raw) > maxBytes {
		return nil, ErrKeyUnavailable
	}
	return raw, nil
}

func errorsJoinKeyFile(writeErr, closeErr error) error {
	if writeErr != nil || closeErr != nil {
		return ErrKeyUnavailable
	}
	return nil
}
