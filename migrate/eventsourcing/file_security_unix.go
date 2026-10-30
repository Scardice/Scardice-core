//go:build !windows

package eventsourcing

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func openReadOnlyNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrSourceMutation
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrSourceMutation
	}
	return file, nil
}

func writeFileNoFollow(path string, data []byte, mode os.FileMode) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = syscall.Close(fd)
		return ErrSourceMutation
	}
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
