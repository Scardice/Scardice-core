//go:build windows

package eventsourcing

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openReadOnlyNoFollow(path string) (*os.File, error) {
	return openWindowsMigrationFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, windows.OPEN_EXISTING, false)
}

func writeFileNoFollow(path string, data []byte, _ os.FileMode) error {
	file, err := openWindowsMigrationFile(path, windows.GENERIC_WRITE, 0, windows.CREATE_ALWAYS, true)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

func openWindowsMigrationFile(path string, access, share, creation uint32, writeThrough bool) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if writeThrough {
		flags |= windows.FILE_FLAG_WRITE_THROUGH
	}
	handle, err := windows.CreateFile(pointer, access, share, nil, creation, flags, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(handle)
		if err != nil {
			return nil, err
		}
		return nil, ErrSourceMutation
	}
	return os.NewFile(uintptr(handle), filepath.Base(path)), nil
}
