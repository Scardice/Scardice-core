//go:build windows

package eventstore

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var localKeyEntropy = []byte("Scardice-core/eventstore/local-key/v1")

func CreateLocalKeyFile(path string, material []byte) error {
	if len(material) != 32 {
		return ErrKeyUnavailable
	}
	if err := ensureSecurePath(filepath.Dir(path)); err != nil {
		return err
	}
	protected, err := protectLocalKey(material)
	if err != nil {
		return ErrKeyUnavailable
	}
	file, err := openWindowsFile(path, windows.GENERIC_WRITE, 0, windows.CREATE_NEW, true)
	if err != nil {
		return ErrKeyUnavailable
	}
	if _, err = file.Write(protected); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return ErrKeyUnavailable
	}
	return nil
}

func ensureSecurePath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ErrKeyUnavailable
	}
	clean := filepath.Clean(absolute)
	volume := filepath.VolumeName(clean)
	current := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(clean, current)
	for _, part := range strings.Split(remainder, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		pointer, pointerErr := windows.UTF16PtrFromString(current)
		if pointerErr != nil {
			return ErrKeyUnavailable
		}
		attributes, attributeErr := windows.GetFileAttributes(pointer)
		if attributeErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrKeyUnavailable
		}
	}
	return nil
}

func readCurrentRootID(path string) (string, error) {
	raw, err := readWindowsFile(path, 256)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func readSecureFile(path string, maxBytes int) ([]byte, error) {
	if maxBytes < 0 {
		return nil, ErrKeyUnavailable
	}
	protected, err := readWindowsFile(path, 64*1024)
	if err != nil {
		return nil, err
	}
	plaintext, err := unprotectLocalKey(protected)
	if err != nil || len(plaintext) > maxBytes {
		return nil, ErrKeyUnavailable
	}
	return plaintext, nil
}

func readWindowsFile(path string, maxBytes int) ([]byte, error) {
	if ensureSecurePath(filepath.Dir(path)) != nil {
		return nil, ErrKeyUnavailable
	}
	file, err := openWindowsFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, windows.OPEN_EXISTING, false)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(raw) > maxBytes {
		return nil, ErrKeyUnavailable
	}
	return raw, nil
}

func openWindowsFile(path string, access, share, creation uint32, writeThrough bool) (*os.File, error) {
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
		return nil, ErrKeyUnavailable
	}
	return os.NewFile(uintptr(handle), filepath.Base(path)), nil
}

func protectLocalKey(plaintext []byte) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	entropy := windows.DataBlob{Size: uint32(len(localKeyEntropy)), Data: &localKeyEntropy[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}

func unprotectLocalKey(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrKeyUnavailable
	}
	input := windows.DataBlob{Size: uint32(len(ciphertext)), Data: &ciphertext[0]}
	entropy := windows.DataBlob{Size: uint32(len(localKeyEntropy)), Data: &localKeyEntropy[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}
