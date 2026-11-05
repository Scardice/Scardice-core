//go:build windows

package v1reader

import (
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// localKeyEntropy is the DPAPI entropy the v1 store protected its key files
// with; a different value cannot unprotect them.
var localKeyEntropy = []byte("Scardice-core/eventstore/local-key/v1")

// readKeyFile reads one DPAPI-protected key file written by the v1 store. The
// file only opens for the same Windows user and machine that wrote it.
func readKeyFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer file.Close()
	protected, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(protected) == 0 || len(protected) > 64*1024 {
		return nil, ErrKeyUnavailable
	}
	input := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	entropy := windows.DataBlob{Size: uint32(len(localKeyEntropy)), Data: &localKeyEntropy[0]}
	var output windows.DataBlob
	if err = windows.CryptUnprotectData(&input, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, ErrKeyUnavailable
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	raw := append([]byte(nil), unsafe.Slice(output.Data, output.Size)...)
	if len(raw) != keyFileBytes {
		return nil, ErrKeyUnavailable
	}
	return raw, nil
}
