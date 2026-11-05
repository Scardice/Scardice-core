//go:build !windows

package v1reader

import (
	"io"
	"os"
)

// readKeyFile reads one raw 32-byte key file. Unlike the v1 runtime it does not
// insist on owner-only permissions: the files are only read here, once, by the
// person who runs the migration.
func readKeyFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrKeyUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, keyFileBytes+1))
	if err != nil || len(raw) != keyFileBytes {
		return nil, ErrKeyUnavailable
	}
	return raw, nil
}
