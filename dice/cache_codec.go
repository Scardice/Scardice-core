package dice

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

var cacheZstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

func loadGobCacheFile(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var decoded io.Reader = reader
	if magic, err := reader.Peek(len(cacheZstdMagic)); err == nil && bytes.Equal(magic, cacheZstdMagic) {
		zr, err := zstd.NewReader(reader)
		if err != nil {
			return err
		}
		defer zr.Close()
		decoded = zr
	}

	return gob.NewDecoder(decoded).Decode(value)
}

func saveGobCacheFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	encErr := gob.NewEncoder(zw).Encode(value)
	if err := zw.Close(); err != nil && encErr == nil {
		encErr = err
	}
	if err := f.Close(); err != nil && encErr == nil {
		encErr = err
	}
	if encErr != nil {
		_ = os.Remove(tmpPath)
		return encErr
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
