package dice

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type cacheCodecFixture struct {
	Version int
	Items   []string
}

func TestSaveGobCacheFileUsesZstd(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.gob")
	expected := cacheCodecFixture{
		Version: 1,
		Items:   []string{"alpha", "beta", "gamma"},
	}

	if err := saveGobCacheFile(cachePath, &expected); err != nil {
		t.Fatalf("saveGobCacheFile() error = %v", err)
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(data) < len(cacheZstdMagic) || !bytes.Equal(data[:len(cacheZstdMagic)], cacheZstdMagic) {
		t.Fatalf("cache file is not zstd encoded")
	}

	var actual cacheCodecFixture
	if err := loadGobCacheFile(cachePath, &actual); err != nil {
		t.Fatalf("loadGobCacheFile() error = %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("loadGobCacheFile() = %#v, want %#v", actual, expected)
	}
}

func TestLoadGobCacheFileSupportsLegacyGob(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "legacy.gob")
	expected := cacheCodecFixture{
		Version: 2,
		Items:   []string{"legacy", "plain-gob"},
	}

	f, err := os.Create(cachePath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := gob.NewEncoder(f).Encode(&expected); err != nil {
		_ = f.Close()
		t.Fatalf("Encode() error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var actual cacheCodecFixture
	if err := loadGobCacheFile(cachePath, &actual); err != nil {
		t.Fatalf("loadGobCacheFile() error = %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("loadGobCacheFile() = %#v, want %#v", actual, expected)
	}
}
