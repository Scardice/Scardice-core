//nolint:testpackage
package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteFileCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := AtomicWriteFile(path, []byte("hello"), 0o640); err != nil {
		t.Fatalf("AtomicWriteFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("file content = %q, want %q", string(data), "hello")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("file mode = %o, want 640", got)
	}
}

func TestAtomicWriteFileOverwritesAndKeepsExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	if err := AtomicWriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatalf("AtomicWriteFile returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("file content = %q, want %q", string(data), "new")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
}

func TestAtomicWriteFileMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "config.yaml")

	if err := AtomicWriteFile(path, []byte("hello"), 0o644); err == nil {
		t.Fatal("expected error for missing parent directory, got nil")
	}
}

func TestAtomicWriteReaderCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upload.bin")

	if err := AtomicWriteReader(path, strings.NewReader("streamed"), 0o644); err != nil {
		t.Fatalf("AtomicWriteReader returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "streamed" {
		t.Fatalf("file content = %q, want %q", string(data), "streamed")
	}
}
