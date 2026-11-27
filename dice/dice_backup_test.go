//nolint:testpackage
package dice

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupStaleBackupTempFiles(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := os.MkdirAll(BackupDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", BackupDir, err)
	}

	oldPart := filepath.Join(BackupDir, "bak_old.zip"+BackupTempSuffix)
	freshPart := filepath.Join(BackupDir, "bak_new.zip"+BackupTempSuffix)
	finalFile := filepath.Join(BackupDir, "bak_done.zip")
	for _, path := range []string{oldPart, freshPart, finalFile} {
		if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	oldTime := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(oldPart, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes(%s) error = %v", oldPart, err)
	}

	cleanupStaleBackupTempFiles()

	if _, err := os.Stat(oldPart); !os.IsNotExist(err) {
		t.Fatalf("old temp file %s should be removed, err = %v", oldPart, err)
	}
	for _, path := range []string{freshPart, finalFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s should be kept, err = %v", path, err)
		}
	}
}
