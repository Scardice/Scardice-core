package dice

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupStartReclaimsOnlyOwnedStaleStages(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(BackupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(BackupDir, BackupStagingDirPrefix+"owned")
	unowned := filepath.Join(BackupDir, BackupStagingDirPrefix+"unowned")
	unrelated := filepath.Join(BackupDir, "user-data")
	for _, dir := range []string{owned, unowned, unrelated} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(owned, backupStageOwnershipFile), []byte(backupStageOwnershipValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "partial.zip"), []byte("interrupted backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unowned, backupStageOwnershipFile), []byte("not owned by Scardice\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := &DiceManager{}
	if _, err := manager.Backup(BackupSelectionBasic, false); err == nil {
		t.Fatal("backup without a runtime Dice unexpectedly succeeded")
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("owned interrupted staging directory was not reclaimed: %v", err)
	}
	for _, path := range []string{unowned, unrelated} {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Fatalf("non-owned path %q was changed during reclamation: info=%v err=%v", path, info, err)
		}
	}
	job := manager.BackupJobSnapshot()
	if job == nil || job.Status != BackupJobStatusFailed || job.Stage != BackupJobStagePreparing {
		t.Fatalf("failed backup job after residue cleanup = %#v", job)
	}
}

func TestBackupResidueSweepPreservesActiveOwnedStage(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := prepareBackupWorkspace(); err != nil {
		t.Fatal(err)
	}
	stageDir, err := createBackupStagingDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanBackupStagingDir(stageDir, "") })

	if err := prepareBackupWorkspace(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(stageDir); err != nil || !info.IsDir() {
		t.Fatalf("active owned staging directory was reclaimed: info=%v err=%v", info, err)
	}
}
