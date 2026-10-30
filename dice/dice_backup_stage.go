package dice

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const BackupStagingDirPrefix = ".scardice-backup-stage-"

const (
	backupStageOwnershipFile  = ".scardice-backup-owner"
	backupStageOwnershipValue = "scardice-backup-stage-v1\n"
)

var activeBackupStages sync.Map

func prepareBackupWorkspace() error {
	if err := os.MkdirAll(BackupDir, 0o755); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	entries, err := os.ReadDir(BackupDir)
	if err != nil {
		return fmt.Errorf("inspect backup directory for stale staging: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), BackupStagingDirPrefix) || entry.Type()&fs.ModeSymlink != 0 || !entry.IsDir() {
			continue
		}
		stageDir := filepath.Join(BackupDir, entry.Name())
		if _, active := activeBackupStages.Load(filepath.Clean(stageDir)); active {
			continue
		}
		markerPath := filepath.Join(stageDir, backupStageOwnershipFile)
		markerInfo, err := os.Lstat(markerPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect backup staging ownership %q: %w", entry.Name(), err)
		}
		if !markerInfo.Mode().IsRegular() || markerInfo.Size() != int64(len(backupStageOwnershipValue)) {
			continue
		}
		marker, err := os.ReadFile(markerPath)
		if err != nil {
			return fmt.Errorf("read backup staging ownership %q: %w", entry.Name(), err)
		}
		if string(marker) != backupStageOwnershipValue {
			continue
		}
		if err := os.RemoveAll(stageDir); err != nil {
			return fmt.Errorf("reclaim stale backup staging %q: %w", entry.Name(), err)
		}
	}
	return nil
}

func createBackupStagingDir() (string, error) {
	stageDir, err := os.MkdirTemp(BackupDir, BackupStagingDirPrefix)
	if err != nil {
		return "", fmt.Errorf("create backup staging directory: %w", err)
	}
	activeBackupStages.Store(filepath.Clean(stageDir), struct{}{})
	markerPath := filepath.Join(stageDir, backupStageOwnershipFile)
	marker, err := os.OpenFile(markerPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		activeBackupStages.Delete(filepath.Clean(stageDir))
		stageErr := fmt.Errorf("create backup staging ownership marker: %w", err)
		if cleanupErr := os.RemoveAll(stageDir); cleanupErr != nil {
			stageErr = errors.Join(stageErr, fmt.Errorf("clean incomplete backup staging directory: %w", cleanupErr))
		}
		return "", stageErr
	}
	written, writeErr := io.WriteString(marker, backupStageOwnershipValue)
	if writeErr == nil && written != len(backupStageOwnershipValue) {
		writeErr = io.ErrShortWrite
	}
	syncErr := marker.Sync()
	closeErr := marker.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		activeBackupStages.Delete(filepath.Clean(stageDir))
		var stageErr error
		switch {
		case writeErr != nil:
			stageErr = fmt.Errorf("write backup staging ownership marker: %w", writeErr)
		case syncErr != nil:
			stageErr = fmt.Errorf("sync backup staging ownership marker: %w", syncErr)
		default:
			stageErr = fmt.Errorf("close backup staging ownership marker: %w", closeErr)
		}
		if cleanupErr := os.RemoveAll(stageDir); cleanupErr != nil {
			stageErr = errors.Join(stageErr, fmt.Errorf("clean incomplete backup staging directory: %w", cleanupErr))
		}
		return "", stageErr
	}
	return stageDir, nil
}

func cleanBackupStagingDir(stageDir, publishedPath string) error {
	defer activeBackupStages.Delete(filepath.Clean(stageDir))
	if err := os.RemoveAll(stageDir); err != nil {
		cleanupErr := fmt.Errorf("clean backup staging directory: %w", err)
		if publishedPath == "" {
			return cleanupErr
		}
		if removeErr := os.Remove(publishedPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errors.Join(cleanupErr, fmt.Errorf("remove published backup after staging cleanup failure: %w", removeErr))
		}
		return cleanupErr
	}
	return nil
}
