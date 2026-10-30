package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexmullins/zip"

	"Scardice-core/eventstore"
	"Scardice-core/utils/crypto"
)

type eventStoreBackupSnapshotter interface {
	SnapshotSQLite(ctx context.Context, destination string) error
	BackupKeyFiles(ctx context.Context) ([]eventstore.BackupKeyFile, bool, error)
}

type eventStoreBackupEntry struct {
	name   string
	source string
	data   []byte
	mode   fs.FileMode
}

func (dm *DiceManager) backupEventStore(sel BackupSelection, fromAuto bool, progress *backupJobProgress) (result string, resultErr error) {
	if dm == nil || len(dm.Dice) == 0 || dm.Dice[0] == nil {
		return "", errors.New("dice: no runtime Dice is available for EventStore backup")
	}
	store := dm.durableStore
	if store == nil {
		store = dm.Dice[0].DurableStore
	}
	if store == nil {
		return "", errors.New("dice: authoritative EventStore is unavailable for backup")
	}
	snapshotter, ok := store.(eventStoreBackupSnapshotter)
	if !ok {
		return "", eventstore.ErrSnapshotUnsupported
	}
	stageDir, err := createBackupStagingDir()
	if err != nil {
		return "", err
	}
	publishedPath := ""
	defer func() {
		if cleanupErr := cleanBackupStagingDir(stageDir, publishedPath); cleanupErr != nil {
			result = ""
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()

	snapshotPath := filepath.Join(stageDir, "events.db")
	ctx := context.Background()
	progress.update(BackupJobStageSnapshot, 0, 0)
	if err := snapshotter.SnapshotSQLite(ctx, snapshotPath); err != nil {
		return "", fmt.Errorf("snapshot authoritative EventStore: %w", err)
	}

	progress.update(BackupJobStageCollecting, 0, 0)
	keyFiles, externalKeySource, err := snapshotter.BackupKeyFiles(ctx)
	if err != nil {
		return "", fmt.Errorf("collect EventStore backup key files: %w", err)
	}
	entries, config, err := eventStoreBackupFiles(dm.Dice, sel)
	if err != nil {
		return "", err
	}
	entries = append(entries, eventStoreBackupEntry{name: "data/endpoint/events.db", source: snapshotPath, mode: 0o600})
	for _, keyFile := range keyFiles {
		if keyFile.Name == "" || len(keyFile.Data) == 0 {
			return "", errors.New("eventstore: incomplete configured key file for backup")
		}
		entries = append(entries, eventStoreBackupEntry{name: keyFile.Name, data: keyFile.Data, mode: 0o600})
	}

	bakFn := "bak_" + time.Now().Format("060102_150405")
	if fromAuto {
		bakFn += "_auto"
	}
	bakFn += "_r" + strconv.FormatUint(uint64(sel), 16)
	fnHashed := crypto.CalculateSHA512Str([]byte(bakFn))[:8]
	bakFn += "_" + fnHashed + ".zip"
	stagePath := filepath.Join(stageDir, "backup.zip")
	archivePath := filepath.Join(BackupDir, bakFn)
	file, err := os.OpenFile(stagePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create staged EventStore backup: %w", err)
	}
	writer := zip.NewWriter(file)
	writerClosed := false
	fileClosed := false
	defer func() {
		if !writerClosed {
			_ = writer.Close()
		}
		if !fileClosed {
			_ = file.Close()
		}
	}()

	completedFiles := 0
	totalFiles := len(entries) + 1
	progress.update(BackupJobStageArchiving, completedFiles, totalFiles)
	for _, entry := range entries {
		if err := writeEventStoreBackupEntry(writer, entry); err != nil {
			return "", err
		}
		completedFiles++
		progress.update(BackupJobStageArchiving, completedFiles, totalFiles)
	}
	keyBoundary := "bundled-local-key-files"
	if externalKeySource {
		keyBoundary = "external-configured-key-source"
	}
	metadata, err := json.Marshal(map[string]any{
		"config":      config,
		"version":     VERSION.String(),
		"versionCode": VERSION_CODE,
		"eventStore": map[string]any{
			"database":                "data/endpoint/events.db",
			"snapshot":                "sqlite-vacuum-into",
			"keyMaterial":             keyBoundary,
			"storyLogArchiveIncluded": true,
		},
	})
	if err != nil {
		return "", fmt.Errorf("encode backup metadata: %w", err)
	}
	if err := writeEventStoreBackupEntry(writer, eventStoreBackupEntry{name: "backup_info.json", data: metadata}); err != nil {
		return "", err
	}
	completedFiles++
	progress.update(BackupJobStageFinalizing, completedFiles, totalFiles)
	err = writer.Close()
	writerClosed = true
	if err != nil {
		return "", fmt.Errorf("finish EventStore backup archive: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync EventStore backup archive: %w", err)
	}
	err = file.Close()
	fileClosed = true
	if err != nil {
		return "", fmt.Errorf("close EventStore backup archive: %w", err)
	}
	if err := os.Link(stagePath, archivePath); err != nil {
		return "", fmt.Errorf("publish EventStore backup archive: %w", err)
	}
	publishedPath = archivePath
	return archivePath, nil
}

func eventStoreBackupFiles(dices []*Dice, sel BackupSelection) ([]eventStoreBackupEntry, backupConfigGlobal, error) {
	config := backupConfigGlobal{Global: true, Dices: make(map[string]*backupConfigDice)}
	entries := make([]eventStoreBackupEntry, 0)
	if err := addEventStoreBackupFile(&entries, "data/endpoint/config.json"); err != nil {
		return nil, backupConfigGlobal{}, err
	}
	for _, selection := range []struct {
		bit  BackupSelection
		path string
		flag *bool
	}{
		{BackupSelectionDecks, "data/decks", &config.Decks},
		{BackupSelectionHelpDoc, "data/helpdoc", &config.HelpDoc},
		{BackupSelectionCensor, "data/censor", &config.Censor},
		{BackupSelectionNames, "data/names", &config.Names},
		{BackupSelectionImages, "data/images", &config.Images},
	} {
		if sel&selection.bit == 0 {
			continue
		}
		info, err := os.Stat(selection.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, backupConfigGlobal{}, fmt.Errorf("inspect backup directory %q: %w", selection.path, err)
		}
		if !info.IsDir() {
			return nil, backupConfigGlobal{}, fmt.Errorf("inspect backup directory %q: path is not a directory", selection.path)
		}
		*selection.flag = true
		include := func(path string, entry fs.DirEntry) bool { return true }
		var includeErr error
		if selection.bit == BackupSelectionDecks {
			include = func(path string, entry fs.DirEntry) bool {
				if !entry.IsDir() {
					return true
				}
				base := filepath.Base(path)
				if !strings.HasPrefix(base, "_") || !strings.HasSuffix(base, ".deck") {
					return true
				}
				exists, err := eventStoreBackupFileExists(filepath.Join(filepath.Dir(path), base[1:]))
				if err != nil {
					includeErr = err
					return false
				}
				return !exists
			}
		}
		if err := appendEventStoreBackupDirectory(&entries, selection.path, include); err != nil {
			return nil, backupConfigGlobal{}, err
		}
		if includeErr != nil {
			return nil, backupConfigGlobal{}, includeErr
		}
	}

	for _, d := range dices {
		if d == nil {
			return nil, backupConfigGlobal{}, errors.New("dice: nil runtime Dice in EventStore backup")
		}
		diceConfig := backupConfigDice{
			Accounts: true, MiscConfig: true, PlayerData: true, CustomReply: true,
			CustomText: true, JSScripts: sel&BackupSelectionJS != 0,
		}
		config.Dices[d.BaseConfig.Name] = &diceConfig
		dataDir := d.BaseConfig.DataDir
		for _, path := range []string{
			filepath.Join(dataDir, "configs", "plugin-configs.json"),
			filepath.Join(dataDir, "configs", "text-template.yaml"),
		} {
			if err := addEventStoreBackupFile(&entries, path); err != nil {
				return nil, backupConfigGlobal{}, err
			}
		}
		replyDir := filepath.Join(dataDir, "extensions", "reply")
		if err := appendEventStoreBackupDirectory(&entries, replyDir, func(path string, entry fs.DirEntry) bool {
			if entry.IsDir() {
				return !strings.EqualFold(entry.Name(), "assets") && !strings.EqualFold(entry.Name(), "images")
			}
			if strings.HasPrefix(entry.Name(), ".reply") || entry.Name() == "info.yaml" {
				return false
			}
			ext := filepath.Ext(path)
			return ext == ".yaml" || ext == ""
		}); err != nil {
			return nil, backupConfigGlobal{}, err
		}
		if sel&BackupSelectionJS != 0 {
			if err := appendEventStoreBackupDirectory(&entries, filepath.Join(dataDir, "scripts"), func(_ string, entry fs.DirEntry) bool {
				if entry.IsDir() && entry.Name() == "_builtin" {
					return false
				}
				return entry.IsDir() || filepath.Ext(entry.Name()) == ".js"
			}); err != nil {
				return nil, backupConfigGlobal{}, err
			}
			extDataDir := filepath.Join(dataDir, "extensions")
			if err := appendEventStoreBackupDirectory(&entries, extDataDir, func(path string, entry fs.DirEntry) bool {
				if entry.IsDir() {
					if filepath.Dir(path) == extDataDir {
						ext := d.ExtFind(entry.Name(), false)
						return ext != nil && ext.IsJsExt
					}
					return true
				}
				return true
			}); err != nil {
				return nil, backupConfigGlobal{}, err
			}
		}
	}
	return entries, config, nil
}

func appendEventStoreBackupDirectory(entries *[]eventStoreBackupEntry, root string, include func(string, fs.DirEntry) bool) error {
	info, err := os.Stat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect backup directory %q: %w", root, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("inspect backup directory %q: path is not a directory", root)
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk backup path %q: %w", path, walkErr)
		}
		if entry.IsDir() {
			if include != nil && !include(path, entry) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect backup file %q: %w", path, err)
		}
		if !fileInfo.Mode().IsRegular() || (include != nil && !include(path, entry)) {
			return nil
		}
		*entries = append(*entries, eventStoreBackupEntry{name: filepath.ToSlash(path), source: path})
		return nil
	})
}

func addEventStoreBackupFile(entries *[]eventStoreBackupEntry, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect backup file %q: %w", path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("inspect backup file %q: path is not a regular file", path)
	}
	*entries = append(*entries, eventStoreBackupEntry{name: filepath.ToSlash(path), source: path})
	return nil
}

func writeEventStoreBackupEntry(writer *zip.Writer, entry eventStoreBackupEntry) error {
	header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate, Flags: 0x800}
	if entry.mode != 0 {
		header.SetMode(entry.mode)
	}
	output, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create backup entry %q: %w", entry.name, err)
	}
	if entry.source != "" {
		input, err := os.Open(entry.source)
		if err != nil {
			return fmt.Errorf("open backup file %q: %w", entry.source, err)
		}
		_, copyErr := io.Copy(output, input)
		closeErr := input.Close()
		if copyErr != nil {
			return fmt.Errorf("copy backup file %q: %w", entry.source, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close backup file %q: %w", entry.source, closeErr)
		}
		return nil
	}
	if _, err := output.Write(entry.data); err != nil {
		return fmt.Errorf("write backup entry %q: %w", entry.name, err)
	}
	return nil
}

func eventStoreBackupFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect backup file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("inspect backup file %q: path is not a regular file", path)
	}
	return true, nil
}
