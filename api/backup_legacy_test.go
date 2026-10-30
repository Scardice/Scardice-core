package api

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"Scardice-core/dice"
)

func newLegacyBackupAPIFixture(t *testing.T) *echo.Echo {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	dataDir := filepath.Join("data", "default")
	for _, dir := range []string{
		filepath.Join(dataDir, "configs"),
		filepath.Join(dataDir, "extensions", "reply"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string][]byte{
		filepath.Join("data", "dice.yaml"):                         []byte("legacy: true\n"),
		filepath.Join(dataDir, "serve.yaml"):                       []byte("legacy: true\n"),
		filepath.Join(dataDir, "configs", "plugin-configs.json"):   []byte(`{"legacy":true}`),
		filepath.Join(dataDir, "extensions", "reply", "base.yaml"): []byte("reply: true\n"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeLegacyBackupPayload(t, filepath.Join(dataDir, "configs", "text-template.yaml"), 16<<20)

	databasePath := filepath.Join(dataDir, "data.db")
	database, err := gorm.Open(gormsqlite.Open(databasePath), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("open legacy backup database: %v", err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := database.Exec("CREATE TABLE IF NOT EXISTS backup_probe (id INTEGER PRIMARY KEY, value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO backup_probe(value) VALUES (?)", "legacy backup row").Error; err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "data-logs.db"), []byte("legacy log database fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	runtimeDice := &dice.Dice{
		BaseConfig: dice.BaseConfig{Name: "default", DataDir: dataDir},
		Logger:     zap.NewNop().Sugar(),
		DBOperator: &uiAPIContractLogOperator{db: database},
	}
	manager := setUpUIAPIContractDice(t, runtimeDice)
	server := echo.New()
	server.Use(middleware.Recover())
	Bind(server, manager)
	return server
}

func writeLegacyBackupPayload(t *testing.T, path string, size int) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64<<10)
	state := uint64(0x9e3779b97f4a7c15)
	remaining := size
	for remaining > 0 {
		count := min(len(buffer), remaining)
		for index := range count {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			buffer[index] = byte(state)
		}
		if _, err := file.Write(buffer[:count]); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		remaining -= count
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyBackupPublishesOnlyCompleteReadableArchiveWithTruthfulProgress(t *testing.T) {
	server := newLegacyBackupAPIFixture(t)
	response := postBackup(t, server, uint64(dice.BackupSelectionBasic))
	if response.Code != http.StatusAccepted {
		t.Fatalf("legacy backup acceptance status = %d, want %d: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	accepted := decodeBackupJobResponse(t, response)
	if !accepted.Success || accepted.Job == nil {
		t.Fatalf("legacy backup acceptance = %#v", accepted)
	}

	deadline := time.Now().Add(10 * time.Second)
	observedArchiving := false
	var finished *dice.BackupJob
	for time.Now().Before(deadline) {
		_, job := getBackupStatus(t, server, uiAPIContractToken)
		if job == nil || job.ID != accepted.Job.ID {
			t.Fatalf("legacy backup status = %#v, want job %q", job, accepted.Job.ID)
		}
		if job.Status == dice.BackupJobStatusRunning {
			if job.Stage == dice.BackupJobStageArchiving {
				observedArchiving = true
				if job.CompletedFiles != 0 || job.TotalFiles != 0 {
					t.Fatalf("legacy archiving progress = %#v; want indeterminate 0/0 until finalization", job)
				}
			}
			for _, item := range listBackups(t, server) {
				download := downloadBackup(t, server, item.Name)
				if download.Code != http.StatusOK {
					t.Fatalf("visible running legacy archive %q download status = %d", item.Name, download.Code)
				}
				reader, err := zip.NewReader(bytes.NewReader(download.Body.Bytes()), int64(download.Body.Len()))
				if err != nil {
					t.Fatalf("visible running legacy archive %q was partial: %v", item.Name, err)
				}
				for _, entry := range reader.File {
					input, err := entry.Open()
					if err != nil {
						t.Fatalf("open visible legacy ZIP entry %q: %v", entry.Name, err)
					}
					_, readErr := io.Copy(io.Discard, input)
					closeErr := input.Close()
					if readErr != nil || closeErr != nil {
						t.Fatalf("read visible legacy ZIP entry %q: read=%v close=%v", entry.Name, readErr, closeErr)
					}
				}
			}
			time.Sleep(time.Millisecond)
			continue
		}
		finished = job
		break
	}
	if finished == nil {
		t.Fatal("legacy backup did not reach a terminal state")
	}
	if !observedArchiving {
		t.Fatal("legacy backup never exposed its indeterminate archiving stage")
	}
	if finished.Status != dice.BackupJobStatusSucceeded || finished.Stage != dice.BackupJobStageFinalizing ||
		finished.Filename == "" || finished.CompletedFiles <= 0 || finished.CompletedFiles != finished.TotalFiles {
		t.Fatalf("legacy terminal job = %#v; want successful complete counts", finished)
	}

	items := listBackups(t, server)
	if len(items) != 1 || items[0].Name != finished.Filename {
		t.Fatalf("published legacy backups = %#v, terminal=%#v", items, finished)
	}
	files := readBackupZip(t, filepath.Join(dice.BackupDir, finished.Filename))
	if len(files) != finished.TotalFiles {
		t.Fatalf("legacy terminal total = %d, archive entries = %d", finished.TotalFiles, len(files))
	}
	for _, name := range []string{
		"data/dice.yaml",
		filepath.Join("data", "default", "serve.yaml"),
		filepath.Join("data", "default", "data.db"),
		filepath.Join("data", "default", "data-logs.db"),
		filepath.Join("data", "default", "configs", "text-template.yaml"),
		filepath.Join("data", "default", "extensions", "reply", "base.yaml"),
		"backup_info.json",
	} {
		if _, ok := files[name]; !ok {
			t.Errorf("legacy backup is missing %q", name)
		}
	}
	if err := os.WriteFile(filepath.Join("data", "images"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	failedResponse := postBackup(t, server, uint64(dice.BackupSelectionBasic|dice.BackupSelectionImages))
	if failedResponse.Code != http.StatusAccepted {
		t.Fatalf("storage-error backup status = %d, body=%s", failedResponse.Code, failedResponse.Body.String())
	}
	failedStart := decodeBackupJobResponse(t, failedResponse)
	failed := waitForBackupTerminal(t, server, failedStart.Job.ID)
	if failed.Status != dice.BackupJobStatusFailed || !strings.Contains(failed.Error, "path is not a directory") {
		t.Fatalf("masked legacy storage error job = %#v", failed)
	}
	if afterFailure := listBackups(t, server); len(afterFailure) != 1 || afterFailure[0].Name != finished.Filename {
		t.Fatalf("failed legacy backup published an archive: %#v", afterFailure)
	}

	stages, err := filepath.Glob(filepath.Join(dice.BackupDir, dice.BackupStagingDirPrefix+"*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("legacy staging residue = %v, err=%v", stages, err)
	}
}
