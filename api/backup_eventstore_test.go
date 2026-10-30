package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"Scardice-core/dice"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

func newEventStoreBackupAPIFixture(t *testing.T) (*echo.Echo, *eventstore.Database, *eventstore.GORMStore, *dice.DiceManager) {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)

	endpointKeys := filepath.Join(root, "data", "endpoint", "keys")
	rootsDir := filepath.Join(endpointKeys, "roots")
	if err := os.MkdirAll(rootsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(endpointKeys, "index.key")
	if err := eventstore.CreateLocalKeyFile(indexPath, bytes.Repeat([]byte{0x41}, 32)); err != nil {
		t.Fatalf("create local index key: %v", err)
	}
	if err := eventstore.CreateLocalKeyFile(filepath.Join(rootsDir, "root-v1.key"), bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatalf("create local encryption root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootsDir, "current"), []byte("root-v1\n"), 0o600); err != nil {
		t.Fatalf("write current encryption root: %v", err)
	}
	keys := eventstore.NewLocalFileKeySource(indexPath, rootsDir)

	databasePath := filepath.Join(root, "data", "endpoint", "events.db")
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: databasePath, KeySource: keys, DatabaseIdentity: "backup-api-test",
	})
	if err != nil {
		t.Fatalf("open EventStore database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	if _, err := database.SQLDB().ExecContext(ctx, "PRAGMA wal_autocheckpoint = 0"); err != nil {
		t.Fatalf("disable test WAL autocheckpoint: %v", err)
	}
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "backup-api-test", IndexRootID: filepath.Base(indexPath),
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatalf("set EventStore readiness: %v", err)
	}
	if _, err := store.CreateStoryLog(ctx, "default", "backup-group", "backup-session"); err != nil {
		t.Fatalf("create typed story-log session: %v", err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: "default", GroupID: "backup-group", LogName: "backup-session",
		Nickname: "Player", IMUserID: "backup-player", Time: 1760000000,
		Message: "latest committed WAL story entry", RawMsgID: "backup-message", UniformID: "backup-uniform",
	}); err != nil {
		t.Fatalf("append typed story-log entry: %v", err)
	}
	walInfo, err := os.Stat(databasePath + "-wal")
	if err != nil || walInfo.Size() <= 32 {
		t.Fatalf("expected committed EventStore writes in WAL before backup, stat=%v err=%v", walInfo, err)
	}

	dataDir := filepath.Join(root, "data", "default")
	for _, dir := range []string{
		filepath.Join(dataDir, "configs"), filepath.Join(dataDir, "extensions", "reply"),
		filepath.Join(dataDir, "scripts"), filepath.Join(root, "data", "images"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string][]byte{
		filepath.Join(dataDir, "configs", "plugin-configs.json"):      []byte(`{"plugin":"configured"}`),
		filepath.Join(dataDir, "configs", "text-template.yaml"):       []byte("custom: true\n"),
		filepath.Join(dataDir, "extensions", "reply", "default.yaml"): []byte("reply: true\n"),
		filepath.Join(dataDir, "scripts", "selected.js"):              []byte("// optional script\n"),
		filepath.Join(root, "data", "images", "selected.png"):         []byte("optional image fixture"),
	} {
		if err := os.WriteFile(name, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	runtimeDice := &dice.Dice{
		BaseConfig: dice.BaseConfig{Name: "default", DataDir: filepath.Join("data", "default")},
		Logger:     logger.M(), DurableStore: store,
	}
	manager := setUpUIAPIContractDice(t, runtimeDice)
	manager.EventSourcedMode = true
	server := echo.New()
	server.Use(middleware.Recover())
	Bind(server, manager)
	return server, database, store, manager
}

type gatedEventStoreBackup struct {
	*eventstore.GORMStore
	snapshotEntered chan struct{}
	snapshotRelease chan struct{}
	enterOnce       sync.Once
	snapshotCalls   atomic.Int32
	snapshotPath    string
}

func (s *gatedEventStoreBackup) SnapshotSQLite(ctx context.Context, destination string) error {
	s.snapshotCalls.Add(1)
	s.snapshotPath = destination
	s.enterOnce.Do(func() { close(s.snapshotEntered) })
	select {
	case <-s.snapshotRelease:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.GORMStore.SnapshotSQLite(ctx, destination)
}

func downloadBackup(t *testing.T, server *echo.Echo, name string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/sd-api/backup/download?name="+url.QueryEscape(name), nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

func listBackups(t *testing.T, server *echo.Echo) []backupFileItem {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/sd-api/backup/list", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("backup list HTTP status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var result struct {
		Items []backupFileItem `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode backup list: %v", err)
	}
	return result.Items
}

type backupZipEntry struct {
	data []byte
	mode fs.FileMode
}

func readBackupZip(t *testing.T, name string) map[string]backupZipEntry {
	t.Helper()
	reader, err := zip.OpenReader(name)
	if err != nil {
		t.Fatalf("open backup zip: %v", err)
	}
	defer reader.Close()
	files := make(map[string]backupZipEntry, len(reader.File))
	for _, file := range reader.File {
		input, err := file.Open()
		if err != nil {
			t.Fatalf("open backup entry %q: %v", file.Name, err)
		}
		data, readErr := io.ReadAll(input)
		closeErr := input.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read backup entry %q: read=%v close=%v", file.Name, readErr, closeErr)
		}
		files[file.Name] = backupZipEntry{data: data, mode: file.Mode()}
	}
	return files
}

func findEventStoreBackup(t *testing.T) string {
	t.Helper()
	backups, err := filepath.Glob(filepath.Join(dice.BackupDir, "*.zip"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backup archives = %v, err=%v; want exactly one", backups, err)
	}
	return backups[0]
}

func TestBackupStatusRequiresAuthenticationAndStartsEmpty(t *testing.T) {
	server, _, _, _ := newEventStoreBackupAPIFixture(t)

	unauthorized, _ := getBackupStatus(t, server, "")
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated backup status = %d, want %d: %s", unauthorized.Code, http.StatusForbidden, unauthorized.Body.String())
	}

	unauthorizedStartRequest := httptest.NewRequest(http.MethodPost, "/sd-api/backup/do_backup", strings.NewReader(`{"selection":0}`))
	unauthorizedStartRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	unauthorizedStart := httptest.NewRecorder()
	server.ServeHTTP(unauthorizedStart, unauthorizedStartRequest)
	if unauthorizedStart.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated backup start = %d, want %d: %s", unauthorizedStart.Code, http.StatusForbidden, unauthorizedStart.Body.String())
	}
	authorized, job := getBackupStatus(t, server, uiAPIContractToken)
	if authorized.Code != http.StatusOK || job != nil || authorized.Body.String() != "{\"job\":null}\n" {
		t.Fatalf("fresh authenticated backup status = %d job=%#v body=%s; want job=null", authorized.Code, job, authorized.Body.String())
	}
}

func TestBackupPOSTRejectsMalformedInputAndPreservesDemoMode(t *testing.T) {
	server, _, _, manager := newEventStoreBackupAPIFixture(t)

	malformedRequest := httptest.NewRequest(http.MethodPost, "/sd-api/backup/do_backup", strings.NewReader(`{"selection":`))
	malformedRequest.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	malformedRequest.Header.Set("Token", uiAPIContractToken)
	malformedResponse := httptest.NewRecorder()
	server.ServeHTTP(malformedResponse, malformedRequest)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatalf("malformed backup request status = %d, want %d: %s", malformedResponse.Code, http.StatusBadRequest, malformedResponse.Body.String())
	}
	malformed := decodeBackupJobResponse(t, malformedResponse)
	if malformed.Success || malformed.Error == "" || malformed.Job != nil {
		t.Fatalf("malformed backup response = %#v; want detailed failure without a job", malformed)
	}

	manager.JustForTest = true
	demoResponse := postBackup(t, server, uint64(dice.BackupSelectionBasic))
	if demoResponse.Code != http.StatusOK || demoResponse.Body.String() != "{\"testMode\":true}\n" {
		t.Fatalf("demo backup response = status %d body %s; want unchanged testMode response", demoResponse.Code, demoResponse.Body.String())
	}
	_, job := getBackupStatus(t, server, uiAPIContractToken)
	if job != nil {
		t.Fatalf("demo backup unexpectedly created a job: %#v", job)
	}
}

func TestBackupPOSTReturnsPromptlyAndSharesSingleFlightWithSynchronousAndCronCallers(t *testing.T) {
	server, _, store, manager := newEventStoreBackupAPIFixture(t)
	gated := &gatedEventStoreBackup{
		GORMStore: store, snapshotEntered: make(chan struct{}), snapshotRelease: make(chan struct{}),
	}
	myDice.DurableStore = gated
	var releaseOnce sync.Once
	releaseSnapshot := func() { releaseOnce.Do(func() { close(gated.snapshotRelease) }) }
	defer releaseSnapshot()

	body, err := json.Marshal(map[string]uint64{"selection": uint64(dice.BackupSelectionBasic)})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/sd-api/backup/do_backup", bytes.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	request.Header.Set("Token", uiAPIContractToken)
	responseChannel := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		responseChannel <- recorder
	}()

	select {
	case <-gated.snapshotEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("asynchronous backup did not reach the snapshot stage")
	}
	backupRoot, err := filepath.Abs(dice.BackupDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath, err := filepath.Abs(gated.snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	relativeSnapshot, err := filepath.Rel(backupRoot, snapshotPath)
	if err != nil || relativeSnapshot == ".." || strings.HasPrefix(relativeSnapshot, ".."+string(filepath.Separator)) ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(snapshotPath)), dice.BackupStagingDirPrefix) {
		t.Fatalf("snapshot scratch path = %q, want hidden staging under backup root %q (relative=%q, err=%v)",
			gated.snapshotPath, backupRoot, relativeSnapshot, err)
	}
	var acceptedResponse *httptest.ResponseRecorder
	select {
	case acceptedResponse = <-responseChannel:
	case <-time.After(2 * time.Second):
		t.Fatal("backup POST waited for the blocked snapshot instead of returning promptly")
	}
	if acceptedResponse.Code != http.StatusAccepted {
		t.Fatalf("backup acceptance status = %d, want %d: %s", acceptedResponse.Code, http.StatusAccepted, acceptedResponse.Body.String())
	}
	accepted := decodeBackupJobResponse(t, acceptedResponse)
	if !accepted.Success || accepted.Job == nil || accepted.Job.Status != dice.BackupJobStatusRunning {
		t.Fatalf("backup acceptance = %#v; want running job", accepted)
	}
	_, running := getBackupStatus(t, server, uiAPIContractToken)
	if running == nil || running.ID != accepted.Job.ID || running.Stage != dice.BackupJobStageSnapshot ||
		running.CompletedFiles != 0 || running.TotalFiles != 0 {
		t.Fatalf("blocked snapshot progress = %#v; want indeterminate snapshot stage", running)
	}
	if items := listBackups(t, server); len(items) != 0 {
		t.Fatalf("backup list exposed in-progress staging artifacts: %#v", items)
	}

	busyResponse := postBackup(t, server, uint64(dice.BackupSelectionBasic))
	if busyResponse.Code != http.StatusConflict {
		t.Fatalf("duplicate backup status = %d, want %d: %s", busyResponse.Code, http.StatusConflict, busyResponse.Body.String())
	}
	busy := decodeBackupJobResponse(t, busyResponse)
	if busy.Success || busy.Error == "" || busy.Job == nil || busy.Job.ID != accepted.Job.ID {
		t.Fatalf("duplicate backup response = %#v; want active job and detailed busy error", busy)
	}
	if _, err := manager.Backup(dice.BackupSelectionBasic, false); !errors.Is(err, dice.ErrBackupInProgress) {
		t.Fatalf("synchronous backup during UI job error = %v, want ErrBackupInProgress", err)
	}
	if err := manager.BackupAuto(); !errors.Is(err, dice.ErrBackupInProgress) {
		t.Fatalf("cron backup during UI job error = %v, want ErrBackupInProgress", err)
	}
	if calls := gated.snapshotCalls.Load(); calls != 1 {
		t.Fatalf("snapshot executions while callers contend = %d, want one", calls)
	}

	activities, err := store.RecentManagementActivities(context.Background(), 10)
	if err != nil {
		t.Fatalf("read backup management activity: %v", err)
	}
	acceptedActivity := false
	for _, activity := range activities {
		if activity.Action == "backup_create" && activity.Status == "accepted" && activity.HTTPStatus == http.StatusAccepted {
			acceptedActivity = true
			break
		}
	}
	if !acceptedActivity {
		t.Fatalf("HTTP 202 backup acceptance was not recorded as accepted: %#v", activities)
	}

	releaseSnapshot()
	finished := waitForBackupTerminal(t, server, accepted.Job.ID)
	if finished.Status != dice.BackupJobStatusSucceeded || finished.Filename == "" ||
		finished.CompletedFiles != finished.TotalFiles || finished.TotalFiles <= 0 {
		t.Fatalf("released backup terminal status = %#v; want successful archive and complete counts", finished)
	}
}

func TestEventStoreBaseBackupPOSTProducesReopenableAuthoritativeSnapshot(t *testing.T) {
	server, _, _, _ := newEventStoreBackupAPIFixture(t)

	blockedSystemTemp := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedSystemTemp, []byte("system temp must not be used"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, blockedSystemTemp)
	}
	if runtime.GOOS != "windows" {
		if unexpected, err := os.MkdirTemp("", "backup-system-temp-probe-"); err == nil {
			_ = os.RemoveAll(unexpected)
			t.Fatalf("invalid test setup: system temporary directory remained usable at %q", unexpected)
		}
	}

	if dice.BackupSelectionBasic != 0 {
		t.Fatalf("base selection = %d, want UI contract value 0", dice.BackupSelectionBasic)
	}
	response := postBackup(t, server, uint64(dice.BackupSelectionBasic))
	if response.Code != http.StatusAccepted {
		t.Fatalf("base backup HTTP status = %d, want %d: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	accepted := decodeBackupJobResponse(t, response)
	if !accepted.Success || accepted.Job == nil || accepted.Job.ID == "" ||
		accepted.Job.Status != dice.BackupJobStatusRunning || accepted.Job.Stage != dice.BackupJobStagePreparing ||
		accepted.Job.CompletedFiles != 0 || accepted.Job.TotalFiles != 0 ||
		accepted.Job.StartedAt <= 0 || accepted.Job.FinishedAt != 0 {
		t.Fatalf("base backup acceptance = %#v; want a running job", accepted)
	}
	finished := waitForBackupTerminal(t, server, accepted.Job.ID)
	if finished.Status != dice.BackupJobStatusSucceeded || finished.Stage != dice.BackupJobStageFinalizing ||
		finished.Filename == "" || finished.Error != "" || finished.TotalFiles <= 0 ||
		finished.CompletedFiles != finished.TotalFiles || finished.StartedAt <= 0 || finished.FinishedAt < finished.StartedAt {
		t.Fatalf("completed base backup job = %#v; want truthful successful terminal progress", finished)
	}
	_, persisted := getBackupStatus(t, server, uiAPIContractToken)
	if persisted == nil || *persisted != *finished {
		t.Fatalf("terminal backup status did not persist in manager memory: first=%#v later=%#v", finished, persisted)
	}
	stages, err := filepath.Glob(filepath.Join(dice.BackupDir, dice.BackupStagingDirPrefix+"*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("staging artifacts after successful backup = %v, err=%v; want complete cleanup", stages, err)
	}

	baseArchive := findEventStoreBackup(t)
	if filepath.Base(baseArchive) != finished.Filename {
		t.Fatalf("terminal filename = %q, published archive = %q", finished.Filename, filepath.Base(baseArchive))
	}
	archiveInfo, err := os.Stat(baseArchive)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && archiveInfo.Mode().Perm() != 0o600 {
		t.Fatalf("backup archive permissions = %04o, want 0600", archiveInfo.Mode().Perm())
	}
	download := downloadBackup(t, server, filepath.Base(baseArchive))
	if download.Code != http.StatusOK || download.Body.Len() == 0 {
		t.Fatalf("base backup download status=%d bytes=%d; want non-empty HTTP 200", download.Code, download.Body.Len())
	}
	downloadedPath := filepath.Join(t.TempDir(), "downloaded.zip")
	if err := os.WriteFile(downloadedPath, download.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	baseFiles := readBackupZip(t, downloadedPath)
	if finished.TotalFiles != len(baseFiles) {
		t.Fatalf("terminal file total = %d, archive entries = %d", finished.TotalFiles, len(baseFiles))
	}
	listedArchives := listBackups(t, server)
	published := false
	for _, item := range listedArchives {
		if item.Name == filepath.Base(baseArchive) {
			published = true
			break
		}
	}
	if !published {
		t.Fatalf("complete downloaded backup %q was not visible in authenticated list: %#v", filepath.Base(baseArchive), listedArchives)
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{
			"data/endpoint/events.db", "data/endpoint/keys/index.key",
			"data/endpoint/keys/roots/current", "data/endpoint/keys/roots/root-v1.key",
		} {
			if mode := baseFiles[name].mode.Perm(); mode != 0o600 {
				t.Errorf("sensitive ZIP entry %q mode = %04o, want 0600", name, mode)
			}
		}
	}
	for _, name := range []string{
		"data/endpoint/events.db", "data/endpoint/keys/index.key", "data/endpoint/keys/roots/current",
		"data/endpoint/keys/roots/root-v1.key", "data/default/configs/plugin-configs.json",
		"data/default/configs/text-template.yaml", "data/default/extensions/reply/default.yaml",
		"backup_info.json",
	} {
		if _, ok := baseFiles[name]; !ok {
			t.Errorf("base backup is missing %q", name)
		}
	}
	var metadata struct {
		EventStore struct {
			Database                string `json:"database"`
			Snapshot                string `json:"snapshot"`
			KeyMaterial             string `json:"keyMaterial"`
			StoryLogArchiveIncluded bool   `json:"storyLogArchiveIncluded"`
		} `json:"eventStore"`
	}
	if err := json.Unmarshal(baseFiles["backup_info.json"].data, &metadata); err != nil ||
		metadata.EventStore.Database != "data/endpoint/events.db" ||
		metadata.EventStore.Snapshot != "sqlite-vacuum-into" ||
		metadata.EventStore.KeyMaterial != "bundled-local-key-files" ||
		!metadata.EventStore.StoryLogArchiveIncluded {
		t.Fatalf("EventStore backup metadata = %+v, err=%v", metadata.EventStore, err)
	}
	for _, name := range []string{"data/default/scripts/selected.js", "data/images/selected.png"} {
		if _, ok := baseFiles[name]; ok {
			t.Errorf("base-only backup unexpectedly includes optional file %q", name)
		}
	}
	for _, name := range []string{"data/default/data.db", "data/default/data-logs.db"} {
		if _, ok := baseFiles[name]; ok {
			t.Errorf("EventStore backup unexpectedly includes legacy SQL database %q", name)
		}
	}

	unpackRoot := t.TempDir()
	for name, entry := range baseFiles {
		destination := filepath.Join(unpackRoot, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, entry.data, entry.mode.Perm()); err != nil {
			t.Fatalf("extract %q with archived mode %04o: %v", name, entry.mode.Perm(), err)
		}
	}
	restoredDB, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(unpackRoot, "data", "endpoint", "events.db"),
		KeySource: eventstore.NewLocalFileKeySource(
			filepath.Join(unpackRoot, "data", "endpoint", "keys", "index.key"),
			filepath.Join(unpackRoot, "data", "endpoint", "keys", "roots"),
		), DatabaseIdentity: "backup-api-test",
	})
	if err != nil {
		t.Fatalf("reopen extracted EventStore snapshot with bundled configured key files: %v", err)
	}
	defer restoredDB.Close()
	restoredStore := eventstore.NewStore(restoredDB)
	logs, err := restoredStore.ListStoryLogs(context.Background(), "default", "backup-group")
	if err != nil || len(logs) != 1 || logs[0].Name != "backup-session" {
		t.Fatalf("restored story-log sessions = %#v, err=%v", logs, err)
	}
	entries, err := restoredStore.GetStoryLogEntries(context.Background(), "default", "backup-group", "backup-session")
	if err != nil || len(entries) != 1 || entries[0].Message != "latest committed WAL story entry" {
		t.Fatalf("restored/decrypted story-log entries = %#v, err=%v", entries, err)
	}

	optionalResponse := postBackup(t, server, uint64(dice.BackupSelectionImages|dice.BackupSelectionJS))
	if optionalResponse.Code != http.StatusAccepted {
		t.Fatalf("optional backup HTTP status = %d, want %d: %s", optionalResponse.Code, http.StatusAccepted, optionalResponse.Body.String())
	}
	optionalAccepted := decodeBackupJobResponse(t, optionalResponse)
	if !optionalAccepted.Success || optionalAccepted.Job == nil {
		t.Fatalf("optional backup acceptance = %#v", optionalAccepted)
	}
	optionalFinished := waitForBackupTerminal(t, server, optionalAccepted.Job.ID)
	if optionalFinished.Status != dice.BackupJobStatusSucceeded || optionalFinished.Filename == "" {
		t.Fatalf("optional backup terminal status = %#v", optionalFinished)
	}
	archives, err := filepath.Glob(filepath.Join(dice.BackupDir, "*.zip"))
	if err != nil || len(archives) != 2 {
		t.Fatalf("backup archives after optional request = %v, err=%v; want two", archives, err)
	}
	selectedFiles := readBackupZip(t, findArchiveBySelection(t, archives, "_r21_"))
	for _, name := range []string{"data/default/scripts/selected.js", "data/images/selected.png", "data/endpoint/events.db"} {
		if _, ok := selectedFiles[name]; !ok {
			t.Errorf("requested optional backup is missing %q", name)
		}
	}
}

func findArchiveBySelection(t *testing.T, archives []string, token string) string {
	t.Helper()
	for _, archive := range archives {
		if strings.Contains(filepath.Base(archive), token) {
			return archive
		}
	}
	t.Fatalf("no archive name contains selection token %q: %v", token, archives)
	return ""
}

func TestEventStoreBackupSnapshotFailureNeverReportsSuccess(t *testing.T) {
	server, database, _, _ := newEventStoreBackupAPIFixture(t)
	if err := database.Close(); err != nil {
		t.Fatalf("close EventStore before backup: %v", err)
	}

	response := postBackup(t, server, uint64(dice.BackupSelectionBasic))
	if response.Code != http.StatusAccepted {
		t.Fatalf("failed backup acceptance HTTP status = %d, want %d: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	accepted := decodeBackupJobResponse(t, response)
	if !accepted.Success || accepted.Job == nil {
		t.Fatalf("failed backup was not accepted as an asynchronous job: %#v", accepted)
	}
	failed := waitForBackupTerminal(t, server, accepted.Job.ID)
	if failed.Status != dice.BackupJobStatusFailed || failed.Stage != dice.BackupJobStageSnapshot ||
		!strings.Contains(failed.Error, "snapshot authoritative EventStore") || failed.Filename != "" || failed.FinishedAt < failed.StartedAt {
		t.Fatalf("failed backup terminal status = %#v; want detailed snapshot failure", failed)
	}
	archives, err := filepath.Glob(filepath.Join(dice.BackupDir, "*.zip"))
	if err != nil || len(archives) != 0 {
		t.Fatalf("archives after failed snapshot = %v, err=%v; want no partial ZIP", archives, err)
	}
	stages, err := filepath.Glob(filepath.Join(dice.BackupDir, dice.BackupStagingDirPrefix+"*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("staging artifacts after failed snapshot = %v, err=%v; want complete cleanup", stages, err)
	}
}

func TestEventStoreBackupReportsExternalKeySourceBoundary(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, "data", "endpoint"), 0o700); err != nil {
		t.Fatal(err)
	}
	const databaseIdentity = "external-key-backup-test"
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(root, "data", "endpoint", "events.db"),
		KeySource: endpointAPITestKeySource{}, DatabaseIdentity: databaseIdentity,
	})
	if err != nil {
		t.Fatalf("open external-key EventStore: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database)
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: databaseIdentity, IndexRootID: "api-test-index-v1",
		EncryptionRootIDs: []string{"api-test-root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatalf("set external-key readiness: %v", err)
	}
	runtimeDice := &dice.Dice{
		BaseConfig: dice.BaseConfig{Name: "default", DataDir: filepath.Join("data", "default")},
		Logger:     logger.M(), DurableStore: store,
	}
	manager := setUpUIAPIContractDice(t, runtimeDice)
	manager.EventSourcedMode = true
	server := echo.New()
	server.Use(middleware.Recover())
	Bind(server, manager)

	response := postBackup(t, server, uint64(dice.BackupSelectionBasic))
	if response.Code != http.StatusAccepted {
		t.Fatalf("external-key backup HTTP status = %d, want %d: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	accepted := decodeBackupJobResponse(t, response)
	if !accepted.Success || accepted.Job == nil {
		t.Fatalf("external-key backup acceptance = %#v", accepted)
	}
	finished := waitForBackupTerminal(t, server, accepted.Job.ID)
	if finished.Status != dice.BackupJobStatusSucceeded {
		t.Fatalf("external-key backup terminal status = %#v", finished)
	}
	files := readBackupZip(t, findEventStoreBackup(t))
	for _, name := range []string{"data/endpoint/keys/index.key", "data/endpoint/keys/roots/current", "data/endpoint/keys/roots/api-test-root-v1.key"} {
		if _, ok := files[name]; ok {
			t.Errorf("external key source was falsely bundled as %q", name)
		}
	}
	var metadata struct {
		EventStore struct {
			KeyMaterial string `json:"keyMaterial"`
		} `json:"eventStore"`
	}
	if err := json.Unmarshal(files["backup_info.json"].data, &metadata); err != nil ||
		metadata.EventStore.KeyMaterial != "external-configured-key-source" {
		t.Fatalf("external key-source metadata = %+v, err=%v", metadata.EventStore, err)
	}
}

func TestBackupListHidesUnpublishedStagingArtifacts(t *testing.T) {
	server, _, _, _ := newEventStoreBackupAPIFixture(t)
	stageDir := filepath.Join(dice.BackupDir, dice.BackupStagingDirPrefix+"test")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "partial.zip"), []byte("incomplete archive"), 0o600); err != nil {
		t.Fatal(err)
	}

	items := listBackups(t, server)
	if len(items) != 0 {
		t.Fatalf("backup list exposed unpublished staging files: %#v", items)
	}
}
