package dice

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/dice/service"
	"Scardice-core/dice/storylog"
	"Scardice-core/eventstore"
)

func TestEventStoreBackedLogNewThenList(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db"),
		KeySource: groupCardSQLiteKeySource{}, DatabaseIdentity: "log-consumer-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(groupCardSQLiteKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "log-consumer-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	const groupID = "UI-Group:9001"
	groupCtx, _ := newQuitCommandTestContext(t, d, ep, "QQ:9001", groupID, "EventSourceGroup")
	groupCtx.Group.SetLogState(0, "", false)
	d.DBOperator = nil
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)

	d.ImSession.ExecuteNew(ep, newGroupMsg(groupID, "QQ:9001", ".log new eventstore-session"))
	if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for '.log new' reply")
	}
	state := groupCtx.Group.GetLogState()
	if !state.On || state.Name != "eventstore-session" || state.ID == 0 {
		t.Fatalf(".log new did not create and activate its EventStore session: %#v", state)
	}

	d.ImSession.ExecuteNew(ep, newGroupMsg(groupID, "QQ:9001", ".log list"))
	reply, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout waiting for '.log list' reply")
	}
	if !strings.Contains(reply, "eventstore-session") {
		t.Fatalf(".log list reply %q omitted the created session", reply)
	}
}

func TestEventStoreStoryLogStatsRejectsMissingSession(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db"),
		KeySource: groupCardSQLiteKeySource{}, DatabaseIdentity: "log-stats-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(groupCardSQLiteKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "log-stats-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d.DBOperator = nil
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)
	_, err = d.LogRepository.StoryLogStats("UI-Group:missing", "absent")
	if !errors.Is(err, service.ErrLogNotFound) {
		t.Fatalf("StoryLogStats(missing) error=%v, want not found", err)
	}
}

func TestEventStoreLogOnDoesNotCreateMissingSession(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db"),
		KeySource: groupCardSQLiteKeySource{}, DatabaseIdentity: "log-on-missing-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(groupCardSQLiteKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "log-on-missing-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	const groupID = "UI-Group:missing-session"
	groupCtx, _ := newQuitCommandTestContext(t, d, ep, "QQ:9001", groupID, "MissingSession")
	groupCtx.Group.SetLogState(0, "", false)
	d.DBOperator = nil
	d.LogRepository = service.NewEventStoreLogRepository(store, d.BaseConfig.Name)

	d.ImSession.ExecuteNew(ep, newGroupMsg(groupID, "QQ:9001", ".log on absent-session"))
	if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for '.log on' reply")
	}
	sessions, err := store.ListStoryLogs(ctx, d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.GetStoryLogState(ctx, d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 || state.On || state.Name != "" || state.SessionID != 0 {
		t.Fatalf("'.log on' missing session created state: sessions=%#v state=%#v", sessions, state)
	}

	if _, err := store.CreateStoryLog(ctx, d.BaseConfig.Name, groupID, "empty-session"); err != nil {
		t.Fatal(err)
	}
	d.ImSession.ExecuteNew(ep, newGroupMsg(groupID, "QQ:9001", ".log on empty-session"))
	if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for existing empty-session '.log on' reply")
	}
	state, err = store.GetStoryLogState(ctx, d.BaseConfig.Name, groupID)
	if err != nil || !state.On || state.Name != "empty-session" {
		t.Fatalf("'.log on' existing empty session state=%#v err=%v", state, err)
	}
	entries, err := store.GetStoryLogEntries(ctx, d.BaseConfig.Name, groupID, "empty-session")
	if err != nil || len(entries) != 0 {
		t.Fatalf("existing empty session entries=%#v err=%v", entries, err)
	}
}

func newEventStoreLogUploadRepository(t *testing.T) (*Dice, *eventstore.Database, *eventstore.GORMStore, service.LogRepository) {
	t.Helper()
	d, _, _, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "story-upload.db"),
		KeySource: groupCardSQLiteKeySource{}, DatabaseIdentity: "story-upload-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := eventstore.NewStore(db, eventstore.WithKeySource(groupCardSQLiteKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "story-upload-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d.DBOperator = nil
	repository := service.NewEventStoreLogRepository(store, d.BaseConfig.Name)
	d.LogRepository = repository
	return d, db, store, repository
}

func seedEventStoreUploadLog(t *testing.T, store *eventstore.GORMStore, diceID, groupID, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.CreateStoryLog(ctx, diceID, groupID, name); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: diceID, GroupID: groupID, LogName: name, Nickname: "Recorder",
		IMUserID: "user", Time: time.Now().Add(-time.Minute).Unix(), Message: "archived line",
		RawMsgID: "seed-upload-entry",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEventStoreStoryLogUploadPersistsMetadataAndInvalidatesCacheAfterAppend(t *testing.T) {
	for _, test := range []struct {
		name    string
		version storylog.StoryVersion
	}{
		{name: "v1", version: storylog.StoryVersionV1},
		{name: "v105", version: storylog.StoryVersionV105},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, _, store, repository := newEventStoreLogUploadRepository(t)
			const groupID, name = "QQ-Group:upload", "upload-session"
			seedEventStoreUploadLog(t, store, d.BaseConfig.Name, groupID, name)
			_, _, contentUpdatedAtBeforeUpload, err := repository.UploadInfo(groupID, name)
			if err != nil {
				t.Fatalf("read content timestamp before upload: %v", err)
			}
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestNumber := requests.Add(1)
				if r.Method != http.MethodPut {
					t.Errorf("upload method=%s, want PUT", r.Method)
				}
				responseURL := "https://local.example/story/first"
				if requestNumber > 1 {
					responseURL = "https://local.example/story/updated"
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"url":"` + responseURL + `"}`))
			}))
			defer server.Close()
			backupDir := t.TempDir()
			env := storylog.UploadEnv{
				Dir: backupDir, Repo: repository, Log: d.Logger, Backends: []string{server.URL},
				Version: test.version, LogName: name, GroupID: groupID, UniformID: "test-bot",
			}
			url, _, err := storylog.Upload(env)
			if err != nil || url != "https://local.example/story/first" {
				t.Fatalf("first Upload() url=%q err=%v", url, err)
			}
			storedURL, uploadTime, updateTime, err := repository.UploadInfo(groupID, name)
			if err != nil || storedURL != url || uploadTime < updateTime || updateTime != contentUpdatedAtBeforeUpload {
				t.Fatalf("stored upload metadata=%q,%d,%d before-content-time=%d err=%v", storedURL, uploadTime, updateTime, contentUpdatedAtBeforeUpload, err)
			}
			cachedURL, _, err := storylog.Upload(env)
			if err != nil || cachedURL != url || requests.Load() != 1 {
				t.Fatalf("unchanged cached Upload() url=%q err=%v backend requests=%d", cachedURL, err, requests.Load())
			}
			if !storyLogBackupContains(t, backupDir, "archived line") {
				t.Fatal("unchanged cache reuse removed or corrupted the existing ZIP")
			}

			const addedMessage = "new-content-cache-marker"
			if err := store.AppendStoryLogEntry(context.Background(), eventstore.StoryLogEntry{
				DiceID: d.BaseConfig.Name, GroupID: groupID, LogName: name, Nickname: "Recorder",
				IMUserID: "user", RawMsgID: "upload-cache-new-entry", Time: uploadTime, Message: addedMessage,
			}); err != nil {
				t.Fatalf("append changed log entry: %v", err)
			}
			assertStoryLogUploadCacheInvalidated(t, repository, groupID, name)
			updatedURL, _, err := storylog.Upload(env)
			if err != nil || updatedURL != "https://local.example/story/updated" || requests.Load() != 2 {
				t.Fatalf("Upload() after append url=%q err=%v backend requests=%d, want updated URL and a second upload", updatedURL, err, requests.Load())
			}
			storedURLAfterAppend, updatedUploadTime, _, err := repository.UploadInfo(groupID, name)
			if err != nil || storedURLAfterAppend != updatedURL || updatedUploadTime <= 0 {
				t.Fatalf("upload metadata after append url=%q uploadTime=%d err=%v", storedURLAfterAppend, updatedUploadTime, err)
			}
			cachedUpdatedURL, _, err := storylog.Upload(env)
			if err != nil || cachedUpdatedURL != updatedURL || requests.Load() != 2 {
				t.Fatalf("unchanged post-append cache url=%q err=%v backend requests=%d", cachedUpdatedURL, err, requests.Load())
			}
			if !storyLogBackupContains(t, backupDir, addedMessage) {
				t.Fatalf("updated local ZIP payload omitted appended message %q", addedMessage)
			}
		})
	}
}
func TestEventStoreStoryLogUploadInvalidatesCacheAfterRecall(t *testing.T) {
	for _, test := range []struct {
		name    string
		version storylog.StoryVersion
	}{
		{name: "v1", version: storylog.StoryVersionV1},
		{name: "v105", version: storylog.StoryVersionV105},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, _, store, repository := newEventStoreLogUploadRepository(t)
			const groupID, name = "QQ-Group:upload-recall", "upload-recall-session"
			seedEventStoreUploadLog(t, store, d.BaseConfig.Name, groupID, name)
			if err := store.AppendStoryLogEntry(context.Background(), eventstore.StoryLogEntry{
				DiceID: d.BaseConfig.Name, GroupID: groupID, LogName: name, Nickname: "Recorder",
				IMUserID: "user", Time: time.Now().Add(-30 * time.Second).Unix(), Message: "retained marker",
				RawMsgID: "retained-upload-entry",
			}); err != nil {
				t.Fatalf("append retained entry: %v", err)
			}
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestNumber := requests.Add(1)
				if r.Method != http.MethodPut {
					t.Errorf("upload method=%s, want PUT", r.Method)
				}
				responseURL := "https://local.example/story/first"
				if requestNumber > 1 {
					responseURL = "https://local.example/story/updated"
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"url":"` + responseURL + `"}`))
			}))
			defer server.Close()
			backupDir := t.TempDir()
			env := storylog.UploadEnv{
				Dir: backupDir, Repo: repository, Log: d.Logger, Backends: []string{server.URL},
				Version: test.version, LogName: name, GroupID: groupID, UniformID: "test-bot",
			}
			url, _, err := storylog.Upload(env)
			if err != nil || url != "https://local.example/story/first" {
				t.Fatalf("first Upload() url=%q err=%v", url, err)
			}
			if err := store.DeleteStoryLogEntryByRawID(context.Background(), d.BaseConfig.Name, groupID, "seed-upload-entry"); err != nil {
				t.Fatalf("recall archived entry: %v", err)
			}
			assertStoryLogUploadCacheInvalidated(t, repository, groupID, name)
			if err := os.RemoveAll(backupDir); err != nil {
				t.Fatalf("clear first local backup: %v", err)
			}
			updatedURL, _, err := storylog.Upload(env)
			if err != nil || updatedURL != "https://local.example/story/updated" || requests.Load() != 2 {
				t.Fatalf("Upload() after recall url=%q err=%v backend requests=%d, want updated URL and a second upload", updatedURL, err, requests.Load())
			}
			if storyLogBackupContains(t, backupDir, "archived line") {
				t.Fatal("updated local ZIP payload retained recalled message")
			}
			if !storyLogBackupContains(t, backupDir, "retained marker") {
				t.Fatal("updated local ZIP payload omitted retained message")
			}
		})
	}
}
func TestEventStoreStoryLogUploadInvalidatesCacheAfterEdit(t *testing.T) {
	for _, test := range []struct {
		name    string
		version storylog.StoryVersion
	}{
		{name: "v1", version: storylog.StoryVersionV1},
		{name: "v105", version: storylog.StoryVersionV105},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, _, store, repository := newEventStoreLogUploadRepository(t)
			const groupID, name = "QQ-Group:upload-edit", "upload-edit-session"
			seedEventStoreUploadLog(t, store, d.BaseConfig.Name, groupID, name)
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestNumber := requests.Add(1)
				if r.Method != http.MethodPut {
					t.Errorf("upload method=%s, want PUT", r.Method)
				}
				responseURL := "https://local.example/story/first"
				if requestNumber > 1 {
					responseURL = "https://local.example/story/updated"
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"url":"` + responseURL + `"}`))
			}))
			defer server.Close()
			backupDir := t.TempDir()
			env := storylog.UploadEnv{
				Dir: backupDir, Repo: repository, Log: d.Logger, Backends: []string{server.URL},
				Version: test.version, LogName: name, GroupID: groupID, UniformID: "test-bot",
			}
			url, _, err := storylog.Upload(env)
			if err != nil || url != "https://local.example/story/first" {
				t.Fatalf("first Upload() url=%q err=%v", url, err)
			}
			if err := store.EditStoryLogEntryByRawID(context.Background(), d.BaseConfig.Name, groupID, "seed-upload-entry", "edited content marker"); err != nil {
				t.Fatalf("edit archived entry: %v", err)
			}
			assertStoryLogUploadCacheInvalidated(t, repository, groupID, name)
			if err := os.RemoveAll(backupDir); err != nil {
				t.Fatalf("clear first local backup: %v", err)
			}
			updatedURL, _, err := storylog.Upload(env)
			if err != nil || updatedURL != "https://local.example/story/updated" || requests.Load() != 2 {
				t.Fatalf("Upload() after edit url=%q err=%v backend requests=%d, want updated URL and a second upload", updatedURL, err, requests.Load())
			}
			if storyLogBackupContains(t, backupDir, "archived line") {
				t.Fatal("updated local ZIP payload retained edited message")
			}
			if !storyLogBackupContains(t, backupDir, "edited content marker") {
				t.Fatal("updated local ZIP payload omitted edited message")
			}
		})
	}
}

func assertStoryLogUploadCacheInvalidated(t *testing.T, repository service.LogRepository, groupID, name string) {
	t.Helper()
	url, uploadTime, _, err := repository.UploadInfo(groupID, name)
	if err != nil || url != "" || uploadTime != 0 {
		t.Fatalf("archive upload cache after content mutation = %q,%d err=%v, want empty metadata", url, uploadTime, err)
	}
}

func storyLogBackupContains(t *testing.T, dir, message string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read backup directory: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".zip" {
			continue
		}
		archive, err := zip.OpenReader(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("open backup %q: %v", entry.Name(), err)
		}
		found := false
		for _, file := range archive.File {
			reader, err := file.Open()
			if err != nil {
				_ = archive.Close()
				t.Fatalf("open backup payload %q: %v", file.Name, err)
			}
			payload, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil {
				_ = archive.Close()
				t.Fatalf("read backup payload %q: read=%v close=%v", file.Name, readErr, closeErr)
			}
			if strings.Contains(string(payload), message) {
				found = true
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatalf("close backup %q: %v", entry.Name(), err)
		}
		if found {
			return true
		}
	}
	return false
}

func TestEventStoreStoryLogUploadReportsMetadataCommitFailure(t *testing.T) {
	d, db, store, repository := newEventStoreLogUploadRepository(t)
	const groupID, name = "QQ-Group:upload-failure", "upload-failure-session"
	seedEventStoreUploadLog(t, store, d.BaseConfig.Name, groupID, name)
	if err := db.GORM().Exec(`CREATE TRIGGER block_story_log_upload BEFORE UPDATE OF payload ON story_log_sessions BEGIN SELECT RAISE(ABORT, 'test upload metadata failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"url":"https://local.example/story"}`))
	}))
	defer server.Close()
	url, _, err := storylog.Upload(storylog.UploadEnv{
		Dir: t.TempDir(), Repo: repository, Log: d.Logger, Backends: []string{server.URL},
		Version: storylog.StoryVersionV1, LogName: name, GroupID: groupID, UniformID: "test-bot",
	})
	if err == nil || url != "" || requests.Load() != 1 {
		t.Fatalf("Upload() after remote success returned url=%q err=%v requests=%d, want local metadata error", url, err, requests.Load())
	}
	storedURL, _, _, readErr := repository.UploadInfo(groupID, name)
	if readErr != nil || storedURL != "" {
		t.Fatalf("metadata after failed local commit=%q err=%v", storedURL, readErr)
	}
}
