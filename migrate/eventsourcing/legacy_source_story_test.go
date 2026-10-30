package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"Scardice-core/eventstore"
)

func TestLegacySourceStreamsStoryLogRecordsFromSnapshot(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "legacy")
	dataDir := filepath.Join(root, "default")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte("{}\n"))
	createLegacySQLiteFixture(t, filepath.Join(dataDir, "data.db"))

	dataDB, err := sql.Open("sqlite", filepath.Join(dataDir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []struct {
		id, name string
		on       bool
	}{
		{id: "QQ-Group:active", name: "active-session", on: true},
		{id: "QQ-Group:paused", name: "paused-session", on: false},
	} {
		payload, marshalErr := json.Marshal(map[string]any{
			"groupId": group.id, "groupName": group.id, "logCurName": group.name, "logOn": group.on,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err = dataDB.Exec(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`, group.id, 100, payload); err != nil {
			t.Fatal(err)
		}
	}
	if err = dataDB.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dataDir, "data-logs.db")
	logDB, err := sql.Open("sqlite", logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE logs (id INTEGER PRIMARY KEY, name TEXT, group_id TEXT, extra TEXT, created_at INTEGER, updated_at INTEGER, upload_url TEXT, upload_time INTEGER)`,
		`CREATE TABLE log_items (id INTEGER PRIMARY KEY, log_id INTEGER, group_id TEXT, nickname TEXT, im_userid TEXT, time INTEGER, message TEXT, is_dice INTEGER, command_id INTEGER, command_info TEXT, raw_msg_id TEXT, user_uniform_id TEXT, removed INTEGER, parent_id INTEGER, seq INTEGER)`,
		`INSERT INTO logs (id, name, group_id, extra, created_at, updated_at, upload_url, upload_time) VALUES
			(17, 'active-session', 'QQ-Group:active', 'session-extra', 1001, 1003, 'https://uploads.invalid/active', 1004),
			(29, 'paused-session', 'QQ-Group:paused', NULL, NULL, NULL, '', 0)`,
		`INSERT INTO log_items (id, log_id, group_id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id, removed, parent_id, seq) VALUES
			(301, 17, 'QQ-Group:active', 'Alice', 'QQ:123', 1002, 'rich message', 1, 42, '{"args":[".r","1d20"],"success":true}', 'raw-msg-301', 'uniform-123', NULL, 12, 77),
			(402, 29, 'QQ-Group:paused', NULL, NULL, NULL, NULL, NULL, NULL, '', 'raw-msg-402', 'uniform-456', 1, NULL, NULL)`,
	} {
		if _, err = logDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = logDB.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeDigest := sha256.Sum256(before)

	source := NewLegacySourceWithKeySource(root, sqliteTargetKeySource{})
	inventory, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundLogDB := false
	for _, file := range inventory.Metadata.Files {
		if file.Name == "default/data-logs.db" {
			foundLogDB = true
		}
	}
	if !foundLogDB {
		t.Fatal("legacy source inventory omitted data-logs.db")
	}
	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	streamer, ok := snapshot.Source.(RecordStreamer)
	if !ok {
		t.Fatalf("snapshot source %T is not streaming", snapshot.Source)
	}
	var records []SourceRecord
	if err = streamer.StreamRecords(ctx, func(batch []SourceRecord) error {
		records = append(records, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var sessions, states, entries int
	for _, record := range records {
		if record.RecordType == RecordTypeEvent {
			payload := string(record.Payload)
			for _, privateLogField := range []string{"active-session", "paused-session", `"logCurName"`, `"logCurFile"`, `"logOn"`} {
				if strings.Contains(payload, privateLogField) {
					t.Fatalf("group domain event duplicated archive-owned log field %q: %s", privateLogField, payload)
				}
			}
		}
		if record.RecordType != RecordTypeLogArchive {
			continue
		}
		var payload legacyStoryLogImportPayload
		if err = json.Unmarshal(record.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if record.Identity != payload.SourceID || record.Kind != payload.Kind || !record.Sensitive ||
			len(record.ContentDigest) != 0 || record.Size != uint64(len(record.Payload)) {
			t.Fatalf("story-log source record metadata/payload mismatch: %#v / %#v", record, payload)
		}
		switch payload.Kind {
		case legacyLogImportSession:
			if payload.Session != nil && strings.HasSuffix(payload.SourceID, "/session/17") &&
				payload.Session.GroupID == "QQ-Group:active" && payload.Session.Name == "active-session" &&
				payload.Session.CreatedAt == 1001 && payload.Session.UpdatedAt == 1003 &&
				payload.Session.Extra != nil && *payload.Session.Extra == "session-extra" &&
				payload.Session.UploadURL == "https://uploads.invalid/active" && payload.Session.UploadTime == 1004 {
				sessions++
			}
			if payload.Session != nil && strings.HasSuffix(payload.SourceID, "/session/29") &&
				payload.Session.GroupID == "QQ-Group:paused" && payload.Session.Name == "paused-session" &&
				payload.Session.CreatedAt == 0 && payload.Session.UpdatedAt == 0 && payload.Session.Extra == nil {
				sessions++
			}
		case legacyLogImportState:
			if payload.State != nil && strings.HasSuffix(payload.SessionSourceID, "/session/17") &&
				payload.State.GroupID == "QQ-Group:active" && payload.State.Name == "active-session" && payload.State.On {
				states++
			}
			if payload.State != nil && strings.HasSuffix(payload.SessionSourceID, "/session/29") &&
				payload.State.GroupID == "QQ-Group:paused" && payload.State.Name == "paused-session" && !payload.State.On {
				states++
			}
		case legacyLogImportEntry:
			if payload.Entry != nil && strings.HasSuffix(payload.SourceID, "/entry/301") &&
				strings.HasSuffix(payload.SessionSourceID, "/session/17") &&
				payload.Entry.GroupID == "QQ-Group:active" && payload.Entry.LogName == "active-session" &&
				payload.Entry.Nickname == "Alice" && payload.Entry.IMUserID == "QQ:123" &&
				payload.Entry.Time == 1002 && payload.Entry.Message == "rich message" &&
				payload.Entry.IsDice && payload.Entry.CommandID == 42 &&
				string(payload.Entry.CommandInfo) == `{"args":[".r","1d20"],"success":true}` &&
				payload.Entry.RawMsgID == "raw-msg-301" && payload.Entry.UniformID == "uniform-123" &&
				payload.Entry.ParentID != nil && *payload.Entry.ParentID == 12 &&
				payload.Entry.Seq != nil && *payload.Entry.Seq == 77 {
				entries++
			}
			if payload.Entry != nil && strings.HasSuffix(payload.SourceID, "/entry/402") &&
				strings.HasSuffix(payload.SessionSourceID, "/session/29") &&
				payload.Entry.GroupID == "QQ-Group:paused" && payload.Entry.Nickname == "" &&
				payload.Entry.IMUserID == "" && payload.Entry.Time == 0 && payload.Entry.Message == "" &&
				!payload.Entry.IsDice && payload.Entry.CommandID == 0 &&
				payload.Entry.Removed != nil && *payload.Entry.Removed == 1 {
				entries++
			}
		}
	}
	if sessions != 2 || states != 2 || entries != 2 {
		t.Fatalf("legacy story-log semantic records = sessions:%d states:%d entries:%d; want 2 each", sessions, states, entries)
	}
	if err = source.Recheck(ctx, inventory.Metadata); err != nil {
		t.Fatalf("legacy source changed while snapshotting/importing: %v", err)
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	afterDigest := sha256.Sum256(after)
	if beforeDigest != afterDigest {
		t.Fatal("legacy data-logs.db changed during read-only import")
	}
}

func TestLegacySourceImportsStoryLogsAcrossBatchBoundaryAndReopens(t *testing.T) {
	ctx := context.Background()
	const sessionCount = 251
	root := filepath.Join(t.TempDir(), "legacy")
	dataDir := filepath.Join(root, "default")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte("{}\n"))
	dataPath := filepath.Join(dataDir, "data.db")
	createLegacySQLiteFixture(t, dataPath)
	logPath := filepath.Join(dataDir, "data-logs.db")
	dataDB, err := sql.Open("sqlite", dataPath)
	if err != nil {
		t.Fatal(err)
	}
	logDB, err := sql.Open("sqlite", logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE logs (id INTEGER PRIMARY KEY, name TEXT, group_id TEXT, extra TEXT, created_at INTEGER, updated_at INTEGER, upload_url TEXT, upload_time INTEGER)`,
		`CREATE TABLE log_items (id INTEGER PRIMARY KEY, log_id INTEGER, group_id TEXT, nickname TEXT, im_userid TEXT, time INTEGER, message TEXT, is_dice INTEGER, command_id INTEGER, command_info TEXT, raw_msg_id TEXT, user_uniform_id TEXT, removed INTEGER, parent_id INTEGER, seq INTEGER)`,
	} {
		if _, err = logDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for index := range sessionCount {
		groupID := fmt.Sprintf("QQ-Group:story-boundary-%03d", index)
		logName := fmt.Sprintf("session-%03d", index)
		on := index%2 == 0
		groupPayload, marshalErr := json.Marshal(map[string]any{
			"groupId": groupID, "groupName": groupID, "logCurName": logName, "logOn": on,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err = dataDB.Exec(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`, groupID, index+1, groupPayload); err != nil {
			t.Fatal(err)
		}
		sessionID := 1000 + index
		entryID := 10000 + index
		var extra any = fmt.Sprintf("legacy extra %03d", index)
		switch index {
		case 0:
			extra = ""
		case 1:
			extra = nil
		}
		uploadURL := ""
		if index == sessionCount-1 {
			uploadURL = "https://uploads.invalid/private-story-log"
			extra = "private-story-log-extra-250"
		}
		if _, err = logDB.Exec(
			`INSERT INTO logs (id, name, group_id, extra, created_at, updated_at, upload_url, upload_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sessionID, logName, groupID, extra, 100000+index, 200000+index, uploadURL, 300000+index,
		); err != nil {
			t.Fatal(err)
		}
		commandInfo := fmt.Sprintf(`{"command":"roll-%03d","success":true}`, index)
		message := fmt.Sprintf("private-story-log-message-%03d", index)
		rawMessageID := fmt.Sprintf("private-story-log-raw-%03d", index)
		if index == sessionCount-1 {
			message = "private-story-log-message-250"
			rawMessageID = "private-story-log-raw-250"
		}
		if _, err = logDB.Exec(
			`INSERT INTO log_items (id, log_id, group_id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id, removed, parent_id, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entryID, sessionID, groupID, fmt.Sprintf("Player-%03d", index), fmt.Sprintf("QQ:%03d", index),
			400000+index, message, index%2, 500+index, commandInfo, rawMessageID,
			fmt.Sprintf("uniform-%03d", index), index%2, 90000+index, 70000+index,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err = dataDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err = logDB.Close(); err != nil {
		t.Fatal(err)
	}
	logSourceBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	dataSourceBytes, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	logSourceDigest := sha256.Sum256(logSourceBytes)
	dataSourceDigest := sha256.Sum256(dataSourceBytes)

	source := NewLegacySourceWithKeySource(root, sqliteTargetKeySource{})
	inventory, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "target.db")
	target := NewSQLiteTarget(targetPath, sqliteTargetKeySource{})
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "old-index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "story-log-boundary",
	}).Run(ctx, Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Batches < 2 {
		t.Fatalf("import used %d batches for %d story-log records", result.Batches, sessionCount*3)
	}
	if err = source.Recheck(ctx, inventory.Metadata); err != nil {
		t.Fatalf("legacy source changed during import: %v", err)
	}
	logSourceBytes, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	dataSourceBytes, err = os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(logSourceBytes) != logSourceDigest || sha256.Sum256(dataSourceBytes) != dataSourceDigest {
		t.Fatal("legacy source database bytes changed during import")
	}

	reopened := NewSQLiteTarget(targetPath, sqliteTargetKeySource{})
	reopened.identity = result.TargetIdentity
	if err = reopened.openLocked(ctx); err != nil {
		t.Fatal(err)
	}
	prefix, ok := legacyStoryLogSourcePrefix(legacyStoryLogSourceID(inventory.Identity, "default", "QQ-Group:000", legacyLogImportSession, 1000))
	if !ok {
		t.Fatal("invalid source-scoped log identity")
	}
	receipts, err := reopened.store.ListStoryLogImports(ctx, prefix, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != sessionCount*3 {
		t.Fatalf("reopened import receipts = %d, want %d", len(receipts), sessionCount*3)
	}
	counts := make(map[eventstore.StoryLogImportKind]int)
	for index := range receipts {
		counts[receipts[index].Kind]++
		clear(receipts[index].SemanticDigest)
	}
	if counts[eventstore.StoryLogImportSession] != sessionCount ||
		counts[eventstore.StoryLogImportEntry] != sessionCount ||
		counts[eventstore.StoryLogImportState] != sessionCount {
		t.Fatalf("reopened record kinds = %#v", counts)
	}
	for _, index := range []int{0, 1, 249, 250} {
		groupID := fmt.Sprintf("QQ-Group:story-boundary-%03d", index)
		logName := fmt.Sprintf("session-%03d", index)
		sessions, listErr := reopened.store.ListStoryLogs(ctx, "default", groupID)
		if listErr != nil || len(sessions) != 1 || sessions[0].Name != logName {
			t.Fatalf("reopened sessions for %s = %#v, err=%v", groupID, sessions, listErr)
		}
		switch index {
		case 0:
			if sessions[0].Extra == nil || *sessions[0].Extra != "" {
				t.Fatalf("empty legacy extra lost for %s: %#v", groupID, sessions[0].Extra)
			}
		case 1:
			if sessions[0].Extra != nil {
				t.Fatalf("NULL legacy extra changed for %s: %#v", groupID, sessions[0].Extra)
			}
		case 250:
			if sessions[0].Extra == nil || *sessions[0].Extra != "private-story-log-extra-250" ||
				sessions[0].UploadURL != "https://uploads.invalid/private-story-log" {
				t.Fatalf("reopened session metadata = %#v", sessions[0])
			}
		}
		entries, entriesErr := reopened.store.GetStoryLogEntries(ctx, "default", groupID, logName)
		if entriesErr != nil || len(entries) != 1 {
			t.Fatalf("reopened entries for %s = %#v, err=%v", groupID, entries, entriesErr)
		}
		entry := entries[0]
		if entry.Message != fmt.Sprintf("private-story-log-message-%03d", index) ||
			entry.Nickname != fmt.Sprintf("Player-%03d", index) || entry.IMUserID != fmt.Sprintf("QQ:%03d", index) ||
			entry.Time != int64(400000+index) || entry.CommandID != int64(500+index) ||
			string(entry.CommandInfo) != fmt.Sprintf(`{"command":"roll-%03d","success":true}`, index) ||
			entry.RawMsgID != fmt.Sprintf("private-story-log-raw-%03d", index) ||
			entry.UniformID != fmt.Sprintf("uniform-%03d", index) ||
			entry.Removed == nil || *entry.Removed != index%2 ||
			entry.ParentID == nil || *entry.ParentID != 90000+index ||
			entry.Seq == nil || *entry.Seq != int64(70000+index) {
			t.Fatalf("reopened rich entry for %s = %#v", groupID, entry)
		}
		state, stateErr := reopened.store.GetStoryLogState(ctx, "default", groupID)
		if stateErr != nil || state.SessionID != sessions[0].ID || state.Name != logName || state.On != (index%2 == 0) {
			t.Fatalf("reopened state for %s = %#v, err=%v", groupID, state, stateErr)
		}
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{targetPath, targetPath + "-wal", targetPath + "-shm"} {
		contents, readErr := os.ReadFile(path)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, private := range []string{"private-story-log-message-250", "private-story-log-extra-250", "private-story-log-raw-250"} {
			if strings.Contains(string(contents), private) {
				t.Fatalf("%s contains decrypted story-log value %q", path, private)
			}
		}
	}
	t.Logf("manifest SHA-256=%x; unchanged data-logs.db SHA-256=%x", result.ManifestDigest, logSourceDigest)
}

func TestLegacyStoryLogSourceRejectsOrphansAndInvalidFilesFromSnapshot(t *testing.T) {
	for _, scenario := range []struct {
		name                    string
		unreadable              bool
		danglingState           bool
		orphanEntry             bool
		duplicateName           bool
		mismatchedGroupIdentity bool
		incompleteSchema        bool
		duplicateID             bool
	}{
		{name: "unreadable database", unreadable: true},
		{name: "orphan entry", orphanEntry: true},
		{name: "dangling current group state", danglingState: true},
		{name: "duplicate session identity", duplicateName: true},
		{name: "mismatched group identity", mismatchedGroupIdentity: true},
		{name: "incomplete schema", incompleteSchema: true},
		{name: "duplicate legacy id", duplicateID: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			root := filepath.Join(t.TempDir(), "legacy")
			dataDir := filepath.Join(root, "default")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"))
			writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte("{}\n"))
			dataPath := filepath.Join(dataDir, "data.db")
			createLegacySQLiteFixture(t, dataPath)
			if scenario.danglingState || scenario.mismatchedGroupIdentity {
				dataDB, err := sql.Open("sqlite", dataPath)
				if err != nil {
					t.Fatal(err)
				}
				rowID, groupID := "QQ-Group:dangling", "QQ-Group:dangling"
				name := "missing"
				if scenario.mismatchedGroupIdentity {
					rowID, groupID, name = "QQ-Group:row", "QQ-Group:payload", ""
				}
				groupPayload, marshalErr := json.Marshal(map[string]any{
					"groupId": groupID, "groupName": groupID, "logCurName": name, "logOn": scenario.danglingState,
				})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if _, err = dataDB.Exec(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`, rowID, 1, groupPayload); err != nil {
					t.Fatal(err)
				}
				if err = dataDB.Close(); err != nil {
					t.Fatal(err)
				}
			}
			logPath := filepath.Join(dataDir, "data-logs.db")
			if scenario.unreadable {
				writeLegacyFixtureFile(t, logPath, []byte("not a SQLite database"))
			} else {
				logDB, err := sql.Open("sqlite", logPath)
				if err != nil {
					t.Fatal(err)
				}
				statements := []string{
					`CREATE TABLE logs (id INTEGER, name TEXT, group_id TEXT, extra TEXT, created_at INTEGER, updated_at INTEGER, upload_url TEXT, upload_time INTEGER)`,
				}
				if !scenario.incompleteSchema {
					statements = append(statements, `CREATE TABLE log_items (id INTEGER, log_id INTEGER, group_id TEXT, nickname TEXT, im_userid TEXT, time INTEGER, message TEXT, is_dice INTEGER, command_id INTEGER, command_info TEXT, raw_msg_id TEXT, user_uniform_id TEXT, removed INTEGER, parent_id INTEGER, seq INTEGER)`)
				}
				for _, statement := range statements {
					if _, err = logDB.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
				if scenario.orphanEntry {
					if _, err = logDB.Exec(`INSERT INTO logs (id, name, group_id, created_at, updated_at) VALUES (1, 'session', 'QQ-Group:orphan', 1, 1)`); err != nil {
						t.Fatal(err)
					}
					if _, err = logDB.Exec(`INSERT INTO log_items (id, log_id, group_id, nickname, im_userid, time, message, is_dice, command_id) VALUES (2, 999, 'QQ-Group:orphan', 'player', 'QQ:1', 1, 'orphan', 0, 0)`); err != nil {
						t.Fatal(err)
					}
				}
				if scenario.duplicateName {
					for _, id := range []int{1, 2} {
						if _, err = logDB.Exec(`INSERT INTO logs (id, name, group_id, created_at, updated_at) VALUES (?, 'duplicate', 'QQ-Group:duplicate', 1, 1)`, id); err != nil {
							t.Fatal(err)
						}
					}
				}
				if scenario.duplicateID {
					for _, row := range []struct {
						name, groupID string
					}{{name: "one", groupID: "QQ-Group:one"}, {name: "two", groupID: "QQ-Group:two"}} {
						if _, err = logDB.Exec(`INSERT INTO logs (id, name, group_id, created_at, updated_at) VALUES (5, ?, ?, 1, 1)`, row.name, row.groupID); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err = logDB.Close(); err != nil {
					t.Fatal(err)
				}
			}
			source := NewLegacySourceWithKeySource(root, sqliteTargetKeySource{})
			snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
			if err != nil {
				t.Fatal(err)
			}
			streamer := snapshot.Source.(RecordStreamer)
			err = streamer.StreamRecords(ctx, func([]SourceRecord) error { return nil })
			if err == nil {
				t.Fatal("invalid legacy story-log source streamed as success")
			}
			if scenario.incompleteSchema {
				var unsupported *UnsupportedPreflightError
				if !errors.As(err, &unsupported) {
					t.Fatalf("incomplete legacy schema error = %v, want unsupported preflight", err)
				}
			} else if !scenario.unreadable && !errors.Is(err, ErrValidation) {
				t.Fatalf("invalid legacy story-log error = %v, want validation failure", err)
			}
			if scenario.orphanEntry {
				targetPath := filepath.Join(t.TempDir(), "target.db")
				targetIdentity := "orphan-log-import"
				_, importErr := NewImporter(ImporterOptions{
					Readiness: &readinessFake{value: eventstore.Readiness{
						Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "current", IndexRootID: "current-index",
					}},
					Source: source, Target: NewSQLiteTarget(targetPath, sqliteTargetKeySource{}),
					SnapshotRoot: filepath.Join(t.TempDir(), "import-snapshot"), TargetIdentity: targetIdentity,
				}).Run(ctx, Request{Mode: ModeImport})
				if !errors.Is(importErr, ErrValidation) || !errors.Is(importErr, ErrQuarantined) {
					t.Fatalf("orphan log import error = %v, want validation and quarantine", importErr)
				}
				reopened := NewSQLiteTarget(targetPath, sqliteTargetKeySource{})
				reopened.identity = targetIdentity
				if err = reopened.openLocked(ctx); err != nil {
					t.Fatal(err)
				}
				readiness, readinessErr := reopened.store.GetReadiness(ctx)
				if readinessErr != nil || readiness.Mode != "fresh" {
					_ = reopened.Close()
					t.Fatalf("target readiness after orphan import = %#v, err=%v", readiness, readinessErr)
				}
				imports, listErr := reopened.store.ListStoryLogImports(ctx, "", "")
				if listErr != nil || len(imports) != 0 {
					_ = reopened.Close()
					t.Fatalf("published log imports after orphan import = %d, err=%v", len(imports), listErr)
				}
				if err = reopened.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestLegacySourceImportsCrashStoppedStoryLogWALReadOnlyAndReopens(t *testing.T) {
	if fixturePath := os.Getenv("LEGACY_STORY_LOG_WAL_FIXTURE_PATH"); fixturePath != "" {
		database, err := sql.Open("sqlite", fixturePath)
		if err != nil {
			t.Fatal(err)
		}
		database.SetMaxOpenConns(1)
		for _, statement := range []string{
			"PRAGMA journal_mode=WAL",
			"PRAGMA wal_autocheckpoint=0",
			`CREATE TABLE logs (id INTEGER PRIMARY KEY, name TEXT, group_id TEXT, extra TEXT, created_at INTEGER, updated_at INTEGER, upload_url TEXT, upload_time INTEGER)`,
			`CREATE TABLE log_items (id INTEGER PRIMARY KEY, log_id INTEGER, group_id TEXT, nickname TEXT, im_userid TEXT, time INTEGER, message TEXT, is_dice INTEGER, command_id INTEGER, command_info TEXT, raw_msg_id TEXT, user_uniform_id TEXT, removed INTEGER, parent_id INTEGER, seq INTEGER)`,
			`INSERT INTO logs VALUES (17, 'wal-session', 'QQ-Group:100', NULL, 100, 101, '', NULL)`,
			`INSERT INTO log_items VALUES (31, 17, 'QQ-Group:100', 'WalUser', 'QQ:31', 102, 'committed-only-in-wal', 0, 0, NULL, 'raw-wal', 'uniform-wal', NULL, NULL, NULL)`,
		} {
			if _, err = database.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
		os.Exit(0)
	}

	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "legacy")
	dataDir := filepath.Join(root, "nested", "instance")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: nested/instance\n"))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte("{}\n"))
	dataPath := filepath.Join(dataDir, "data.db")
	createLegacySQLiteFixture(t, dataPath)
	groupPayload, err := json.Marshal(map[string]any{
		"groupId": "QQ-Group:100", "groupName": "WAL group", "logCurName": "wal-session", "logOn": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	dataDB, err := sql.Open("sqlite", dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dataDB.Exec(`UPDATE group_info SET data = ? WHERE id = ?`, groupPayload, "QQ-Group:100"); err != nil {
		t.Fatal(err)
	}
	if err = dataDB.Close(); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dataDir, "data-logs.db")
	child := exec.Command(os.Args[0], "-test.run=^TestLegacySourceImportsCrashStoppedStoryLogWALReadOnlyAndReopens$")
	child.Env = append(os.Environ(), "LEGACY_STORY_LOG_WAL_FIXTURE_PATH="+logPath)
	if output, childErr := child.CombinedOutput(); childErr != nil {
		t.Fatalf("create crash-stopped WAL fixture: %v: %s", childErr, output)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, statErr := os.Stat(logPath + suffix)
		if statErr != nil {
			t.Fatalf("missing WAL fixture component %q: %v", suffix, statErr)
		}
		if suffix == "-wal" && info.Size() == 0 {
			t.Fatal("crash-stopped WAL fixture has no committed WAL frames")
		}
	}

	source := NewLegacySourceWithKeySource(root, sqliteTargetKeySource{})
	inventory, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readLogComponents := func(dir string, metadata SourceMetadata) map[string][]byte {
		t.Helper()
		contents := make(map[string][]byte)
		for _, file := range metadata.Files {
			name := filepath.Base(file.Name)
			if name != "data-logs.db" && name != "data-logs.db-wal" && name != "data-logs.db-shm" {
				continue
			}
			path := filepath.Join(dir, filepath.FromSlash(file.Name))
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			contents[file.Name] = data
		}
		return contents
	}
	sourceBefore := readLogComponents(root, inventory.Metadata)
	for _, suffix := range []string{"data-logs.db", "data-logs.db-wal", "data-logs.db-shm"} {
		found := false
		for name := range sourceBefore {
			found = found || strings.HasSuffix(name, suffix)
		}
		if !found {
			t.Fatalf("inventory omitted nested %s", suffix)
		}
	}
	mainOnlyPath := filepath.Join(t.TempDir(), "main-only.db")
	mainBytes, ok := sourceBefore["nested/instance/data-logs.db"]
	if !ok {
		t.Fatal("inventory omitted nested/instance/data-logs.db")
	}
	if err = os.WriteFile(mainOnlyPath, mainBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mainOnly, err := sql.Open("sqlite", "file:"+filepath.ToSlash(mainOnlyPath)+"?mode=rw&_pragma=query_only(1)")
	if err != nil {
		t.Fatal(err)
	}
	var mainOnlyLogs int
	err = mainOnly.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'logs'`).Scan(&mainOnlyLogs)
	closeErr := mainOnly.Close()
	if err != nil || closeErr != nil || mainOnlyLogs != 0 {
		t.Fatalf("main-only database contains logs table=%d, query err=%v, close err=%v; fixture must depend on WAL", mainOnlyLogs, err, closeErr)
	}

	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	snapshotInventory, err := snapshot.Source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBefore := readLogComponents(snapshot.Root, snapshot.Metadata)
	streamer, ok := snapshot.Source.(RecordStreamer)
	if !ok {
		t.Fatalf("snapshot source %T does not stream", snapshot.Source)
	}
	found := make(map[string]bool)
	collect := func(batch []SourceRecord) error {
		for _, record := range batch {
			if record.RecordType != RecordTypeLogArchive {
				continue
			}
			var payload legacyStoryLogImportPayload
			if err := json.Unmarshal(record.Payload, &payload); err != nil {
				return err
			}
			switch payload.Kind {
			case legacyLogImportSession:
				found[legacyLogImportSession] = payload.Session != nil && payload.Session.Name == "wal-session"
			case legacyLogImportEntry:
				found[legacyLogImportEntry] = payload.Entry != nil && payload.Entry.Message == "committed-only-in-wal"
			case legacyLogImportState:
				found[legacyLogImportState] = payload.State != nil && payload.State.Name == "wal-session" && payload.State.On
			}
		}
		return nil
	}
	if err = streamer.StreamRecords(ctx, collect); err != nil {
		t.Fatalf("stream snapshot WAL records: %v", err)
	}
	if !found[legacyLogImportSession] || !found[legacyLogImportEntry] || !found[legacyLogImportState] {
		t.Fatalf("snapshot WAL archive records = %#v; committed session, entry, and active state required", found)
	}
	for name, expected := range snapshotBefore {
		actual, readErr := os.ReadFile(filepath.Join(snapshot.Root, filepath.FromSlash(name)))
		if readErr != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("snapshot file %s changed during SQL reading: read err=%v", name, readErr)
		}
	}
	if err = snapshot.Source.Recheck(ctx, snapshotInventory.Metadata); err != nil {
		t.Fatalf("snapshot metadata changed during SQL reading: %v", err)
	}

	clear(found)
	if err = source.StreamRecords(ctx, collect); err != nil {
		t.Fatalf("direct source WAL stream: %v", err)
	}
	if !found[legacyLogImportSession] || !found[legacyLogImportEntry] || !found[legacyLogImportState] {
		t.Fatalf("direct source WAL archive records = %#v", found)
	}
	for name, expected := range sourceBefore {
		actual, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if readErr != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("original source file %s changed during SQL reading: read err=%v", name, readErr)
		}
	}
	if err = source.Recheck(ctx, inventory.Metadata); err != nil {
		t.Fatalf("original source metadata changed during SQL reading: %v", err)
	}

	targetPath := filepath.Join(t.TempDir(), "target.db")
	target := NewSQLiteTarget(targetPath, sqliteTargetKeySource{})
	defer target.Close()
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "old-index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "import-snapshot"), TargetIdentity: "crash-stopped-log-wal",
	}).Run(ctx, Request{Mode: ModeImport})
	if err != nil {
		t.Fatalf("public importer WAL workflow: %v", err)
	}
	if len(result.ManifestDigest) != sha256.Size {
		t.Fatalf("public importer returned manifest digest size %d", len(result.ManifestDigest))
	}
	if err = source.Recheck(ctx, inventory.Metadata); err != nil {
		t.Fatalf("original source changed during public import: %v", err)
	}
	if err = target.Reopen(ctx); err != nil {
		t.Fatalf("reopen imported target %s: %v", targetPath, err)
	}
	sessions, err := target.store.ListStoryLogs(ctx, "default", "QQ-Group:100")
	if err != nil || len(sessions) != 1 || sessions[0].Name != "wal-session" {
		t.Fatalf("reopened target sessions = %#v, err=%v", sessions, err)
	}
	entries, err := target.store.GetStoryLogEntries(ctx, "default", "QQ-Group:100", "wal-session")
	if err != nil || len(entries) != 1 || entries[0].Message != "committed-only-in-wal" {
		t.Fatalf("reopened target WAL entries = %#v, err=%v", entries, err)
	}
	state, err := target.store.GetStoryLogState(ctx, "default", "QQ-Group:100")
	if err != nil || state.SessionID != sessions[0].ID || state.Name != "wal-session" || !state.On {
		t.Fatalf("reopened target WAL state = %#v, err=%v", state, err)
	}
	t.Logf("Importer.Run reopened-target manifest SHA-256=%x; source identity=%s", result.ManifestDigest, inventory.Identity)
	for _, file := range inventory.Metadata.Files {
		if contents, ok := sourceBefore[file.Name]; ok {
			t.Logf("unchanged source %s SHA-256=%x", file.Name, sha256.Sum256(contents))
		}
	}
	shmName := "nested/instance/data-logs.db-shm"
	changedSHM := append([]byte(nil), sourceBefore[shmName]...)
	if len(changedSHM) == 0 {
		t.Fatal("source inventory did not preserve the original SHM bytes")
	}
	changedSHM[0] ^= 0xff
	if err = os.WriteFile(logPath+"-shm", changedSHM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = source.Recheck(ctx, inventory.Metadata); !errors.Is(err, ErrSourceDrift) {
		t.Fatalf("original SHM drift error = %v, want %v", err, ErrSourceDrift)
	}
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySourceRejectsDataDirSymlinkEscapeDuringInventoryAndSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	outsideDir := filepath.Join(t.TempDir(), "outside-source")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: instance\n    dataDir: instance\n"))
	writeLegacyFixtureFile(t, filepath.Join(outsideDir, "serve.yaml"), []byte("{}\n"))
	createLegacySQLiteFixture(t, filepath.Join(outsideDir, "data.db"))
	if err := os.Symlink(outsideDir, filepath.Join(root, "instance")); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	source := NewLegacySource(root)
	_, inventoryErr := source.Inventory(context.Background())
	snapshotTarget := filepath.Join(t.TempDir(), "snapshot")
	_, snapshotErr := source.Snapshot(context.Background(), snapshotTarget)
	if !errors.Is(inventoryErr, ErrSourceMutation) {
		t.Errorf("Inventory error = %v, want %v", inventoryErr, ErrSourceMutation)
	}
	if !errors.Is(snapshotErr, ErrSourceMutation) {
		t.Errorf("Snapshot error = %v, want %v", snapshotErr, ErrSourceMutation)
	}
	if _, err := os.Stat(filepath.Join(snapshotTarget, "instance", "data.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot copied outside source data.db: stat error=%v", err)
	}
}

func TestLegacySourceAcceptsSymlinkRootAndAbsoluteInternalDataDir(t *testing.T) {
	actualRoot := filepath.Join(t.TempDir(), "source")
	dataDir := filepath.Join(actualRoot, "instance")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(actualRoot, "dice.yaml"), []byte(fmt.Sprintf("diceConfigs:\n  - name: instance\n    dataDir: %q\n", dataDir)))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte("{}\n"))
	createLegacySQLiteFixture(t, filepath.Join(dataDir, "data.db"))
	rootAlias := filepath.Join(t.TempDir(), "source-link")
	if err := os.Symlink(actualRoot, rootAlias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	source := NewLegacySource(rootAlias)
	if _, err := source.Inventory(context.Background()); err != nil {
		t.Fatalf("Inventory through explicit root symlink and absolute internal DataDir: %v", err)
	}
	snapshot, err := source.Snapshot(context.Background(), filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatalf("Snapshot through explicit root symlink: %v", err)
	}
	if _, err = os.Stat(filepath.Join(snapshot.Root, "instance", "data.db")); err != nil {
		t.Fatalf("snapshot omitted internal absolute DataDir database: %v", err)
	}
	movedRoot := actualRoot + "-moved"
	if err = os.Rename(actualRoot, movedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err = snapshot.Source.Inventory(context.Background()); err != nil {
		t.Fatalf("snapshot source still depends on absolute original dataDir: %v", err)
	}
}
