package eventsourcing

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

// readDropRecordList parses a record file in order, for runs whose records
// can share an identity.
func readDropRecordList(t *testing.T, path string) []map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		var record map[string]any
		if err = json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("drop record line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func dropDetail(record map[string]any) map[string]any {
	detail, _ := record["detail"].(map[string]any)
	return detail
}

// streamLegacyFixtureWithDrops streams a SQLite fixture through the real
// stream with a recorder and counts what was imported.
type legacyImportCounts struct{ baselines, players, moderation, groups int }

func streamLegacyFixtureWithDrops(t *testing.T, path string) (legacyImportCounts, *dropRecorder, error) {
	t.Helper()
	drops := newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow)
	var counts legacyImportCounts
	err := streamLegacySQLiteWithDrops(context.Background(), path, "default", drops, func(batch []SourceRecord) error {
		for _, record := range batch {
			switch {
			case record.Kind == attributestate.EventBaselineImported:
				counts.baselines++
			case record.Kind == string(playerstate.EventPlayerCreated):
				counts.players++
			case record.Kind == string(groupstate.EventGroupCreated):
				counts.groups++
			case record.RecordType == RecordTypeSecret && record.Domain == "moderation":
				counts.moderation++
			}
		}
		return nil
	})
	return counts, drops, err
}

func execLegacyFixture(t *testing.T, path string, statements ...string) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, statement := range statements {
		if _, err = database.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// A non-empty attrs row without an identity cannot be addressed; it is
// recorded with everything readable and the remaining attrs import.
func TestStreamLegacySQLiteDropsAttrsWithoutIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	execLegacyFixture(t, path,
		`INSERT INTO attrs (id, data, attrs_type, binding_sheet_id, name, owner_id, sheet_type, is_hidden, created_at, updated_at)
			SELECT '', data, 'character', 'bind-1', 'Nameless', 'QQ:7', 'coc7', 0, 100, 101 FROM attrs WHERE id = 'QQ-Group:100-QQ:200'`,
		`INSERT INTO attrs (id, data, attrs_type, created_at, updated_at)
			SELECT '   ', data, 'group_user', 102, 103 FROM attrs WHERE id = 'QQ-Group:100-QQ:200'`,
		`INSERT INTO attrs (id, data, created_at, updated_at)
			SELECT NULL, data, 104, 105 FROM attrs WHERE id = 'QQ-Group:100-QQ:200'`,
	)
	counts, drops, err := streamLegacyFixtureWithDrops(t, path)
	if err != nil {
		t.Fatalf("attrs without identity aborted the import: %v", err)
	}
	if counts.baselines != 1 || counts.groups != 1 || counts.players != 1 || counts.moderation != 1 {
		t.Fatalf("imported rows = %#v, want the fixture rows only", counts)
	}
	recordPath, count, err := drops.Close()
	if err != nil || count != 3 {
		t.Fatalf("drop records = %q/%d/%v, want 3", recordPath, count, err)
	}
	records := readDropRecordList(t, recordPath)
	for _, record := range records {
		detail := dropDetail(record)
		if record["kind"] != "attrs" || record["reason"] != "attrs-missing-id" || detail["table"] != "attrs" || detail["data"] == "" || detail["data"] == nil {
			t.Fatalf("attrs drop record = %#v", record)
		}
	}
	var first map[string]any
	for _, record := range records {
		if detail := dropDetail(record); detail["createdAt"] == float64(100) {
			first = detail
		}
	}
	if first["attrsType"] != "character" || first["bindingSheetId"] != "bind-1" || first["name"] != "Nameless" ||
		first["ownerId"] != "QQ:7" || first["sheetType"] != "coc7" || first["createdAt"] != float64(100) || first["updatedAt"] != float64(101) {
		t.Fatalf("attrs drop detail = %#v", first)
	}
}

// Text that is not valid UTF-8 survives a drop record losslessly as base64.
func TestLegacyDropRecordKeepsNonUTF8DataAsBase64(t *testing.T) {
	drops := newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow)
	if err := recordLegacyRowDrop(drops, "attrs", "default", "id", "attrs-missing-id", []byte{0xff, 0x41}, nil); err != nil {
		t.Fatal(err)
	}
	path, _, err := drops.Close()
	if err != nil {
		t.Fatal(err)
	}
	detail := dropDetail(readDropRecordList(t, path)[0])
	if detail["dataBase64"] != "/0E=" || detail["data"] != nil {
		t.Fatalf("non-UTF-8 detail = %#v", detail)
	}
}

// ban_info rows whose JSON is damaged are recorded; the other bans import.
func TestStreamLegacySQLiteDropsBanWithInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	execLegacyFixture(t, path,
		`INSERT INTO ban_info (id, ban_updated_at, data) VALUES ('QQ:garbage', 9, 'not json')`,
		`INSERT INTO ban_info (id, ban_updated_at, data) VALUES ('QQ:wrongtype', 10, '{"score":"high"}')`,
	)
	counts, drops, err := streamLegacyFixtureWithDrops(t, path)
	if err != nil {
		t.Fatalf("damaged ban JSON aborted the import: %v", err)
	}
	if counts.moderation != 1 || counts.baselines != 1 || counts.groups != 1 {
		t.Fatalf("imported rows = %#v, want the fixture rows only", counts)
	}
	recordPath, count, err := drops.Close()
	if err != nil || count != 2 {
		t.Fatalf("drop records = %q/%d/%v, want 2", recordPath, count, err)
	}
	records := readDropRecords(t, recordPath)
	for id, want := range map[string]struct {
		data      string
		updatedAt float64
	}{"QQ:garbage": {"not json", 9}, "QQ:wrongtype": {`{"score":"high"}`, 10}} {
		record := records[id]
		detail := dropDetail(record)
		if record["kind"] != "ban_info" || record["reason"] != "invalid-data" || detail["rowId"] != id ||
			detail["data"] != want.data || detail["banUpdatedAt"] != want.updatedAt {
			t.Fatalf("ban drop record %s = %#v", id, record)
		}
	}
}

// A player row without user or group cannot name its stream.
func TestStreamLegacySQLiteDropsPlayersWithoutIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	execLegacyFixture(t, path,
		`INSERT INTO group_player_info (name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id) VALUES ('NoUser', NULL, 5, '{$t}', 20, 'QQ-Group:100')`,
		`INSERT INTO group_player_info (name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id) VALUES ('NoGroup', 'QQ:5', 6, '', 0, '')`,
	)
	counts, drops, err := streamLegacyFixtureWithDrops(t, path)
	if err != nil {
		t.Fatalf("player without identity aborted the import: %v", err)
	}
	if counts.players != 1 || counts.groups != 1 || counts.baselines != 1 {
		t.Fatalf("imported rows = %#v, want the fixture rows only", counts)
	}
	recordPath, count, err := drops.Close()
	if err != nil || count != 2 {
		t.Fatalf("drop records = %q/%d/%v, want 2", recordPath, count, err)
	}
	for _, record := range readDropRecordList(t, recordPath) {
		detail := dropDetail(record)
		if record["kind"] != "group_player_info" || record["reason"] != "player-missing-identity" || detail["table"] != "group_player_info" {
			t.Fatalf("player drop record = %#v", record)
		}
		switch detail["name"] {
		case "NoUser":
			if detail["userId"] != "" || detail["groupId"] != "QQ-Group:100" || detail["lastCommandTime"] != float64(5) ||
				detail["autoSetNameTemplate"] != "{$t}" || detail["diceSideNum"] != float64(20) {
				t.Fatalf("NoUser detail = %#v", detail)
			}
		case "NoGroup":
			if detail["userId"] != "QQ:5" || detail["groupId"] != "" || detail["lastCommandTime"] != float64(6) {
				t.Fatalf("NoGroup detail = %#v", detail)
			}
		default:
			t.Fatalf("unexpected player drop %#v", detail)
		}
	}

	// Without a recorder the row still aborts with safe row context.
	err = streamLegacySQLiteWithDrops(context.Background(), path, "default", nil, func([]SourceRecord) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "group_player_info") {
		t.Fatalf("player without identity and no recorder = %v", err)
	}
}

// A group whose story log is current but has no matching session imports; only
// the story-log state is dropped, and a group with a session keeps its state.
func TestLegacySourceDropsStoryLogStateWithoutSession(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "legacy")
	dataDir := filepath.Join(root, "default")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: default\n"))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte("{}\n"))
	createLegacySQLiteFixture(t, filepath.Join(dataDir, "data.db"))
	execLegacyFixture(t, filepath.Join(dataDir, "data.db"),
		`INSERT INTO group_info (id, created_at, data) VALUES ('QQ-Group:nosession', 1, '{"groupId":"QQ-Group:nosession","logCurName":"gone","logOn":true}')`,
		`INSERT INTO group_info (id, created_at, data) VALUES ('QQ-Group:paused', 1, '{"groupId":"QQ-Group:paused","logCurName":"gone-too","logOn":false}')`,
		`INSERT INTO group_info (id, created_at, data) VALUES ('QQ-Group:withsession', 1, '{"groupId":"QQ-Group:withsession","logCurName":"live","logOn":true}')`,
	)
	execLegacyFixture(t, filepath.Join(dataDir, "data-logs.db"),
		`CREATE TABLE logs (id INTEGER PRIMARY KEY, name TEXT, group_id TEXT, extra TEXT, created_at INTEGER, updated_at INTEGER, upload_url TEXT, upload_time INTEGER)`,
		`CREATE TABLE log_items (id INTEGER PRIMARY KEY, log_id INTEGER, group_id TEXT, nickname TEXT, im_userid TEXT, time INTEGER, message TEXT, is_dice INTEGER, command_id INTEGER, command_info TEXT, raw_msg_id TEXT, user_uniform_id TEXT, removed INTEGER, parent_id INTEGER, seq INTEGER)`,
		`INSERT INTO logs (id, name, group_id, created_at, updated_at) VALUES (3, 'live', 'QQ-Group:withsession', 1, 1)`,
	)
	source := NewLegacySource(root)
	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	drops := newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow)
	snapshot.Source.(interface{ bindDropRecorder(*dropRecorder) }).bindDropRecorder(drops)
	states := map[string]bool{}
	groups := map[string]bool{}
	if err = snapshot.Source.(RecordStreamer).StreamRecords(ctx, func(batch []SourceRecord) error {
		for _, record := range batch {
			if record.Domain == legacyLogRecordDomain && record.Kind == legacyLogImportState {
				var payload legacyStoryLogImportPayload
				if err := json.Unmarshal(record.Payload, &payload); err != nil {
					return err
				}
				states[payload.GroupID] = true
			}
			if record.Kind == string(groupstate.EventGroupCreated) {
				groups[record.Identity] = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("story-log state without a session aborted the import: %v", err)
	}
	if !states["QQ-Group:withsession"] || states["QQ-Group:nosession"] || len(states) != 1 {
		t.Fatalf("imported story-log states = %v", states)
	}
	if len(groups) < 4 {
		t.Fatalf("imported groups = %v, want every group", groups)
	}
	recordPath, count, err := drops.Close()
	if err != nil || count != 2 {
		t.Fatalf("drop records = %q/%d/%v, want 2", recordPath, count, err)
	}
	records := readDropRecords(t, recordPath)
	for id, wantOn := range map[string]bool{"QQ-Group:nosession": true, "QQ-Group:paused": false} {
		record := records[id]
		detail := dropDetail(record)
		storyLog, _ := detail["storyLog"].(map[string]any)
		if record["kind"] != "group_info" || record["reason"] != "story-log-session-missing" || detail["groupImported"] != true ||
			storyLog["logOn"] != wantOn || storyLog["logCurName"] == "" || storyLog["logCurName"] == nil {
			t.Fatalf("story-log drop record %s = %#v", id, record)
		}
	}
}

// The remote snapshot feeds the same stream, so remote rows that cannot be
// imported are recorded identically, including NULL ids and data the copy
// into the local snapshot must not reject.
func TestRemoteSQLSourceDropsUnimportableRows(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(filepath.Join(root, "default"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: data/default\n"))
	writeLegacyFixtureFile(t, filepath.Join(root, "default", "serve.yaml"), []byte("{}\n"))
	remotePath := filepath.Join(t.TempDir(), "remote.db")
	createLegacySQLiteFixture(t, remotePath)
	execLegacyFixture(t, remotePath,
		`INSERT INTO attrs (id, data, attrs_type, created_at, updated_at) SELECT NULL, data, 'character', 1, 2 FROM attrs WHERE id = 'QQ-Group:100-QQ:200'`,
		`INSERT INTO ban_info (id, ban_updated_at, data) VALUES ('QQ:nullban', 1, NULL)`,
		`INSERT INTO ban_info (id, ban_updated_at, data) VALUES ('QQ:garbage', 2, 'not json')`,
		`INSERT INTO group_player_info (name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id) VALUES ('NoUser', NULL, 5, '', 0, 'QQ-Group:100')`,
	)
	source := NewRemoteSQLSource(root, eventstore.DatabaseConfig{Type: "mysql", DSN: "unused"})
	source.open = func(context.Context, eventstore.DatabaseConfig) (*sql.DB, error) {
		return sql.Open("sqlite", "file:"+filepath.ToSlash(remotePath)+"?mode=ro")
	}
	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatalf("remote snapshot rejected rows the importer can drop: %v", err)
	}
	drops := newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow)
	snapshot.Source.(interface{ bindDropRecorder(*dropRecorder) }).bindDropRecorder(drops)
	if err = snapshot.Source.(RecordStreamer).StreamRecords(ctx, func([]SourceRecord) error { return nil }); err != nil {
		t.Fatalf("remote import aborted on droppable rows: %v", err)
	}
	recordPath, count, err := drops.Close()
	if err != nil || count != 4 {
		t.Fatalf("drop records = %q/%d/%v, want 4", recordPath, count, err)
	}
	reasons := map[string]int{}
	for _, record := range readDropRecordList(t, recordPath) {
		reasons[record["kind"].(string)+"/"+record["reason"].(string)]++
	}
	for _, want := range []string{"attrs/attrs-missing-id", "ban_info/data-empty", "ban_info/invalid-data", "group_player_info/player-missing-identity"} {
		if reasons[want] != 1 {
			t.Fatalf("remote drop reasons = %v, missing %s", reasons, want)
		}
	}
}
