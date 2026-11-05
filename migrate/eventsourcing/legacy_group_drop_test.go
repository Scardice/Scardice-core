package eventsourcing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// legacyDropFixedNow pins the record file name used by drop tests.
func legacyDropFixedNow() time.Time { return time.Date(2026, 10, 31, 8, 30, 15, 0, time.UTC) }

// readDropRecords parses the JSONL record file of one run, keyed by identity.
func readDropRecords(t *testing.T, path string) map[string]map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		var record map[string]any
		if err = json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("drop record line %q: %v", line, err)
		}
		identity, _ := record["identity"].(string)
		if _, duplicate := records[identity]; duplicate {
			t.Fatalf("duplicate drop record identity %q", identity)
		}
		records[identity] = record
	}
	return records
}

// Rows whose group state cannot be decided no longer abort the whole import:
// every one is recorded with its original data, and the other groups import.
func TestLegacyGroupImportDropsUndecidableRowsAndRecordsThem(t *testing.T) {
	database := newLegacyGroupDatabase(t)
	insert := func(id any, data string) {
		t.Helper()
		if _, err := database.Exec(`INSERT INTO group_info (id, created_at, updated_at, data) VALUES (?, 7, 8, ?)`, id, []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	insert("QQ-Group:good", `{"active":true,"diceIdActiveMap":{"QQ:bot":true}}`)
	want := map[string]struct{ reason, data string }{
		"QQ-Group:scalar":        {legacyGroupDropInvalidData, `{"active":"yes"}`},
		"QQ-Group:ext":           {legacyGroupDropUndecidable, `{"activatedExtList":[{"name":"  "}]}`},
		"QQ-Group:contradiction": {legacyGroupDropUndecidable, `{"active":true,"notInGroup":true}`},
		"QQ-Group:json":          {legacyGroupDropInvalidData, `not json`},
		"QQ-Group:trailing":      {legacyGroupDropInvalidData, `{"groupId":"x"} junk`},
	}
	for id, fixture := range want {
		insert(id, fixture.data)
	}
	if _, err := database.Exec(`INSERT INTO group_info (id, created_at, updated_at, data) VALUES (CAST(X'FF41' AS TEXT), 7, 8, '{}')`); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	drops := newDropRecorder(dataDir, dropSourceLegacyImport, legacyDropFixedNow)
	states, err := streamLegacyGroupDatabaseStates(t, database, "QQ:bot", drops)
	if err != nil {
		t.Fatalf("undecidable rows aborted the import: %v", err)
	}
	if len(states) != 1 || !states["QQ-Group:good"].Active {
		t.Fatalf("imported groups = %#v, want only QQ-Group:good", states)
	}
	path, count, err := drops.Close()
	if err != nil || count != len(want)+1 {
		t.Fatalf("drop records = %q/%d/%v, want %d", path, count, err, len(want)+1)
	}
	if wantPath := filepath.Join(dataDir, "migration-drops", "legacy-import-20261031T083015Z.jsonl"); path != wantPath {
		t.Fatalf("record file = %q, want %q", path, wantPath)
	}
	if runtime.GOOS != "windows" {
		for target, mode := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
			info, statErr := os.Stat(target)
			if statErr != nil || info.Mode().Perm() != mode {
				t.Fatalf("%s mode = %v/%v, want %v", target, info, statErr, mode)
			}
		}
	}

	records := readDropRecords(t, path)
	for id, fixture := range want {
		record := records[id]
		detail, _ := record["detail"].(map[string]any)
		if record["source"] != "legacy-import" || record["kind"] != "group_info" || record["reason"] != fixture.reason ||
			record["droppedAt"] != "2026-10-31T08:30:15Z" || detail == nil ||
			detail["rowId"] != id || detail["data"] != fixture.data || detail["createdAt"] != float64(7) || detail["updatedAt"] != float64(8) {
			t.Fatalf("drop record %s = %#v", id, record)
		}
		if message, _ := detail["error"].(string); message == "" {
			t.Fatalf("drop record %s lacks the decision error: %#v", id, detail)
		}
	}
	invalid := records["\uFFFDA"]
	invalidDetail, _ := invalid["detail"].(map[string]any)
	if invalid["reason"] != legacyGroupDropInvalidID || invalidDetail["rowIdBase64"] != "/0E=" {
		t.Fatalf("invalid-id drop record = %#v", invalid)
	}
}

// v150 deleted group_info rows with NULL data or a present-but-not-positive
// created_at/updated_at; NULL timestamps were kept, and so are they here.
func TestLegacyGroupImportFollowsV150BadRowRules(t *testing.T) {
	database := newLegacyGroupDatabase(t)
	good := []byte(`{"active":true,"diceIdActiveMap":{"QQ:bot":true}}`)
	for _, row := range []struct {
		id        string
		createdAt any
		updatedAt any
		data      any
	}{
		{"QQ-Group:null-data", 1, 1, nil},
		{"QQ-Group:empty-data", 1, 1, []byte{}},
		{"QQ-Group:zero-created", 0, 1, good},
		{"QQ-Group:negative-created", -3, 1, good},
		{"QQ-Group:zero-updated", 1, 0, good},
		{"QQ-Group:null-times", nil, nil, good},
		{"QQ-Group:positive-times", 1, 2, good},
	} {
		if _, err := database.Exec(`INSERT INTO group_info (id, created_at, updated_at, data) VALUES (?, ?, ?, ?)`, row.id, row.createdAt, row.updatedAt, row.data); err != nil {
			t.Fatal(err)
		}
	}
	drops := newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow)
	states, err := streamLegacyGroupDatabaseStates(t, database, "QQ:bot", drops)
	if err != nil {
		t.Fatal(err)
	}
	path, count, err := drops.Close()
	if err != nil || count != 5 {
		t.Fatalf("drop records = %q/%d/%v, want 5", path, count, err)
	}
	if len(states) != 2 || !states["QQ-Group:null-times"].Active || !states["QQ-Group:positive-times"].Active {
		t.Fatalf("imported groups = %#v", states)
	}
	records := readDropRecords(t, path)
	for id, reason := range map[string]string{
		"QQ-Group:null-data":        legacyGroupDropDataNull,
		"QQ-Group:empty-data":       legacyGroupDropDataEmpty,
		"QQ-Group:zero-created":     legacyGroupDropCreatedAt,
		"QQ-Group:negative-created": legacyGroupDropCreatedAt,
		"QQ-Group:zero-updated":     legacyGroupDropUpdatedAt,
	} {
		if records[id]["reason"] != reason {
			t.Fatalf("drop record %s = %#v, want reason %s", id, records[id], reason)
		}
	}
	nullData, _ := records["QQ-Group:null-data"]["detail"].(map[string]any)
	if nullData["dataNull"] != true {
		t.Fatalf("NULL data detail = %#v", nullData)
	}
}

func TestLegacyGroupImportToleratesTableWithoutUpdatedAtColumn(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "groups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, statement := range []string{
		`CREATE TABLE group_info (id TEXT PRIMARY KEY, created_at INTEGER, data BLOB)`,
		`INSERT INTO group_info (id, created_at, data) VALUES ('QQ-Group:1', 4, '{"active":true,"diceIdActiveMap":{"QQ:bot":true}}')`,
	} {
		if _, err = database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	states, err := streamLegacyGroupDatabaseStates(t, database, "QQ:bot", newDropRecorder(t.TempDir(), dropSourceLegacyImport, legacyDropFixedNow))
	if err != nil || !states["QQ-Group:1"].Active {
		t.Fatalf("states = %#v, err = %v", states, err)
	}
}

// A drop must never be silent: without a recorder, or when the record file
// cannot be written, the import stops instead of discarding the row.
func TestLegacyGroupImportRefusesToDropWithoutDurableRecord(t *testing.T) {
	database := newLegacyGroupDatabase(t)
	if _, err := database.Exec(`INSERT INTO group_info (id, created_at, data) VALUES ('QQ-Group:bad', 5, 'not json')`); err != nil {
		t.Fatal(err)
	}
	if _, err := streamLegacyGroupDatabaseStates(t, database, "QQ:bot", nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("no recorder error = %v, want %v", err, ErrValidation)
	}

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "migration-drops"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := streamLegacyGroupDatabaseStates(t, database, "QQ:bot", newDropRecorder(dataDir, dropSourceLegacyImport, legacyDropFixedNow))
	if err == nil || errors.Is(err, ErrValidation) {
		t.Fatalf("unwritable record file error = %v, want a write failure", err)
	}
}
