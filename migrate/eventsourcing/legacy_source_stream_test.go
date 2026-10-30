package eventsourcing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice"
)

func TestStreamLegacySQLiteRejectsMissingOwnedTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec("DROP TABLE ban_info"); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	err = streamLegacySQLite(context.Background(), path, "default", func([]SourceRecord) error { return nil })
	if !errors.Is(err, ErrUnsupportedPreflight) || !strings.Contains(err.Error(), "ban_info") {
		t.Fatalf("missing table error = %v", err)
	}
}

func TestStreamLegacySQLiteNormalizesNullableScalarColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	group, err := json.Marshal(map[string]any{
		"groupId": "QQ-Group:100", "groupName": "Legacy Group",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`UPDATE group_info SET created_at = NULL, data = ? WHERE id = 'QQ-Group:100'`, group); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`UPDATE group_player_info SET name = NULL, last_command_time = NULL, auto_set_name_template = NULL, dice_side_num = NULL WHERE user_id = 'QQ:200'`); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	var groupCreated groupstate.GroupCreatedV1
	var playerCreated playerstate.PlayerCreatedV1
	err = streamLegacySQLiteWithKeySource(context.Background(), path, "default", sqliteTargetKeySource{}, func(batch []SourceRecord) error {
		for _, record := range batch {
			switch record.Kind {
			case string(groupstate.EventGroupCreated):
				if unmarshalErr := json.Unmarshal(record.Payload, &groupCreated); unmarshalErr != nil {
					return unmarshalErr
				}
			case string(playerstate.EventPlayerCreated):
				if unmarshalErr := json.Unmarshal(record.Payload, &playerCreated); unmarshalErr != nil {
					return unmarshalErr
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if groupCreated.GroupID != "QQ-Group:100" || groupCreated.EnteredAt != 0 {
		t.Fatalf("group created from nullable timestamp = %#v", groupCreated)
	}
	if playerCreated.GroupID != "QQ-Group:100" || playerCreated.UserID != "QQ:200" || playerCreated.Name != "" {
		t.Fatalf("player created from nullable optional fields = %#v", playerCreated)
	}
}

func TestStreamLegacySQLiteReportsInvalidPlayerContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`UPDATE group_player_info SET user_id = NULL WHERE group_id = 'QQ-Group:100'`); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	err = streamLegacySQLiteWithKeySource(context.Background(), path, "default", sqliteTargetKeySource{}, func([]SourceRecord) error {
		return nil
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid player error = %v, want %v", err, ErrValidation)
	}
	if !strings.Contains(err.Error(), "group_player_info") || !strings.Contains(err.Error(), "QQ-Group:100") {
		t.Fatalf("invalid player error lacks safe row context: %v", err)
	}
}

func TestStreamLegacySQLiteSkipsEmptyUnaddressableAttrsPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	emptyAttrs, err := ds.NewDictVal(&ds.ValueMap{}).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(
		`INSERT INTO attrs (id, data, attrs_type, binding_sheet_id, name, owner_id, sheet_type, is_hidden, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"", emptyAttrs, nil, "", "", "", "", true, 100, 101,
	); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	baselines := 0
	err = streamLegacySQLiteWithKeySource(context.Background(), path, "default", sqliteTargetKeySource{}, func(batch []SourceRecord) error {
		for _, record := range batch {
			if record.Kind == attributestate.EventBaselineImported {
				baselines++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if baselines != 1 {
		t.Fatalf("attribute baselines = %d, want only the addressed fixture row", baselines)
	}
}

func TestStreamLegacySQLiteRejectsNonEmptyAttrsWithoutIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	values := &ds.ValueMap{}
	values.Store("hp", ds.NewIntVal(60))
	attrs, err := ds.NewDictVal(values).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO attrs (id, data, created_at, updated_at) VALUES (?, ?, ?, ?)`, "", attrs, 100, 101); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	err = streamLegacySQLiteWithKeySource(context.Background(), path, "default", sqliteTargetKeySource{}, func([]SourceRecord) error {
		return nil
	})
	if !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), `legacy attrs ""`) {
		t.Fatalf("non-empty attrs without identity error = %v", err)
	}
}

func TestStreamLegacySQLiteYieldsBoundedBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	createLegacySQLiteFixture(t, path)
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = func() (resultErr error) {
		statement, err := transaction.Prepare(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, statement.Close()) }()
		for index := range MaxBatchRecords + 200 {
			id := fmt.Sprintf("QQ-Group:%04d", index+1000)
			payload, err := json.Marshal(map[string]any{"groupId": id, "groupName": id})
			if err != nil {
				return err
			}
			if _, err = statement.Exec(id, index, payload); err != nil {
				return err
			}
		}
		return nil
	}(); err != nil {
		t.Fatal(err)
	}
	if err = transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	batches := 0
	records := 0
	err = streamLegacySQLiteWithKeySource(context.Background(), path, "default", sqliteTargetKeySource{}, func(batch []SourceRecord) error {
		batches++
		if len(batch) == 0 || len(batch) > MaxBatchRecords {
			t.Fatalf("batch records = %d", len(batch))
		}
		var bytes uint64
		for _, record := range batch {
			bytes += record.Size
		}
		if bytes > MaxBatchBytes {
			t.Fatalf("batch bytes = %d", bytes)
		}
		records += len(batch)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if batches < 2 || records < MaxBatchRecords+200 {
		t.Fatalf("batches/records = %d/%d", batches, records)
	}
}

func createLegacySQLiteFixture(t *testing.T, path string) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	statements := []string{
		`CREATE TABLE group_info (id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER, data BLOB)`,
		`CREATE TABLE group_player_info (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, user_id TEXT, last_command_time INTEGER, auto_set_name_template TEXT, dice_side_num INTEGER, group_id TEXT)`,
		`CREATE TABLE attrs (id TEXT, data BLOB, attrs_type TEXT, binding_sheet_id TEXT, name TEXT, owner_id TEXT, sheet_type TEXT, is_hidden INTEGER, created_at INTEGER, updated_at INTEGER)`,
		`CREATE TABLE ban_info (id TEXT PRIMARY KEY, ban_updated_at INTEGER, updated_at INTEGER, data BLOB)`,
		`CREATE TABLE endpoint_info (user_id TEXT PRIMARY KEY, cmd_num INTEGER, cmd_last_time INTEGER, online_time INTEGER, updated_at INTEGER)`,
	}
	for _, statement := range statements {
		if _, err = database.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = database.Exec(`INSERT INTO endpoint_info (user_id, cmd_num, cmd_last_time, online_time, updated_at) VALUES (?, ?, ?, ?, ?)`, "QQ:12345", 84, nil, 789, 34567); err != nil {
		t.Fatal(err)
	}
	group, err := json.Marshal(map[string]any{
		"active": true, "groupId": "QQ-Group:100", "groupName": "Legacy Group", "enteredTime": int64(99),
		"diceIdActiveMap": map[string]bool{"QQ:bot": true}, "diceIdExistsMap": map[string]bool{"QQ:bot": true},
		"activatedExtList": []map[string]string{{"name": "coc7"}}, "system": "coc7", "diceSideNum": int64(100),
		"showGroupWelcome": true, "groupWelcomeMessage": "welcome", "botList": map[string]bool{"QQ:other-bot": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`, "QQ-Group:100", 98, group); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO group_player_info (name, user_id, last_command_time, auto_set_name_template, dice_side_num, group_id) VALUES (?, ?, ?, ?, ?, ?)`, "Alice", "QQ:200", 123, "{$t玩家_RAW}", 100, "QQ-Group:100"); err != nil {
		t.Fatal(err)
	}
	attrMap := &ds.ValueMap{}
	attrMap.Store("hp", ds.NewIntVal(60))
	attrMap.Store("san", ds.NewIntVal(45))
	attrs, err := ds.NewDictVal(attrMap).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO attrs (id, data, attrs_type, binding_sheet_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, "QQ-Group:100-QQ:200", attrs, "group_user", "character-1", 100, 101); err != nil {
		t.Fatal(err)
	}
	ban, err := json.Marshal(dice.BanListInfoItem{ID: "QQ:bad", Name: "Bad", Score: 42, Rank: dice.BanRankBanned, Times: []int64{100}, Reasons: []string{"spam"}, Places: []string{"QQ-Group:100"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO ban_info (id, ban_updated_at, updated_at, data) VALUES (?, ?, ?, ?)`, "QQ:bad", 100, 100, ban); err != nil {
		t.Fatal(err)
	}
}

func writeLegacyFixtureFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
