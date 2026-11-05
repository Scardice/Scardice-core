package eventsourcing

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"Scardice-core/core/groupstate"
)

func TestLegacyGroupSnapshotPreservesHistoricalState(t *testing.T) {
	group, err := decodeLegacyGroupSnapshot([]byte(`{
		"groupId":"QQ-Group:42",
		"guildId":"QQ-Guild:7",
		"channelId":"QQ-Channel:9",
		"groupName":"Archive Group",
		"inviteUserId":"QQ:inviter",
		"enteredTime":777,
		"active":true,
		"notInGroup":false,
		"diceIdActiveMap":{"QQ:bot":true,"QQ:retired":false},
		"diceIdExistsMap":{"QQ:bot":true,"QQ:retired":false},
		"activatedExtList":[{"name":"coc7","version":"1.0"},{"name":"help"}],
		"inactivatedExtSet":{"deck":{}},
		"system":"coc7",
		"diceSideNum":100,
		"diceSideExpr":"1d100",
		"rollShaperMode":"coc",
		"cocRuleIndex":2,
		"defaultHelpGroup":"coc",
		"helpPackages":["coc7","common"],
		"showGroupWelcome":true,
		"groupWelcomeMessage":"welcome",
		"botList":{"QQ:other-bot":true},
		"privileges":{"QQ:owner":60,"QQ:blocked":-30},
		"playerGroups":{"investigators":["QQ:owner","QQ:member"],"empty":null},
		"logCurName":"archive-owned elsewhere",
		"runtimeFieldFromOlderBuild":{"ignored":true}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if group.GroupID != "QQ-Group:42" || group.GuildID != "QQ-Guild:7" || group.ChannelID != "QQ-Channel:9" ||
		group.GroupName != "Archive Group" || group.InviteUserID != "QQ:inviter" || group.EnteredTime != 777 {
		t.Fatalf("identity snapshot = %#v", group)
	}
	if !reflect.DeepEqual(group.ActivatedExtensions, []string{"coc7", "help"}) || !group.InactivatedExtensions["deck"] {
		t.Fatalf("extension snapshot = %#v / %#v", group.ActivatedExtensions, group.InactivatedExtensions)
	}

	records, err := legacyGroupRecords("QQ:bot", group, 1)
	if err != nil {
		t.Fatal(err)
	}
	state := groupstate.State{}
	for _, record := range records {
		event, decodeErr := groupstate.DecodeTypedEvent(groupstate.EventType(record.Kind), record.Payload)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		state, decodeErr = groupstate.Reduce(state, event)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
	}
	if state.GroupID != "QQ-Group:42" || state.GuildID != "QQ-Guild:7" || state.ChannelID != "QQ-Channel:9" ||
		state.GroupName != "Archive Group" || state.InviteUserID != "QQ:inviter" || state.EnteredAt != 777 || !state.Active {
		t.Fatalf("replayed identity/activation = %#v", state)
	}
	if !reflect.DeepEqual(state.DiceIDActive, map[string]bool{"QQ:bot": true}) ||
		!reflect.DeepEqual(state.DiceIDExists, map[string]bool{"QQ:bot": true}) {
		t.Fatalf("replayed dice maps = %#v / %#v", state.DiceIDActive, state.DiceIDExists)
	}
	if !reflect.DeepEqual(state.ActivatedExtensions, []string{"coc7", "help"}) || !state.InactivatedExtensions["deck"] ||
		state.System != "coc7" || state.DiceSideNum != 100 || state.DiceSideExpr != "1d100" ||
		state.RollShaperMode != "coc" || state.CocRuleIndex != 2 {
		t.Fatalf("replayed extension/template state = %#v", state)
	}
	if state.DefaultHelpGroup != "coc" || !reflect.DeepEqual(state.HelpPackages, []string{"coc7", "common"}) ||
		!state.ShowGroupWelcome || state.GroupWelcomeMessage != "welcome" || !state.BotList["QQ:other-bot"] {
		t.Fatalf("replayed group preferences = %#v", state)
	}
	if state.Privileges["QQ:owner"] != 60 || state.Privileges["QQ:blocked"] != -30 ||
		!reflect.DeepEqual(state.PlayerGroups["investigators"], []string{"QQ:owner", "QQ:member"}) {
		t.Fatalf("replayed privileges/teams = %#v / %#v", state.Privileges, state.PlayerGroups)
	}
	if members, exists := state.PlayerGroups["empty"]; !exists || members != nil {
		t.Fatalf("empty historical team = %#v, exists=%t", members, exists)
	}
}

func TestLegacyGroupImportDoesNotInventEndpointMembership(t *testing.T) {
	states, err := streamLegacyGroupStates(t, "default", map[string]string{
		"QQ-Group:missing-active": `{"active":true,"notInGroup":false}`,
		"QQ-Group:missing-exists": `{"active":false,"notInGroup":false}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"QQ-Group:missing-active", "QQ-Group:missing-exists"} {
		state, found := states[id]
		if !found || state.GroupID != id || state.Active || len(state.DiceIDActive) != 0 || len(state.DiceIDExists) != 0 {
			t.Fatalf("group %q was lost or acquired a synthetic endpoint membership: %#v", id, state)
		}
	}
}

func TestLegacyGroupSnapshotRejectsMalformedOwnedFields(t *testing.T) {
	fixtures := [][]byte{
		[]byte(`{"active":"true"}`),
		[]byte(`{"diceIdActiveMap":{"QQ:bot":1}}`),
		[]byte(`{"activatedExtList":[{"name":3}]}`),
		[]byte(`{"activatedExtList":[3]}`),
		[]byte(`{"inactivatedExtSet":{"deck":true}}`),
		[]byte(`{"playerGroups":{"team":[1]}}`),
		[]byte(`{"groupId":"QQ-Group:1"} trailing`),
	}
	for _, fixture := range fixtures {
		if _, err := decodeLegacyGroupSnapshot(fixture); !errors.Is(err, ErrValidation) {
			t.Fatalf("fixture %s error = %v", fixture, err)
		}
	}
}

// streamLegacyGroupStates imports group_info rows through the real SQLite
// source stream and replays the emitted events, returning the resulting
// consumer-visible group state per row id.
func streamLegacyGroupStates(t *testing.T, diceID string, rows map[string]string) (map[string]groupstate.State, error) {
	t.Helper()
	database := newLegacyGroupDatabase(t)
	for id, data := range rows {
		if _, err := database.Exec(`INSERT INTO group_info (id, created_at, data) VALUES (?, ?, ?)`, id, 5, []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	return streamLegacyGroupDatabaseStates(t, database, diceID, nil)
}

func newLegacyGroupDatabase(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "groups.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err = database.Exec(`CREATE TABLE group_info (id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER, data BLOB)`); err != nil {
		t.Fatal(err)
	}
	return database
}

// streamLegacyGroupDatabaseStates streams group_info through the real stream
// and replays the emitted events, returning the consumer-visible group state
// per imported group id. drops receives the rows the stream cannot import.
func streamLegacyGroupDatabaseStates(t *testing.T, database *sql.DB, diceID string, drops *dropRecorder) (map[string]groupstate.State, error) {
	t.Helper()
	byStream := map[string][]SourceRecord{}
	batcher := &sourceRecordBatcher{yield: func(batch []SourceRecord) error {
		for _, record := range batch {
			byStream[record.Identity] = append(byStream[record.Identity], record)
		}
		return nil
	}}
	if err := streamLegacyGroups(context.Background(), database, diceID, drops, batcher); err != nil {
		return nil, err
	}
	if err := batcher.flush(); err != nil {
		t.Fatal(err)
	}
	states := make(map[string]groupstate.State, len(byStream))
	for _, records := range byStream {
		state := groupstate.State{}
		for _, record := range records {
			event, decodeErr := groupstate.DecodeTypedEvent(groupstate.EventType(record.Kind), record.Payload)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if state, decodeErr = groupstate.Reduce(state, event); decodeErr != nil {
				t.Fatal(decodeErr)
			}
		}
		states[state.GroupID] = state
	}
	return states, nil
}

// QQ-CH groups auto-created while QQChannelAutoOn=false are persisted by the
// historical runtime with Active=false while diceIdActiveMap still lists the
// endpoint (SetBotOnAtGroup stores it, then Active is reset). The historical
// IsActive requires both, so the group is off and the import must not abort.
func TestLegacyGroupImportQQChannelDefaultGroupIsInactive(t *testing.T) {
	states, err := streamLegacyGroupStates(t, "QQ:bot", map[string]string{
		"QQ-CH-Group:900": `{"groupId":"QQ-CH-Group:900","active":false,
			"diceIdActiveMap":{"QQ:bot":true},"diceIdExistsMap":{"QQ:bot":true}}`,
		"QQ-Group:901": `{"groupId":"QQ-Group:901","active":true,
			"diceIdActiveMap":{"QQ:bot":true,"QQ:other":false},"diceIdExistsMap":{"QQ:bot":true,"QQ:other":true}}`,
	})
	if err != nil {
		t.Fatalf("QQ-CH default group aborted the import: %v", err)
	}
	channel := states["QQ-CH-Group:900"]
	if channel.Active || len(channel.DiceIDActive) != 0 || !channel.DiceIDExists["QQ:bot"] {
		t.Fatalf("auto-off QQ-CH group = active:%t activeMap:%v exists:%v", channel.Active, channel.DiceIDActive, channel.DiceIDExists)
	}
	normal := states["QQ-Group:901"]
	if !normal.Active || !normal.DiceIDActive["QQ:bot"] || normal.DiceIDActive["QQ:other"] || !normal.DiceIDExists["QQ:other"] {
		t.Fatalf("active group = active:%t activeMap:%v exists:%v", normal.Active, normal.DiceIDActive, normal.DiceIDExists)
	}
}

// Automatic quit removes only the exists entry, so an active endpoint missing
// from diceIdExistsMap is a state the historical loader accepted as-is.
func TestLegacyGroupImportActiveEndpointMissingFromExistsMap(t *testing.T) {
	states, err := streamLegacyGroupStates(t, "QQ:bot", map[string]string{
		"QQ-Group:1": `{"active":true,"diceIdActiveMap":{"QQ:bot":true},"diceIdExistsMap":{}}`,
	})
	if err != nil {
		t.Fatalf("active-but-not-exists group aborted the import: %v", err)
	}
	state := states["QQ-Group:1"]
	if !state.Active || !state.DiceIDActive["QQ:bot"] || len(state.DiceIDExists) != 0 {
		t.Fatalf("state = active:%t activeMap:%v exists:%v", state.Active, state.DiceIDActive, state.DiceIDExists)
	}
}

// The historical loader decoded loosely: null scalars are zero values, an
// empty/missing/null extension entry is skipped, duplicates collapse, the row
// id overrides the embedded groupId, notInGroup is never read when the maps are
// present, and "QQ-Group:" keys were dropped from the exists map.
func TestLegacyGroupImportToleratesShapesTheHistoricalLoaderAccepted(t *testing.T) {
	states, err := streamLegacyGroupStates(t, "QQ:bot", map[string]string{
		"QQ-Group:10": `{"groupId":null,"groupName":null,"active":true,"enteredTime":null,
			"diceIdActiveMap":{"QQ:bot":true},"diceIdExistsMap":{"QQ:bot":true,"QQ-Group:10":true},
			"notInGroup":true,
			"activatedExtList":[{"name":""},{"version":"1"},null,{"name":null},{"name":"coc7"},{"name":"coc7"},{"name":"deck"}],
			"inactivatedExtSet":{"deck":null,"":{},"help":{"ignored":1}}}`,
		"QQ-Group:11": `{"groupId":"QQ-Group:STALE","active":true,"diceIdActiveMap":{"QQ:bot":true}}`,
	})
	if err != nil {
		t.Fatalf("loosely shaped rows aborted the import: %v", err)
	}
	state := states["QQ-Group:10"]
	if !state.Active || state.GroupName != "" || state.EnteredAt != 5 {
		t.Fatalf("scalar nulls = %#v", state)
	}
	if !reflect.DeepEqual(state.ActivatedExtensions, []string{"coc7", "deck"}) {
		t.Fatalf("activated extensions = %v", state.ActivatedExtensions)
	}
	// "deck" is in both sets; the historical activated list governed dispatch.
	if state.InactivatedExtensions["deck"] || !state.InactivatedExtensions["help"] || state.InactivatedExtensions[""] {
		t.Fatalf("inactivated extensions = %v", state.InactivatedExtensions)
	}
	if !reflect.DeepEqual(state.DiceIDExists, map[string]bool{"QQ:bot": true}) {
		t.Fatalf("exists map = %v", state.DiceIDExists)
	}
	if _, kept := states["QQ-Group:STALE"]; kept {
		t.Fatal("embedded groupId overrode the row id")
	}
	if !states["QQ-Group:11"].Active {
		t.Fatalf("row-id group state = %#v", states["QQ-Group:11"])
	}
}
