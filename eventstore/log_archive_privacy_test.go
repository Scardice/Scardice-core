package eventstore_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"Scardice-core/eventstore"
)

func openStoryLogPrivacyStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "archive.db"), DatabaseIdentity: "archive-privacy"})
	if err != nil {
		t.Fatal(err)
	}
	return eventstore.NewStore(db), db
}
func seedStoryPrivacyScope(t *testing.T, store *eventstore.GORMStore, dice, group, source string) {
	t.Helper()
	ctx := context.Background()
	session, err := store.CreateStoryLog(ctx, dice, group, "session")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStoryLogState(ctx, eventstore.StoryLogState{DiceID: dice, GroupID: group, SessionID: session.ID, Name: session.Name, On: true}); err != nil {
		t.Fatal(err)
	}
	entry := eventstore.StoryLogEntry{DiceID: dice, GroupID: group, LogName: session.Name, RawMsgID: source + "-raw", Message: "plaintext message"}
	if err := store.AppendStoryLogEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueStoryLogIntent(ctx, eventstore.StoryLogIntent{EffectID: source + "-intent", Entry: entry}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportStoryLogBatch(ctx, []eventstore.StoryLogImportRecord{{SourceID: source + "-import", Kind: eventstore.StoryLogImportSession, DiceID: dice, GroupID: group, Session: &eventstore.StoryLogSession{DiceID: dice, GroupID: group, Name: "imported"}}}); err != nil {
		t.Fatal(err)
	}
}
func archiveCount(t *testing.T, db *eventstore.Database, table, dice, group string) int64 {
	t.Helper()
	var count int64
	if err := db.GORM().Table(table).Where("dice_id = ? AND group_id = ?", []byte(dice), []byte(group)).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}
func archiveTables() []string {
	return []string{"story_log_sessions", "story_log_states", "story_log_entries", "story_log_outbound_intents", "story_log_imports"}
}
func archiveRequest() eventstore.PrivacyDryRunRequest {
	return eventstore.PrivacyDryRunRequest{GroupID: "g", DiceIDs: []string{"dice-a"}, Scopes: []string{"logs"}}
}
func TestStoryPrivacyDeletesAllFiveTablesAndPreservesOtherScopes(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t)
	defer db.Close()
	seedStoryPrivacyScope(t, store, "dice-a", "g", "target")
	seedStoryPrivacyScope(t, store, "dice-b", "g", "other-dice")
	seedStoryPrivacyScope(t, store, "dice-a", "g-longer", "other-group")
	req := archiveRequest()
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Counts.LogSessions != 2 || scan.Counts.LogStates != 1 || scan.Counts.LogEntries != 1 || scan.Counts.LogIntents != 1 || scan.Counts.LogImports != 1 {
		t.Fatalf("archive counts=%+v", scan.Counts)
	}
	result, err := store.PrivacyDeleteGroup(ctx, eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if err != nil || result.Deleted != scan.Counts {
		t.Fatalf("delete result=%+v err=%v", result, err)
	}
	for _, table := range archiveTables() {
		if count := archiveCount(t, db, table, "dice-a", "g"); count != 0 {
			t.Fatalf("target table %s retained %d rows", table, count)
		}
		for _, survivor := range [][2]string{{"dice-b", "g"}, {"dice-a", "g-longer"}} {
			if count := archiveCount(t, db, table, survivor[0], survivor[1]); count == 0 {
				t.Fatalf("cross-owner delete %s %+v", table, survivor)
			}
		}
	}
	if err := store.CompleteStoryLogIntent(ctx, "target-intent", true); err != nil {
		t.Fatal(err)
	}
	if logs, err := store.ListStoryLogs(ctx, "dice-a", "g"); err != nil || len(logs) != 0 {
		t.Fatalf("deleted intent resurrected archive: %+v %v", logs, err)
	}
}
func TestStoryPrivacyFailureRollsBackEveryTableAndPublication(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t)
	defer db.Close()
	seedStoryPrivacyScope(t, store, "dice-a", "g", "target")
	req := archiveRequest()
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec("CREATE TRIGGER reject_story_privacy BEFORE DELETE ON story_log_imports BEGIN SELECT RAISE(ABORT, 'injected'); END").Error; err != nil {
		t.Fatal(err)
	}
	result, err := store.PrivacyDeleteGroup(ctx, eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if err == nil || result.Deleted != (eventstore.PrivacyCounts{}) {
		t.Fatalf("failed delete claimed counts: %+v %v", result, err)
	}
	after, err := store.PrivacyDryRun(ctx, req)
	if err != nil || string(after.Digest) != string(scan.Digest) || after.Counts != scan.Counts {
		t.Fatalf("rollback changed durable snapshot: before=%+v after=%+v err=%v", scan, after, err)
	}
}
func TestStoryPrivacyRejectsStaleBodyAndCatalogReadAfterRecreation(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t)
	defer db.Close()
	seedStoryPrivacyScope(t, store, "dice-a", "g", "target")
	req := archiveRequest()
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EditStoryLogEntryByRawID(ctx, "dice-a", "g", "target-raw", "edited"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrivacyDeleteGroup(ctx, eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}); !errors.Is(err, eventstore.ErrPrivacyConfirmationMismatch) {
		t.Fatalf("stale body confirmation=%v", err)
	}
	_, read, err := store.GetStoryLogStateSnapshot(ctx, "dice-a", "g")
	if err != nil {
		t.Fatal(err)
	}
	scan, err = store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrivacyDeleteGroup(ctx, eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateStoryLog(ctx, "dice-a", "g", "session"); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, eventstore.UnitOfWork{CatalogReads: []eventstore.CatalogReadExpectation{read}, Operations: []eventstore.OperationUpdate{{OperationID: "stale"}}})
	if !errors.Is(err, eventstore.ErrParticipantConflict) {
		t.Fatalf("old Story read succeeded after same-name recreation: %v", err)
	}
}
