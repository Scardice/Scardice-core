package eventstore_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/core/privacypurge"
	"Scardice-core/eventstore"

	"gorm.io/gorm"
)

func openStoryLogPrivacyStore(t *testing.T, path string, initialize bool) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	ctx := context.Background()
	source := fixedExternalKeySource{indexID: "story-log-privacy-index-v1", rootID: "story-log-privacy-root-v1"}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: path, DatabaseIdentity: "story-log-privacy-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if initialize {
		if err := store.SetReadiness(ctx, eventstore.Readiness{
			Mode: "import", SchemaVersion: 1, DatabaseIdentity: "story-log-privacy-test",
			IndexRootID: "story-log-privacy-index-v1", EncryptionRootIDs: []string{"story-log-privacy-root-v1"},
			SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return store, db
}

type seededStoryLogScope struct {
	diceID       string
	groupID      string
	sessionName  string
	rawMessageID string
	effectID     string
	importID     string
}

func seedStoryLogPrivacyScope(t *testing.T, ctx context.Context, store *eventstore.GORMStore, diceID, groupID, prefix string) seededStoryLogScope {
	t.Helper()
	seed := seededStoryLogScope{
		diceID: diceID, groupID: groupID, sessionName: prefix + "-session",
		rawMessageID: prefix + "-inbound", effectID: prefix + "-outbound-effect", importID: prefix + "-import-source",
	}
	session, err := store.CreateStoryLog(ctx, diceID, groupID, seed.sessionName)
	if err != nil {
		t.Fatalf("create %s session: %v", prefix, err)
	}
	if err := store.SetStoryLogState(ctx, eventstore.StoryLogState{
		DiceID: diceID, GroupID: groupID, SessionID: session.ID, Name: seed.sessionName, On: true,
	}); err != nil {
		t.Fatalf("set %s state: %v", prefix, err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: diceID, GroupID: groupID, LogName: seed.sessionName,
		Nickname: "Player", IMUserID: prefix + "-user", Time: 10,
		Message: prefix + " inbound message", RawMsgID: seed.rawMessageID, UniformID: prefix + "-uniform",
	}); err != nil {
		t.Fatalf("append %s inbound entry: %v", prefix, err)
	}
	if err := store.QueueStoryLogIntent(ctx, eventstore.StoryLogIntent{EffectID: seed.effectID, Entry: eventstore.StoryLogEntry{
		DiceID: diceID, GroupID: groupID, LogName: seed.sessionName,
		Nickname: "Dice", Message: prefix + " outbound message", UniformID: prefix + "-outbound-uniform",
	}}); err != nil {
		t.Fatalf("queue %s outbound intent: %v", prefix, err)
	}
	importSession := &eventstore.StoryLogSession{DiceID: diceID, GroupID: groupID, Name: prefix + "-imported-session", CreatedAt: 20, UpdatedAt: 30}
	if _, err := store.ImportStoryLogBatch(ctx, []eventstore.StoryLogImportRecord{{
		SourceID: seed.importID, Kind: eventstore.StoryLogImportSession,
		DiceID: diceID, GroupID: groupID, Session: importSession,
	}}); err != nil {
		t.Fatalf("import %s session metadata: %v", prefix, err)
	}
	return seed
}

func expectedStoryLogPrivacyCounts() eventstore.PrivacyCounts {
	return eventstore.PrivacyCounts{LogSessions: 2, LogStates: 1, LogEntries: 1, LogIntents: 1, LogImports: 1}
}

func storyLogPrivacyCountTotal(counts eventstore.PrivacyCounts) int64 {
	return counts.LogSessions + counts.LogStates + counts.LogEntries + counts.LogIntents + counts.LogImports
}

func storyLogPrivacyCountsForOwner(t *testing.T, db *eventstore.Database, owner []byte) eventstore.PrivacyCounts {
	t.Helper()
	count := func(table string) int64 {
		var result int64
		if err := db.GORM().Table(table).Where("owner_hmac = ?", owner).Count(&result).Error; err != nil {
			t.Fatalf("count %s for owner: %v", table, err)
		}
		return result
	}
	return eventstore.PrivacyCounts{
		LogSessions: count("story_log_sessions"),
		LogStates:   count("story_log_states"),
		LogEntries:  count("story_log_entries"),
		LogIntents:  count("story_log_outbound_intents"),
		LogImports:  count("story_log_imports"),
	}
}

func assertStoryLogPrivacyOwnerCounts(t *testing.T, db *eventstore.Database, owner []byte, want eventstore.PrivacyCounts) {
	t.Helper()
	if got := storyLogPrivacyCountsForOwner(t, db, owner); got != want {
		t.Fatalf("archive rows for owner = %+v, want %+v", got, want)
	}
}

func containsStoryLogPrivacyUncovered(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func startStoryLogPrivacyDelete(t *testing.T, ctx context.Context, store *eventstore.GORMStore, req eventstore.PrivacyDryRunRequest, operationID string) (eventstore.PrivacyDryRunResult, uint64) {
	t.Helper()
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatalf("privacy dry-run: %v", err)
	}
	private := eventstore.PrivacyOperationContext{
		GroupID: req.GroupID, DiceIDs: append([]string(nil), req.DiceIDs...), Scopes: append([]string(nil), req.Scopes...),
		Phase: "fence", Counts: scan.Counts, ConfirmationDigest: append([]byte(nil), scan.Digest...), ConfirmationVersion: scan.Version,
	}
	if err := store.PrivacyCreateOperation(ctx, operationID, scan.SubjectKey, private); err != nil {
		t.Fatalf("create privacy operation: %v", err)
	}
	fenceVersion, err := store.PrivacyFence(ctx, scan.SubjectKey, "group", operationID)
	if err != nil {
		t.Fatalf("fence privacy subject: %v", err)
	}
	view, private, err := store.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		t.Fatalf("load privacy operation: %v", err)
	}
	private.Phase = "delete"
	if _, err := store.PrivacyUpdateOperation(ctx, operationID, view.Version, private, "running"); err != nil {
		t.Fatalf("begin privacy delete phase: %v", err)
	}
	return scan, fenceVersion
}

func runStoryLogPrivacyBatch(t *testing.T, ctx context.Context, store *eventstore.GORMStore, operationID string, groupID string, diceIDs, scopes []string, limit int) eventstore.PrivacyBatchResult {
	t.Helper()
	view, private, err := store.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		t.Fatalf("load operation before batch: %v", err)
	}
	batch, err := store.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{
		OperationID: operationID, GroupID: groupID, Phase: "delete", DiceIDs: diceIDs, Scopes: scopes,
		Cursor: private.Cursor, Limit: limit,
	})
	if err != nil {
		t.Fatalf("delete privacy batch: %v", err)
	}
	private.Cursor, private.Phase = batch.NextCursor, "delete"
	if _, err := store.PrivacyUpdateOperation(ctx, operationID, view.Version, private, "running"); err != nil {
		t.Fatalf("persist privacy batch cursor: %v", err)
	}
	return batch
}

func TestStoryLogPrivacyDryRunHashesOnlyExplicitArchiveScope(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t, filepath.Join(t.TempDir(), "story-log-privacy.db"), true)
	defer db.Close()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	seedStoryLogPrivacyScope(t, ctx, store, "dice-other", "group-target", "other-dice")
	seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-other", "other-group")

	selected, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"logs"},
	})
	if err != nil {
		t.Fatalf("dry-run explicit archive scope: %v", err)
	}
	if selected.Counts != expectedStoryLogPrivacyCounts() {
		t.Fatalf("archive dry-run counts = %+v, want %+v", selected.Counts, expectedStoryLogPrivacyCounts())
	}
	if containsStoryLogPrivacyUncovered(selected.Uncovered, "logs") {
		t.Fatalf("selected archive scope still reported uncovered: %v", selected.Uncovered)
	}

	allDice, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: target.groupID, DiceIDs: []string{target.diceID, "dice-other"}, Scopes: []string{"logs"},
	})
	if err != nil {
		t.Fatalf("dry-run both dice archive scope: %v", err)
	}
	bothDiceWant := expectedStoryLogPrivacyCounts()
	bothDiceWant.LogSessions *= 2
	bothDiceWant.LogStates *= 2
	bothDiceWant.LogEntries *= 2
	bothDiceWant.LogIntents *= 2
	bothDiceWant.LogImports *= 2
	if allDice.Counts != bothDiceWant || string(allDice.Digest) == string(selected.Digest) {
		t.Fatalf("expanded Dice selection counts=%+v digestEqual=%t, want %+v and distinct digest", allDice.Counts, string(allDice.Digest) == string(selected.Digest), bothDiceWant)
	}

	noLogs, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"group_record"},
	})
	if err != nil {
		t.Fatalf("dry-run without archive scope: %v", err)
	}
	if noLogs.Counts.LogSessions+noLogs.Counts.LogStates+noLogs.Counts.LogEntries+noLogs.Counts.LogIntents+noLogs.Counts.LogImports != 0 || !containsStoryLogPrivacyUncovered(noLogs.Uncovered, "logs") {
		t.Fatalf("unselected archive scope counts=%+v uncovered=%v; archive data must remain outside this selection", noLogs.Counts, noLogs.Uncovered)
	}
	defaultScope, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: target.groupID, DiceIDs: []string{target.diceID}})
	if err != nil {
		t.Fatalf("dry-run existing default scope: %v", err)
	}
	if storyLogPrivacyCountTotal(defaultScope.Counts) != 0 || !containsStoryLogPrivacyUncovered(defaultScope.Uncovered, "logs") {
		t.Fatalf("default selection unexpectedly covers archive: counts=%+v uncovered=%v", defaultScope.Counts, defaultScope.Uncovered)
	}

	if err := store.EditStoryLogEntryByRawID(ctx, target.diceID, target.groupID, target.rawMessageID, "edited target message"); err != nil {
		t.Fatalf("edit selected archive entry: %v", err)
	}
	changed, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"logs"},
	})
	if err != nil || changed.Counts != selected.Counts || string(changed.Digest) == string(selected.Digest) {
		t.Fatalf("same-count archive content change did not change confirmation digest: before=%+v after=%+v err=%v", selected.Counts, changed.Counts, err)
	}
}

func TestStoryLogPrivacyRejectsStaleArchiveConfirmation(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t, filepath.Join(t.TempDir(), "story-log-stale.db"), true)
	defer db.Close()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	service := privacypurge.NewService(store)
	request := privacypurge.Request{GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"logs"}, AllowActive: true}
	confirmation, err := service.DryRun(ctx, request)
	if err != nil {
		t.Fatalf("service dry-run: %v", err)
	}
	if err := store.EditStoryLogEntryByRawID(ctx, target.diceID, target.groupID, target.rawMessageID, "changed after confirmation"); err != nil {
		t.Fatalf("change archive after confirmation: %v", err)
	}
	request.ConfirmationDigest = confirmation.ConfirmationDigest
	request.ConfirmationVersion = confirmation.ConfirmationVersion
	result, err := service.Confirm(ctx, request)
	if !errors.Is(err, privacypurge.ErrConfirmationMismatch) || result.Status != "rejected" {
		t.Fatalf("stale archive confirmation result=%+v err=%v, want rejected confirmation mismatch", result, err)
	}
	entries, err := store.GetStoryLogEntries(ctx, target.diceID, target.groupID, target.sessionName)
	if err != nil || len(entries) != 1 || entries[0].Message != "changed after confirmation" {
		t.Fatalf("stale confirmation changed selected archive: entries=%+v err=%v", entries, err)
	}
	subjectKey, err := store.PrivacySubjectKey(ctx, target.groupID)
	if err != nil {
		t.Fatalf("resolve rejected purge subject: %v", err)
	}
	if fenceVersion, err := store.PrivacyFenceVersion(ctx, subjectKey, "group"); err != nil || fenceVersion != 0 {
		t.Fatalf("stale confirmation created a fence: version=%d err=%v", fenceVersion, err)
	}
}
func TestStoryLogPrivacyServiceReportsArchiveCountsAfterConfirm(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t, filepath.Join(t.TempDir(), "story-log-service.db"), true)
	defer db.Close()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	if err := store.RegisterProjection(eventstore.ProjectionDescriptor{
		Name: "story-log-privacy-service-test", Version: "1",
		Apply: func(context.Context, *gorm.DB, []eventstore.Envelope) error { return nil },
	}); err != nil {
		t.Fatalf("register rebuild projector: %v", err)
	}
	service := privacypurge.NewService(store)
	request := privacypurge.Request{GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"group_record", "players", "attrs", "logs"}, AllowActive: true}
	confirmation, err := service.DryRun(ctx, request)
	if err != nil {
		t.Fatalf("service dry-run: %v", err)
	}
	request.ConfirmationDigest = confirmation.ConfirmationDigest
	request.ConfirmationVersion = confirmation.ConfirmationVersion
	result, err := service.Confirm(ctx, request)
	if !errors.Is(err, privacypurge.ErrUncoveredData) || !result.Completed || result.Deleted != expectedStoryLogPrivacyCounts() {
		t.Fatalf("service purge result=%+v err=%v, want completed with exact per-table archive counts", result, err)
	}
	sessions, err := store.ListStoryLogs(ctx, target.diceID, target.groupID)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("service purge left sessions=%+v err=%v", sessions, err)
	}
}

func TestStoryLogPrivacyBatchResumesAndPreservesOtherDiceAndGroups(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "story-log-resume.db")
	store, db := openStoryLogPrivacyStore(t, path, true)
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	otherDice := seedStoryLogPrivacyScope(t, ctx, store, "dice-other", "group-target", "other-dice")
	otherGroup := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-other", "other-group")
	request := eventstore.PrivacyDryRunRequest{GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"logs"}}
	scan, _ := startStoryLogPrivacyDelete(t, ctx, store, request, "story-log-privacy-resume")
	if scan.Counts != expectedStoryLogPrivacyCounts() {
		t.Fatalf("purge confirmation counts=%+v, want %+v", scan.Counts, expectedStoryLogPrivacyCounts())
	}
	if err := store.QueueStoryLogIntent(ctx, eventstore.StoryLogIntent{EffectID: "late-target-effect", Entry: eventstore.StoryLogEntry{
		DiceID: target.diceID, GroupID: target.groupID, LogName: target.sessionName, Message: "must stay blocked",
	}}); err == nil {
		t.Fatal("archive write during subject fence succeeded")
	}
	owner, err := store.PrivacySubjectKey(ctx, target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	wantOwnerRows := expectedStoryLogPrivacyCounts()
	wantOwnerRows.LogSessions *= 2
	wantOwnerRows.LogStates *= 2
	wantOwnerRows.LogEntries *= 2
	wantOwnerRows.LogIntents *= 2
	wantOwnerRows.LogImports *= 2
	assertStoryLogPrivacyOwnerCounts(t, db, owner, wantOwnerRows)
	first := runStoryLogPrivacyBatch(t, ctx, store, "story-log-privacy-resume", target.groupID, request.DiceIDs, request.Scopes, 1)
	if first.Done || storyLogPrivacyCountTotal(first.Deleted) > 1 || first.NextCursor == "" {
		t.Fatalf("first batch=%+v, want bounded nonterminal progress", first)
	}
	_, persisted, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-resume")
	if err != nil || persisted.Cursor != first.NextCursor {
		t.Fatalf("stored archive cursor=%q err=%v, want %q", persisted.Cursor, err, first.NextCursor)
	}
	firstCursor := first.NextCursor
	if err := db.Close(); err != nil {
		t.Fatalf("close database between batches: %v", err)
	}
	db = nil
	store, db = openStoryLogPrivacyStore(t, path, false)
	_, persisted, err = store.PrivacyLoadOperation(ctx, "story-log-privacy-resume")
	if err != nil || persisted.Cursor != firstCursor {
		t.Fatalf("reopened archive cursor=%q err=%v, want %q", persisted.Cursor, err, firstCursor)
	}

	deleted := first.Deleted
	cursor := firstCursor
	for page := range 16 {
		pageNumber := page + 1
		before := cursor
		batch := runStoryLogPrivacyBatch(t, ctx, store, "story-log-privacy-resume", target.groupID, request.DiceIDs, request.Scopes, 1)
		if storyLogPrivacyCountTotal(batch.Deleted) > 1 {
			t.Fatalf("batch %d exceeded one-row bound: %+v", pageNumber, batch.Deleted)
		}
		deleted.LogSessions += batch.Deleted.LogSessions
		deleted.LogStates += batch.Deleted.LogStates
		deleted.LogEntries += batch.Deleted.LogEntries
		deleted.LogIntents += batch.Deleted.LogIntents
		deleted.LogImports += batch.Deleted.LogImports
		_, private, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-resume")
		if err != nil {
			t.Fatalf("load resumed cursor: %v", err)
		}
		cursor = private.Cursor
		if !batch.Done && cursor == before && storyLogPrivacyCountTotal(batch.Deleted) == 0 {
			t.Fatalf("batch %d made no cursor or row progress at %q", pageNumber, cursor)
		}
		if batch.Done {
			break
		}
		if pageNumber == 16 {
			t.Fatalf("archive purge did not finish after bounded pages; cursor=%q", cursor)
		}
	}
	if deleted != expectedStoryLogPrivacyCounts() {
		t.Fatalf("resumable deleted counts=%+v, want %+v", deleted, expectedStoryLogPrivacyCounts())
	}
	targetOwner, err := store.PrivacySubjectKey(ctx, target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	otherGroupOwner, err := store.PrivacySubjectKey(ctx, otherGroup.groupID)
	if err != nil {
		t.Fatal(err)
	}
	assertStoryLogPrivacyOwnerCounts(t, db, targetOwner, expectedStoryLogPrivacyCounts())
	assertStoryLogPrivacyOwnerCounts(t, db, otherGroupOwner, expectedStoryLogPrivacyCounts())

	targetSessions, err := store.ListStoryLogs(ctx, target.diceID, target.groupID)
	if err != nil || len(targetSessions) != 0 {
		t.Fatalf("purged sessions=%+v err=%v", targetSessions, err)
	}
	targetState, err := store.GetStoryLogState(ctx, target.diceID, target.groupID)
	if err != nil || targetState.On || targetState.Name != "" {
		t.Fatalf("purged state=%+v err=%v", targetState, err)
	}
	targetEntries, err := store.GetStoryLogEntries(ctx, target.diceID, target.groupID, target.sessionName)
	if err != nil || len(targetEntries) != 0 {
		t.Fatalf("purged entries=%+v err=%v", targetEntries, err)
	}
	targetImports, err := store.ListStoryLogImports(ctx, target.importID, target.diceID)
	if err != nil || len(targetImports) != 0 {
		t.Fatalf("purged import metadata=%+v err=%v", targetImports, err)
	}
	otherDiceSessions, err := store.ListStoryLogs(ctx, otherDice.diceID, otherDice.groupID)
	if err != nil || len(otherDiceSessions) != 2 {
		t.Fatalf("same-group other-Dice sessions=%+v err=%v", otherDiceSessions, err)
	}
	otherDiceImports, err := store.ListStoryLogImports(ctx, otherDice.importID, otherDice.diceID)
	if err != nil || len(otherDiceImports) != 1 {
		t.Fatalf("same-group other-Dice imports=%+v err=%v", otherDiceImports, err)
	}
	otherGroupSessions, err := store.ListStoryLogs(ctx, otherGroup.diceID, otherGroup.groupID)
	if err != nil || len(otherGroupSessions) != 2 {
		t.Fatalf("other-group sessions=%+v err=%v", otherGroupSessions, err)
	}
	for _, tc := range []struct {
		effectID string
		want     int64
	}{{target.effectID, 0}, {otherDice.effectID, 1}, {otherGroup.effectID, 1}} {
		var count int64
		if err := db.GORM().Table("story_log_outbound_intents").Where("effect_id = ?", tc.effectID).Count(&count).Error; err != nil || count != tc.want {
			t.Fatalf("intent %q count=%d err=%v, want %d", tc.effectID, count, err, tc.want)
		}
	}
	if err := store.CompleteStoryLogIntent(ctx, target.effectID, true); err != nil {
		t.Fatalf("complete purged late intent: %v", err)
	}
	targetEntries, err = store.GetStoryLogEntries(ctx, target.diceID, target.groupID, target.sessionName)
	if err != nil || len(targetEntries) != 0 {
		t.Fatalf("late intent restored purged archive: entries=%+v err=%v", targetEntries, err)
	}
	view, _, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-resume")
	if err != nil {
		t.Fatalf("load completed operation for audit: %v", err)
	}
	if _, err := store.PrivacyFinalizeOperation(ctx, "story-log-privacy-resume", view.Version, "completed-uncovered"); err != nil {
		t.Fatalf("finalize archive purge: %v", err)
	}
	if fenceVersion, err := store.PrivacyFenceVersion(ctx, scan.SubjectKey, "group"); err != nil || fenceVersion != 0 {
		t.Fatalf("finalized subject fence version=%d err=%v, want released", fenceVersion, err)
	}
	var audit struct {
		LogSessions int64 `gorm:"column:log_sessions"`
		LogStates   int64 `gorm:"column:log_states"`
		LogEntries  int64 `gorm:"column:log_entries"`
		LogIntents  int64 `gorm:"column:log_intents"`
		LogImports  int64 `gorm:"column:log_imports"`
	}
	if err := db.GORM().Table("privacy_purge_audit").Select("log_sessions", "log_states", "log_entries", "log_intents", "log_imports").Take(&audit).Error; err != nil {
		t.Fatalf("read privacy audit archive counts: %v", err)
	}
	if audit.LogSessions != 2 || audit.LogStates != 1 || audit.LogEntries != 1 || audit.LogIntents != 1 || audit.LogImports != 1 {
		t.Fatalf("privacy audit archive counts=%+v, want sessions=2 and one of each other row", audit)
	}
}

func TestStoryLogPrivacyBatchRollsBackFailedArchiveRowsAndResumes(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t, filepath.Join(t.TempDir(), "story-log-rollback.db"), true)
	defer db.Close()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	request := eventstore.PrivacyDryRunRequest{GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"logs"}}
	startStoryLogPrivacyDelete(t, ctx, store, request, "story-log-privacy-rollback")
	targetOwner, err := store.PrivacySubjectKey(ctx, target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec(`CREATE TRIGGER reject_story_log_entry_delete BEFORE DELETE ON story_log_entries BEGIN SELECT RAISE(ABORT, 'test rollback'); END`).Error; err != nil {
		t.Fatalf("create delete failure trigger: %v", err)
	}
	var deleted eventstore.PrivacyCounts
	var failedCursor string
	failed := false
	for page := range 8 {
		view, private, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-rollback")
		if err != nil {
			t.Fatalf("load operation before failed batch: %v", err)
		}
		failedCursor = private.Cursor
		batch, err := store.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{
			OperationID: "story-log-privacy-rollback", GroupID: target.groupID, Phase: "delete",
			DiceIDs: request.DiceIDs, Scopes: request.Scopes, Cursor: private.Cursor, Limit: eventstore.PrivacyBatchRecords,
		})
		if err != nil {
			if !errors.Is(err, eventstore.ErrParticipantFailure) {
				t.Fatalf("triggered archive delete error=%v, want ErrParticipantFailure", err)
			}
			failed = true
			break
		}
		deleted.LogSessions += batch.Deleted.LogSessions
		deleted.LogStates += batch.Deleted.LogStates
		deleted.LogEntries += batch.Deleted.LogEntries
		deleted.LogIntents += batch.Deleted.LogIntents
		deleted.LogImports += batch.Deleted.LogImports
		private.Cursor, private.Phase = batch.NextCursor, "delete"
		if _, err := store.PrivacyUpdateOperation(ctx, "story-log-privacy-rollback", view.Version, private, "running"); err != nil {
			t.Fatalf("persist operation before failed batch: %v", err)
		}
		if batch.Done {
			t.Fatal("delete failure trigger was not reached")
		}
		if page == 7 {
			t.Fatal("delete failure trigger was not reached within bounded pages")
		}
	}
	if !failed {
		t.Fatal("expected a failed archive delete batch")
	}
	_, private, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-rollback")
	if err != nil || private.Cursor != failedCursor {
		t.Fatalf("failed batch advanced operation cursor to %q err=%v, want %q", private.Cursor, err, failedCursor)
	}
	remaining := storyLogPrivacyCountsForOwner(t, db, targetOwner)
	if remaining.LogEntries != 1 {
		t.Fatalf("failed batch removed the rejected entry: remaining=%+v", remaining)
	}
	if err := db.GORM().Exec("DROP TRIGGER reject_story_log_entry_delete").Error; err != nil {
		t.Fatalf("drop delete failure trigger: %v", err)
	}
	for page := range 8 {
		batch := runStoryLogPrivacyBatch(t, ctx, store, "story-log-privacy-rollback", target.groupID, request.DiceIDs, request.Scopes, eventstore.PrivacyBatchRecords)
		deleted.LogSessions += batch.Deleted.LogSessions
		deleted.LogStates += batch.Deleted.LogStates
		deleted.LogEntries += batch.Deleted.LogEntries
		deleted.LogIntents += batch.Deleted.LogIntents
		deleted.LogImports += batch.Deleted.LogImports
		if batch.Done {
			break
		}
		if page == 7 {
			t.Fatal("archive purge did not resume after the failed batch")
		}
	}
	if deleted != expectedStoryLogPrivacyCounts() {
		t.Fatalf("deleted before and after rollback=%+v, want %+v", deleted, expectedStoryLogPrivacyCounts())
	}
	assertStoryLogPrivacyOwnerCounts(t, db, targetOwner, eventstore.PrivacyCounts{})
}
func TestStoryLogPrivacyUnselectedScopeRetainsArchiveRows(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t, filepath.Join(t.TempDir(), "story-log-unselected.db"), true)
	defer db.Close()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	request := eventstore.PrivacyDryRunRequest{GroupID: target.groupID, DiceIDs: []string{target.diceID}}
	scan, err := store.PrivacyDryRun(ctx, request)
	if err != nil {
		t.Fatalf("default-scope dry-run: %v", err)
	}
	if storyLogPrivacyCountTotal(scan.Counts) != 0 || !containsStoryLogPrivacyUncovered(scan.Uncovered, "logs") {
		t.Fatalf("default request included unselected archive: counts=%+v uncovered=%v", scan.Counts, scan.Uncovered)
	}
	request.Scopes = []string{"group_record"}
	_, fenceVersion := startStoryLogPrivacyDelete(t, ctx, store, request, "story-log-privacy-unselected")
	batch, err := store.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{
		OperationID: "story-log-privacy-unselected", GroupID: target.groupID, Phase: "delete",
		DiceIDs: request.DiceIDs, Scopes: request.Scopes, Limit: eventstore.PrivacyBatchRecords,
	})
	if err != nil || !batch.Done || storyLogPrivacyCountTotal(batch.Deleted) != 0 {
		t.Fatalf("group-only batch=%+v err=%v, want no archive deletion", batch, err)
	}
	owner, err := store.PrivacySubjectKey(ctx, target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	assertStoryLogPrivacyOwnerCounts(t, db, owner, expectedStoryLogPrivacyCounts())
	if err := store.PrivacyUnfence(ctx, scan.SubjectKey, "group", fenceVersion, "story-log-privacy-unselected"); err != nil {
		t.Fatalf("release subject fence: %v", err)
	}
}

func TestStoryLogPrivacySubjectFencingDoesNotChangeEventTombstoneBehavior(t *testing.T) {
	ctx := context.Background()
	store, db := openStoryLogPrivacyStore(t, filepath.Join(t.TempDir(), "story-log-domain-events.db"), true)
	defer db.Close()
	target := seedStoryLogPrivacyScope(t, ctx, store, "dice-target", "group-target", "target")
	stream := eventstore.StreamID{AggregateType: "group", AggregateID: "11:dice-target12:group-target"}
	if _, err := store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
		Stream: stream, Events: []eventstore.NewEvent{{EventType: "privacy-test", SchemaVersion: 1, Payload: []byte(`{"ok":true}`), Metadata: eventstore.Metadata{
			EventID: "target-group-event", CommandID: "target-group-command", CorrelationID: "target-group-correlation", Producer: "privacy-test", OccurredAt: time.Unix(1, 0).UTC(),
		}}}},
	}}); err != nil {
		t.Fatalf("append domain event: %v", err)
	}
	descriptor := eventstore.ProjectionDescriptor{Name: "story-log-privacy-test", Version: "1", Apply: func(context.Context, *gorm.DB, []eventstore.Envelope) error { return nil }}
	if err := store.RegisterProjection(descriptor); err != nil {
		t.Fatalf("register rebuild projector: %v", err)
	}
	request := eventstore.PrivacyDryRunRequest{GroupID: target.groupID, DiceIDs: []string{target.diceID}, Scopes: []string{"group_record", "logs"}}
	scan, fenceVersion := startStoryLogPrivacyDelete(t, ctx, store, request, "story-log-privacy-domain")
	if scan.Counts.GroupRecord != 1 || scan.Counts.LogSessions != 2 || scan.Counts.LogStates != 1 || scan.Counts.LogEntries != 1 || scan.Counts.LogIntents != 1 || scan.Counts.LogImports != 1 {
		t.Fatalf("combined event/archive dry-run counts=%+v", scan.Counts)
	}
	var revisionBefore uint64
	if err := db.GORM().Table("projection_control").Select("history_revision").Where("singleton_id = ?", "default").Scan(&revisionBefore).Error; err != nil {
		t.Fatalf("read history revision before purge: %v", err)
	}
	for page := range 16 {
		batch := runStoryLogPrivacyBatch(t, ctx, store, "story-log-privacy-domain", target.groupID, request.DiceIDs, request.Scopes, 1)
		if batch.Done {
			break
		}
		if page == 15 {
			t.Fatal("combined domain/archive purge did not finish")
		}
	}
	var tombstones int64
	if err := db.GORM().Table("event_tombstones").Where("global_position = ?", 1).Count(&tombstones).Error; err != nil || tombstones != 1 {
		t.Fatalf("domain event tombstone count=%d err=%v, want 1", tombstones, err)
	}
	var revisionAfter uint64
	if err := db.GORM().Table("projection_control").Select("history_revision").Where("singleton_id = ?", "default").Scan(&revisionAfter).Error; err != nil || revisionAfter != revisionBefore+1 {
		t.Fatalf("history revision before=%d after=%d err=%v, want one increment", revisionBefore, revisionAfter, err)
	}
	if err := store.PrivacyRebuildPublish(ctx, scan.TargetHighWater); err != nil {
		t.Fatalf("rebuild projection after combined purge: %v", err)
	}
	if _, err := store.Load(ctx, stream, 0); err != nil {
		t.Fatalf("load purged event history marker: %v", err)
	}
	var remainingEvents int64
	if err := db.GORM().Table("domain_events").Where("event_id = ?", "target-group-event").Count(&remainingEvents).Error; err != nil || remainingEvents != 0 {
		t.Fatalf("purged domain event count=%d err=%v, want 0 with tombstone retained", remainingEvents, err)
	}
	if err := store.PrivacyUnfence(ctx, scan.SubjectKey, "group", fenceVersion, "story-log-privacy-domain"); err != nil {
		t.Fatalf("release subject fence: %v", err)
	}
}

type storyLogPrivacyPayloadCapture struct {
	mu    sync.Mutex
	pages []storyLogPrivacyPayloadPage
}

type storyLogPrivacyPayloadPage struct {
	bytes int64
}

func (c *storyLogPrivacyPayloadCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pages = nil
}

func (c *storyLogPrivacyPayloadCapture) snapshot() []storyLogPrivacyPayloadPage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]storyLogPrivacyPayloadPage(nil), c.pages...)
}

func (c *storyLogPrivacyPayloadCapture) append(page storyLogPrivacyPayloadPage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pages = append(c.pages, page)
}

func observeStoryLogPrivacyPayloads(destination any) (storyLogPrivacyPayloadPage, bool) {
	value := reflect.ValueOf(destination)
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return storyLogPrivacyPayloadPage{}, false
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return storyLogPrivacyPayloadPage{}, false
	}
	if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
		return storyLogPrivacyPayloadPage{bytes: int64(value.Len())}, true
	}
	rowType := value.Type()
	if value.Kind() == reflect.Slice {
		rowType = rowType.Elem()
	}
	for rowType.Kind() == reflect.Pointer || rowType.Kind() == reflect.Interface {
		rowType = rowType.Elem()
	}
	if rowType.Kind() != reflect.Struct {
		return storyLogPrivacyPayloadPage{}, false
	}
	fieldType, ok := rowType.FieldByName("Payload")
	if !ok || fieldType.Type.Kind() != reflect.Slice || fieldType.Type.Elem().Kind() != reflect.Uint8 {
		return storyLogPrivacyPayloadPage{}, false
	}
	page := storyLogPrivacyPayloadPage{}
	if value.Kind() == reflect.Slice {
		for i := range value.Len() {
			row := value.Index(i)
			for row.IsValid() && (row.Kind() == reflect.Pointer || row.Kind() == reflect.Interface) {
				if row.IsNil() {
					break
				}
				row = row.Elem()
			}
			if !row.IsValid() || row.Kind() != reflect.Struct {
				return storyLogPrivacyPayloadPage{}, false
			}
			page.bytes += int64(row.FieldByName("Payload").Len())
		}
	} else {
		page.bytes = int64(value.FieldByName("Payload").Len())
	}
	return page, true
}

func registerStoryLogPrivacyPayloadObserver(db *gorm.DB, capture *storyLogPrivacyPayloadCapture) error {
	return db.Callback().Query().After("gorm:query").Register("story-log-privacy-materialized-payloads", func(queryDB *gorm.DB) {
		if page, ok := observeStoryLogPrivacyPayloads(queryDB.Statement.Dest); ok {
			capture.append(page)
		}
	})
}

func assertStoryLogPrivacyPayloadBudget(t *testing.T, capture *storyLogPrivacyPayloadCapture, wantBytes int64, phase string) {
	t.Helper()
	var materializedBytes int64
	for _, page := range capture.snapshot() {
		if page.bytes > int64(eventstore.PrivacyBatchBytes) {
			t.Fatalf("%s materialized %d payload bytes in one result, exceeding %d", phase, page.bytes, eventstore.PrivacyBatchBytes)
		}
		materializedBytes += page.bytes
	}
	if materializedBytes != wantBytes {
		t.Fatalf("%s materialized %d payload bytes, want %d", phase, materializedBytes, wantBytes)
	}
}

func addStoryLogPrivacyCounts(dst *eventstore.PrivacyCounts, src eventstore.PrivacyCounts) {
	dst.LogSessions += src.LogSessions
	dst.LogStates += src.LogStates
	dst.LogEntries += src.LogEntries
	dst.LogIntents += src.LogIntents
	dst.LogImports += src.LogImports
}

func TestStoryLogPrivacyBoundsMaterializedPayloadBytesAcrossResume(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "story-log-byte-bound.db")
	store, db := openStoryLogPrivacyStore(t, path, true)
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	const diceID, groupID, sessionName = "dice-byte", "group-byte", "large-session"
	session, err := store.CreateStoryLog(ctx, diceID, groupID, sessionName)
	if err != nil {
		t.Fatalf("create target session: %v", err)
	}
	const smallMessageBytes = 3 * 1024 * 1024
	smallMessage := strings.Repeat("x", smallMessageBytes)
	for i := range 4 {
		if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
			DiceID: diceID, GroupID: groupID, LogName: sessionName, Time: int64(i + 1), Message: smallMessage,
		}); err != nil {
			t.Fatalf("append bounded target entry %d: %v", i, err)
		}
	}
	oversizeMessage := strings.Repeat("y", 9*1024*1024)
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: diceID, GroupID: groupID, LogName: sessionName, Time: 5, Message: oversizeMessage,
	}); err != nil {
		t.Fatalf("append valid single over-budget target entry: %v", err)
	}
	otherDiceSession, err := store.CreateStoryLog(ctx, "dice-byte-other", groupID, "other-dice-session")
	if err != nil {
		t.Fatalf("create same-group other-Dice session: %v", err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: "dice-byte-other", GroupID: groupID, LogName: otherDiceSession.Name, Message: "preserve other Dice",
	}); err != nil {
		t.Fatalf("append same-group other-Dice entry: %v", err)
	}
	otherGroupSession, err := store.CreateStoryLog(ctx, diceID, "group-byte-other", "other-group-session")
	if err != nil {
		t.Fatalf("create other-group session: %v", err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{
		DiceID: diceID, GroupID: "group-byte-other", LogName: otherGroupSession.Name, Message: "preserve other group",
	}); err != nil {
		t.Fatalf("append other-group entry: %v", err)
	}
	var stored struct {
		Rows       int64 `gorm:"column:rows"`
		MaxBytes   int64 `gorm:"column:max_bytes"`
		TotalBytes int64 `gorm:"column:total_bytes"`
	}
	if err := db.GORM().Table("story_log_entries").Where("session_id = ?", session.ID).Select("count(*) AS rows, max(length(payload)) AS max_bytes, sum(length(payload)) AS total_bytes").Scan(&stored).Error; err != nil {
		t.Fatalf("measure target encrypted entries: %v", err)
	}
	if stored.Rows != 5 || stored.MaxBytes <= int64(eventstore.PrivacyBatchBytes) || stored.TotalBytes <= int64(eventstore.PrivacyBatchBytes) {
		t.Fatalf("fixture must contain multiple rows and one valid payload over the batch budget: rows=%d largest=%d total=%d bound=%d", stored.Rows, stored.MaxBytes, stored.TotalBytes, eventstore.PrivacyBatchBytes)
	}
	var sessionPayloadBytes int64
	if err := db.GORM().Table("story_log_sessions").Where("id = ?", session.ID).Select("length(payload)").Scan(&sessionPayloadBytes).Error; err != nil {
		t.Fatalf("measure target session payload: %v", err)
	}
	wantMaterializedBytes := stored.TotalBytes + sessionPayloadBytes

	capture := &storyLogPrivacyPayloadCapture{}
	if err := registerStoryLogPrivacyPayloadObserver(db.GORM(), capture); err != nil {
		t.Fatalf("register materialized payload observer: %v", err)
	}
	request := eventstore.PrivacyDryRunRequest{GroupID: groupID, DiceIDs: []string{diceID}, Scopes: []string{"logs"}}
	scan, err := store.PrivacyDryRun(ctx, request)
	if err != nil {
		t.Fatalf("byte-bounded archive dry-run: %v", err)
	}
	wantCounts := eventstore.PrivacyCounts{LogSessions: 1, LogEntries: 5}
	if scan.Counts != wantCounts || len(scan.Digest) == 0 {
		t.Fatalf("dry-run counts=%+v digest=%x, want %+v and confirmation digest", scan.Counts, scan.Digest, wantCounts)
	}
	assertStoryLogPrivacyPayloadBudget(t, capture, wantMaterializedBytes, "dry-run")

	started, _ := startStoryLogPrivacyDelete(t, ctx, store, request, "story-log-privacy-byte-bound")
	if started.Counts != scan.Counts || string(started.Digest) != string(scan.Digest) {
		t.Fatalf("fenced operation confirmation differs from initial dry-run: first=%+v resumed=%+v", scan.Counts, started.Counts)
	}
	capture.reset()
	first := runStoryLogPrivacyBatch(t, ctx, store, "story-log-privacy-byte-bound", groupID, request.DiceIDs, request.Scopes, eventstore.PrivacyBatchRecords)
	if first.Done || first.NextCursor == "" {
		t.Fatalf("first archive batch did not commit resumable progress: %+v", first)
	}
	deleted := first.Deleted
	assertStoryLogPrivacyPayloadBudget(t, capture, 0, "first delete batch")
	_, persisted, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-byte-bound")
	if err != nil || persisted.Cursor != first.NextCursor {
		t.Fatalf("first committed cursor=%q err=%v, want %q", persisted.Cursor, err, first.NextCursor)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close database between committed batches: %v", err)
	}
	db = nil
	store, db = openStoryLogPrivacyStore(t, path, false)
	capture.reset()
	if err := registerStoryLogPrivacyPayloadObserver(db.GORM(), capture); err != nil {
		t.Fatalf("register resumed materialized payload observer: %v", err)
	}
	_, persisted, err = store.PrivacyLoadOperation(ctx, "story-log-privacy-byte-bound")
	if err != nil || persisted.Cursor != first.NextCursor {
		t.Fatalf("reopened operation cursor=%q err=%v, want %q", persisted.Cursor, err, first.NextCursor)
	}
	cursor := first.NextCursor
	done := false
	for page := range 32 {
		before := cursor
		batch := runStoryLogPrivacyBatch(t, ctx, store, "story-log-privacy-byte-bound", groupID, request.DiceIDs, request.Scopes, eventstore.PrivacyBatchRecords)
		addStoryLogPrivacyCounts(&deleted, batch.Deleted)
		_, resumed, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-byte-bound")
		if err != nil {
			t.Fatalf("load resumed archive cursor: %v", err)
		}
		cursor = resumed.Cursor
		if !batch.Done && cursor == before && storyLogPrivacyCountTotal(batch.Deleted) == 0 {
			t.Fatalf("resume made no cursor or delete progress at %q", cursor)
		}
		if batch.Done {
			done = true
			break
		}
		if page == 31 {
			t.Fatal("archive purge did not complete after database reopen")
		}
	}
	if !done || deleted != wantCounts {
		t.Fatalf("resumed purge done=%t deleted=%+v, want %+v", done, deleted, wantCounts)
	}
	assertStoryLogPrivacyPayloadBudget(t, capture, 0, "resumed delete")

	targetSessions, err := store.ListStoryLogs(ctx, diceID, groupID)
	if err != nil || len(targetSessions) != 0 {
		t.Fatalf("target sessions after purge=%+v err=%v", targetSessions, err)
	}
	targetEntries, err := store.GetStoryLogEntries(ctx, diceID, groupID, sessionName)
	if err != nil || len(targetEntries) != 0 {
		t.Fatalf("target entries after purge=%d err=%v", len(targetEntries), err)
	}
	otherDiceSessions, err := store.ListStoryLogs(ctx, "dice-byte-other", groupID)
	if err != nil || len(otherDiceSessions) != 1 {
		t.Fatalf("same-group other-Dice sessions=%+v err=%v", otherDiceSessions, err)
	}
	otherDiceEntries, err := store.GetStoryLogEntries(ctx, "dice-byte-other", groupID, otherDiceSession.Name)
	if err != nil || len(otherDiceEntries) != 1 || otherDiceEntries[0].Message != "preserve other Dice" {
		t.Fatalf("same-group other-Dice entries=%+v err=%v", otherDiceEntries, err)
	}
	otherGroupSessions, err := store.ListStoryLogs(ctx, diceID, "group-byte-other")
	if err != nil || len(otherGroupSessions) != 1 {
		t.Fatalf("other-group sessions=%+v err=%v", otherGroupSessions, err)
	}
	otherGroupEntries, err := store.GetStoryLogEntries(ctx, diceID, "group-byte-other", otherGroupSession.Name)
	if err != nil || len(otherGroupEntries) != 1 || otherGroupEntries[0].Message != "preserve other group" {
		t.Fatalf("other-group entries=%+v err=%v", otherGroupEntries, err)
	}
	view, _, err := store.PrivacyLoadOperation(ctx, "story-log-privacy-byte-bound")
	if err != nil {
		t.Fatalf("load completed operation for finalization: %v", err)
	}
	if _, err := store.PrivacyFinalizeOperation(ctx, "story-log-privacy-byte-bound", view.Version, "completed-uncovered"); err != nil {
		t.Fatalf("finalize resumed byte-bound purge: %v", err)
	}
	if got, err := store.PrivacyFenceVersion(ctx, scan.SubjectKey, "group"); err != nil || got != 0 {
		t.Fatalf("finalized fence version=%d err=%v, want released", got, err)
	}
}
