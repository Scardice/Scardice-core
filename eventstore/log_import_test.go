package eventstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestStoryLogImportsAreTypedIdempotentAndVerifiedAfterReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "story-log-import.db")
	source := newTestKeySource()
	store, db := openLogArchiveTestStore(t, path, source)
	emptyExtra := ""
	sessionID := "legacy/data-logs.db/logs/31"
	entryID := "legacy/data-logs.db/log_items/72"
	stateID := "legacy/data.db/groups/group-a/log-state"
	created := StoryLogImportRecord{
		SourceID: sessionID, Kind: StoryLogImportSession, DiceID: "dice-a", GroupID: "group-a",
		Session: &StoryLogSession{ID: 31, DiceID: "dice-a", GroupID: "group-a", Name: "session", CreatedAt: 100, UpdatedAt: 200, UploadURL: "https://example.invalid/log", UploadTime: 300, Extra: &emptyExtra},
	}
	seq := int64(12)
	entry := StoryLogImportRecord{
		SourceID: entryID, Kind: StoryLogImportEntry, DiceID: "dice-a", GroupID: "group-a", SessionSourceID: sessionID,
		Entry: &StoryLogEntry{ID: 72, LogID: 31, DiceID: "dice-a", GroupID: "group-a", LogName: "session", Nickname: "Player", IMUserID: "user-1", Time: 400, Message: "imported message", IsDice: true, CommandID: 9, CommandInfo: []byte(`{"command":"roll"}`), RawMsgID: "raw-1", UniformID: "uniform-1", Seq: &seq},
	}
	state := StoryLogImportRecord{
		SourceID: stateID, Kind: StoryLogImportState, DiceID: "dice-a", GroupID: "group-a", SessionSourceID: sessionID,
		State: &StoryLogState{DiceID: "dice-a", GroupID: "group-a", SessionID: 31, Name: "session", On: true},
	}
	originalDigest, err := store.StoryLogImportSemanticDigest(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.Entry.ID, entry.Entry.LogID = 9001, 9002
	remappedDigest, err := store.StoryLogImportSemanticDigest(ctx, entry)
	if err != nil || string(originalDigest) != string(remappedDigest) {
		t.Fatalf("semantic digest changed with target surrogate IDs: %x, %x, err=%v", originalDigest, remappedDigest, err)
	}
	entry.Entry.ID, entry.Entry.LogID = 72, 31
	if _, err := store.Commit(ctx, UnitOfWork{LogImports: []StoryLogImportRecord{entry, created}}); err != nil {
		t.Fatalf("commit same-batch entry before its session: %v", err)
	}
	receipts, err := store.ImportStoryLogBatch(ctx, []StoryLogImportRecord{entry, state})
	if err != nil || len(receipts) != 2 {
		t.Fatalf("import entries/state receipts=%#v err=%v", receipts, err)
	}
	if _, err := store.ImportStoryLogBatch(ctx, []StoryLogImportRecord{created, entry, state}); err != nil {
		t.Fatalf("idempotent exact import: %v", err)
	}
	changed := entry
	changed.Entry = &StoryLogEntry{DiceID: entry.Entry.DiceID, GroupID: entry.Entry.GroupID, LogName: entry.Entry.LogName, Message: "different semantic content"}
	if _, err := store.ImportStoryLogBatch(ctx, []StoryLogImportRecord{changed}); !errors.Is(err, ErrParticipantFailure) {
		t.Fatalf("same source identity with changed content error=%v, want participant failure", err)
	}
	stored, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(stored) != 1 || stored[0].Message != "imported message" || stored[0].Seq == nil || *stored[0].Seq != 12 {
		t.Fatalf("imported entries=%#v err=%v", stored, err)
	}
	selected, err := store.GetStoryLogState(ctx, "dice-a", "group-a")
	if err != nil || !selected.On || selected.Name != "session" {
		t.Fatalf("imported state=%#v err=%v", selected, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, db = openLogArchiveTestStore(t, path, source)
	defer db.Close()
	manifest, err := store.ListStoryLogImports(ctx, "legacy/", "dice-a")
	if err != nil || len(manifest) != 3 {
		t.Fatalf("reopened import manifest=%#v err=%v", manifest, err)
	}
	byID := make(map[string]StoryLogImportReceipt, len(manifest))
	for _, receipt := range manifest {
		byID[receipt.SourceID] = receipt
	}
	for _, record := range []StoryLogImportRecord{created, entry, state} {
		digest, err := store.StoryLogImportSemanticDigest(ctx, record)
		if err != nil || string(byID[record.SourceID].SemanticDigest) != string(digest) {
			t.Fatalf("reopened digest for %q = %x, want %x, err=%v", record.SourceID, byID[record.SourceID].SemanticDigest, digest, err)
		}
	}
	var session storyLogSessionRow
	if err := db.GORM().Where("scope_hmac = ?", func() []byte { scope, _, _, _ := store.storyLogKeys(ctx, "dice-a", "group-a", ""); return scope }()).First(&session).Error; err != nil {
		t.Fatal(err)
	}
	private, err := store.storyLogSession(ctx, session)
	if err != nil || private.Extra == nil || *private.Extra != "" || private.CreatedAt != 100 || private.UpdatedAt != 200 || private.UploadURL != "https://example.invalid/log" || private.UploadTime != 300 {
		t.Fatalf("imported nullable session metadata=%#v err=%v", private, err)
	}
}

func TestStoryLogImportDigestPreservesNullableExtra(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	record := StoryLogImportRecord{SourceID: "source/log/1", Kind: StoryLogImportSession, DiceID: "dice", GroupID: "group", Session: &StoryLogSession{DiceID: "dice", GroupID: "group", Name: "session"}}
	nilDigest, err := store.StoryLogImportSemanticDigest(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	record.Session.Extra = &empty
	emptyDigest, err := store.StoryLogImportSemanticDigest(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	if string(nilDigest) == string(emptyDigest) {
		t.Fatal("nullable and empty extra produced the same canonical digest")
	}
}

func TestListStoryLogImportsCrossesReadbackBatchBoundary(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	sessionSourceID := "bulk/session"
	session := StoryLogImportRecord{
		SourceID: sessionSourceID, Kind: StoryLogImportSession, DiceID: "dice", GroupID: "group",
		Session: &StoryLogSession{DiceID: "dice", GroupID: "group", Name: "bulk"},
	}
	if _, err := store.Commit(ctx, UnitOfWork{LogImports: []StoryLogImportRecord{session}}); err != nil {
		t.Fatal(err)
	}
	entries := make([]StoryLogImportRecord, MaxUnitOfWorkEvents+1)
	for index := range entries {
		entries[index] = StoryLogImportRecord{
			SourceID: fmt.Sprintf("bulk/entry/%05d", index), Kind: StoryLogImportEntry,
			DiceID: "dice", GroupID: "group", SessionSourceID: sessionSourceID,
			Entry: &StoryLogEntry{DiceID: "dice", GroupID: "group", LogName: "bulk", Message: fmt.Sprintf("entry-%d", index)},
		}
	}
	for start := 0; start < len(entries); start += MaxUnitOfWorkEvents {
		end := min(start+MaxUnitOfWorkEvents, len(entries))
		if _, err := store.Commit(ctx, UnitOfWork{LogImports: entries[start:end]}); err != nil {
			t.Fatal(err)
		}
	}
	receipts, err := store.ListStoryLogImports(ctx, "bulk/", "dice")
	if err != nil || len(receipts) != len(entries)+1 {
		t.Fatalf("receipts=%d err=%v", len(receipts), err)
	}
	seen := make(map[string]StoryLogImportKind, len(receipts))
	for _, receipt := range receipts {
		seen[receipt.SourceID] = receipt.Kind
	}
	if seen[sessionSourceID] != StoryLogImportSession || seen[fmt.Sprintf("bulk/entry/%05d", MaxUnitOfWorkEvents)] != StoryLogImportEntry {
		t.Fatalf("boundary receipts missing: %#v", seen)
	}
}
