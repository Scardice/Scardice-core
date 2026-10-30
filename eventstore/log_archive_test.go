package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func openLogArchiveTestStore(t *testing.T, path string, source *MemoryKeySource) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source, DatabaseIdentity: "log-archive-test"})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, WithKeySource(source))
	if err := store.SetReadiness(context.Background(), Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "log-archive-test", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return store, db
}

func TestStoryLogArchivePersistsEncryptedAndIsolatesScope(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	source := newTestKeySource()
	store, db := openLogArchiveTestStore(t, path, source)
	first, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateStoryLog(ctx, "dice-b", "group-a", "session"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateStoryLog(ctx, "dice-a", "group-b", "session"); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{
		DiceID: "dice-a", GroupID: "group-a", LogName: "session", Nickname: "Alice", IMUserID: "user-private",
		Time: 100, Message: "private message body", RawMsgID: "platform-message-id", UniformID: "uniform-private",
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 || entries[0].Message != "private message body" {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
	other, err := store.GetStoryLogEntries(ctx, "dice-b", "group-a", "session")
	if err != nil || len(other) != 0 {
		t.Fatalf("other dice entries=%#v err=%v", other, err)
	}
	var rows []logArchiveEntryRow
	if err := db.GORM().Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || string(rows[0].Payload) == "" {
		t.Fatalf("stored rows=%#v", rows)
	}
	for _, secret := range []string{"dice-a", "group-a", "Alice", "user-private", "private message body", "platform-message-id", "uniform-private"} {
		if containsBytes(rows[0].Payload, []byte(secret)) {
			t.Fatalf("plaintext %q leaked into archive payload", secret)
		}
	}
	if len(rows[0].ScopeHMAC) == 0 || len(rows[0].OwnerHMAC) == 0 || len(rows[0].Nonce) == 0 {
		t.Fatalf("incomplete protected row=%#v", rows[0])
	}
	state := StoryLogState{DiceID: "dice-a", GroupID: "group-a", SessionID: first.ID, Name: "session", On: true}
	if err := store.SetStoryLogState(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, db = openLogArchiveTestStore(t, path, source)
	defer db.Close()
	state, err = store.GetStoryLogState(ctx, "dice-a", "group-a")
	if err != nil || !state.On || state.Name != "session" {
		t.Fatalf("reopened state=%#v err=%v", state, err)
	}
	entries, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 || entries[0].Message != "private message body" {
		t.Fatalf("reopened entries=%#v err=%v", entries, err)
	}
	if err := store.DeleteStoryLogEntryByRawID(ctx, "dice-a", "group-a", "platform-message-id"); err != nil {
		t.Fatal(err)
	}
	entries, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries after deletion=%#v err=%v", entries, err)
	}
}

func TestStoryLogArchiveRequiresEncryptionKey(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := NewStore(db).CreateStoryLog(context.Background(), "dice", "group", "session"); !errors.Is(err, ErrKeySourceUnavailable) {
		t.Fatalf("CreateStoryLog() err=%v, want key source unavailable", err)
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
func TestStoryLogIntentQueuesAndFinalizesAtomically(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "session"); err != nil {
		t.Fatal(err)
	}
	intent := StoryLogIntent{EffectID: "effect-success", Entry: StoryLogEntry{
		DiceID: "dice-a", GroupID: "group-a", LogName: "session",
		Nickname: "Dice", Message: "reply", RawMsgID: "reply-id",
	}}
	if err := store.QueueStoryLogIntent(ctx, intent); err != nil {
		t.Fatalf("QueueStoryLogIntent() error = %v", err)
	}
	var queued int64
	if err := db.GORM().Model(&logArchiveIntentRow{}).Count(&queued).Error; err != nil || queued != 1 {
		t.Fatalf("queued intents = %d, err = %v", queued, err)
	}
	if err := store.CompleteStoryLogIntent(ctx, intent.EffectID, true); err != nil {
		t.Fatalf("successful completion error = %v", err)
	}
	entries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 || entries[0].Message != "reply" {
		t.Fatalf("entries after success = %#v, err = %v", entries, err)
	}
	if err := store.QueueStoryLogIntent(ctx, StoryLogIntent{EffectID: "effect-failure", Entry: StoryLogEntry{
		DiceID: "dice-a", GroupID: "group-a", LogName: "session",
		Nickname: "Dice", Message: "failed reply", RawMsgID: "failed-id",
	}}); err != nil {
		t.Fatalf("QueueStoryLogIntent(failure) error = %v", err)
	}
	if err := store.CompleteStoryLogIntent(ctx, "effect-failure", false); err != nil {
		t.Fatalf("failed completion error = %v", err)
	}
	entries, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries after failed effect = %#v, err = %v", entries, err)
	}
	if err := db.GORM().Model(&logArchiveIntentRow{}).Count(&queued).Error; err != nil || queued != 0 {
		t.Fatalf("intents after terminal outcomes = %d, err = %v", queued, err)
	}
	subject, err := store.PrivacySubjectKey(ctx, "group-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PrivacyCreateOperation(ctx, "purge", subject, PrivacyOperationContext{GroupID: "group-a"}); err != nil {
		t.Fatal(err)
	}
	version, err := store.PrivacyFence(ctx, subject, privacyFenceScope, "purge")
	if err != nil {
		t.Fatal(err)
	}
	err = store.QueueStoryLogIntent(ctx, StoryLogIntent{EffectID: "effect-fenced", Entry: StoryLogEntry{
		DiceID: "dice-a", GroupID: "group-a", LogName: "session", Message: "must not queue",
	}})
	if !errors.Is(err, ErrParticipantFailure) {
		t.Fatalf("QueueStoryLogIntent() under purge fence error = %v, want participant failure", err)
	}
	if err := db.GORM().Model(&logArchiveIntentRow{}).Count(&queued).Error; err != nil || queued != 0 {
		t.Fatalf("queued intents after fenced attempt = %d, err = %v", queued, err)
	}
	if err := store.PrivacyUnfence(ctx, subject, privacyFenceScope, version, "purge"); err != nil {
		t.Fatal(err)
	}
}
func TestStoryLogRawIDMutationTargetsLatestSessionMatch(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	for _, name := range []string{"earlier", "latest"} {
		if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", name); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{
			DiceID: "dice-a", GroupID: "group-a", LogName: name, RawMsgID: "shared-message",
			Time: 100, Message: name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []struct {
		diceID, groupID, name string
	}{
		{diceID: "dice-a", groupID: "group-b", name: "other-group"},
		{diceID: "dice-b", groupID: "group-a", name: "other-dice"},
	} {
		if _, err := store.CreateStoryLog(ctx, scope.diceID, scope.groupID, scope.name); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{
			DiceID: scope.diceID, GroupID: scope.groupID, LogName: scope.name,
			RawMsgID: "shared-message", Time: 100, Message: "outside-scope",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.EditStoryLogEntryByRawID(ctx, "dice-a", "group-a", "shared-message", "edited-latest"); err != nil {
		t.Fatal(err)
	}
	earlier, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "earlier")
	if err != nil || len(earlier) != 1 || earlier[0].Message != "earlier" {
		t.Fatalf("earlier entries after edit=%#v err=%v", earlier, err)
	}
	latest, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "latest")
	if err != nil || len(latest) != 1 || latest[0].Message != "edited-latest" {
		t.Fatalf("latest entries after edit=%#v err=%v", latest, err)
	}
	if err := store.DeleteStoryLogEntryByRawID(ctx, "dice-a", "group-a", "shared-message"); err != nil {
		t.Fatal(err)
	}
	earlier, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "earlier")
	if err != nil || len(earlier) != 1 {
		t.Fatalf("earlier entries after delete=%#v err=%v", earlier, err)
	}
	latest, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "latest")
	if err != nil || len(latest) != 0 {
		t.Fatalf("latest entries after delete=%#v err=%v", latest, err)
	}
	for _, scope := range []struct {
		diceID, groupID, name string
	}{
		{diceID: "dice-a", groupID: "group-b", name: "other-group"},
		{diceID: "dice-b", groupID: "group-a", name: "other-dice"},
	} {
		entries, err := store.GetStoryLogEntries(ctx, scope.diceID, scope.groupID, scope.name)
		if err != nil || len(entries) != 1 || entries[0].Message != "outside-scope" {
			t.Fatalf("out-of-scope entries after raw-ID mutation=%#v err=%v", entries, err)
		}
	}
}

func TestStoryLogRawIDDeletePreservesOlderHistoricalMatch(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	for _, name := range []string{"earlier", "latest"} {
		if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", name); err != nil {
			t.Fatal(err)
		}
		if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{
			DiceID: "dice-a", GroupID: "group-a", LogName: name, RawMsgID: "shared-recall",
			Time: 100, Message: name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteStoryLogEntryByRawID(ctx, "dice-a", "group-a", "shared-recall"); err != nil {
		t.Fatal(err)
	}
	earlier, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "earlier")
	if err != nil || len(earlier) != 1 {
		t.Fatalf("older historical match after recall=%#v err=%v", earlier, err)
	}
	latest, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "latest")
	if err != nil || len(latest) != 0 {
		t.Fatalf("latest match after recall=%#v err=%v", latest, err)
	}
}
func TestDeletingHistoricalStoryLogPreservesSelectedSession(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	current, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "current")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "other"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetStoryLogState(ctx, StoryLogState{
		DiceID: "dice-a", GroupID: "group-a", SessionID: current.ID, Name: "current", On: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteStoryLog(ctx, "dice-a", "group-a", "other"); err != nil {
		t.Fatal(err)
	}
	state, err := store.GetStoryLogState(ctx, "dice-a", "group-a")
	if err != nil || state.SessionID != current.ID || state.Name != "current" || !state.On {
		t.Fatalf("state after deleting history = %#v, err = %v", state, err)
	}
	if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{
		DiceID: "dice-a", GroupID: "group-a", LogName: state.Name, Message: "still recording",
	}); err != nil {
		t.Fatalf("append to current session after deleting history: %v", err)
	}
	entries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "current")
	if err != nil || len(entries) != 1 {
		t.Fatalf("current entries=%#v err=%v", entries, err)
	}
	if err := store.DeleteStoryLog(ctx, "dice-a", "group-a", "current"); err != nil {
		t.Fatal(err)
	}
	state, err = store.GetStoryLogState(ctx, "dice-a", "group-a")
	if err != nil || state.SessionID != 0 || state.Name != "" || state.On {
		t.Fatalf("state after deleting selected session = %#v, err = %v", state, err)
	}
}

func TestDeletingStoryLogDiscardsOnlyItsPendingArchiveIntents(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(900, 0).UTC()}
	ids := &outboxRecoveryIDs{}
	source := newTestKeySource()
	store, db := openOutboxRecoveryStore(t, filepath.Join(t.TempDir(), "delete-log-intents.db"), source, clock, ids, true)
	defer db.Close()

	deleted, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "deleted")
	if err != nil {
		t.Fatal(err)
	}
	kept, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "kept")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStoryLogState(ctx, StoryLogState{
		DiceID: "dice-a", GroupID: "group-a", SessionID: deleted.ID, Name: deleted.Name, On: true,
	}); err != nil {
		t.Fatal(err)
	}
	seedIntent := func(effectID, name, message string) {
		t.Helper()
		effect := newOutboxRecoveryEffect(t, source, clock, effectID, "lane-story-log-delete", RiskProviderIdempotent)
		seedOutboxRecoveryEffect(t, store, effect, "operation-"+effectID, "event-"+effectID, clock.Now())
		if err := store.QueueStoryLogIntent(ctx, StoryLogIntent{EffectID: effectID, Entry: StoryLogEntry{
			DiceID: "dice-a", GroupID: "group-a", LogName: name, Message: message,
		}}); err != nil {
			t.Fatalf("QueueStoryLogIntent(%s): %v", effectID, err)
		}
	}
	seedIntent("deleted-success", deleted.Name, "must not return after delete")
	seedIntent("deleted-failure", deleted.Name, "failed reply")
	seedIntent("kept-success", kept.Name, "kept reply")

	if err := store.DeleteStoryLog(ctx, "dice-a", "group-a", deleted.Name); err != nil {
		t.Fatal(err)
	}
	var targetedIntents, keptIntents int64
	if err := db.GORM().Model(&logArchiveIntentRow{}).Where("effect_id IN ?", []string{"deleted-success", "deleted-failure"}).Count(&targetedIntents).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&logArchiveIntentRow{}).Where("effect_id = ?", "kept-success").Count(&keptIntents).Error; err != nil {
		t.Fatal(err)
	}
	if targetedIntents != 0 || keptIntents != 1 {
		t.Fatalf("pending intents after delete: targeted=%d kept=%d, want 0 and 1", targetedIntents, keptIntents)
	}
	var pendingOutbox int64
	if err := db.GORM().Table("outbox_effects").Where("effect_id IN ? AND status = ?", []string{"deleted-success", "deleted-failure"}, OutboxStatusPending).Count(&pendingOutbox).Error; err != nil {
		t.Fatal(err)
	}
	if pendingOutbox != 2 {
		t.Fatalf("deleting log canceled %d provider effects, want both still pending", 2-pendingOutbox)
	}
	state, err := store.GetStoryLogState(ctx, "dice-a", "group-a")
	if err != nil || state.SessionID != 0 || state.On || state.Name != "" {
		t.Fatalf("state after deleting selected session=%#v err=%v", state, err)
	}

	complete := func(id, status, providerMessageID string) (OutboxCompletionRequest, CommitResult, error) {
		t.Helper()
		lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "delete-test-" + id, LeaseDuration: time.Minute})
		if err != nil {
			return OutboxCompletionRequest{}, CommitResult{}, err
		}
		if lease.Effect.EffectID != id {
			return OutboxCompletionRequest{}, CommitResult{}, errors.New("claimed unexpected outbox effect")
		}
		dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
			EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner,
			LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
		})
		if err != nil {
			return OutboxCompletionRequest{}, CommitResult{}, err
		}
		request := OutboxCompletionRequest{
			EffectID: id, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch,
			AttemptID: dispatched.Effect.AttemptID, Status: status, ResultCode: status,
			ProviderMessageID: providerMessageID,
		}
		result, err := store.CompleteOutbox(ctx, request)
		return request, result, err
	}
	successRequest, _, err := complete("deleted-success", OutboxStatusSucceeded, "provider-message-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := complete("deleted-failure", OutboxStatusFailed, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := complete("kept-success", OutboxStatusSucceeded, "provider-message-3"); err != nil {
		t.Fatal(err)
	}
	result, err := store.CompleteOutbox(ctx, successRequest)
	if err != nil || !result.Idempotent {
		t.Fatalf("repeated successful completion=%#v err=%v, want idempotent", result, err)
	}
	sessions, err := store.ListStoryLogs(ctx, "dice-a", "group-a")
	if err != nil || len(sessions) != 1 || sessions[0].ID != kept.ID {
		t.Fatalf("sessions after terminal outcomes=%#v err=%v, want only kept session", sessions, err)
	}
	deletedEntries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", deleted.Name)
	if err != nil || len(deletedEntries) != 0 {
		t.Fatalf("deleted session was recreated: entries=%#v err=%v", deletedEntries, err)
	}
	keptEntries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", kept.Name)
	if err != nil || len(keptEntries) != 1 || keptEntries[0].Message != "kept reply" {
		t.Fatalf("other session intent did not complete normally: entries=%#v err=%v", keptEntries, err)
	}
}

func TestStoryLogIntentFollowsOutboxTerminalCommit(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(700, 0).UTC()}
	ids := &outboxRecoveryIDs{}
	source := newTestKeySource()
	path := filepath.Join(t.TempDir(), "story-log-outbox.db")
	store, db := openOutboxRecoveryStore(t, path, source, clock, ids, true)
	defer db.Close()
	if _, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "session"); err != nil {
		t.Fatal(err)
	}

	complete := func(id, status, providerMessageID string) error {
		t.Helper()
		lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "story-log-" + id, LeaseDuration: time.Minute})
		if err != nil {
			return err
		}
		dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
			EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner,
			LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
		})
		if err != nil {
			return err
		}
		_, err = store.CompleteOutbox(ctx, OutboxCompletionRequest{
			EffectID: id, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch,
			AttemptID: dispatched.Effect.AttemptID, Status: status, ResultCode: status,
			ProviderMessageID: providerMessageID,
		})
		return err
	}
	seedAndQueue := func(id, operationID, eventID, message string) {
		t.Helper()
		effect := newOutboxRecoveryEffect(t, source, clock, id, "lane-"+id, RiskProviderIdempotent)
		seedOutboxRecoveryEffect(t, store, effect, operationID, eventID, clock.Now())
		if err := store.QueueStoryLogIntent(ctx, StoryLogIntent{EffectID: id, Entry: StoryLogEntry{
			DiceID: "dice-a", GroupID: "group-a", LogName: "session",
			Nickname: "Dice", Message: message, RawMsgID: "local-id",
		}}); err != nil {
			t.Fatalf("QueueStoryLogIntent(%s): %v", id, err)
		}
	}

	seedAndQueue("log-effect-success", "log-op-success", "log-event-success", "accepted")
	if err := complete("log-effect-success", OutboxStatusSucceeded, "provider-message-1"); err != nil {
		t.Fatalf("successful outbox completion: %v", err)
	}
	entries, err := store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 || entries[0].Message != "accepted" || entries[0].RawMsgID != "provider-message-1" {
		t.Fatalf("entries after successful terminal commit=%#v err=%v", entries, err)
	}

	seedAndQueue("log-effect-failed", "log-op-failed", "log-event-failed", "rejected")
	if err := complete("log-effect-failed", OutboxStatusFailed, ""); err != nil {
		t.Fatalf("failed outbox completion: %v", err)
	}
	entries, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 || entries[0].Message != "accepted" {
		t.Fatalf("failed effect reached archive: entries=%#v err=%v", entries, err)
	}
	var intentCount int64
	if err := db.GORM().Model(&logArchiveIntentRow{}).Count(&intentCount).Error; err != nil || intentCount != 0 {
		t.Fatalf("terminal intent count=%d err=%v", intentCount, err)
	}

	seedAndQueue("log-effect-tampered", "log-op-tampered", "log-event-tampered", "tampered")
	if err := db.GORM().Model(&logArchiveIntentRow{}).Where("effect_id = ?", "log-effect-tampered").Update("payload", []byte("tampered")).Error; err != nil {
		t.Fatal(err)
	}
	if err := complete("log-effect-tampered", OutboxStatusSucceeded, "provider-message-2"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered intent completion error=%v", err)
	}
	if row := loadOutboxRecoveryRow(t, db, "log-effect-tampered"); row.Status != OutboxStatusDispatched {
		t.Fatalf("outbox terminal transition escaped failed archive transaction: %#v", row)
	}
	if err := db.GORM().Model(&logArchiveIntentRow{}).Count(&intentCount).Error; err != nil || intentCount != 1 {
		t.Fatalf("rollback intent count=%d err=%v", intentCount, err)
	}
	entries, err = store.GetStoryLogEntries(ctx, "dice-a", "group-a", "session")
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries after failed terminal transaction=%#v err=%v", entries, err)
	}
}
func appendOrderedFixture(t *testing.T, store *GORMStore, entries []StoryLogEntry) []StoryLogEntry {
	t.Helper()
	ctx := context.Background()
	if _, err := store.CreateStoryLog(ctx, "dice", "group", "session"); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		entry.DiceID, entry.GroupID, entry.LogName = "dice", "group", "session"
		if err := store.AppendStoryLogEntry(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	read, err := store.GetStoryLogEntries(ctx, "dice", "group", "session")
	if err != nil {
		t.Fatal(err)
	}
	return read
}
func messages(entries []StoryLogEntry) []string {
	out := make([]string, len(entries))
	for i, entry := range entries {
		out[i] = entry.Message
	}
	return out
}

// A message recovered after an outage is stored after everything that arrived
// live, but it belongs between the messages around its sequence number. Within
// one second the stored order says nothing, so the sequence decides, and a
// reply sits next to the message that caused it wherever that message lands.
func TestStoryLogReadsRecoveredMessagesInSequenceOrder(t *testing.T) {
	source := newTestKeySource()
	store, db := openLogArchiveTestStore(t, filepath.Join(t.TempDir(), "events.db"), source)
	defer db.Close()

	read := appendOrderedFixture(t, store, []StoryLogEntry{
		{Nickname: "A", Time: 100, Message: "seq10", Seq: new(int64(10)), CommandID: 10},
		{Nickname: "C", Time: 100, Message: "seq12", Seq: new(int64(12)), CommandID: 12},
		{Nickname: "bot", Time: 101, Message: "reply to 12", IsDice: true, CommandID: 12},
		// Recovered afterwards, in the same second as the neighbours.
		{Nickname: "B", Time: 100, Message: "seq11", Seq: new(int64(11)), CommandID: 11},
		{Nickname: "bot", Time: 100, Message: "reply to 11", IsDice: true, CommandID: 11},
	})

	want := []string{"seq10", "seq11", "reply to 11", "seq12", "reply to 12"}
	if got := messages(read); !slices.Equal(got, want) {
		t.Fatalf("read order = %v, want %v", got, want)
	}
}

// Logs without sequence numbers (older data, other platforms) must read exactly
// as before: by time, then by the order they were stored in.
func TestStoryLogWithoutSequencesKeepsTimeThenStoredOrder(t *testing.T) {
	source := newTestKeySource()
	store, db := openLogArchiveTestStore(t, filepath.Join(t.TempDir(), "events.db"), source)
	defer db.Close()

	read := appendOrderedFixture(t, store, []StoryLogEntry{
		{Nickname: "A", Time: 100, Message: "first"},
		{Nickname: "bot", Time: 100, Message: "second", IsDice: true, CommandID: 7},
		{Nickname: "B", Time: 99, Message: "earlier second"},
		{Nickname: "C", Time: 100, Message: "third"},
	})

	want := []string{"earlier second", "first", "second", "third"}
	if got := messages(read); !slices.Equal(got, want) {
		t.Fatalf("read order = %v, want %v", got, want)
	}
}
func TestOrderStoryLogEntriesAnchorsAndDeterminism(t *testing.T) {
	seqEntry := func(id uint64, at, seq int64, msg string) StoryLogEntry {
		return StoryLogEntry{ID: id, Time: at, Seq: new(seq), Message: msg}
	}
	stored := []StoryLogEntry{
		seqEntry(1, 50, 20, "live 20"),
		// No command ties this notice to a message: it follows the newest sequence stored before it.
		{ID: 2, Time: 50, IsDice: true, Message: "notice"},
		seqEntry(3, 50, 18, "recovered 18"),
		seqEntry(4, 50, 19, "recovered 19"),
		// A dice entry whose command is unknown stays where storage put it.
		{ID: 5, Time: 50, IsDice: true, CommandID: 99, Message: "orphan reply"},
	}
	want := []string{"recovered 18", "recovered 19", "live 20", "notice", "orphan reply"}

	got := messages(orderStoryLogEntries(stored))
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for range 20 {
		if again := messages(orderStoryLogEntries(stored)); !slices.Equal(again, got) {
			t.Fatalf("order is not deterministic: %v then %v", got, again)
		}
	}
	if stored[0].Message != "live 20" || stored[2].Message != "recovered 18" {
		t.Fatal("ordering mutated its input")
	}
}

// The baseline marks where a log last resumed recording. It has to survive a
// restart, travel inside the encrypted state, and read as zero for states that
// were written before it existed.
func TestStoryLogStateKeepsBaselineSequence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	source := newTestKeySource()
	store, db := openLogArchiveTestStore(t, path, source)
	session, err := store.CreateStoryLog(ctx, "dice", "group", "session")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStoryLogState(ctx, StoryLogState{DiceID: "dice", GroupID: "group", SessionID: session.ID, Name: "session", On: true, BaselineSeq: 4242}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, db = openLogArchiveTestStore(t, path, source)
	defer db.Close()
	state, err := store.GetStoryLogState(ctx, "dice", "group")
	if err != nil || state.BaselineSeq != 4242 || !state.On || state.Name != "session" {
		t.Fatalf("state after restart = %+v err=%v", state, err)
	}
	var row storyLogStateRow
	if err := db.GORM().Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if containsBytes(row.Payload, []byte("4242")) || containsBytes(row.Payload, []byte("baseline")) {
		t.Fatal("baseline is stored in the clear")
	}
}
