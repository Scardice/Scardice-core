package privacypurge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"Scardice-core/eventstore"

	"gorm.io/gorm"
)

type privacyServiceKeySource struct {
	indexID, rootID string
	index, root     []byte
}

func newPrivacyServiceKeySource() *privacyServiceKeySource {
	return &privacyServiceKeySource{
		indexID: "privacy-index-v1", rootID: "privacy-root-v1",
		index: []byte("01234567890123456789012345678901"),
		root:  []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}
}
func (s *privacyServiceKeySource) IndexRootID(context.Context) (string, error) {
	if s == nil {
		return "", eventstore.ErrKeySourceUnavailable
	}
	return s.indexID, nil
}
func (s *privacyServiceKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	if s == nil {
		return nil, eventstore.ErrKeySourceUnavailable
	}
	return append([]byte(nil), s.index...), nil
}
func (s *privacyServiceKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	if s == nil {
		return eventstore.EncryptionRoot{}, eventstore.ErrKeySourceUnavailable
	}
	return eventstore.EncryptionRoot{ID: s.rootID, Material: append([]byte(nil), s.root...)}, nil
}
func (s *privacyServiceKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if s == nil {
		return nil, eventstore.ErrKeyUnavailable
	}
	if id != s.rootID {
		return nil, eventstore.ErrKeyUnavailable
	}
	return append([]byte(nil), s.root...), nil
}

func privacyServiceCanonical(parts ...string) string {
	out := ""
	var outSb59 strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&outSb59, "%d:%s", len(p), p)
	}
	out += outSb59.String()
	return out
}

func privacyServiceEvent(id string, payload []byte) eventstore.NewEvent {
	return eventstore.NewEvent{EventType: "privacy.test", SchemaVersion: 1, Payload: payload, Metadata: eventstore.Metadata{
		EventID: id, CommandID: id + "-command", CorrelationID: id + "-correlation",
		OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true,
	}}
}

func privacyServiceProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: "privacy", Version: "privacy-service-v1", Apply: func(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
		for _, e := range events {
			if err := eventstore.UpsertProjectionRow(tx, "privacy", e.Stream.AggregateID, e.Payload); err != nil {
				return err
			}
		}
		return nil
	}}
}

func openPrivacyServiceStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database, *privacyServiceKeySource) {
	t.Helper()
	source := newPrivacyServiceKeySource()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "privacy-service.db"), KeySource: source, DatabaseIdentity: "privacy-service",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithProjection(privacyServiceProjection()))
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "privacy-service", IndexRootID: source.indexID,
		EncryptionRootIDs: []string{source.rootID}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return store, db, source
}

func seedPrivacyServiceScope(t *testing.T, store *eventstore.GORMStore) eventstore.PrivacyDryRunResult {
	t.Helper()
	ctx := context.Background()
	group := privacyServiceCanonical("dice-a", "group-a")
	player := privacyServiceCanonical("dice-a", "group-a", "player-a")
	attrs := privacyServiceCanonical("dice-a", "group-a")
	streams := []eventstore.StreamAppend{
		{Stream: eventstore.StreamID{AggregateType: "group", AggregateID: group}, Events: []eventstore.NewEvent{privacyServiceEvent("privacy-group", []byte(`{"name":"group"}`))}},
		{Stream: eventstore.StreamID{AggregateType: "player", AggregateID: player}, Events: []eventstore.NewEvent{privacyServiceEvent("privacy-player", []byte(`{"name":"player"}`))}},
		{Stream: eventstore.StreamID{AggregateType: "attrs/group", AggregateID: attrs}, Events: []eventstore.NewEvent{privacyServiceEvent("privacy-attrs", []byte(`{"display":"attrs"}`))}},
	}
	if _, err := store.Commit(ctx, eventstore.UnitOfWork{Streams: streams}); err != nil {
		t.Fatal(err)
	}
	scan, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record", "players", "attrs"}})
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func TestPrivacyServiceInvalidatesCompatibilityCacheWhileFenced(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	scan := seedPrivacyServiceScope(t, store)
	invalidated := false
	svc := NewService(store, WithGroupCacheInvalidator(func(ctx context.Context, groupID string) error {
		if groupID != "group-a" {
			t.Fatalf("invalidated group = %q", groupID)
		}
		version, err := store.PrivacyFenceVersion(ctx, scan.SubjectKey, "group")
		if err != nil {
			return err
		}
		if version == 0 {
			t.Fatal("cache invalidated after privacy fence was released")
		}
		invalidated = true
		return nil
	}))
	dry, err := svc.DryRun(ctx, Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Confirm(ctx, Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true, ConfirmationDigest: dry.ConfirmationDigest, ConfirmationVersion: dry.ConfirmationVersion})
	if !errors.Is(err, ErrUncoveredData) {
		t.Fatalf("confirm err = %v", err)
	}
	if !invalidated {
		t.Fatal("privacy deletion did not invalidate compatibility cache")
	}
}

func TestSQLitePrivacyServiceConfirmResumeAndScrub(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	scan := seedPrivacyServiceScope(t, store)
	if scan.Counts != (eventstore.PrivacyCounts{GroupRecord: 1, Players: 1, Attrs: 1}) {
		t.Fatalf("dry-run counts=%+v", scan.Counts)
	}
	svc := NewService(store)
	dry, err := svc.DryRun(ctx, Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record", "players", "attrs"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Confirm(ctx, Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"attrs", "players", "group_record", "attrs"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true, ConfirmationDigest: dry.ConfirmationDigest, ConfirmationVersion: dry.ConfirmationVersion})
	if !errors.Is(err, ErrUncoveredData) {
		t.Fatalf("confirm err=%v result=%+v", err, result)
	}
	if !result.Completed || result.Status != "completed-uncovered" || result.Deleted != scan.Counts || result.OperationID == "" {
		t.Fatalf("confirm result=%+v", result)
	}
	view, private, err := store.PrivacyLoadOperation(ctx, result.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "completed-uncovered" || private.GroupID != "" || len(private.DiceIDs) != 0 || len(private.Scopes) != 0 || private.Phase != "" {
		t.Fatalf("operation view=%+v private=%+v", view, private)
	}
	if fence, err := store.PrivacyFenceVersion(ctx, scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("fence=%d err=%v", fence, err)
	}
	var auditCount int64
	if err := db.GORM().Table("privacy_purge_audit").Where("status = ?", "completed-uncovered").Count(&auditCount).Error; err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit rows=%d", auditCount)
	}
	if err := store.ValidateReadiness(ctx); err != nil {
		t.Fatalf("readiness after purge=%v", err)
	}
	for _, stream := range []eventstore.StreamID{{AggregateType: "group", AggregateID: privacyServiceCanonical("dice-a", "group-a")}, {AggregateType: "player", AggregateID: privacyServiceCanonical("dice-a", "group-a", "player-a")}, {AggregateType: "attrs/group", AggregateID: privacyServiceCanonical("dice-a", "group-a")}} {
		rows, loadErr := store.Load(ctx, stream, 0)
		if loadErr != nil || len(rows) != 0 {
			t.Fatalf("stream %s rows=%d err=%v", stream.AggregateType, len(rows), loadErr)
		}
	}
	assertPrivacyPurgeTerminal(t, store, db, result.OperationID, scan.SubjectKey, []string{"group_record", "players", "attrs"})
	resumed, resumeErr := svc.Confirm(ctx, Request{GroupID: "group-a", OperationID: result.OperationID, Resume: true})
	if !errors.Is(resumeErr, ErrUncoveredData) || !resumed.Completed {
		t.Fatalf("repeat resume=%+v err=%v", resumed, resumeErr)
	}
	var repeatAudit int64
	if err := db.GORM().Table("privacy_purge_audit").Where("status = ?", "completed-uncovered").Count(&repeatAudit).Error; err != nil {
		t.Fatal(err)
	}
	if repeatAudit != 1 {
		t.Fatalf("repeat audit rows=%d", repeatAudit)
	}
}

func TestSQLitePrivacyLogResumeReturnsOriginalPlannedCounts(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	current, err := store.CreateStoryLog(ctx, "dice-a", "group-a", "current")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStoryLogState(ctx, eventstore.StoryLogState{DiceID: "dice-a", GroupID: "group-a", SessionID: current.ID, Name: current.Name, On: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendStoryLogEntry(ctx, eventstore.StoryLogEntry{DiceID: "dice-a", GroupID: "group-a", LogName: current.Name, Time: 100, Message: "entry"}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueStoryLogIntent(ctx, eventstore.StoryLogIntent{EffectID: "resume-intent", Entry: eventstore.StoryLogEntry{DiceID: "dice-a", GroupID: "group-a", LogName: current.Name, Message: "pending"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportStoryLogBatch(ctx, []eventstore.StoryLogImportRecord{{
		SourceID: "resume-source-session", Kind: eventstore.StoryLogImportSession,
		DiceID: "dice-a", GroupID: "group-a",
		Session: &eventstore.StoryLogSession{DiceID: "dice-a", GroupID: "group-a", Name: "imported", CreatedAt: 101, UpdatedAt: 102},
	}}); err != nil {
		t.Fatal(err)
	}

	repo := &failingPrivacyRepository{GORMStore: store, failDeleteAfter: true}
	svc := NewService(repo)
	request := Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"logs"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true}
	dry, err := svc.DryRun(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	wantCounts := eventstore.PrivacyCounts{LogSessions: 2, LogStates: 1, LogEntries: 1, LogIntents: 1, LogImports: 1}
	if dry.Counts != wantCounts {
		t.Fatalf("planned counts=%+v want=%+v", dry.Counts, wantCounts)
	}
	request.ConfirmationDigest, request.ConfirmationVersion = dry.ConfirmationDigest, dry.ConfirmationVersion
	partial, err := svc.Confirm(ctx, request)
	if err == nil || partial.OperationID == "" || partial.Status != "resumable-failure" {
		t.Fatalf("injected post-commit failure result=%+v err=%v", partial, err)
	}
	resumed, err := svc.Confirm(ctx, Request{GroupID: "group-a", OperationID: partial.OperationID, Resume: true})
	if err != nil && !errors.Is(err, ErrUncoveredData) {
		t.Fatalf("resume error=%v result=%+v", err, resumed)
	}
	if !resumed.Completed || resumed.Counts != wantCounts || resumed.Deleted != wantCounts {
		t.Fatalf("resumed result=%+v want counts/deleted=%+v", resumed, wantCounts)
	}
}

type failingPrivacyRepository struct {
	*eventstore.GORMStore
	failDeleteBefore, failDeleteAfter, failRebuild, failFinalize, failFinalizeAfter bool
	deleteCalls                                                                     int
	deleteRequests                                                                  []eventstore.PrivacyBatchRequest
}

func (r *failingPrivacyRepository) PrivacyFinalizeOperation(ctx context.Context, operationID string, expected uint64, status string) (uint64, error) {
	if r.failFinalize {
		r.failFinalize = false
		return 0, errors.New("injected finalizer failure")
	}
	if r.failFinalizeAfter {
		r.failFinalizeAfter = false
		version, err := r.GORMStore.PrivacyFinalizeOperation(ctx, operationID, expected, status)
		if err != nil {
			return version, err
		}
		return version, errors.New("injected finalizer post-commit failure")
	}
	return r.GORMStore.PrivacyFinalizeOperation(ctx, operationID, expected, status)
}

func (r *failingPrivacyRepository) PrivacyDeleteBatch(ctx context.Context, req eventstore.PrivacyBatchRequest) (eventstore.PrivacyBatchResult, error) {
	r.deleteCalls++
	r.deleteRequests = append(r.deleteRequests, req)
	if r.failDeleteBefore {
		r.failDeleteBefore = false
		return eventstore.PrivacyBatchResult{}, errors.New("injected delete failure")
	}
	result, err := r.GORMStore.PrivacyDeleteBatch(ctx, req)
	if err == nil && r.failDeleteAfter {
		r.failDeleteAfter = false
		return result, errors.New("post-commit privacy crash")
	}
	return result, err
}
func (r *failingPrivacyRepository) PrivacyRebuildPublish(ctx context.Context, target uint64) error {
	if r.failRebuild {
		r.failRebuild = false
		return errors.New("injected rebuild failure")
	}
	return r.GORMStore.PrivacyRebuildPublish(ctx, target)
}

func startPrivacyServiceOperation(t *testing.T, store eventstore.PrivacyHistoryRepository) (Request, eventstore.PrivacyDryRunResult) {
	t.Helper()
	ctx := context.Background()
	scan, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: "group-a", ActiveDiceIDs: []string{"dice-a"}, DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}})
	if err != nil {
		t.Fatal(err)
	}
	return Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}, scan
}

func assertPrivacyPurgeTerminal(t *testing.T, store *eventstore.GORMStore, db *eventstore.Database, operationID string, subjectKey []byte, scopes []string) {
	t.Helper()
	selected := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		selected[scope] = true
	}
	streams := make([]eventstore.StreamID, 0, 3)
	if selected["group_record"] {
		streams = append(streams, eventstore.StreamID{AggregateType: "group", AggregateID: privacyServiceCanonical("dice-a", "group-a")})
	}
	if selected["players"] {
		streams = append(streams, eventstore.StreamID{AggregateType: "player", AggregateID: privacyServiceCanonical("dice-a", "group-a", "player-a")})
	}
	if selected["attrs"] {
		streams = append(streams, eventstore.StreamID{AggregateType: "attrs/group", AggregateID: privacyServiceCanonical("dice-a", "group-a")})
	}
	rowKeys := make([]string, len(streams))
	for i, stream := range streams {
		rowKeys[i] = stream.AggregateID
		rows, err := store.Load(context.Background(), stream, 0)
		if err != nil || len(rows) != 0 {
			t.Fatalf("terminal stream %s rows=%d err=%v", stream.AggregateType, len(rows), err)
		}
	}
	if len(streams) == 3 {
		var heads, projections int64
		if err := db.GORM().Table("aggregate_heads").Where("aggregate_id IN ?", rowKeys).Count(&heads).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.GORM().Table("projection_read_models").Where("row_key IN ?", rowKeys).Count(&projections).Error; err != nil {
			t.Fatal(err)
		}
		if heads != 0 || projections != 0 {
			t.Fatalf("raw terminal rows heads=%d projections=%d keys=%v", heads, projections, rowKeys)
		}
	}
	view, private, err := store.PrivacyLoadOperation(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "completed-uncovered" || private.GroupID != "" || len(private.DiceIDs) != 0 || len(private.Scopes) != 0 || len(private.ActiveDiceIDs) != 0 || len(private.ConfirmationDigest) != 0 || private.ConfirmationVersion != 0 || private.Counts != (eventstore.PrivacyCounts{}) || private.TargetHighWater != 0 || private.Cursor != "" || private.Phase != "" {
		t.Fatalf("terminal private context view=%+v private=%+v", view, private)
	}
	var stored struct {
		PrivateContext []byte
		PrivateNonce   []byte
		PrivateKeyID   string
	}
	if err := db.GORM().Table("operations").Select("private_context", "private_nonce", "private_key_id").Where("operation_id = ?", operationID).Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored.PrivateContext) != 0 || len(stored.PrivateNonce) != 0 || stored.PrivateKeyID != "" {
		t.Fatalf("raw operation private fields remain context=%d nonce=%d key=%q", len(stored.PrivateContext), len(stored.PrivateNonce), stored.PrivateKeyID)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), subjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("terminal fence=%d err=%v", fence, err)
	}
	var audits int64
	if err := db.GORM().Table("privacy_purge_audit").Where("status = ?", "completed-uncovered").Count(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("terminal audits=%d", audits)
	}
}

func TestSQLitePrivacyDeleteCrashBeforeCallbackResumes(t *testing.T) {
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	repo := &failingPrivacyRepository{GORMStore: store, failDeleteBefore: true}
	svc := NewService(repo)
	req, scan := startPrivacyServiceOperation(t, repo)
	failed, err := svc.Confirm(context.Background(), req)
	if err == nil || failed.Status != "resumable-failure" || failed.Phase != "delete" {
		t.Fatalf("failure result=%+v err=%v", failed, err)
	}
	fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group")
	if err != nil || fence == 0 {
		t.Fatalf("failure fence=%d err=%v", fence, err)
	}
	resumed, err := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(err, ErrUncoveredData) || !resumed.Completed {
		t.Fatalf("resumed=%+v err=%v", resumed, err)
	}
	assertPrivacyPurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat delete recovery=%+v err=%v", repeated, repeatErr)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("released fence=%d err=%v", fence, err)
	}
}

func TestSQLitePrivacyRebuildFailureResumesWithoutRepeatDelete(t *testing.T) {
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	repo := &failingPrivacyRepository{GORMStore: store, failRebuild: true}
	svc := NewService(repo)
	req, scan := startPrivacyServiceOperation(t, repo)
	failed, err := svc.Confirm(context.Background(), req)
	if err == nil || failed.Status != "resumable-failure" || failed.Phase != "rebuild" {
		t.Fatalf("failure result=%+v err=%v", failed, err)
	}
	fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group")
	if err != nil || fence == 0 {
		t.Fatalf("rebuild failure fence=%d err=%v", fence, err)
	}
	view, private, err := store.PrivacyLoadOperation(context.Background(), failed.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		PrivateContext []byte
		PrivateNonce   []byte
	}
	if err := db.GORM().Table("operations").Select("private_context", "private_nonce").Where("operation_id = ?", failed.OperationID).Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored.PrivateContext) == 0 || len(stored.PrivateNonce) == 0 || bytes.Contains(stored.PrivateContext, []byte(`"phase"`)) {
		t.Fatalf("private failure cursor/context was not encrypted: context=%d nonce=%d", len(stored.PrivateContext), len(stored.PrivateNonce))
	}
	if view.Status != "resumable-failure" || private.Phase != "rebuild" || len(private.ConfirmationDigest) == 0 {
		t.Fatalf("saved failure view=%+v private=%+v", view, private)
	}
	resumed, err := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(err, ErrUncoveredData) || !resumed.Completed || resumed.Counts != scan.Counts || resumed.Deleted != scan.Counts {
		t.Fatalf("resumed=%+v err=%v", resumed, err)
	}
	assertPrivacyPurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat rebuild recovery=%+v err=%v", repeated, repeatErr)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("released fence=%d err=%v", fence, err)
	}
}

func TestSQLitePrivacyCommitThenCrashResumesWithoutDuplicateDelete(t *testing.T) {
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	repo := &failingPrivacyRepository{GORMStore: store, failDeleteAfter: true}
	svc := NewService(repo)
	req, scan := startPrivacyServiceOperation(t, repo)
	failed, err := svc.Confirm(context.Background(), req)
	if err == nil || failed.Status != "resumable-failure" || failed.Phase != "delete" {
		t.Fatalf("post-commit failure result=%+v err=%v", failed, err)
	}
	resumed, err := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(err, ErrUncoveredData) || !resumed.Completed || resumed.Counts != scan.Counts || resumed.Deleted != scan.Counts {
		t.Fatalf("post-commit resume=%+v err=%v", resumed, err)
	}
	if repo.deleteCalls != 2 || repo.deleteRequests[0].Cursor != "" || repo.deleteRequests[1].Cursor != repo.deleteRequests[0].Cursor {
		t.Fatalf("delete retries calls=%d requests=%+v", repo.deleteCalls, repo.deleteRequests)
	}
	assertPrivacyPurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat post-commit recovery=%+v err=%v", repeated, repeatErr)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("released fence=%d err=%v", fence, err)
	}
}
func TestSQLitePrivacyFinalizerCrashResumes(t *testing.T) {
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	repo := &failingPrivacyRepository{GORMStore: store, failFinalize: true}
	svc := NewService(repo)
	req, scan := startPrivacyServiceOperation(t, repo)
	failed, err := svc.Confirm(context.Background(), req)
	if err == nil || failed.Status != "resumable-failure" || failed.Phase != "reopen" {
		t.Fatalf("finalizer failure result=%+v err=%v", failed, err)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence == 0 {
		t.Fatalf("reopen fence=%d err=%v", fence, err)
	}
	resumed, err := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(err, ErrUncoveredData) || !resumed.Completed {
		t.Fatalf("finalizer resume=%+v err=%v", resumed, err)
	}
	assertPrivacyPurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat finalizer recovery=%+v err=%v", repeated, repeatErr)
	}
}
func TestSQLitePrivacyFinalizerCommitThenErrorIsTerminal(t *testing.T) {
	store, db, _ := openPrivacyServiceStore(t)
	defer db.Close()
	seedPrivacyServiceScope(t, store)
	repo := &failingPrivacyRepository{GORMStore: store, failFinalizeAfter: true}
	svc := NewService(repo)
	req, scan := startPrivacyServiceOperation(t, repo)
	result, err := svc.Confirm(context.Background(), req)
	if !errors.Is(err, ErrUncoveredData) || result.Status != "completed-uncovered" || !result.Completed {
		t.Fatalf("post-commit finalizer result=%+v err=%v", result, err)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("post-commit fence=%d err=%v", fence, err)
	}
	resumed, resumeErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: result.OperationID, Resume: true})
	if !errors.Is(resumeErr, ErrUncoveredData) || !resumed.Completed || resumed.Status != "completed-uncovered" {
		t.Fatalf("post-commit resume=%+v err=%v", resumed, resumeErr)
	}
}
