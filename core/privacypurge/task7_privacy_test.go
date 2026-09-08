package privacypurge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"gorm.io/gorm"
)

type task7ServiceKeySource struct {
	indexID, rootID string
	index, root     []byte
}

func newTask7ServiceKeySource() *task7ServiceKeySource {
	return &task7ServiceKeySource{
		indexID: "task7-index-v1", rootID: "task7-root-v1",
		index: []byte("01234567890123456789012345678901"),
		root:  []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}
}
func (s *task7ServiceKeySource) IndexRootID(context.Context) (string, error) {
	if s == nil {
		return "", eventstore.ErrKeySourceUnavailable
	}
	return s.indexID, nil
}
func (s *task7ServiceKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	if s == nil {
		return nil, eventstore.ErrKeySourceUnavailable
	}
	return append([]byte(nil), s.index...), nil
}
func (s *task7ServiceKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	if s == nil {
		return eventstore.EncryptionRoot{}, eventstore.ErrKeySourceUnavailable
	}
	return eventstore.EncryptionRoot{ID: s.rootID, Material: append([]byte(nil), s.root...)}, nil
}
func (s *task7ServiceKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if s == nil {
		return nil, eventstore.ErrKeyUnavailable
	}
	if id != s.rootID {
		return nil, eventstore.ErrKeyUnavailable
	}
	return append([]byte(nil), s.root...), nil
}

func task7ServiceCanonical(parts ...string) string {
	out := ""
	for _, p := range parts {
		out += fmt.Sprintf("%d:%s", len(p), p)
	}
	return out
}

func task7ServiceEvent(id string, payload []byte) eventstore.NewEvent {
	return eventstore.NewEvent{EventType: "privacy.test", SchemaVersion: 1, Payload: payload, Metadata: eventstore.Metadata{
		EventID: id, CommandID: id + "-command", CorrelationID: id + "-correlation",
		OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true,
	}}
}

func task7ServiceProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: "privacy", Version: "task7-v1", Apply: func(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
		for _, e := range events {
			if err := eventstore.UpsertProjectionRow(tx, "privacy", e.Stream.AggregateID, e.Payload); err != nil {
				return err
			}
		}
		return nil
	}}
}

func openTask7ServiceStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database, *task7ServiceKeySource) {
	t.Helper()
	source := newTask7ServiceKeySource()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task7-privacy.db"), KeySource: source, DatabaseIdentity: "task7-service",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithProjection(task7ServiceProjection()))
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "task7-service", IndexRootID: source.indexID,
		EncryptionRootIDs: []string{source.rootID}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return store, db, source
}

func seedTask7ServiceScope(t *testing.T, store *eventstore.GORMStore) eventstore.PrivacyDryRunResult {
	t.Helper()
	ctx := context.Background()
	group := task7ServiceCanonical("dice-a", "group-a")
	player := task7ServiceCanonical("dice-a", "group-a", "player-a")
	attrs := task7ServiceCanonical("dice-a", "group-a")
	streams := []eventstore.StreamAppend{
		{Stream: eventstore.StreamID{AggregateType: "group", AggregateID: group}, Events: []eventstore.NewEvent{task7ServiceEvent("task7-group", []byte(`{"name":"group"}`))}},
		{Stream: eventstore.StreamID{AggregateType: "player", AggregateID: player}, Events: []eventstore.NewEvent{task7ServiceEvent("task7-player", []byte(`{"name":"player"}`))}},
		{Stream: eventstore.StreamID{AggregateType: "attrs/group", AggregateID: attrs}, Events: []eventstore.NewEvent{task7ServiceEvent("task7-attrs", []byte(`{"display":"attrs"}`))}},
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

func TestTask7SQLitePrivacyServiceConfirmResumeAndScrub(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openTask7ServiceStore(t)
	defer db.Close()
	scan := seedTask7ServiceScope(t, store)
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
	for _, stream := range []eventstore.StreamID{{AggregateType: "group", AggregateID: task7ServiceCanonical("dice-a", "group-a")}, {AggregateType: "player", AggregateID: task7ServiceCanonical("dice-a", "group-a", "player-a")}, {AggregateType: "attrs/group", AggregateID: task7ServiceCanonical("dice-a", "group-a")}} {
		rows, loadErr := store.Load(ctx, stream, 0)
		if loadErr != nil || len(rows) != 0 {
			t.Fatalf("stream %s rows=%d err=%v", stream.AggregateType, len(rows), loadErr)
		}
	}
	assertTask7PurgeTerminal(t, store, db, result.OperationID, scan.SubjectKey, []string{"group_record", "players", "attrs"})
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

type task7FailingPrivacyRepo struct {
	*eventstore.GORMStore
	failDeleteBefore, failDeleteAfter, failRebuild, failFinalize, failFinalizeAfter bool
	deleteCalls int
	deleteRequests []eventstore.PrivacyBatchRequest
}

func (r *task7FailingPrivacyRepo) PrivacyFinalizeOperation(ctx context.Context, operationID string, expected uint64, status string) (uint64, error) {
	if r.failFinalize {
		r.failFinalize = false
		return 0, errors.New("task7 injected finalizer failure")
	}
	if r.failFinalizeAfter {
		r.failFinalizeAfter = false
		version, err := r.GORMStore.PrivacyFinalizeOperation(ctx, operationID, expected, status)
		if err != nil {
			return version, err
		}
		return version, errors.New("task7 injected finalizer post-commit failure")
	}
	return r.GORMStore.PrivacyFinalizeOperation(ctx, operationID, expected, status)
}

func (r *task7FailingPrivacyRepo) PrivacyDeleteBatch(ctx context.Context, req eventstore.PrivacyBatchRequest) (eventstore.PrivacyBatchResult, error) {
	r.deleteCalls++
	r.deleteRequests = append(r.deleteRequests, req)
	if r.failDeleteBefore {
		r.failDeleteBefore = false
		return eventstore.PrivacyBatchResult{}, errors.New("task7 injected delete failure")
	}
	result, err := r.GORMStore.PrivacyDeleteBatch(ctx, req)
	if err == nil && r.failDeleteAfter {
		r.failDeleteAfter = false
		return result, errors.New("task7 post-commit crash")
	}
	return result, err
}
func (r *task7FailingPrivacyRepo) PrivacyRebuildPublish(ctx context.Context, target uint64) error {
	if r.failRebuild {
		r.failRebuild = false
		return errors.New("task7 injected rebuild failure")
	}
	return r.GORMStore.PrivacyRebuildPublish(ctx, target)
}

func task7StartServiceOperation(t *testing.T, store eventstore.PrivacyHistoryRepository) (Request, eventstore.PrivacyDryRunResult) {
	t.Helper()
	ctx := context.Background()
	scan, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: "group-a", ActiveDiceIDs: []string{"dice-a"}, DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}})
	if err != nil {
		t.Fatal(err)
	}
	return Request{GroupID: "group-a", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}, ActiveDiceIDs: []string{"dice-a"}, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}, scan
}

func assertTask7PurgeTerminal(t *testing.T, store *eventstore.GORMStore, db *eventstore.Database, operationID string, subjectKey []byte, scopes []string) {
	t.Helper()
	selected := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		selected[scope] = true
	}
	streams := make([]eventstore.StreamID, 0, 3)
	if selected["group_record"] {
		streams = append(streams, eventstore.StreamID{AggregateType: "group", AggregateID: task7ServiceCanonical("dice-a", "group-a")})
	}
	if selected["players"] {
		streams = append(streams, eventstore.StreamID{AggregateType: "player", AggregateID: task7ServiceCanonical("dice-a", "group-a", "player-a")})
	}
	if selected["attrs"] {
		streams = append(streams, eventstore.StreamID{AggregateType: "attrs/group", AggregateID: task7ServiceCanonical("dice-a", "group-a")})
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

func TestTask7SQLitePrivacyDeleteCrashBeforeCallbackResumes(t *testing.T) {
	store, db, _ := openTask7ServiceStore(t)
	defer db.Close()
	seedTask7ServiceScope(t, store)
	repo := &task7FailingPrivacyRepo{GORMStore: store, failDeleteBefore: true}
	svc := NewService(repo)
	req, scan := task7StartServiceOperation(t, repo)
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
	assertTask7PurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat delete recovery=%+v err=%v", repeated, repeatErr)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("released fence=%d err=%v", fence, err)
	}
}

func TestTask7SQLitePrivacyRebuildFailureResumesWithoutRepeatDelete(t *testing.T) {
	store, db, _ := openTask7ServiceStore(t)
	defer db.Close()
	seedTask7ServiceScope(t, store)
	repo := &task7FailingPrivacyRepo{GORMStore: store, failRebuild: true}
	svc := NewService(repo)
	req, scan := task7StartServiceOperation(t, repo)
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
	if !errors.Is(err, ErrUncoveredData) || !resumed.Completed || resumed.Deleted != (eventstore.PrivacyCounts{}) {
		t.Fatalf("resumed=%+v err=%v", resumed, err)
	}
	assertTask7PurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat rebuild recovery=%+v err=%v", repeated, repeatErr)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("released fence=%d err=%v", fence, err)
	}
}

func TestTask7SQLitePrivacyCommitThenCrashResumesWithoutDuplicateDelete(t *testing.T) {
	store, db, _ := openTask7ServiceStore(t)
	defer db.Close()
	seedTask7ServiceScope(t, store)
	repo := &task7FailingPrivacyRepo{GORMStore: store, failDeleteAfter: true}
	svc := NewService(repo)
	req, scan := task7StartServiceOperation(t, repo)
	failed, err := svc.Confirm(context.Background(), req)
	if err == nil || failed.Status != "resumable-failure" || failed.Phase != "delete" {
		t.Fatalf("post-commit failure result=%+v err=%v", failed, err)
	}
	resumed, err := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(err, ErrUncoveredData) || !resumed.Completed || resumed.Deleted != (eventstore.PrivacyCounts{}) {
		t.Fatalf("post-commit resume=%+v err=%v", resumed, err)
	}
	if repo.deleteCalls != 2 || repo.deleteRequests[0].Cursor != "" || repo.deleteRequests[1].Cursor != repo.deleteRequests[0].Cursor {
		t.Fatalf("delete retries calls=%d requests=%+v", repo.deleteCalls, repo.deleteRequests)
	}
	assertTask7PurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat post-commit recovery=%+v err=%v", repeated, repeatErr)
	}
	if fence, err := store.PrivacyFenceVersion(context.Background(), scan.SubjectKey, "group"); err != nil || fence != 0 {
		t.Fatalf("released fence=%d err=%v", fence, err)
	}
}
func TestTask7SQLitePrivacyFinalizerCrashResumes(t *testing.T) {
	store, db, _ := openTask7ServiceStore(t)
	defer db.Close()
	seedTask7ServiceScope(t, store)
	repo := &task7FailingPrivacyRepo{GORMStore: store, failFinalize: true}
	svc := NewService(repo)
	req, scan := task7StartServiceOperation(t, repo)
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
	assertTask7PurgeTerminal(t, store, db, failed.OperationID, scan.SubjectKey, []string{"group_record"})
	repeated, repeatErr := svc.Confirm(context.Background(), Request{GroupID: req.GroupID, OperationID: failed.OperationID, Resume: true})
	if !errors.Is(repeatErr, ErrUncoveredData) || !repeated.Completed {
		t.Fatalf("repeat finalizer recovery=%+v err=%v", repeated, repeatErr)
	}
}
func TestTask7SQLitePrivacyFinalizerCommitThenErrorIsTerminal(t *testing.T) {
	store, db, _ := openTask7ServiceStore(t)
	defer db.Close()
	seedTask7ServiceScope(t, store)
	repo := &task7FailingPrivacyRepo{GORMStore: store, failFinalizeAfter: true}
	svc := NewService(repo)
	req, scan := task7StartServiceOperation(t, repo)
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
