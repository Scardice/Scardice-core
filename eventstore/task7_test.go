package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"
)

func task7Event(id string, delta int) NewEvent {
	return NewEvent{
		EventType:     "counter.changed",
		SchemaVersion: 1,
		Payload:       json.RawMessage(fmt.Sprintf(`{"delta":%d}`, delta)),
		Metadata: Metadata{
			EventID:                id + "-event",
			CommandID:              id + "-command",
			CorrelationID:          id + "-correlation",
			OccurredAtUnixNanoUTC: 1,
			OccurredAtUnixNanoSet: true,
		},
	}
}

type task7KeySource struct {
	indexID       string
	indexMaterial []byte
	rootID        string
	rootMaterial  []byte
}

func task7Source() *task7KeySource {
	return &task7KeySource{
		indexID: "task7-index-v1", indexMaterial: []byte("01234567890123456789012345678901"),
		rootID: "task7-root-v1", rootMaterial: []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}
}

func (s *task7KeySource) IndexRootID(context.Context) (string, error) {
	if s == nil {
		return "", ErrKeySourceUnavailable
	}
	return s.indexID, nil
}
func (s *task7KeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	if s == nil {
		return nil, ErrKeySourceUnavailable
	}
	return append([]byte(nil), s.indexMaterial...), nil
}
func (s *task7KeySource) CurrentEncryptionRoot(context.Context) (EncryptionRoot, error) {
	if s == nil {
		return EncryptionRoot{}, ErrKeySourceUnavailable
	}
	return EncryptionRoot{ID: s.rootID, Material: append([]byte(nil), s.rootMaterial...)}, nil
}
func (s *task7KeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if s == nil || id != s.rootID {
		return nil, ErrKeyUnavailable
	}
	return append([]byte(nil), s.rootMaterial...), nil
}

func task7OpenSQLite(t testing.TB, source *task7KeySource, name string) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{
		Type:             "sqlite",
		DSN:              filepath.Join(t.TempDir(), name+".db"),
		KeySource:        source,
		DatabaseIdentity: "task7-sqlite",
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(db), db
}

func task7Projection() ProjectionDescriptor {
	return ProjectionDescriptor{
		Name:    "counter",
		Version: "v1",
		Apply: func(ctx context.Context, tx *gorm.DB, events []Envelope) error {
			for _, event := range events {
				if err := UpsertProjectionRow(tx, "counter", event.Stream.AggregateID, event.Payload); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func task7FailingProjection() ProjectionDescriptor {
	return ProjectionDescriptor{
		Name:    "late-failure",
		Version: "v1",
		Apply: func(ctx context.Context, tx *gorm.DB, events []Envelope) error {
			for _, event := range events {
				if err := UpsertProjectionRow(tx, "late-failure", event.Stream.AggregateID, event.Payload); err != nil {
					return err
				}
			}
			if len(events) == 0 {
				return errors.New("task7 projector received no events")
			}
			var marker projectionReadModelRow
			if err := tx.Where("projection_name = ? AND row_key = ?", "late-failure", events[0].Stream.AggregateID).First(&marker).Error; err != nil {
				return fmt.Errorf("task7 projector marker missing: %w", err)
			}
			return errors.New("task7 late projector failure")
		},
	}
}

func task7QueuePayloads(t testing.TB, source *task7KeySource, ctx context.Context, prefix string) (InboxUpdate, InboxUpdate, NewEffect, NewEffect) {
	t.Helper()
	inbox := make([]InboxUpdate, 2)
	for i := range inbox {
		id := fmt.Sprintf("%s-inbox-%d", prefix, i+1)
		ciphertext, nonce, keyID, err := a6Seal(ctx, source, "inbox/v1", id, "endpoint", 1, []byte(fmt.Sprintf(`{"inbox":%d}`, i+1)))
		if err != nil {
			t.Fatal(err)
		}
		inbox[i] = InboxUpdate{
			InboxID: id, EndpointID: "endpoint", ProviderEventKey: fmt.Sprintf("%s-provider-%d", prefix, i+1),
			LaneHMAC: []byte(prefix + "-lane"), Status: InboxStatusPending,
			PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID,
		}
	}
	effects := make([]NewEffect, 2)
	for i := range effects {
		id := fmt.Sprintf("%s-effect-%d", prefix, i+1)
		ciphertext, nonce, keyID, err := a6Seal(ctx, source, "outbox/v1", id, "endpoint", 1, []byte(fmt.Sprintf(`{"effect":%d}`, i+1)))
		if err != nil {
			t.Fatal(err)
		}
		effects[i] = NewEffect{
			EffectID: id, EndpointID: "endpoint", LaneHMAC: []byte(prefix + "-lane"), EffectType: "send",
			RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
			PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID,
		}
	}
	return inbox[0], inbox[1], effects[0], effects[1]
}

func task7AssertLateRollback(t testing.TB, db *Database, stream StreamID, operationID string, beforeSequence eventGlobalSequenceRow, beforeControl projectionControlRow) {
	t.Helper()
	var operationCount, projectionCount, headCount int64
	if err := db.GORM().Model(&operationRow{}).Where("operation_id = ?", operationID).Count(&operationCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&projectionReadModelRow{}).Where("projection_name = ? AND row_key = ?", "late-failure", stream.AggregateID).Count(&projectionCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&aggregateHeadRow{}).Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).Count(&headCount).Error; err != nil {
		t.Fatal(err)
	}
	var sequence eventGlobalSequenceRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
		t.Fatal(err)
	}
	var control projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		t.Fatal(err)
	}
	if operationCount != 0 || projectionCount != 0 || headCount != 0 {
		t.Fatalf("late rollback left operation=%d projection=%d head=%d", operationCount, projectionCount, headCount)
	}
	if sequence != beforeSequence {
		t.Fatalf("event sequence changed: before=%#v after=%#v", beforeSequence, sequence)
	}
	if control != beforeControl {
		t.Fatalf("projection control changed: before=%#v after=%#v", beforeControl, control)
	}
}

func TestTask7SQLiteEndToEndKernelPath(t *testing.T) {
	ctx := context.Background()
	source := task7Source()
	store, db := task7OpenSQLite(t, source, "task7-e2e")
	defer db.Close()
	if err := store.RegisterProjection(task7Projection()); err != nil {
		t.Fatal(err)
	}

	inbox1, inbox2, effect1, effect2 := task7QueuePayloads(t, source, ctx, "task7")
	stream := StreamID{AggregateType: "counter", AggregateID: "counter-1"}
	commit, err := store.Commit(ctx, UnitOfWork{
		Streams:    []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event("task7-counter", 1)}}},
		Operations: []OperationUpdate{{OperationID: "task7-operation", PrincipalID: "owner", Kind: "counter", Status: "succeeded"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(commit.Events) != 1 || commit.Events[0].GlobalPosition == 0 || commit.StreamVersions[stream] != 1 {
		t.Fatalf("commit allocation = %#v", commit)
	}

	inboxResult, err := store.AcceptInbox(ctx, inbox1)
	if err != nil || inboxResult.OrderingSequence != 1 {
		t.Fatalf("first inbox acceptance = %#v err=%v", inboxResult, err)
	}
	inboxResult, err = store.AcceptInbox(ctx, inbox2)
	if err != nil || inboxResult.OrderingSequence != 2 {
		t.Fatalf("second inbox acceptance = %#v err=%v", inboxResult, err)
	}
	effectResult, err := store.AcceptOutbox(ctx, effect1)
	if err != nil || effectResult.OrderingSequence != 1 {
		t.Fatalf("first outbox acceptance = %#v err=%v", effectResult, err)
	}
	effectResult, err = store.AcceptOutbox(ctx, effect2)
	if err != nil || effectResult.OrderingSequence != 2 {
		t.Fatalf("second outbox acceptance = %#v err=%v", effectResult, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(commit.Events) != 1 || commit.Events[0].GlobalPosition == 0 || commit.StreamVersions[stream] != 1 {
		t.Fatalf("commit allocation = %#v", commit)
	}

	live, err := store.ReadProjectionRow(ctx, "counter", "counter-1")
	if err != nil {
		t.Fatal(err)
	}
	if live.ProjectionName != "counter" || string(live.Payload) != `{"delta":1}` {
		t.Fatalf("synchronous projection = %#v", live)
	}

	firstInbox, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "inbox-worker", LeaseDuration: time.Minute})
	if err != nil || firstInbox.Update.InboxID != inbox1.InboxID || firstInbox.Update.OrderingSequence != 1 {
		t.Fatalf("first inbox claim = %#v err=%v", firstInbox, err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "other-inbox-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inbox ordering bypass = %v", err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{
		InboxID: firstInbox.Update.InboxID, ExpectedVersion: firstInbox.Update.Version,
		Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "operator", Reason: "task7-proof",
	}); err != nil {
		t.Fatal(err)
	}
	secondInbox, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "inbox-worker", LeaseDuration: time.Minute})
	if err != nil || secondInbox.Update.InboxID != inbox2.InboxID || secondInbox.Update.OrderingSequence != 2 {
		t.Fatalf("second inbox claim = %#v err=%v", secondInbox, err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{
		InboxID: secondInbox.Update.InboxID, ExpectedVersion: secondInbox.Update.Version,
		Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "operator", Reason: "task7-proof",
	}); err != nil {
		t.Fatal(err)
	}

	firstEffect, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "outbox-worker", LeaseDuration: time.Minute})
	if err != nil || firstEffect.Effect.EffectID != effect1.EffectID || firstEffect.Effect.OrderingSequence != 1 {
		t.Fatalf("first outbox claim = %#v err=%v", firstEffect, err)
	}
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "other-outbox-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outbox ordering bypass = %v", err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
		EffectID: firstEffect.Effect.EffectID, WorkerID: "outbox-worker", LeaseEpoch: firstEffect.Effect.LeaseEpoch, AttemptID: firstEffect.Effect.AttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{
		EffectID: dispatched.Effect.EffectID, WorkerID: "outbox-worker", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID,
		Status: OutboxStatusSucceeded, ResultCode: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	secondEffect, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "outbox-worker", LeaseDuration: time.Minute})
	if err != nil || secondEffect.Effect.EffectID != effect2.EffectID || secondEffect.Effect.OrderingSequence != 2 {
		t.Fatalf("second outbox claim = %#v err=%v", secondEffect, err)
	}
	dispatched, err = store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
		EffectID: secondEffect.Effect.EffectID, WorkerID: "outbox-worker", LeaseEpoch: secondEffect.Effect.LeaseEpoch, AttemptID: secondEffect.Effect.AttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{
		EffectID: dispatched.Effect.EffectID, WorkerID: "outbox-worker", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID,
		Status: OutboxStatusSucceeded, ResultCode: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	var inboxRows []inboxMessageRow
	if err := db.GORM().Where("inbox_id IN ?", []string{inbox1.InboxID, inbox2.InboxID}).Find(&inboxRows).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRows) != 2 {
		t.Fatalf("terminal inbox rows = %d", len(inboxRows))
	}
	for _, row := range inboxRows {
		if row.Status != InboxStatusConfirmedConsumed || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
			t.Fatalf("terminal inbox payload = %#v", row)
		}
	}
	var outboxRows []outboxEffectRow
	if err := db.GORM().Where("effect_id IN ?", []string{effect1.EffectID, effect2.EffectID}).Find(&outboxRows).Error; err != nil {
		t.Fatal(err)
	}
	if len(outboxRows) != 2 {
		t.Fatalf("terminal outbox rows = %d", len(outboxRows))
	}
	for _, row := range outboxRows {
		if row.Status != OutboxStatusSucceeded || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
			t.Fatalf("terminal outbox payload = %#v", row)
		}
	}

	artifact, err := store.PutArtifact(ctx, ArtifactPutRequest{
		ArtifactID: "task7-artifact", OperationID: "task7-operation", OwnerPrincipalID: "owner",
		MediaType: "application/json", SafeFilename: "counter.json", Plaintext: []byte(`{"counter":1}`), TTL: time.Minute,
	})
	if err != nil || artifact.Size != int64(len(`{"counter":1}`)) {
		t.Fatalf("artifact put = %#v err=%v", artifact, err)
	}
	consumed, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: artifact.ArtifactID})
	if err != nil || string(consumed.Plaintext) != `{"counter":1}` {
		t.Fatalf("artifact consume = %#v err=%v", consumed, err)
	}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: artifact.ArtifactID}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("artifact second consume = %v", err)
	}

	kv, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "task7-plugin", Key: "counter", Value: []byte("1")})
	if err != nil || kv.Version != 1 {
		t.Fatalf("plugin put = %#v err=%v", kv, err)
	}
	readKV, err := store.GetPluginKV(ctx, "task7-plugin", "counter")
	if err != nil || string(readKV.Value) != "1" || readKV.Version != kv.Version {
		t.Fatalf("plugin read = %#v err=%v", readKV, err)
	}

	rebuild, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"})
	if err != nil || rebuild.GenerationID == "" || rebuild.TerminalPosition != commit.Events[0].GlobalPosition {
		t.Fatalf("shadow rebuild = %#v err=%v", rebuild, err)
	}
	rebuilt, err := store.ReadProjectionRow(ctx, "counter", "counter-1")
	if err != nil || rebuilt.ProjectionGeneration != rebuild.GenerationID || string(rebuilt.Payload) != `{"delta":1}` {
		t.Fatalf("published projection = %#v err=%v", rebuilt, err)
	}
	if err := store.ValidateReadiness(ctx); err != nil {
		t.Fatalf("readiness validation = %v", err)
	}
	readiness, err := store.GetReadiness(ctx)
	if err != nil || readiness.Mode != "fresh" || readiness.IndexRootID != source.indexID {
		t.Fatalf("readiness = %#v err=%v", readiness, err)
	}

	var scrubbed operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", artifact.ArtifactID).First(&scrubbed).Error; err != nil {
		t.Fatal(err)
	}
	if len(scrubbed.Ciphertext) != 0 || len(scrubbed.Nonce) != 0 {
		t.Fatal("consumed artifact ciphertext was not scrubbed")
	}
}

func TestTask7SQLiteConflictRollsBackWholeTransaction(t *testing.T) {
	ctx := context.Background()
	store, db := task7OpenSQLite(t, task7Source(), "task7-conflict")
	defer db.Close()
	stream := StreamID{AggregateType: "counter", AggregateID: "rollback-counter"}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event("task7-rollback-first", 1)}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams:    []StreamAppend{{Stream: stream, ExpectedVersion: 0, Events: []NewEvent{task7Event("task7-rollback-conflict", 2)}}},
		Operations: []OperationUpdate{{OperationID: "must-not-persist", PrincipalID: "owner"}},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale commit error = %v", err)
	}
	events, err := store.Load(ctx, stream, 0)
	if err != nil || len(events) != 1 || events[0].StreamVersion != 1 {
		t.Fatalf("rollback stream = %#v err=%v", events, err)
	}
	var operationCount int64
	if err := db.GORM().Model(&operationRow{}).Where("operation_id = ?", "must-not-persist").Count(&operationCount).Error; err != nil {
		t.Fatal(err)
	}
	if operationCount != 0 {
		t.Fatalf("conflicting operation persisted: %d", operationCount)
	}
}

func TestTask7SQLiteLateProjectorRollback(t *testing.T) {
	ctx := context.Background()
	source := task7Source()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task7-late-failure.db"), KeySource: source, DatabaseIdentity: "task7-sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, WithProjection(task7FailingProjection()))
	stream := StreamID{AggregateType: "counter", AggregateID: "late-rollback"}
	operationID := "late-rollback-operation"
	var beforeSequence eventGlobalSequenceRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&beforeSequence).Error; err != nil {
		t.Fatal(err)
	}
	var beforeControl projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&beforeControl).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event("late-rollback-event", 1)}}},
		Operations: []OperationUpdate{{OperationID: operationID, PrincipalID: "owner"}},
	}); !errors.Is(err, ErrProjectorFailure) {
		t.Fatalf("late projector error = %v", err)
	}
	events, err := store.Load(ctx, stream, 0)
	if err != nil || len(events) != 0 {
		t.Fatalf("late rollback events=%#v err=%v", events, err)
	}
	task7AssertLateRollback(t, db, stream, operationID, beforeSequence, beforeControl)
}

func TestTask7RemoteTransactionRollbackOptIn(t *testing.T) {
	cases := []struct {
		name string
		typeName string
		env string
	}{
		{name: "mysql", typeName: "mysql", env: "SCARDICE_EVENTSTORE_MYSQL_DSN"},
		{name: "postgres", typeName: "postgres", env: "SCARDICE_EVENTSTORE_POSTGRES_DSN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dsn := os.Getenv(tc.env)
			if dsn == "" {
				t.Skipf("%s is unset; opt-in %s transaction test skipped", tc.env, tc.typeName)
			}
			source := task7Source()
			db, err := OpenDatabase(context.Background(), DatabaseConfig{
				Type: tc.typeName, DSN: dsn, KeySource: source,
				DatabaseIdentity: "task7-remote-" + tc.name, TLSVerify: true,
				ConnectTimeout: 5 * time.Second, QueryTimeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store := NewStore(db, WithProjection(task7FailingProjection()))
			stream := StreamID{AggregateType: "task7-remote-counter", AggregateID: fmt.Sprintf("%s-%d", tc.name, time.Now().UnixNano())}
			operationID := stream.AggregateID + "-operation"
			var beforeSequence eventGlobalSequenceRow
			if err := db.GORM().Where("singleton_id = ?", "default").First(&beforeSequence).Error; err != nil {
				t.Fatal(err)
			}
			var beforeControl projectionControlRow
			if err := db.GORM().Where("singleton_id = ?", "default").First(&beforeControl).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(context.Background(), UnitOfWork{
				Streams:    []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event(stream.AggregateID+"-event", 1)}}},
				Operations: []OperationUpdate{{OperationID: operationID, PrincipalID: "owner"}},
			}); !errors.Is(err, ErrProjectorFailure) {
				t.Fatalf("late projector error = %v", err)
			}
			events, err := store.Load(context.Background(), stream, 0)
			if err != nil || len(events) != 0 {
				t.Fatalf("rollback after late projector events=%#v err=%v", events, err)
			}
			task7AssertLateRollback(t, db, stream, operationID, beforeSequence, beforeControl)
		})
	}
}

func task7SQLiteSize(path string) int64 {
	var size int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err == nil {
			size += info.Size()
		}
	}
	return size
}

func task7BenchmarkKernelPath(b *testing.B, store *GORMStore, source *task7KeySource, ctx context.Context, prefix string) {
	inbox1, inbox2, effect1, effect2 := task7QueuePayloads(b, source, ctx, prefix)
	stream := StreamID{AggregateType: "counter", AggregateID: prefix}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams:    []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event(prefix, 1)}}},
		Operations: []OperationUpdate{{OperationID: prefix + "-operation", PrincipalID: "owner", Kind: "counter", Status: "succeeded"}},
	}); err != nil {
		b.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, inbox1); err != nil {
		b.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, inbox2); err != nil {
		b.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, effect1); err != nil {
		b.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, effect2); err != nil {
		b.Fatal(err)
	}
	if _, err := store.ReadProjectionRow(ctx, "counter", prefix); err != nil {
		b.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "bench-inbox", LeaseDuration: time.Minute})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: inboxLease.Update.InboxID, ExpectedVersion: inboxLease.Update.Version, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "bench", Reason: "bench"}); err != nil {
		b.Fatal(err)
	}
	inboxLease, err = store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "bench-inbox", LeaseDuration: time.Minute})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: inboxLease.Update.InboxID, ExpectedVersion: inboxLease.Update.Version, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "bench", Reason: "bench"}); err != nil {
		b.Fatal(err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "bench-outbox", LeaseDuration: time.Minute})
	if err != nil {
		b.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effectLease.Effect.EffectID, WorkerID: "bench-outbox", LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{EffectID: dispatched.Effect.EffectID, WorkerID: "bench-outbox", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}); err != nil {
		b.Fatal(err)
	}
	effectLease, err = store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "bench-outbox", LeaseDuration: time.Minute})
	if err != nil {
		b.Fatal(err)
	}
	dispatched, err = store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effectLease.Effect.EffectID, WorkerID: "bench-outbox", LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{EffectID: dispatched.Effect.EffectID, WorkerID: "bench-outbox", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}); err != nil {
		b.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: prefix + "-artifact", OperationID: prefix + "-operation", OwnerPrincipalID: "owner", Plaintext: []byte(`{"counter":1}`), TTL: time.Minute}); err != nil {
		b.Fatal(err)
	}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: prefix + "-artifact"}); err != nil {
		b.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "bench-plugin", Key: prefix, Value: []byte("1")}); err != nil {
		b.Fatal(err)
	}
	if _, err := store.GetPluginKV(ctx, "bench-plugin", prefix); err != nil {
		b.Fatal(err)
	}
	if _, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"}); err != nil {
		b.Fatal(err)
	}
	if err := store.ValidateReadiness(ctx); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkTask7SQLiteKernelPath(b *testing.B) {
	ctx := context.Background()
	source := task7Source()
	payloadBytes := int64(len(`{"delta":1}`) + len(`{"counter":1}`))
	b.SetBytes(payloadBytes)
	b.ResetTimer()
	var elapsed time.Duration
	var growth int64
	var footprint int64
	for i := range b.N {
		b.StopTimer()
		dbPath := filepath.Join(b.TempDir(), fmt.Sprintf("task7-benchmark-%d.db", i))
		db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: dbPath, KeySource: source, DatabaseIdentity: "task7-benchmark"})
		if err != nil {
			b.Fatal(err)
		}
		store := NewStore(db)
		if err := store.RegisterProjection(task7Projection()); err != nil {
			_ = db.Close()
			b.Fatal(err)
		}
		if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			b.Fatal(err)
		}
		startSize := task7SQLiteSize(dbPath)
		b.StartTimer()
		started := time.Now()
		task7BenchmarkKernelPath(b, store, source, ctx, fmt.Sprintf("bench-%d", i))
		elapsed += time.Since(started)
		if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			b.Fatal(err)
		}
		finalSize := task7SQLiteSize(dbPath)
		growth += finalSize - startSize
		footprint += finalSize
		if err := db.Close(); err != nil {
			b.Fatal(err)
		}
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(dbPath + suffix)
		}
	}
	if b.N > 0 {
		b.ReportMetric(float64(growth)/float64(b.N), "db-growth-bytes/op")
		b.ReportMetric(float64(footprint)/float64(b.N), "db-footprint-bytes/op")
	}
	if elapsed > 0 && b.N > 0 {
		b.ReportMetric(float64(b.N)/elapsed.Seconds(), "ops/s")
	}
}
