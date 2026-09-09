package eventstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type task6OutboxClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *task6OutboxClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *task6OutboxClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type task6OutboxIDs struct {
	mu sync.Mutex
	n  int
}

func (g *task6OutboxIDs) NewID() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return fmt.Sprintf("task6-attempt-%d", g.n), nil
}

func task6OutboxOpen(t testing.TB, path string, source *MemoryKeySource, clock *task6OutboxClock, ids *task6OutboxIDs, initialize bool) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, WithKeySource(source), WithClock(clock), WithIDGenerator(ids))
	if initialize {
		if err := store.SetReadiness(context.Background(), Readiness{
			Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
			EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
			TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return store, db
}

func task6OutboxEffect(t testing.TB, source *MemoryKeySource, clock *task6OutboxClock, id, lane, risk string) NewEffect {
	t.Helper()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "outbox/v1", id, "endpoint-1", 1, []byte("payload:"+id))
	if err != nil {
		t.Fatal(err)
	}
	return NewEffect{
		EffectID: id, EndpointID: "endpoint-1", LaneHMAC: []byte(lane), EffectType: "send",
		RiskClass: risk, Status: OutboxStatusPending, PayloadCiphertext: ciphertext, PayloadNonce: nonce,
		PayloadEncryptionKeyID: keyID, PayloadExpiresAt: clock.Now().Add(24 * time.Hour),
	}
}

func task6OutboxSeed(t testing.TB, store *GORMStore, effect NewEffect, operationID, eventID string, occurredAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	payload := []byte(fmt.Sprintf(`{"effectId":%q,"operationId":%q,"endpointId":%q}`, effect.EffectID, operationID, effect.EndpointID))
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []NewEvent{{
			EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: payload,
			Metadata: Metadata{EventID: eventID, CommandID: eventID + "-command", CorrelationID: eventID + "-correlation", PrincipalID: "task6-principal", Producer: "task6-test", OccurredAt: occurredAt},
		}}}},
		Operations: []OperationUpdate{{OperationID: operationID, ExpectedVersion: 0, Version: 1, Kind: "outbound-effect", Status: "pending", PrincipalID: "task6-principal", ResourceID: effect.EffectID, IdempotencyScope: "task6", IdempotencyKey: operationID, RequestDigest: []byte("task6-request")}},
	}); err != nil {
		t.Fatal(err)
	}
}

func task6OutboxRow(t testing.TB, db *Database, effectID string) outboxEffectRow {
	t.Helper()
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func task6OperationRow(t testing.TB, db *Database, operationID string) operationRow {
	t.Helper()
	var row operationRow
	if err := db.GORM().Where("operation_id = ?", operationID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func task6OutboxEvents(t testing.TB, store *GORMStore, effectID string) []Envelope {
	t.Helper()
	events, err := store.Load(context.Background(), StreamID{AggregateType: "outbound-effect", AggregateID: effectID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestTask6OutboxRestartAcceptBeforeLeaseIsDispatchable(t *testing.T) {
	ctx := context.Background()
	clock := &task6OutboxClock{now: time.Unix(100, 0).UTC()}
	ids := &task6OutboxIDs{}
	source := task6Source()
	path := filepath.Join(t.TempDir(), "task6-restart.db")
	store, db := task6OutboxOpen(t, path, source, clock, ids, true)
	effect := task6OutboxEffect(t, source, clock, "task6-restart-effect", "task6-restart-lane", RiskPreDispatchRetryable)
	task6OutboxSeed(t, store, effect, "task6-restart-operation", "task6-restart-event", clock.Now())
	before := task6OutboxRow(t, db, effect.EffectID)
	if before.Status != OutboxStatusPending || len(before.PayloadCiphertext) == 0 || len(before.PayloadNonce) == 0 {
		t.Fatalf("accepted outbox row = %#v", before)
	}
	if operation := task6OperationRow(t, db, "task6-restart-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("accepted operation = %#v", operation)
	}
	if events := task6OutboxEvents(t, store, effect.EffectID); len(events) != 1 || events[0].EventType != "OutboundEffectRequestedV1" {
		t.Fatalf("accepted source events = %#v", events)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, reopenedDB := task6OutboxOpen(t, path, source, clock, ids, false)
	defer reopenedDB.Close()
	lease, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-restart-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if lease.Effect.EffectID != effect.EffectID || lease.Effect.Status != OutboxStatusLeased || lease.Effect.OrderingSequence != 1 {
		t.Fatalf("reopened claim = %#v", lease)
	}
	dispatched, err := reopened.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.Effect.Status != OutboxStatusDispatched || dispatched.Effect.EffectID != effect.EffectID {
		t.Fatalf("reopened dispatch marker = %#v", dispatched)
	}
	row := task6OutboxRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusDispatched || len(row.PayloadCiphertext) == 0 || len(row.PayloadNonce) == 0 {
		t.Fatalf("reopened dispatched row = %#v", row)
	}
	if operation := task6OperationRow(t, reopenedDB, "task6-restart-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("reopened operation = %#v", operation)
	}
	if events := task6OutboxEvents(t, reopened, effect.EffectID); len(events) != 1 {
		t.Fatalf("restart created duplicate source event: %#v", events)
	}
}

func TestTask6OutboxCrashBeforeDispatchMarkerReclaimsExpiredLease(t *testing.T) {
	ctx := context.Background()
	clock := &task6OutboxClock{now: time.Unix(200, 0).UTC()}
	ids := &task6OutboxIDs{}
	source := task6Source()
	path := filepath.Join(t.TempDir(), "task6-crash-before-marker.db")
	store, db := task6OutboxOpen(t, path, source, clock, ids, true)
	effect := task6OutboxEffect(t, source, clock, "task6-crash-effect", "task6-crash-lane", RiskPreDispatchRetryable)
	successor := task6OutboxEffect(t, source, clock, "task6-crash-successor", "task6-crash-lane", RiskPreDispatchRetryable)
	task6OutboxSeed(t, store, effect, "task6-crash-operation", "task6-crash-event", clock.Now())
	task6OutboxSeed(t, store, successor, "task6-crash-successor-operation", "task6-crash-successor-event", clock.Now())
	first, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-crash-worker", LeaseDuration: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if first.Effect.EffectID != effect.EffectID || first.Effect.Status != OutboxStatusLeased {
		t.Fatalf("pre-marker claim = %#v", first)
	}
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-other-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lane bypass while lease active = %v", err)
	}
	if row := task6OutboxRow(t, db, effect.EffectID); row.Status != OutboxStatusLeased || row.LeaseEpoch != first.Effect.LeaseEpoch {
		t.Fatalf("leased row before crash = %#v", row)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Advance(11 * time.Second)
	reopened, reopenedDB := task6OutboxOpen(t, path, source, clock, ids, false)
	defer reopenedDB.Close()
	reclaimed, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-recovery-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.Effect.EffectID != effect.EffectID || reclaimed.Effect.Status != OutboxStatusLeased || reclaimed.Effect.LeaseEpoch != first.Effect.LeaseEpoch+1 || reclaimed.Effect.AttemptID == first.Effect.AttemptID || reclaimed.Effect.RetryCount != 1 {
		t.Fatalf("reclaimed lease = %#v", reclaimed)
	}
	if _, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-successor-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("successor bypassed reclaimed lease = %v", err)
	}
	row := task6OutboxRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusLeased || row.LeaseOwner != "task6-recovery-worker" || len(row.PayloadCiphertext) == 0 || len(row.PayloadNonce) == 0 {
		t.Fatalf("reclaimed durable row = %#v", row)
	}
	if operation := task6OperationRow(t, reopenedDB, "task6-crash-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("reclaimed operation = %#v", operation)
	}
	if events := task6OutboxEvents(t, reopened, effect.EffectID); len(events) != 1 {
		t.Fatalf("reclaim duplicated source event: %#v", events)
	}
}

func TestTask6OutboxCrashAfterNonIdempotentDispatchBlocksLaneAndScrubs(t *testing.T) {
	ctx := context.Background()
	clock := &task6OutboxClock{now: time.Unix(300, 0).UTC()}
	ids := &task6OutboxIDs{}
	source := task6Source()
	path := filepath.Join(t.TempDir(), "task6-crash-after-dispatch.db")
	store, db := task6OutboxOpen(t, path, source, clock, ids, true)
	effect := task6OutboxEffect(t, source, clock, "task6-ambiguous-effect", "task6-ambiguous-lane", RiskNonIdempotentAfterDispatch)
	successor := task6OutboxEffect(t, source, clock, "task6-ambiguous-successor", "task6-ambiguous-lane", RiskPreDispatchRetryable)
	task6OutboxSeed(t, store, effect, "task6-ambiguous-operation", "task6-ambiguous-event", clock.Now())
	task6OutboxSeed(t, store, successor, "task6-ambiguous-successor-operation", "task6-ambiguous-successor-event", clock.Now())
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-provider-worker", LeaseDuration: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.Effect.Status != OutboxStatusDispatched {
		t.Fatalf("dispatch marker = %#v", dispatched)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Advance(11 * time.Second)
	reopened, reopenedDB := task6OutboxOpen(t, path, source, clock, ids, false)
	defer reopenedDB.Close()
	if _, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-recovery-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired non-idempotent effect was provider-eligible: %v", err)
	}
	row := task6OutboxRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusAmbiguous || row.LeaseExpiry != nil || row.ResolutionReason != "expired-after-dispatch" || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("expired non-idempotent row = %#v", row)
	}
	if operation := task6OperationRow(t, reopenedDB, "task6-ambiguous-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("ambiguous recovery operation = %#v", operation)
	}
	if events := task6OutboxEvents(t, reopened, effect.EffectID); len(events) != 1 || events[0].EventType != "OutboundEffectRequestedV1" {
		t.Fatalf("ambiguous recovery events = %#v", events)
	}
	if _, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-successor-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("successor bypassed ambiguous lane = %v", err)
	}
}

func TestTask6OutboxProviderIdempotentRetryKeepsIdentityAndOrdering(t *testing.T) {
	ctx := context.Background()
	clock := &task6OutboxClock{now: time.Unix(400, 0).UTC()}
	ids := &task6OutboxIDs{}
	source := task6Source()
	path := filepath.Join(t.TempDir(), "task6-provider-idempotent.db")
	store, db := task6OutboxOpen(t, path, source, clock, ids, true)
	effect := task6OutboxEffect(t, source, clock, "task6-idempotent-effect", "task6-idempotent-lane", RiskProviderIdempotent)
	successor := task6OutboxEffect(t, source, clock, "task6-idempotent-successor", "task6-idempotent-lane", RiskProviderIdempotent)
	task6OutboxSeed(t, store, effect, "task6-idempotent-operation", "task6-idempotent-event", clock.Now())
	task6OutboxSeed(t, store, successor, "task6-idempotent-successor-operation", "task6-idempotent-successor-event", clock.Now())
	first, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-idempotent-worker", LeaseDuration: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: first.Effect.LeaseOwner, LeaseEpoch: first.Effect.LeaseEpoch, AttemptID: first.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.Effect.Status != OutboxStatusDispatched {
		t.Fatalf("idempotent dispatch marker = %#v", dispatched)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Advance(11 * time.Second)
	reopened, reopenedDB := task6OutboxOpen(t, path, source, clock, ids, false)
	defer reopenedDB.Close()
	retry, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-idempotent-retry-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if retry.Effect.EffectID != first.Effect.EffectID || retry.Effect.EffectID != dispatched.Effect.EffectID || retry.Effect.Status != OutboxStatusLeased || retry.Effect.LeaseEpoch != first.Effect.LeaseEpoch+1 || retry.Effect.RetryCount != 1 || len(retry.Effect.PayloadCiphertext) == 0 || len(retry.Effect.PayloadNonce) == 0 {
		t.Fatalf("idempotent retry lease = %#v", retry)
	}
	if _, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-idempotent-successor-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idempotent successor bypassed retry = %v", err)
	}
	markedAgain, err := reopened.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: retry.Effect.EffectID, WorkerID: retry.Effect.LeaseOwner, LeaseEpoch: retry.Effect.LeaseEpoch, AttemptID: retry.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.CompleteOutbox(ctx, OutboxCompletionRequest{EffectID: markedAgain.Effect.EffectID, WorkerID: markedAgain.Effect.LeaseOwner, LeaseEpoch: markedAgain.Effect.LeaseEpoch, AttemptID: markedAgain.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "provider-accepted", ProviderMessageID: "provider-message-1"}); err != nil {
		t.Fatal(err)
	}
	next, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-idempotent-successor-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if next.Effect.EffectID != successor.EffectID || next.Effect.OrderingSequence != 2 {
		t.Fatalf("successor after idempotent completion = %#v", next)
	}
	row := task6OutboxRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusSucceeded || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 || row.ProviderMessageID != "provider-message-1" {
		t.Fatalf("idempotent completed row = %#v", row)
	}
	if events := task6OutboxEvents(t, reopened, effect.EffectID); len(events) != 1 {
		t.Fatalf("idempotent retry duplicated source event: %#v", events)
	}
}

func TestTask6OutboxTerminalCompletionRetryIsIdempotentWithoutSecondEvent(t *testing.T) {
	ctx := context.Background()
	clock := &task6OutboxClock{now: time.Unix(500, 0).UTC()}
	ids := &task6OutboxIDs{}
	source := task6Source()
	path := filepath.Join(t.TempDir(), "task6-terminal-retry.db")
	store, db := task6OutboxOpen(t, path, source, clock, ids, true)
	effect := task6OutboxEffect(t, source, clock, "task6-terminal-effect", "task6-terminal-lane", RiskProviderIdempotent)
	task6OutboxSeed(t, store, effect, "task6-terminal-operation", "task6-terminal-event", clock.Now())
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-terminal-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	completion := OutboxCompletionRequest{EffectID: effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok", ProviderMessageID: "provider-terminal-1"}
	first, err := store.CompleteOutbox(ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	rowAfterFirst := task6OutboxRow(t, db, effect.EffectID)
	if rowAfterFirst.Status != OutboxStatusSucceeded || rowAfterFirst.Version != first.Version || rowAfterFirst.CompletedAt == nil || rowAfterFirst.LeaseExpiry != nil || len(rowAfterFirst.PayloadCiphertext) != 0 || len(rowAfterFirst.PayloadNonce) != 0 {
		t.Fatalf("first terminal completion row = %#v result=%#v", rowAfterFirst, first)
	}
	opAfterFirst := task6OperationRow(t, db, "task6-terminal-operation")
	eventsAfterFirst := task6OutboxEvents(t, store, effect.EffectID)
	if len(eventsAfterFirst) != 1 || eventsAfterFirst[0].EventType != "OutboundEffectRequestedV1" {
		t.Fatalf("first terminal completion events = %#v", eventsAfterFirst)
	}

	second, err := store.CompleteOutbox(ctx, completion)
	if err != nil || !second.Idempotent || second.Version != first.Version {
		t.Fatalf("terminal completion retry = %#v err=%v", second, err)
	}
	rowAfterRetry := task6OutboxRow(t, db, effect.EffectID)
	if rowAfterRetry.Status != rowAfterFirst.Status || rowAfterRetry.Version != rowAfterFirst.Version || rowAfterRetry.ResultCode != rowAfterFirst.ResultCode || rowAfterRetry.ProviderMessageID != rowAfterFirst.ProviderMessageID || len(rowAfterRetry.PayloadCiphertext) != 0 || len(rowAfterRetry.PayloadNonce) != 0 {
		t.Fatalf("terminal retry changed row = %#v", rowAfterRetry)
	}
	opAfterRetry := task6OperationRow(t, db, "task6-terminal-operation")
	if opAfterRetry.Version != opAfterFirst.Version || opAfterRetry.Status != opAfterFirst.Status {
		t.Fatalf("terminal retry changed operation = %#v before=%#v", opAfterRetry, opAfterFirst)
	}
	eventsAfterRetry := task6OutboxEvents(t, store, effect.EffectID)
	if len(eventsAfterRetry) != len(eventsAfterFirst) || eventsAfterRetry[0].EventID != eventsAfterFirst[0].EventID {
		t.Fatalf("terminal retry appended result event: before=%#v after=%#v", eventsAfterFirst, eventsAfterRetry)
	}
}
