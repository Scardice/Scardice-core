package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type outboxRecoveryClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *outboxRecoveryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *outboxRecoveryClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type outboxRecoveryIDs struct {
	mu sync.Mutex
	n  int
}

func (g *outboxRecoveryIDs) NewID() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return fmt.Sprintf("task6-attempt-%d", g.n), nil
}

func openOutboxRecoveryStore(t testing.TB, path string, clock *outboxRecoveryClock, ids *outboxRecoveryIDs, initialize bool) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, WithClock(clock), WithIDGenerator(ids))
	if initialize {
		if err := store.SetReadiness(context.Background(), Readiness{
			Mode: "import", SchemaVersion: supportedReadinessSchemaVersion, DatabaseIdentity: "db-1",
			CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	return store, db
}

func newOutboxRecoveryEffect(_ testing.TB, _ *outboxRecoveryClock, id, lane, risk string) NewEffect {
	return NewEffect{EffectID: id, EndpointID: "endpoint-1", Lane: lane, EffectType: "send", RiskClass: risk, Status: OutboxStatusPending, Payload: []byte("payload:" + id)}
}

func seedOutboxRecoveryEffect(t testing.TB, store *GORMStore, effect NewEffect, operationID, eventID string, occurredAt time.Time) {
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

func loadOutboxRecoveryRow(t testing.TB, db *Database, effectID string) outboxEffectRow {
	t.Helper()
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func loadOutboxRecoveryOperation(t testing.TB, db *Database, operationID string) operationRow {
	t.Helper()
	var row operationRow
	if err := db.GORM().Where("operation_id = ?", operationID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row
}

func loadOutboxRecoveryEvents(t testing.TB, store *GORMStore, effectID string) []Envelope {
	t.Helper()
	events, err := store.Load(context.Background(), StreamID{AggregateType: "outbound-effect", AggregateID: effectID}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestOutboxRestartAcceptBeforeLeaseIsDispatchable(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
	ids := &outboxRecoveryIDs{}

	path := filepath.Join(t.TempDir(), "task6-restart.db")
	store, db := openOutboxRecoveryStore(t, path, clock, ids, true)
	effect := newOutboxRecoveryEffect(t, clock, "task6-restart-effect", "task6-restart-lane", RiskPreDispatchRetryable)
	seedOutboxRecoveryEffect(t, store, effect, "task6-restart-operation", "task6-restart-event", clock.Now())
	before := loadOutboxRecoveryRow(t, db, effect.EffectID)
	if before.Status != OutboxStatusPending || string(before.Payload) != string(effect.Payload) {
		t.Fatalf("accepted outbox row = %#v", before)
	}
	if operation := loadOutboxRecoveryOperation(t, db, "task6-restart-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("accepted operation = %#v", operation)
	}
	if events := loadOutboxRecoveryEvents(t, store, effect.EffectID); len(events) != 1 || events[0].EventType != "OutboundEffectRequestedV1" {
		t.Fatalf("accepted source events = %#v", events)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, reopenedDB := openOutboxRecoveryStore(t, path, clock, ids, false)
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
	row := loadOutboxRecoveryRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusDispatched || string(row.Payload) != string(effect.Payload) {
		t.Fatalf("reopened dispatched row = %#v", row)
	}
	if operation := loadOutboxRecoveryOperation(t, reopenedDB, "task6-restart-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("reopened operation = %#v", operation)
	}
	if events := loadOutboxRecoveryEvents(t, reopened, effect.EffectID); len(events) != 1 {
		t.Fatalf("restart created duplicate source event: %#v", events)
	}
}

func TestOutboxCrashBeforeDispatchMarkerReclaimsExpiredLease(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(200, 0).UTC()}
	ids := &outboxRecoveryIDs{}

	path := filepath.Join(t.TempDir(), "task6-crash-before-marker.db")
	store, db := openOutboxRecoveryStore(t, path, clock, ids, true)
	effect := newOutboxRecoveryEffect(t, clock, "task6-crash-effect", "task6-crash-lane", RiskPreDispatchRetryable)
	successor := newOutboxRecoveryEffect(t, clock, "task6-crash-successor", "task6-crash-lane", RiskPreDispatchRetryable)
	seedOutboxRecoveryEffect(t, store, effect, "task6-crash-operation", "task6-crash-event", clock.Now())
	seedOutboxRecoveryEffect(t, store, successor, "task6-crash-successor-operation", "task6-crash-successor-event", clock.Now())
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
	if row := loadOutboxRecoveryRow(t, db, effect.EffectID); row.Status != OutboxStatusLeased || row.LeaseEpoch != first.Effect.LeaseEpoch {
		t.Fatalf("leased row before crash = %#v", row)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Advance(11 * time.Second)
	reopened, reopenedDB := openOutboxRecoveryStore(t, path, clock, ids, false)
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
	row := loadOutboxRecoveryRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusLeased || row.LeaseOwner != "task6-recovery-worker" || string(row.Payload) != string(effect.Payload) {
		t.Fatalf("reclaimed durable row = %#v", row)
	}
	if operation := loadOutboxRecoveryOperation(t, reopenedDB, "task6-crash-operation"); operation.Status != "pending" || operation.Version != 1 {
		t.Fatalf("reclaimed operation = %#v", operation)
	}
	if events := loadOutboxRecoveryEvents(t, reopened, effect.EffectID); len(events) != 1 {
		t.Fatalf("reclaim duplicated source event: %#v", events)
	}
}

func TestOutboxManualResolutionSettlesOperationEventAndStoryAtomically(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolution string
		status     string
		eventType  string
		entryCount int
	}{
		{name: "succeeded", resolution: OutboxResolutionSucceeded, status: OutboxStatusSucceeded, eventType: "OutboundEffectSucceededV1", entryCount: 1},
		{name: "failed", resolution: OutboxResolutionFailed, status: OutboxStatusFailed, eventType: "OutboundEffectFailedV1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := &outboxRecoveryClock{now: time.Unix(350, 0).UTC()}
			ids := &outboxRecoveryIDs{}

			path := filepath.Join(t.TempDir(), "task6-manual-resolution.db")
			store, db := openOutboxRecoveryStore(t, path, clock, ids, true)
			defer db.Close()

			effect := newOutboxRecoveryEffect(t, clock, "task6-resolution-"+tc.name, "task6-resolution-lane", RiskNonIdempotentAfterDispatch)
			successor := newOutboxRecoveryEffect(t, clock, "task6-resolution-successor-"+tc.name, "task6-resolution-lane", RiskPreDispatchRetryable)
			operationID := "task6-resolution-operation-" + tc.name
			seedOutboxRecoveryEffect(t, store, effect, operationID, "task6-resolution-event-"+tc.name, clock.Now())
			seedOutboxRecoveryEffect(t, store, successor, "task6-resolution-successor-operation-"+tc.name, "task6-resolution-successor-event-"+tc.name, clock.Now())
			if _, err := store.CreateStoryLog(ctx, "dice", "group", "session"); err != nil {
				t.Fatal(err)
			}
			message := "manually adjudicated " + tc.name
			if err := store.QueueStoryLogIntent(ctx, StoryLogIntent{EffectID: effect.EffectID, Entry: StoryLogEntry{
				DiceID: "dice", GroupID: "group", LogName: "session", Nickname: "Dice", Message: message,
			}}); err != nil {
				t.Fatal(err)
			}

			claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-resolution-provider", LeaseDuration: time.Minute})
			if err != nil || claimed.Effect.EffectID != effect.EffectID {
				t.Fatalf("initial claim = %#v err=%v", claimed, err)
			}
			if _, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
				EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner,
				LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID,
			}); err != nil {
				t.Fatal(err)
			}
			clock.Advance(2 * time.Minute)
			if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-resolution-recovery", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
				t.Fatalf("ambiguous isolation claim err=%v", err)
			}
			ambiguous := loadOutboxRecoveryRow(t, db, effect.EffectID)
			if ambiguous.Status != OutboxStatusAmbiguous || ambiguous.ResolutionReason != "expired-after-dispatch" {
				t.Fatalf("isolated effect = %#v", ambiguous)
			}
			if operation := loadOutboxRecoveryOperation(t, db, operationID); operation.Status != "ambiguous" || operation.Version != 2 {
				t.Fatalf("isolated operation = %#v", operation)
			}
			events, err := store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 2)
			if err != nil || len(events) != 1 || events[0].EventType != "OutboundEffectAmbiguousV1" {
				t.Fatalf("isolated events = %#v err=%v", events, err)
			}
			var intents int64
			if err := db.GORM().Model(&logArchiveIntentRow{}).Where("effect_id = ?", effect.EffectID).Count(&intents).Error; err != nil || intents != 1 {
				t.Fatalf("isolated intent count=%d err=%v", intents, err)
			}
			next, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-resolution-successor", LeaseDuration: time.Minute})
			if err != nil || next.Effect.EffectID != successor.EffectID {
				t.Fatalf("successor claim = %#v err=%v", next, err)
			}

			if _, err := store.ResolveOutbox(ctx, OutboxResolutionRequest{
				EffectID: effect.EffectID, ExpectedVersion: ambiguous.Version, Resolution: OutboxResolutionRetry,
				PrincipalID: "task6-operator", Reason: "retry must stay forbidden",
			}); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("non-idempotent retry resolution err=%v", err)
			}
			principal := "task6-operator-" + tc.name
			reason := "provider evidence " + tc.name
			resolution := OutboxResolutionRequest{
				EffectID: effect.EffectID, ExpectedVersion: ambiguous.Version, Resolution: tc.resolution,
				PrincipalID: principal, Reason: reason,
			}
			result, err := store.ResolveOutbox(ctx, resolution)
			stream := StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}
			if err != nil || result.Version != ambiguous.Version+1 ||
				len(result.OperationIDs) != 1 || result.OperationIDs[0] != operationID ||
				len(result.Events) != 1 || result.Events[0].EventType != tc.eventType ||
				result.StreamVersions[stream] != 3 {
				t.Fatalf("resolution result=%#v err=%v", result, err)
			}
			if _, err := store.ResolveOutbox(ctx, resolution); !errors.Is(err, ErrParticipantConflict) {
				t.Fatalf("replayed resolution err=%v", err)
			}

			resolved := loadOutboxRecoveryRow(t, db, effect.EffectID)
			if resolved.Status != tc.status || resolved.ResolutionPrincipal != principal || resolved.ResolutionReason != reason || resolved.Version != ambiguous.Version+1 {
				t.Fatalf("resolved effect = %#v", resolved)
			}
			if operation := loadOutboxRecoveryOperation(t, db, operationID); operation.Status != tc.status || operation.Version != 3 {
				t.Fatalf("resolved operation = %#v", operation)
			}
			events, err = store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 2)
			if err != nil || len(events) != 2 || events[1].EventType != tc.eventType || events[1].Metadata.PrincipalID != principal {
				t.Fatalf("resolved events = %#v err=%v", events, err)
			}
			var payload struct {
				Status string `json:"status"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(events[1].Payload, &payload); err != nil || payload.Status != tc.status || payload.Reason != reason {
				t.Fatalf("resolved event payload=%#v err=%v", payload, err)
			}
			if err := db.GORM().Model(&logArchiveIntentRow{}).Where("effect_id = ?", effect.EffectID).Count(&intents).Error; err != nil || intents != 0 {
				t.Fatalf("resolved intent count=%d err=%v", intents, err)
			}
			entries, err := store.GetStoryLogEntries(ctx, "dice", "group", "session")
			if err != nil || len(entries) != tc.entryCount || (tc.entryCount == 1 && entries[0].Message != message) {
				t.Fatalf("resolved story entries=%#v err=%v", entries, err)
			}
			markedNext, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
				EffectID: next.Effect.EffectID, WorkerID: next.Effect.LeaseOwner,
				LeaseEpoch: next.Effect.LeaseEpoch, AttemptID: next.Effect.AttemptID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{
				EffectID: markedNext.Effect.EffectID, WorkerID: markedNext.Effect.LeaseOwner, LeaseEpoch: markedNext.Effect.LeaseEpoch,
				AttemptID: markedNext.Effect.AttemptID, Status: OutboxStatusSucceeded,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-resolution-replay-check", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
				t.Fatalf("resolved effect was replayed: %v", err)
			}
		})
	}
}

func TestOutboxProviderIdempotentRetryKeepsIdentityAndOrdering(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(400, 0).UTC()}
	ids := &outboxRecoveryIDs{}

	path := filepath.Join(t.TempDir(), "task6-provider-idempotent.db")
	store, db := openOutboxRecoveryStore(t, path, clock, ids, true)
	effect := newOutboxRecoveryEffect(t, clock, "task6-idempotent-effect", "task6-idempotent-lane", RiskProviderIdempotent)
	successor := newOutboxRecoveryEffect(t, clock, "task6-idempotent-successor", "task6-idempotent-lane", RiskProviderIdempotent)
	seedOutboxRecoveryEffect(t, store, effect, "task6-idempotent-operation", "task6-idempotent-event", clock.Now())
	seedOutboxRecoveryEffect(t, store, successor, "task6-idempotent-successor-operation", "task6-idempotent-successor-event", clock.Now())
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
	reopened, reopenedDB := openOutboxRecoveryStore(t, path, clock, ids, false)
	defer reopenedDB.Close()
	retry, err := reopened.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "task6-idempotent-retry-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if retry.Effect.EffectID != first.Effect.EffectID || retry.Effect.EffectID != dispatched.Effect.EffectID || retry.Effect.Status != OutboxStatusLeased || retry.Effect.LeaseEpoch != first.Effect.LeaseEpoch+1 || retry.Effect.RetryCount != 1 || string(retry.Effect.Payload) != string(first.Effect.Payload) {
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
	row := loadOutboxRecoveryRow(t, reopenedDB, effect.EffectID)
	if row.Status != OutboxStatusSucceeded || string(row.Payload) != string(effect.Payload) || row.ProviderMessageID != "provider-message-1" {
		t.Fatalf("idempotent completed row = %#v", row)
	}
	if events := loadOutboxRecoveryEvents(t, reopened, effect.EffectID); len(events) != 1 {
		t.Fatalf("idempotent retry duplicated source event: %#v", events)
	}
}

func TestOutboxTerminalCompletionRetryIsIdempotentWithoutSecondEvent(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(500, 0).UTC()}
	ids := &outboxRecoveryIDs{}

	path := filepath.Join(t.TempDir(), "task6-terminal-retry.db")
	store, db := openOutboxRecoveryStore(t, path, clock, ids, true)
	effect := newOutboxRecoveryEffect(t, clock, "task6-terminal-effect", "task6-terminal-lane", RiskProviderIdempotent)
	seedOutboxRecoveryEffect(t, store, effect, "task6-terminal-operation", "task6-terminal-event", clock.Now())
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
	rowAfterFirst := loadOutboxRecoveryRow(t, db, effect.EffectID)
	if rowAfterFirst.Status != OutboxStatusSucceeded || rowAfterFirst.Version != first.Version || rowAfterFirst.CompletedAt == nil || rowAfterFirst.LeaseExpiry != nil || string(rowAfterFirst.Payload) != string(effect.Payload) {
		t.Fatalf("first terminal completion row = %#v result=%#v", rowAfterFirst, first)
	}
	opAfterFirst := loadOutboxRecoveryOperation(t, db, "task6-terminal-operation")
	eventsAfterFirst := loadOutboxRecoveryEvents(t, store, effect.EffectID)
	if len(eventsAfterFirst) != 1 || eventsAfterFirst[0].EventType != "OutboundEffectRequestedV1" {
		t.Fatalf("first terminal completion events = %#v", eventsAfterFirst)
	}

	second, err := store.CompleteOutbox(ctx, completion)
	if err != nil || !second.Idempotent || second.Version != first.Version {
		t.Fatalf("terminal completion retry = %#v err=%v", second, err)
	}
	rowAfterRetry := loadOutboxRecoveryRow(t, db, effect.EffectID)
	if rowAfterRetry.Status != rowAfterFirst.Status || rowAfterRetry.Version != rowAfterFirst.Version || rowAfterRetry.ResultCode != rowAfterFirst.ResultCode || rowAfterRetry.ProviderMessageID != rowAfterFirst.ProviderMessageID || string(rowAfterRetry.Payload) != string(effect.Payload) {
		t.Fatalf("terminal retry changed row = %#v", rowAfterRetry)
	}
	opAfterRetry := loadOutboxRecoveryOperation(t, db, "task6-terminal-operation")
	if opAfterRetry.Version != opAfterFirst.Version || opAfterRetry.Status != opAfterFirst.Status {
		t.Fatalf("terminal retry changed operation = %#v before=%#v", opAfterRetry, opAfterFirst)
	}
	eventsAfterRetry := loadOutboxRecoveryEvents(t, store, effect.EffectID)
	if len(eventsAfterRetry) != len(eventsAfterFirst) || eventsAfterRetry[0].EventID != eventsAfterFirst[0].EventID {
		t.Fatalf("terminal retry appended result event: before=%#v after=%#v", eventsAfterFirst, eventsAfterRetry)
	}
}
