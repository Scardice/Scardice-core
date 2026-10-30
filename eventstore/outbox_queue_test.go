package eventstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestQuarantineOutboxScrubsLeaseAndAppendsAuditedFailure(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	effect := newOutboxTestEffect("quarantine-effect", "quarantine-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	sourcePayload := []byte(`{"effectId":"quarantine-effect","operationId":"quarantine-operation","endpointId":"endpoint"}`)
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []NewEvent{{
			EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: sourcePayload,
			Metadata: Metadata{EventID: "source-event", CommandID: "source-command", CorrelationID: "source-correlation", PrincipalID: "source-principal", OccurredAt: time.Unix(100, 0).UTC()},
		}}}},
		Operations: []OperationUpdate{{OperationID: "quarantine-operation", ExpectedVersion: 0, Version: 1, Status: "pending", PrincipalID: "source-principal", ResourceID: effect.EffectID}},
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "quarantine-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("mode", "import").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.QuarantineOutbox(ctx, OutboxQuarantineRequest{
		EffectID: lease.Effect.EffectID, ExpectedVersion: lease.Effect.Version,
		WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
		ErrorCode: "raw-token-/secret", Reason: "raw /path/token",
	}); err != nil {
		t.Fatal(err)
	}
	var outbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&outbox).Error; err != nil {
		t.Fatal(err)
	}
	if outbox.Status != OutboxStatusFailed || outbox.LeaseExpiry != nil || len(outbox.PayloadCiphertext) != 0 || len(outbox.PayloadNonce) != 0 {
		t.Fatalf("quarantined outbox = %#v", outbox)
	}
	if outbox.ErrorCode == "raw-token-/secret" || outbox.ResolutionReason == "raw /path/token" {
		t.Fatalf("quarantine retained raw diagnostic: %#v", outbox)
	}
	var operation operationRow
	if err := db.GORM().Where("operation_id = ?", "quarantine-operation").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if operation.Status != "failed" || operation.Version != 2 || operation.ErrorCode == "" {
		t.Fatalf("quarantined operation = %#v", operation)
	}
	events, err := store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 2)
	if err != nil || len(events) != 1 {
		t.Fatalf("quarantine result events=%#v err=%v", events, err)
	}
	var readiness storeReadinessRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&readiness).Error; err != nil {
		t.Fatal(err)
	}
	if readiness.TerminalGlobalPosition != events[0].GlobalPosition || readiness.TerminalProjectionPosition != events[0].GlobalPosition {
		t.Fatalf("import readiness terminals = global %d/projection %d, event %d", readiness.TerminalGlobalPosition, readiness.TerminalProjectionPosition, events[0].GlobalPosition)
	}
	if events[0].EventType != "OutboundEffectFailedV1" || string(events[0].Payload) == "" || string(events[0].Payload) == string(sourcePayload) {
		t.Fatalf("quarantine result event = %#v", events[0])
	}
	if bytes.Contains(events[0].Payload, []byte("raw-token")) || bytes.Contains(events[0].Payload, []byte("/path/token")) {
		t.Fatalf("quarantine event retained raw diagnostic: %s", events[0].Payload)
	}
}
func TestQuarantineOutboxAfterDispatchSettlesAmbiguous(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	effect := newOutboxTestEffect("quarantine-dispatched", "quarantine-dispatched-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []NewEvent{{
			EventType: "OutboundEffectRequestedV1", SchemaVersion: 1,
			Payload:  []byte(`{"effectId":"quarantine-dispatched","operationId":"quarantine-dispatched-operation","endpointId":"endpoint"}`),
			Metadata: Metadata{EventID: "source-event", CommandID: "source-command", CorrelationID: "source-correlation", PrincipalID: "source-principal", OccurredAt: time.Unix(100, 0).UTC()},
		}}}},
		Operations: []OperationUpdate{{OperationID: "quarantine-dispatched-operation", ExpectedVersion: 0, Version: 1, Status: "pending", PrincipalID: "source-principal", ResourceID: effect.EffectID}},
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "quarantine-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	req := OutboxQuarantineRequest{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, ErrorCode: "terminal-persistence", Reason: "terminal persistence failed"}
	if _, err := store.QuarantineOutbox(ctx, req); err != nil {
		t.Fatal(err)
	}
	var outbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&outbox).Error; err != nil {
		t.Fatal(err)
	}
	if outbox.Status != OutboxStatusAmbiguous {
		t.Fatalf("quarantined dispatched outbox status = %q, want %q", outbox.Status, OutboxStatusAmbiguous)
	}
	var operation operationRow
	if err := db.GORM().Where("operation_id = ?", "quarantine-dispatched-operation").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if operation.Status != "ambiguous" {
		t.Fatalf("quarantined dispatched operation status = %q, want ambiguous", operation.Status)
	}
	events, err := store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 2)
	if err != nil || len(events) != 1 {
		t.Fatalf("quarantine events = %#v, err = %v", events, err)
	}
	if events[0].EventType != "OutboundEffectAmbiguousV1" {
		t.Fatalf("quarantine event type = %q, want OutboundEffectAmbiguousV1", events[0].EventType)
	}
	if _, err := store.QuarantineOutbox(ctx, req); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale quarantine err = %v, want stale lease", err)
	}
}
func TestPreDispatchRequeueRequiresNarrowLeaseAPI(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	effect := newOutboxTestEffect("pre-requeue", "lane-pre")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(context.Background(), UnitOfWork{Effects: []NewEffect{{EffectID: dispatched.Effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Version: dispatched.Effect.Version + 1, Status: OutboxStatusPending, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}}})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("generic pending transition err=%v", err)
	}
	result, err := store.RequeuePreDispatch(context.Background(), OutboxPreDispatchRequeueRequest{EffectID: dispatched.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, RetryCount: 1, NextAttemptAt: time.Now().Add(time.Minute)})
	if err != nil || result.Version != dispatched.Effect.Version+1 {
		t.Fatalf("narrow requeue result=%#v err=%v", result, err)
	}
	if _, err := store.RequeuePreDispatch(context.Background(), OutboxPreDispatchRequeueRequest{EffectID: dispatched.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale requeue err=%v", err)
	}
}
func TestOutboxLeaseDispatchCompletionAndStale(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("effect-1", "lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: "worker", LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.Effect.Status != OutboxStatusDispatched || dispatched.Effect.AttemptID == claimed.Effect.AttemptID {
		t.Fatalf("dispatch marker = %#v", dispatched)
	}
	if _, err := store.CompleteOutbox(context.Background(), OutboxCompletionRequest{EffectID: "effect-1", WorkerID: "stale", LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale completion err=%v", err)
	}
	completion := OutboxCompletionRequest{EffectID: "effect-1", WorkerID: "worker", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}
	if _, err := store.CompleteOutbox(context.Background(), completion); err != nil {
		t.Fatal(err)
	}
	if result, err := store.CompleteOutbox(context.Background(), completion); err != nil || !result.Idempotent {
		t.Fatalf("terminal completion idempotence = %#v err=%v", result, err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "effect-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusSucceeded || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("terminal outbox row = %#v", row)
	}
}
func TestOutboxNonIdempotentDispatchExpiryBecomesAmbiguous(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	effect := newOutboxTestEffect("ambiguous-effect", "ambiguous-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: "worker", LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("ambiguous claim err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous {
		t.Fatalf("status = %q, want %q", row.Status, OutboxStatusAmbiguous)
	}
	if _, err := store.ResolveOutbox(context.Background(), OutboxResolutionRequest{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version + 1, Resolution: OutboxResolutionSucceeded, PrincipalID: "operator", Reason: "provider checked"}); err != nil {
		t.Fatal(err)
	}
}
func TestOutboxAcceptanceDedupeDoesNotAdvanceLane(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	first, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("dedupe-effect", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("dedupe-effect", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Deduplicated || duplicate.OrderingSequence != first.OrderingSequence {
		t.Fatalf("duplicate result = %#v", duplicate)
	}
	second, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("dedupe-effect-2", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	if second.OrderingSequence != 2 {
		t.Fatalf("lane after duplicate = %d", second.OrderingSequence)
	}
}
func TestOutboxIngressRejectsPayloadTTLBypass(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	effect := newOutboxTestEffect("ttl-effect", "ttl-lane")
	expired := newOutboxTestEffect("ttl-expired-effect", "ttl-expired-lane")
	expired.PayloadExpiresAt = clock.Now().Add(-time.Second)
	if _, err := store.AcceptOutbox(context.Background(), expired); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox ttl err = %v", err)
	}
	effect.PayloadExpiresAt = clock.Now().Add(InboxPayloadTTL + time.Second)
	if _, err := store.AcceptOutbox(context.Background(), effect); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("outbox ttl err = %v", err)
	}
}
func TestOutboxDispatchedExpiryScrubsBeforeAmbiguity(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	effect := newOutboxTestEffect("dispatched-expired", "dispatched-expired-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("dispatched expiry err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 || row.ScrubbedAt == nil {
		t.Fatalf("dispatched expiry row = %#v", row)
	}
}
func TestOutboxLeaseExpiryIsolatesNonIdempotentDispatchAndAdvancesLane(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	effect := newOutboxTestEffect("lease-only-scrub", "lease-only-scrub-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(5 * time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
		EffectID:   effect.EffectID,
		WorkerID:   claimed.Effect.LeaseOwner,
		LeaseEpoch: claimed.Effect.LeaseEpoch,
		AttemptID:  claimed.Effect.AttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	blocked := newOutboxTestEffect("lease-only-scrub-followup", "lease-only-scrub-lane")
	if _, err := store.AcceptOutbox(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease-only expiry claim err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Version != dispatched.Effect.Version+1 || row.Status != OutboxStatusAmbiguous || row.LeaseExpiry != nil ||
		row.ErrorCode != "dispatch-lease-expired" || row.ResolutionReason != "expired-after-dispatch" ||
		len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 || row.ScrubbedAt == nil {
		t.Fatalf("lease-only expiry row = %#v", row)
	}
	next, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "third", LeaseDuration: time.Minute})
	if err != nil || next.Effect.EffectID != blocked.EffectID {
		t.Fatalf("successor after isolated ambiguity = %#v err=%v", next, err)
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
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "replay-check", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("isolated outbox was replayed: %v", err)
	}
}
func TestOutboxUpdateDispatchedExpirySettlesAmbiguous(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	effect := newOutboxTestEffect("update-dispatched-expired", "update-dispatched-expired-lane")
	effect.RiskClass = RiskProviderIdempotent
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Status: OutboxStatusAmbiguous, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("dispatched update expiry err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous || row.CompletedAt == nil || row.ErrorCode != "payload-expired" ||
		len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("dispatched update expiry row = %#v", row)
	}
}
func TestOutboxObservedExpiryMarksNonIdempotentDispatchAmbiguous(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	effect := newOutboxTestEffect("observed-expired-nonidempotent", "observed-expired-nonidempotent-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "observed-expired-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Status: OutboxStatusAmbiguous, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("non-idempotent observed expiry err = %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous || row.LeaseExpiry != nil || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("non-idempotent observed expiry row = %#v", row)
	}
	version := row.Version
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: version, Status: OutboxStatusPending}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("ambiguous replay err = %v", err)
	}
	var replay outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&replay).Error; err != nil {
		t.Fatal(err)
	}
	if replay.Version != version {
		t.Fatalf("ambiguous replay changed version from %d to %d", version, replay.Version)
	}
}
func TestPublicUpdateCannotCompleteDispatchedEffect(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	effect := newOutboxTestEffect("public-dispatched-completion", "public-dispatched-completion-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "public-dispatched-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: dispatched.Effect.Version, Status: OutboxStatusSucceeded, LeaseOwner: dispatched.Effect.LeaseOwner, LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("dispatched generic completion err = %v", err)
	}
}
