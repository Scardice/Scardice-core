package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A process stopped between dispatching an effect and recording the outcome
// leaves a dispatched row whose lease later expires. The next claim has to turn
// it into an ambiguous outcome. With a projector registered (production always
// has some) settlement used to fail on every attempt, and since each claim
// settles expired rows before taking new work, one such row stopped the whole
// outbound queue.
func TestExpiredDispatchIsSettledWhileProjectorsAreRegistered(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "settle.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	clock := &queueTestClock{now: time.Unix(100, 0).UTC()}
	store := NewStore(db, WithClock(clock), WithPayloadCodec(queueTestCodec{}), WithProjection(projectionDescriptor("v1", projectionApply)))
	ctx := context.Background()

	effect := newOutboxTestEffect("stopped-mid-dispatch", "stopped-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
	effect.PayloadExpiresAt = clock.Now().Add(5 * time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	source := []byte(`{"effectId":"stopped-mid-dispatch","operationId":"stopped-operation","endpointId":"endpoint"}`)
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, Events: []NewEvent{{
			EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: source,
			Metadata: Metadata{EventID: "source-event", CommandID: "source-command", CorrelationID: "source-correlation", PrincipalID: "source-principal", OccurredAt: time.Unix(100, 0).UTC()},
		}}}},
		Operations: []OperationUpdate{{OperationID: "stopped-operation", ExpectedVersion: 0, Version: 1, Status: "pending", PrincipalID: "source-principal", ResourceID: effect.EffectID}},
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID}); err != nil {
		t.Fatal(err)
	}

	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "restarted", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim after the lease expired: %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusAmbiguous {
		t.Fatalf("expired dispatch is %q, want %q", row.Status, OutboxStatusAmbiguous)
	}
	events, err := store.Load(ctx, StreamID{AggregateType: "outbound-effect", AggregateID: effect.EffectID}, 0)
	if err != nil || len(events) != 2 || events[1].EventType != "OutboundEffectAmbiguousV1" {
		t.Fatalf("stream after settlement: %#v err=%v", events, err)
	}
}
