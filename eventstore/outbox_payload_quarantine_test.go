package eventstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOutboxCorruptPayloadIsolatedBeforeLease(t *testing.T) {
	for _, corruption := range []string{"ciphertext", "nonce", "dispatched"} {
		t.Run(corruption, func(t *testing.T) {
			ctx := context.Background()
			clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
			source := newTestKeySource()
			store, db := openOutboxRecoveryStore(t, t.TempDir()+"/poison.db", source, clock, &outboxRecoveryIDs{}, true)
			defer db.Close()
			risk := RiskPreDispatchRetryable
			if corruption == "dispatched" {
				risk = RiskProviderIdempotent
			}
			for _, item := range []struct{ id, lane string }{{"bad", "a"}, {"successor", "a"}, {"other", "b"}} {
				if corruption == "dispatched" && item.id == "other" {
					continue
				}
				effect := newOutboxRecoveryEffect(t, source, clock, item.id, item.lane, risk)
				seedOutboxRecoveryEffect(t, store, effect, "op-"+item.id, "event-"+item.id, clock.Now())
			}
			if corruption == "dispatched" {
				lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "old", LeaseDuration: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID}); err != nil {
					t.Fatal(err)
				}
				clock.Advance(2 * time.Minute)
			}
			column, value := "payload_ciphertext", []byte("damaged ciphertext")
			if corruption == "nonce" {
				column, value = "payload_nonce", []byte{}
			}
			if err := db.GORM().Model(&outboxEffectRow{}).Where("effect_id = ?", "bad").Update(column, value).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "quarantine"}); err == nil {
				t.Fatal("corrupt payload dispatched")
			}
			row := loadOutboxRecoveryRow(t, db, "bad")
			want := OutboxStatusFailed
			if corruption == "dispatched" {
				want = OutboxStatusAmbiguous
			}
			if row.Status != want || len(row.PayloadCiphertext) != 0 || row.LeaseExpiry != nil {
				t.Fatalf("poison row not isolated: status=%s ciphertext=%d", row.Status, len(row.PayloadCiphertext))
			}
			if op := loadOutboxRecoveryOperation(t, db, "op-bad"); op.Status != want {
				t.Errorf("operation status=%s, want %s", op.Status, want)
			}
			events := loadOutboxRecoveryEvents(t, store, "bad")
			if len(events) != 2 {
				t.Fatalf("isolation did not append terminal result: %d events", len(events))
			}
			if corruption == "dispatched" {
				seedOutboxRecoveryEffect(t, store, newOutboxRecoveryEffect(t, source, clock, "other", "b", risk), "op-other", "event-other", clock.Now())
			}
			seen := map[string]bool{}
			for range 2 {
				lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "healthy"})
				if err != nil {
					t.Fatal(err)
				}
				seen[lease.Effect.EffectID] = true
			}
			if !seen["successor"] || !seen["other"] {
				t.Fatalf("poison blocked healthy work: %v", seen)
			}
		})
	}
}

type unavailableOutboxRoot struct{ *MemoryKeySource }

func (unavailableOutboxRoot) EncryptionRoot(context.Context, string) ([]byte, error) {
	return nil, ErrKeyUnavailable
}

func TestOutboxTemporaryKeyFailureIsNotCorruption(t *testing.T) {
	ctx := context.Background()
	clock := &outboxRecoveryClock{now: time.Unix(100, 0).UTC()}
	source := newTestKeySource()
	store, db := openOutboxRecoveryStore(t, t.TempDir()+"/key.db", source, clock, &outboxRecoveryIDs{}, true)
	defer db.Close()
	effect := newOutboxRecoveryEffect(t, source, clock, "intact", "lane", RiskPreDispatchRetryable)
	seedOutboxRecoveryEffect(t, store, effect, "op-intact", "event-intact", clock.Now())
	store.codec = &a6PayloadCodec{source: unavailableOutboxRoot{source}}
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("key outage misclassified: %v", err)
	}
	if row := loadOutboxRecoveryRow(t, db, effect.EffectID); row.Status != OutboxStatusPending || row.Version != 1 || len(row.PayloadCiphertext) == 0 {
		t.Fatalf("temporary key outage changed intact row: %#v", row)
	}
	store.codec = &a6PayloadCodec{source: source}
	if lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "restored"}); err != nil || lease.Effect.EffectID != effect.EffectID {
		t.Fatalf("restored key cannot dispatch intact payload: %v", err)
	}
}
