package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type task5Clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *task5Clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *task5Clock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type task5Codec struct{}

func (task5Codec) Encrypt(_ context.Context, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "test-key", nil
}
func (task5Codec) Decrypt(_ context.Context, ciphertext, _ []byte, _ string) ([]byte, error) {
	const prefix = "sealed:"
	if len(ciphertext) < len(prefix) || string(ciphertext[:len(prefix)]) != prefix {
		return nil, errors.New("bad ciphertext")
	}
	return append([]byte(nil), ciphertext[len(prefix):]...), nil
}

func task5Store(t *testing.T) (*GORMStore, *Database, *task5Clock) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task5.db")})
	if err != nil {
		t.Fatal(err)
	}
	clock := &task5Clock{now: time.Unix(100, 0).UTC()}
	return NewStore(db, WithClock(clock), WithPayloadCodec(task5Codec{})), db, clock
}

func task5Inbox(id, provider, lane string) InboxUpdate {
	return InboxUpdate{InboxID: id, EndpointID: "endpoint", ProviderEventKey: provider, LaneHMAC: []byte(lane), Status: InboxStatusPending, PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "digest-key"}
}

func task5Effect(id, lane string) NewEffect {
	return NewEffect{EffectID: id, EndpointID: "endpoint", LaneHMAC: []byte(lane), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "digest-key"}
}

func TestInboxAcceptanceDedupeAndLaneAllocation(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	first, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-1", "provider-1", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.OrderingSequence != 1 || first.Deduplicated {
		t.Fatalf("first result = %#v", first)
	}
	second, err := store.AcceptInbox(context.Background(), task5Inbox("different-id", "provider-1", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduplicated || second.OrderingSequence != 1 || len(second.InboxIDs) != 1 || second.InboxIDs[0] != "inbox-1" {
		t.Fatalf("dedupe result = %#v", second)
	}
	third, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-2", "provider-2", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if third.OrderingSequence != 2 {
		t.Fatalf("caller sequence bypassed allocation: %#v", third)
	}
}

func TestInboxOrderingAndResolution(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	if _, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-1", "p1", "lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(context.Background(), task5Inbox("inbox-2", "p2", "lane")); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil || first.Update.InboxID != "inbox-1" {
		t.Fatalf("first claim = %#v err=%v", first, err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("predecessor claim err=%v", err)
	}
	started := first.Update
	started.ExpectedVersion = first.Update.Version
	started.Status = InboxStatusCallbackStarted
	if _, err := store.UpdateInbox(context.Background(), started); err != nil {
		t.Fatal(err)
	}
	ambiguous := started
	ambiguous.ExpectedVersion = 3
	ambiguous.Status = InboxStatusAmbiguous
	if _, err := store.UpdateInbox(context.Background(), ambiguous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ambiguous predecessor claim err=%v", err)
	}
	if _, err := store.ResolveInbox(context.Background(), InboxResolutionRequest{InboxID: "inbox-1", ExpectedVersion: 4, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "operator", Reason: "verified"}); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute})
	if err != nil || second.Update.InboxID != "inbox-2" {
		t.Fatalf("resolved successor claim = %#v err=%v", second, err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "inbox-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatal("terminal inbox payload was not scrubbed")
	}
}

func TestOutboxLeaseDispatchCompletionAndStale(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	if _, err := store.AcceptOutbox(context.Background(), task5Effect("effect-1", "lane")); err != nil {
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
	if _, err := store.CompleteOutbox(context.Background(), completion); err != nil {
		t.Fatalf("idempotent completion: %v", err)
	}
	var row outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "effect-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != OutboxStatusSucceeded || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("terminal outbox row = %#v", row)
	}
}

func TestArtifactCodecBoundAndOneWinner(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "op-1", PrincipalID: "principal"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "artifact-1", OperationID: "op-1", OwnerPrincipalID: "principal", Plaintext: []byte("secret"), TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.ConsumeArtifact(context.Background(), ArtifactConsumeRequest{ArtifactID: "artifact-1"})
	if err != nil || string(got.Plaintext) != "secret" {
		t.Fatalf("consume = %#v err=%v", got, err)
	}
	var consumed operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-1").First(&consumed).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeArtifact(context.Background(), ArtifactConsumeRequest{ArtifactID: "artifact-1"}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("losing consume err=%v", err)
	}
	var row operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Version != consumed.Version {
		t.Fatalf("losing consume mutated version from %d to %d", consumed.Version, row.Version)
	}
	if len(row.Ciphertext) != 0 || len(row.Nonce) != 0 {
		t.Fatal("artifact ciphertext was not scrubbed")
	}
	if _, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "too-large", OperationID: "op-1", Plaintext: make([]byte, MaxArtifactBytes+1)}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("size bound err=%v", err)
	}
	if _, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "artifact-2", OperationID: "op-1", Plaintext: []byte("expired"), TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ConsumeArtifact(context.Background(), ArtifactConsumeRequest{ArtifactID: "artifact-2"}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("expired consume err=%v", err)
	}
}

func TestInboxConcurrentAcceptanceAllocatesUniqueSequences(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	const count = 12
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := task5Inbox("concurrent-"+strconv.Itoa(i), "provider-"+strconv.Itoa(i), "shared-lane")
			_, err := store.AcceptInbox(context.Background(), u)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var rows []inboxMessageRow
	if err := db.GORM().Where("lane_hmac = ?", []byte("shared-lane")).Order("ordering_sequence ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != count {
		t.Fatalf("rows = %d, want %d", len(rows), count)
	}
	for i, row := range rows {
		if row.OrderingSequence != uint64(i+1) {
			t.Fatalf("sequence[%d] = %d", i, row.OrderingSequence)
		}
	}
}

func TestInboxPayloadExpiryScrubsWithoutUnblockingRetry(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	expiry := clock.Now().Add(time.Minute)
	u := task5Inbox("expiry-inbox", "expiry-provider", "expiry-lane")
	u.PayloadExpiresAt = expiry
	if _, err := store.AcceptInbox(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired claim err = %v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "expiry-inbox").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusLeased || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("expired row = %#v", row)
	}
}

func TestOutboxNonIdempotentDispatchExpiryBecomesAmbiguous(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	effect := task5Effect("ambiguous-effect", "ambiguous-lane")
	effect.RiskClass = RiskNonIdempotentAfterDispatch
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
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
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

func TestArtifactFailsClosedWithoutCodec(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "no-codec.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, WithClock(&task5Clock{now: time.Unix(100, 0).UTC()}))
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "no-codec-op", PrincipalID: "principal"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(context.Background(), ArtifactPutRequest{ArtifactID: "no-codec-artifact", OperationID: "no-codec-op", Plaintext: []byte("secret")}); !errors.Is(err, ErrEncryptionUnavailable) {
		t.Fatalf("without codec err = %v", err)
	}
	var rows int64
	if err := db.GORM().Model(&operationArtifactRow{}).Where("artifact_id = ?", "no-codec-artifact").Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("failed encryption left an artifact row")
	}
}

func TestTask5UnitOfWorkParticipantsUseLaneInvariants(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	work := UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: "uow-inbox", EndpointID: "endpoint", ProviderEventKey: "uow-provider",
		LaneHMAC: []byte("uow-lane"), OrderingSequence: 99, Status: InboxStatusPending,
		PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), DigestKeyID: "uow-key",
	}}}
	result, err := store.Commit(context.Background(), work)
	if err != nil {
		t.Fatal(err)
	}
	if result.OrderingSequence != 1 {
		t.Fatalf("uow sequence = %d, want 1", result.OrderingSequence)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "uow-inbox").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OrderingSequence != 1 || row.Status != InboxStatusPending {
		t.Fatalf("uow row = %#v", row)
	}
}
func TestTask5UnitOfWorkRejectsInvalidIngressParticipants(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	badInbox := task5Inbox("bad-uow-inbox", "bad-uow-provider", "bad-uow-lane")
	badInbox.Status = InboxStatusCallbackStarted
	if _, err := store.Commit(context.Background(), UnitOfWork{InboxUpdates: []InboxUpdate{badInbox}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid inbox participant err = %v", err)
	}
	goodInbox, err := store.AcceptInbox(context.Background(), task5Inbox("good-inbox", "good-provider", "bad-uow-lane"))
	if err != nil || goodInbox.OrderingSequence != 1 {
		t.Fatalf("lane after rejected inbox = %#v err=%v", goodInbox, err)
	}
	badEffect := task5Effect("bad-uow-effect", "bad-uow-effect-lane")
	badEffect.RiskClass = "high"
	if _, err := store.Commit(context.Background(), UnitOfWork{Effects: []NewEffect{badEffect}}); !errors.Is(err, ErrInvalidRiskClass) {
		t.Fatalf("invalid effect participant err = %v", err)
	}
	goodEffect, err := store.AcceptOutbox(context.Background(), task5Effect("good-effect", "bad-uow-effect-lane"))
	if err != nil || goodEffect.OrderingSequence != 1 {
		t.Fatalf("lane after rejected effect = %#v err=%v", goodEffect, err)
	}
}

func TestTask5LeaseMutationsRejectExpiredAttempt(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	if _, err := store.AcceptInbox(context.Background(), task5Inbox("expired-lease-inbox", "expired-lease-provider", "expired-lease-lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	update := claimed.Update
	update.ExpectedVersion = claimed.Update.Version
	update.Status = InboxStatusCallbackStarted
	if _, err := store.UpdateInbox(context.Background(), update); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired inbox mutation err = %v", err)
	}
	if _, err := store.AcceptOutbox(context.Background(), task5Effect("expired-lease-effect", "expired-lease-outbox-lane")); err != nil {
		t.Fatal(err)
	}
	outbox, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.RenewOutbox(context.Background(), OutboxRenewRequest{EffectID: outbox.Effect.EffectID, WorkerID: outbox.Effect.LeaseOwner, LeaseEpoch: outbox.Effect.LeaseEpoch, AttemptID: outbox.Effect.AttemptID, LeaseDuration: time.Minute}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired outbox renew err = %v", err)
	}
}

func TestTask5OutboxAcceptanceDedupeDoesNotAdvanceLane(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	first, err := store.AcceptOutbox(context.Background(), task5Effect("dedupe-effect", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.AcceptOutbox(context.Background(), task5Effect("dedupe-effect", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Deduplicated || duplicate.OrderingSequence != first.OrderingSequence {
		t.Fatalf("duplicate result = %#v", duplicate)
	}
	second, err := store.AcceptOutbox(context.Background(), task5Effect("dedupe-effect-2", "dedupe-lane"))
	if err != nil {
		t.Fatal(err)
	}
	if second.OrderingSequence != 2 {
		t.Fatalf("lane after duplicate = %d", second.OrderingSequence)
	}
}

func TestTask5ArtifactParticipantBoundsAndStatus(t *testing.T) {
	store, db, _ := task5Store(t)
	defer db.Close()
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-uow-op"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "oversize-uow-artifact", OperationID: "artifact-uow-op", Size: MaxArtifactBytes + 1, Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), Status: "available"}}}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversize participant err = %v", err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "invalid-uow-artifact", OperationID: "artifact-uow-op", Size: 1, Ciphertext: []byte("cipher"), Nonce: []byte("nonce"), Status: "consumed"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid artifact participant err = %v", err)
	}
}
func TestInboxIngressRejectsPayloadTTLBypass(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	update := task5Inbox("ttl-inbox", "ttl-provider", "ttl-lane")
	update.PayloadExpiresAt = clock.Now().Add(InboxPayloadTTL + time.Second)
	if _, err := store.AcceptInbox(context.Background(), update); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("inbox ttl err = %v", err)
	}
}

func TestOutboxIngressRejectsPayloadTTLBypass(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	effect := task5Effect("ttl-effect", "ttl-lane")
	effect.PayloadExpiresAt = clock.Now().Add(InboxPayloadTTL + time.Second)
	if _, err := store.AcceptOutbox(context.Background(), effect); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("outbox ttl err = %v", err)
	}
}

func TestInboxCallbackExpiryScrubsWithoutUnblockingRetry(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	update := task5Inbox("callback-expired", "callback-provider", "callback-lane")
	update.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	callback := claimed.Update
	callback.ExpectedVersion = claimed.Update.Version
	callback.Status = InboxStatusCallbackStarted
	if _, err := store.UpdateInbox(context.Background(), callback); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("callback expiry err = %v", err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", update.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusCallbackStarted || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("callback expiry row = %#v", row)
	}
}

func TestOutboxDispatchedExpiryScrubsBeforeAmbiguity(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	effect := task5Effect("dispatched-expired", "dispatched-expired-lane")
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
