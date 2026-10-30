package eventstore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestLeaseCommitErrorsReturnZeroLease(t *testing.T) {
	{
		store, db, _ := openQueueTestStore(t)
		defer db.Close()
		if _, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("commit-error-claim-inbox", "commit-error-provider", "commit-error-lane")); err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_claim_inbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableInboxMessages {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker"})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, InboxLease{}) {
			t.Fatalf("claim inbox commit error lease=%#v err=%v", lease, err)
		}
	}
	{
		store, db, _ := openQueueTestStore(t)
		defer db.Close()
		if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("commit-error-claim-effect", "commit-error-claim-lane")); err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_claim_outbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableOutboxEffects {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker"})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, OutboxLease{}) {
			t.Fatalf("claim outbox commit error lease=%#v err=%v", lease, err)
		}
	}
	{
		store, db, _ := openQueueTestStore(t)
		defer db.Close()
		if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("commit-error-renew-effect", "commit-error-renew-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_renew_outbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableOutboxEffects {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.RenewOutbox(context.Background(), OutboxRenewRequest{EffectID: claimed.Effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID, LeaseDuration: time.Minute})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, OutboxLease{}) {
			t.Fatalf("renew outbox commit error lease=%#v err=%v", lease, err)
		}
	}
	{
		store, db, _ := openQueueTestStore(t)
		defer db.Close()
		if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("commit-error-mark-effect", "commit-error-mark-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		const callbackName = "task5_test_rollback_mark_outbox"
		if err := db.GORM().Callback().Update().After("gorm:update").Register(callbackName, func(tx *gorm.DB) {
			if tx.Statement.Table == tableOutboxEffects {
				tx.Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		lease, err := store.MarkOutboxDispatched(context.Background(), OutboxDispatchRequest{EffectID: claimed.Effect.EffectID, WorkerID: claimed.Effect.LeaseOwner, LeaseEpoch: claimed.Effect.LeaseEpoch, AttemptID: claimed.Effect.AttemptID})
		_ = db.GORM().Callback().Update().Remove(callbackName)
		if err == nil || !reflect.DeepEqual(lease, OutboxLease{}) {
			t.Fatalf("mark outbox commit error lease=%#v err=%v", lease, err)
		}
	}
}

func TestPersistedVersionWidthOverflowFailsClosed(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	effect := newOutboxTestEffect("persisted-width-effect", "persisted-width-lane")
	if _, err := store.AcceptOutbox(context.Background(), effect); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&outboxEffectRow{}).Where("effect_id = ?", effect.EffectID).Update("version", maxPersistedVersion).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("persisted outbox version overflow err=%v", err)
	}
	inbox := newInboxTestUpdate("persisted-width-inbox", "persisted-width-inbox-provider", "persisted-width-inbox-lane")
	if _, err := store.AcceptInbox(context.Background(), inbox); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", inbox.InboxID).Update("lease_epoch", maxPersistedVersion).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("persisted inbox lease epoch overflow err=%v", err)
	}
	laneInbox := newInboxTestUpdate("persisted-width-lane-inbox", "persisted-width-lane-provider", "persisted-width-lane")
	if _, err := store.AcceptInbox(context.Background(), laneInbox); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&laneHeadRow{}).Where("kind = ? AND lane_hmac = ?", "inbox", laneInbox.LaneHMAC).Update("next_sequence", maxPersistedVersion).Error; err != nil {
		t.Fatal(err)
	}
	laneInbox.InboxID = "persisted-width-lane-inbox-2"
	laneInbox.ProviderEventKey = "persisted-width-lane-provider-2"
	if _, err := store.AcceptInbox(context.Background(), laneInbox); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("persisted lane sequence overflow err=%v", err)
	}
}

func TestUnitOfWorkParticipantsUseLaneInvariants(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
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
func TestUnitOfWorkRejectsInvalidIngressParticipants(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	badInbox := newInboxTestUpdate("bad-uow-inbox", "bad-uow-provider", "bad-uow-lane")
	badInbox.Status = InboxStatusCallbackStarted
	if _, err := store.Commit(context.Background(), UnitOfWork{InboxUpdates: []InboxUpdate{badInbox}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid inbox participant err = %v", err)
	}
	goodInbox, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("good-inbox", "good-provider", "bad-uow-lane"))
	if err != nil || goodInbox.OrderingSequence != 1 {
		t.Fatalf("lane after rejected inbox = %#v err=%v", goodInbox, err)
	}
	badEffect := newOutboxTestEffect("bad-uow-effect", "bad-uow-effect-lane")
	badEffect.RiskClass = "high"
	if _, err := store.Commit(context.Background(), UnitOfWork{Effects: []NewEffect{badEffect}}); !errors.Is(err, ErrInvalidRiskClass) {
		t.Fatalf("invalid effect participant err = %v", err)
	}
	goodEffect, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("good-effect", "bad-uow-effect-lane"))
	if err != nil || goodEffect.OrderingSequence != 1 {
		t.Fatalf("lane after rejected effect = %#v err=%v", goodEffect, err)
	}
}
func TestUOWExistingIngressIdentityIsImmutable(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("uow-identity-inbox", "uow-identity-provider", "uow-identity-lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: "uow-identity-inbox", ExpectedVersion: 1, EndpointID: "forged"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("inbox identity mutation err = %v", err)
	}
	if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("uow-identity-effect", "uow-identity-effect-lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: "uow-identity-effect", ExpectedVersion: 1, EndpointID: "forged"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("effect identity mutation err = %v", err)
	}
}

func TestLeaseMutationsRejectExpiredAttempt(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	if _, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("expired-lease-inbox", "expired-lease-provider", "expired-lease-lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	update := InboxUpdate{InboxID: claimed.Update.InboxID, ExpectedVersion: claimed.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: claimed.Update.LeaseOwner, LeaseEpoch: claimed.Update.LeaseEpoch, AttemptID: claimed.Update.AttemptID}
	if _, err := store.UpdateInbox(context.Background(), update); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("expired inbox mutation err = %v", err)
	}
	if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("expired-lease-effect", "expired-lease-outbox-lane")); err != nil {
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
func TestExpiredLeasedMutationScrubsBeforeStaleLease(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("expired-observed-inbox", "expired-observed-provider", "expired-observed-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "expired-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	effect := newOutboxTestEffect("expired-observed-effect", "expired-observed-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "expired-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inboxLease.Update.InboxID, ExpectedVersion: inboxLease.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: inboxLease.Update.LeaseOwner, LeaseEpoch: inboxLease.Update.LeaseEpoch, AttemptID: inboxLease.Update.AttemptID}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox mutation err = %v", err)
	}
	if _, err := store.RenewOutbox(ctx, OutboxRenewRequest{EffectID: effectLease.Effect.EffectID, WorkerID: effectLease.Effect.LeaseOwner, LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID, LeaseDuration: time.Minute}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox renewal err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatal("expired inbox payload was not scrubbed")
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if effectRow.Status != OutboxStatusFailed || effectRow.CompletedAt == nil || len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatalf("expired outbox was not terminalized: %#v", effectRow)
	}
}
func TestExpiredRowsPrecedeVersionConflicts(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("expired-version-inbox", "expired-version-provider", "expired-version-inbox-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	effect := newOutboxTestEffect("expired-version-effect", "expired-version-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	resolveInbox := newInboxTestUpdate("expired-version-resolve-inbox", "expired-version-resolve-provider", "expired-version-resolve-inbox-lane")
	resolveInbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, resolveInbox); err != nil {
		t.Fatal(err)
	}
	resolveEffect := newOutboxTestEffect("expired-version-resolve-effect", "expired-version-resolve-effect-lane")
	resolveEffect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, resolveEffect); err != nil {
		t.Fatal(err)
	}
	uowInbox := newInboxTestUpdate("expired-version-uow-inbox", "expired-version-uow-provider", "expired-version-uow-inbox-lane")
	uowInbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, uowInbox); err != nil {
		t.Fatal(err)
	}
	uowEffect := newOutboxTestEffect("expired-version-uow-effect", "expired-version-uow-effect-lane")
	uowEffect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, uowEffect); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 99, Status: InboxStatusPending}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox version err = %v", err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: 99, Status: OutboxStatusPending}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox version err = %v", err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: resolveInbox.InboxID, ExpectedVersion: 99, Resolution: InboxResolutionRetry, PrincipalID: "operator", Reason: "expired"}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox resolution version err = %v", err)
	}
	if _, err := store.ResolveOutbox(ctx, OutboxResolutionRequest{EffectID: resolveEffect.EffectID, ExpectedVersion: 99, Resolution: OutboxResolutionRetry, PrincipalID: "operator", Reason: "expired"}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired outbox resolution version err = %v", err)
	}
	var resolvedExpired outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", resolveEffect.EffectID).First(&resolvedExpired).Error; err != nil {
		t.Fatal(err)
	}
	if resolvedExpired.Status != OutboxStatusFailed || resolvedExpired.CompletedAt == nil || resolvedExpired.ResolutionReason != "payload-expired" {
		t.Fatalf("expired manual resolution left pending row: %#v", resolvedExpired)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: uowInbox.InboxID, ExpectedVersion: 99, Status: InboxStatusPending}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired UoW inbox version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: uowEffect.EffectID, ExpectedVersion: 99, Status: OutboxStatusPending}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired UoW outbox version err = %v", err)
	}
	for _, table := range []string{"inbox_messages", "outbox_effects"} {
		var count int64
		if err := db.GORM().Table(table).Where("(payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0) OR (payload_nonce IS NOT NULL AND length(payload_nonce) > 0)").Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expired %s payloads remain: %d", table, count)
		}
	}
}

func TestStrictIngressAndParticipantContracts(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	inbox := newInboxTestUpdate("strict-inbox", "strict-provider", "strict-lane")
	inbox.ContentDigest = []byte("strict-digest")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	conflicting := inbox
	conflicting.PayloadCiphertext = []byte("different")
	conflicting.ContentDigest = []byte("different-digest")
	if _, err := store.AcceptInbox(ctx, conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("inbox content conflict err = %v", err)
	}
	invalidOutbox := newOutboxTestEffect("strict-effect", "strict-outbox-lane")
	invalidOutbox.Status = OutboxStatusLeased
	if _, err := store.AcceptOutbox(ctx, invalidOutbox); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("non-pending outbox acceptance err = %v", err)
	}
	pendingLease := InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Status: InboxStatusPending, LeaseOwner: "forged", LeaseEpoch: 1, AttemptID: "forged-attempt"}
	if _, err := store.UpdateInbox(ctx, pendingLease); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending inbox lease injection err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, Resolution: InboxResolutionRetry, ExpectedVersion: 1}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("uow inbox resolution err = %v", err)
	}
	effect := newOutboxTestEffect("strict-uow-effect", "strict-uow-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, Status: OutboxStatusSucceeded, ExpectedVersion: 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("uow outbox terminal transition err = %v", err)
	}

	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, Status: OutboxStatusLeased, ExpectedVersion: 1}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("forged outbox lease transition err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Operations: []OperationUpdate{{OperationID: "artifact-uow-roundtrip", PrincipalID: "artifact-owner"}},
		ArtifactUpdates: []ArtifactUpdate{{
			ArtifactID: "artifact-uow-roundtrip", OperationID: "artifact-uow-roundtrip",
			Size: 3, Ciphertext: []byte("sealed:abc"), Nonce: []byte("nonce"), EncryptionKeyID: "artifact-key",
			Status: "ready",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	artifact, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-uow-roundtrip"})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.Plaintext) != "abc" || artifact.OwnerPrincipalID != "artifact-owner" {
		t.Fatalf("artifact roundtrip = %#v", artifact)
	}
}
func TestStableDedupeAfterScrubAndLeaseRequiredTransitions(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	inbox := newInboxTestUpdate("stable-inbox", "stable-provider", "stable-lane")
	inbox.ContentDigest = []byte("stable-digest")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	failedInbox := InboxUpdate{InboxID: inboxLease.Update.InboxID, ExpectedVersion: inboxLease.Update.Version, Status: InboxStatusFailed, LeaseOwner: inboxLease.Update.LeaseOwner, LeaseEpoch: inboxLease.Update.LeaseEpoch, AttemptID: inboxLease.Update.AttemptID}
	if _, err := store.UpdateInbox(ctx, failedInbox); err != nil {
		t.Fatal(err)
	}
	terminalInboxUpdate := failedInbox
	terminalInboxUpdate.ExpectedVersion = 3
	terminalInboxUpdate.PrincipalID = "attacker"
	if _, err := store.UpdateInbox(ctx, terminalInboxUpdate); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal inbox generic update err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, Status: InboxStatusFailed, ExpectedVersion: 3}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal inbox participant update err = %v", err)
	}
	replayInbox := inbox
	replayInbox.PayloadCiphertext = []byte("re-encrypted")
	if result, err := store.AcceptInbox(ctx, replayInbox); err != nil || !result.Deduplicated {
		t.Fatalf("scrubbed inbox replay = %#v err=%v", result, err)
	}
	conflictingInbox := replayInbox
	conflictingInbox.ContentDigest = []byte("different-digest")
	if _, err := store.AcceptInbox(ctx, conflictingInbox); !errors.Is(err, ErrConflict) {
		t.Fatalf("scrubbed inbox digest conflict err = %v", err)
	}

	effect := newOutboxTestEffect("stable-effect", "stable-effect-lane")
	effect.ContentDigest = []byte("stable-effect-digest")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	outboxLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{EffectID: effect.EffectID, WorkerID: outboxLease.Effect.LeaseOwner, LeaseEpoch: outboxLease.Effect.LeaseEpoch, AttemptID: outboxLease.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{EffectID: effect.EffectID, WorkerID: outboxLease.Effect.LeaseOwner, LeaseEpoch: outboxLease.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: OutboxStatusSucceeded, ResultCode: "ok"}); err != nil {
		t.Fatal(err)
	}
	terminalEffectUpdate := effect
	terminalEffectUpdate.ExpectedVersion = 4
	terminalEffectUpdate.Status = OutboxStatusSucceeded
	terminalEffectUpdate.ResultCode = "rewritten"
	if _, err := store.UpdateOutbox(ctx, terminalEffectUpdate); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal outbox generic update err = %v", err)
	}
	replayEffect := effect
	replayEffect.PayloadCiphertext = []byte("re-encrypted")
	if result, err := store.AcceptOutbox(ctx, replayEffect); err != nil || !result.Deduplicated {
		t.Fatalf("scrubbed outbox replay = %#v err=%v", result, err)
	}
	conflictingEffect := replayEffect
	conflictingEffect.ContentDigest = []byte("different-effect-digest")
	if _, err := store.AcceptOutbox(ctx, conflictingEffect); !errors.Is(err, ErrConflict) {
		t.Fatalf("scrubbed outbox digest conflict err = %v", err)
	}
}
func TestPublicIngressRejectsImmutableFieldsAndVersions(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("public-immutable-inbox", "public-immutable-provider", "public-immutable-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "new-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Version: 1, PayloadCiphertext: []byte("sealed"), PayloadNonce: []byte("nonce"), DigestKeyID: "key"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("accept inbox version err = %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Status: InboxStatusPending, PayloadCiphertext: []byte("sealed")}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("update inbox payload err = %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 9, Status: InboxStatusPending}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("update inbox version err = %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{InboxID: inbox.InboxID, ExpectedVersion: 1, Status: InboxStatusPending, Resolution: InboxResolutionRetry}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("update inbox resolution metadata err = %v", err)
	}
	effect := newOutboxTestEffect("public-immutable-effect", "public-immutable-effect-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, NewEffect{EffectID: "new-effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Version: 1, PayloadCiphertext: []byte("sealed"), PayloadNonce: []byte("nonce"), DigestKeyID: "key"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("accept outbox version err = %v", err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: 1, Status: OutboxStatusPending, EndpointID: "forged"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("update outbox endpoint err = %v", err)
	}
	if _, err := store.UpdateOutbox(ctx, NewEffect{EffectID: effect.EffectID, ExpectedVersion: 1, Version: 9, Status: OutboxStatusPending}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("update outbox version err = %v", err)
	}
}

func TestPendingTerminationAndNonceBound(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	inbox := newInboxTestUpdate("pending-termination-inbox", "pending-termination-provider", "pending-termination-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	failedInbox := InboxUpdate{InboxID: inbox.InboxID, Status: InboxStatusFailed, ExpectedVersion: 1}
	if _, err := store.UpdateInbox(ctx, failedInbox); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending inbox termination err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, Status: InboxStatusFailed, ExpectedVersion: 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending inbox participant termination err = %v", err)
	}

	effect := newOutboxTestEffect("pending-termination-effect", "pending-termination-effect-lane")
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	failedEffect := NewEffect{EffectID: effect.EffectID, Status: OutboxStatusFailed, ExpectedVersion: 1}
	if _, err := store.UpdateOutbox(ctx, failedEffect); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending outbox termination err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, Status: OutboxStatusFailed, ExpectedVersion: 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pending outbox participant termination err = %v", err)
	}

	invalidNonce := newInboxTestUpdate("nonce-bound", "nonce-bound-provider", "nonce-bound-lane")
	invalidNonce.PayloadNonce = make([]byte, task5NonceLimit+1)
	if _, err := store.AcceptInbox(ctx, invalidNonce); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("nonce bound err = %v", err)
	}
}
func TestParticipantVersionContract(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	inbox := newInboxTestUpdate("participant-version-inbox", "participant-version-provider", "participant-version-lane")
	inbox.Version = 2
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{inbox}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new inbox supplied version err = %v", err)
	}
	inbox.Version = 1
	inbox.ExpectedVersion = 9
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{inbox}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new inbox expected version err = %v", err)
	}
	inbox.ExpectedVersion = 0
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{inbox}}); err != nil {
		t.Fatalf("new inbox version 1: %v", err)
	}
	replayInbox := inbox
	replayInbox.Version = 0
	if result, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{replayInbox}}); err != nil || !result.Deduplicated || !result.Idempotent {
		t.Fatalf("existing inbox full replay = %#v err=%v", result, err)
	}
	oversizedInboxReplay := replayInbox
	oversizedInboxReplay.PayloadCiphertext = make([]byte, task5PayloadLimit+1)
	var bound *OversizeError
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{oversizedInboxReplay}}); !errors.As(err, &bound) {
		t.Fatalf("oversized inbox replay err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 3, Status: InboxStatusPending}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("existing inbox supplied version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 2, Status: InboxStatusPending}}}); err != nil {
		t.Fatalf("existing inbox version 2: %v", err)
	}

	effect := newOutboxTestEffect("participant-version-effect", "participant-version-effect-lane")
	effect.Version = 2
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new effect supplied version err = %v", err)
	}
	effect.Version = 1
	effect.ExpectedVersion = 9
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new effect expected version err = %v", err)
	}
	effect.ExpectedVersion = 0
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); err != nil {
		t.Fatalf("new effect version 1: %v", err)
	}
	replayEffect := effect
	replayEffect.Version = 0
	if result, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{replayEffect}}); err != nil || !result.Deduplicated || !result.Idempotent {
		t.Fatalf("existing effect full replay = %#v err=%v", result, err)
	}
	oversizedEffectReplay := replayEffect
	oversizedEffectReplay.PayloadCiphertext = make([]byte, task5PayloadLimit+1)
	bound = nil
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{oversizedEffectReplay}}); !errors.As(err, &bound) {
		t.Fatalf("oversized effect replay err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: 1, Version: 3, Status: OutboxStatusPending}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("existing effect supplied version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: 1, Version: 2, Status: OutboxStatusPending}}}); err != nil {
		t.Fatalf("existing effect version 2: %v", err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "participant-version-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: effectLease.Effect.Version, RetryCount: 9, Version: effectLease.Effect.Version + 1}}}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("sparse leased effect without identity err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: effectLease.Effect.Version, RetryCount: 9, Version: effectLease.Effect.Version + 1, LeaseOwner: effectLease.Effect.LeaseOwner, LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID}}}); err != nil {
		t.Fatalf("sparse leased effect with identity: %v", err)
	}

	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "participant-version-operation", PrincipalID: "participant-version-principal"}}}); err != nil {
		t.Fatal(err)
	}
	artifact := ArtifactUpdate{ArtifactID: "participant-version-artifact", OperationID: "participant-version-operation", OwnerPrincipalID: "participant-version-principal", Size: 8, Ciphertext: []byte("sealed:artifact"), Nonce: []byte("nonce"), EncryptionKeyID: "test-key"}
	artifact.Version = 2
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{artifact}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("new artifact supplied version err = %v", err)
	}
	artifact.Version = 1
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{artifact}}); err != nil {
		t.Fatalf("new artifact version 1: %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: artifact.ArtifactID, ExpectedVersion: 1, Version: 3}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("existing artifact supplied version err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: artifact.ArtifactID, ExpectedVersion: 1, Version: 2}}}); err != nil {
		t.Fatalf("existing artifact version 2: %v", err)
	}
}
func TestUOWExpiryScrubsBeforeError(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	inbox := newInboxTestUpdate("uow-expired-inbox", "uow-expired-provider", "uow-expired-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	inboxLease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "uow-expiry-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: inboxLease.Update.Version, Version: inboxLease.Update.Version + 1, Status: InboxStatusCallbackStarted, LeaseOwner: inboxLease.Update.LeaseOwner, LeaseEpoch: inboxLease.Update.LeaseEpoch, AttemptID: inboxLease.Update.AttemptID}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow callback expiry err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatalf("uow inbox expiry retained payload: %#v", inboxRow)
	}

	effect := newOutboxTestEffect("uow-expired-effect", "uow-expired-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	effectLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "uow-expiry-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: effect.EffectID, ExpectedVersion: effectLease.Effect.Version, Version: effectLease.Effect.Version + 1, Status: OutboxStatusPending, LeaseOwner: effectLease.Effect.LeaseOwner, LeaseEpoch: effectLease.Effect.LeaseEpoch, AttemptID: effectLease.Effect.AttemptID}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow pending expiry err = %v", err)
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if effectRow.Status != OutboxStatusFailed || effectRow.CompletedAt == nil || len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatalf("uow effect expiry was not terminalized: %#v", effectRow)
	}

	ambiguous := newOutboxTestEffect("uow-expired-ambiguous", "uow-expired-ambiguous-lane")
	ambiguous.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, ambiguous); err != nil {
		t.Fatal(err)
	}
	ambiguousLease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "uow-expiry-worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{EffectID: ambiguous.EffectID, ExpectedVersion: ambiguousLease.Effect.Version, Version: ambiguousLease.Effect.Version + 1, Status: OutboxStatusAmbiguous, LeaseOwner: ambiguousLease.Effect.LeaseOwner, LeaseEpoch: ambiguousLease.Effect.LeaseEpoch, AttemptID: ambiguousLease.Effect.AttemptID}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow ambiguous expiry err = %v", err)
	}
	effectRow = outboxEffectRow{}
	if err := db.GORM().Where("effect_id = ?", ambiguous.EffectID).First(&effectRow).Error; err != nil {
		t.Fatalf("query ambiguous effect %q err=%v", ambiguous.EffectID, err)
	}
	if effectRow.Status != OutboxStatusFailed || effectRow.CompletedAt == nil || len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatalf("uow leased expiry was not terminalized: %#v", effectRow)
	}
}
func TestPublicExpiredReplayScrubsBeforeDedupe(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("expired-replay-inbox", "expired-replay-provider", "expired-replay-inbox-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	effect := newOutboxTestEffect("expired-replay-effect", "expired-replay-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	sameInbox := inbox
	sameInbox.PayloadExpiresAt = clock.Now().Add(-time.Minute)
	if _, err := store.AcceptInbox(ctx, sameInbox); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("same expired inbox replay err = %v", err)
	}
	changedInbox := inbox
	changedInbox.PayloadExpiresAt = time.Time{}
	changedInbox.PayloadCiphertext = []byte("changed")
	if _, err := store.AcceptInbox(ctx, changedInbox); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed expired inbox replay err = %v", err)
	}
	sameEffect := effect
	sameEffect.PayloadExpiresAt = clock.Now().Add(-time.Minute)
	if _, err := store.AcceptOutbox(ctx, sameEffect); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("same expired outbox replay err = %v", err)
	}
	changedEffect := effect
	changedEffect.PayloadExpiresAt = time.Time{}
	changedEffect.PayloadCiphertext = []byte("changed")
	if _, err := store.AcceptOutbox(ctx, changedEffect); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed expired outbox replay err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatal("expired inbox replay retained payload")
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatal("expired outbox replay retained payload")
	}
}
func TestUOWExpiredInitialDedupePrecedesReplay(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("uow-dedupe-expired-inbox", "uow-dedupe-expired-provider", "uow-dedupe-expired-lane")
	inbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	effect := newOutboxTestEffect("uow-dedupe-expired-effect", "uow-dedupe-expired-effect-lane")
	effect.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, effect); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	replayInbox := newInboxTestUpdate("uow-dedupe-expired-new-id", inbox.ProviderEventKey, string(inbox.LaneHMAC))
	replayInbox.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{replayInbox}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired inbox dedupe err = %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{effect}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired effect dedupe err = %v", err)
	}
	var inboxRow inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inboxRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(inboxRow.PayloadCiphertext) != 0 || len(inboxRow.PayloadNonce) != 0 {
		t.Fatal("uow expired inbox dedupe retained payload")
	}
	var effectRow outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effectRow).Error; err != nil {
		t.Fatal(err)
	}
	if len(effectRow.PayloadCiphertext) != 0 || len(effectRow.PayloadNonce) != 0 {
		t.Fatal("uow expired effect dedupe retained payload")
	}
}
