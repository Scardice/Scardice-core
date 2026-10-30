package eventstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestA6ArtifactAADBindsRowIdentity(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	for _, operationID := range []string{"artifact-op-1", "artifact-op-2"} {
		if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: operationID, PrincipalID: "owner-" + operationID}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "artifact-a", OperationID: "artifact-op-1", OwnerPrincipalID: "owner-artifact-op-1", Plaintext: []byte("alpha")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "artifact-b", OperationID: "artifact-op-2", OwnerPrincipalID: "owner-artifact-op-2", Plaintext: []byte("bravo")}); err != nil {
		t.Fatal(err)
	}
	var first, second operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-a").First(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Where("artifact_id = ?", "artifact-b").First(&second).Error; err != nil {
		t.Fatal(err)
	}
	first.Ciphertext, second.Ciphertext = second.Ciphertext, first.Ciphertext
	first.Nonce, second.Nonce = second.Nonce, first.Nonce
	if err := db.GORM().Save(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Save(&second).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-a"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("swapped artifact err=%v", err)
	}
}
func TestA6ArtifactUoWBoundCiphertext(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-uow-op", PrincipalID: "artifact-uow-owner"}}}); err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "artifact/v1", "artifact-uow", "artifact-uow-owner", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "artifact-uow", OperationID: "artifact-uow-op", OwnerPrincipalID: "artifact-uow-owner", Size: 7, Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID}}}); err != nil {
		t.Fatalf("bound artifact UoW err=%v", err)
	}
}
func TestA6UoWRejectsWrongCiphertextKey(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "operation-private/v1", "uow-op", "owner", 1, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	source.Roots["root-v1"] = []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA987654")
	_, err = store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "uow-op", Version: 0, PrincipalID: "owner", PrivateContextCiphertext: ciphertext, PrivateContextNonce: nonce, EncryptionKeyID: keyID}}})
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong-key UoW err=%v", err)
	}
}
func TestA6ArtifactStatusUpdateKeepsPayloadDecryptable(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-status-op", PrincipalID: "artifact-status-owner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "artifact-status", OperationID: "artifact-status-op", OwnerPrincipalID: "artifact-status-owner", Plaintext: []byte("status")}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&operationArtifactRow{}).Where("artifact_id = ?", "artifact-status").Update("status", "ready").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "artifact-status", Status: "available", ExpectedVersion: 1}}}); err != nil {
		t.Fatal(err)
	}
	result, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-status"})
	if err != nil || string(result.Plaintext) != "status" {
		t.Fatalf("status update consume=%q err=%v", result.Plaintext, err)
	}
}
func TestA6ClaimRejectsTamperedPayloadBeforeLease(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inboxCipher, inboxNonce, inboxKey, err := a6Seal(ctx, source, "inbox/v1", "claim-inbox", "endpoint", 1, []byte("inbox"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "claim-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Status: InboxStatusPending, PayloadCiphertext: inboxCipher, PayloadNonce: inboxNonce, PayloadEncryptionKeyID: inboxKey}); err != nil {
		t.Fatal(err)
	}
	var inbox inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "claim-inbox").First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	inbox.PayloadCiphertext[0] ^= 1
	if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", inbox.InboxID).Update("payload_ciphertext", inbox.PayloadCiphertext).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered inbox claim err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Status != InboxStatusPending || inbox.Version != 1 {
		t.Fatalf("tampered inbox mutated row=%#v", inbox)
	}
}
func TestA6ClaimsCommitExpiredScrubBeforeAuthFailure(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	expiredAt := now.Add(-time.Minute)
	futureAt := now.Add(time.Hour)
	expiredInboxCipher, expiredInboxNonce, keyID, err := a6Seal(ctx, source, "inbox/v1", "expired-inbox", "endpoint", 1, []byte("expired"))
	if err != nil {
		t.Fatal(err)
	}
	candidateInboxCipher, candidateInboxNonce, _, err := a6Seal(ctx, source, "inbox/v1", "candidate-inbox", "endpoint", 1, []byte("candidate"))
	if err != nil {
		t.Fatal(err)
	}
	candidateInboxCipher[0] ^= 1
	inboxRows := []inboxMessageRow{
		{InboxID: "blocked-inbox", EndpointID: "endpoint", ProviderEventKey: "blocked-provider", LaneHMAC: []byte("blocked-lane"), OrderingSequence: 1, Status: InboxStatusCallbackStarted, Version: 1, PayloadVersion: 1},
		{InboxID: "expired-inbox", EndpointID: "endpoint", ProviderEventKey: "expired-provider", LaneHMAC: []byte("blocked-lane"), OrderingSequence: 2, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: expiredInboxCipher, PayloadNonce: expiredInboxNonce, EncryptionKeyID: keyID, PayloadExpiresAt: &expiredAt},
		{InboxID: "candidate-inbox", EndpointID: "endpoint", ProviderEventKey: "candidate-provider", LaneHMAC: []byte("candidate-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: candidateInboxCipher, PayloadNonce: candidateInboxNonce, EncryptionKeyID: keyID, PayloadExpiresAt: &futureAt},
	}
	if err := db.GORM().Create(&inboxRows).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered inbox claim err=%v", err)
	}
	var expiredInbox inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "expired-inbox").First(&expiredInbox).Error; err != nil {
		t.Fatal(err)
	}
	if expiredInbox.Version != 2 || len(expiredInbox.PayloadCiphertext) != 0 || len(expiredInbox.PayloadNonce) != 0 {
		t.Fatalf("expired inbox scrub was rolled back: %#v", expiredInbox)
	}

	expiredOutboxCipher, expiredOutboxNonce, outboxKeyID, err := a6Seal(ctx, source, "outbox/v1", "expired-effect", "endpoint", 1, []byte("expired"))
	if err != nil {
		t.Fatal(err)
	}
	candidateOutboxCipher, candidateOutboxNonce, _, err := a6Seal(ctx, source, "outbox/v1", "candidate-effect", "endpoint", 1, []byte("candidate"))
	if err != nil {
		t.Fatal(err)
	}
	candidateOutboxCipher[0] ^= 1
	outboxRows := []outboxEffectRow{
		{EffectID: "blocked-effect", EndpointID: "endpoint", LaneHMAC: []byte("blocked-outbox-lane"), OrderingSequence: 1, EffectClass: "send", RiskClass: RiskNonIdempotentAfterDispatch, Status: OutboxStatusDispatched, Version: 1, PayloadVersion: 1, LeaseOwner: "inflight-worker", LeaseEpoch: 1, AttemptID: "inflight-attempt", LeaseExpiry: &futureAt, DispatchedAt: &now},
		{EffectID: "expired-effect", EndpointID: "endpoint", LaneHMAC: []byte("blocked-outbox-lane"), OrderingSequence: 2, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: expiredOutboxCipher, PayloadNonce: expiredOutboxNonce, EncryptionKeyID: outboxKeyID, PayloadExpiresAt: &expiredAt},
		{EffectID: "candidate-effect", EndpointID: "endpoint", LaneHMAC: []byte("candidate-outbox-lane"), OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: candidateOutboxCipher, PayloadNonce: candidateOutboxNonce, EncryptionKeyID: outboxKeyID, PayloadExpiresAt: &futureAt},
	}
	if err := db.GORM().Create(&outboxRows).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered outbox claim err=%v", err)
	}
	var expiredOutbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "expired-effect").First(&expiredOutbox).Error; err != nil {
		t.Fatal(err)
	}
	if expiredOutbox.Status != OutboxStatusFailed || expiredOutbox.CompletedAt == nil || expiredOutbox.Version != 2 ||
		len(expiredOutbox.PayloadCiphertext) != 0 || len(expiredOutbox.PayloadNonce) != 0 {
		t.Fatalf("expired outbox failure was rolled back: %#v", expiredOutbox)
	}
}
func TestA6AcceptExpiredRowsPrecedePayloadAuthentication(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	inbox := inboxMessageRow{
		InboxID: "expired-accept-inbox", EndpointID: "endpoint", ProviderEventKey: "expired-provider",
		LaneHMAC: []byte("expired-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1,
		PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	if _, err := store.AcceptInbox(ctx, InboxUpdate{
		InboxID: inbox.InboxID, EndpointID: inbox.EndpointID, ProviderEventKey: inbox.ProviderEventKey,
		LaneHMAC: inbox.LaneHMAC, PayloadCiphertext: []byte{0x02}, PayloadNonce: make([]byte, 12),
		PayloadEncryptionKeyID: source.CurrentID,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired inbox auth/dedupe precedence err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Version != 2 || len(inbox.PayloadCiphertext) != 0 || len(inbox.PayloadNonce) != 0 {
		t.Fatalf("expired inbox was not scrubbed before auth: %#v", inbox)
	}

	effect := outboxEffectRow{
		EffectID: "expired-accept-effect", EndpointID: "endpoint", LaneHMAC: []byte("expired-effect-lane"),
		OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
		Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&effect).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	if _, err := store.AcceptOutbox(ctx, NewEffect{
		EffectID: effect.EffectID, EndpointID: effect.EndpointID, LaneHMAC: effect.LaneHMAC,
		EffectType: effect.EffectClass, RiskClass: effect.RiskClass, PayloadCiphertext: []byte{0x02},
		PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired outbox auth/dedupe precedence err=%v", err)
	}
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if effect.Version != 2 || len(effect.PayloadCiphertext) != 0 || len(effect.PayloadNonce) != 0 {
		t.Fatalf("expired outbox was not scrubbed before auth: %#v", effect)
	}
}
func TestA6UOWExpiredRowsPrecedePayloadAuthentication(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	inbox := inboxMessageRow{
		InboxID: "uow-expired-auth-inbox", EndpointID: "endpoint", ProviderEventKey: "uow-provider",
		LaneHMAC: []byte("uow-expired-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1,
		PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 2, Status: InboxStatusPending,
		EndpointID: inbox.EndpointID, PayloadCiphertext: []byte{0x02}, PayloadNonce: make([]byte, 12),
		PayloadEncryptionKeyID: source.CurrentID,
	}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired inbox auth precedence err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Version != 2 || len(inbox.PayloadCiphertext) != 0 || len(inbox.PayloadNonce) != 0 {
		t.Fatalf("uow expired inbox was not scrubbed: %#v", inbox)
	}

	effect := outboxEffectRow{
		EffectID: "uow-expired-auth-effect", EndpointID: "endpoint", LaneHMAC: []byte("uow-expired-effect-lane"),
		OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
		Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&effect).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{
		EffectID: effect.EffectID, ExpectedVersion: 1, Version: 2, Status: OutboxStatusPending,
		EndpointID: effect.EndpointID, EffectType: effect.EffectClass, RiskClass: effect.RiskClass,
		PayloadCiphertext: []byte{0x02}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID,
	}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired outbox auth precedence err=%v", err)
	}
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if effect.Version != 2 || len(effect.PayloadCiphertext) != 0 || len(effect.PayloadNonce) != 0 {
		t.Fatalf("uow expired outbox was not scrubbed: %#v", effect)
	}
}
func TestA6MixedUOWExpiryScrubsExplicitAndDedupeRows(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	rows := []inboxMessageRow{
		{InboxID: "mixed-explicit", EndpointID: "endpoint", ProviderEventKey: "explicit-provider", LaneHMAC: []byte("mixed-lane-a"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{1}, PayloadNonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt},
		{InboxID: "mixed-dedupe", EndpointID: "endpoint", ProviderEventKey: "dedupe-provider", LaneHMAC: []byte("mixed-lane-b"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{1}, PayloadNonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt},
	}
	if err := db.GORM().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	work := UnitOfWork{InboxUpdates: []InboxUpdate{
		{InboxID: rows[0].InboxID, EndpointID: rows[0].EndpointID, ProviderEventKey: rows[0].ProviderEventKey, PayloadCiphertext: []byte{2}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID},
		{InboxID: "mixed-new-id", EndpointID: rows[1].EndpointID, ProviderEventKey: rows[1].ProviderEventKey, PayloadCiphertext: []byte{2}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID},
	}}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("mixed UoW expiry err=%v", err)
	}
	for i := range rows {
		if err := db.GORM().Where("inbox_id = ?", rows[i].InboxID).First(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
		if rows[i].Version != 2 || len(rows[i].PayloadCiphertext) != 0 || len(rows[i].PayloadNonce) != 0 {
			t.Fatalf("mixed UoW row not scrubbed: %#v", rows[i])
		}
	}
}
func TestA6UOWArtifactDerivesOwnerFromSameUOWOperation(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	artifact, nonce, keyID, err := a6Seal(ctx, source, "artifact/v1", "same-uow-artifact", "same-uow-owner", 1, []byte("artifact"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Commit(ctx, UnitOfWork{
		Operations: []OperationUpdate{{OperationID: "same-uow-operation", PrincipalID: "same-uow-owner"}},
		ArtifactUpdates: []ArtifactUpdate{{
			ArtifactID: "same-uow-artifact", OperationID: "same-uow-operation", Size: int64(len("artifact")),
			Ciphertext: artifact, Nonce: nonce, EncryptionKeyID: keyID,
		}},
	})
	if err != nil {
		t.Fatalf("same-UoW operation/artifact err=%v", err)
	}
	if len(result.ArtifactIDs) != 1 || result.ArtifactIDs[0] != "same-uow-artifact" {
		t.Fatalf("same-UoW artifact result=%#v", result)
	}
	var row operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "same-uow-artifact").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OwnerPrincipalID != "same-uow-owner" {
		t.Fatalf("same-UoW artifact owner=%q", row.OwnerPrincipalID)
	}
}
func TestA6UOWSparseOperationUsesPersistedPrincipalForArtifactAAD(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	operationID := "sparse-owner-operation"
	privateCiphertext, privateNonce, keyID, err := a6Seal(ctx, source, "operation-private/v1", operationID, "persisted-owner", 1, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{
		OperationID: operationID, PrincipalID: "persisted-owner",
		PrivateContextCiphertext: privateCiphertext, PrivateContextNonce: privateNonce, EncryptionKeyID: keyID,
	}}}); err != nil {
		t.Fatal(err)
	}
	artifactCiphertext, artifactNonce, artifactKeyID, err := a6Seal(ctx, source, "artifact/v1", "sparse-owner-artifact", "persisted-owner", 1, []byte("artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Operations: []OperationUpdate{{OperationID: operationID, ExpectedVersion: 1}},
		ArtifactUpdates: []ArtifactUpdate{{
			ArtifactID: "sparse-owner-artifact", OperationID: operationID, Size: 8,
			Ciphertext: artifactCiphertext, Nonce: artifactNonce, EncryptionKeyID: artifactKeyID,
		}},
	}); err != nil {
		t.Fatalf("sparse operation artifact AAD err=%v", err)
	}
	var row operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "sparse-owner-artifact").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.OwnerPrincipalID != "persisted-owner" {
		t.Fatalf("artifact owner=%q", row.OwnerPrincipalID)
	}
}
func TestA6UOWExpiredArtifactPrecedesPayloadAuthentication(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	row := operationArtifactRow{
		ArtifactID: "uow-expired-artifact", Version: 1, PayloadVersion: 1, OperationID: "uow-operation",
		OwnerPrincipalID: "owner", MediaType: "application/octet-stream", Size: 1, Status: "available",
		Ciphertext: []byte{1}, Nonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, ExpiresAt: expiredAt,
	}
	if err := db.GORM().Create(&operationRow{
		OperationID: row.OperationID, Version: 1, Status: "pending", Kind: "test",
		PrincipalID: row.OwnerPrincipalID, IdempotencyScope: "scope", IdempotencyKey: row.OperationID,
		PrivatePayloadVersion: 1, CreatedAt: expiredAt, UpdatedAt: expiredAt,
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{
		ArtifactID: row.ArtifactID, OperationID: row.OperationID, OwnerPrincipalID: row.OwnerPrincipalID,
		Size: 1, Ciphertext: []byte{2}, Nonce: make([]byte, 12), EncryptionKeyID: source.CurrentID,
	}}}); !errors.Is(err, ErrArtifactGone) {
		t.Fatalf("expired artifact auth precedence err=%v", err)
	}
	if err := db.GORM().Where("artifact_id = ?", row.ArtifactID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Version != 2 || row.Status != "expired" || len(row.Ciphertext) != 0 || len(row.Nonce) != 0 {
		t.Fatalf("expired artifact was not scrubbed: %#v", row)
	}
}
func TestA6MixedInboxArtifactExpiryCompensation(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	inbox := inboxMessageRow{
		InboxID: "mixed-inbox-artifact-expiry", EndpointID: "endpoint", ProviderEventKey: "provider",
		LaneHMAC: []byte("mixed-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1,
		PayloadCiphertext: []byte{1}, PayloadNonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	queueSchedulingMigrateFixture(t, db)
	operationID := "mixed-inbox-artifact-operation"
	if err := db.GORM().Create(&operationRow{
		OperationID: operationID, Version: 1, Status: "pending", Kind: "test", PrincipalID: "owner",
		IdempotencyScope: "scope", IdempotencyKey: operationID, PrivatePayloadVersion: 1,
		CreatedAt: expiredAt, UpdatedAt: expiredAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	artifact := operationArtifactRow{
		ArtifactID: "mixed-inbox-artifact", Version: 1, PayloadVersion: 1, OperationID: operationID,
		OwnerPrincipalID: "owner", MediaType: "application/octet-stream", Size: 1, Status: "available",
		Ciphertext: []byte{1}, Nonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, ExpiresAt: expiredAt,
	}
	if err := db.GORM().Create(&artifact).Error; err != nil {
		t.Fatal(err)
	}
	_, err := store.Commit(context.Background(), UnitOfWork{
		InboxUpdates: []InboxUpdate{{
			InboxID: inbox.InboxID, EndpointID: inbox.EndpointID, ProviderEventKey: inbox.ProviderEventKey,
			PayloadCiphertext: []byte{2}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID,
		}},
		ArtifactUpdates: []ArtifactUpdate{{
			ArtifactID: artifact.ArtifactID, OperationID: operationID, OwnerPrincipalID: "owner",
			Size: 1, Ciphertext: []byte{2}, Nonce: make([]byte, 12), EncryptionKeyID: source.CurrentID,
		}},
	})
	if !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("mixed inbox/artifact expiry err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Where("artifact_id = ?", artifact.ArtifactID).First(&artifact).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Version != 2 || len(inbox.PayloadCiphertext) != 0 || len(inbox.PayloadNonce) != 0 {
		t.Fatalf("mixed inbox row not scrubbed: %#v", inbox)
	}
	if artifact.Version != 2 || artifact.Status != "expired" || len(artifact.Ciphertext) != 0 || len(artifact.Nonce) != 0 {
		t.Fatalf("mixed artifact row not scrubbed: %#v", artifact)
	}
}
func TestA6UOWOperationVersionOverflowPrecedesPrivateAuthentication(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	now := time.Now().UTC()
	row := operationRow{
		Version: maxPersistedVersion, Status: "pending", OperationID: "overflow-operation", Kind: "test",
		PrincipalID: "owner", IdempotencyScope: "scope", IdempotencyKey: "overflow-operation",
		PrivatePayloadVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	_, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{
		OperationID: row.OperationID, ExpectedVersion: row.Version, PrincipalID: row.PrincipalID,
		PrivateContextCiphertext: []byte{1}, PrivateContextNonce: make([]byte, 12), EncryptionKeyID: source.CurrentID,
	}}})
	if !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("operation version overflow err=%v", err)
	}
}
func TestA6UOWArtifactRejectsUnadmittedEncryptionRoot(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "unadmitted-artifact-operation", PrincipalID: "owner"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{
		ArtifactID: "unadmitted-artifact", OperationID: "unadmitted-artifact-operation", OwnerPrincipalID: "owner",
		Size: 1, Ciphertext: []byte{1}, Nonce: make([]byte, 12), EncryptionKeyID: source.CurrentID + "-unadmitted",
	}}})
	if !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unadmitted artifact root err=%v", err)
	}
}
