package eventstore

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func TestPrivacyResolvePendingAdvancesQueueLaneHeads(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	subject := bytes.Repeat([]byte{1}, 32)
	otherSubject := bytes.Repeat([]byte{2}, 32)
	if err := db.GORM().Create(&operationRow{
		OperationID: "purge-queue-head", Kind: "privacy-purge", Status: "running", Version: 1,
		PrincipalID: fmt.Sprintf("hmac:%x", subject),
	}).Error; err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"purged-head", "surviving-successor"} {
		key := subject
		if i == 1 {
			key = otherSubject
		}
		inbox := newInboxTestUpdate("in-"+id, "provider-"+id, "privacy-inbox-lane")
		inbox.SubjectKey = key
		if _, err := store.AcceptInbox(ctx, inbox); err != nil {
			t.Fatal(err)
		}
		effect := newOutboxTestEffect("out-"+id, "privacy-outbox-lane")
		effect.SubjectKey = key
		if _, err := store.AcceptOutbox(ctx, effect); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PrivacyResolvePending(ctx, subject, "purge-queue-head"); err != nil {
		t.Fatal(err)
	}
	var purgedInbox inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "in-purged-head").First(&purgedInbox).Error; err != nil {
		t.Fatal(err)
	}
	var purgedOutbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "out-purged-head").First(&purgedOutbox).Error; err != nil {
		t.Fatal(err)
	}
	if purgedInbox.Status != InboxStatusSkipped || len(purgedInbox.PayloadCiphertext) != 0 ||
		purgedOutbox.Status != OutboxStatusFailed || len(purgedOutbox.PayloadCiphertext) != 0 {
		t.Fatalf("privacy purge did not preserve terminal scrubbing: inbox=%s outbox=%s", purgedInbox.Status, purgedOutbox.Status)
	}
	inbox, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "privacy-inbox-worker", LeaseDuration: time.Minute})
	if err != nil || inbox.Update.InboxID != "in-surviving-successor" {
		t.Fatalf("claim after privacy purge = %q, %v; want surviving inbox successor", inbox.Update.InboxID, err)
	}
	outbox, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "privacy-outbox-worker", LeaseDuration: time.Minute})
	if err != nil || outbox.Effect.EffectID != "out-surviving-successor" {
		t.Fatalf("claim after privacy purge = %q, %v; want surviving outbox successor", outbox.Effect.EffectID, err)
	}
}
