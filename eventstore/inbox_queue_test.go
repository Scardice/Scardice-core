package eventstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestInboxAcceptanceDedupeAndLaneAllocation(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	first, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("inbox-1", "provider-1", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.OrderingSequence != 1 || first.Deduplicated {
		t.Fatalf("first result = %#v", first)
	}
	second, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("different-id", "provider-1", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduplicated || second.OrderingSequence != 1 || len(second.InboxIDs) != 1 || second.InboxIDs[0] != "inbox-1" {
		t.Fatalf("dedupe result = %#v", second)
	}
	third, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("inbox-2", "provider-2", "lane-1"))
	if err != nil {
		t.Fatal(err)
	}
	if third.OrderingSequence != 2 {
		t.Fatalf("caller sequence bypassed allocation: %#v", third)
	}
}

func TestInboxRedeliveryDeduplicatesStableContentAcrossEnvelopeChanges(t *testing.T) {
	for _, path := range []string{"accept", "uow-new-id", "uow-same-id"} {
		t.Run(path, func(t *testing.T) {
			store, db, _ := openQueueTestStore(t)
			defer db.Close()
			ctx := context.Background()
			original := newInboxTestUpdate("original", "provider", "lane")
			original.Subject = "group"
			original.ContentDigest = []byte{1, 2, 3}
			original.Payload = []byte(`{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"body":"same","providerData":"first"}}`)
			if _, err := store.AcceptInbox(ctx, original); err != nil {
				t.Fatal(err)
			}
			redelivery := original
			redelivery.InboxID = "redelivery"
			redelivery.Payload = []byte(`{"endpointId":"endpoint","generation":2,"desiredVersion":3,"message":{"body":"same","providerData":"redelivered"}}`)
			var result CommitResult
			var err error
			if path == "accept" {
				result, err = store.AcceptInbox(ctx, redelivery)
			} else {
				if path == "uow-same-id" {
					redelivery.InboxID = original.InboxID
				}
				result, err = store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{redelivery}})
			}
			if err != nil || !result.Deduplicated || !result.Idempotent || result.OrderingSequence != 1 || result.Version != 1 {
				t.Fatalf("redelivery=%+v err=%v", result, err)
			}
			conflict := redelivery
			conflict.ContentDigest = []byte{4, 5, 6}
			if path == "accept" {
				_, err = store.AcceptInbox(ctx, conflict)
			} else {
				_, err = store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{conflict}})
			}
			if err == nil {
				t.Fatal("different stable content was accepted as a duplicate")
			}
			lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"})
			if err != nil || lease.Update.InboxID != original.InboxID || !bytes.Equal(lease.Update.Payload, original.Payload) || !bytes.Equal(lease.Update.ContentDigest, original.ContentDigest) {
				t.Fatalf("duplicate replaced the accepted envelope: %+v %v", lease, err)
			}
			if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "other"}); !errors.Is(err, ErrNotFound) {
				t.Fatalf("redelivery allocated another row: %v", err)
			}
		})
	}
}

func TestInboxDigestDedupePreservesExactLaneSubjectAndContent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lane    string
		subject string
		digest  []byte
	}{
		{name: "lane", lane: "Lane", subject: "group", digest: []byte{1}},
		{name: "subject", lane: "lane", subject: "Group", digest: []byte{1}},
		{name: "content", lane: "lane", subject: "group", digest: []byte{2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db, _ := openQueueTestStore(t)
			defer db.Close()
			original := newInboxTestUpdate("original", "provider", "lane")
			original.Subject, original.ContentDigest = "group", []byte{1}
			if _, err := store.AcceptInbox(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			redelivery := original
			redelivery.InboxID, redelivery.Lane, redelivery.Subject, redelivery.ContentDigest = "redelivery", tc.lane, tc.subject, tc.digest
			if _, err := store.AcceptInbox(context.Background(), redelivery); !errors.Is(err, ErrConflict) {
				t.Fatalf("conflicting redelivery=%v", err)
			}
		})
	}
}

func TestInboxDigestlessRedeliveryComparesRawPayload(t *testing.T) {
	for _, digest := range [][]byte{nil, {1}} {
		t.Run(fmt.Sprintf("stored-digest-%x", digest), func(t *testing.T) {
			store, db, _ := openQueueTestStore(t)
			defer db.Close()
			original := newInboxTestUpdate("original", "provider", "lane")
			original.ContentDigest = digest
			if _, err := store.AcceptInbox(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			redelivery := original
			redelivery.InboxID, redelivery.ContentDigest = "redelivery", nil
			if result, err := store.AcceptInbox(context.Background(), redelivery); err != nil || !result.Deduplicated {
				t.Fatalf("digestless duplicate=%+v err=%v", result, err)
			}
			redelivery.Payload = []byte("different raw body")
			if _, err := store.AcceptInbox(context.Background(), redelivery); !errors.Is(err, ErrConflict) {
				t.Fatalf("digestless content conflict=%v", err)
			}
			if len(digest) == 0 {
				redelivery.Payload = original.Payload
				redelivery.ContentDigest = []byte{1}
				if _, err := store.AcceptInbox(context.Background(), redelivery); !errors.Is(err, ErrConflict) {
					t.Fatalf("supplied digest matched a digestless stored row: %v", err)
				}
			}
		})
	}
}

func TestInboxExpiredCallbackRecoveryRollsBackAndNeverReplays(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	original := newInboxTestUpdate("callback", "provider", "lane")
	if _, err := store.AcceptInbox(ctx, original); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("successor", "next-provider", "lane")); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{
		InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Status: InboxStatusCallbackStarted,
		LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
	}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * time.Second)
	renewed, err := store.RenewInbox(ctx, InboxRenewRequest{
		InboxID: original.InboxID, WorkerID: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch,
		AttemptID: lease.Update.AttemptID, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * time.Second)
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "blocked"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery ignored renewed expiry: %v", err)
	}
	clock.Advance(30 * time.Second)
	if available, err := store.HasInboxWork(ctx); err != nil || !available {
		t.Fatalf("expired callback was not scheduled: %v %v", available, err)
	}
	if err := db.GORM().Exec("CREATE TRIGGER reject_callback_recovery BEFORE UPDATE ON lane_heads WHEN NEW.active_id = 'successor' BEGIN SELECT RAISE(ABORT, 'injected'); END").Error; err != nil {
		t.Fatal(err)
	}
	if recovered, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "restarted"}); err == nil || recovered.Update.InboxID != "" {
		t.Fatalf("failed recovery returned a lease: %+v %v", recovered, err)
	}
	var before inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", original.InboxID).Take(&before).Error; err != nil {
		t.Fatal(err)
	}
	if before.Status != InboxStatusCallbackStarted || before.Version != renewed.Update.Version || before.CompletedAt != nil ||
		before.LeaseExpiry == nil || !before.LeaseExpiry.Equal(renewed.Update.LeaseExpiresAt) || before.CallbackStartedAt == nil || !bytes.Equal(before.Payload, original.Payload) {
		t.Fatalf("failed recovery escaped rollback: %+v", before)
	}
	if err := db.GORM().Exec("DROP TRIGGER reject_callback_recovery").Error; err != nil {
		t.Fatal(err)
	}
	next, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "restarted"})
	if err != nil || next.Update.InboxID != "successor" {
		t.Fatalf("recovery did not advance the lane: %+v %v", next, err)
	}
	var recovered inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", original.InboxID).Take(&recovered).Error; err != nil {
		t.Fatal(err)
	}
	if recovered.Status != InboxStatusAmbiguous || recovered.Version != renewed.Update.Version+1 || recovered.LeaseExpiry != nil ||
		recovered.CompletedAt == nil || !recovered.CompletedAt.Equal(clock.Now()) || !bytes.Equal(recovered.Payload, original.Payload) ||
		recovered.LeaseOwner != lease.Update.LeaseOwner || recovered.LeaseEpoch != lease.Update.LeaseEpoch || recovered.AttemptID != lease.Update.AttemptID ||
		recovered.CallbackStartedAt == nil || !recovered.CallbackStartedAt.Equal(*before.CallbackStartedAt) {
		t.Fatalf("recovered callback metadata/body=%+v", recovered)
	}
	if _, err := store.RenewInbox(ctx, InboxRenewRequest{
		InboxID: original.InboxID, WorkerID: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
	}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("recovered callback owner renewed its lease: %v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{
		InboxID: next.Update.InboxID, ExpectedVersion: next.Update.Version, Status: InboxStatusFailed,
		LeaseOwner: next.Update.LeaseOwner, LeaseEpoch: next.Update.LeaseEpoch, AttemptID: next.Update.AttemptID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "replay-check"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired callback was replayed: %v", err)
	}
}

func TestInboxIsolatedFailuresDoNotBlockSuccessorsOrReplay(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		id := "inbox-" + strconv.Itoa(i)
		if _, err := store.AcceptInbox(ctx, newInboxTestUpdate(id, "p"+strconv.Itoa(i), "lane")); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil || first.Update.InboxID != "inbox-1" {
		t.Fatalf("first claim = %#v err=%v", first, err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("leased predecessor claim err=%v", err)
	}
	started := InboxUpdate{InboxID: first.Update.InboxID, ExpectedVersion: first.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: first.Update.LeaseOwner, LeaseEpoch: first.Update.LeaseEpoch, AttemptID: first.Update.AttemptID}
	if _, err := store.UpdateInbox(ctx, started); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("callback-started predecessor claim err=%v", err)
	}
	ambiguous := started
	ambiguous.ExpectedVersion = 3
	ambiguous.Status = InboxStatusAmbiguous
	if _, err := store.UpdateInbox(ctx, ambiguous); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "other", LeaseDuration: time.Minute})
	if err != nil || second.Update.InboxID != "inbox-2" {
		t.Fatalf("successor after ambiguity = %#v err=%v", second, err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "third", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("successor bypassed active lease err=%v", err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{
		InboxID: second.Update.InboxID, ExpectedVersion: second.Update.Version, Status: InboxStatusFailed,
		LeaseOwner: second.Update.LeaseOwner, LeaseEpoch: second.Update.LeaseEpoch, AttemptID: second.Update.AttemptID,
	}); err != nil {
		t.Fatal(err)
	}
	third, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "third", LeaseDuration: time.Minute})
	if err != nil || third.Update.InboxID != "inbox-3" {
		t.Fatalf("successor after failure = %#v err=%v", third, err)
	}
	if _, err := store.UpdateInbox(ctx, InboxUpdate{
		InboxID: third.Update.InboxID, ExpectedVersion: third.Update.Version, Status: InboxStatusFailed,
		LeaseOwner: third.Update.LeaseOwner, LeaseEpoch: third.Update.LeaseEpoch, AttemptID: third.Update.AttemptID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "replay-check", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("isolated inbox was replayed: %v", err)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: "inbox-1", ExpectedVersion: 4, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "operator", Reason: "verified"}); err != nil {
		t.Fatal(err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "inbox-1").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusConfirmedConsumed || string(row.Payload) != "inbound-payload" {
		t.Fatalf("resolved inbox payload/status = %q/%q", row.Payload, row.Status)
	}
}
func TestInboxLeaseRenewalRequiresCurrentOwnerEpochAndAttempt(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("renew-inbox", "renew-provider", "renew-lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * time.Second)
	renewed, err := store.RenewInbox(ctx, InboxRenewRequest{
		InboxID:       claimed.Update.InboxID,
		WorkerID:      claimed.Update.LeaseOwner,
		LeaseEpoch:    claimed.Update.LeaseEpoch,
		AttemptID:     claimed.Update.AttemptID,
		LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Update.Version != claimed.Update.Version+1 || !renewed.Update.LeaseExpiresAt.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("renewed lease = %#v", renewed)
	}
	if _, err := store.RenewInbox(ctx, InboxRenewRequest{
		InboxID:       claimed.Update.InboxID,
		WorkerID:      claimed.Update.LeaseOwner,
		LeaseEpoch:    claimed.Update.LeaseEpoch,
		AttemptID:     "stale-attempt",
		LeaseDuration: time.Minute,
	}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale renewal err = %v", err)
	}
}
func TestInboxConcurrentAcceptanceAllocatesUniqueSequences(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	const count = 12
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := newInboxTestUpdate("concurrent-"+strconv.Itoa(i), "provider-"+strconv.Itoa(i), "shared-lane")
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
	if err := db.GORM().Where("lane = ?", "shared-lane").Order("ordering_sequence ASC").Find(&rows).Error; err != nil {
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
func TestUOWCallbackStartedTimestamp(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	inbox := newInboxTestUpdate("uow-callback-started", "uow-callback-provider", "uow-callback-lane")
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "uow-callback-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{InboxID: inbox.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version + 1, Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID}}}); err != nil {
		t.Fatal(err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.CallbackStartedAt == nil || row.Status != InboxStatusCallbackStarted {
		t.Fatalf("callback-started participant row = %#v", row)
	}
}

func TestInboxPersistsPlaintextSubjectAndOmitsSubjectOnDuplicate(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()

	update := newInboxTestUpdate("subject-inbox", "subject-provider", "subject-lane")
	update.Subject = "group:plain"
	if _, err := store.AcceptInbox(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	lease, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "subject-worker", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if lease.Update.Subject != update.Subject {
		t.Fatalf("claimed subject = %q, want %q", lease.Update.Subject, update.Subject)
	}
	if _, err := store.UpdateInbox(context.Background(), InboxUpdate{
		InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version,
		Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner,
		LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version + 1,
		Status: InboxStatusConfirmedConsumed, LeaseOwner: lease.Update.LeaseOwner,
		LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
	}}}); err != nil {
		t.Fatal(err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", update.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Subject != update.Subject || string(row.Payload) != string(update.Payload) {
		t.Fatalf("terminal inbox metadata = %#v", row)
	}
}
func TestInboxStatusesReportWhatBecameOfEachRow(t *testing.T) {
	ctx := context.Background()
	store, db, _ := openQueueTestStore(t)
	defer db.Close()

	var ids []string
	for i := range 3 {
		update := newInboxTestUpdate(fmt.Sprintf("inbox-%d", i), fmt.Sprintf("provider-%d", i), "lane")
		if _, err := store.AcceptInbox(ctx, update); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, update.InboxID)
	}
	if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", ids[1]).Update("status", InboxStatusConfirmedConsumed).Error; err != nil {
		t.Fatal(err)
	}

	statuses, err := store.InboxStatuses(ctx, append(ids, "purged-or-never-existed"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{ids[0]: InboxStatusPending, ids[1]: InboxStatusConfirmedConsumed, ids[2]: InboxStatusPending}
	if len(statuses) != len(want) {
		t.Fatalf("statuses = %v, want exactly %v (an unknown id has no entry)", statuses, want)
	}
	for id, status := range want {
		if statuses[id] != status {
			t.Fatalf("%s is %q, want %q", id, statuses[id], status)
		}
	}
}
func TestInboxStatusesAreBounded(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()

	if statuses, err := store.InboxStatuses(context.Background(), nil); err != nil || len(statuses) != 0 {
		t.Fatalf("no ids: %v, %v", statuses, err)
	}
	tooMany := make([]string, MaxInboxStatusQuery+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("inbox-%d", i)
	}
	if _, err := store.InboxStatuses(context.Background(), tooMany); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("an unbounded lookup was accepted: %v", err)
	}
}
