package eventstore

import (
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
	if row.Status != InboxStatusConfirmedConsumed || len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
		t.Fatalf("resolved isolated inbox = %#v", row)
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
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	expiry := clock.Now().Add(time.Minute)
	u := newInboxTestUpdate("expiry-inbox", "expiry-provider", "expiry-lane")
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
func TestInboxIngressRejectsPayloadTTLBypass(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	update := newInboxTestUpdate("ttl-inbox", "ttl-provider", "ttl-lane")
	update.PayloadExpiresAt = clock.Now().Add(InboxPayloadTTL + time.Second)
	if _, err := store.AcceptInbox(context.Background(), update); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("inbox ttl err = %v", err)
	}
	expired := newInboxTestUpdate("ttl-expired-inbox", "ttl-expired-provider", "ttl-expired-lane")
	expired.PayloadExpiresAt = clock.Now().Add(-time.Second)
	if _, err := store.AcceptInbox(context.Background(), expired); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("expired inbox ttl err = %v", err)
	}
}
func TestInboxCallbackExpiryScrubsWithoutUnblockingRetry(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	update := newInboxTestUpdate("callback-expired", "callback-provider", "callback-lane")
	update.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptInbox(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	callback := InboxUpdate{InboxID: claimed.Update.InboxID, ExpectedVersion: claimed.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: claimed.Update.LeaseOwner, LeaseEpoch: claimed.Update.LeaseEpoch, AttemptID: claimed.Update.AttemptID}
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
	if _, err := store.ResolveInbox(context.Background(), InboxResolutionRequest{
		InboxID: row.InboxID, ExpectedVersion: row.Version, Resolution: InboxResolutionSkip,
		PrincipalID: "operator", Reason: "callback expired",
	}); err != nil {
		t.Fatalf("callback expiry resolve err = %v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", row.InboxID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != InboxStatusSkipped {
		t.Fatalf("callback expiry resolved status = %q", row.Status)
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
func TestInboxIngressAllowsExplicitReacceptAfterDedupeTTL(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	first := newInboxTestUpdate("ttl-reaccept-first", "ttl-reaccept-provider", "ttl-reaccept-lane")
	first.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	if _, err := store.AcceptInbox(ctx, first); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7*24*time.Hour + time.Second)
	second := newInboxTestUpdate("ttl-reaccept-second", "ttl-reaccept-provider", "ttl-reaccept-lane")
	second.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	second.AllowExpiredDedupe = true
	result, err := store.AcceptInbox(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deduplicated || len(result.InboxIDs) != 1 || result.InboxIDs[0] != second.InboxID {
		t.Fatalf("post-TTL result = %#v", result)
	}
}
func TestInboxIngressAllowsExplicitReacceptAfterTerminalDedupeTTL(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	first := newInboxTestUpdate("ttl-terminal-first", "ttl-terminal-provider", "ttl-terminal-lane")
	first.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	if _, err := store.AcceptInbox(ctx, first); err != nil {
		t.Fatal(err)
	}
	lease, claimErr := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "ttl-terminal-worker", LeaseDuration: time.Minute})
	if claimErr != nil {
		t.Fatal(claimErr)
	}
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "test", Reason: "terminal"}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7*24*time.Hour + time.Second)
	second := newInboxTestUpdate("ttl-terminal-second", "ttl-terminal-provider", "ttl-terminal-lane")
	second.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	second.AllowExpiredDedupe = true
	result, claimErr := store.AcceptInbox(ctx, second)
	if claimErr != nil {
		t.Fatal(claimErr)
	}
	if result.Deduplicated || len(result.InboxIDs) != 1 || result.InboxIDs[0] != second.InboxID {
		t.Fatalf("post-terminal-TTL result = %#v", result)
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
