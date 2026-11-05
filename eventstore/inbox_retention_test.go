package eventstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestTerminalInboxRetentionDeletesWholeRowsOnlyAfterThirtyDays(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	clock.Advance(60 * 24 * time.Hour)
	cutoff := clock.Now().Add(-terminalInboxRetention)
	aged := cutoff.Add(-time.Hour)
	fresh := cutoff.Add(time.Hour)
	type sample struct {
		id, status string
		completed  *time.Time
		remove     bool
	}
	samples := []sample{
		{"consumed", InboxStatusConfirmedConsumed, &aged, true}, {"failed", InboxStatusFailed, &aged, true}, {"skipped", InboxStatusSkipped, &aged, true}, {"ambiguous", InboxStatusAmbiguous, &aged, true},
		{"boundary", InboxStatusConfirmedConsumed, &cutoff, false}, {"fresh", InboxStatusFailed, &fresh, false}, {"undated", InboxStatusConfirmedConsumed, nil, false},
		{"pending", InboxStatusPending, &aged, false}, {"leased", InboxStatusLeased, &aged, false}, {"started", InboxStatusCallbackStarted, &aged, false},
	}
	payload := []byte{0, 255, 'p', 'l', 'a', 'i', 'n'}
	for _, sample := range samples {
		row := inboxMessageRow{InboxID: sample.id, EndpointID: "endpoint", ProviderEventKey: sample.id, Lane: sample.id, OrderingSequence: 1, Status: sample.status, Version: 1, CompletedAt: sample.completed, Payload: payload}
		if err := db.GORM().Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	var before inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "consumed").Take(&before).Error; err != nil || !bytes.Equal(before.Payload, payload) {
		t.Fatalf("terminal body scrubbed early: %+v %v", before, err)
	}
	deleted, err := store.DeleteExpiredTerminalInbox(ctx)
	if err != nil || deleted != 4 {
		t.Fatalf("delete=%d err=%v", deleted, err)
	}
	for _, sample := range samples {
		var row inboxMessageRow
		err := db.GORM().Where("inbox_id = ?", sample.id).Take(&row).Error
		if sample.remove {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf("expired row survived or lookup failed: %s %v", sample.id, err)
			}
			continue
		}
		if err != nil || !bytes.Equal(row.Payload, payload) {
			t.Fatalf("retained row changed %s: %+v %v", sample.id, row, err)
		}
	}
	clock.Advance(time.Second)
	if deleted, err := store.DeleteExpiredTerminalInbox(ctx); err != nil || deleted != 1 {
		t.Fatalf("strict boundary did not advance: %d %v", deleted, err)
	}
}
func TestTerminalInboxRetentionRollsBackAndReleasesTheLaneAfterCommit(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	clock.Advance(60 * 24 * time.Hour)
	completed := clock.Now().Add(-terminalInboxRetention - time.Hour)
	expired := inboxMessageRow{InboxID: "expired", EndpointID: "endpoint", ProviderEventKey: "expired", Lane: "shared", OrderingSequence: 1, Status: InboxStatusAmbiguous, Version: 1, CompletedAt: &completed, Payload: []byte("retain until deletion")}
	if err := db.GORM().Create(&expired).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "next", EndpointID: "endpoint", ProviderEventKey: "next", Lane: "shared", Payload: []byte{}}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec("CREATE TRIGGER reject_inbox_retention BEFORE DELETE ON inbox_messages BEGIN SELECT RAISE(ABORT,'injected'); END").Error; err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteExpiredTerminalInbox(ctx); err == nil || deleted != 0 {
		t.Fatalf("failed cleanup=%d %v", deleted, err)
	}
	var row inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "expired").Take(&row).Error; err != nil || !bytes.Equal(row.Payload, expired.Payload) {
		t.Fatalf("rollback lost body: %+v %v", row, err)
	}
	if err := db.GORM().Exec("DROP TRIGGER reject_inbox_retention").Error; err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.DeleteExpiredTerminalInbox(ctx); err != nil || deleted != 1 {
		t.Fatalf("cleanup=%d %v", deleted, err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"})
	if err != nil || lease.Update.InboxID != "next" {
		t.Fatalf("lane not released: %+v %v", lease, err)
	}
}

func TestExpiredCallbackAmbiguityStartsTheRetentionClock(t *testing.T) {
	for _, recovery := range []string{"expired-owner", "claim"} {
		t.Run(recovery, func(t *testing.T) {
			store, db, clock := openQueueTestStore(t)
			defer db.Close()
			ctx := context.Background()
			if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "callback", EndpointID: "endpoint", ProviderEventKey: "callback", Lane: "lane", Payload: []byte("retained")}); err != nil {
				t.Fatal(err)
			}
			lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker", LeaseDuration: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			update := InboxUpdate{InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner, LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID, LeaseExpiresAt: lease.Update.LeaseExpiresAt}
			started, err := store.UpdateInbox(ctx, update)
			if err != nil {
				t.Fatal(err)
			}
			clock.Advance(2 * time.Minute)
			if recovery == "claim" {
				if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "restarted"}); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expired callback was replayed: %v", err)
				}
			} else {
				update.ExpectedVersion = started.Version
				update.Status = InboxStatusAmbiguous
				if _, err := store.UpdateInbox(ctx, update); err != nil {
					t.Fatal(err)
				}
			}
			var row inboxMessageRow
			if err := db.GORM().Where("inbox_id = ?", "callback").Take(&row).Error; err != nil || row.Status != InboxStatusAmbiguous || row.CompletedAt == nil || !row.CompletedAt.Equal(clock.Now()) || string(row.Payload) != "retained" {
				t.Fatalf("ambiguity completion/body=%+v %v", row, err)
			}
			clock.Advance(terminalInboxRetention + time.Second)
			if deleted, err := store.DeleteExpiredTerminalInbox(ctx); err != nil || deleted != 1 {
				t.Fatalf("expired callback cleanup=%d %v", deleted, err)
			}
		})
	}
}

func TestInboxExpiredCallbackRecoveryIsBounded(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	started := clock.Now()
	expires := started.Add(time.Minute)
	if err := db.GORM().Transaction(func(tx *gorm.DB) error {
		for i := 0; i <= task5InboxRecoveryBatchSize; i++ {
			id := fmt.Sprintf("callback-%03d", i)
			sequence, laneID, err := task5AllocateLane(tx, inboxLaneKind, id, started)
			if err != nil {
				return err
			}
			row := inboxMessageRow{
				InboxID: id, EndpointID: "endpoint", ProviderEventKey: id, Lane: id, LaneID: laneID,
				OrderingSequence: sequence, Status: InboxStatusCallbackStarted, Version: 3,
				LeaseOwner: "stopped-worker", LeaseEpoch: 1, AttemptID: id, LeaseExpiry: &expires,
				CallbackStartedAt: &started, Payload: []byte("retain"),
			}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			if err := refreshQueueLane(tx, inboxLaneKind, id, started); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "restarted"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired callbacks were replayed: %v", err)
	}
	var recovered int64
	if err := db.GORM().Model(&inboxMessageRow{}).Where("status = ?", InboxStatusAmbiguous).Count(&recovered).Error; err != nil || recovered != task5InboxRecoveryBatchSize {
		t.Fatalf("recovery exceeded its batch: %d %v", recovered, err)
	}
	if available, err := store.HasInboxWork(ctx); err != nil || !available {
		t.Fatalf("remaining expired callback was not scheduled: %v %v", available, err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "restarted"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remaining callback was replayed: %v", err)
	}
	if err := db.GORM().Model(&inboxMessageRow{}).Where("status = ?", InboxStatusAmbiguous).Count(&recovered).Error; err != nil || recovered != task5InboxRecoveryBatchSize+1 {
		t.Fatalf("remaining expired callback was not recovered: %d %v", recovered, err)
	}
	if available, err := store.HasInboxWork(ctx); err != nil || available {
		t.Fatalf("recovered callbacks remained scheduled: %v %v", available, err)
	}
}
