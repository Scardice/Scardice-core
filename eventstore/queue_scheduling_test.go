package eventstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"
)

func queueSchedulingMigrateFixture(t testing.TB, db *Database) {
	t.Helper()
	if err := migrateQueueScheduling(db.GORM()); err != nil {
		t.Fatal(err)
	}
}

func TestQueueSchedulingMigrationBatchPlansUseVersionIndexesWithoutTempSort(t *testing.T) {
	_, db, _ := openQueueTestStore(t)
	defer db.Close()

	t.Run("inbox", func(t *testing.T) {
		var rows []inboxMessageRow
		sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
			return inboxSchedulingMigrationBatch(tx, &rows)
		})
		assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_inbox_scheduling_version")
	})
	t.Run("outbox", func(t *testing.T) {
		var rows []outboxEffectRow
		sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
			return outboxSchedulingMigrationBatch(tx, &rows)
		})
		assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_outbox_scheduling_version")
	})
	t.Run("lane-heads", func(t *testing.T) {
		var rows []laneHeadRow
		sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
			return laneSchedulingMigrationBatch(tx, &rows)
		})
		assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_lane_heads_scheduling_version")
	})
}

func queueSchedulingCompleteInbox(t *testing.T, store *GORMStore, lease InboxLease) {
	t.Helper()
	if _, err := store.ResolveInbox(context.Background(), InboxResolutionRequest{
		InboxID:         lease.Update.InboxID,
		ExpectedVersion: lease.Update.Version,
		Resolution:      InboxResolutionConfirmedConsumed,
		PrincipalID:     "queue-scheduling-test",
		Reason:          "processed",
	}); err != nil {
		t.Fatal(err)
	}
}

func queueSchedulingCompleteOutbox(t *testing.T, store *GORMStore, lease OutboxLease) {
	t.Helper()
	ctx := context.Background()
	dispatched, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
		EffectID:   lease.Effect.EffectID,
		WorkerID:   lease.Effect.LeaseOwner,
		LeaseEpoch: lease.Effect.LeaseEpoch,
		AttemptID:  lease.Effect.AttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, OutboxCompletionRequest{
		EffectID:   dispatched.Effect.EffectID,
		WorkerID:   dispatched.Effect.LeaseOwner,
		LeaseEpoch: dispatched.Effect.LeaseEpoch,
		AttemptID:  dispatched.Effect.AttemptID,
		Status:     OutboxStatusSucceeded,
		ResultCode: "ok",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInboxQueueSchedulingUsesReadyLaneAgeNotLocalSequence(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	for _, id := range []string{"older-lane-first", "older-lane-ready"} {
		if _, err := store.AcceptInbox(ctx, newInboxTestUpdate(id, id+"-provider", "older-lane")); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "first-worker", LeaseDuration: time.Minute})
	if err != nil || first.Update.InboxID != "older-lane-first" {
		t.Fatalf("first claim = %#v, %v", first, err)
	}
	queueSchedulingCompleteInbox(t, store, first)

	clock.Advance(time.Second)
	if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("newer-lane-low-sequence", "newer-lane-provider", "newer-lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "fair-worker", LeaseDuration: time.Minute})
	if err != nil || claimed.Update.InboxID != "older-lane-ready" {
		t.Fatalf("fair claim = %#v, %v; want older-lane-ready", claimed, err)
	}
}

func TestOutboxQueueSchedulingUsesReadyLaneAgeNotLocalSequence(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	for _, id := range []string{"older-lane-first", "older-lane-ready"} {
		if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect(id, "older-lane")); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "first-worker", LeaseDuration: time.Minute})
	if err != nil || first.Effect.EffectID != "older-lane-first" {
		t.Fatalf("first claim = %#v, %v", first, err)
	}
	queueSchedulingCompleteOutbox(t, store, first)

	clock.Advance(time.Second)
	if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("newer-lane-low-sequence", "newer-lane")); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "fair-worker", LeaseDuration: time.Minute})
	if err != nil || claimed.Effect.EffectID != "older-lane-ready" {
		t.Fatalf("fair claim = %#v, %v; want older-lane-ready", claimed, err)
	}
}

func TestQueueSchedulingRefreshesGenericCommitParticipants(t *testing.T) {
	t.Run("inbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()

		if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("generic-inbox-first", "generic-inbox-first-provider", "generic-inbox-old-lane")); err != nil {
			t.Fatal(err)
		}
		first, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "generic-inbox-first-worker", LeaseDuration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		queueSchedulingCompleteInbox(t, store, first)

		clock.Advance(time.Second)
		if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{
			newInboxTestUpdate("generic-inbox-ready", "generic-inbox-ready-provider", "generic-inbox-old-lane"),
		}}); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)
		if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("generic-inbox-newer", "generic-inbox-newer-provider", "generic-inbox-new-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "generic-inbox-worker", LeaseDuration: time.Minute})
		if err != nil || claimed.Update.InboxID != "generic-inbox-ready" {
			t.Fatalf("claim after generic commit = %#v, %v; want generic-inbox-ready", claimed, err)
		}
	})

	t.Run("outbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()

		if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("generic-outbox-first", "generic-outbox-old-lane")); err != nil {
			t.Fatal(err)
		}
		first, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "generic-outbox-first-worker", LeaseDuration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		queueSchedulingCompleteOutbox(t, store, first)

		clock.Advance(time.Second)
		if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{
			newOutboxTestEffect("generic-outbox-ready", "generic-outbox-old-lane"),
		}}); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)
		if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("generic-outbox-newer", "generic-outbox-new-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "generic-outbox-worker", LeaseDuration: time.Minute})
		if err != nil || claimed.Effect.EffectID != "generic-outbox-ready" {
			t.Fatalf("claim after generic commit = %#v, %v; want generic-outbox-ready", claimed, err)
		}
	})
}

func TestQueueSchedulingPreservesInflightBlockingAndIsolationProgress(t *testing.T) {
	t.Run("inbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()
		head := newInboxTestUpdate("isolated-inbox-head", "isolated-inbox-head-provider", "isolated-inbox-lane")
		head.PayloadExpiresAt = clock.Now().Add(time.Minute)
		if _, err := store.AcceptInbox(ctx, head); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcceptInbox(ctx, newInboxTestUpdate("isolated-inbox-successor", "isolated-inbox-successor-provider", "isolated-inbox-lane")); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "isolated-inbox-worker", LeaseDuration: time.Minute})
		if err != nil || lease.Update.InboxID != head.InboxID {
			t.Fatalf("head claim = %#v, %v", lease, err)
		}
		if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "blocked-inbox-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("claim behind inflight head err = %v, want not found", err)
		}
		started, err := store.UpdateInbox(ctx, InboxUpdate{
			InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version,
			Status: InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.UpdateInbox(ctx, InboxUpdate{
			InboxID: lease.Update.InboxID, ExpectedVersion: started.Version,
			Status: InboxStatusAmbiguous, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
		}); err != nil {
			t.Fatal(err)
		}
		successor, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "successor-inbox-worker", LeaseDuration: time.Minute})
		if err != nil || successor.Update.InboxID != "isolated-inbox-successor" {
			t.Fatalf("successor claim = %#v, %v", successor, err)
		}
		queueSchedulingCompleteInbox(t, store, successor)
		clock.Advance(2 * time.Minute)
		if available, err := store.HasInboxWork(ctx); err != nil || available {
			t.Fatalf("work after isolated payload was scrubbed = %v, %v; want false", available, err)
		}
	})

	t.Run("outbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()
		head := newOutboxTestEffect("isolated-outbox-head", "isolated-outbox-lane")
		head.RiskClass = RiskNonIdempotentAfterDispatch
		if _, err := store.AcceptOutbox(ctx, head); err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("isolated-outbox-successor", "isolated-outbox-lane")); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "isolated-outbox-worker", LeaseDuration: time.Minute})
		if err != nil || lease.Effect.EffectID != head.EffectID {
			t.Fatalf("head claim = %#v, %v", lease, err)
		}
		if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "blocked-outbox-worker", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("claim behind inflight head err = %v, want not found", err)
		}
		if _, err := store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
			EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner,
			LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
		}); err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * time.Minute)
		if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "isolation-observer", LeaseDuration: time.Minute}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired dispatched isolation err = %v, want not found", err)
		}
		successor, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "successor-outbox-worker", LeaseDuration: time.Minute})
		if err != nil || successor.Effect.EffectID != "isolated-outbox-successor" {
			t.Fatalf("successor claim = %#v, %v", successor, err)
		}
		queueSchedulingCompleteOutbox(t, store, successor)
		if available, err := store.HasOutboxWork(ctx); err != nil || available {
			t.Fatalf("work after isolated head and completed successor = %v, %v; want false", available, err)
		}
	})
}

func TestOutboxQueueSchedulingTracksFutureDueHeadAcrossClockChange(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()

	delayed := newOutboxTestEffect("future-due-head", "future-due-lane")
	delayed.NextAttemptAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, delayed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("future-due-successor", "future-due-lane")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("ready-other-lane", "ready-other-lane")); err != nil {
		t.Fatal(err)
	}
	other, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "other-lane-worker", LeaseDuration: time.Minute})
	if err != nil || other.Effect.EffectID != "ready-other-lane" {
		t.Fatalf("ready lane claim = %#v, %v", other, err)
	}
	queueSchedulingCompleteOutbox(t, store, other)
	if available, err := store.HasOutboxWork(ctx); err != nil || available {
		t.Fatalf("work before head due = %v, %v; want false", available, err)
	}

	clock.Advance(time.Minute)
	if available, err := store.HasOutboxWork(ctx); err != nil || !available {
		t.Fatalf("work when head becomes due = %v, %v; want true", available, err)
	}
	head, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "due-head-worker", LeaseDuration: time.Minute})
	if err != nil || head.Effect.EffectID != delayed.EffectID {
		t.Fatalf("due head claim = %#v, %v", head, err)
	}
	queueSchedulingCompleteOutbox(t, store, head)
	successor, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "due-successor-worker", LeaseDuration: time.Minute})
	if err != nil || successor.Effect.EffectID != "future-due-successor" {
		t.Fatalf("due successor claim = %#v, %v", successor, err)
	}
}

func queueSchedulingRestoreLegacyLaneHeadSchema(t *testing.T, db *Database) {
	t.Helper()
	tx := db.GORM().Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE lane_heads_legacy (kind varchar(32) NOT NULL, lane_hmac blob NOT NULL, next_sequence integer NOT NULL, updated_at datetime NOT NULL, PRIMARY KEY (kind, lane_hmac))`,
		`INSERT INTO lane_heads_legacy(kind, lane_hmac, next_sequence, updated_at) SELECT kind, lane_hmac, next_sequence, updated_at FROM lane_heads`,
		`DROP TABLE lane_heads`,
		`ALTER TABLE lane_heads_legacy RENAME TO lane_heads`,
		`CREATE UNIQUE INDEX pk_lane_heads ON lane_heads(kind, lane_hmac)`,
	} {
		if err := tx.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit().Error; err != nil {
		t.Fatal(err)
	}
}

func TestQueueSchedulingMigratesLegacyLaneCursors(t *testing.T) {
	t.Run("inbox", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy-inbox.db")
		db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
		if err != nil {
			t.Fatal(err)
		}
		clock := &queueTestClock{now: time.Unix(100, 0).UTC()}
		store := NewStore(db, WithClock(clock), WithPayloadCodec(queueTestCodec{}))
		for _, id := range []string{"legacy-inbox-first", "legacy-inbox-ready"} {
			if _, err := store.AcceptInbox(context.Background(), newInboxTestUpdate(id, id+"-provider", "legacy-inbox-old-lane")); err != nil {
				t.Fatal(err)
			}
		}
		first, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "legacy-inbox-first-worker", LeaseDuration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		queueSchedulingCompleteInbox(t, store, first)
		queueSchedulingRestoreLegacyLaneHeadSchema(t, db)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		db, err = OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		store = NewStore(db, WithClock(clock), WithPayloadCodec(queueTestCodec{}))
		third, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("legacy-inbox-third", "legacy-inbox-third-provider", "legacy-inbox-old-lane"))
		if err != nil || third.OrderingSequence != 3 {
			t.Fatalf("post-migration lane cursor = %#v, %v; want sequence 3", third, err)
		}
		clock.Advance(time.Second)
		if _, err := store.AcceptInbox(context.Background(), newInboxTestUpdate("legacy-inbox-newer", "legacy-inbox-newer-provider", "legacy-inbox-new-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimInbox(context.Background(), InboxClaimRequest{WorkerID: "legacy-inbox-worker", LeaseDuration: time.Minute})
		if err != nil || claimed.Update.InboxID != "legacy-inbox-ready" {
			t.Fatalf("post-migration fair claim = %#v, %v; want legacy-inbox-ready", claimed, err)
		}
	})

	t.Run("outbox", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "legacy-outbox.db")
		db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
		if err != nil {
			t.Fatal(err)
		}
		clock := &queueTestClock{now: time.Unix(100, 0).UTC()}
		store := NewStore(db, WithClock(clock), WithPayloadCodec(queueTestCodec{}))
		for _, id := range []string{"legacy-outbox-first", "legacy-outbox-ready"} {
			if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect(id, "legacy-outbox-old-lane")); err != nil {
				t.Fatal(err)
			}
		}
		first, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "legacy-outbox-first-worker", LeaseDuration: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		queueSchedulingCompleteOutbox(t, store, first)
		queueSchedulingRestoreLegacyLaneHeadSchema(t, db)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}

		db, err = OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: path})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		store = NewStore(db, WithClock(clock), WithPayloadCodec(queueTestCodec{}))
		third, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("legacy-outbox-third", "legacy-outbox-old-lane"))
		if err != nil || third.OrderingSequence != 3 {
			t.Fatalf("post-migration lane cursor = %#v, %v; want sequence 3", third, err)
		}
		clock.Advance(time.Second)
		if _, err := store.AcceptOutbox(context.Background(), newOutboxTestEffect("legacy-outbox-newer", "legacy-outbox-new-lane")); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimOutbox(context.Background(), OutboxClaimRequest{WorkerID: "legacy-outbox-worker", LeaseDuration: time.Minute})
		if err != nil || claimed.Effect.EffectID != "legacy-outbox-ready" {
			t.Fatalf("post-migration fair claim = %#v, %v; want legacy-outbox-ready", claimed, err)
		}
	})
}

func queueSchedulingForceReadyCursor(t *testing.T, db *Database, kind string, lane []byte, id string, sequence uint64, now time.Time) {
	t.Helper()
	if err := db.GORM().Model(&laneHeadRow{}).Where("kind = ? AND lane_hmac = ?", kind, lane).Updates(map[string]any{
		"active_id": id, "active_sequence": sequence, "active_since": now,
		"ready_at": now, "ready_action": queueReadyActionClaim,
		"scheduling_version": queueSchedulingVersion,
	}).Error; err != nil {
		t.Fatal(err)
	}
}

func TestQueueSchedulingClaimValidatesCursorAgainstCurrentRow(t *testing.T) {
	t.Run("terminal-inbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()
		update := newInboxTestUpdate("stale-terminal-inbox", "stale-terminal-provider", "stale-terminal-inbox-lane")
		if _, err := store.AcceptInbox(ctx, update); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "stale-terminal-inbox-worker"})
		if err != nil {
			t.Fatal(err)
		}
		queueSchedulingCompleteInbox(t, store, lease)
		var before inboxMessageRow
		if err := db.GORM().Where("inbox_id = ?", update.InboxID).First(&before).Error; err != nil {
			t.Fatal(err)
		}
		queueSchedulingForceReadyCursor(t, db, inboxLaneKind, before.LaneHMAC, before.InboxID, before.OrderingSequence, clock.Now())
		if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "stale-terminal-inbox-claim"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("terminal cursor claim err = %v, want not found", err)
		}
		var after inboxMessageRow
		if err := db.GORM().Where("inbox_id = ?", before.InboxID).First(&after).Error; err != nil {
			t.Fatal(err)
		}
		if after.Status != before.Status || after.Version != before.Version {
			t.Fatalf("terminal inbox changed from %#v to %#v", before, after)
		}
	})

	t.Run("terminal-outbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()
		effect := newOutboxTestEffect("stale-terminal-outbox", "stale-terminal-outbox-lane")
		if _, err := store.AcceptOutbox(ctx, effect); err != nil {
			t.Fatal(err)
		}
		lease, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "stale-terminal-outbox-worker"})
		if err != nil {
			t.Fatal(err)
		}
		queueSchedulingCompleteOutbox(t, store, lease)
		var before outboxEffectRow
		if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&before).Error; err != nil {
			t.Fatal(err)
		}
		queueSchedulingForceReadyCursor(t, db, outboxLaneKind, before.LaneHMAC, before.EffectID, before.OrderingSequence, clock.Now())
		if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "stale-terminal-outbox-claim"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("terminal cursor claim err = %v, want not found", err)
		}
		var after outboxEffectRow
		if err := db.GORM().Where("effect_id = ?", before.EffectID).First(&after).Error; err != nil {
			t.Fatal(err)
		}
		if after.Status != before.Status || after.Version != before.Version {
			t.Fatalf("terminal outbox changed from %#v to %#v", before, after)
		}
	})

	t.Run("future-outbox", func(t *testing.T) {
		store, db, clock := openQueueTestStore(t)
		defer db.Close()
		ctx := context.Background()
		effect := newOutboxTestEffect("stale-future-outbox", "stale-future-outbox-lane")
		effect.NextAttemptAt = clock.Now().Add(time.Hour)
		if _, err := store.AcceptOutbox(ctx, effect); err != nil {
			t.Fatal(err)
		}
		var before outboxEffectRow
		if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&before).Error; err != nil {
			t.Fatal(err)
		}
		queueSchedulingForceReadyCursor(t, db, outboxLaneKind, before.LaneHMAC, before.EffectID, before.OrderingSequence, clock.Now())
		if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "stale-future-outbox-claim"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("future cursor claim err = %v, want not found", err)
		}
		var after outboxEffectRow
		if err := db.GORM().Where("effect_id = ?", before.EffectID).First(&after).Error; err != nil {
			t.Fatal(err)
		}
		if after.Status != before.Status || after.Version != before.Version {
			t.Fatalf("future outbox changed from %#v to %#v", before, after)
		}
	})
}
