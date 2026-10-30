package eventstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestOutboxWorkProbeFindsLegacyScrubbedExpiredPending(t *testing.T) {
	store, db, clock := openQueueTestStore(t)
	defer db.Close()
	ctx := context.Background()
	head := newOutboxTestEffect("legacy-expired-head", "legacy-expired-lane")
	head.NextAttemptAt = clock.Now().Add(time.Hour)
	head.PayloadExpiresAt = clock.Now().Add(time.Minute)
	if _, err := store.AcceptOutbox(ctx, head); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("legacy-expired-successor", "legacy-expired-lane")); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&outboxEffectRow{}).Where("effect_id = ?", head.EffectID).Updates(map[string]any{
		"version": 2, "payload_ciphertext": nil, "payload_nonce": nil, "payload_present": false,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if available, err := store.HasOutboxWork(ctx); err != nil || available {
		t.Fatalf("work before payload expiry = %v, %v; want false", available, err)
	}
	clock.Advance(2 * time.Minute)
	if available, err := store.HasOutboxWork(ctx); err != nil || !available {
		t.Fatalf("work after payload expiry = %v, %v; want true", available, err)
	}
	next, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "legacy-expired-worker", LeaseDuration: time.Minute})
	if err != nil || next.Effect.EffectID != "legacy-expired-successor" {
		t.Fatalf("successor claim = %#v, %v", next, err)
	}
	var isolated outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", head.EffectID).First(&isolated).Error; err != nil {
		t.Fatal(err)
	}
	if isolated.Status != OutboxStatusFailed || isolated.Version != 3 || isolated.CompletedAt == nil {
		t.Fatalf("isolated legacy head = %#v", isolated)
	}
}

func TestInboxClaimPlanUsesReadyLaneIndex(t *testing.T) {
	_, db, clock := openQueueTestStore(t)
	defer db.Close()

	var candidate struct {
		InboxID string `gorm:"column:inbox_id"`
	}
	sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
		return scanInboxClaimable(tx, clock.Now(), &candidate)
	})
	assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_lane_heads_action_ready")
}

func TestOutboxClaimPlanUsesReadyLaneIndex(t *testing.T) {
	_, db, clock := openQueueTestStore(t)
	defer db.Close()

	var candidate struct {
		EffectID string `gorm:"column:effect_id"`
	}
	sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
		return scanOutboxClaimable(tx, clock.Now(), &candidate)
	})
	assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_lane_heads_action_ready")
}

func TestInboxPayloadScrubPlanUsesOrderedUnionWithoutTempSort(t *testing.T) {
	_, db, clock := openQueueTestStore(t)
	defer db.Close()

	var candidates []task5ExpiredPayloadCandidate
	sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
		return inboxExpiredPayloadCandidates(tx, clock.Now(), task5PayloadScrubBatchSize).Scan(&candidates)
	})
	assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_inbox_status_payload_expiry")
}

func TestOutboxPayloadScrubPlanUsesOrderedUnionWithoutTempSort(t *testing.T) {
	_, db, clock := openQueueTestStore(t)
	defer db.Close()

	var candidates []task5ExpiredPayloadCandidate
	sql := db.GORM().ToSQL(func(tx *gorm.DB) *gorm.DB {
		return outboxExpiredPayloadCandidates(tx, clock.Now(), task5PayloadScrubBatchSize).Scan(&candidates)
	})
	assertSQLiteOrderedPlan(t, db.GORM(), sql, "ix_outbox_status_payload_expiry")
}

func sqlitePlanDetails(t *testing.T, db *gorm.DB, sql string) string {
	t.Helper()
	var plan []struct {
		Detail string `gorm:"column:detail"`
	}
	if err := db.Raw("EXPLAIN QUERY PLAN " + sql).Scan(&plan).Error; err != nil {
		t.Fatal(err)
	}
	details := make([]string, 0, len(plan))
	for _, row := range plan {
		details = append(details, row.Detail)
	}
	return strings.Join(details, "\n")
}

func assertSQLiteOrderedPlan(t *testing.T, db *gorm.DB, sql, indexName string) {
	t.Helper()
	joined := sqlitePlanDetails(t, db, sql)
	if strings.Contains(joined, "USE TEMP B-TREE FOR ORDER BY") {
		t.Fatalf("query still materializes a temporary sort:\n%s", joined)
	}
	if !strings.Contains(joined, indexName) {
		t.Fatalf("query does not use %s:\n%s", indexName, joined)
	}
}
