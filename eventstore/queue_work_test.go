package eventstore

import (
	"strings"
	"testing"

	"gorm.io/gorm"
)

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
