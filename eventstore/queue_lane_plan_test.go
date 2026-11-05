package eventstore

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"
)

// A lane keeps every message it ever carried, and nearly all of them are long
// finished. Finding the lane's live head therefore has to seek straight to the
// (lane, status) range: if the statement lets SQLite walk the lane in
// ordering_sequence order and filter by status row by row, its cost grows with
// the lane's whole history (18 ms for a 34,000-message lane in production,
// against 0.03 ms through the index) and runs on every queue mutation.
func TestLaneHeadLookupsSeekThroughTheLaneStatusOrderingIndex(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDatabase(ctx, DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "lane-plan.db"),
		DatabaseIdentity: "lane-plan",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	type issued struct {
		sql  string
		vars []any
	}
	var mu sync.Mutex
	var statements []issued
	if err := db.GORM().Callback().Query().After("gorm:query").Register("lane-plan:capture", func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}
		mu.Lock()
		statements = append(statements, issued{sql: tx.Statement.SQL.String(), vars: append([]any(nil), tx.Statement.Vars...)})
		mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}

	lane := "0123456789abcdef0123456789abcdef"
	if err := db.GORM().Transaction(func(tx *gorm.DB) error {
		if _, err := task5Lane(tx, inboxLaneKind, lane, SystemClock{}.Now()); err != nil {
			return err
		}
		if _, err := task5Lane(tx, outboxLaneKind, lane, SystemClock{}.Now()); err != nil {
			return err
		}
		if _, _, err := earliestInboxLaneRow(tx, lane); err != nil {
			return err
		}
		_, _, err := earliestOutboxLaneRow(tx, lane)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	captured := append([]issued(nil), statements...)
	mu.Unlock()
	checked := 0
	for _, statement := range captured {
		var table, index string
		switch {
		case strings.Contains(statement.sql, "FROM `inbox_messages`") || strings.Contains(statement.sql, `FROM "inbox_messages"`):
			table, index = "inbox_messages", "ix_inbox_lane_status_ordering"
		case strings.Contains(statement.sql, "FROM `outbox_effects`") || strings.Contains(statement.sql, `FROM "outbox_effects"`):
			table, index = "outbox_effects", "ix_outbox_lane_status_ordering"
		default:
			continue
		}
		plan := func() string {
			rows, err := db.GORM().Raw("EXPLAIN QUERY PLAN "+statement.sql, statement.vars...).Rows()
			if err != nil {
				t.Fatalf("explain %s: %v", statement.sql, err)
			}
			defer func() {
				if err := rows.Close(); err != nil {
					t.Errorf("close query plan: %v", err)
				}
			}()
			var details []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				details = append(details, detail)
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("iterate query plan: %v", err)
			}
			return strings.Join(details, "; ")
		}()
		if !strings.Contains(plan, index) {
			t.Fatalf("lane head lookup on %s does not seek through %s:\n  sql:  %s\n  plan: %s", table, index, statement.sql, plan)
		}
		checked++
	}
	if checked < 4 {
		t.Fatalf("captured %d lane head lookups, want one per status probe on both queues (>= 4)", checked)
	}
}
