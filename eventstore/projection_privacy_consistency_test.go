package eventstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func openProjectionConsistencyStore(t *testing.T, path string) (*GORMStore, *Database) {
	t.Helper()
	database, err := OpenDatabase(context.Background(), DatabaseConfig{
		Type: "sqlite", DSN: path, KeySource: newTransactionTestKeySource(), DatabaseIdentity: "projection-consistency",
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(database, WithProjection(transactionTestProjection())), database
}

func TestRebuildAfterPrivacyDeletionAndReopen(t *testing.T) {
	for _, tc := range []struct {
		name   string
		purged [3]bool
	}{
		{name: "leading", purged: [3]bool{true, false, false}},
		{name: "interior", purged: [3]bool{false, true, false}},
		{name: "trailing", purged: [3]bool{false, false, true}},
		{name: "all", purged: [3]bool{true, true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "events.db")
			store, database := openProjectionConsistencyStore(t, path)
			defer database.Close()
			target := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "purged")}
			survivor := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "survivor")}
			versions := map[StreamID]uint64{}
			wantSurvivor := ""
			for index, purge := range tc.purged {
				stream := survivor
				if purge {
					stream = target
				} else {
					wantSurvivor = fmt.Sprintf(`{"delta":%d}`, index+1)
				}
				_, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{
					Stream: stream, ExpectedVersion: versions[stream], Events: []NewEvent{transactionTestEvent(fmt.Sprintf("event-%d", index), index+1)},
				}}})
				if err != nil {
					t.Fatal(err)
				}
				versions[stream]++
			}
			scan := seedPrivacyOperation(t, store, "purged", "dice", "purge", []string{"group_record"})
			batch, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{
				OperationID: "purge", GroupID: "purged", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}, Phase: "delete",
			})
			if err != nil || !batch.Done || batch.Deleted.GroupRecord != int64(versions[target]) {
				t.Fatalf("delete: %+v, %v", batch, err)
			}
			if err := store.PrivacyRebuildPublish(ctx, scan.TargetHighWater); err != nil {
				t.Fatal(err)
			}
			check := func(store *GORMStore) {
				t.Helper()
				result, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"})
				if err != nil || result.TerminalPosition != 3 {
					t.Fatalf("rebuild after legitimate deletion: %+v, %v", result, err)
				}
				if _, err := store.ReadProjectionRow(ctx, "counter", target.AggregateID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("purged projection returned: %v", err)
				}
				rows, err := store.ListProjectionRows(ctx, "counter")
				if err != nil {
					t.Fatal(err)
				}
				if wantSurvivor == "" {
					if len(rows) != 0 {
						t.Fatalf("fully erased projection: %+v", rows)
					}
				} else if len(rows) != 1 || rows[0].RowKey != survivor.AggregateID || string(rows[0].Payload) != wantSurvivor {
					t.Fatalf("surviving state changed: %+v", rows)
				}
			}
			check(store)
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, reopenedDB := openProjectionConsistencyStore(t, path)
			defer reopenedDB.Close()
			check(reopened)

			_, err = reopened.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{
				Stream: survivor, ExpectedVersion: versions[survivor], Events: []NewEvent{transactionTestEvent("unrecorded-loss", 4)},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := reopenedDB.GORM().Where("event_id = ?", "unrecorded-loss-event").Delete(&domainEventRow{}).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrProjectionInvariant) {
				t.Fatalf("unrecorded event loss accepted: %v", err)
			}
		})
	}
}

func TestRebuildDoesNotResurrectConcurrentPrivacyDeletion(t *testing.T) {
	for _, privacyRebuild := range []bool{false, true} {
		t.Run(fmt.Sprintf("privacy_rebuild=%t", privacyRebuild), func(t *testing.T) {
			ctx := context.Background()
			store, database := openProjectionConsistencyStore(t, filepath.Join(t.TempDir(), "events.db"))
			defer database.Close()
			target := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "purged")}
			survivor := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "survivor")}
			if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{
				{Stream: target, Events: []NewEvent{transactionTestEvent("target", 1)}},
				{Stream: survivor, Events: []NewEvent{transactionTestEvent("survivor", 2)}},
			}}); err != nil {
				t.Fatal(err)
			}
			scan := seedPrivacyOperation(t, store, "purged", "dice", "purge", []string{"group_record"})
			type replayKey struct{}
			interleaved := false
			if err := database.GORM().Callback().Query().After("gorm:query").Register("test:purge-during-replay", func(tx *gorm.DB) {
				if interleaved || tx.Statement.Context.Value(replayKey{}) != true || tx.Statement.Table != tableDomainEvents || !strings.Contains(tx.Statement.SQL.String(), "global_position >") {
					return
				}
				interleaved = true
				if _, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{
					OperationID: "purge", GroupID: "purged", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}, Phase: "delete",
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.PrivacyRebuildPublish(ctx, scan.TargetHighWater); err != nil {
					t.Fatal(err)
				}
			}); err != nil {
				t.Fatal(err)
			}
			replayCtx := context.WithValue(ctx, replayKey{}, true)
			var err error
			if privacyRebuild {
				err = store.PrivacyRebuildPublish(replayCtx, scan.TargetHighWater)
			} else {
				_, err = store.Rebuild(replayCtx, RebuildRequest{ProjectorVersion: "v1"})
			}
			if !interleaved || !errors.Is(err, ErrParticipantConflict) {
				t.Fatalf("stale rebuild not rejected: interleaved=%t, error=%v", interleaved, err)
			}
			events, err := store.Load(ctx, target, 1)
			if err != nil || len(events) != 0 {
				t.Fatalf("purged events returned: %+v, %v", events, err)
			}
			if _, err := store.ReadProjectionRow(ctx, "counter", target.AggregateID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("purged projection resurrected: %v", err)
			}
			row, err := store.ReadProjectionRow(ctx, "counter", survivor.AggregateID)
			if err != nil || string(row.Payload) != `{"delta":2}` {
				t.Fatalf("survivor changed: %+v, %v", row, err)
			}
		})
	}
}

func TestRebuildRejectsConcurrentGenerationReplacement(t *testing.T) {
	ctx := context.Background()
	store, database := openProjectionConsistencyStore(t, filepath.Join(t.TempDir(), "events.db"))
	defer database.Close()
	first := StreamID{AggregateType: "counter", AggregateID: "first-page"}
	last := StreamID{AggregateType: "counter", AggregateID: "last-page"}
	for start := 0; start < projectionPageSize; start += 64 {
		count := min(64, projectionPageSize-start)
		events := make([]NewEvent, count)
		for i := range events {
			events[i] = transactionTestEvent(fmt.Sprintf("page-%d", start+i), start+i+1)
		}
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{
			Stream: first, ExpectedVersion: uint64(start), Events: events,
		}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: last, Events: []NewEvent{transactionTestEvent("last", 1001)}}}}); err != nil {
		t.Fatal(err)
	}
	type replayKey struct{}
	pages := 0
	if err := database.GORM().Callback().Query().After("gorm:query").Register("test:replace-during-replay", func(tx *gorm.DB) {
		if tx.Statement.Context.Value(replayKey{}) != true || tx.Statement.Table != tableDomainEvents || !strings.Contains(tx.Statement.SQL.String(), "global_position >") {
			return
		}
		pages++
		if pages == 2 {
			// Publishing another generation removes the already-built first page
			// of this rebuild even though the event history itself is unchanged.
			if err := store.PrivacyRebuildPublish(ctx, 1001); err != nil {
				t.Fatal(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rebuild(context.WithValue(ctx, replayKey{}, true), RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrParticipantConflict) || pages != 2 {
		t.Fatalf("invalidated shadow generation published: pages=%d, error=%v", pages, err)
	}
	for stream, value := range map[StreamID]int{first: 1000, last: 1001} {
		row, err := store.ReadProjectionRow(ctx, "counter", stream.AggregateID)
		if err != nil || string(row.Payload) != fmt.Sprintf(`{"delta":%d}`, value) {
			t.Fatalf("published state lost a page: row=%+v, error=%v", row, err)
		}
	}
}
