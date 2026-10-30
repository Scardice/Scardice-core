package eventstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

func seedPrivacyOperation(t *testing.T, store *GORMStore, group, dice, operation string, scopes []string) PrivacyDryRunResult {
	t.Helper()
	ctx := context.Background()
	scan, err := store.PrivacyDryRun(ctx, PrivacyDryRunRequest{GroupID: group, DiceIDs: []string{dice}, Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	private := PrivacyOperationContext{GroupID: group, DiceIDs: []string{dice}, Scopes: scopes, Phase: "delete", Counts: scan.Counts, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}
	createErr := store.PrivacyCreateOperation(ctx, operation, scan.SubjectKey, private)
	if createErr != nil {
		t.Fatal(createErr)
	}
	_, fenceErr := store.PrivacyFence(ctx, scan.SubjectKey, "group", operation)
	if fenceErr != nil {
		t.Fatal(fenceErr)
	}
	return scan
}

func TestSQLiteLiveAndRebuiltDigestAgree(t *testing.T) {
	ctx := context.Background()
	store, db := openTransactionTestStore(t, newTransactionTestKeySource(), "task7-privacy-digest")
	defer db.Close()
	if err := store.RegisterProjection(transactionTestProjection()); err != nil {
		t.Fatal(err)
	}
	stream := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice-a", "digest-group")}
	commit, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{transactionTestEvent("privacy-digest", 7)}}}})
	if err != nil {
		t.Fatal(err)
	}
	var control projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		t.Fatal(err)
	}
	liveDigest, err := store.DigestProjection(ctx, control.ActiveGeneration)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.TerminalPosition != commit.Events[0].GlobalPosition || rebuilt.Digest != liveDigest {
		t.Fatalf("live/rebuilt result mismatch terminal=%d want=%d live=%s rebuilt=%s", rebuilt.TerminalPosition, commit.Events[0].GlobalPosition, liveDigest, rebuilt.Digest)
	}
	publishedDigest, err := store.DigestProjection(ctx, rebuilt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if publishedDigest != rebuilt.Digest {
		t.Fatalf("published digest=%s rebuild digest=%s", publishedDigest, rebuilt.Digest)
	}
	liveRow, err := store.ReadProjectionRow(ctx, "counter", stream.AggregateID)
	if err != nil || string(liveRow.Payload) != `{"delta":7}` {
		t.Fatalf("published row=%+v err=%v", liveRow, err)
	}
}

func TestSQLitePrivacySparseHighWaterRebuildPreservesHole(t *testing.T) {
	ctx := context.Background()
	store, db := openTransactionTestStore(t, newTransactionTestKeySource(), "task7-privacy-sparse")
	defer db.Close()
	if err := store.RegisterProjection(transactionTestProjection()); err != nil {
		t.Fatal(err)
	}
	targetGroup := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice-a", "sparse-group")}
	survivorGroup := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice-b", "sparse-group")}
	targetPlayer := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice-a", "sparse-group", "player-a")}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{
		{Stream: targetGroup, Events: []NewEvent{transactionTestEvent("sparse-target-group", 1)}},
		{Stream: survivorGroup, Events: []NewEvent{transactionTestEvent("sparse-survivor-group", 2)}},
		{Stream: targetPlayer, Events: []NewEvent{transactionTestEvent("sparse-target-player", 3)}},
	}}); err != nil {
		t.Fatal(err)
	}
	scan := seedPrivacyOperation(t, store, "sparse-group", "dice-a", "sparse-operation", []string{"group_record"})
	if scan.TargetHighWater != 3 {
		t.Fatalf("target high-water=%d", scan.TargetHighWater)
	}
	batch, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "sparse-operation", GroupID: "sparse-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"group_record"}, Limit: PrivacyBatchRecords})
	if err != nil || batch.Deleted.GroupRecord != 1 || !batch.Done {
		t.Fatalf("sparse delete batch=%+v err=%v", batch, err)
	}
	if rows, err := store.Load(ctx, targetGroup, 0); err != nil || len(rows) != 0 {
		t.Fatalf("purged sparse target rows=%d err=%v", len(rows), err)
	}
	if rows, err := store.Load(ctx, survivorGroup, 0); err != nil || len(rows) != 1 {
		t.Fatalf("survivor rows=%d err=%v", len(rows), err)
	}
	var beforeControl projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&beforeControl).Error; err != nil {
		t.Fatal(err)
	}
	liveDigest, err := store.DigestProjection(ctx, beforeControl.ActiveGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PrivacyRebuildPublish(ctx, scan.TargetHighWater); err != nil {
		t.Fatal(err)
	}
	var control projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		t.Fatal(err)
	}
	if control.TerminalPosition != scan.TargetHighWater {
		t.Fatalf("terminal=%d target=%d", control.TerminalPosition, scan.TargetHighWater)
	}
	survivor, err := store.ReadProjectionRow(ctx, "counter", survivorGroup.AggregateID)
	if err != nil || string(survivor.Payload) != `{"delta":2}` {
		t.Fatalf("survivor projection=%+v err=%v", survivor, err)
	}
	if _, err := store.ReadProjectionRow(ctx, "counter", targetGroup.AggregateID); err == nil {
		t.Fatal("purged target projection remained")
	}
	rebuiltDigest, err := store.DigestProjection(ctx, control.ActiveGeneration)
	if err != nil || rebuiltDigest == (EventChecksum{}) {
		t.Fatalf("sparse digest=%s err=%v", rebuiltDigest, err)
	}
	if liveDigest != rebuiltDigest {
		t.Fatalf("sparse live/rebuilt digest live=%s rebuilt=%s", liveDigest, rebuiltDigest)
	}
}
func TestSQLiteEmptyProjectorRebuildKeepsOldReadModel(t *testing.T) {
	ctx := context.Background()
	store, db := openTransactionTestStore(t, newTransactionTestKeySource(), "task7-privacy-empty-projector")
	defer db.Close()
	old := projectionReadModelRow{ProjectionGeneration: "old-generation", ProjectionName: "legacy", RowKey: "group-a", Payload: []byte(`{"old":true}`), UpdatedAt: time.Unix(1, 0).UTC()}
	if err := db.GORM().Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{"active_generation": old.ProjectionGeneration, "publication_state": "published"}).Error; err != nil {
		t.Fatal(err)
	}
	var beforeControl projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&beforeControl).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.PrivacyRebuildPublish(ctx, 0); !errors.Is(err, ErrInvalidProjector) {
		t.Fatalf("empty projector error=%v", err)
	}
	var afterControl projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&afterControl).Error; err != nil {
		t.Fatal(err)
	}
	if afterControl.ActiveGeneration != beforeControl.ActiveGeneration || afterControl.TerminalPosition != beforeControl.TerminalPosition || afterControl.PublicationState != beforeControl.PublicationState {
		t.Fatalf("projection control changed before=%+v after=%+v", beforeControl, afterControl)
	}
	var retained projectionReadModelRow
	if err := db.GORM().Where("projection_generation = ? AND projection_name = ? AND row_key = ?", old.ProjectionGeneration, old.ProjectionName, old.RowKey).First(&retained).Error; err != nil {
		t.Fatal(err)
	}
	if string(retained.Payload) != `{"old":true}` {
		t.Fatalf("old read model payload=%q", retained.Payload)
	}
}

func TestSQLitePrivacyCapacityRecordAndEightMiBBound(t *testing.T) {
	ctx := context.Background()
	t.Run("more-than-500-records", func(t *testing.T) {
		store, db := openTransactionTestStore(t, newTransactionTestKeySource(), "task7-privacy-500")
		defer db.Close()
		if err := store.RegisterProjection(transactionTestProjection()); err != nil {
			t.Fatal(err)
		}
		stream := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice-a", "capacity-group", "player-a")}
		events := make([]NewEvent, 501)
		for i := range events {
			events[i] = transactionTestEvent(fmt.Sprintf("capacity-%03d", i), i)
		}
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: events}}}); err != nil {
			t.Fatal(err)
		}
		scan := seedPrivacyOperation(t, store, "capacity-group", "dice-a", "capacity-operation", []string{"players"})
		view, private, err := store.PrivacyLoadOperation(ctx, "capacity-operation")
		if err != nil {
			t.Fatal(err)
		}
		first, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "capacity-operation", GroupID: "capacity-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Limit: 500})
		if err != nil {
			t.Fatal(err)
		}
		if first.Deleted.Players != 500 || first.Done || first.NextCursor == "" {
			t.Fatalf("first batch=%+v", first)
		}
		private.Cursor = first.NextCursor
		if _, updateErr := store.PrivacyUpdateOperation(ctx, "capacity-operation", view.Version, private, "running"); updateErr != nil {
			t.Fatal(updateErr)
		}
		_, _, err = store.PrivacyLoadOperation(ctx, "capacity-operation")
		if err != nil {
			t.Fatal(err)
		}
		second, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "capacity-operation", GroupID: "capacity-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Cursor: first.NextCursor, Limit: 500})
		if err != nil {
			t.Fatal(err)
		}
		if second.Deleted.Players != 1 || !second.Done || second.NextCursor == "" {
			t.Fatalf("second batch=%+v", second)
		}
		if first.Deleted.Players > PrivacyBatchRecords || second.Deleted.Players > PrivacyBatchRecords {
			t.Fatalf("batch exceeded record bound first=%d second=%d", first.Deleted.Players, second.Deleted.Players)
		}
		if scan.Counts.Players != 501 {
			t.Fatalf("dry-run count=%+v", scan.Counts)
		}
		remaining, err := store.Load(ctx, stream, 0)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("remaining events=%d err=%v", len(remaining), err)
		}
	})

	t.Run("five-hundred-16KiB-records", func(t *testing.T) {
		store, db := openTransactionTestStore(t, newTransactionTestKeySource(), "task7-privacy-8mib")
		defer db.Close()
		if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA journal_mode = MEMORY; PRAGMA synchronous = OFF"); err != nil {
			t.Fatal(err)
		}
		// Controlled durable SQLite fixture: 500 rows × 16 KiB stays just under 8 MiB, keeping focused validation bounded.
		stream := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice-a", "bytes-group", "player-a")}
		const records = 500
		const commitChunk = 60         // several durable inserts keep each batch below the 16 MiB unit bound
		const payloadBytes = 16 * 1024 // bounded fixture; the production page size remains 32 rows
		now := time.Now().UTC()
		for start := 0; start < records; start += commitChunk {
			end := minInt(start+commitChunk, records)
			rows := make([]domainEventRow, 0, end-start)
			for i := start; i < end; i++ {
				rows = append(rows, domainEventRow{
					EventID: fmt.Sprintf("bytes-%03d", i), AggregateType: stream.AggregateType, AggregateID: stream.AggregateID,
					AggregateVersion: uint64(i + 1), GlobalPosition: uint64(i + 1), EventType: "privacy.test", SchemaVersion: 1,
					Payload: make([]byte, payloadBytes), CommandID: fmt.Sprintf("bytes-command-%03d", i),
					CorrelationID: fmt.Sprintf("bytes-correlation-%03d", i), Producer: "task7", OccurredAtUnixNanoUTC: now.UnixNano(),
					Checksum: make([]byte, 32), CreatedAt: now,
				})
			}
			if err := db.GORM().CreateInBatches(&rows, commitChunk).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := db.GORM().Model(&eventGlobalSequenceRow{}).Where("singleton_id = ?", "default").Update("next_position", records+1).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.GORM().Create(&aggregateHeadRow{AggregateType: stream.AggregateType, AggregateID: stream.AggregateID, CurrentVersion: records, UpdatedAt: now}).Error; err != nil {
			t.Fatal(err)
		}
		scan := seedPrivacyOperation(t, store, "bytes-group", "dice-a", "bytes-operation", []string{"players"})
		cursor := ""
		total := int64(0)
		batches := 0
		maxBatchBytes := int64(0)
		for {
			batch, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "bytes-operation", GroupID: "bytes-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Cursor: cursor, Limit: PrivacyBatchRecords})
			if err != nil {
				t.Fatal(err)
			}
			batches++
			batchBytes := batch.Deleted.Players * payloadBytes
			if batchBytes > maxBatchBytes {
				maxBatchBytes = batchBytes
			}
			if batch.Deleted.Players > PrivacyBatchRecords || batchBytes > PrivacyBatchBytes {
				t.Fatalf("batch exceeded bounds records=%d payload=%d", batch.Deleted.Players, batchBytes)
			}
			total += batch.Deleted.Players
			view, private, err := store.PrivacyLoadOperation(ctx, "bytes-operation")
			if err != nil {
				t.Fatal(err)
			}
			private.Cursor = batch.NextCursor
			if _, err := store.PrivacyUpdateOperation(ctx, "bytes-operation", view.Version, private, "running"); err != nil {
				t.Fatal(err)
			}
			cursor = batch.NextCursor
			if batch.Done {
				break
			}
		}
		if total != int64(records) || batches != 1 || maxBatchBytes > PrivacyBatchBytes {
			t.Fatalf("capacity total=%d batches=%d max_batch_bytes=%d", total, batches, maxBatchBytes)
		}
		if scan.Counts.Players != int64(records) {
			t.Fatalf("dry-run count=%+v", scan.Counts)
		}
		remaining, err := store.Load(ctx, stream, 0)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("remaining events=%d err=%v", len(remaining), err)
		}
	})
}

func TestSQLitePrivacyDeleteBatchEightMiBCursorBoundary(t *testing.T) {
	ctx := context.Background()
	store, db := openTransactionTestStore(t, newTransactionTestKeySource(), "task7-privacy-page-boundary")
	defer db.Close()
	stream := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice-a", "page-group", "player-a")}
	events := make([]NewEvent, 34)
	for i := range events {
		events[i] = transactionTestEvent(fmt.Sprintf("page-boundary-%02d", i), i)
		events[i].Payload = make([]byte, MaxEventPayloadBytes)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: events}}}); err != nil {
		t.Fatal(err)
	}
	scan := seedPrivacyOperation(t, store, "page-group", "dice-a", "page-boundary-operation", []string{"players"})
	if scan.Counts.Players != 34 {
		t.Fatalf("dry-run count=%+v", scan.Counts)
	}
	firstCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	first, err := store.PrivacyDeleteBatch(firstCtx, PrivacyBatchRequest{OperationID: "page-boundary-operation", GroupID: "page-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Limit: PrivacyBatchRecords})
	cancel()
	if err != nil || first.Deleted.Players != 32 || first.Done || first.NextCursor != "32" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	view, private, err := store.PrivacyLoadOperation(ctx, "page-boundary-operation")
	if err != nil {
		t.Fatal(err)
	}
	private.Cursor = first.NextCursor
	if _, err := store.PrivacyUpdateOperation(ctx, "page-boundary-operation", view.Version, private, "running"); err != nil {
		t.Fatal(err)
	}
	secondCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	second, err := store.PrivacyDeleteBatch(secondCtx, PrivacyBatchRequest{OperationID: "page-boundary-operation", GroupID: "page-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Cursor: first.NextCursor, Limit: PrivacyBatchRecords})
	cancel()
	if err != nil || second.Deleted.Players != 2 || !second.Done || second.NextCursor != "34" {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	if rows, err := store.Load(ctx, stream, 0); err != nil || len(rows) != 0 {
		t.Fatalf("remaining rows=%d err=%v", len(rows), err)
	}
}

type privacyRunMetric struct {
	mode                                  string
	synchronous                           int
	p50, p95                              time.Duration
	throughput                            float64
	allocDeltaBytes, heapInuseDeltaBytes  uint64
	mainDBGrowthBytes, walBytes, shmBytes int64
	rebuildTime, aggregateLoadTime        time.Duration
	backlog                               int64
}

func privacyDatabaseSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
func nonnegativeDelta(after, before uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

func durationPercentile(samples []time.Duration, percentile float64) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}

func TestSQLitePrivacyWorkloadMetricReport(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []struct {
		name   string
		pragma string
		want   int
	}{{"NORMAL", "NORMAL", 1}, {"FULL", "FULL", 2}} {
		t.Run(mode.name, func(t *testing.T) {
			source := newTransactionTestKeySource()
			path := filepath.Join(t.TempDir(), "task7-metrics.db")
			db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source, DatabaseIdentity: "task7-metrics"})
			if err != nil {
				t.Fatal(err)
			}
			store := NewStore(db)
			defer db.Close()
			if err := store.RegisterProjection(transactionTestProjection()); err != nil {
				t.Fatal(err)
			}
			if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA synchronous = "+mode.pragma); err != nil {
				t.Fatal(err)
			}
			var synchronous int
			if err := db.SQLDB().QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
				t.Fatal(err)
			}
			if synchronous != mode.want {
				t.Fatalf("effective synchronous=%d want=%d", synchronous, mode.want)
			}
			beforeSize := privacyDatabaseSize(path)
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			samples := make([]time.Duration, 0, 5)
			var rebuild time.Duration
			var aggregateLoad time.Duration
			for i := range 5 {
				stream := StreamID{AggregateType: "group", AggregateID: fmt.Sprintf("metric-%d", i)}
				started := time.Now()
				if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{transactionTestEvent(fmt.Sprintf("metric-event-%d", i), i)}}}}); err != nil {
					t.Fatal(err)
				}
				samples = append(samples, time.Since(started))
				loadStarted := time.Now()
				if _, err := store.Load(ctx, stream, 0); err != nil {
					t.Fatal(err)
				}
				aggregateLoad += time.Since(loadStarted)
				rebuildStarted := time.Now()
				if _, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"}); err != nil {
					t.Fatal(err)
				}
				rebuild += time.Since(rebuildStarted)
			}
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			var sequence eventGlobalSequenceRow
			var control projectionControlRow
			if err := db.GORM().Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
				t.Fatal(err)
			}
			backlog := int64(0)
			if sequence.NextPosition > control.TerminalPosition {
				backlog = int64(sequence.NextPosition - 1 - control.TerminalPosition)
			}
			walBytes := privacyDatabaseSize(path + "-wal")
			shmBytes := privacyDatabaseSize(path + "-shm")
			metrics := privacyRunMetric{
				mode: mode.name, synchronous: synchronous, p50: durationPercentile(samples, .50), p95: durationPercentile(samples, .95),
				throughput:      float64(len(samples)) / time.Duration(sumDurations(samples)).Seconds(),
				allocDeltaBytes: nonnegativeDelta(after.TotalAlloc, before.TotalAlloc), heapInuseDeltaBytes: nonnegativeDelta(after.HeapInuse, before.HeapInuse),
				mainDBGrowthBytes: privacyDatabaseSize(path) - beforeSize, walBytes: walBytes, shmBytes: shmBytes,
				rebuildTime: rebuild, aggregateLoadTime: aggregateLoad, backlog: backlog,
			}
			if metrics.p50 <= 0 || metrics.p95 <= 0 || metrics.throughput <= 0 || metrics.rebuildTime <= 0 || metrics.aggregateLoadTime <= 0 || metrics.mainDBGrowthBytes < 0 || metrics.walBytes < 0 || metrics.shmBytes < 0 {
				t.Fatalf("invalid metrics=%+v", metrics)
			}
			if metrics.synchronous < 0 || metrics.p50 < 0 || metrics.p95 < 0 || metrics.throughput < 0 || metrics.rebuildTime < 0 || metrics.aggregateLoadTime < 0 || metrics.mainDBGrowthBytes < 0 || metrics.walBytes < 0 || metrics.shmBytes < 0 || metrics.backlog < 0 {
				t.Fatalf("negative metrics=%+v", metrics)
			}
			t.Logf("mode=%s synchronous=%d p50=%s p95=%s throughput=%.2f_events_per_second alloc_delta_bytes=%d heap_inuse_delta_bytes=%d main_db_growth_bytes=%d rebuild_time=%s backlog=%d wal_bytes=%d shm_bytes=%d aggregate_load_time=%s", metrics.mode, metrics.synchronous, metrics.p50, metrics.p95, metrics.throughput, metrics.allocDeltaBytes, metrics.heapInuseDeltaBytes, metrics.mainDBGrowthBytes, metrics.rebuildTime, metrics.backlog, metrics.walBytes, metrics.shmBytes, metrics.aggregateLoadTime)
		})
	}
}

func sumDurations(values []time.Duration) int64 {
	var total int64
	for _, value := range values {
		total += int64(value)
	}
	return total
}
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func BenchmarkSQLitePrivacyFullWorkload(b *testing.B) {
	for _, mode := range []struct {
		name   string
		pragma string
	}{{name: "NORMAL", pragma: "NORMAL"}, {name: "FULL", pragma: "FULL"}} {
		b.Run(mode.name, func(b *testing.B) {
			ctx := context.Background()
			source := newTransactionTestKeySource()
			path := filepath.Join(b.TempDir(), "task7-benchmark.db")
			db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source, DatabaseIdentity: "task7-benchmark"})
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			store := NewStore(db)
			if err := store.RegisterProjection(transactionTestProjection()); err != nil {
				b.Fatal(err)
			}
			if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA synchronous = "+mode.pragma); err != nil {
				b.Fatal(err)
			}
			var synchronous int
			if err := db.SQLDB().QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
				b.Fatal(err)
			}
			beforeSize := privacyDatabaseSize(path)
			aggregateLoad := time.Duration(0)
			b.ReportAllocs()
			b.ResetTimer()
			started := time.Now()
			for i := range b.N {
				stream := StreamID{AggregateType: "group", AggregateID: fmt.Sprintf("benchmark-%d", i)}
				if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{transactionTestEvent(fmt.Sprintf("benchmark-event-%d", i), i)}}}}); err != nil {
					b.Fatal(err)
				}
				loadStarted := time.Now()
				if _, err := store.Load(ctx, stream, 0); err != nil {
					b.Fatal(err)
				}
				aggregateLoad += time.Since(loadStarted)
			}
			elapsed := time.Since(started)
			b.StopTimer()
			rebuildStarted := time.Now()
			if _, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"}); err != nil {
				b.Fatal(err)
			}
			rebuild := time.Since(rebuildStarted)
			var sequence eventGlobalSequenceRow
			var control projectionControlRow
			if err := db.GORM().Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
				b.Fatal(err)
			}
			if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil {
				b.Fatal(err)
			}
			backlog := int64(0)
			if sequence.NextPosition > control.TerminalPosition {
				backlog = int64(sequence.NextPosition - 1 - control.TerminalPosition)
			}
			walBytes := privacyDatabaseSize(path + "-wal")
			throughput := float64(b.N) / elapsed.Seconds()
			b.ReportMetric(float64(synchronous), "synchronous")
			b.ReportMetric(throughput, "commit-load-events/s")
			b.ReportMetric(float64(maxInt64(privacyDatabaseSize(path)-beforeSize, 0)), "main-db-growth-bytes")
			b.ReportMetric(float64(rebuild.Microseconds()), "rebuild-us/run")
			b.ReportMetric(float64(backlog), "backlog")
			b.ReportMetric(float64(walBytes), "wal-bytes")
			b.ReportMetric(float64(aggregateLoad.Microseconds())/float64(maxInt(b.N, 1)), "aggregate-load-us/op")
		})
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
