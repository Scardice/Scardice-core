package eventstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

func task7PrivacySeedOperation(t *testing.T, store *GORMStore, group, dice, operation string, scopes []string) PrivacyDryRunResult {
	t.Helper()
	ctx := context.Background()
	scan, err := store.PrivacyDryRun(ctx, PrivacyDryRunRequest{GroupID: group, DiceIDs: []string{dice}, Scopes: scopes})
	if err != nil { t.Fatal(err) }
	private := PrivacyOperationContext{GroupID: group, DiceIDs: []string{dice}, Scopes: scopes, Phase: "delete", Counts: scan.Counts, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}
	if err := store.PrivacyCreateOperation(ctx, operation, scan.SubjectKey, private); err != nil { t.Fatal(err) }
	if _, err := store.PrivacyFence(ctx, scan.SubjectKey, "group", operation); err != nil { t.Fatal(err) }
	return scan
}

func TestTask7SQLiteLiveAndRebuiltDigestAgree(t *testing.T) {
	ctx := context.Background()
	store, db := task7OpenSQLite(t, task7Source(), "task7-privacy-digest")
	defer db.Close()
	if err := store.RegisterProjection(task7Projection()); err != nil { t.Fatal(err) }
	stream := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice-a", "digest-group")}
	commit, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event("privacy-digest", 7)}}}})
	if err != nil { t.Fatal(err) }
	var control projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil { t.Fatal(err) }
	liveDigest, err := store.DigestProjection(ctx, control.ActiveGeneration)
	if err != nil { t.Fatal(err) }
	rebuilt, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"})
	if err != nil { t.Fatal(err) }
	if rebuilt.TerminalPosition != commit.Events[0].GlobalPosition || rebuilt.Digest != liveDigest {
		t.Fatalf("live/rebuilt result mismatch terminal=%d want=%d live=%s rebuilt=%s", rebuilt.TerminalPosition, commit.Events[0].GlobalPosition, liveDigest, rebuilt.Digest)
	}
	publishedDigest, err := store.DigestProjection(ctx, rebuilt.GenerationID)
	if err != nil { t.Fatal(err) }
	if publishedDigest != rebuilt.Digest { t.Fatalf("published digest=%s rebuild digest=%s", publishedDigest, rebuilt.Digest) }
	liveRow, err := store.ReadProjectionRow(ctx, "counter", stream.AggregateID)
	if err != nil || string(liveRow.Payload) != `{"delta":7}` { t.Fatalf("published row=%+v err=%v", liveRow, err) }
}

func TestTask7SQLiteEmptyProjectorRebuildKeepsOldReadModel(t *testing.T) {
	ctx := context.Background()
	store, db := task7OpenSQLite(t, task7Source(), "task7-privacy-empty-projector")
	defer db.Close()
	old := projectionReadModelRow{ProjectionGeneration: "old-generation", ProjectionName: "legacy", RowKey: "group-a", Payload: []byte(`{"old":true}`), UpdatedAt: time.Unix(1, 0).UTC()}
	if err := db.GORM().Create(&old).Error; err != nil { t.Fatal(err) }
	if err := db.GORM().Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{"active_generation": old.ProjectionGeneration, "publication_state": "published"}).Error; err != nil { t.Fatal(err) }
	if err := store.PrivacyRebuildPublish(ctx, 0); !errors.Is(err, ErrInvalidProjector) { t.Fatalf("empty projector error=%v", err) }
	var retained projectionReadModelRow
	if err := db.GORM().Where("projection_generation = ? AND projection_name = ? AND row_key = ?", old.ProjectionGeneration, old.ProjectionName, old.RowKey).First(&retained).Error; err != nil { t.Fatal(err) }
	if string(retained.Payload) != `{"old":true}` { t.Fatalf("old read model payload=%q", retained.Payload) }
}

func TestTask7SQLitePrivacyCapacityRecordAndEightMiBBound(t *testing.T) {
	ctx := context.Background()
	t.Run("more-than-500-records", func(t *testing.T) {
		store, db := task7OpenSQLite(t, task7Source(), "task7-privacy-500")
		defer db.Close()
		if err := store.RegisterProjection(task7Projection()); err != nil { t.Fatal(err) }
		stream := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice-a", "capacity-group", "player-a")}
		events := make([]NewEvent, 501)
		for i := range events { events[i] = task7Event(fmt.Sprintf("capacity-%03d", i), i) }
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: events}}}); err != nil { t.Fatal(err) }
		scan := task7PrivacySeedOperation(t, store, "capacity-group", "dice-a", "capacity-operation", []string{"players"})
		private := PrivacyOperationContext{GroupID: "capacity-group", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Phase: "delete", Cursor: ""}
		view, loaded, err := store.PrivacyLoadOperation(ctx, "capacity-operation")
		if err != nil { t.Fatal(err) }
		private = loaded
		first, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "capacity-operation", GroupID: "capacity-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Limit: 500})
		if err != nil { t.Fatal(err) }
		if first.Deleted.Players != 500 || first.Done || first.NextCursor == "" { t.Fatalf("first batch=%+v", first) }
		private.Cursor = first.NextCursor
		if _, err := store.PrivacyUpdateOperation(ctx, "capacity-operation", view.Version, private, "running"); err != nil { t.Fatal(err) }
		secondView, loaded, err := store.PrivacyLoadOperation(ctx, "capacity-operation")
		if err != nil { t.Fatal(err) }
		second, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "capacity-operation", GroupID: "capacity-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Cursor: first.NextCursor, Limit: 500})
		if err != nil { t.Fatal(err) }
		if second.Deleted.Players != 1 || !second.Done || second.NextCursor == "" { t.Fatalf("second batch=%+v", second) }
		if first.Deleted.Players > PrivacyBatchRecords || second.Deleted.Players > PrivacyBatchRecords { t.Fatalf("batch exceeded record bound first=%d second=%d", first.Deleted.Players, second.Deleted.Players) }
		_ = secondView
		_ = loaded
		if scan.Counts.Players != 501 { t.Fatalf("dry-run count=%+v", scan.Counts) }
		remaining, err := store.Load(ctx, stream, 0)
		if err != nil || len(remaining) != 0 { t.Fatalf("remaining events=%d err=%v", len(remaining), err) }
	})

	t.Run("eight-mebibyte-payload-bound", func(t *testing.T) {
		store, db := task7OpenSQLite(t, task7Source(), "task7-privacy-8mib")
		defer db.Close()
		if err := store.RegisterProjection(task7Projection()); err != nil { t.Fatal(err) }
		stream := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice-a", "bytes-group", "player-a")}
		events := make([]NewEvent, 34)
		for i := range events { events[i] = task7Event(fmt.Sprintf("bytes-%03d", i), i); events[i].Payload = make([]byte, MaxEventPayloadBytes) }
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: events}}}); err != nil { t.Fatal(err) }
		task7PrivacySeedOperation(t, store, "bytes-group", "dice-a", "bytes-operation", []string{"players"})
		first, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "bytes-operation", GroupID: "bytes-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Limit: PrivacyBatchRecords})
		if err != nil { t.Fatal(err) }
		if first.Deleted.Players != 32 || first.Done { t.Fatalf("8MiB first batch=%+v", first) }
		view, private, err := store.PrivacyLoadOperation(ctx, "bytes-operation")
		if err != nil { t.Fatal(err) }
		private.Cursor = first.NextCursor
		if _, err := store.PrivacyUpdateOperation(ctx, "bytes-operation", view.Version, private, "running"); err != nil { t.Fatal(err) }
		second, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "bytes-operation", GroupID: "bytes-group", Phase: "delete", DiceIDs: []string{"dice-a"}, Scopes: []string{"players"}, Cursor: first.NextCursor, Limit: PrivacyBatchRecords})
		if err != nil { t.Fatal(err) }
		if second.Deleted.Players != 2 || !second.Done { t.Fatalf("8MiB second batch=%+v", second) }
		if first.Deleted.Players+second.Deleted.Players != 34 { t.Fatalf("8MiB total=%d", first.Deleted.Players+second.Deleted.Players) }
	})
}

type task7PrivacyRunMetric struct {
	mode string
	synchronous int
	p50, p95 time.Duration
	throughput float64
	memoryBytes uint64
	dbGrowthBytes int64
	rebuildTime, aggregateLoadTime time.Duration
	backlog, walBytes int64
}

func task7Percentile(samples []time.Duration, percentile float64) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 { return 0 }
	index := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	if index < 0 { index = 0 }
	if index >= len(ordered) { index = len(ordered)-1 }
	return ordered[index]
}

func TestTask7SQLiteNormalFullMetricReport(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []struct{name string; pragma string; want int}{{"NORMAL", "NORMAL", 1}, {"FULL", "FULL", 2}} {
		t.Run(mode.name, func(t *testing.T) {
			source := task7Source()
			path := filepath.Join(t.TempDir(), "task7-metrics.db")
			db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source, DatabaseIdentity: "task7-metrics"})
			if err != nil { t.Fatal(err) }
			store := NewStore(db)
			defer db.Close()
			if err := store.RegisterProjection(task7Projection()); err != nil { t.Fatal(err) }
			if _, err := db.SQLDB().ExecContext(ctx, "PRAGMA synchronous = "+mode.pragma); err != nil { t.Fatal(err) }
			var synchronous int
			if err := db.SQLDB().QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil { t.Fatal(err) }
			if synchronous != mode.want { t.Fatalf("effective synchronous=%d want=%d", synchronous, mode.want) }
			beforeSize := task7SQLiteSize(path)
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			samples := make([]time.Duration, 0, 5)
			var aggregateLoad time.Duration
			var rebuild time.Duration
			for i := 0; i < 5; i++ {
				stream := StreamID{AggregateType: "group", AggregateID: fmt.Sprintf("metric-%d", i)}
				started := time.Now()
				if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{task7Event(fmt.Sprintf("metric-event-%d", i), i)}}}}); err != nil { t.Fatal(err) }
				samples = append(samples, time.Since(started))
				loadStarted := time.Now()
				if _, err := store.Load(ctx, stream, 0); err != nil { t.Fatal(err) }
				aggregateLoad += time.Since(loadStarted)
				rebuildStarted := time.Now()
				if _, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"}); err != nil { t.Fatal(err) }
				rebuild += time.Since(rebuildStarted)
			}
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			var sequence eventGlobalSequenceRow
			var control projectionControlRow
			if err := db.GORM().Where("singleton_id = ?", "default").First(&sequence).Error; err != nil { t.Fatal(err) }
			if err := db.GORM().Where("singleton_id = ?", "default").First(&control).Error; err != nil { t.Fatal(err) }
			backlog := int64(0)
			if sequence.NextPosition > control.TerminalPosition { backlog = int64(sequence.NextPosition - 1 - control.TerminalPosition) }
			walBytes := task7SQLiteSize(path + "-wal")
			metrics := task7PrivacyRunMetric{mode: mode.name, synchronous: synchronous, p50: task7Percentile(samples, .50), p95: task7Percentile(samples, .95), throughput: float64(len(samples)) / time.Duration(sumTask7Durations(samples)).Seconds(), memoryBytes: after.TotalAlloc - before.TotalAlloc, dbGrowthBytes: maxInt64(task7SQLiteSize(path)-beforeSize, 0), rebuildTime: rebuild, aggregateLoadTime: aggregateLoad, backlog: backlog, walBytes: walBytes}
			if metrics.p50 <= 0 || metrics.p95 <= 0 || metrics.throughput <= 0 || metrics.aggregateLoadTime <= 0 || metrics.rebuildTime <= 0 { t.Fatalf("invalid metrics=%+v", metrics) }
			t.Logf("mode=%s synchronous=%d p50=%s p95=%s throughput=%.2f_events_per_second memory_bytes=%d db_growth_bytes=%d rebuild_time=%s backlog=%d wal_bytes=%d aggregate_load_time=%s", metrics.mode, metrics.synchronous, metrics.p50, metrics.p95, metrics.throughput, metrics.memoryBytes, metrics.dbGrowthBytes, metrics.rebuildTime, metrics.backlog, metrics.walBytes, metrics.aggregateLoadTime)
		})
	}
}

func sumTask7Durations(values []time.Duration) int64 { var total int64; for _, value := range values { total += int64(value) }; return total }
func maxInt64(a, b int64) int64 { if a > b { return a }; return b }

