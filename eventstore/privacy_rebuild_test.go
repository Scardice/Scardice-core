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

func TestSQLiteLiveAndRebuiltDigestAgree(t *testing.T) {
	ctx := context.Background()
	store, db := openTransactionTestStore(t, "task7-privacy-digest")
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

func TestSQLiteEmptyProjectorRebuildKeepsOldReadModel(t *testing.T) {
	ctx := context.Background()
	store, db := openTransactionTestStore(t, "task7-privacy-empty-projector")
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
	if _, err := store.Rebuild(ctx, RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrInvalidProjector) {
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
			path := filepath.Join(t.TempDir(), "task7-metrics.db")
			db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, DatabaseIdentity: "task7-metrics"})
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

			path := filepath.Join(b.TempDir(), "task7-benchmark.db")
			db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, DatabaseIdentity: "task7-benchmark"})
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
