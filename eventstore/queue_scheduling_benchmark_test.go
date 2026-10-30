package eventstore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

const queueSchedulingBenchmarkBacklog = 4_096

var queueSchedulingBenchmarkHistorySizes = [...]int{0, 1_000, 100_000, 400_000}

type queueSchedulingBenchmarkMode uint8

const (
	queueSchedulingBenchmarkScrubbed queueSchedulingBenchmarkMode = iota
	queueSchedulingBenchmarkFuture
	queueSchedulingBenchmarkPending
	queueSchedulingBenchmarkFair
)

type queueSchedulingBenchmarkFixture struct {
	store    *GORMStore
	database *Database
	clock    *queueTestClock
	lane     []byte
	other    []byte
}

func queueSchedulingBenchmarkLane(prefix byte, number int) []byte {
	lane := make([]byte, 32)
	lane[0] = prefix
	binary.BigEndian.PutUint64(lane[24:], uint64(number+1))
	return lane
}

func queueSchedulingBenchmarkPendingRow(id string, lane []byte, sequence uint64, now time.Time) outboxEffectRow {
	expires := now.Add(24 * time.Hour)
	return outboxEffectRow{
		EffectID: id, Version: 1, EndpointID: "benchmark-endpoint",
		LaneHMAC: lane, OrderingSequence: sequence, EffectClass: "send",
		RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
		PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"),
		EncryptionKeyID: "benchmark-key", PayloadVersion: 1, PayloadExpiresAt: &expires,
		PayloadPresent: true, SchedulingVersion: 0, CreatedAt: now,
	}
}

func queueSchedulingBenchmarkEffect(id string, lane []byte) NewEffect {
	return NewEffect{
		EffectID: id, EndpointID: "benchmark-endpoint", LaneHMAC: append([]byte(nil), lane...),
		EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
		PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"),
		DigestKeyID: "benchmark-key",
	}
}

func queueSchedulingBenchmarkInsertRows(b *testing.B, db *gorm.DB, rows []outboxEffectRow) {
	b.Helper()
	if len(rows) == 0 {
		return
	}
	if err := db.CreateInBatches(&rows, 100).Error; err != nil {
		b.Fatal(err)
	}
}

func queueSchedulingBenchmarkOpen(b *testing.B, history int, mode queueSchedulingBenchmarkMode) queueSchedulingBenchmarkFixture {
	b.Helper()
	ctx := context.Background()
	database, err := OpenDatabase(ctx, DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(b.TempDir(), "queue-scheduling.db"),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = database.Close() })
	db := database.GORM()
	clock := &queueTestClock{now: time.Unix(10_000, 0).UTC()}

	historyLanes := make([][]byte, 64)
	for index := range historyLanes {
		historyLanes[index] = queueSchedulingBenchmarkLane(0x10, index)
	}
	const seedBatchSize = 1_000
	for batch := range (history + seedBatchSize - 1) / seedBatchSize {
		start := batch * seedBatchSize
		end := min(start+seedBatchSize, history)
		rows := make([]outboxEffectRow, 0, end-start)
		for offset := range end - start {
			index := start + offset
			laneIndex := index % len(historyLanes)
			expired := clock.Now().Add(-time.Hour)
			rows = append(rows, outboxEffectRow{
				EffectID: fmt.Sprintf("scrubbed-history-%09d", index), Version: 1,
				EndpointID: "benchmark-endpoint", LaneHMAC: historyLanes[laneIndex],
				OrderingSequence: uint64(index/len(historyLanes) + 1), EffectClass: "send",
				RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusAmbiguous,
				PayloadVersion: 1, PayloadExpiresAt: &expired, PayloadPresent: false,
				SchedulingVersion: 0, CreatedAt: clock.Now().Add(-2 * time.Hour),
			})
		}
		queueSchedulingBenchmarkInsertRows(b, db, rows)
	}

	fixture := queueSchedulingBenchmarkFixture{database: database, clock: clock}
	switch mode {
	case queueSchedulingBenchmarkScrubbed:
	case queueSchedulingBenchmarkFuture:
		fixture.lane = queueSchedulingBenchmarkLane(0x80, 0)
		row := queueSchedulingBenchmarkPendingRow("future-due", fixture.lane, 1, clock.Now())
		due := clock.Now().Add(time.Hour)
		row.NextAttemptAt = &due
		queueSchedulingBenchmarkInsertRows(b, db, []outboxEffectRow{row})
		if err := db.Create(&laneHeadRow{
			Kind: outboxLaneKind, LaneHMAC: fixture.lane, NextSequence: 2,
			SchedulingVersion: 0, UpdatedAt: clock.Now(),
		}).Error; err != nil {
			b.Fatal(err)
		}
	case queueSchedulingBenchmarkPending:
		fixture.lane = queueSchedulingBenchmarkLane(0x81, 0)
		for batch := range (queueSchedulingBenchmarkBacklog + seedBatchSize - 1) / seedBatchSize {
			start := batch * seedBatchSize
			end := min(start+seedBatchSize, queueSchedulingBenchmarkBacklog)
			rows := make([]outboxEffectRow, 0, end-start)
			for offset := range end - start {
				index := start + offset
				rows = append(rows, queueSchedulingBenchmarkPendingRow(
					fmt.Sprintf("pending-backlog-%06d", index), fixture.lane, uint64(index+1), clock.Now(),
				))
			}
			queueSchedulingBenchmarkInsertRows(b, db, rows)
		}
		if err := db.Create(&laneHeadRow{
			Kind: outboxLaneKind, LaneHMAC: fixture.lane,
			NextSequence:      queueSchedulingBenchmarkBacklog + 1,
			SchedulingVersion: 0, UpdatedAt: clock.Now(),
		}).Error; err != nil {
			b.Fatal(err)
		}
	case queueSchedulingBenchmarkFair:
		fixture.lane = queueSchedulingBenchmarkLane(0x82, 0)
		fixture.other = queueSchedulingBenchmarkLane(0x83, 0)
		rows := []outboxEffectRow{
			queueSchedulingBenchmarkPendingRow("fair-old-high-sequence", fixture.lane, 100, clock.Now()),
			queueSchedulingBenchmarkPendingRow("fair-new-low-sequence", fixture.other, 1, clock.Now()),
		}
		queueSchedulingBenchmarkInsertRows(b, db, rows)
		heads := []laneHeadRow{
			{Kind: outboxLaneKind, LaneHMAC: fixture.lane, NextSequence: 101, SchedulingVersion: 0, UpdatedAt: clock.Now().Add(-2 * time.Nanosecond)},
			{Kind: outboxLaneKind, LaneHMAC: fixture.other, NextSequence: 2, SchedulingVersion: 0, UpdatedAt: clock.Now().Add(-time.Nanosecond)},
		}
		if err := db.Create(&heads).Error; err != nil {
			b.Fatal(err)
		}
	default:
		b.Fatal("unknown queue scheduling benchmark mode")
	}
	if err := migrateQueueScheduling(db); err != nil {
		b.Fatal(err)
	}
	fixture.store = NewStore(database, WithClock(clock))
	return fixture
}

func queueSchedulingBenchmarkComplete(b *testing.B, fixture queueSchedulingBenchmarkFixture, lease OutboxLease) {
	b.Helper()
	ctx := context.Background()
	dispatched, err := fixture.store.MarkOutboxDispatched(ctx, OutboxDispatchRequest{
		EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner,
		LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
	})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := fixture.store.CompleteOutbox(ctx, OutboxCompletionRequest{
		EffectID: dispatched.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner,
		LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID,
		Status: OutboxStatusSucceeded, ResultCode: "benchmark-complete",
	}); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkQueueSchedulingScrubbedAmbiguous(b *testing.B) {
	for _, history := range queueSchedulingBenchmarkHistorySizes {
		b.Run(fmt.Sprintf("history_%d", history), func(b *testing.B) {
			fixture := queueSchedulingBenchmarkOpen(b, history, queueSchedulingBenchmarkScrubbed)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				available, err := fixture.store.HasOutboxWork(ctx)
				if err != nil || available {
					b.Fatalf("HasOutboxWork = %v, %v; want false", available, err)
				}
				if _, err := fixture.store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "scrubbed-benchmark"}); !errors.Is(err, ErrNotFound) {
					b.Fatalf("ClaimOutbox err = %v; want not found", err)
				}
			}
		})
	}
}

func BenchmarkQueueSchedulingFutureDue(b *testing.B) {
	for _, history := range queueSchedulingBenchmarkHistorySizes {
		b.Run(fmt.Sprintf("history_%d", history), func(b *testing.B) {
			fixture := queueSchedulingBenchmarkOpen(b, history, queueSchedulingBenchmarkFuture)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				available, err := fixture.store.HasOutboxWork(ctx)
				if err != nil || available {
					b.Fatalf("HasOutboxWork = %v, %v; want false", available, err)
				}
				if _, err := fixture.store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "future-benchmark"}); !errors.Is(err, ErrNotFound) {
					b.Fatalf("ClaimOutbox err = %v; want not found", err)
				}
			}
		})
	}
}

func BenchmarkQueueSchedulingPendingBacklog(b *testing.B) {
	for _, history := range queueSchedulingBenchmarkHistorySizes {
		b.Run(fmt.Sprintf("history_%d", history), func(b *testing.B) {
			fixture := queueSchedulingBenchmarkOpen(b, history, queueSchedulingBenchmarkPending)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := range b.N {
				available, err := fixture.store.HasOutboxWork(ctx)
				if err != nil || !available {
					b.Fatalf("HasOutboxWork = %v, %v; want true", available, err)
				}
				lease, err := fixture.store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "pending-benchmark", LeaseDuration: time.Minute})
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				queueSchedulingBenchmarkComplete(b, fixture, lease)
				if _, err := fixture.store.AcceptOutbox(ctx, queueSchedulingBenchmarkEffect(
					fmt.Sprintf("pending-refill-%09d", iteration), fixture.lane,
				)); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			b.StopTimer()
		})
	}
}

func BenchmarkQueueSchedulingReadyLaneFairness(b *testing.B) {
	for _, history := range queueSchedulingBenchmarkHistorySizes {
		b.Run(fmt.Sprintf("history_%d", history), func(b *testing.B) {
			fixture := queueSchedulingBenchmarkOpen(b, history, queueSchedulingBenchmarkFair)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := range b.N {
				available, err := fixture.store.HasOutboxWork(ctx)
				if err != nil || !available {
					b.Fatalf("HasOutboxWork = %v, %v; want true", available, err)
				}
				oldLane, err := fixture.store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "fair-old-benchmark", LeaseDuration: time.Minute})
				if err != nil || !strings.HasPrefix(oldLane.Effect.EffectID, "fair-old-") {
					b.Fatalf("old lane claim = %#v, %v", oldLane, err)
				}
				b.StopTimer()
				queueSchedulingBenchmarkComplete(b, fixture, oldLane)
				newLane, err := fixture.store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "fair-new-benchmark", LeaseDuration: time.Minute})
				if err != nil || !strings.HasPrefix(newLane.Effect.EffectID, "fair-new-") {
					b.Fatalf("new lane claim = %#v, %v", newLane, err)
				}
				queueSchedulingBenchmarkComplete(b, fixture, newLane)
				if _, err := fixture.store.AcceptOutbox(ctx, queueSchedulingBenchmarkEffect(
					fmt.Sprintf("fair-old-refill-%09d", iteration), fixture.lane,
				)); err != nil {
					b.Fatal(err)
				}
				fixture.clock.Advance(time.Nanosecond)
				if _, err := fixture.store.AcceptOutbox(ctx, queueSchedulingBenchmarkEffect(
					fmt.Sprintf("fair-new-refill-%09d", iteration), fixture.other,
				)); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			b.StopTimer()
		})
	}
}
