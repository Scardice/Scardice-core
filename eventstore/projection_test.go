package eventstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
	"gorm.io/gorm"
)

func projectionTestStore(t *testing.T) (*GORMStore, *Database) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "projection.db")})
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(db), db
}

func projectionDescriptor(version string, apply Projector) ProjectionDescriptor {
	return ProjectionDescriptor{Name: "events", Version: version, Apply: apply}
}

func writeProjection(tx *gorm.DB, event Envelope) error {
	return UpsertProjectionRow(tx, "events", event.EventID, event.Payload)
}
func projectionApply(_ context.Context, tx *gorm.DB, events []Envelope) error {
	for _, event := range events {
		if err := writeProjection(tx, event); err != nil {
			return err
		}
	}
	return nil
}

func TestProjectionRegistrationRejectsEmptyDuplicateAndConflictingVersion(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	apply := func(context.Context, *gorm.DB, []Envelope) error { return nil }
	if err := store.RegisterProjection(ProjectionDescriptor{Version: "v1", Apply: apply}); !errors.Is(err, ErrInvalidProjector) {
		t.Fatalf("empty name error = %v", err)
	}
	if err := store.RegisterProjection(ProjectionDescriptor{Name: "events", Apply: apply}); !errors.Is(err, ErrInvalidProjector) {
		t.Fatalf("empty version error = %v", err)
	}
	if err := store.RegisterProjection(projectionDescriptor("v1", apply)); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterProjection(projectionDescriptor("v1", apply)); !errors.Is(err, ErrDuplicateProjector) {
		t.Fatalf("duplicate error = %v", err)
	}
	if err := store.RegisterProjection(projectionDescriptor("v2", apply)); !errors.Is(err, ErrProjectorVersionConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestProjectorLiveWritesUseActiveGenerationAndRollback(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	var calls int
	store.RegisterProjection(projectionDescriptor("v1", func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		calls++
		for _, event := range events {
			if err := writeProjection(tx, event); err != nil {
				return err
			}
		}
		return nil
	}))
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "1"}, Events: []NewEvent{testEvent("live-1")}}}}); err != nil {
		t.Fatal(err)
	}
	row, err := store.ReadProjectionRow(context.Background(), "events", "live-1")
	if err != nil || row.ProjectionGeneration != "initial" {
		t.Fatalf("live row = %#v, err = %v", row, err)
	}
	store.RegisterProjector(func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		for _, event := range events {
			if err := writeProjection(tx, event); err != nil {
				return err
			}
		}
		return errors.New("projector failed")
	})
	_, err = store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "1"}, ExpectedVersion: 1, Events: []NewEvent{testEvent("live-2")}}}})
	if !errors.Is(err, ErrProjectorFailure) {
		t.Fatalf("rollback error = %v", err)
	}
	var count int64
	if err := db.GORM().Model(&domainEventRow{}).Where("event_id = ?", "live-2").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed event count = %d", count)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestRebuildKeysetDigestAndPriorGenerationRetention(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	apply := func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		for _, event := range events {
			if err := writeProjection(tx, event); err != nil {
				return err
			}
		}
		return nil
	}
	if err := store.RegisterProjection(projectionDescriptor("v1", apply)); err != nil {
		t.Fatal(err)
	}
	for batch := 0; batch < 16; batch++ {
		events := make([]NewEvent, 64)
		for i := range events {
			events[i] = testEvent(fmt.Sprintf("rebuild-%04d", batch*64+i))
		}
		if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "rebuild"}, ExpectedVersion: uint64(batch * 64), Events: events}}}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TerminalPosition != 1024 || result.GenerationID == "" {
		t.Fatalf("result = %#v", result)
	}
	var oldRows int64
	if err := db.GORM().Model(&projectionReadModelRow{}).Where("projection_generation = ?", "initial").Count(&oldRows).Error; err != nil {
		t.Fatal(err)
	}
	if oldRows != 1024 {
		t.Fatalf("prior generation rows = %d", oldRows)
	}
	var control projectionControlRow
	if err := db.GORM().First(&control).Error; err != nil {
		t.Fatal(err)
	}
	if control.ActiveGeneration != result.GenerationID || control.TerminalPosition != 1024 {
		t.Fatalf("control = %#v", control)
	}
	again, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Digest != again.Digest {
		t.Fatalf("digest changed: %s != %s", result.Digest, again.Digest)
	}
}

func TestRebuildRejectsCorruptChecksumAndUnsupportedSchema(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "bad"}, Events: []NewEvent{testEvent("bad-checksum")}}}}); err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().First(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&domainEventRow{}).Where("event_id = ?", "bad-checksum").Update("payload", []byte("tampered")).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("checksum rebuild error = %v", err)
	}
	var after projectionControlRow
	if err := db.GORM().First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration != before.ActiveGeneration || after.TerminalPosition != before.TerminalPosition {
		t.Fatalf("published after checksum corruption: before=%#v after=%#v", before, after)
	}
}

func TestRebuildRejectsUnsupportedSchema(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "unsupported"}, Events: []NewEvent{testEvent("unsupported-schema")}}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&domainEventRow{}).Where("event_id = ?", "unsupported-schema").Update("schema_version", 99).Error; err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().First(&before).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrUnsupportedEventSchema) {
		t.Fatalf("unsupported rebuild error = %v", err)
	}
	var after projectionControlRow
	if err := db.GORM().First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration != before.ActiveGeneration || after.TerminalPosition != before.TerminalPosition {
		t.Fatalf("published after unsupported schema: before=%#v after=%#v", before, after)
	}
}

func TestDigestIgnoresGeneration(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	now := time.Now().UTC()
	rows := []projectionReadModelRow{
		{ProjectionGeneration: "one", ProjectionName: "events", RowKey: "a", Payload: []byte("1"), UpdatedAt: now},
		{ProjectionGeneration: "two", ProjectionName: "events", RowKey: "a", Payload: []byte("1"), UpdatedAt: now.Add(time.Hour)},
	}
	if err := db.GORM().Create(&rows[0]).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Create(&rows[1]).Error; err != nil {
		t.Fatal(err)
	}
	first, err := store.DigestProjection(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.DigestProjection(context.Background(), "two")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("generation-dependent digest: %s != %s", first, second)
	}
}

func TestGenerationAwareReaderDoesNotMixGenerations(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "reader"}, Events: []NewEvent{testEvent("reader-1")}}}}); err != nil {
		t.Fatal(err)
	}
}
