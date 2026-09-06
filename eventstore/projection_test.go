package eventstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"sync"
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
	if err := store.RegisterProjection(ProjectionDescriptor{Name: "alias", Version: "v1", SchemaVersion: "v2", Apply: apply}); !errors.Is(err, ErrProjectorVersionConflict) {
		t.Fatalf("alias version conflict error = %v", err)
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
	if err := store.RegisterProjection(ProjectionDescriptor{Name: "other", Version: "v2", Apply: apply}); !errors.Is(err, ErrProjectorVersionConflict) {
		t.Fatalf("cross-projector conflict error = %v", err)
	}
	_, dbWithOption := projectionTestStore(t)
	defer dbWithOption.Close()
	invalid := NewStore(dbWithOption, WithProjection(ProjectionDescriptor{Name: " ", Version: "v1", Apply: apply}))
	if _, err := invalid.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "option"}, Events: []NewEvent{testEvent("option")}}}}); !errors.Is(err, ErrInvalidProjector) {
		t.Fatalf("invalid option error = %v", err)
	}
}
func TestProjectorSetVersionIncludesEveryStableName(t *testing.T) {
	apply := func(context.Context, *gorm.DB, []Envelope) error { return nil }
	single := projectorSetVersion([]ProjectionDescriptor{{Name: "events", Version: "v1", Apply: apply}})
	double := projectorSetVersion([]ProjectionDescriptor{
		{Name: "events", Version: "v1", Apply: apply},
		{Name: "other", Version: "v1", Apply: apply},
	})
	if single == double {
		t.Fatalf("projector set identity ignored registration set: %q", single)
	}
	collisionA := projectorSetVersion([]ProjectionDescriptor{{Name: "a=b", Version: "v"}})
	collisionB := projectorSetVersion([]ProjectionDescriptor{{Name: "a", Version: "b=v"}})
	if collisionA == collisionB {
		t.Fatalf("projector set identity collided: %q", collisionA)
	}
}
func TestRebuildEmptyStorePublishesGeneration(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	result, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.GenerationID == "" || result.TerminalPosition != 0 {
		t.Fatalf("empty rebuild result = %#v", result)
	}
	var control projectionControlRow
	if err := db.GORM().First(&control).Error; err != nil {
		t.Fatal(err)
	}
	if control.ActiveGeneration != result.GenerationID || control.TerminalPosition != 0 {
		t.Fatalf("empty rebuild control = %#v", control)
	}
}

func TestRebuildRejectsMalformedPersistedEnvelope(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "malformed"}, Events: []NewEvent{testEvent("malformed")}}}}); err != nil {
		t.Fatal(err)
	}
	var row domainEventRow
	if err := db.GORM().Where("event_id = ?", "malformed").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	envelope, err := projectionEnvelope(row)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Stream.AggregateType = ""
	checksum := ComputeEventChecksum(envelope)
	row.Checksum = append([]byte(nil), checksum[:]...)
	if err := db.GORM().Model(&domainEventRow{}).Where("event_id = ?", "malformed").Updates(map[string]any{"aggregate_type": "", "checksum": row.Checksum}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("malformed rebuild error = %v", err)
	}
}

func TestRebuildRejectsGlobalPositionGap(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "gap"}, Events: []NewEvent{testEvent("gap")}}}}); err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().First(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&domainEventRow{}).Where("event_id = ?", "gap").Update("global_position", 0).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"}); !errors.Is(err, ErrProjectionInvariant) {
		t.Fatalf("gap rebuild error = %v", err)
	}
	var after projectionControlRow
	if err := db.GORM().First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration != before.ActiveGeneration || after.TerminalPosition != before.TerminalPosition {
		t.Fatalf("gap rebuild published: before=%#v after=%#v", before, after)
	}
}
func TestRebuildRejectsMixedLegacyAndStableProjectors(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterProjector(Projector(func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		for _, event := range events {
			if err := UpsertProjectionRow(tx, "legacy", event.EventID, event.Payload); err != nil {
				return err
			}
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "mixed"}, Events: []NewEvent{testEvent("mixed-1")}}}}); err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().First(&before).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: projectorSetVersion([]ProjectionDescriptor{{Name: "events", Version: "v1"}})}); !errors.Is(err, ErrLegacyProjector) {
		t.Fatalf("mixed rebuild error = %v", err)
	}
	var after projectionControlRow
	if err := db.GORM().First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration != before.ActiveGeneration || after.TerminalPosition != before.TerminalPosition {
		t.Fatalf("mixed rebuild published: before=%#v after=%#v", before, after)
	}
}

func TestLiveAndRebuildPreserveNilPayload(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(projectionDescriptor("v1", projectionApply)); err != nil {
		t.Fatal(err)
	}
	event := testEvent("nil-payload")
	event.Payload = nil
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "nil"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	row, err := store.ReadProjectionRow(context.Background(), "events", "nil-payload")
	if err != nil {
		t.Fatal(err)
	}
	if row.Payload != nil {
		t.Fatalf("live nil payload became non-nil: %#v", row.Payload)
	}
	result, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := store.ReadProjectionRow(context.Background(), "events", "nil-payload")
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.ProjectionGeneration != result.GenerationID || rebuilt.Payload != nil {
		t.Fatalf("rebuilt nil payload = %#v", rebuilt)
	}
	emptyEvent := testEvent("empty-load")
	emptyEvent.Payload = []byte{}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "empty"}, Events: []NewEvent{emptyEvent}}}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background(), StreamID{"a", "empty"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Payload == nil || len(loaded[0].Payload) != 0 {
		t.Fatalf("empty payload round trip = %#v", loaded)
	}
}



func TestRebuildAbortsWhenProjectorRegistryChanges(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls int
	if err := store.RegisterProjection(projectionDescriptor("v1", func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		calls++
		if calls == 2 {
			close(started)
			<-release
		}
		return projectionApply(context.Background(), tx, events)
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "registry"}, Events: []NewEvent{testEvent("registry-1")}}}}); err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().First(&before).Error; err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan error, 1)
	go func() {
		_, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
		resultCh <- err
	}()
	<-started
	if err := store.RegisterProjection(ProjectionDescriptor{Name: "other", Version: "v1", Apply: projectionApply}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-resultCh; !errors.Is(err, ErrProjectorRegistryChanged) {
		t.Fatalf("registry change rebuild error = %v", err)
	}
	var after projectionControlRow
	if err := db.GORM().First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration != before.ActiveGeneration || after.TerminalPosition != before.TerminalPosition {
		t.Fatalf("published after registry change: before=%#v after=%#v", before, after)
	}
}

func TestProjectorLiveWritesUseActiveGenerationAndRollback(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	var calls int
	if err := store.RegisterProjection(projectionDescriptor("v1", func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		calls++
		for _, event := range events {
			if err := writeProjection(tx, event); err != nil {
				return err
			}
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
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
	var pageSizes []int
	apply := func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		pageSizes = append(pageSizes, len(events))
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
			if batch == 0 && i == 0 {
				events[i].Payload = []byte{}
			}
		}
		if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "rebuild"}, ExpectedVersion: uint64(batch * 64), Events: events}}}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	row, err := store.ReadProjectionRow(context.Background(), "events", "rebuild-0000")
	if err != nil {
		t.Fatal(err)
	}
	if row.Payload == nil || len(row.Payload) != 0 {
		t.Fatalf("empty payload was not preserved: %#v", row.Payload)
	}
	if result.TerminalPosition != 1024 || result.GenerationID == "" {
		t.Fatalf("result = %#v", result)
	}
	sawFullPage, sawRemainder := false, false
	for _, size := range pageSizes {
		sawFullPage = sawFullPage || size == projectionPageSize
		sawRemainder = sawRemainder || size == 24
	}
	if !sawFullPage || !sawRemainder {
		t.Fatalf("keyset page sizes = %#v", pageSizes)
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
func TestRebuildCatchesConcurrentCommitBeforePublication(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	apply := func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		if len(events) == projectionPageSize {
			once.Do(func() {
				close(started)
				<-release
			})
		}
		return projectionApply(context.Background(), tx, events)
	}
	if err := store.RegisterProjection(projectionDescriptor("v1", apply)); err != nil {
		t.Fatal(err)
	}
	for batch := 0; batch < 16; batch++ {
		events := make([]NewEvent, 64)
		for i := range events {
			events[i] = testEvent(fmt.Sprintf("concurrent-%04d", batch*64+i))
		}
		if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "concurrent"}, ExpectedVersion: uint64(batch * 64), Events: events}}}); err != nil {
			t.Fatal(err)
		}
	}
	rebuildResult := make(chan RebuildResult, 1)
	rebuildErrors := make(chan error, 1)
	go func() {
		result, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
		rebuildResult <- result
		rebuildErrors <- err
	}()
	<-started
	commitResult := make(chan error, 1)
	go func() {
		_, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "concurrent"}, ExpectedVersion: 1024, Events: []NewEvent{testEvent("concurrent-tail")}}}})
		commitResult <- err
	}()
	close(release)
	if err := <-commitResult; err != nil {
		t.Fatal(err)
	}
	if err := <-rebuildErrors; err != nil {
		t.Fatal(err)
	}
	result := <-rebuildResult
	var control projectionControlRow
	if err := db.GORM().First(&control).Error; err != nil {
		t.Fatal(err)
	}
	if control.TerminalPosition != 1025 {
		t.Fatalf("terminal position = %d, rebuild result = %#v", control.TerminalPosition, result)
	}
	row, err := store.ReadProjectionRow(context.Background(), "events", "concurrent-tail")
	if err != nil {
		t.Fatal(err)
	}
	if row.ProjectionGeneration != control.ActiveGeneration {
		t.Fatalf("reader mixed generations: row=%#v control=%#v", row, control)
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
		{ProjectionGeneration: "one", ProjectionName: "z", RowKey: "z", Payload: []byte("1"), UpdatedAt: now},
		{ProjectionGeneration: "one", ProjectionName: "A", RowKey: "A", Payload: []byte("2"), UpdatedAt: now},
		{ProjectionGeneration: "two", ProjectionName: "A", RowKey: "A", Payload: []byte("2"), UpdatedAt: now.Add(time.Hour)},
		{ProjectionGeneration: "two", ProjectionName: "z", RowKey: "z", Payload: []byte("1"), UpdatedAt: now.Add(time.Hour)},
	}
	for i := range rows {
		if err := db.GORM().Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
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
	result, err := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	row, err := store.ReadProjectionRow(context.Background(), "events", "reader-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.ProjectionGeneration != result.GenerationID || string(row.Payload) != `{"value":1}` {
		t.Fatalf("reader mixed generations: row=%#v result=%#v", row, result)
	}
}
