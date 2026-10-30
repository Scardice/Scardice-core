package eventstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
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
	row, eventErr := store.ReadProjectionRow(context.Background(), "events", "nil-payload")
	if eventErr != nil {
		t.Fatal(eventErr)
	}
	if row.Payload != nil {
		t.Fatalf("live nil payload became non-nil: %#v", row.Payload)
	}
	result, eventErr := store.Rebuild(context.Background(), RebuildRequest{ProjectorVersion: "v1"})
	if eventErr != nil {
		t.Fatal(eventErr)
	}
	rebuilt, eventErr := store.ReadProjectionRow(context.Background(), "events", "nil-payload")
	if eventErr != nil {
		t.Fatal(eventErr)
	}
	if rebuilt.ProjectionGeneration != result.GenerationID || rebuilt.Payload != nil {
		t.Fatalf("rebuilt nil payload = %#v", rebuilt)
	}
	emptyEvent := testEvent("empty-load")
	emptyEvent.Payload = []byte{}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "empty"}, Events: []NewEvent{emptyEvent}}}}); err != nil {
		t.Fatal(err)
	}
	loaded, eventErr := store.Load(context.Background(), StreamID{"a", "empty"}, 0)
	if eventErr != nil {
		t.Fatal(eventErr)
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

func TestRebuildAbortsWhenLegacyProjectorRegistersConcurrently(t *testing.T) {
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
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{"a", "legacy-registry"}, Events: []NewEvent{testEvent("legacy-registry-1")}}}}); err != nil {
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
	if err := store.RegisterProjector(Projector(func(context.Context, *gorm.DB, []Envelope) error { return nil })); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-resultCh; !errors.Is(err, ErrProjectorRegistryChanged) {
		t.Fatalf("legacy registry change error = %v", err)
	}
	var after projectionControlRow
	if err := db.GORM().First(&after).Error; err != nil {
		t.Fatal(err)
	}
	if after.ActiveGeneration != before.ActiveGeneration || after.TerminalPosition != before.TerminalPosition {
		t.Fatalf("published after legacy registry change: before=%#v after=%#v", before, after)
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
	registerErr := store.RegisterProjector(func(_ context.Context, tx *gorm.DB, events []Envelope) error {
		for _, event := range events {
			if err := writeProjection(tx, event); err != nil {
				return err
			}
		}
		return errors.New("projector failed")
	})
	if registerErr != nil {
		t.Fatal(registerErr)
	}
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
	for batch := range 16 {
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
	for batch := range 16 {
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

func insertProjectionPageRows(t *testing.T, db *Database, generation, projectionName string, keys []string) {
	t.Helper()
	now := time.Now().UTC()
	rows := make([]projectionReadModelRow, len(keys))
	for index, key := range keys {
		rows[index] = projectionReadModelRow{
			ProjectionGeneration: generation,
			ProjectionName:       projectionName,
			RowKey:               key,
			Payload:              []byte(key),
			PayloadPresent:       true,
			UpdatedAt:            now,
		}
	}
	if err := db.GORM().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
}

func TestProjectionRowPageUsesBoundedRangeAndStableCursor(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()

	want := []string{"1:a1:x", "1:a2:id", "1:a9:special"}
	insertProjectionPageRows(t, db, "initial", "attributes", want)
	insertProjectionPageRows(t, db, "initial", "attributes", []string{
		"1:a/invalid-continuation",
		"1:a:upper-bound",
		"1:b1:x",
		"2:a11:x",
		"9:x1:a1:x",
	})
	insertProjectionPageRows(t, db, "prior", "attributes", []string{"1:a1:prior"})
	insertProjectionPageRows(t, db, "initial", "other", []string{"1:a1:other"})

	request := ProjectionPageRequest{
		ProjectionName: "attributes",
		RowKeyPrefix:   "1:a",
		RowKeyStart:    "1:a0",
		RowKeyEnd:      "1:a:",
		Limit:          2,
	}
	var (
		cursor   string
		expected *ProjectionSnapshot
		got      []string
		pages    int
	)
	for {
		request.AfterRowKey = cursor
		request.ExpectedSnapshot = expected
		page, err := store.ListProjectionRowsPage(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if expected == nil {
			snapshot := page.Snapshot
			expected = &snapshot
			if snapshot.Generation != "initial" || snapshot.TerminalPosition != 0 || snapshot.HistoryRevision != 0 {
				t.Fatalf("first snapshot = %+v", snapshot)
			}
		} else if page.Snapshot != *expected {
			t.Fatalf("page snapshot = %+v, want %+v", page.Snapshot, *expected)
		}
		if page.Done {
			if len(page.Rows) != 0 || page.NextRowKey != cursor {
				t.Fatalf("terminal page = %+v, cursor = %q", page, cursor)
			}
			break
		}
		if len(page.Rows) == 0 || len(page.Rows) > request.Limit {
			t.Fatalf("page row count = %d", len(page.Rows))
		}
		if page.NextRowKey != page.Rows[len(page.Rows)-1].RowKey || page.NextRowKey == cursor {
			t.Fatalf("page cursor = %q after %q", page.NextRowKey, cursor)
		}
		for _, row := range page.Rows {
			if row.ProjectionGeneration != expected.Generation ||
				row.ProjectionName != request.ProjectionName ||
				row.RowKey < request.RowKeyStart || row.RowKey >= request.RowKeyEnd ||
				string(row.Payload) != row.RowKey {
				t.Fatalf("out-of-range or corrupt row: %+v", row)
			}
			got = append(got, row.RowKey)
		}
		cursor = page.NextRowKey
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("paged row keys = %v, want %v", got, want)
	}
	if pages != 3 {
		t.Fatalf("page calls = %d, want two data pages plus empty terminal page", pages)
	}
}

func TestProjectionRowPageRejectsGenerationTerminalAndPrivacyRevisionChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *Database)
	}{
		{
			name: "generation replacement",
			mutate: func(t *testing.T, db *Database) {
				tx := db.GORM().Begin()
				if tx.Error != nil {
					t.Fatal(tx.Error)
				}
				replacement := projectionReadModelRow{
					ProjectionGeneration: "replacement",
					ProjectionName:       "attributes",
					RowKey:               "1:a1:z",
					Payload:              []byte("replacement"),
					PayloadPresent:       true,
					UpdatedAt:            time.Now().UTC(),
				}
				if err := tx.Create(&replacement).Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Where("projection_generation = ?", "initial").Delete(&projectionReadModelRow{}).Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").
					Update("active_generation", "replacement").Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Commit().Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "live terminal advance",
			mutate: func(t *testing.T, db *Database) {
				tx := db.GORM().Begin()
				if tx.Error != nil {
					t.Fatal(tx.Error)
				}
				if err := tx.Model(&projectionReadModelRow{}).
					Where("projection_generation = ? AND projection_name = ? AND row_key = ?", "initial", "attributes", "1:a1:z").
					Update("payload", []byte("updated")).Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").
					Update("terminal_position", 1).Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Commit().Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "privacy deletion revision",
			mutate: func(t *testing.T, db *Database) {
				tx := db.GORM().Begin()
				if tx.Error != nil {
					t.Fatal(tx.Error)
				}
				if err := tx.Where("projection_generation = ? AND projection_name = ? AND row_key = ?", "initial", "attributes", "1:a1:z").
					Delete(&projectionReadModelRow{}).Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").
					Update("history_revision", 1).Error; err != nil {
					_ = tx.Rollback().Error
					t.Fatal(err)
				}
				if err := tx.Commit().Error; err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db := projectionTestStore(t)
			defer db.Close()
			insertProjectionPageRows(t, db, "initial", "attributes", []string{"1:a1:x", "1:a1:z"})

			first, err := store.ListProjectionRowsPage(context.Background(), ProjectionPageRequest{
				ProjectionName: "attributes",
				RowKeyPrefix:   "1:a",
				RowKeyStart:    "1:a0",
				RowKeyEnd:      "1:a:",
				Limit:          1,
			})
			if err != nil {
				t.Fatal(err)
			}
			if first.Done || len(first.Rows) != 1 || first.NextRowKey != "1:a1:x" {
				t.Fatalf("first page = %+v", first)
			}

			tc.mutate(t, db)
			next, err := store.ListProjectionRowsPage(context.Background(), ProjectionPageRequest{
				ProjectionName:   "attributes",
				RowKeyPrefix:     "1:a",
				RowKeyStart:      "1:a0",
				RowKeyEnd:        "1:a:",
				AfterRowKey:      first.NextRowKey,
				Limit:            1,
				ExpectedSnapshot: &first.Snapshot,
			})
			if !errors.Is(err, ErrParticipantConflict) {
				t.Fatalf("changed snapshot error = %v", err)
			}
			if len(next.Rows) != 0 || next.NextRowKey != "" || next.Snapshot.Generation != "" || next.Done {
				t.Fatalf("snapshot conflict returned partial page: %+v", next)
			}
		})
	}
}

func TestProjectionRowPageRejectsUnboundedOrUnfencedRequests(t *testing.T) {
	store, db := projectionTestStore(t)
	defer db.Close()

	for _, request := range []ProjectionPageRequest{
		{ProjectionName: "attributes", Limit: 0},
		{ProjectionName: "attributes", Limit: MaxProjectionReadPageRows + 1},
		{ProjectionName: "attributes", RowKeyStart: "1:a0", Limit: 1},
		{ProjectionName: "attributes", RowKeyStart: "1:a:", RowKeyEnd: "1:a0", Limit: 1},
		{ProjectionName: "attributes", AfterRowKey: "cursor", Limit: 1},
	} {
		if page, err := store.ListProjectionRowsPage(context.Background(), request); !errors.Is(err, ErrProjectionInvariant) || len(page.Rows) != 0 {
			t.Fatalf("request %+v returned page %+v, error %v", request, page, err)
		}
	}
}
