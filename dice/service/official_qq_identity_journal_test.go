package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"Scardice-core/model"
)

func TestOfficialQQIdentityJournal_CreatePending_persistsMapping(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "identity-journal.db")
	db := openOfficialQQIdentityJournalTestDB(t, dbPath)
	clock := newOfficialQQIdentityJournalTestClock()
	journal := NewOfficialQQIdentityJournal(&mockDBOperator{db: db}, clock.Now)
	requireOfficialQQIdentityJournalInit(t, journal)
	spec := officialQQIdentityJournalTestSpec("group_info", "id", "old-group", "new-group")

	err := journal.CreatePending(context.Background(), []OfficialQQIdentityMappingSpec{spec})

	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	closeOfficialQQIdentityJournalTestDB(t, db)
	db = openOfficialQQIdentityJournalTestDB(t, dbPath)
	journal = NewOfficialQQIdentityJournal(&mockDBOperator{db: db}, clock.Now)
	got, err := journal.Get(context.Background(), spec.Key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.NewID != spec.NewID || got.State != model.OfficialQQIdentityMappingPending {
		t.Fatalf("Get() = new ID %q, state %q", got.NewID, got.State)
	}
	if got.CreatedAt != clock.initial.Unix() || got.UpdatedAt != clock.initial.Unix() || got.Error != "" {
		t.Fatalf("Get() timestamps/error = %d/%d/%q", got.CreatedAt, got.UpdatedAt, got.Error)
	}
}

func TestOfficialQQIdentityJournal_CreatePending_isAtomicWhenMappingConflicts(t *testing.T) {
	db := openOfficialQQIdentityJournalTestDB(t, filepath.Join(t.TempDir(), "identity-journal.db"))
	clock := newOfficialQQIdentityJournalTestClock()
	journal := NewOfficialQQIdentityJournal(&mockDBOperator{db: db}, clock.Now)
	requireOfficialQQIdentityJournalInit(t, journal)
	existing := officialQQIdentityJournalTestSpec("group_info", "id", "old-existing", "new-existing")
	if err := journal.CreatePending(context.Background(), []OfficialQQIdentityMappingSpec{existing}); err != nil {
		t.Fatalf("seed CreatePending() error = %v", err)
	}
	newMapping := officialQQIdentityJournalTestSpec("log_items", "group_id", "old-new", "new-new")

	err := journal.CreatePending(context.Background(), []OfficialQQIdentityMappingSpec{newMapping, existing})

	if err == nil {
		t.Fatal("CreatePending() error = nil, want unique-key conflict")
	}
	var count int64
	if countErr := db.Model(&model.OfficialQQIdentityMapping{}).Where("old_id = ?", newMapping.Key.OldID).Count(&count).Error; countErr != nil {
		t.Fatalf("count rolled-back mapping: %v", countErr)
	}
	if count != 0 {
		t.Fatalf("rolled-back mapping count = %d, want 0", count)
	}
}

func TestOfficialQQIdentityJournal_Transition_appliesPendingMapping(t *testing.T) {
	journal, clock, spec := newOfficialQQIdentityJournalTestFixture(t)
	clock.Advance(time.Minute)

	err := journal.Transition(context.Background(), OfficialQQIdentityMappingTransition{Key: spec.Key, State: model.OfficialQQIdentityMappingApplied})

	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	got, err := journal.Get(context.Background(), spec.Key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.State != model.OfficialQQIdentityMappingApplied || got.UpdatedAt != clock.Now().Unix() || got.Error != "" {
		t.Fatalf("Get() state/timestamp/error = %q/%d/%q", got.State, got.UpdatedAt, got.Error)
	}
	if err := journal.Transition(context.Background(), OfficialQQIdentityMappingTransition{Key: spec.Key, State: model.OfficialQQIdentityMappingBlocked, Error: "late collision"}); !errors.Is(err, ErrOfficialQQIdentityMappingTransition) {
		t.Fatalf("terminal Transition() error = %v", err)
	}
}

func TestOfficialQQIdentityJournal_Transition_blocksAndRequeuesMapping(t *testing.T) {
	journal, clock, spec := newOfficialQQIdentityJournalTestFixture(t)
	clock.Advance(time.Minute)

	err := journal.Transition(context.Background(), OfficialQQIdentityMappingTransition{Key: spec.Key, State: model.OfficialQQIdentityMappingBlocked, Error: "target exists"})

	if err != nil {
		t.Fatalf("blocked Transition() error = %v", err)
	}
	blocked, err := journal.Get(context.Background(), spec.Key)
	if err != nil {
		t.Fatalf("blocked Get() error = %v", err)
	}
	if blocked.State != model.OfficialQQIdentityMappingBlocked || blocked.Error != "target exists" || blocked.UpdatedAt != clock.Now().Unix() {
		t.Fatalf("blocked mapping = state %q, error %q, updated %d", blocked.State, blocked.Error, blocked.UpdatedAt)
	}
	clock.Advance(time.Minute)
	if err = journal.Transition(context.Background(), OfficialQQIdentityMappingTransition{Key: spec.Key, State: model.OfficialQQIdentityMappingPending}); err != nil {
		t.Fatalf("pending Transition() error = %v", err)
	}
	pending, err := journal.Get(context.Background(), spec.Key)
	if err != nil {
		t.Fatalf("pending Get() error = %v", err)
	}
	if pending.State != model.OfficialQQIdentityMappingPending || pending.Error != "" || pending.UpdatedAt != clock.Now().Unix() {
		t.Fatalf("pending mapping = state %q, error %q, updated %d", pending.State, pending.Error, pending.UpdatedAt)
	}
}

type officialQQIdentityJournalTestClock struct {
	initial time.Time
	current time.Time
}

func newOfficialQQIdentityJournalTestClock() *officialQQIdentityJournalTestClock {
	initial := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	return &officialQQIdentityJournalTestClock{initial: initial, current: initial}
}

func (c *officialQQIdentityJournalTestClock) Now() time.Time { return c.current }

func (c *officialQQIdentityJournalTestClock) Advance(duration time.Duration) {
	c.current = c.current.Add(duration)
}

func newOfficialQQIdentityJournalTestFixture(t *testing.T) (*OfficialQQIdentityJournal, *officialQQIdentityJournalTestClock, OfficialQQIdentityMappingSpec) {
	t.Helper()
	db := openOfficialQQIdentityJournalTestDB(t, filepath.Join(t.TempDir(), "identity-journal.db"))
	clock := newOfficialQQIdentityJournalTestClock()
	journal := NewOfficialQQIdentityJournal(&mockDBOperator{db: db}, clock.Now)
	requireOfficialQQIdentityJournalInit(t, journal)
	spec := officialQQIdentityJournalTestSpec("attrs", "id", "old-user", "new-user")
	if err := journal.CreatePending(context.Background(), []OfficialQQIdentityMappingSpec{spec}); err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	return journal, clock, spec
}

func officialQQIdentityJournalTestSpec(store, keyspace, oldID, newID string) OfficialQQIdentityMappingSpec {
	return OfficialQQIdentityMappingSpec{
		Key: OfficialQQIdentityMappingKey{
			MigrationID: "official-qq-appid-to-uin-v1",
			Account:     "123456789",
			Store:       store,
			Keyspace:    keyspace,
			OldID:       oldID,
		},
		NewID: newID,
	}
}

func openOfficialQQIdentityJournalTestDB(t *testing.T, path string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open temp journal: %v", err)
	}
	return db
}

func closeOfficialQQIdentityJournalTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get temp journal DB: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close temp journal DB: %v", err)
	}
}

func requireOfficialQQIdentityJournalInit(t *testing.T, journal *OfficialQQIdentityJournal) {
	t.Helper()
	if err := journal.Init(context.Background()); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
}
