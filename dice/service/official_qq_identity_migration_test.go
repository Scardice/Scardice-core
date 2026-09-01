//go:build cgo

package service

import (
	"context"
	"path/filepath"
	"testing"

	"gorm.io/gorm"

	"Scardice-core/model"
)

func TestOfficialQQIdentityMigrator_ApplyPending_copiesSourceAndAppliesMapping(t *testing.T) {
	db, journal, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	const oldID = "OpenQQ-Group-T:123456789-group-open-id"
	const newID = "OpenQQ-Group:1-group-open-id"
	seedOfficialQQIdentityMigrationTestGroup(t, db, oldID, "source")
	source := officialQQIdentityMigrationTestSource(123456789, "1", "group-open-id")

	result, err := migrator.MigrateVerifiedSource(context.Background(), source, 10)

	if err != nil {
		t.Fatalf("MigrateVerifiedSource() error = %v", err)
	}
	if result.Processed != 1 {
		t.Fatalf("MigrateVerifiedSource() processed = %d, want 1", result.Processed)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, oldID, "source")
	requireOfficialQQIdentityMigrationTestGroup(t, db, newID, "source")
	mapping, err := journal.Get(context.Background(), officialQQIdentityMigrationTestGroupKey("123456789", oldID))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if mapping.State != model.OfficialQQIdentityMappingApplied {
		t.Fatalf("mapping state = %q, want applied", mapping.State)
	}
}

func TestOfficialQQIdentityMigrator_ApplyPending_resumesBoundedBatch(t *testing.T) {
	db, _, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	const firstOldID = "OpenQQ-Group-T:123456789-group-one"
	const firstNewID = "OpenQQ-Group:1-group-one"
	const secondOldID = "OpenQQ-Group-T:123456789-group-two"
	const secondNewID = "OpenQQ-Group:1-group-two"
	seedOfficialQQIdentityMigrationTestGroup(t, db, firstOldID, "one")
	seedOfficialQQIdentityMigrationTestGroup(t, db, secondOldID, "two")
	source := officialQQIdentityMigrationTestSource(123456789, "1", "group-one", "group-two")

	result, err := migrator.MigrateVerifiedSource(context.Background(), source, 1)
	if err != nil || result.Processed != 1 || result.Declared != 2 {
		t.Fatalf("first MigrateVerifiedSource() = %#v, %v", result, err)
	}
	result, err = migrator.MigrateVerifiedSource(context.Background(), source, 1)
	if err != nil || result.Processed != 1 || result.Declared != 0 {
		t.Fatalf("resumed MigrateVerifiedSource() = %#v, %v", result, err)
	}
	result, err = migrator.MigrateVerifiedSource(context.Background(), source, 1)
	if err != nil || result.Processed != 0 || result.Declared != 0 {
		t.Fatalf("completed MigrateVerifiedSource() = %#v, %v", result, err)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, firstOldID, "one")
	requireOfficialQQIdentityMigrationTestGroup(t, db, firstNewID, "one")
	requireOfficialQQIdentityMigrationTestGroup(t, db, secondOldID, "two")
	requireOfficialQQIdentityMigrationTestGroup(t, db, secondNewID, "two")
}

func TestOfficialQQIdentityMigrator_ApplyPending_blocksCollisionWithoutMutation(t *testing.T) {
	db, journal, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	const oldID = "OpenQQ-Group-T:123456789-group-open-id"
	const newID = "OpenQQ-Group:1-group-open-id"
	seedOfficialQQIdentityMigrationTestGroup(t, db, oldID, "source")
	seedOfficialQQIdentityMigrationTestGroup(t, db, newID, "target")
	source := officialQQIdentityMigrationTestSource(123456789, "1", "group-open-id")

	result, err := migrator.MigrateVerifiedSource(context.Background(), source, 10)

	if err != nil || result.Processed != 1 {
		t.Fatalf("MigrateVerifiedSource() = %#v, %v", result, err)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, oldID, "source")
	requireOfficialQQIdentityMigrationTestGroup(t, db, newID, "target")
	mapping, err := journal.Get(context.Background(), officialQQIdentityMigrationTestGroupKey("123456789", oldID))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if mapping.State != model.OfficialQQIdentityMappingBlocked || mapping.Error == "" {
		t.Fatalf("collision mapping = state %q, error %q", mapping.State, mapping.Error)
	}
}

func TestOfficialQQIdentityMigrator_ApplyPending_keepsAccountsIndependent(t *testing.T) {
	db, journal, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	const accountAOldID = "OpenQQ-Group-T:123456789-group-a"
	const accountANewID = "OpenQQ-Group:1-group-a"
	const accountBPendingOldID = "OpenQQ-Group-T:987654321-group-b-two"
	const accountBPendingNewID = "OpenQQ-Group:2-group-b-two"
	seedOfficialQQIdentityMigrationTestGroup(t, db, accountAOldID, "a")
	seedOfficialQQIdentityMigrationTestGroup(t, db, "OpenQQ-Group-T:987654321-group-b-one", "b-one")
	seedOfficialQQIdentityMigrationTestGroup(t, db, accountBPendingOldID, "b-two")
	accountBSource := officialQQIdentityMigrationTestSource(987654321, "2", "group-b-one", "group-b-two")
	if result, err := migrator.MigrateVerifiedSource(context.Background(), accountBSource, 1); err != nil || result.Processed != 1 {
		t.Fatalf("prepare account B = %#v, %v", result, err)
	}
	accountASource := officialQQIdentityMigrationTestSource(123456789, "1", "group-a")

	result, err := migrator.MigrateVerifiedSource(context.Background(), accountASource, 10)

	if err != nil || result.Processed != 1 {
		t.Fatalf("MigrateVerifiedSource() = %#v, %v", result, err)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, accountANewID, "a")
	requireOfficialQQIdentityMigrationTestMissingGroup(t, db, accountBPendingNewID)
	mapping, err := journal.Get(context.Background(), officialQQIdentityMigrationTestGroupKey("987654321", accountBPendingOldID))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if mapping.State != model.OfficialQQIdentityMappingPending {
		t.Fatalf("account B state = %q, want pending", mapping.State)
	}
}

func newOfficialQQIdentityMigratorTestFixture(t *testing.T) (*gorm.DB, *OfficialQQIdentityJournal, *OfficialQQIdentityMigrator) {
	t.Helper()
	db := openOfficialQQIdentityJournalTestDB(t, filepath.Join(t.TempDir(), "identity-migration.db"))
	if err := db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatalf("migrate group_info: %v", err)
	}
	clock := newOfficialQQIdentityJournalTestClock()
	journal := NewOfficialQQIdentityJournal(&mockDBOperator{db: db}, clock.Now)
	requireOfficialQQIdentityJournalInit(t, journal)
	return db, journal, NewOfficialQQIdentityMigrator(&mockDBOperator{db: db}, clock.Now)
}

func officialQQIdentityMigrationTestSource(appID uint64, uin string, groupOpenIDs ...string) OfficialQQVerifiedIdentitySource {
	groups := make([]OfficialQQGroupIdentitySource, len(groupOpenIDs))
	for index, groupOpenID := range groupOpenIDs {
		groups[index] = OfficialQQGroupIdentitySource{GroupOpenID: groupOpenID}
	}
	return OfficialQQVerifiedIdentitySource{AppID: appID, VerifiedUIN: uin, Groups: groups}
}

func officialQQIdentityMigrationTestGroupKey(account, oldID string) OfficialQQIdentityMappingKey {
	return OfficialQQIdentityMappingKey{
		MigrationID: OfficialQQExplicitIdentityMigrationID,
		Account:     account,
		Store:       OfficialQQIdentityStoreGroupInfo,
		Keyspace:    OfficialQQIdentityKeyspaceID,
		OldID:       oldID,
	}
}

func seedOfficialQQIdentityMigrationTestGroup(t *testing.T, db *gorm.DB, id, data string) {
	t.Helper()
	updatedAt := int64(2)
	if err := db.Create(&model.GroupInfo{ID: id, CreatedAt: 1, UpdatedAt: &updatedAt, Data: []byte(data)}).Error; err != nil {
		t.Fatalf("seed group %q: %v", id, err)
	}
}

func requireOfficialQQIdentityMigrationTestGroup(t *testing.T, db *gorm.DB, id, data string) {
	t.Helper()
	var row model.GroupInfo
	if err := db.Where("id = ?", id).Take(&row).Error; err != nil {
		t.Fatalf("read group %q: %v", id, err)
	}
	if string(row.Data) != data {
		t.Fatalf("group %q data = %q, want %q", id, row.Data, data)
	}
}

func requireOfficialQQIdentityMigrationTestMissingGroup(t *testing.T, db *gorm.DB, id string) {
	t.Helper()
	var count int64
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", id).Count(&count).Error; err != nil {
		t.Fatalf("count group %q: %v", id, err)
	}
	if count != 0 {
		t.Fatalf("group %q count = %d, want 0", id, count)
	}
}
