package service

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/model"
)

func TestOfficialQQIdentityJournal_CreatePending_rejectsManualTemporaryMapping(t *testing.T) {
	_, journal, _ := newOfficialQQIdentityMigratorTestFixture(t)
	spec := OfficialQQIdentityMappingSpec{
		Key: OfficialQQIdentityMappingKey{
			MigrationID: OfficialQQExplicitIdentityMigrationID,
			Account:     "123456789",
			Store:       OfficialQQIdentityStoreGroupInfo,
			Keyspace:    OfficialQQIdentityKeyspaceID,
			OldID:       "OpenQQ-Group-T:123456789-group-open-id",
		},
		NewID: "OpenQQ-Group:1-group-open-id",
	}

	err := journal.CreatePending(context.Background(), []OfficialQQIdentityMappingSpec{spec})

	if !errors.Is(err, ErrOfficialQQIdentityMappingUnverified) {
		t.Fatalf("CreatePending() error = %v, want unverified mapping", err)
	}
}

func TestOfficialQQIdentityMigrator_MigrateVerifiedSource_defersTemporaryIDsWithoutUIN(t *testing.T) {
	db, _, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	seedOfficialQQIdentityMigrationTestGroup(t, db, "OpenQQ-Group-T:123456789-group-open-id", "source")
	source := OfficialQQVerifiedIdentitySource{
		AppID:  123456789,
		Groups: []OfficialQQGroupIdentitySource{{GroupOpenID: "group-open-id"}},
	}

	result, err := migrator.MigrateVerifiedSource(context.Background(), source, 10)

	if err != nil {
		t.Fatalf("MigrateVerifiedSource() error = %v", err)
	}
	if !result.Deferred || result.Declared != 0 || result.Processed != 0 {
		t.Fatalf("MigrateVerifiedSource() result = %#v, want deferred no-op", result)
	}
	var mappings int64
	if err := db.Model(&model.OfficialQQIdentityMapping{}).Count(&mappings).Error; err != nil {
		t.Fatalf("count mappings: %v", err)
	}
	if mappings != 0 {
		t.Fatalf("mapping count = %d, want 0", mappings)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, "OpenQQ-Group-T:123456789-group-open-id", "source")
	requireOfficialQQIdentityMigrationTestMissingGroup(t, db, "OpenQQ-Group:1-group-open-id")
}

func TestOfficialQQIdentityMigrator_MigrateVerifiedSource_generatesAndAppliesSourceMappings(t *testing.T) {
	db, journal, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	const oldGroupID = "OpenQQ-Group-T:123456789-group-open-id"
	const newGroupID = "OpenQQ-Group:1-group-open-id"
	seedOfficialQQIdentityMigrationTestGroup(t, db, oldGroupID, "source")
	source := OfficialQQVerifiedIdentitySource{
		AppID:       123456789,
		VerifiedUIN: "1",
		Groups: []OfficialQQGroupIdentitySource{{
			GroupOpenID:   "group-open-id",
			MemberOpenIDs: []string{"member-open-id"},
		}},
	}

	result, err := migrator.MigrateVerifiedSource(context.Background(), source, 10)

	if err != nil {
		t.Fatalf("MigrateVerifiedSource() error = %v", err)
	}
	if result.Deferred || result.Declared != 2 || result.Processed != 2 {
		t.Fatalf("MigrateVerifiedSource() result = %#v", result)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, oldGroupID, "source")
	requireOfficialQQIdentityMigrationTestGroup(t, db, newGroupID, "source")
	groupMapping, err := journal.Get(context.Background(), OfficialQQIdentityMappingKey{
		MigrationID: OfficialQQExplicitIdentityMigrationID,
		Account:     "123456789",
		Store:       OfficialQQIdentityStoreGroupInfo,
		Keyspace:    OfficialQQIdentityKeyspaceID,
		OldID:       oldGroupID,
	})
	if err != nil {
		t.Fatalf("get group mapping: %v", err)
	}
	if groupMapping.NewID != newGroupID || groupMapping.SourceHash != "bb8e1496" || groupMapping.State != model.OfficialQQIdentityMappingApplied {
		t.Fatalf("group mapping = %#v", groupMapping)
	}
	delegateMapping, err := journal.Get(context.Background(), OfficialQQIdentityMappingKey{
		MigrationID: OfficialQQExplicitIdentityMigrationID,
		Account:     "123456789",
		Store:       OfficialQQIdentityStoreDelegate,
		Keyspace:    OfficialQQIdentityKeyspacePlayerUserID,
		OldID:       "OpenQQ:member-open-id",
	})
	if err != nil {
		t.Fatalf("get delegate mapping: %v", err)
	}
	if delegateMapping.NewID != "OpenQQ:1-member-open-id" || delegateMapping.SourceHash != "f3c16a62" || delegateMapping.State != model.OfficialQQIdentityMappingApplied {
		t.Fatalf("delegate mapping = %#v", delegateMapping)
	}
}

func TestOfficialQQIdentityMigrator_MigrateVerifiedSource_retainsHashesWhenBlockedAndPending(t *testing.T) {
	db, journal, migrator := newOfficialQQIdentityMigratorTestFixture(t)
	const oldGroupID = "OpenQQ-Group-T:123456789-group-open-id"
	const newGroupID = "OpenQQ-Group:1-group-open-id"
	seedOfficialQQIdentityMigrationTestGroup(t, db, oldGroupID, "source")
	seedOfficialQQIdentityMigrationTestGroup(t, db, newGroupID, "target")
	source := OfficialQQVerifiedIdentitySource{
		AppID:       123456789,
		VerifiedUIN: "1",
		Groups: []OfficialQQGroupIdentitySource{{
			GroupOpenID:   "group-open-id",
			MemberOpenIDs: []string{"member-open-id"},
		}},
	}

	result, err := migrator.MigrateVerifiedSource(context.Background(), source, 1)

	if err != nil || result.Declared != 2 || result.Processed != 1 {
		t.Fatalf("MigrateVerifiedSource() = %#v, %v", result, err)
	}
	blocked, err := journal.Get(context.Background(), OfficialQQIdentityMappingKey{
		MigrationID: OfficialQQExplicitIdentityMigrationID,
		Account:     "123456789",
		Store:       OfficialQQIdentityStoreGroupInfo,
		Keyspace:    OfficialQQIdentityKeyspaceID,
		OldID:       oldGroupID,
	})
	if err != nil {
		t.Fatalf("get blocked mapping: %v", err)
	}
	if blocked.State != model.OfficialQQIdentityMappingBlocked || blocked.SourceHash != "bb8e1496" {
		t.Fatalf("blocked mapping = %#v", blocked)
	}
	pending, err := journal.Get(context.Background(), OfficialQQIdentityMappingKey{
		MigrationID: OfficialQQExplicitIdentityMigrationID,
		Account:     "123456789",
		Store:       OfficialQQIdentityStoreDelegate,
		Keyspace:    OfficialQQIdentityKeyspacePlayerUserID,
		OldID:       "OpenQQ:member-open-id",
	})
	if err != nil {
		t.Fatalf("get pending mapping: %v", err)
	}
	if pending.State != model.OfficialQQIdentityMappingPending || pending.SourceHash != "f3c16a62" {
		t.Fatalf("pending mapping = %#v", pending)
	}
	requireOfficialQQIdentityMigrationTestGroup(t, db, oldGroupID, "source")
	requireOfficialQQIdentityMigrationTestGroup(t, db, newGroupID, "target")
}
