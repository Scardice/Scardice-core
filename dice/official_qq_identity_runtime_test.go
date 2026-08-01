package dice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/dice/service"
	"Scardice-core/model"
)

func TestOfficialQQIdentityRuntime_defersTemporaryGroupsWithoutVerifiedUIN(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-runtime.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator() error = %v", err)
	}
	t.Cleanup(operator.Close)
	if err := operator.db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatalf("migrate group_info: %v", err)
	}
	const oldGroupID = "OpenQQ-Group-T:123456789-group-open-id"
	updatedAt := int64(1)
	if err := operator.db.Create(&model.GroupInfo{ID: oldGroupID, CreatedAt: 1, UpdatedAt: &updatedAt, Data: []byte("source")}).Error; err != nil {
		t.Fatalf("seed group_info: %v", err)
	}
	groups := new(SyncMap[string, *GroupInfo])
	groups.Store(oldGroupID, &GroupInfo{GroupID: oldGroupID})
	d := &Dice{DBOperator: operator, ImSession: &IMSession{ServiceAtNew: groups}}
	adapter := &PlatformAdapterOfficialQQ{AppID: 123456789}

	result, err := adapter.migrateVerifiedIdentityAfterMe(context.Background(), d, &dto.User{})

	if err != nil {
		t.Fatalf("migrateVerifiedIdentityAfterMe() error = %v", err)
	}
	if !result.Deferred || result.Declared != 0 || result.Processed != 0 {
		t.Fatalf("migrateVerifiedIdentityAfterMe() result = %#v", result)
	}
	if operator.db.Migrator().HasTable(&model.OfficialQQIdentityMapping{}) {
		t.Fatal("missing verified UIN created an identity journal table")
	}
	var targetCount int64
	if err := operator.db.Model(&model.GroupInfo{}).Where("id = ?", "OpenQQ-Group:1-group-open-id").Count(&targetCount).Error; err != nil {
		t.Fatalf("count target group: %v", err)
	}
	if targetCount != 0 {
		t.Fatalf("target group count = %d, want 0", targetCount)
	}
}

func TestOfficialQQIdentityRuntime_appliesCurrentSourcesAfterSDKIdentityAvailable(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-runtime.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator() error = %v", err)
	}
	t.Cleanup(operator.Close)
	if err := operator.db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatalf("migrate group_info: %v", err)
	}
	const groupOpenID = "group-open-id"
	const memberOpenID = "member-open-id"
	oldGroupID := formatDiceIDOfficialQQGroupOpenID("123456789", groupOpenID)
	newGroupID := "OpenQQ-Group:1-" + groupOpenID
	oldMemberID := formatDiceIDOfficialQQMemberOpenID("123456789", groupOpenID, memberOpenID)
	updatedAt := int64(1)
	if err := operator.db.Create(&model.GroupInfo{ID: oldGroupID, CreatedAt: 1, UpdatedAt: &updatedAt, Data: []byte("source")}).Error; err != nil {
		t.Fatalf("seed group_info: %v", err)
	}
	players := new(SyncMap[string, *GroupPlayerInfo])
	players.Store(oldMemberID, &GroupPlayerInfo{UserID: oldMemberID})
	groups := new(SyncMap[string, *GroupInfo])
	groups.Store(oldGroupID, &GroupInfo{GroupID: oldGroupID, Players: players})
	d := &Dice{DBOperator: operator, ImSession: &IMSession{ServiceAtNew: groups}}
	adapter := &PlatformAdapterOfficialQQ{AppID: 123456789}

	result, err := adapter.migrateVerifiedIdentityAfterMe(context.Background(), d, &dto.User{ID: "1"})

	if err != nil {
		t.Fatalf("migrateVerifiedIdentityAfterMe() error = %v", err)
	}
	if result.Deferred || result.Declared != 2 || result.Processed != 2 {
		t.Fatalf("migrateVerifiedIdentityAfterMe() result = %#v", result)
	}
	var sourceRow model.GroupInfo
	if err := operator.db.Where("id = ?", oldGroupID).Take(&sourceRow).Error; err != nil || string(sourceRow.Data) != "source" {
		t.Fatalf("source group = %#v, %v", sourceRow, err)
	}
	var targetRow model.GroupInfo
	if err := operator.db.Where("id = ?", newGroupID).Take(&targetRow).Error; err != nil || string(targetRow.Data) != "source" {
		t.Fatalf("target group = %#v, %v", targetRow, err)
	}
	journal := service.NewOfficialQQIdentityJournal(operator, time.Now)
	delegate, err := journal.Get(context.Background(), service.OfficialQQIdentityMappingKey{
		MigrationID: service.OfficialQQExplicitIdentityMigrationID,
		Account:     "123456789",
		Store:       service.OfficialQQIdentityStoreDelegate,
		Keyspace:    service.OfficialQQIdentityKeyspacePlayerUserID,
		OldID:       "OpenQQ:" + memberOpenID,
	})
	if err != nil {
		t.Fatalf("get delegate mapping: %v", err)
	}
	if delegate.SourceHash != "f3c16a62" || delegate.State != model.OfficialQQIdentityMappingApplied {
		t.Fatalf("delegate mapping = %#v", delegate)
	}
}
