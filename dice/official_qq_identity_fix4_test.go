package dice

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"Scardice-core/model"
)

func TestOfficialQQIdentityMigrationMergesConflictingGroupRow(t *testing.T) {
	const (
		appID = "123456789"
		uin   = "1"
	)
	dbOperator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbOperator.Close)
	db := dbOperator.db
	if err := db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatal(err)
	}

	makeGroup := func(id string) model.GroupInfo {
		data, marshalErr := json.Marshal(&GroupInfo{GroupID: id})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		timestamp := int64(1)
		return model.GroupInfo{ID: id, UpdatedAt: &timestamp, Data: data}
	}
	conflictOldID := "OpenQQ-Group-T:" + appID + "-conflict"
	conflictNewID := "OpenQQ-Group:" + uin + "-conflict"
	cleanOldID := "OpenQQ-Group-T:" + appID + "-clean"
	cleanNewID := "OpenQQ-Group:" + uin + "-clean"

	if err := db.Create(&[]model.GroupInfo{
		makeGroup(conflictOldID),
		makeGroup(conflictNewID),
		makeGroup(cleanOldID),
	}).Error; err != nil {
		t.Fatal(err)
	}

	migration := &officialQQIdentityMigration{
		appID:       appID,
		uin:         uin,
		oldEndpoint: "OpenQQ:legacy-bot",
		newEndpoint: formatDiceIDOfficialQQ(uin),
		groups:      map[string]string{},
		users:       map[string]string{},
	}
	if err := migration.collectDatabase(dbOperator); err != nil {
		t.Fatalf("collectDatabase() error = %v", err)
	}
	if err := migration.migrateDataDB(dbOperator); err != nil {
		t.Fatalf("migrateDataDB() should merge a single conflict, got %v", err)
	}

	var oldConflict, newConflict, oldClean, newClean int64
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", conflictOldID).Count(&oldConflict).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", conflictNewID).Count(&newConflict).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", cleanOldID).Count(&oldClean).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", cleanNewID).Count(&newClean).Error; err != nil {
		t.Fatal(err)
	}
	if oldConflict != 0 || newConflict != 1 {
		t.Fatalf("conflict row state old/new = %d/%d, want 0/1 (merge into target)", oldConflict, newConflict)
	}
	if oldClean != 0 || newClean != 1 {
		t.Fatalf("clean row state old/new = %d/%d, want 0/1 (must still migrate)", oldClean, newClean)
	}
}
