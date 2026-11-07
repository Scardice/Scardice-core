package dice

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"Scardice-core/model"
)

func TestOfficialQQIdentityMigrationMergesConflictingPlayerRow(t *testing.T) {
	const (
		appID = "123456789"
		uin   = "1"
	)
	dbOperator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-player-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbOperator.Close)
	db := dbOperator.db
	if err := db.AutoMigrate(&model.GroupInfo{}, &model.GroupPlayerInfoBase{}); err != nil {
		t.Fatal(err)
	}

	oldGroup := "OpenQQ-Group-T:" + appID + "-g"
	newGroup := "OpenQQ-Group:" + uin + "-g"
	oldUser := "OpenQQ-Member-T:" + appID + "-g-m"
	newUser := "OpenQQ:" + uin + "-m"
	oldGroupData, _ := json.Marshal(&GroupInfo{GroupID: oldGroup})
	newGroupData, _ := json.Marshal(&GroupInfo{GroupID: newGroup})
	ts := int64(1)
	if err := db.Create(&[]model.GroupInfo{
		{ID: oldGroup, UpdatedAt: &ts, Data: oldGroupData},
		{ID: newGroup, UpdatedAt: &ts, Data: newGroupData},
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&[]model.GroupPlayerInfoBase{
		{GroupID: oldGroup, UserID: oldUser, Name: "old"},
		{GroupID: newGroup, UserID: newUser, Name: "new"},
	}).Error; err != nil {
		t.Fatal(err)
	}

	m := &officialQQIdentityMigration{
		appID:       appID,
		uin:         uin,
		oldEndpoint: "OpenQQ:legacy",
		newEndpoint: formatDiceIDOfficialQQ(uin),
		groups:      map[string]string{},
		users:       map[string]string{},
	}
	if err := m.collectDatabase(dbOperator); err != nil {
		t.Fatal(err)
	}
	// Both group and player target rows already exist.  fix6 merges them into the
	// canonical row and removes the old duplicates instead of leaving stale rows.
	if err := m.migrateDataDB(dbOperator); err != nil {
		t.Fatalf("migrateDataDB() should merge conflicting player row, got %v", err)
	}

	var oldGroupCount, newGroupCount, oldPlayerCount, newPlayerCount int64
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", oldGroup).Count(&oldGroupCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.GroupInfo{}).Where("id = ?", newGroup).Count(&newGroupCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.GroupPlayerInfoBase{}).Where("group_id = ? AND user_id = ?", oldGroup, oldUser).Count(&oldPlayerCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.GroupPlayerInfoBase{}).Where("group_id = ? AND user_id = ?", newGroup, newUser).Count(&newPlayerCount).Error; err != nil {
		t.Fatal(err)
	}
	if oldGroupCount != 0 || newGroupCount != 1 || oldPlayerCount != 0 || newPlayerCount != 1 {
		t.Fatalf("rows after merge = oldGroup:%d newGroup:%d oldPlayer:%d newPlayer:%d, want 0/1/0/1",
			oldGroupCount, newGroupCount, oldPlayerCount, newPlayerCount)
	}
}

func TestOfficialQQCloseEventQueueInstanceOnlyAffectsOwner(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}
	oldQueue := newOfficialQQEventQueue()
	newQueue := newOfficialQQEventQueue()
	pa.eventQueue = newQueue
	pa.eventQueueAccepting = true

	// An old connection failure must not disable the queue of the session that
	// replaced it.
	pa.closeOfficialQQEventQueueInstance(oldQueue)
	if !pa.eventQueueAccepting {
		t.Fatal("old queue cleanup disabled the current queue")
	}

	pa.closeOfficialQQEventQueueInstance(newQueue)
	if pa.eventQueueAccepting {
		t.Fatal("closing the current queue should stop accepting events")
	}
}
