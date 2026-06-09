package service

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"Scardice-core/model"
)

func TestGroupLocalDataDeleteServices(t *testing.T) {
	dsn := fmt.Sprintf("file:group_local_data_delete_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}

	migrateErr := db.AutoMigrate(&model.GroupInfo{}, &model.GroupPlayerInfoBase{}, &model.AttributesItemModel{})
	if migrateErr != nil {
		t.Fatalf("auto migrate failed: %v", migrateErr)
	}

	op := &mockDBOperator{db: db}
	targetGroupID := "QQ-Group:10_%"
	otherGroupID := "QQ-Group:10A%"
	now := int64(123)

	createErr := db.Create(&model.GroupInfo{ID: targetGroupID, UpdatedAt: &now, Data: []byte("{}")}).Error
	if createErr != nil {
		t.Fatalf("insert target group failed: %v", createErr)
	}
	createErr = db.Create(&model.GroupInfo{ID: otherGroupID, UpdatedAt: &now, Data: []byte("{}")}).Error
	if createErr != nil {
		t.Fatalf("insert other group failed: %v", createErr)
	}
	createErr = db.Create(&model.GroupPlayerInfoBase{GroupID: targetGroupID, UserID: "QQ:1"}).Error
	if createErr != nil {
		t.Fatalf("insert target player 1 failed: %v", createErr)
	}
	createErr = db.Create(&model.GroupPlayerInfoBase{GroupID: targetGroupID, UserID: "QQ:2"}).Error
	if createErr != nil {
		t.Fatalf("insert target player 2 failed: %v", createErr)
	}
	createErr = db.Create(&model.GroupPlayerInfoBase{GroupID: otherGroupID, UserID: "QQ:3"}).Error
	if createErr != nil {
		t.Fatalf("insert other player failed: %v", createErr)
	}

	attrs := []*model.AttributesItemModel{
		{Id: targetGroupID, AttrsType: AttrsTypeGroup, Data: []byte("{}")},
		{Id: targetGroupID + "-QQ:1", AttrsType: "", Data: []byte("{}")},
		{Id: targetGroupID + "-QQ:2", AttrsType: AttrsTypeGroupUser, Data: []byte("{}")},
		{Id: otherGroupID, AttrsType: AttrsTypeGroup, Data: []byte("{}")},
		{Id: otherGroupID + "-QQ:3", AttrsType: AttrsTypeGroupUser, Data: []byte("{}")},
	}
	for _, attr := range attrs {
		createErr = db.Create(attr).Error
		if createErr != nil {
			t.Fatalf("insert attr %s failed: %v", attr.Id, createErr)
		}
	}

	groupRows, err := GroupInfoDelete(op, targetGroupID)
	if err != nil {
		t.Fatalf("delete group info failed: %v", err)
	}
	if groupRows != 1 {
		t.Fatalf("expected 1 deleted group row, got %d", groupRows)
	}

	playerRows, err := GroupPlayerInfoDeleteByGroup(op, targetGroupID)
	if err != nil {
		t.Fatalf("delete group players failed: %v", err)
	}
	if playerRows != 2 {
		t.Fatalf("expected 2 deleted player rows, got %d", playerRows)
	}

	groupAttrRows, groupUserAttrRows, err := AttrsDeleteByGroupScope(op, targetGroupID)
	if err != nil {
		t.Fatalf("delete group attrs failed: %v", err)
	}
	if groupAttrRows != 1 {
		t.Fatalf("expected 1 deleted group attr row, got %d", groupAttrRows)
	}
	if groupUserAttrRows != 2 {
		t.Fatalf("expected 2 deleted group-user attr rows, got %d", groupUserAttrRows)
	}

	assertCount(t, db, &model.GroupInfo{}, "id = ?", []any{targetGroupID}, 0)
	assertCount(t, db, &model.GroupInfo{}, "id = ?", []any{otherGroupID}, 1)
	assertCount(t, db, &model.GroupPlayerInfoBase{}, "group_id = ?", []any{targetGroupID}, 0)
	assertCount(t, db, &model.GroupPlayerInfoBase{}, "group_id = ?", []any{otherGroupID}, 1)
	assertCount(t, db, &model.AttributesItemModel{}, "id = ?", []any{targetGroupID}, 0)
	assertCount(t, db, &model.AttributesItemModel{}, "id = ?", []any{targetGroupID + "-QQ:1"}, 0)
	assertCount(t, db, &model.AttributesItemModel{}, "id = ?", []any{targetGroupID + "-QQ:2"}, 0)
	assertCount(t, db, &model.AttributesItemModel{}, "id = ?", []any{otherGroupID}, 1)
	assertCount(t, db, &model.AttributesItemModel{}, "id = ?", []any{otherGroupID + "-QQ:3"}, 1)
}

func assertCount(t *testing.T, db *gorm.DB, modelValue any, query string, args []any, want int64) {
	t.Helper()

	var count int64
	if err := db.Model(modelValue).Where(query, args...).Count(&count).Error; err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != want {
		t.Fatalf("expected count %d for query %q, got %d", want, query, count)
	}
}
