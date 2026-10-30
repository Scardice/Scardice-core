package dice

import (
	"encoding/json"
	"path/filepath"
	"testing"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/model"
)

func newOfficialQQMergeTestAttrs(t *testing.T, values map[string]int64) []byte {
	t.Helper()
	vm := &ds.ValueMap{}
	for key, value := range values {
		vm.Store(key, ds.NewIntVal(ds.IntType(value)))
	}
	data, err := ds.NewDictVal(vm).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOfficialQQIdentityMigrationMergesSingleSourceCollisions(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-merge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(operator.Close)
	if err := operator.db.AutoMigrate(&model.AttributesItemModel{}, &model.BanInfo{}); err != nil {
		t.Fatal(err)
	}

	const (
		appID = "123456789"
		uin   = "1"
	)
	oldUserID := "OpenQQ-Member-T:" + appID + "-group-open-id-member-open-id"
	newUserID := "OpenQQ:" + uin + "-member-open-id"
	oldGroupID := "OpenQQ-Group-T:" + appID + "-group-open-id"
	newGroupID := "OpenQQ-Group:" + uin + "-group-open-id"

	if err := operator.db.Create(&model.AttributesItemModel{
		Id: newUserID, AttrsType: "user", Data: newOfficialQQMergeTestAttrs(t, map[string]int64{"shared": 2, "new-only": 2}), CreatedAt: 2, UpdatedAt: 2,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := operator.db.Create(&model.AttributesItemModel{
		Id: oldUserID, AttrsType: "user", Data: newOfficialQQMergeTestAttrs(t, map[string]int64{"shared": 1, "old-only": 1}), CreatedAt: 1, UpdatedAt: 1,
	}).Error; err != nil {
		t.Fatal(err)
	}

	oldBan := &BanListInfoItem{
		ID: oldUserID, Name: "old-name", Score: 5, Rank: BanRankNormal,
		Times: []int64{1}, Reasons: []string{"old-reason"}, Places: []string{oldGroupID}, BanTime: 1,
	}
	oldBanData, err := json.Marshal(oldBan)
	if err != nil {
		t.Fatal(err)
	}
	newBan := &BanListInfoItem{
		ID: newUserID, Name: "new-name", Score: 10, Rank: BanRankBanned,
		Times: []int64{2}, Reasons: []string{"new-reason"}, Places: []string{newGroupID}, BanTime: 2,
		BanUpdatedAt: 2, UpdatedAt: 2,
	}
	newBanData, err := json.Marshal(newBan)
	if err != nil {
		t.Fatal(err)
	}
	if err := operator.db.Create(&model.BanInfo{ID: oldUserID, BanUpdatedAt: 1, UpdatedAt: 1, Data: oldBanData}).Error; err != nil {
		t.Fatal(err)
	}
	if err := operator.db.Create(&model.BanInfo{ID: newUserID, BanUpdatedAt: 2, UpdatedAt: 2, Data: newBanData}).Error; err != nil {
		t.Fatal(err)
	}

	migration := &officialQQIdentityMigration{
		appID:       appID,
		uin:         uin,
		oldEndpoint: "OpenQQ:bot-open-id",
		newEndpoint: "OpenQQ:" + uin,
		groups:      map[string]string{},
		users:       map[string]string{oldUserID: newUserID},
	}
	if err := migration.run(&Dice{DBOperator: operator}); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	var attrs model.AttributesItemModel
	if err := operator.db.Where("id = ?", newUserID).Take(&attrs).Error; err != nil {
		t.Fatalf("merged attrs not found: %v", err)
	}
	var oldCount int64
	if err := operator.db.Model(&model.AttributesItemModel{}).Where("id = ?", oldUserID).Count(&oldCount).Error; err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("old attrs row still exists: %d", oldCount)
	}
	value, err := ds.VMValueFromJSON(attrs.Data)
	if err != nil {
		t.Fatal(err)
	}
	dict, ok := value.ReadDictData()
	if !ok {
		t.Fatal("merged attrs is not a dict")
	}
	for _, key := range []string{"shared", "new-only", "old-only"} {
		if _, exists := dict.Dict.Load(key); !exists {
			t.Fatalf("merged attrs missing key %q", key)
		}
	}
	if shared, _ := dict.Dict.Load("shared"); shared == nil || shared.ToString() != "2" {
		t.Fatalf("merged attrs shared = %v, want newer value 2", shared)
	}

	var bans []model.BanInfo
	if err := operator.db.Where("id = ?", newUserID).Find(&bans).Error; err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("merged ban rows = %d, want 1", len(bans))
	}
	var mergedBan BanListInfoItem
	if err := json.Unmarshal(bans[0].Data, &mergedBan); err != nil {
		t.Fatal(err)
	}
	if mergedBan.Rank != BanRankBanned || mergedBan.Score != 10 || mergedBan.Name != "new-name" {
		t.Fatalf("merged ban = %#v", mergedBan)
	}
	if len(mergedBan.Reasons) != 2 || len(mergedBan.Places) != 1 || len(mergedBan.Times) != 2 {
		t.Fatalf("merged ban did not keep both sides: %#v", mergedBan)
	}
	if mergedBan.Places[0] != newGroupID {
		t.Fatalf("merged ban places = %v, want %s", mergedBan.Places, newGroupID)
	}
	if err := operator.db.Model(&model.BanInfo{}).Where("id = ?", oldUserID).Count(&oldCount).Error; err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("old ban row still exists: %d", oldCount)
	}
}

func TestOfficialQQIdentityMigrationMovesCorruptBanPrimaryKey(t *testing.T) {
	operator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-corrupt-ban.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(operator.Close)
	if err := operator.db.AutoMigrate(&model.BanInfo{}); err != nil {
		t.Fatal(err)
	}

	oldID := "OpenQQ-Member-T:123456789-group-open-id-member-open-id"
	newID := "OpenQQ:1-member-open-id"
	if err := operator.db.Create(&model.BanInfo{ID: oldID, Data: []byte("{")}).Error; err != nil {
		t.Fatal(err)
	}
	migration := &officialQQIdentityMigration{
		appID:       "123456789",
		uin:         "1",
		oldEndpoint: "OpenQQ:bot-open-id",
		newEndpoint: "OpenQQ:1",
		groups:      map[string]string{},
		users:       map[string]string{oldID: newID},
	}
	if err := migration.run(&Dice{DBOperator: operator}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	var count int64
	if err := operator.db.Model(&model.BanInfo{}).Where("id = ?", newID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("corrupt ban was not migrated: count=%d", count)
	}
}

func TestMergeOfficialQQAttrItemsPrefersNewerValues(t *testing.T) {
	target := &AttributesItem{ID: "new", Name: "new-name", LastModifiedTime: 2, valueMap: &ds.ValueMap{}}
	target.valueMap.Store("shared", ds.NewIntVal(2))
	source := &AttributesItem{ID: "old", LastModifiedTime: 1, valueMap: &ds.ValueMap{}}
	source.valueMap.Store("shared", ds.NewIntVal(1))
	source.valueMap.Store("old-only", ds.NewIntVal(1))

	merged := mergeOfficialQQAttrItems(target, source)
	if merged != target {
		t.Fatal("merge did not prefer the newer item")
	}
	if shared, _ := merged.valueMap.Load("shared"); shared == nil || shared.ToString() != "2" {
		t.Fatalf("shared value = %v, want 2", shared)
	}
	if _, exists := merged.valueMap.Load("old-only"); !exists {
		t.Fatal("older-only key was dropped")
	}
	if merged.Name != "new-name" {
		t.Fatalf("name = %q", merged.Name)
	}
}
