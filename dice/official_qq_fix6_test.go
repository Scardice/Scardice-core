package dice

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/model"
)

// fix6：冲突保留旧行时，旧群组对象不能覆盖规范 ID 下的新群组对象。
func TestOfficialQQMemoryGroupMergeKeepsNewGroup(t *testing.T) {
	const (
		appID = "app"
		uin   = "1"
	)
	oldID := "OpenQQ-Group-T:" + appID + "-g"
	newID := "OpenQQ-Group:" + uin + "-g"
	oldUser := "OpenQQ-Member-T:" + appID + "-g-m"
	newUser := "OpenQQ:" + uin + "-m"
	oldUser2 := "OpenQQ-Member-T:" + appID + "-g-m2"
	newUser2 := "OpenQQ:" + uin + "-m2"

	newGroup := &GroupInfo{GroupID: newID, GroupName: "new-name", EnteredTime: 200}
	newGroup.DiceIDActiveMap = new(SyncMap[string, bool])
	newGroup.DiceIDExistsMap = new(SyncMap[string, bool])
	newGroup.BotList = new(SyncMap[string, bool])
	newGroup.Players = new(SyncMap[string, *GroupPlayerInfo])
	newGroup.Players.Store(newUser, &GroupPlayerInfo{UserID: newUser, GroupID: newID, Name: "new-player", LastCommandTime: 200})
	newGroup.PlayerGroups = new(SyncMap[string, []string])
	newGroup.PlayerGroups.Store("team", []string{newUser})

	oldGroup := &GroupInfo{
		GroupID:             oldID,
		GroupName:           "old-name",
		EnteredTime:         100,
		Active:              true,
		ShowGroupWelcome:    true,
		GroupWelcomeMessage: "欢迎",
		CocRuleIndex:        2,
		HelpPackages:        []string{"coc7"},
		LogOn:               true,
		LogCurName:          "old-log",
		LogCurID:            42,
	}
	oldGroup.DiceIDActiveMap = new(SyncMap[string, bool])
	oldGroup.DiceIDExistsMap = new(SyncMap[string, bool])
	oldGroup.BotList = new(SyncMap[string, bool])
	oldGroup.Players = new(SyncMap[string, *GroupPlayerInfo])
	oldGroup.Players.Store(oldUser, &GroupPlayerInfo{UserID: oldUser, GroupID: oldID, Name: "old-player", LastCommandTime: 100})
	oldGroup.Players.Store(oldUser2, &GroupPlayerInfo{UserID: oldUser2, GroupID: oldID, Name: "old-player-2", LastCommandTime: 100})
	oldGroup.PlayerGroups = new(SyncMap[string, []string])
	oldGroup.PlayerGroups.Store(oldUser, []string{oldID})
	oldGroup.PlayerGroups.Store("team", []string{oldUser2})

	d := &Dice{
		ImSession: &IMSession{
			ServiceAtNew: new(SyncMap[string, *GroupInfo]),
			PendingQuits: new(SyncMap[string, *PendingQuitInfo]),
		},
		DirtyGroups: new(SyncMap[string, int64]),
	}
	d.Config = NewConfig(d)
	d.ImSession.ServiceAtNew.Store(oldID, oldGroup)
	d.ImSession.ServiceAtNew.Store(newID, newGroup)

	m := &officialQQIdentityMigration{
		appID: appID, uin: uin,
		oldEndpoint: "OpenQQ:legacy",
		newEndpoint: formatDiceIDOfficialQQ(uin),
		groups:      map[string]string{},
		users:       map[string]string{},
	}
	m.addGroup(oldID)
	m.addMember(oldID, oldUser)
	m.addMember(oldID, oldUser2)
	m.migrateMemory(d)

	got, ok := d.ImSession.ServiceAtNew.Load(newID)
	if !ok {
		t.Fatal("new group missing after migrateMemory")
	}
	if got != newGroup {
		t.Fatal("old group object overwrote the new group object")
	}
	if got.GroupName != "new-name" {
		t.Fatalf("group name = %q, want new-name", got.GroupName)
	}
	if player, ok := got.Players.Load(newUser); !ok || player == nil || player.Name != "new-player" {
		t.Fatalf("new player was lost: %#v", player)
	}
	if player, ok := got.Players.Load(newUser2); !ok || player == nil || player.Name != "old-player-2" {
		t.Fatalf("old-only player was not merged: %#v", player)
	}
	if !got.Active || !got.ShowGroupWelcome || got.GroupWelcomeMessage != "欢迎" ||
		got.CocRuleIndex != 2 || !got.LogOn || got.LogCurName != "old-log" || got.LogCurID != 42 {
		t.Fatalf("old-only group settings were not merged: %#v", got)
	}
	if len(got.HelpPackages) != 1 || got.HelpPackages[0] != "coc7" {
		t.Fatalf("help packages = %#v, want [coc7]", got.HelpPackages)
	}
	if team, ok := got.PlayerGroups.Load("team"); !ok || len(team) != 2 {
		t.Fatalf("player group team = %#v, want merged members", team)
	}
}

func TestOfficialQQDispatchReturnsErrorWhenQueueClosed(t *testing.T) {
	queue := newOfficialQQEventQueue()
	queue.Close()
	pa := &PlatformAdapterOfficialQQ{
		eventQueue:          queue,
		eventQueueAccepting: true,
	}
	ran := false
	if err := pa.dispatchOfficialQQEvent(func() { ran = true }); err == nil {
		t.Fatal("dispatch should fail when the queue is closed")
	}
	if ran {
		t.Fatal("event must not run after the queue is closed")
	}
}

func TestOfficialQQEventDeduper(t *testing.T) {
	d := newOfficialQQEventDeduper(20*time.Millisecond, 16)
	if d.Seen("a") {
		t.Fatal("empty deduper reported a hit")
	}
	d.Mark("a")
	if !d.Seen("a") {
		t.Fatal("marked key was not seen")
	}
	d.Unmark("a")
	if d.Seen("a") {
		t.Fatal("unmarked key was still seen")
	}
	d.Mark("b")
	time.Sleep(30 * time.Millisecond)
	if d.Seen("b") {
		t.Fatal("expired key was still seen")
	}
}

func TestOfficialQQBotMentionFallbackWithoutIsYou(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}
	oneBot := &dto.WSPayload{RawMessage: []byte(`{"d":{"mentions":[{"id":"bot-id","bot":true}]}}`)}
	if ids := pa.parseBotSelfOpenIDs(oneBot); len(ids) != 1 || ids[0] != "bot-id" {
		t.Fatalf("single bot fallback = %#v, want bot-id", ids)
	}

	twoBots := &dto.WSPayload{RawMessage: []byte(`{"d":{"mentions":[{"id":"bot-a","bot":true},{"id":"bot-b","bot":true}]}}`)}
	if ids := pa.parseBotSelfOpenIDs(twoBots); len(ids) != 0 {
		t.Fatalf("ambiguous bot mentions should not claim self, got %#v", ids)
	}
}

func TestOfficialQQServeLoopCancel(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}
	epoch, stop := pa.beginServeLoop()
	if !pa.serveLoopCurrent(epoch, stop) {
		t.Fatal("new serve loop should be current")
	}
	pa.cancelServeLoop()
	if pa.serveLoopCurrent(epoch, stop) {
		t.Fatal("cancelled serve loop is still current")
	}

	oldEpoch, oldStop := pa.beginServeLoop()
	newEpoch, newStop := pa.beginServeLoop()
	if pa.serveLoopCurrent(oldEpoch, oldStop) {
		t.Fatal("old serve loop should be invalidated by a new one")
	}
	if !pa.serveLoopCurrent(newEpoch, newStop) {
		t.Fatal("new serve loop should be current")
	}
}

func TestOfficialQQIdentityLogConflictIsRenamed(t *testing.T) {
	const (
		appID = "app"
		uin   = "1"
	)
	dbOperator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-log-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbOperator.Close)
	db := dbOperator.db
	if err := db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatal(err)
	}

	oldGroup := "OpenQQ-Group-T:" + appID + "-g"
	newGroup := "OpenQQ-Group:" + uin + "-g"
	oldLog := model.LogInfo{Name: "记录", GroupID: oldGroup}
	newLog := model.LogInfo{Name: "记录", GroupID: newGroup}
	if err := db.Create(&oldLog).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&newLog).Error; err != nil {
		t.Fatal(err)
	}
	item := model.LogOneItem{LogID: oldLog.ID, GroupID: oldGroup, Message: "old"}
	if err := db.Create(&item).Error; err != nil {
		t.Fatal(err)
	}

	m := &officialQQIdentityMigration{
		appID: appID, uin: uin,
		oldEndpoint: "OpenQQ:legacy",
		newEndpoint: formatDiceIDOfficialQQ(uin),
		groups:      map[string]string{},
		users:       map[string]string{},
	}
	m.addGroup(oldGroup)
	if err := m.migrateLogDB(dbOperator); err != nil {
		t.Fatal(err)
	}

	var migrated model.LogInfo
	if err := db.Where("id = ?", oldLog.ID).First(&migrated).Error; err != nil {
		t.Fatal(err)
	}
	if migrated.GroupID != newGroup || !strings.HasPrefix(migrated.Name, "记录 (旧") {
		t.Fatalf("conflicting log was not renamed/moved: %#v", migrated)
	}
	var renamed int64
	if err := db.Model(&model.LogInfo{}).Where("group_id = ? AND name LIKE ?", newGroup, "记录 (旧%").Count(&renamed).Error; err != nil {
		t.Fatal(err)
	}
	if renamed != 1 {
		t.Fatalf("renamed conflicting logs = %d, want 1", renamed)
	}
	var movedItems int64
	if err := db.Model(&model.LogOneItem{}).Where("log_id = ? AND group_id = ?", oldLog.ID, newGroup).Count(&movedItems).Error; err != nil {
		t.Fatal(err)
	}
	if movedItems != 1 {
		t.Fatalf("moved log items = %d, want 1", movedItems)
	}
}
