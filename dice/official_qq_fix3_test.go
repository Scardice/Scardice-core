package dice

import (
	"encoding/json"
	"testing"

	botevent "github.com/sealdice/botgo/event"
)

func TestOfficialQQEventQueuePanicReturnsPanicError(t *testing.T) {
	q := newOfficialQQEventQueue()
	defer q.Close()

	err := q.EnqueueWait(func() { panic("fix3-p2") })
	if !botevent.IsPanic(err) {
		t.Fatalf("EnqueueWait() error = %v, want botgo PanicError", err)
	}
	if err := q.EnqueueWait(func() {}); err != nil {
		t.Fatalf("worker did not survive the panic: %v", err)
	}
}

func TestOfficialQQDispatchPanicReturnsPanicError(t *testing.T) {
	q := newOfficialQQEventQueue()
	defer q.Close()

	pa := &PlatformAdapterOfficialQQ{eventQueue: q, eventQueueAccepting: true}
	err := pa.dispatchOfficialQQEvent(func() { panic("fix3-p2") })
	if !botevent.IsPanic(err) {
		t.Fatalf("dispatchOfficialQQEvent() error = %v, want botgo PanicError", err)
	}
}

func TestOfficialQQMergeOnlyRespectsUserInactivatedExt(t *testing.T) {
	// 新群只是“未自动启用”（只写 InactivatedExtSet），不算用户手动关闭，
	// 旧群的启用状态应正常导入。
	autoTarget := fix3TestGroup("new-auto")
	autoTarget.SetActivatedExtList(nil, nil)
	autoTarget.AddToInactivated("coc7")
	autoSource := fix3TestGroup("old-auto")
	autoSource.SetActivatedExtList([]*ExtInfo{{Name: "coc7"}, {Name: "fu"}}, nil)

	mergeOfficialQQGroupMemory(autoTarget, autoSource, nil)
	if !fix3GroupHasExt(autoTarget, "coc7") {
		t.Fatal("auto-inactivated coc7 should still be imported from the old group")
	}
	if !fix3GroupHasExt(autoTarget, "fu") {
		t.Fatal("untouched fu should be imported from the old group")
	}

	// 新群里用户手动关闭的扩展不能被旧群的启用状态复活。
	userTarget := fix3TestGroup("new-user")
	userTarget.SetActivatedExtList(nil, nil)
	userTarget.AddToUserInactivated("coc7")
	userSource := fix3TestGroup("old-user")
	userSource.SetActivatedExtList([]*ExtInfo{{Name: "coc7"}, {Name: "fu"}}, nil)

	mergeOfficialQQGroupMemory(userTarget, userSource, nil)
	if fix3GroupHasExt(userTarget, "coc7") {
		t.Fatal("user-inactivated coc7 must not be re-enabled by the merge")
	}
	if !fix3GroupHasExt(userTarget, "fu") {
		t.Fatal("untouched fu should be imported from the old group")
	}
}

func TestGroupInfoUserInactivatedSetBackfill(t *testing.T) {
	// 旧数据只有 InactivatedExtSet：保守地视为用户手动关闭。
	var legacy GroupInfo
	if err := json.Unmarshal([]byte(`{"inactivatedExtSet":{"coc7":{}}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if !legacy.IsUserInactivated("coc7") {
		t.Fatal("legacy inactivated extension should be treated as user-inactivated")
	}

	// 新数据带空的 UserInactivatedExtSet：自动关闭项不应被当成手动关闭。
	var modern GroupInfo
	if err := json.Unmarshal([]byte(`{"inactivatedExtSet":{"coc7":{}},"userInactivatedExtSet":{}}`), &modern); err != nil {
		t.Fatal(err)
	}
	if modern.IsUserInactivated("coc7") {
		t.Fatal("auto-inactivated extension must not be treated as user-inactivated")
	}

	// 序列化自动关闭项时必须写出非 nil 的空 UserInactivatedExtSet，
	// 否则重新加载时会被旧数据回填规则误判为手动关闭。
	auto := &GroupInfo{}
	auto.AddToInactivated("coc7")
	data, err := json.Marshal(auto)
	if err != nil {
		t.Fatal(err)
	}
	var restored GroupInfo
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.IsUserInactivated("coc7") {
		t.Fatalf("round-trip turned auto-inactivation into user-inactivation: %s", data)
	}
}

func fix3TestGroup(id string) *GroupInfo {
	group := &GroupInfo{GroupID: id}
	group.DiceIDActiveMap = new(SyncMap[string, bool])
	group.DiceIDExistsMap = new(SyncMap[string, bool])
	group.BotList = new(SyncMap[string, bool])
	group.Players = new(SyncMap[string, *GroupPlayerInfo])
	group.PlayerGroups = new(SyncMap[string, []string])
	group.InactivatedExtSet = StringSet{}
	group.UserInactivatedExtSet = StringSet{}
	return group
}

func fix3GroupHasExt(group *GroupInfo, name string) bool {
	for _, ext := range group.GetActivatedExtListRaw() {
		if ext != nil && ext.Name == name {
			return true
		}
	}
	return false
}
