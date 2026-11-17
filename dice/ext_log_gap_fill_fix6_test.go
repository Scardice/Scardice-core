//nolint:testpackage
package dice

import (
	"sync"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
)

// TestLogStateConcurrentAccess 锁定 GroupInfo 日志状态的并发安全。
// 修复前 logStateMu 是指针懒初始化：两个消息协程同时首次访问会各建一把锁，
// 等于没有互斥（-race 必现）；MarshalJSON 也不持有该锁，保存协程可能写出
// “新 logCurId + 旧 logCurName”的撕裂状态。
func TestLogStateConcurrentAccess(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix6", Players: new(SyncMap[string, *GroupPlayerInfo])}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := range 200 {
			g.SetLogState(uint64(i+1), "run-a", i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			state := g.GetLogState()
			if state.ID == 0 && state.Name != "" {
				t.Errorf("torn state: %+v", state)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			if _, err := g.MarshalJSON(); err != nil {
				t.Errorf("marshal: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

// TestLogGapReplayDeniedCommandsCoverAdmin 锁定静默重放的指令黑名单。
// 漏掉 .ext/.set/.black 时，≤5 条的小断层会把 .ext off log 之类管理指令
// 真正执行一遍——日志被关掉，但用户完全不知情。
func TestLogGapReplayDeniedCommandsCoverAdmin(t *testing.T) {
	task := logGapFillTask{
		dice:  &Dice{Logger: zap.NewNop().Sugar(), CommandPrefix: []string{"。", ".", "/"}},
		group: &GroupInfo{GroupID: "QQ-Group:fix6"},
	}
	cases := []struct {
		text string
		want bool
	}{
		{".log off", true},
		{".bot off", true},
		{".master add 123456", true},
		{".dismiss", true},
		{".ban @某人", true},
		{".ext off log", true},
		{".set 骰子 名字", true},
		{".black add 123", true},
		{".reply off", true},
		{".randalgo set pcg", true},
		{"。ext off log", true},
		{"。log new 另一个记录", true},
		{"。reply off", true},
		{".st 力量50", false},
		{".ra 侦查", false},
		{".draw 卡组", false},
		{".jrrp", false},
		{"普通聊天", false},
	}
	for _, c := range cases {
		if got := task.isDeniedReplayCommand(&Message{Message: c.text, Platform: "QQ"}); got != c.want {
			t.Errorf("isDeniedReplayCommand(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

// TestLogGapFetchWindowClampsToNewest 锁定超大断层的窗口计算：
// 拉取和“已记录消息”去重必须用同一个窗口，否则离线数天时会为几十万 seq
// 建去重集合，却只补最近的 2000 条。
func TestLogGapFetchWindowClampsToNewest(t *testing.T) {
	cases := []struct {
		name      string
		from, to  int64
		wantFrom  int64
		wantTotal int64
	}{
		{"empty", 100, 101, 100, 0},
		{"one", 100, 102, 100, 1},
		{"small", 100, 150, 100, 49},
		{"exact-max", 100, 100 + logGapFillMaxMessages + 1, 100, logGapFillMaxMessages},
		{"over-max", 100, 100000, 100000 - 1 - logGapFillMaxMessages, logGapFillMaxMessages},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			from, total := logGapFetchWindow(c.from, c.to)
			if from != c.wantFrom || total != c.wantTotal {
				t.Fatalf("logGapFetchWindow(%d,%d) = (%d,%d), want (%d,%d)",
					c.from, c.to, from, total, c.wantFrom, c.wantTotal)
			}
		})
	}
}

// TestRepairPersistedLogStateFixesForeignGroupID 覆盖“ID 被复用成另一个群的同名日志”。
// 只比对名字发现不了这种状态：运行期 LogAppendByID 会因归属不符永久失败，
// 启动时必须按本群名字找回自己的日志。
func TestRepairPersistedLogStateFixesForeignGroupID(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const logName = "run-a"
	const groupA = "QQ-Group:100"
	const groupB = "QQ-Group:200"

	idA, err := service.LogGetOrCreate(op, groupA, logName)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := service.LogGetOrCreate(op, groupB, logName)
	if err != nil {
		t.Fatal(err)
	}
	if idA == idB {
		t.Fatal("setup: two groups must have distinct logs")
	}

	g := &GroupInfo{GroupID: groupB}
	g.SetLogState(idA, logName, true) // 名字对、归属错
	repairPersistedLogState(d, g)

	state := g.GetLogState()
	if state.ID != idB {
		t.Fatalf("repair picked log %d, want %d (own group)", state.ID, idB)
	}
	if owner, _, err := service.LogGetOwnerByID(op, state.ID); err != nil || owner != groupB {
		t.Fatalf("owner = %q, %v; want %q", owner, err, groupB)
	}
}

// TestUserLogEndClearsBotOffPause 覆盖“.bot off 暂停期间用户结束了日志”。
// 结束日志是用户显式操作，必须清掉暂停标记；否则后续 .bot on 仍按“从暂停恢复”
// 处理，会用指令 seq 覆盖基线，并在回复里谎称“日志已随骰子恢复”。
func TestUserLogEndClearsBotOffPause(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix6"}
	g.SetLogState(9, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	if !g.suspendLogForBotOff() {
		t.Fatal("setup: suspend failed")
	}
	if !g.isLogPausedByBotOff() {
		t.Fatal("setup: pause flag not set")
	}

	// .log end：结束日志并清除暂停标记
	g.ClearLogState()
	g.clearLogPausedByBotOff()

	if g.isLogPausedByBotOff() {
		t.Fatal("pause flag should be cleared by explicit .log end")
	}
	if resumed := g.resumeLogPausedByBotOff(); resumed {
		t.Fatal("resume must be a no-op after user explicitly ended the log")
	}
	if state := g.GetLogState(); state.On || state.Name != "" {
		t.Fatalf("ended log was resurrected: %+v", state)
	}
}
