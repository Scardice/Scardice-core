//nolint:testpackage
package dice

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/schema"
)

// newFix5LogGapEnv 建立一个“日志开启、基线 1000、最后记录 1050”的群，
// 并把 endpoint 换成可按 seq 拉历史的 stub。
func newFix5LogGapEnv(t *testing.T, groupID, senderID string, fetcher *recordingHistoryFetcher) (*Dice, *EndPointInfo, *GroupInfo, *MsgContext, uint64, func()) {
	t.Helper()
	d, ep, g, ctx, _, logID, cleanup := newLogSegmentTestEnv(t, groupID, senderID)
	g.SetLogState(logID, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.markLogSeqCalibrated()
	ep.Adapter = &stubHistoryAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		fetcher:             fetcher,
	}
	return d, ep, g, ctx, logID, cleanup
}

// popFix5GapTask 在测试里阻止 worker 自动启动，取出待执行任务以便同步 run()。
func popFix5GapTask(t *testing.T, g *GroupInfo) logGapFillTask {
	t.Helper()
	if g.logGapPending == nil {
		t.Fatal("expected a pending log gap task")
	}
	task := *g.logGapPending
	g.logGapPending = nil
	return task
}

func countFix5LogRows(t *testing.T, d *Dice, logID uint64, fromSeq, toSeq int64) int64 {
	t.Helper()
	var count int64
	db := d.DBOperator.GetLogDB(constant.READ)
	if err := db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND seq >= ? AND seq <= ?", logID, fromSeq, toSeq).
		Count(&count).Error; err != nil {
		t.Fatalf("count log rows: %v", err)
	}
	return count
}

// TestLogOffBackfillsPreOffGap_1115fix5 锁定 .log off 作为掉线恢复后第一条消息：
// off 之前的窗口继续补日志；off 指令本身已由正常路径记录；off 之后不写；
// 不执行任何历史指令（endpoint.Session 置 nil 也能完成）。
func TestLogOffBackfillsPreOffGap_1115fix5(t *testing.T) {
	const groupID = "QQ-Group:fix5-logoff"
	const senderID = "QQ:fix5-user"
	fetcher := &recordingHistoryFetcher{}
	d, ep, g, ctx, logID, cleanup := newFix5LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}

	// 模拟 off 前的在途任务已经入队，但不自动启动 worker。
	g.logGapWorkerRunning = true
	offMsg := newGroupMsg(groupID, senderID, ".log off")
	offMsg.Seq = 1201
	offMsg.RawID = "m-1201"
	logExt.OnMessageReceived(ctx, offMsg)
	task := popFix5GapTask(t, g)

	if _, ok := g.logOffForUserAtSeq(offMsg.Seq); !ok {
		t.Fatal(".log off should close the log")
	}
	if g.GetLogState().On {
		t.Fatal("log should be off after .log off")
	}
	if g.logOffGapAuthSnapshot() == nil {
		t.Fatal("expected off-gap authorization for the pre-off window")
	}

	// off 授权路径不应依赖 session；置 nil 也应当完成只补日志。
	ep.Session = nil
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1200); got != 150 {
		t.Fatalf("pre-off rows = %d, want 150", got)
	}
	if got := countFix5LogRows(t, d, logID, 1202, 1300); got != 0 {
		t.Fatalf("post-off rows = %d, want 0", got)
	}
	// .log off 指令本身在关闭前由正常消息路径记录，只应有一行。
	if got := countFix5LogRows(t, d, logID, 1201, 1201); got != 1 {
		t.Fatalf(".log off rows = %d, want 1", got)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending after off-window fill = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if g.logOffGapAuthSnapshot() != nil {
		t.Fatal("off-gap authorization should be cleared after the task completes")
	}
	g.logGapWorkerRunning = false
}

// TestLogOffSmallGapBackfillsLogOnly_1115fix5 小断层（≤5）在 off 授权下
// 也不能走 replaySilently 的命令执行路径；endpoint.Session=nil 仍应补日志。
func TestLogOffSmallGapBackfillsLogOnly_1115fix5(t *testing.T) {
	const groupID = "QQ-Group:fix5-logoff-small"
	const senderID = "QQ:fix5-user"
	fetcher := &recordingHistoryFetcher{}
	d, ep, g, ctx, logID, cleanup := newFix5LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}

	g.logGapWorkerRunning = true
	offMsg := newGroupMsg(groupID, senderID, ".log off")
	offMsg.Seq = 1056 // 净缺失 5 条：正常会走 replaySilently
	offMsg.RawID = "m-1056"
	logExt.OnMessageReceived(ctx, offMsg)
	task := popFix5GapTask(t, g)
	if task.gap != 5 {
		t.Fatalf("task gap = %d, want 5", task.gap)
	}
	if _, ok := g.logOffForUserAtSeq(offMsg.Seq); !ok {
		t.Fatal(".log off should close the log")
	}

	ep.Session = nil
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1055); got != 5 {
		t.Fatalf("small pre-off rows = %d, want 5 (log-only path)", got)
	}
	if got := countFix5LogRows(t, d, logID, 1057, 1100); got != 0 {
		t.Fatalf("post-off rows = %d, want 0", got)
	}
	g.logGapWorkerRunning = false
}

// TestBotOffBackfillsPreOffGap_1115fix5 锁定 .bot off 真正让群未激活时的
// off 前窗口补录：保留 pending/epoch，补完只清 pending，不补暂停段。
func TestBotOffBackfillsPreOffGap_1115fix5(t *testing.T) {
	const groupID = "QQ-Group:fix5-botoff"
	const senderID = "QQ:fix5-user"
	fetcher := &recordingHistoryFetcher{}
	d, ep, g, ctx, logID, cleanup := newFix5LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}

	g.logGapWorkerRunning = true
	offMsg := newGroupMsg(groupID, senderID, ".bot off")
	offMsg.Seq = 1201
	offMsg.RawID = "m-1201"
	logExt.OnMessageReceived(ctx, offMsg)
	task := popFix5GapTask(t, g)
	epochBefore := g.logEpoch.Load()

	SetBotOffAtGroupAtSeq(ctx, groupID, offMsg.Seq)
	state := g.GetLogState()
	if state.On || !g.isLogPausedByBotOff() {
		t.Fatalf("bot off should pause the log: on=%v paused=%v", state.On, g.isLogPausedByBotOff())
	}
	if g.logEpoch.Load() != epochBefore {
		t.Fatalf("epoch changed on authorized .bot off: got %d want %d", g.logEpoch.Load(), epochBefore)
	}
	if g.LogGapPendingFrom != 1050 || g.LogGapPendingTo != 1201 {
		t.Fatalf("pending after authorized .bot off = %d..%d, want 1050..1201",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if g.logOffGapAuthSnapshot() == nil {
		t.Fatal("expected off-gap authorization for .bot off")
	}

	ep.Session = nil
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1200); got != 150 {
		t.Fatalf("pre-off rows = %d, want 150", got)
	}
	if got := countFix5LogRows(t, d, logID, 1202, 1300); got != 0 {
		t.Fatalf("paused-period rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1201, 1201); got != 1 {
		t.Fatalf(".bot off rows = %d, want 1", got)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending after off-window fill = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if g.logOffGapAuthSnapshot() != nil {
		t.Fatal("off-gap authorization should be cleared after .bot off task completes")
	}
	g.logGapWorkerRunning = false
}

// TestOffCommandHandlersArmAuth_1115fix5 确认真实命令处理器把 msg.Seq 传到了
// .log off / .bot off，而不是只有直接调用 helper 才生效。
func TestOffCommandHandlersArmAuth_1115fix5(t *testing.T) {
	t.Run("log off", func(t *testing.T) {
		const groupID = "QQ-Group:fix5-cmd-logoff"
		const senderID = "QQ:fix5-user"
		d, _, g, ctx, _, cleanup := newFix5LogGapEnv(t, groupID, senderID, &recordingHistoryFetcher{})
		defer cleanup()

		logExt, ok := d.ExtRegistry.Load("log")
		if !ok {
			t.Fatal("log extension not registered")
		}
		g.logGapWorkerRunning = true
		msg := newGroupMsg(groupID, senderID, ".log off")
		msg.Seq = 1201
		msg.RawID = "m-1201"
		logExt.OnMessageReceived(ctx, msg)
		_ = popFix5GapTask(t, g)

		res := logExt.CmdMap["log"].Solve(ctx, msg, &CmdArgs{Args: []string{"off"}, RawArgs: "off", CleanArgs: "off"})
		if !res.Matched || !res.Solved {
			t.Fatalf("unexpected .log off result: %#v", res)
		}
		if g.GetLogState().On {
			t.Fatal(".log off handler did not close the log")
		}
		if g.logOffGapAuthSnapshot() == nil {
			t.Fatal(".log off handler did not arm off-gap authorization")
		}
		g.logGapWorkerRunning = false
	})

	// .bot off 的完整命令处理器会走 DiceFormatTmpl，需要 attrs 表；测试环境
	// 不准备模板/属性库，因此 .bot off 的接线由 TestBotOffBackfillsPreOffGap_1115fix5
	// 直接调用 SetBotOffAtGroupAtSeq 覆盖。
}

// TestBotOffWithOtherBotActiveKeepsLog_1115fix5 群内还有其它 bot 时，.bot off
// 不会自动暂停日志，也不应建立 off 授权；补全任务按正常开启路径继续。
func TestBotOffWithOtherBotActiveKeepsLog_1115fix5(t *testing.T) {
	const groupID = "QQ-Group:fix5-botoff-other"
	const senderID = "QQ:fix5-user"
	d, _, g, ctx, _, cleanup := newFix5LogGapEnv(t, groupID, senderID, &recordingHistoryFetcher{})
	defer cleanup()

	g.DiceIDActiveMap.Store("QQ:other-bot", true)
	// 1119: “另一个 bot 仍活跃”必须对应一个已启用端点；只有残留 ID 不算。
	d.ImSession.EndPoints = append(d.ImSession.EndPoints, &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{UserID: "QQ:other-bot", Enable: true},
	})
	epochBefore := g.logEpoch.Load()
	SetBotOffAtGroupAtSeq(ctx, groupID, 1201)

	if !g.GetLogState().On {
		t.Fatal("log must stay on while another bot is active")
	}
	if g.logOffGapAuthSnapshot() != nil {
		t.Fatal("no off authorization should be created when the log stays on")
	}
	if g.logEpoch.Load() != epochBefore {
		t.Fatalf("epoch changed with another active bot: got %d want %d", g.logEpoch.Load(), epochBefore)
	}
}

// TestBotOffWithoutGapTaskStillClearsPending_1115fix5 没有待处理补全任务时，
// .bot off 必须保持 1115 的原有语义：清 pending 并推进 epoch。
func TestBotOffWithoutGapTaskStillClearsPending_1115fix5(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix5-botoff-clear"}
	g.SetLogState(7, "run-a", true)
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1100
	epochBefore := g.logEpoch.Load()

	if !g.suspendLogForBotOffAtSeq(1100) {
		t.Fatal("suspendLogForBotOffAtSeq should pause an open log")
	}
	if g.GetLogState().On || !g.isLogPausedByBotOff() {
		t.Fatal("log should be paused")
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending without a task = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if g.logEpoch.Load() <= epochBefore {
		t.Fatalf("epoch = %d, want > %d", g.logEpoch.Load(), epochBefore)
	}
	if g.logOffGapAuthSnapshot() != nil {
		t.Fatal("no authorization should be created without a pending task")
	}
}

// TestLogOffAuthorizesEarlierPreOffTask_1115fix5 off 指令本身没有缺口，但更早
// 触发的任务窗口仍完全在 off 之前时，也要授权它完成。
func TestLogOffAuthorizesEarlierPreOffTask_1115fix5(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix5-earlier"}
	g.SetLogState(7, "run-a", true)
	g.setLogGapPendingRange(1000, 1100)
	g.logGapWorkerRunning = true
	if _, ok := g.logOffForUserAtSeq(1200); !ok {
		t.Fatal(".log off should close the log")
	}
	if g.logOffGapAuthSnapshot() == nil {
		t.Fatal("earlier pre-off task should be authorized")
	}

	task := logGapFillTask{
		dice:    &Dice{Logger: zap.NewNop().Sugar()},
		group:   g,
		logID:   7,
		logName: "run-a",
		epoch:   g.logEpoch.Load(),
		fromSeq: 1000,
		toSeq:   1100,
		gap:     99,
	}
	if !task.logOffGapFillAllowed() {
		t.Fatal("task window 1000..1100 must be allowed before offSeq 1200")
	}
	g.logGapWorkerRunning = false
}

// TestOffGapAuthRejectsTaskBeyondOffSeq_1115fix5 并发晚到的任务窗口如果越过了
// off 指令 seq，不能被授权。
func TestOffGapAuthRejectsTaskBeyondOffSeq_1115fix5(t *testing.T) {
	fetcher := &recordingHistoryFetcher{}
	g := &GroupInfo{GroupID: "QQ-Group:fix5-beyond"}
	g.SetLogState(7, "run-a", true)
	g.setLogGapPendingRange(1000, 1201)
	g.logGapWorkerRunning = true
	epoch := g.logEpoch.Load()
	if !g.armLogOffGapAuth(7, "run-a", epoch, 1201) {
		t.Fatal("expected authorization for the exact off window")
	}
	g.SetLogOn(false)

	task := logGapFillTask{
		dice:     &Dice{Logger: zap.NewNop().Sugar()},
		endpoint: newGapFillTestEndpoint(fetcher),
		group:    g,
		logID:    7,
		logName:  "run-a",
		epoch:    epoch,
		fromSeq:  1201,
		toSeq:    1202,
		gap:      1,
	}
	task.run()
	if fetcher.calls != 0 {
		t.Fatalf("task beyond offSeq fetched %d times, want 0", fetcher.calls)
	}
	if g.logOffGapAuthSnapshot() != nil {
		t.Fatal("cancel path should clear the authorization")
	}
	g.logGapWorkerRunning = false
}

// TestOffGapAuthCancelledByLogOn_1115fix5 .log on/new 会重建基线并推进 epoch，
// 旧 off 授权任务必须取消。
func TestOffGapAuthCancelledByLogOn_1115fix5(t *testing.T) {
	fetcher := &recordingHistoryFetcher{}
	g := &GroupInfo{GroupID: "QQ-Group:fix5-reon"}
	g.SetLogState(7, "run-a", true)
	g.setLogGapPendingRange(1000, 1201)
	g.logGapWorkerRunning = true
	epoch := g.logEpoch.Load()
	if !g.armLogOffGapAuth(7, "run-a", epoch, 1201) {
		t.Fatal("expected authorization")
	}
	g.SetLogOn(false)

	g.resetLogSeq(1202, "m-1202")
	g.SetLogOn(true)

	task := logGapFillTask{
		dice:     &Dice{Logger: zap.NewNop().Sugar()},
		endpoint: newGapFillTestEndpoint(fetcher),
		group:    g,
		logID:    7,
		logName:  "run-a",
		epoch:    epoch,
		fromSeq:  1000,
		toSeq:    1201,
		gap:      200,
	}
	task.run()
	if fetcher.calls != 0 {
		t.Fatalf("task cancelled by .log on fetched %d times, want 0", fetcher.calls)
	}
	if g.logOffGapAuthSnapshot() != nil {
		t.Fatal("resetLogSeq should clear off-gap authorization")
	}
	g.logGapWorkerRunning = false
}

// TestOffGapAuthWriteFailureKeepsPending_1115fix5 off 授权任务写入失败时仍要
// 保留 pending 并退避，不能把窗口当成已完成。
func TestOffGapAuthWriteFailureKeepsPending_1115fix5(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	if err := schema.EnsureLogSchema(d.DBOperator.GetLogDB(constant.WRITE), "mock-sqlite"); err != nil {
		t.Fatal(err)
	}
	const groupID = "QQ-Group:fix5-write"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(d.DBOperator, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}

	badWrite, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "fix5-bad-write.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := badWrite.db.DB()
	_ = sqlDB.Close()
	t.Cleanup(badWrite.Close)
	d.DBOperator = &fix3WriteFailOperator{
		mockDatabaseOperator: d.DBOperator.(*mockDatabaseOperator),
		write:                badWrite.db,
	}

	g := &GroupInfo{
		GroupID: groupID,
		Players: new(SyncMap[string, *GroupPlayerInfo]),
		BotList: new(SyncMap[string, bool]),
	}
	g.SetLogState(logID, logName, true)
	g.markLogSeqCalibrated()
	g.LogGapPendingFrom, g.LogGapPendingTo = 10, 20
	g.logGapWorkerRunning = true
	epoch := g.logEpoch.Load()
	if !g.armLogOffGapAuth(logID, logName, epoch, 20) {
		t.Fatal("expected off-gap authorization")
	}
	g.SetLogOn(false)

	ep.Adapter = &stubHistoryAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		fetcher:             &recordingHistoryFetcher{},
	}
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g,
		logID: logID, logName: logName, epoch: epoch,
		fromSeq: 10, toSeq: 20, gap: 9,
	}
	task.run()

	if g.LogGapPendingFrom != 10 || g.LogGapPendingTo != 20 {
		t.Fatalf("pending after off-window write failure = %d..%d, want 10..20",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if !g.logGapWriteFailed.Load() {
		t.Fatal("logGapWriteFailed must be set when off-window writes fail")
	}
	if retryAt := g.logGapRetryAt.Load(); retryAt < time.Now().Add(time.Minute).Unix() {
		t.Fatalf("retry backoff after off-window write failure = %d, want about 2 minutes ahead", retryAt)
	}
	g.logGapWorkerRunning = false
}
