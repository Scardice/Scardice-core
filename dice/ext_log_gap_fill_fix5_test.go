//nolint:testpackage
package dice

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/dboperator/schema"
)

func newFix5LogTestDB(t *testing.T) (*mockDatabaseOperator, *Dice) {
	t.Helper()
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "fix5.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if err := schema.EnsureLogSchema(op.db, "mock-sqlite"); err != nil {
		t.Fatalf("EnsureLogSchema: %v", err)
	}
	return op, &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}
}

// TestRepairPersistedLogStateRecreatesDeletedLog 覆盖 Web UI 删除当前日志后的自愈：
// 持久化 LogCurID 后重启仍拿着旧 ID，必须按 LogCurName 找回/重建，否则永久写不进日志。
func TestRepairPersistedLogStateRecreatesDeletedLog(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const groupID = "QQ-Group:1"
	const logName = "run-a"

	oldID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	g := &GroupInfo{GroupID: groupID}
	g.SetLogState(oldID, logName, true)
	g.resetLogSeq(1000, "m-1000")

	if err := service.LogDelete(op, groupID, logName); err != nil {
		t.Fatal(err)
	}

	repairPersistedLogState(d, g)
	state := g.GetLogState()
	if state.ID == 0 {
		t.Fatal("repair should recreate the deleted log when LogOn")
	}
	if state.Name != logName || !state.On {
		t.Fatalf("repaired state = %+v, want name=%s on=true", state, logName)
	}
	if got, err := service.LogGetNameByID(op, state.ID); err != nil || got != logName {
		t.Fatalf("LogGetNameByID(%d) = %q, %v; want %q", state.ID, got, err, logName)
	}
	if baseline, _ := g.logSeqBaselineSnapshot(); baseline != 0 {
		t.Fatalf("baseline = %d, want 0 after log recreation", baseline)
	}
	if !service.LogAppendByID(op, state.ID, groupID, &model.LogOneItem{
		Message: "after-repair", RawMsgID: "m-1001", Seq: ptrInt64(1001),
	}) {
		t.Fatal("log append should work after repair")
	}
}

// TestRepairPersistedLogStateFixesNameMismatch 覆盖 ID 被复用（数据库恢复）：
// 同一 ID 指向了同群的另一本日志时，必须按名字找回正确日志，不能继续写错。
func TestRepairPersistedLogStateFixesNameMismatch(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const groupID = "QQ-Group:1"

	idA, err := service.LogGetOrCreate(op, groupID, "run-a")
	if err != nil {
		t.Fatal(err)
	}
	idB, err := service.LogGetOrCreate(op, groupID, "run-b")
	if err != nil {
		t.Fatal(err)
	}

	g := &GroupInfo{GroupID: groupID}
	g.SetLogState(idA, "run-b", true) // 持久 ID 指向 run-a，名字却是 run-b
	repairPersistedLogState(d, g)

	state := g.GetLogState()
	if state.ID != idB || state.Name != "run-b" || !state.On {
		t.Fatalf("repaired state = %+v, want ID=%d name=run-b on=true", state, idB)
	}
}

// TestBotOnResetBaselineClearsResumeSkip 覆盖审查发现的“skip 吞掉真实离线窗口”：
// .bot on 后还没收到消息就再次掉线/重启时，必须用指令消息的 seq 重建基线，
// 而不是等到第一条消息才把整个窗口当成静默段跳过。
func TestBotOnResetBaselineClearsResumeSkip(t *testing.T) {
	newGroup := func() *GroupInfo {
		g := &GroupInfo{GroupID: "QQ-Group:1"}
		g.SetLogState(7, "run-a", true)
		g.resetLogSeq(1000, "m-1000")
		g.updateLogSeq(1050, "m-1050")
		if !g.suspendLogForBotOff() {
			t.Fatal("setup: suspend failed")
		}
		if !g.resumeLogPausedByBotOff() {
			t.Fatal("setup: resume failed")
		}
		return g
	}
	d := &Dice{Logger: zap.NewNop().Sugar()}
	onState := GroupLogState{ID: 7, Name: "run-a", On: true}

	// 反例（修复前的行为）：只恢复、不重建基线，1201 被 skip 吞掉，gap=0。
	oldBehavior := newGroup()
	if from, _, gap := logGapFromMessage(d, oldBehavior, onState, 1201, "m-1201"); gap != 0 || from != 0 {
		t.Fatalf("pre-fix behavior changed: from=%d gap=%d, want 0/0", from, gap)
	}

	// 修复后的 .bot on 路径：用指令消息 seq=1051 重建基线并清掉 skip。
	g := newGroup()
	g.resetLogSeq(1051, "m-1051")
	g.clearLogResumeSkipGap()
	if g.consumeLogResumeSkipGap() {
		t.Fatal("skip marker should be cleared by .bot on")
	}

	// 1052..1200 是恢复后再次掉线的窗口，必须补回来。
	from, _, gap := logGapFromMessage(d, g, onState, 1201, "m-1201")
	if from != 1051 || gap != 149 {
		t.Fatalf("gap after .bot on = %d from=%d, want 149/1051", gap, from)
	}
}

// TestLogGapQueueCoalescesAdjacentGaps 覆盖补全任务合并：
// 抖动产生的相邻断层应合并成一个区间，且只启动一个 worker。
func TestLogGapQueueCoalescesAdjacentGaps(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	base := logGapFillTask{
		dice:      &Dice{Logger: zap.NewNop().Sugar()},
		group:     g,
		logID:     7,
		logName:   "run-a",
		fromSeq:   10,
		toSeq:     20,
		gap:       9,
		lastMsgID: "m-10",
	}

	if !g.mergeLogGapTask(base) {
		t.Fatal("first task should start the worker")
	}
	second := base
	second.fromSeq, second.toSeq, second.gap, second.lastMsgID = 20, 30, 9, "m-20"
	if g.mergeLogGapTask(second) {
		t.Fatal("second adjacent task must reuse the running worker")
	}

	pending := g.logGapPending
	if pending == nil {
		t.Fatal("pending task missing")
	}
	if pending.fromSeq != 10 || pending.toSeq != 30 || pending.gap != 18 || pending.lastMsgID != "m-10" {
		t.Fatalf("merged = %+v, want from=10 to=30 gap=18 lastMsgID=m-10", pending)
	}

	// 日志切换后旧区间已无意义：新任务替换 pending，不能合并进旧日志任务。
	third := base
	third.logID, third.logName = 8, "run-b"
	third.fromSeq, third.toSeq, third.gap, third.lastMsgID = 30, 40, 9, "m-30"
	if g.mergeLogGapTask(third) {
		t.Fatal("switch task must reuse the running worker")
	}
	pending = g.logGapPending
	if pending == nil || pending.logID != 8 || pending.logName != "run-b" || pending.fromSeq != 30 || pending.toSeq != 40 {
		t.Fatalf("pending after log switch = %+v, want run-b 30..40", pending)
	}

	// 基线重建（.log on/new、.bot on、日志重建）后 epoch 变化：
	// 即使日志 ID/名称相同，也要替换 pending，不能把 off/静默段合并进来。
	g.resetLogSeq(40, "m-40")
	fourth := base
	fourth.logID, fourth.logName = 8, "run-b"
	fourth.epoch = g.logEpoch.Load()
	fourth.fromSeq, fourth.toSeq, fourth.gap, fourth.lastMsgID = 50, 60, 9, "m-50"
	if g.mergeLogGapTask(fourth) {
		t.Fatal("post-reset task must reuse the running worker")
	}
	pending = g.logGapPending
	if pending == nil || pending.fromSeq != 50 || pending.toSeq != 60 || pending.epoch != fourth.epoch {
		t.Fatalf("pending after baseline reset = %+v, want 50..60 epoch=%d", pending, fourth.epoch)
	}
}

// TestLogGapTaskCancelsAfterBaselineReset epoch 变化后，在途任务必须取消：
// 否则 .log off→on / .bot off→on 之后，旧区间仍会被写进日志。
func TestLogGapTaskCancelsAfterBaselineReset(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(100, "m-100")
	task := logGapFillTask{
		group:   g,
		logID:   7,
		logName: "run-a",
		epoch:   g.logEpoch.Load(),
		fromSeq: 100,
		toSeq:   200,
	}
	if !task.logStateStillValid() {
		t.Fatal("task should be valid before the baseline reset")
	}
	g.resetLogSeq(300, "m-300")
	if task.logStateStillValid() {
		t.Fatal("task must be cancelled after the baseline was reset")
	}
}

// TestLogSeqCalibrationBacksOffAfterFailure 覆盖 DB 异常时的退避，避免每条消息都查库。
func TestLogSeqCalibrationBacksOffAfterFailure(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	if !g.needLogSeqCalibration() {
		t.Fatal("new group should need calibration")
	}
	g.deferLogSeqCalibration(time.Minute)
	if g.needLogSeqCalibration() {
		t.Fatal("calibration should back off after a failure")
	}
	g.logSeqMu.Lock()
	g.logSeqCalibrationRetryAt = 0
	g.logSeqMu.Unlock()
	if !g.needLogSeqCalibration() {
		t.Fatal("calibration should retry after backoff expires")
	}
	g.markLogSeqCalibrated()
	if g.needLogSeqCalibration() {
		t.Fatal("calibrated flag must win")
	}
}

// TestLogAppendSelfHealsStaleLogID 覆盖运行期（不重启）的自愈：
// 当前日志被删除后，按旧 ID 写入失败时应按名字重建并重试一次。
func TestLogAppendSelfHealsStaleLogID(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const groupID = "QQ-Group:1"
	const logName = "run-a"

	oldID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	g := &GroupInfo{GroupID: groupID}
	g.SetLogState(oldID, logName, true)
	if err := service.LogDelete(op, groupID, logName); err != nil {
		t.Fatal(err)
	}

	ctx := &MsgContext{Dice: d, Group: g}
	item := &model.LogOneItem{Message: "heal", RawMsgID: "m-1", Seq: ptrInt64(1)}
	if !LogAppend(ctx, groupID, oldID, logName, item) {
		t.Fatal("LogAppend should self-heal after the current log was deleted")
	}

	state := g.GetLogState()
	if state.ID == 0 || state.Name != logName || !state.On {
		t.Fatalf("state after self-heal = %+v", state)
	}
	if got, err := service.LogGetNameByID(op, state.ID); err != nil || got != logName {
		t.Fatalf("LogGetNameByID(%d) = %q, %v; want %q", state.ID, got, err, logName)
	}
}
