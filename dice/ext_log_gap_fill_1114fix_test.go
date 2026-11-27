//nolint:testpackage
package dice

import (
	"testing"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

// 1114.fix 回归：.log on/.log new 的消息没有 seq 时，不能把基线留在 off
// 之前，否则下一条带 seq 的消息会把 off 段整体当成缺口补录。
// 有 seq 时行为必须与 1114 完全一致。

func TestLogOnWithoutSeqDefersBaselineReset_1114fix(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:8201"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.SetLogOn(false)
	g.markLogSeqCalibrated()

	epochBefore := g.logEpoch.Load()
	g.SetLogState(7, "run-a", true) // handler 先开日志
	g.resetLogSeqForNewSegment(0, "m-on")

	if got := g.logLastSeq; got != 1050 {
		t.Fatalf("baseline after Seq=0 .log on = %d, want 1050", got)
	}
	if g.LogSeqBaseline != 0 {
		t.Fatalf("persisted baseline = %d, want 0 (old baseline must be cleared)", g.LogSeqBaseline)
	}
	if !g.LogResumeSkipGap {
		t.Fatal("Seq=0 .log on must set LogResumeSkipGap")
	}
	if g.logEpoch.Load() != epochBefore+1 {
		t.Fatalf("epoch = %d, want %d (old tasks must be invalidated)", g.logEpoch.Load(), epochBefore+1)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := g.GetLogState()

	// 下一条带 seq 的消息只重建基线，不算缺口。
	fromSeq, _, gap := logGapFromMessage(d, g, state, 1202, "m-1202")
	if gap != 0 || fromSeq != 0 {
		t.Fatalf("first message after Seq=0 .log on: from=%d gap=%d, want 0/0", fromSeq, gap)
	}
	if g.logLastSeq != 1202 {
		t.Fatalf("baseline after first message = %d, want 1202", g.logLastSeq)
	}
	if g.LogResumeSkipGap {
		t.Fatal("LogResumeSkipGap must be consumed by the first message")
	}

	// 之后的真实掉线窗口仍然要能补。
	fromSeq, _, gap = logGapFromMessage(d, g, state, 1300, "m-1300")
	if fromSeq != 1202 || gap <= 0 {
		t.Fatalf("genuine gap after skip: from=%d gap=%d, want from=1202 gap>0", fromSeq, gap)
	}
}

func TestLogOnWithSeqStillResetsBaseline_1114fix(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:8202"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.SetLogOn(false)
	g.markLogSeqCalibrated()

	epochBefore := g.logEpoch.Load()
	g.SetLogState(7, "run-a", true)
	g.resetLogSeqForNewSegment(1201, "m-on")

	if got := g.logLastSeq; got != 1201 {
		t.Fatalf("baseline after seq-bearing .log on = %d, want 1201", got)
	}
	if g.LogSeqBaseline != 1201 {
		t.Fatalf("persisted baseline = %d, want 1201", g.LogSeqBaseline)
	}
	if g.LogResumeSkipGap {
		t.Fatal("seq-bearing .log on must not set LogResumeSkipGap")
	}
	if g.logEpoch.Load() != epochBefore+1 {
		t.Fatalf("epoch = %d, want %d", g.logEpoch.Load(), epochBefore+1)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := g.GetLogState()
	if _, _, gap := logGapFromMessage(d, g, state, 1202, "m-1202"); gap != 0 {
		t.Fatalf("first message after seq-bearing .log on: gap=%d, want 0", gap)
	}
	if fromSeq, _, gap := logGapFromMessage(d, g, state, 1300, "m-1300"); fromSeq != 1202 || gap <= 0 {
		t.Fatalf("genuine gap: from=%d gap=%d, want from=1202 gap>0", fromSeq, gap)
	}
}

func TestLogNewWithoutSeqDefersBaselineReset_1114fix(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:8203"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.SetLogOn(false)
	g.markLogSeqCalibrated()

	// 模拟 .log new run-b：新日志 ID/名称，但没有 seq。
	g.SetLogState(8, "run-b", true)
	g.resetLogSeqForNewSegment(0, "m-new")

	if got := g.logLastSeq; got != 1050 {
		t.Fatalf("baseline after Seq=0 .log new = %d, want 1050", got)
	}
	if !g.LogResumeSkipGap {
		t.Fatal("Seq=0 .log new must set LogResumeSkipGap")
	}
	if state := g.GetLogState(); state.ID != 8 || state.Name != "run-b" {
		t.Fatalf("state = %+v, want ID=8 name=run-b", state)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := g.GetLogState()
	if fromSeq, _, gap := logGapFromMessage(d, g, state, 1202, "m-1202"); gap != 0 || fromSeq != 0 {
		t.Fatalf("first message after Seq=0 .log new: from=%d gap=%d, want 0/0", fromSeq, gap)
	}
	if g.logLastSeq != 1202 || g.LogResumeSkipGap {
		t.Fatalf("skip not consumed: baseline=%d skip=%v", g.logLastSeq, g.LogResumeSkipGap)
	}
}

// 以下两个是用真实命令处理器 + 日志表验证调用点确实使用了新 helper。
func newLogSegmentTestEnv(t *testing.T, groupID, senderID string) (*Dice, *EndPointInfo, *GroupInfo, *MsgContext, *mockPlatformAdapter, uint64, func()) {
	t.Helper()
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	ctx, _ := newQuitCommandTestContext(t, d, ep, senderID, groupID, "LogSegmentGroup")

	if err := d.DBOperator.GetLogDB(constant.WRITE).AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		cleanup()
		t.Fatalf("AutoMigrate log tables: %v", err)
	}
	logID, err := service.LogGetOrCreate(d.DBOperator, groupID, "run-a")
	if err != nil {
		cleanup()
		t.Fatalf("LogGetOrCreate: %v", err)
	}
	return d, ep, ctx.Group, ctx, adapter, logID, cleanup
}

func TestLogOnSeqZeroHandlerDefersGap_1114fix(t *testing.T) {
	const groupID = "QQ-Group:8204"
	const senderID = "QQ:8204"
	d, ep, g, ctx, _, logID, cleanup := newLogSegmentTestEnv(t, groupID, senderID)
	defer cleanup()
	_ = ep

	g.SetLogState(logID, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.SetLogOn(false)
	g.markLogSeqCalibrated()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	cmdLog := logExt.CmdMap["log"]
	if cmdLog == nil {
		t.Fatal("log command not registered")
	}

	onMsg := newGroupMsg(groupID, senderID, "")
	onMsg.Seq = 0
	res := cmdLog.Solve(ctx, onMsg, &CmdArgs{
		Args:      []string{"on", "run-a"},
		RawArgs:   "on run-a",
		CleanArgs: "on run-a",
	})
	if !res.Matched || !res.Solved {
		t.Fatalf("unexpected .log on result: %#v", res)
	}
	if !g.GetLogState().On {
		t.Fatal(".log on did not enable the log")
	}
	if got := g.logLastSeq; got != 1050 {
		t.Fatalf("baseline after Seq=0 .log on = %d, want 1050", got)
	}
	if !g.LogResumeSkipGap {
		t.Fatal("Seq=0 .log on must set LogResumeSkipGap")
	}

	next := newGroupMsg(groupID, senderID, "hello")
	next.Seq = 1202
	next.RawID = "m-1202"
	logExt.OnMessageReceived(ctx, next)

	if g.logLastSeq != 1202 {
		t.Fatalf("baseline after first message = %d, want 1202", g.logLastSeq)
	}
	if g.LogResumeSkipGap {
		t.Fatal("LogResumeSkipGap must be consumed")
	}
	if g.logGapPending != nil {
		t.Fatalf("unexpected gap task: %+v", g.logGapPending)
	}
	var count int64
	if err := d.DBOperator.GetLogDB(constant.READ).Model(&model.LogOneItem{}).
		Where("log_id = ? AND seq >= ? AND seq <= ?", logID, int64(1051), int64(1201)).
		Count(&count).Error; err != nil {
		t.Fatalf("count off-period rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("off-period rows = %d, want 0", count)
	}
}

func TestLogNewSeqZeroHandlerDefersGap_1114fix(t *testing.T) {
	const groupID = "QQ-Group:8205"
	const senderID = "QQ:8205"
	d, ep, g, ctx, _, logID, cleanup := newLogSegmentTestEnv(t, groupID, senderID)
	defer cleanup()
	_ = ep

	g.SetLogState(logID, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.SetLogOn(false)
	g.markLogSeqCalibrated()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	cmdLog := logExt.CmdMap["log"]
	if cmdLog == nil {
		t.Fatal("log command not registered")
	}

	newMsg := newGroupMsg(groupID, senderID, "")
	newMsg.Seq = 0
	res := cmdLog.Solve(ctx, newMsg, &CmdArgs{
		Args:      []string{"new", "run-b"},
		RawArgs:   "new run-b",
		CleanArgs: "new run-b",
	})
	if !res.Matched || !res.Solved {
		t.Fatalf("unexpected .log new result: %#v", res)
	}
	state := g.GetLogState()
	if !state.On || state.Name != "run-b" {
		t.Fatalf("state after .log new = %+v, want On run-b", state)
	}
	if got := g.logLastSeq; got != 1050 {
		t.Fatalf("baseline after Seq=0 .log new = %d, want 1050", got)
	}
	if !g.LogResumeSkipGap {
		t.Fatal("Seq=0 .log new must set LogResumeSkipGap")
	}

	next := newGroupMsg(groupID, senderID, "hello")
	next.Seq = 1202
	next.RawID = "m-1202"
	logExt.OnMessageReceived(ctx, next)

	if g.logLastSeq != 1202 || g.LogResumeSkipGap {
		t.Fatalf("skip not consumed: baseline=%d skip=%v", g.logLastSeq, g.LogResumeSkipGap)
	}
	if g.logGapPending != nil {
		t.Fatalf("unexpected gap task: %+v", g.logGapPending)
	}
	var count int64
	if err := d.DBOperator.GetLogDB(constant.READ).Model(&model.LogOneItem{}).
		Where("log_id = ? AND seq >= ? AND seq <= ?", state.ID, int64(1051), int64(1201)).
		Count(&count).Error; err != nil {
		t.Fatalf("count new-log off-period rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("new-log off-period rows = %d, want 0", count)
	}
}
