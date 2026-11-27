//nolint:testpackage
package dice

import (
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
)

// 1114.fix2 回归：日志补全的可靠性修复。

// TestLogNewWithoutSeqClearsBaselineAcrossRestart_1114fix2 锁定 Seq=0 的 .log new
// 不能把旧日志持久基线留给新日志：即使 skip 标记丢失，重启后也不能把旧段补进新日志。
func TestLogNewWithoutSeqClearsBaselineAcrossRestart_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9001"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.SetLogOn(false)
	g.markLogSeqCalibrated()

	g.SetLogState(8, "run-b", true)
	g.resetLogSeqForNewSegment(0, "m-new")
	if g.LogSeqBaseline != 0 {
		t.Fatalf("persisted baseline after Seq=0 .log new = %d, want 0", g.LogSeqBaseline)
	}

	// 模拟“skip 标记没保存就重启”：新日志 DB MAX=0，旧基线已清。
	restarted := &GroupInfo{GroupID: g.GroupID, LogCurID: 8, LogCurName: "run-b", LogOn: true}
	restarted.initLogSeqFromPersisted()
	restarted.markLogSeqCalibrated()
	d := &Dice{Logger: zap.NewNop().Sugar()}
	from, _, gap := logGapFromMessage(d, restarted, GroupLogState{ID: 8, Name: "run-b", On: true}, 1202, "m-1202")
	if gap != 0 || from != 0 {
		t.Fatalf("restart with cleared baseline: from=%d gap=%d, want 0/0", from, gap)
	}
}

// TestLogGapPendingFloorAndClear_1114fix2 锁定未完成补全区间的持久化语义：
// 重启后基线被压回区间起点；补全完成/取消后区间被清掉。
func TestLogGapPendingFloorAndClear_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9002"}
	g.SetLogState(7, "run-a", true)
	g.LogSeqBaseline = 1000
	g.logLastSeq = 1101 // 触发消息已落库，但补全还没完成
	g.markLogSeqCalibrated()
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1101

	g.applyLogGapPendingFloor()
	if g.logLastSeq != 1000 {
		t.Fatalf("pending floor did not lower baseline: %d, want 1000", g.logLastSeq)
	}
	d := &Dice{Logger: zap.NewNop().Sugar()}
	if _, _, gap := logGapFromMessage(d, g, GroupLogState{ID: 7, Name: "run-a", On: true}, 1102, "m-1102"); gap != 101 {
		t.Fatalf("gap after pending floor = %d, want 101 (1001..1101)", gap)
	}

	// 持久化字段必须能跨 JSON/配置保存往返。
	payload, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal group: %v", err)
	}
	var reloaded GroupInfo
	if err := json.Unmarshal(payload, &reloaded); err != nil {
		t.Fatalf("unmarshal group: %v", err)
	}
	if reloaded.LogGapPendingFrom != 1000 || reloaded.LogGapPendingTo != 1101 {
		t.Fatalf("pending range round-trip = %d..%d, want 1000..1101", reloaded.LogGapPendingFrom, reloaded.LogGapPendingTo)
	}

	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1101
	g.clearLogGapPendingIfIdle(d)
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending range not cleared: %d..%d", g.LogGapPendingFrom, g.LogGapPendingTo)
	}
}

// TestFilterMissingFiltersAllGroupDiceEndpoints_1114fix2 锁定多端点同群：
// 任一骰子端点的发言都不能被当成玩家消息补录。
func TestFilterMissingFiltersAllGroupDiceEndpoints_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9003"}
	g.DiceIDExistsMap = new(SyncMap[string, bool])
	g.DiceIDExistsMap.Store("QQ:100", true)
	g.DiceIDActiveMap = new(SyncMap[string, bool])
	g.DiceIDActiveMap.Store("QQ:100", true)
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:200"}}
	task := logGapFillTask{group: g, endpoint: ep, fromSeq: 1000, toSeq: 1100}
	msgs := []*Message{
		{Seq: 1001, Sender: SenderBase{UserID: "QQ:100"}, Message: "dice A"},
		{Seq: 1002, Sender: SenderBase{UserID: "QQ:200"}, Message: "dice B"},
		{Seq: 1003, Sender: SenderBase{UserID: "QQ:300"}, Message: "player"},
	}
	got := task.filterMissing(msgs)
	if len(got) != 1 || got[0].Seq != 1003 {
		t.Fatalf("filterMissing = %+v, want only seq 1003", got)
	}
}

// TestWithLogStateReadBlocksOff_1114fix2 锁定补录写入与日志状态的互斥：
// 写入进行中 .log off 必须等待；off 之后的新写入必须被拒绝。
func TestWithLogStateReadBlocksOff_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9004"}
	g.SetLogState(7, "run-a", true)

	entered := make(chan struct{})
	release := make(chan struct{})
	go func() {
		g.withLogStateRead(7, "run-a", func() {
			close(entered)
			<-release
		})
	}()
	<-entered

	offDone := make(chan struct{})
	go func() {
		g.SetLogOn(false)
		close(offDone)
	}()
	select {
	case <-offDone:
		t.Fatal(".log off must wait for the in-flight log write")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-offDone

	if g.withLogStateRead(7, "run-a", func() { t.Fatal("write after log off must not run") }) {
		t.Fatal("withLogStateRead should reject write after log off")
	}
}

// TestLogAppendDeduplicatesRawMsgID_1114fix2 锁定实时/补录交错时的 raw_msg_id 去重。
func TestLogAppendDeduplicatesRawMsgID_1114fix2(t *testing.T) {
	op, _ := newFix5LogTestDB(t)
	const groupID = "QQ-Group:9005"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	seq := int64(1005)
	item := &model.LogOneItem{Nickname: "玩家", Time: 1, Message: "dup", RawMsgID: "dup-raw", Seq: &seq}
	if !service.LogAppend(op, groupID, logName, item) {
		t.Fatal("first append failed")
	}
	if !service.LogAppend(op, groupID, logName, item) {
		t.Fatal("duplicate append should be treated as already logged")
	}
	var count int64
	if err := op.db.Model(&model.LogOneItem{}).Where("log_id = ? AND raw_msg_id = ?", logID, "dup-raw").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("duplicate raw_msg_id rows = %d, want 1", count)
	}
	// 补录路径走 LogAppendByID，也必须去重。
	if !service.LogAppendByID(op, logID, groupID, item) {
		t.Fatal("LogAppendByID duplicate should be treated as already logged")
	}
	if err := op.db.Model(&model.LogOneItem{}).Where("log_id = ? AND raw_msg_id = ?", logID, "dup-raw").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("duplicate raw_msg_id rows after LogAppendByID = %d, want 1", count)
	}

	// 不同 raw_msg_id 仍正常写入。
	item2 := &model.LogOneItem{Nickname: "玩家", Time: 2, Message: "other", RawMsgID: "other-raw", Seq: &seq}
	if !service.LogAppend(op, groupID, logName, item2) {
		t.Fatal("different raw id append failed")
	}
	if err := op.db.Model(&model.LogOneItem{}).Where("log_id = ?", logID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after different raw id = %d, want 2", count)
	}

	// 空 raw_msg_id 不去重（没有平台消息 ID 可用）。
	empty1 := &model.LogOneItem{Nickname: "玩家", Time: 3, Message: "no-id-1"}
	empty2 := &model.LogOneItem{Nickname: "玩家", Time: 4, Message: "no-id-2"}
	if !service.LogAppend(op, groupID, logName, empty1) || !service.LogAppend(op, groupID, logName, empty2) {
		t.Fatal("appends without raw id failed")
	}
	if err := op.db.Model(&model.LogOneItem{}).Where("log_id = ?", logID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("rows after empty raw ids = %d, want 4", count)
	}
}

// TestLogSeqResetSelfHeals_1114fix2 锁定平台 seq 重置自愈：
// 连续 3 条明显回退后重建基线，下一次缺口从新基线起算。
func TestLogSeqResetSelfHeals_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9006"}
	g.SetLogState(7, "run-a", true)
	g.LogSeqBaseline = 5000
	g.logLastSeq = 5000
	g.markLogSeqCalibrated()
	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := GroupLogState{ID: 7, Name: "run-a", On: true}

	for _, seq := range []int64{100, 101, 102} {
		if _, _, gap := logGapFromMessage(d, g, state, seq, "m"); gap != 0 {
			t.Fatalf("seq reset message %d produced gap=%d, want 0", seq, gap)
		}
	}
	if g.logLastSeq != 102 || g.LogSeqBaseline != 102 {
		t.Fatalf("baseline after reset = %d/%d, want 102/102", g.logLastSeq, g.LogSeqBaseline)
	}
	if _, _, gap := logGapFromMessage(d, g, state, 200, "m-200"); gap != 97 {
		t.Fatalf("gap after reset = %d, want 97 (103..199)", gap)
	}
}

// TestLogSeqSmallRegressionDoesNotReset_1114fix2 锁定小幅乱序不会被误判为重置。
func TestLogSeqSmallRegressionDoesNotReset_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9007"}
	g.SetLogState(7, "run-a", true)
	g.LogSeqBaseline = 5000
	g.logLastSeq = 5000
	g.markLogSeqCalibrated()
	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := GroupLogState{ID: 7, Name: "run-a", On: true}

	for _, seq := range []int64{4995, 4996, 4997} {
		if _, _, gap := logGapFromMessage(d, g, state, seq, "m"); gap != 0 {
			t.Fatalf("small regression %d produced gap=%d, want 0", seq, gap)
		}
	}
	if g.logLastSeq != 5000 || g.LogSeqBaseline != 5000 {
		t.Fatalf("small regression reset baseline: %d/%d, want 5000/5000", g.logLastSeq, g.LogSeqBaseline)
	}
}

// TestWithLogStateReadHealDoesNotDeadlock_1114fix2 锁定 P0 回归：
// 补录写入闸门持的是 logWriteMu，不是 logStateMu；LogAppend 失败走
// healLogAppendByID 时可以在同一 goroutine 内 SetLogState，不会自锁。
func TestWithLogStateReadHealDoesNotDeadlock_1114fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:9008"}
	g.SetLogState(7, "run-a", true)

	done := make(chan struct{})
	go func() {
		g.withLogStateRead(7, "run-a", func() {
			// 模拟 healLogAppendByID 的副作用。
			_ = g.GetLogState()
			g.SetLogState(8, "run-a", true)
			g.resetLogSeqBaseline()
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("withLogStateRead + LogAppend heal path deadlocked")
	}
	if state := g.GetLogState(); state.ID != 8 || !state.On {
		t.Fatalf("state after simulated heal = %+v, want ID=8 On=true", state)
	}
}

// TestLogGapPendingClearedAfterTaskRun_1114fix2 锁定真实生命周期：
// task.run() 执行期间 logGapWorkerRunning=true，完成后仍必须清掉 pending 区间，
// 否则下一条消息会反复把基线压回旧区间、重复补录/重放。
func TestLogGapPendingClearedAfterTaskRun_1114fix2(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const groupID = "QQ-Group:9009"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	g := &GroupInfo{GroupID: groupID}
	g.SetLogState(logID, logName, true)
	g.markLogSeqCalibrated()

	fetcher := &recordingHistoryFetcher{empty: true}
	ep := newGapFillTestEndpoint(fetcher)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: logName,
		epoch: g.logEpoch.Load(), fromSeq: 1000, toSeq: 1100, gap: 9,
	}
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1100
	// 模拟 runLogGapWorker 已经把 pending 取走、正在执行 task：workerRunning=true。
	g.logGapWorkerRunning = true
	g.logGapPending = nil

	task.run()

	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending range after completed task.run = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	g.logGapWorkerRunning = false
}
