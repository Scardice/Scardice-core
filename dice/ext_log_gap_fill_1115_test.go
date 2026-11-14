//nolint:testpackage
package dice

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
)

// 1115 回归：1114.fix2 之后的日志补全收尾修复。

// TestLogAppendZeroRawMsgIDNotDeduped_1115 锁定“0 不是有效消息 ID”：
// 部分 OneBot 实现在缺失 message_id 时会给出 0；若把 "0" 当真实 ID 去重，
// 同一本日志里之后所有同格式消息都会被误判成重复而丢失。
func TestLogAppendZeroRawMsgIDNotDeduped_1115(t *testing.T) {
	op, _ := newFix5LogTestDB(t)
	const groupID = "QQ-Group:11001"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}

	seq := int64(1005)
	a := &model.LogOneItem{Nickname: "玩家", Time: 1, Message: "no-id-a", RawMsgID: "0", Seq: &seq}
	b := &model.LogOneItem{Nickname: "玩家", Time: 2, Message: "no-id-b", RawMsgID: int64(0), Seq: &seq}
	if !service.LogAppend(op, groupID, logName, a) || !service.LogAppend(op, groupID, logName, b) {
		t.Fatal("appends with zero raw id failed")
	}
	var count int64
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "0").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("zero raw id rows = %d, want 2 (0 must not dedupe)", count)
	}

	// 正常的非零 raw id 仍然去重。
	real := &model.LogOneItem{Nickname: "玩家", Time: 3, Message: "real", RawMsgID: "raw-1", Seq: &seq}
	if !service.LogAppend(op, groupID, logName, real) || !service.LogAppend(op, groupID, logName, real) {
		t.Fatal("real raw id appends failed")
	}
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "raw-1").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("real raw id rows = %d, want 1", count)
	}

	// 补录去重集合也不能把 "0" 当成“已记录”。
	ids, err := service.LogRawMsgIDsInSeqRange(op, logID, 1000, 1010)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids["0"]; ok {
		t.Fatal(`LogRawMsgIDsInSeqRange must not treat "0" as a recorded raw id`)
	}
}

// TestBotOffOnClearsLogGapPending_1115 锁定 .bot off/.bot on 边界：
// 暂停前未完成的补全区间必须取消，否则恢复后 pending floor 会把
// 关闭期间的聊天重新补进日志（违反 “.bot off 期间不补录”）。
func TestBotOffOnClearsLogGapPending_1115(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:11002"}
	g.SetLogState(7, "run-a", true)
	g.LogSeqBaseline = 1000
	g.logLastSeq = 1100
	g.markLogSeqCalibrated()
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1100
	g.logGapRetryAt.Store(time.Now().Add(time.Minute).Unix())
	epochBefore := g.logEpoch.Load()

	if !g.suspendLogForBotOff() {
		t.Fatal("suspendLogForBotOff should pause an open log")
	}
	if state := g.GetLogState(); state.On {
		t.Fatalf("log still on after .bot off: %+v", state)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending range after .bot off = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if g.logGapRetryAt.Load() != 0 {
		t.Fatalf("retry backoff after .bot off = %d, want 0", g.logGapRetryAt.Load())
	}
	if g.logEpoch.Load() <= epochBefore {
		t.Fatalf("epoch after .bot off = %d, want > %d", g.logEpoch.Load(), epochBefore)
	}

	// 模拟“暂停期间有旧 pending 被持久化、进程重启”：恢复时也必须清掉。
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1100
	g.logGapRetryAt.Store(time.Now().Add(time.Minute).Unix())
	if !g.resumeLogPausedByBotOff() {
		t.Fatal("resumeLogPausedByBotOff should reopen the paused log")
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending range after .bot on = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if g.logGapRetryAt.Load() != 0 {
		t.Fatalf("retry backoff after .bot on = %d, want 0", g.logGapRetryAt.Load())
	}

	// 恢复后的第一条消息只重建基线；第二条消息不能把 .bot off 期间算成缺口。
	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := g.GetLogState()
	if _, _, gap := logGapFromMessage(d, g, state, 5001, "m-5001"); gap != 0 {
		t.Fatalf("first message after .bot on gap = %d, want 0", gap)
	}
	if _, _, gap := logGapFromMessage(d, g, state, 5002, "m-5002"); gap != 0 {
		t.Fatalf("second message after .bot on gap = %d, want 0 (off segment must not be backfilled)", gap)
	}
}

// TestLogAppendNoDedupForPrivateListen_1115 锁定私聊暗骰回显：
// 私聊消息 ID 与群消息 ID 是两套命名空间（Telegram 等按会话独立编号），
// 同 ID 时群日志必须两条都保留；群消息内部仍按 raw_msg_id 去重。
func TestLogAppendNoDedupForPrivateListen_1115(t *testing.T) {
	op, _ := newFix5LogTestDB(t)
	const groupID = "QQ-Group:11004"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}

	seq := int64(2000)
	groupMsg := &model.LogOneItem{Nickname: "玩家", Time: 1, Message: "group", RawMsgID: "shared-id", Seq: &seq}
	if !service.LogAppend(op, groupID, logName, groupMsg) {
		t.Fatal("group message append failed")
	}
	privateEcho := &model.LogOneItem{
		Nickname: "骰子", Time: 2, Message: "private echo", IsDice: true,
		RawMsgID: "shared-id",
	}
	if !service.LogAppend(op, groupID, logName, privateEcho) {
		t.Fatal("private listen echo append failed")
	}
	var count int64
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "shared-id").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("shared raw id rows = %d, want 2 (group + private listen)", count)
	}

	// 群消息自身的重复仍然去重。
	if !service.LogAppend(op, groupID, logName, groupMsg) {
		t.Fatal("duplicate group append should be treated as already logged")
	}
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "shared-id").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after duplicate group append = %d, want 2", count)
	}

	// LogAppendByID 路径也必须跳过骰子发言的去重。
	privateEcho2 := &model.LogOneItem{
		Nickname: "骰子", Time: 3, Message: "private echo 2", IsDice: true,
		RawMsgID: "shared-id",
	}
	if !service.LogAppendByID(op, logID, groupID, privateEcho2) {
		t.Fatal("LogAppendByID private listen echo failed")
	}
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "shared-id").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("rows after LogAppendByID private listen = %d, want 3", count)
	}

	// 反向顺序：私聊回显先写、群消息后写，也不能被对方的 ID 顶掉。
	seq2 := int64(2001)
	privateFirst := &model.LogOneItem{
		Nickname: "骰子", Time: 4, Message: "private first", IsDice: true,
		RawMsgID: "shared-2",
	}
	if !service.LogAppend(op, groupID, logName, privateFirst) {
		t.Fatal("private first append failed")
	}
	groupSecond := &model.LogOneItem{
		Nickname: "玩家", Time: 5, Message: "group second", RawMsgID: "shared-2", Seq: &seq2,
	}
	if !service.LogAppend(op, groupID, logName, groupSecond) {
		t.Fatal("group second append failed")
	}
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "shared-2").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("reverse-order shared raw id rows = %d, want 2", count)
	}
}

// TestLogGapRetryBackoff_1115 锁定拉取失败后的退避：
// 退避期内 pending floor 不能反复压回基线，否则每条新消息都会重新发起
// 一次完整历史拉取；退避结束后仍应恢复补全能力。
func TestLogGapRetryBackoff_1115(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:11003"}
	g.SetLogState(7, "run-a", true)
	g.LogSeqBaseline = 1000
	g.logLastSeq = 1100
	g.markLogSeqCalibrated()
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1100
	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := GroupLogState{ID: 7, Name: "run-a", On: true}

	g.deferLogGapRetry(time.Minute)
	if _, _, gap := logGapFromMessage(d, g, state, 1101, "m-1101"); gap != 0 {
		t.Fatalf("gap during retry backoff = %d, want 0 (pending floor must be skipped)", gap)
	}
	if g.logLastSeq != 1101 {
		t.Fatalf("last seq during backoff = %d, want 1101", g.logLastSeq)
	}

	g.logGapRetryAt.Store(0)
	if _, _, gap := logGapFromMessage(d, g, state, 1102, "m-1102"); gap != 101 {
		t.Fatalf("gap after backoff = %d, want 101 (1001..1101)", gap)
	}

	// 补全结束清 pending 时必须同时清退避，避免影响下一段缺口。
	g.deferLogGapRetry(time.Minute)
	g.clearLogGapPendingIfIdle(d)
	if g.logGapRetryAt.Load() != 0 {
		t.Fatalf("retry backoff after pending cleared = %d, want 0", g.logGapRetryAt.Load())
	}
}
