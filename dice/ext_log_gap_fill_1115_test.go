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
	if countErr := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "0").Count(&count).Error; countErr != nil {
		t.Fatal(countErr)
	}
	if count != 2 {
		t.Fatalf("zero raw id rows = %d, want 2 (0 must not dedupe)", count)
	}

	// 正常的非零 raw id 仍然去重。
	realItem := &model.LogOneItem{Nickname: "玩家", Time: 3, Message: "real", RawMsgID: "raw-1", Seq: &seq}
	if !service.LogAppend(op, groupID, logName, realItem) {
		t.Fatal("real raw id first append failed")
	}
	if !service.LogAppend(op, groupID, logName, realItem) {
		t.Fatal("real raw id duplicate append failed")
	}
	if countErr := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "raw-1").Count(&count).Error; countErr != nil {
		t.Fatal(countErr)
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

	// 骰子自身发言不参与库级去重：同一 raw_msg_id 的重复回调会被保留。
	// 这是为了不丢“不同会话同号”的骰子发言而接受的取舍（见下方用例）。
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
		t.Fatalf("rows after repeated private listen = %d, want 3 (dice rows are not deduped)", count)
	}

	// 骰子 vs 骰子：群内骰子回复与私聊回显的 raw_msg_id 来自不同会话命名空间，
	// 同号时两条都必须保留，不能被 is_dice 分桶去重顶掉。
	diceGroup := &model.LogOneItem{
		Nickname: "骰子", Time: 6, Message: "group dice reply", IsDice: true,
		RawMsgID: "shared-dice",
	}
	dicePrivate := &model.LogOneItem{
		Nickname: "骰子", Time: 7, Message: "private echo", IsDice: true,
		RawMsgID: "shared-dice",
	}
	if !service.LogAppend(op, groupID, logName, diceGroup) || !service.LogAppend(op, groupID, logName, dicePrivate) {
		t.Fatal("dice cross-namespace appends failed")
	}
	if err := op.db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, "shared-dice").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("dice cross-namespace rows = %d, want 2 (must not dedupe across chats)", count)
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

// TestLogGapFetchRespectsRetryBackoff_1115fix 锁定退避覆盖实际拉取：
// fetch 失败后的退避期内，已合并任务/新产生的断层也不能立刻再拉一次；
// pending 区间保留，退避结束后下一次 run() 才真正拉取。
func TestLogGapFetchRespectsRetryBackoff_1115fix(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const groupID = "QQ-Group:11005"
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
	g.deferLogGapRetry(time.Minute)

	task.run()
	if fetcher.calls != 0 {
		t.Fatalf("fetch calls during retry backoff = %d, want 0", fetcher.calls)
	}
	if g.LogGapPendingFrom != 1000 || g.LogGapPendingTo != 1100 {
		t.Fatalf("pending range during backoff = %d..%d, want 1000..1100",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}

	g.logGapRetryAt.Store(0)
	task.run()
	if fetcher.calls == 0 {
		t.Fatal("fetch was not attempted after retry backoff expired")
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending range after backoff fetch = %d..%d, want 0..0",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
}

// TestLogGapDedupeQueryFailureKeepsPending_1115fix2 锁定去重查询失败的收尾：
// 历史拉取成功、但查询已记录消息失败时，run() 不能走
// “missing == 0 -> clearLogGapPendingIfIdle” 分支，否则一次 READ 库抖动
// 就会让 pending 区间被永久清掉。正确行为是保留 pending 并设置退避。
func TestLogGapDedupeQueryFailureKeepsPending_1115fix2(t *testing.T) {
	op, d := newFix5LogTestDB(t)
	const groupID = "QQ-Group:11006"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 READ 库故障：去重查询会返回 “no such table”，而不是空结果。
	if err := op.db.Exec("DROP TABLE log_items").Error; err != nil {
		t.Fatal(err)
	}

	g := &GroupInfo{GroupID: groupID}
	g.SetLogState(logID, logName, true)
	g.markLogSeqCalibrated()
	g.LogGapPendingFrom, g.LogGapPendingTo = 1000, 1100

	fetcher := &recordingHistoryFetcher{empty: true}
	task := logGapFillTask{
		dice: d, endpoint: newGapFillTestEndpoint(fetcher), group: g,
		logID: logID, logName: logName, epoch: g.logEpoch.Load(),
		fromSeq: 1000, toSeq: 1100, gap: 9,
	}
	task.run()

	if fetcher.calls != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetcher.calls)
	}
	if g.LogGapPendingFrom != 1000 || g.LogGapPendingTo != 1100 {
		t.Fatalf("pending range after dedupe failure = %d..%d, want 1000..1100",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	retryAt := g.logGapRetryAt.Load()
	if retryAt < time.Now().Add(time.Minute).Unix() {
		t.Fatalf("retry backoff after dedupe failure = %d, want about 2 minutes ahead", retryAt)
	}

	// 退避期内再次 run() 不应拉取，pending 仍保留。
	task.run()
	if fetcher.calls != 1 {
		t.Fatalf("fetch calls during dedupe-failure backoff = %d, want 1", fetcher.calls)
	}
	if g.LogGapPendingFrom != 1000 || g.LogGapPendingTo != 1100 {
		t.Fatalf("pending range during dedupe-failure backoff = %d..%d, want 1000..1100",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
}
