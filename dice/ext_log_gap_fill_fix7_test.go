//nolint:testpackage
package dice

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/dboperator/schema"
)

// TestEndpointSupportsLogGapFill 锁定补全的能力边界：
// 只有实现 HistoryFetcher 的 OneBot/gocq 适配器才允许建补全任务。
// KOOK/官方 QQ 没有 per-group Message.Seq，也不实现历史拉取，必须为 false。
func TestEndpointSupportsLogGapFill(t *testing.T) {
	if endpointSupportsLogGapFill(nil) {
		t.Fatal("nil endpoint must not support log gap fill")
	}
	if endpointSupportsLogGapFill(&EndPointInfo{}) {
		t.Fatal("endpoint without adapter must not support log gap fill")
	}
	plain := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{}}
	plain.Adapter = newMockPlatformAdapter()
	if endpointSupportsLogGapFill(plain) {
		t.Fatal("adapter without HistoryFetcher must not support log gap fill")
	}
	withHistory := newGapFillTestEndpoint(&recordingHistoryFetcher{})
	if !endpointSupportsLogGapFill(withHistory) {
		t.Fatal("adapter implementing HistoryFetcher must support log gap fill")
	}
}

// TestLogGapCalibrationFailureDoesNotAdvance 锁定 READ 库故障时的安全行为：
// 校准失败不能用陈旧持久基线算缺口，更不能推进基线；否则会重复补录。
func TestLogGapCalibrationFailureDoesNotAdvance(t *testing.T) {
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "no-log-schema.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()

	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}
	g := &GroupInfo{GroupID: "QQ-Group:fix7"}
	g.LogSeqBaseline = 100
	g.initLogSeqFromPersisted()
	state := GroupLogState{ID: 7, Name: "run-a", On: true}

	fromSeq, _, gap := logGapFromMessage(d, g, state, 5001, "m-5001")
	if gap != 0 || fromSeq != 0 {
		t.Fatalf("calibration failure produced gap=%d from=%d, want 0/0", gap, fromSeq)
	}
	g.logSeqMu.Lock()
	baseline := g.logLastSeq
	g.logSeqMu.Unlock()
	if baseline != 100 {
		t.Fatalf("baseline advanced to %d on calibration failure, want 100", baseline)
	}
	if g.needLogSeqCalibration() {
		t.Fatal("failed calibration must enter backoff")
	}

	// 退避期间继续来消息：仍然不补、不推进基线。
	fromSeq, _, gap = logGapFromMessage(d, g, state, 5002, "m-5002")
	if gap != 0 || fromSeq != 0 {
		t.Fatalf("backoff produced gap=%d from=%d, want 0/0", gap, fromSeq)
	}
	g.logSeqMu.Lock()
	baseline = g.logLastSeq
	g.logSeqMu.Unlock()
	if baseline != 100 {
		t.Fatalf("baseline advanced to %d during calibration backoff, want 100", baseline)
	}
}

// TestLogGapCalibrationRecoveryFillsCorrectGap 锁定 READ 库恢复后的对齐：
// DB MAX(seq)=900、持久基线 100、新消息 5001 时，缺口应为 4100。
func TestLogGapCalibrationRecoveryFillsCorrectGap(t *testing.T) {
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "log-recovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	if err := schema.EnsureLogSchema(op.db, "mock-sqlite"); err != nil {
		t.Fatalf("EnsureLogSchema: %v", err)
	}
	const groupID = "QQ-Group:fix7"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatalf("LogGetOrCreate: %v", err)
	}
	seq900 := int64(900)
	if ok := service.LogAppend(op, groupID, logName, &model.LogOneItem{
		Nickname: "玩家",
		Time:     1,
		Message:  "old",
		RawMsgID: "m-900",
		Seq:      &seq900,
	}); !ok {
		t.Fatal("LogAppend failed")
	}

	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}
	g := &GroupInfo{GroupID: groupID}
	g.LogSeqBaseline = 100
	g.initLogSeqFromPersisted()
	// 模拟上一次校准失败后的退避已到期。
	g.logSeqMu.Lock()
	g.logSeqCalibrationRetryAt = 0
	g.logSeqMu.Unlock()

	fromSeq, _, gap := logGapFromMessage(d, g, GroupLogState{ID: logID, Name: logName, On: true}, 5001, "m-5001")
	if fromSeq != 900 || gap != 4100 {
		t.Fatalf("recovered calibration: from=%d gap=%d, want 900/4100", fromSeq, gap)
	}
	g.logSeqMu.Lock()
	baseline := g.logLastSeq
	g.logSeqMu.Unlock()
	if baseline != 5001 {
		t.Fatalf("baseline = %d, want 5001", baseline)
	}
}

// TestFilterAlreadyLoggedFailsClosed 锁定去重查询失败时跳过补录：
// log_items 没有唯一约束，fail-open 会在 READ 库故障时写出重复日志行。
func TestFilterAlreadyLoggedFailsClosed(t *testing.T) {
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "dedupe-fail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()

	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}
	task := logGapFillTask{
		dice:    d,
		group:   &GroupInfo{GroupID: "QQ-Group:fix7"},
		logID:   7,
		fromSeq: 0,
		toSeq:   10,
	}
	msgs := []*Message{{Seq: 5, RawID: "m-5"}}
	if got := task.filterAlreadyLogged(msgs); got != nil {
		t.Fatalf("dedupe query failure returned %d messages, want nil (fail-closed)", len(got))
	}

	d.DBOperator = nil
	if got := task.filterAlreadyLogged(msgs); got != nil {
		t.Fatalf("nil DB returned %d messages, want nil (fail-closed)", len(got))
	}
}

// TestLogStateStillValidRejectsEpochZeroTask 锁定 epoch 校验不能把 0 当哨兵：
// 老群数据首次加载时 logEpoch 可能本来就是 0，任务必须携带创建时的真实 epoch。
func TestLogStateStillValidRejectsEpochZeroTask(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix7"}
	g.SetLogState(7, "run-a", true)
	g.logEpoch.Add(1)

	task := logGapFillTask{group: g, logID: 7, logName: "run-a", epoch: 0}
	if task.logStateStillValid() {
		t.Fatal("task with stale epoch 0 must be rejected when group epoch is 1")
	}
	task.epoch = g.logEpoch.Load()
	if !task.logStateStillValid() {
		t.Fatal("task with current epoch must be accepted")
	}
}

// TestLogOffForUserClearsAutoRestore 锁定 .bot off 自动关闭后的用户显式 .log off：
// 即使日志已经是关的，也必须清掉“自动开启”标记，.bot on 不能把它重新打开。
func TestLogOffForUserClearsAutoRestore(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix7"}
	g.SetLogState(7, "run-a", true)
	if !g.suspendLogForBotOff() {
		t.Fatal("setup: suspend failed")
	}
	if !g.isLogPausedByBotOff() {
		t.Fatal("setup: auto-off marker missing")
	}
	name, ok := g.logOffForUser()
	if !ok || name != "run-a" {
		t.Fatalf("logOffForUser = (%q,%v), want (run-a,true)", name, ok)
	}
	if g.isLogPausedByBotOff() {
		t.Fatal("explicit .log off must clear the auto-restore marker")
	}
	if g.resumeLogPausedByBotOff() {
		t.Fatal(".bot on must not auto-on after explicit .log off")
	}
	if g.GetLogState().On {
		t.Fatal("log was re-enabled after explicit .log off")
	}
}

// TestBotOffAutoLogOffAndAutoLogOn 锁定方案2的主路径：
// .bot off 自动关闭日志并置标记；.bot on 自动开启并只跳过下一次缺口。
func TestBotOffAutoLogOffAndAutoLogOn(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix7"}
	g.SetLogState(7, "run-a", true)
	if !g.suspendLogForBotOff() {
		t.Fatal("suspendLogForBotOff should close an open log")
	}
	if state := g.GetLogState(); state.On || state.Name != "run-a" || state.ID != 7 {
		t.Fatalf("auto log off state = %+v, want On=false with name/id kept", state)
	}
	if !g.isLogPausedByBotOff() {
		t.Fatal("auto log off marker missing")
	}
	if !g.resumeLogPausedByBotOff() {
		t.Fatal("resumeLogPausedByBotOff should reopen the auto-closed log")
	}
	if !g.GetLogState().On {
		t.Fatal("log should be on after auto log on")
	}
	if g.isLogPausedByBotOff() {
		t.Fatal("auto log on must clear the marker")
	}
	if !g.consumeLogResumeSkipGap() {
		t.Fatal("auto log on must mark the next gap to be skipped")
	}
	if g.consumeLogResumeSkipGap() {
		t.Fatal("skip marker must only be consumed once")
	}
}

// TestBotOffDoesNotTouchAlreadyOffLog 锁定 .bot off 不碰用户手动关闭的日志，
// 也不置自动恢复标记（否则 .bot on 会把它重新打开）。
func TestBotOffDoesNotTouchAlreadyOffLog(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:fix7"}
	g.SetLogState(7, "run-a", true)
	g.SetLogOn(false)
	if g.suspendLogForBotOff() {
		t.Fatal("suspendLogForBotOff must not touch an already-off log")
	}
	if g.isLogPausedByBotOff() {
		t.Fatal("already-off log must not get the auto-restore marker")
	}
	if g.resumeLogPausedByBotOff() {
		t.Fatal(".bot on must not auto-on a log the user closed")
	}
}
