//nolint:testpackage
package dice

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/schema"
)

// 1115.fix3 回归：校准失败保留校准前基线；补录写入失败保留 pending。

type fix3ReadFailOperator struct {
	*mockDatabaseOperator
	read *gorm.DB
}

func (m *fix3ReadFailOperator) GetLogDB(mode constant.DBMode) *gorm.DB {
	if mode == constant.READ {
		return m.read
	}
	return m.db
}

type fix3WriteFailOperator struct {
	*mockDatabaseOperator
	write *gorm.DB
}

func (m *fix3WriteFailOperator) GetLogDB(mode constant.DBMode) *gorm.DB {
	if mode == constant.WRITE {
		return m.write
	}
	return m.db
}

// TestLogGapCalibrationFailureKeepsGap_1115fix3 锁定 READ 校准失败后的收尾：
// 失败期间消息仍会写入 WRITE；校准恢复后不能把基线直接推到新的 DB MAX，
// 必须先用失败前的基线压回 pending floor，重新算出真实断层。
func TestLogGapCalibrationFailureKeepsGap_1115fix3(t *testing.T) {
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "fix3-calib.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if err := schema.EnsureLogSchema(op.db, "mock-sqlite"); err != nil {
		t.Fatal(err)
	}
	const groupID = "QQ-Group:fix3-calib"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(op, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	seq900 := int64(900)
	if !service.LogAppend(op, groupID, logName, &model.LogOneItem{
		Nickname: "玩家", Time: 1, Message: "old", RawMsgID: "m-900", Seq: &seq900,
	}) {
		t.Fatal("seed append failed")
	}

	badRead, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "fix3-bad-read.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(badRead.Close)

	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: &fix3ReadFailOperator{mockDatabaseOperator: op, read: badRead.db}}
	g := &GroupInfo{GroupID: groupID}
	g.LogSeqBaseline = 100
	g.initLogSeqFromPersisted()
	state := GroupLogState{ID: logID, Name: logName, On: true}

	// 第一条消息触发校准失败：本条不补、不推进基线，但必须留下 floor。
	if _, _, gap := logGapFromMessage(d, g, state, 5001, "m-5001"); gap != 0 {
		t.Fatalf("calibration failure gap = %d, want 0", gap)
	}
	if g.LogGapPendingFrom != 100 || g.LogGapPendingTo != 101 {
		t.Fatalf("calibration floor pending = %d..%d, want 100..101",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}

	// 退避期间消息仍会正常入库（模拟 OnMessageReceived 的 LogAppend）。
	for _, item := range []struct {
		seq   int64
		rawID string
	}{{5001, "m-5001"}, {5002, "m-5002"}} {
		seq := item.seq
		if !service.LogAppend(op, groupID, logName, &model.LogOneItem{
			Nickname: "玩家", Time: seq, Message: "after", RawMsgID: item.rawID, Seq: &seq,
		}) {
			t.Fatal("append during calibration backoff failed")
		}
	}

	// READ 恢复、退避到期：校准读到 DB MAX=5002，但 floor 必须把基线压回 100。
	d.DBOperator = &fix3ReadFailOperator{mockDatabaseOperator: op, read: op.db}
	g.logSeqMu.Lock()
	g.logSeqCalibrationRetryAt = 0
	g.logSeqMu.Unlock()

	fromSeq, _, gap := logGapFromMessage(d, g, state, 5003, "m-5003")
	if fromSeq != 100 || gap != 4902 {
		t.Fatalf("recovered calibration: from=%d gap=%d, want from=100 gap=4902 (901..5002 已部分入库，去重会跳过)", fromSeq, gap)
	}
}

// TestLogGapWriteFailureKeepsPending_1115fix3 锁定补录写入失败：
// READ/fetch/dedupe 都成功，但所有 LogAppend 失败时，不能把 pending 清掉。
func TestLogGapWriteFailureKeepsPending_1115fix3(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	if err := schema.EnsureLogSchema(d.DBOperator.GetLogDB(constant.WRITE), "mock-sqlite"); err != nil {
		t.Fatal(err)
	}
	const groupID = "QQ-Group:fix3-write"
	const logName = "run-a"
	logID, err := service.LogGetOrCreate(d.DBOperator, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}

	badWrite, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "fix3-bad-write.db"))
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
	d.ImSession.ServiceAtNew.Store(groupID, g)

	ep.Adapter = &stubHistoryAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		fetcher:             &recordingHistoryFetcher{},
	}
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g,
		logID: logID, logName: logName, epoch: g.logEpoch.Load(),
		fromSeq: 10, toSeq: 20, gap: 9,
	}
	task.run()

	if g.LogGapPendingFrom != 10 || g.LogGapPendingTo != 20 {
		t.Fatalf("pending after all writes failed = %d..%d, want 10..20",
			g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if !g.logGapWriteFailed.Load() {
		t.Fatal("logGapWriteFailed must be set when LogAppend fails")
	}
	if retryAt := g.logGapRetryAt.Load(); retryAt < time.Now().Add(time.Minute).Unix() {
		t.Fatalf("retry backoff after write failure = %d, want about 2 minutes ahead", retryAt)
	}
}
