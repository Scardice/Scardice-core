//nolint:testpackage
package dice

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/dice/service"
)

// recordingHistoryFetcher 记录每次拉取的起点，并按 "从 fromSeq 之后连续生成" 的
// 语义返回 count 条消息。
type recordingHistoryFetcher struct {
	calls     int
	firstFrom int64
	// empty 让拉取返回空页：用于只想验证“是否进入补全流程”的用例，
	// 避免继续走到需要完整 Dice/Endpoint 会话的补录分支。
	empty bool
}

func (f *recordingHistoryFetcher) FetchGroupMsgHistory(_ context.Context, _ string, fromSeq int64, count int) ([]*Message, error) {
	f.calls++
	if f.calls == 1 {
		f.firstFrom = fromSeq
	}
	if f.empty {
		return nil, nil
	}
	msgs := make([]*Message, 0, count)
	for i := range count {
		seq := fromSeq + 1 + int64(i)
		msgs = append(msgs, &Message{
			Seq:      seq,
			RawID:    "m-" + strconv.FormatInt(seq, 10),
			Platform: "QQ",
			Sender:   SenderBase{UserID: "QQ:100", Nickname: "玩家"},
		})
	}
	return msgs, nil
}

// stubHistoryAdapter 让 EndPointInfo.Adapter 满足 HistoryFetcher。
type stubHistoryAdapter struct {
	*mockPlatformAdapter
	fetcher    *recordingHistoryFetcher
	afterFetch func()
}

func (s *stubHistoryAdapter) FetchGroupMsgHistory(ctx context.Context, groupID string, fromSeq int64, count int) ([]*Message, error) {
	msgs, err := s.fetcher.FetchGroupMsgHistory(ctx, groupID, fromSeq, count)
	if s.afterFetch != nil {
		hook := s.afterFetch
		s.afterFetch = nil
		hook()
	}
	return msgs, err
}

func newGapFillTestTask(g *GroupInfo, endpoint *EndPointInfo, fetcher *recordingHistoryFetcher) logGapFillTask {
	return logGapFillTask{
		dice:     &Dice{Logger: zap.NewNop().Sugar()},
		endpoint: endpoint,
		group:    g,
		logID:    7,
		logName:  "run-a",
		fromSeq:  10,
		toSeq:    20,
		gap:      9,
	}
}

func newGapFillTestEndpoint(fetcher *recordingHistoryFetcher) *EndPointInfo {
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:999"}}
	endpoint.Adapter = &stubHistoryAdapter{mockPlatformAdapter: newMockPlatformAdapter(), fetcher: fetcher}
	return endpoint
}

func newCalibrationTestDB(t *testing.T) *mockDatabaseOperator {
	t.Helper()
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "calib.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := op.db.Exec("CREATE TABLE log_items (id INTEGER PRIMARY KEY, log_id INTEGER, seq INTEGER, raw_msg_id TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		logID uint64
		seq   int64
		rawID string
	}{
		{logID: 7, seq: 800, rawID: "db-800"},
		{logID: 7, seq: 900, rawID: "db-900"},
		{logID: 8, seq: 50, rawID: "other-log"},
	} {
		if err := op.db.Exec("INSERT INTO log_items (log_id, seq, raw_msg_id) VALUES (?, ?, ?)", row.logID, row.seq, row.rawID).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.LogGetLastSeq(op, 7); err != nil {
		t.Fatalf("probe schema: %v", err)
	}
	return op
}

// TestCalibrateLogSeqBaselineUsesDBMax 复现“重启后基线停在 .log on”导致的假断层：
// 持久基线是 100，数据库里已经记录到 900，校准后必须用 900 计算缺口。
func TestCalibrateLogSeqBaselineUsesDBMax(t *testing.T) {
	op := newCalibrationTestDB(t)
	defer op.Close()

	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.LogSeqBaseline = 100
	g.initLogSeqFromPersisted()

	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}
	lastSeq, lastMsgID, ok := calibrateLogSeqBaseline(d, g, 7, 100, "msg-100")
	if !ok {
		t.Fatal("calibration with a working DB should report ok")
	}
	if lastSeq != 900 {
		t.Fatalf("calibrated lastSeq = %d, want 900 (DB MAX(seq))", lastSeq)
	}
	if lastMsgID != nil {
		t.Fatalf("calibrated lastMsgID = %v, want nil (DB row has no RawID)", lastMsgID)
	}
	if got, _ := g.logSeqBaselineSnapshot(); got != 100 {
		// 持久基线本身不能被改写：它仍然代表 .log on 的边界（用于 log off 保护）。
		t.Fatalf("persisted baseline changed to %d, want 100", got)
	}
	if g.needLogSeqCalibration() {
		t.Fatal("calibration should be marked done after a successful query")
	}
	if got := g.GetLogState().ID; got != 0 {
		t.Fatalf("unexpected log id %d", got)
	}

	// 第二条消息不能再改写已校准的结果。
	again, _, ok := calibrateLogSeqBaseline(d, g, 7, lastSeq, nil)
	if !ok || again != 900 {
		t.Fatalf("second calibration = %d, ok=%v, want unchanged 900", again, ok)
	}
}

// TestCalibrateLogSeqBaselineKeepsNewerBaseline 持久基线比数据库新时（刚 .log on）
// 不能用 DB MAX 把基线拉回去。
func TestCalibrateLogSeqBaselineKeepsNewerBaseline(t *testing.T) {
	op := newCalibrationTestDB(t)
	defer op.Close()

	g := &GroupInfo{GroupID: "QQ-Group:1"}
	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}

	lastSeq, lastMsgID, ok := calibrateLogSeqBaseline(d, g, 7, 5000, "msg-5000")
	if !ok || lastSeq != 5000 || lastMsgID != "msg-5000" {
		t.Fatalf("calibration moved baseline backwards: (%d,%v,ok=%v), want (5000,msg-5000)", lastSeq, lastMsgID, ok)
	}
}

// TestCalibrateLogSeqBaselineSkipsWithoutDB 没有数据库/日志 ID 时保持原值。
func TestCalibrateLogSeqBaselineSkipsWithoutDB(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	d := &Dice{Logger: zap.NewNop().Sugar()}
	seq, id, ok := calibrateLogSeqBaseline(d, g, 7, 10, "m")
	if !ok || seq != 10 || id != "m" {
		t.Fatalf("nil DB should not change baseline, got (%d,%v,ok=%v)", seq, id, ok)
	}
	if g.needLogSeqCalibration() || !g.isLogSeqCalibrated() {
		t.Fatal("no DB/log id means calibration is not applicable and must be marked done")
	}
}

// TestLogGapFillTaskCancelsWhenLogStateChanged 覆盖任务排队期间用户 .log off /
// .log new 的情况：此时既不能补录（会写进错误的日志），也不能静默重放
// （指令会被执行，但日志关闭后不再记录）。
func TestLogGapFillTaskCancelsWhenLogStateChanged(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(g *GroupInfo)
	}{
		{"log off", func(g *GroupInfo) { g.SetLogOn(false) }},
		{"switch log", func(g *GroupInfo) { g.SetLogState(8, "run-b", true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fetcher := &recordingHistoryFetcher{}
			endpoint := newGapFillTestEndpoint(fetcher)
			g := &GroupInfo{GroupID: "QQ-Group:1"}
			g.SetLogState(7, "run-a", true)
			task := newGapFillTestTask(g, endpoint, fetcher)
			tc.mutate(g)

			task.run()
			if fetcher.calls != 0 {
				t.Fatalf("gap fill fetched history (%d calls) although the log state changed", fetcher.calls)
			}
		})
	}

	// 对照：日志状态没变时必须继续补录。
	t.Run("log unchanged", func(t *testing.T) {
		fetcher := &recordingHistoryFetcher{empty: true}
		endpoint := newGapFillTestEndpoint(fetcher)
		g := &GroupInfo{GroupID: "QQ-Group:2"}
		g.SetLogState(7, "run-a", true)
		newGapFillTestTask(g, endpoint, fetcher).run()
		if fetcher.calls == 0 {
			t.Fatal("gap fill should still fetch history when the log state is intact")
		}
	})
}

// TestLogGapFillTaskCancelsAfterFetch 覆盖“拉取期间日志被关闭”的窗口：
// 拉取已经完成，但写入前必须再校验一次。
func TestLogGapFillTaskCancelsAfterFetch(t *testing.T) {
	fetcher := &recordingHistoryFetcher{}
	endpoint := newGapFillTestEndpoint(fetcher)
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	task := newGapFillTestTask(g, endpoint, fetcher)
	endpoint.Adapter.(*stubHistoryAdapter).afterFetch = func() { g.SetLogOn(false) }

	task.run()
	if fetcher.calls == 0 {
		t.Fatal("expected the task to fetch history before the log was closed")
	}
	if g.GetLogState().On {
		t.Fatal("test setup: log should be off")
	}
}

// TestLogGapFillFetchHistoryKeepsNewestWindow 大断层超过上限时补最新的一段，
// 而不是最旧的一段。
func TestLogGapFillFetchHistoryKeepsNewestWindow(t *testing.T) {
	d := &Dice{Logger: zap.NewNop().Sugar()}
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	endpoint := newGapFillTestEndpoint(&recordingHistoryFetcher{})

	fetcher := &recordingHistoryFetcher{}
	task := logGapFillTask{
		dice: d, endpoint: endpoint, group: g,
		logID: 7, logName: "run-a", fromSeq: 100, toSeq: 6100,
	}
	msgs, err := task.fetchHistoryOnce(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := int64(6100 - 1 - logGapFillMaxMessages)
	if fetcher.firstFrom != wantStart {
		t.Fatalf("first fetch started at %d, want %d (newest window)", fetcher.firstFrom, wantStart)
	}
	if int64(len(msgs)) != logGapFillMaxMessages {
		t.Fatalf("fetched %d messages, want %d", len(msgs), logGapFillMaxMessages)
	}
	if last := msgs[len(msgs)-1].Seq; last != 6099 {
		t.Fatalf("last fetched seq = %d, want 6099", last)
	}

	// 未超过上限时仍然从头补。
	smallerFetcher := &recordingHistoryFetcher{}
	smallTask := logGapFillTask{
		dice: d, endpoint: endpoint, group: g,
		logID: 7, logName: "run-a", fromSeq: 100, toSeq: 150,
	}
	if _, err := smallTask.fetchHistoryOnce(context.Background(), smallerFetcher); err != nil {
		t.Fatal(err)
	}
	if smallerFetcher.firstFrom != 100 {
		t.Fatalf("small gap should start at fromSeq, got %d", smallerFetcher.firstFrom)
	}
}

// TestLogGapFillWindowMarksOnlyReplayedSeq 重放窗口内的消息才算补录；
// 重放期间实时到达的新消息不能被标成 is_gap_fill。
func TestLogGapFillWindowMarksOnlyReplayedSeq(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	if g.isLogGapFillSeq(105) {
		t.Fatal("no window active: nothing should be marked as gap fill")
	}

	end := g.beginLogGapFillWindow(100, 110)
	if !g.isLogGapFillSeq(105) {
		t.Fatal("message inside the replay window should be marked")
	}
	for _, seq := range []int64{99, 100, 110, 111, 0} {
		if g.isLogGapFillSeq(seq) {
			t.Fatalf("seq %d outside the replay window was marked as gap fill", seq)
		}
	}
	end()
	if g.isLogGapFillSeq(105) {
		t.Fatal("window should be closed after the replay finished")
	}
}

// TestLogGapFillForEachMissingStopsWhenLogClosed 覆盖“补录/重放进行到一半时用户
// .log off”的情况：必须立即停止，否则关掉的日志会被继续写入（用户看到的就是
// off 之后内容还在进日志），静默重放还会继续执行指令却不留记录。
func TestLogGapFillForEachMissingStopsWhenLogClosed(t *testing.T) {
	msgs := []*Message{{Seq: 1}, {Seq: 2}, {Seq: 3}, {Seq: 4}}

	t.Run("log off", func(t *testing.T) {
		g := &GroupInfo{GroupID: "QQ-Group:1"}
		g.SetLogState(7, "run-a", true)
		task := logGapFillTask{dice: &Dice{Logger: zap.NewNop().Sugar()}, group: g, logID: 7, logName: "run-a"}

		seen := 0
		processed := task.forEachMissing(msgs, func(*Message) {
			seen++
			if seen == 2 {
				g.SetLogOn(false)
			}
		})
		if processed != 2 || seen != 2 {
			t.Fatalf("processed=%d seen=%d, want 2 and 2 (must stop right after .log off)", processed, seen)
		}
	})

	t.Run("switch log", func(t *testing.T) {
		g := &GroupInfo{GroupID: "QQ-Group:1"}
		g.SetLogState(7, "run-a", true)
		task := logGapFillTask{dice: &Dice{Logger: zap.NewNop().Sugar()}, group: g, logID: 7, logName: "run-a"}

		seen := 0
		processed := task.forEachMissing(msgs, func(*Message) {
			seen++
			if seen == 1 {
				g.SetLogState(8, "run-b", true)
			}
		})
		if processed != 1 || seen != 1 {
			t.Fatalf("processed=%d seen=%d, want 1 and 1 (must stop after switching log)", processed, seen)
		}
	})

	t.Run("log unchanged", func(t *testing.T) {
		g := &GroupInfo{GroupID: "QQ-Group:1"}
		g.SetLogState(7, "run-a", true)
		task := logGapFillTask{dice: &Dice{Logger: zap.NewNop().Sugar()}, group: g, logID: 7, logName: "run-a"}

		seen := 0
		processed := task.forEachMissing(msgs, func(*Message) { seen++ })
		if processed != len(msgs) || seen != len(msgs) {
			t.Fatalf("processed=%d seen=%d, want %d", processed, seen, len(msgs))
		}
	})
}

// TestLogGapAfterRestartCoversOfflineWindow 对应需求一：
// .log on 之后没有 off/end，骰娘掉线（或进程重启）再上线时，要把掉线期间
// 的缺口补回来。这里模拟“重启后内存基线丢失，只有持久基线 + 数据库”的状态。
func TestLogGapAfterRestartCoversOfflineWindow(t *testing.T) {
	op := newCalibrationTestDB(t) // log 7 已有 seq 800/900
	defer op.Close()
	if err := op.db.Exec("INSERT INTO log_items (log_id, seq, raw_msg_id) VALUES (7, 1100, 'db-1100')").Error; err != nil {
		t.Fatal(err)
	}

	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.LogSeqBaseline = 1000 // .log on 的序号
	g.initLogSeqFromPersisted()

	d := &Dice{Logger: zap.NewNop().Sugar(), DBOperator: op}
	state := GroupLogState{ID: 7, Name: "run-a", On: true}

	// 重启后第一条消息：seq 1151。数据库里真正记录到 1100，
	// 离线窗口是 1101..1150（50 条），必须补这一段。
	fromSeq, _, gap := logGapFromMessage(d, g, state, 1151, "m-1151")
	if fromSeq != 1100 {
		t.Fatalf("fromSeq = %d, want 1100 (last logged seq from DB)", fromSeq)
	}
	if gap != 50 {
		t.Fatalf("gap = %d, want 50 (offline window 1101..1150)", gap)
	}
	// 后续消息按正常推进，不再重复补。
	if _, _, gap2 := logGapFromMessage(d, g, state, 1152, "m-1152"); gap2 != 0 {
		t.Fatalf("next message gap = %d, want 0", gap2)
	}
}

// TestLogGapAfterLogOffNoneFromOffPeriod 对应需求二：
// off 之后绝不补全，off 期间的消息既不算缺口也不推进基线；
// 只有再次 .log on 才会从 on 的那一刻重新起算，且不会回头补 off 段。
func TestLogGapAfterLogOffNoneFromOffPeriod(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")  // .log on
	g.updateLogSeq(1050, "m-1050") // 掉线前最后一条已记录
	onState := GroupLogState{ID: 7, Name: "run-a", On: true}
	offState := GroupLogState{ID: 7, Name: "run-a", On: false}
	d := &Dice{Logger: zap.NewNop().Sugar()}

	// .log off 之后到来的消息 1051..1200：不参与缺口计算，也不推进基线。
	for _, seq := range []int64{1051, 1100, 1200} {
		if from, _, gap := logGapFromMessage(d, g, offState, seq, "off"); gap != 0 || from != 0 {
			t.Fatalf("off-period message seq=%d must not create a gap: from=%d gap=%d", seq, from, gap)
		}
	}
	if last, _, _ := g.updateLogSeq(0, nil); last != 1050 {
		t.Fatalf("off-period messages advanced the baseline to %d, want 1050", last)
	}

	// 再次 .log on：基线重置到 on 那一刻。
	g.SetLogOn(true)
	g.resetLogSeq(1201, "m-1201")
	lastSeq, _, _ := g.updateLogSeq(1202, "m-1202")
	if lastSeq != 1201 {
		t.Fatalf("baseline after re-on = %d, want 1201", lastSeq)
	}

	// 从 off 段之后继续记录，off 段（1051..1200）不能被补进来。
	from, _, gap := logGapFromMessage(d, g, onState, 1202, "m-1202")
	if gap != 0 {
		t.Fatalf("gap after re-on = %d (from=%d), want 0", gap, from)
	}
	// 新一段掉线仍然能正常补：on 之后记到 1250，下一条 1301 → 补 1251..1300。
	g.updateLogSeq(1250, "m-1250")
	from, _, gap = logGapFromMessage(d, g, onState, 1301, "m-1301")
	if from != 1250 || gap != 50 {
		t.Fatalf("gap after new outage = %d from=%d, want 50/1250", gap, from)
	}
}

// TestBotOffSuspendsLogAndBotOnResumes .bot off 让群未激活时，日志被自动暂停：
// 只关 LogOn，保留日志名/ID（不 end、不上传）；.bot on 时自动恢复，
// 并标记“下一条消息只重建基线”。
func TestBotOffSuspendsLogAndBotOnResumes(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")

	if !g.suspendLogForBotOff() {
		t.Fatal("log should be suspended on .bot off")
	}
	state := g.GetLogState()
	if state.On || state.ID != 7 || state.Name != "run-a" {
		t.Fatalf(".bot off should only pause the log, got %+v", state)
	}
	if !g.isLogPausedByBotOff() {
		t.Fatal("pause marker should be set")
	}

	if !g.resumeLogPausedByBotOff() {
		t.Fatal("log should be resumed on .bot on")
	}
	if !g.GetLogState().On || g.isLogPausedByBotOff() {
		t.Fatalf("log not resumed correctly: %+v", g.GetLogState())
	}
	if !g.consumeLogResumeSkipGap() {
		t.Fatal(".bot on should mark the next message to skip gap detection")
	}
	if g.consumeLogResumeSkipGap() {
		t.Fatal("skip marker must only apply once")
	}
}

// TestBotOffDoesNotTouchLogThatWasAlreadyOff 用户已经 .log off 时，.bot off
// 不应把它标记成“待恢复”，.bot on 也不能自己打开日志。
func TestBotOffDoesNotTouchLogThatWasAlreadyOff(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", false)

	if g.suspendLogForBotOff() {
		t.Fatal("already-off log should not be reported as newly suspended")
	}
	if g.isLogPausedByBotOff() {
		t.Fatal("no pause marker should be set")
	}
	if g.resumeLogPausedByBotOff() {
		t.Fatal(".bot on must not turn on a log the user turned off")
	}
	if g.GetLogState().On {
		t.Fatal("log should stay off")
	}
}

// TestBotOnAfterLogEndDoesNotResume .bot off 期间用户 .log end/换日志，以用户操作为准。
func TestBotOnAfterLogEndDoesNotResume(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	if !g.suspendLogForBotOff() {
		t.Fatal("setup: suspend failed")
	}
	g.ClearLogState() // .log end

	if g.resumeLogPausedByBotOff() {
		t.Fatal(".bot on must not resurrect a log that was ended")
	}
	if g.GetLogState().On || g.GetLogState().Name != "" {
		t.Fatalf("log state should stay cleared, got %+v", g.GetLogState())
	}
}

// TestLogGapAfterBotOffNoneFromOffPeriod 需求：.bot off 期间的聊天既不被记录，
// 也不会在 .bot on 之后被当成断层补录；之后的正常掉线仍然能补。
func TestLogGapAfterBotOffNoneFromOffPeriod(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050") // 静默前最后一条已记录

	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := GroupLogState{ID: 7, Name: "run-a", On: true}

	// .bot off：日志暂停；静默期间 1051..1200 不经过这里（群未激活）。
	if !g.suspendLogForBotOff() {
		t.Fatal("setup: suspend failed")
	}
	// .bot on：恢复日志并标记跳过下一次缺口。
	if !g.resumeLogPausedByBotOff() {
		t.Fatal("setup: resume failed")
	}
	g.setLogResumeSkipGap()

	// 恢复后第一条消息 1201：只重建基线，不补静默段。
	if from, _, gap := logGapFromMessage(d, g, state, 1201, "m-1201"); gap != 0 || from != 0 {
		t.Fatalf("first message after .bot on must not create a gap: from=%d gap=%d", from, gap)
	}
	if last, _, _ := g.updateLogSeq(0, nil); last != 1201 {
		t.Fatalf("baseline after .bot on = %d, want 1201", last)
	}

	// 之后的新掉线仍然正常补：记到 1250，下一条 1301 → 补 1251..1300。
	g.updateLogSeq(1250, "m-1250")
	from, _, gap := logGapFromMessage(d, g, state, 1301, "m-1301")
	if from != 1250 || gap != 50 {
		t.Fatalf("gap after a new outage = %d from=%d, want 50/1250", gap, from)
	}
}
