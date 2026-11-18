package dice

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/model"
)

// TestLogGapPendingSurvivesRunningTask_1118 锁定：worker 取走任务后 pending 为 nil，
// 新任务到来不能把持久 pending 重置成新窗口；排队任务应覆盖运行中任务的窗口。
func TestLogGapPendingSurvivesRunningTask_1118(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1118-pending"}
	base := logGapFillTask{
		dice: &Dice{Logger: zap.NewNop().Sugar()}, group: g,
		logID: 1, logName: "run-a", epoch: 7,
		fromSeq: 100, toSeq: 500, gap: 399,
	}
	if !g.mergeLogGapTask(base) {
		t.Fatal("first task should start worker")
	}
	// 模拟 worker 已取走任务：logGapPending=nil，但 running 仍指向它。
	g.logGapQueueMu.Lock()
	g.logGapPending = nil
	g.logGapRunningTask = &base
	g.logGapQueueMu.Unlock()

	second := base
	second.fromSeq, second.toSeq, second.gap = 500, 600, 99
	g.mergeLogGapTask(second)

	from, to, _ := g.pendingLogGapRangeSnapshot()
	if from != 100 || to != 600 {
		t.Fatalf("pending after concurrent task = %d..%d, want 100..600", from, to)
	}
	if g.logGapPending == nil || g.logGapPending.fromSeq != 100 || g.logGapPending.toSeq != 600 {
		t.Fatalf("queued task = %#v, want union 100..600", g.logGapPending)
	}
}

type retentionHistoryFetcher struct {
	minSeq int64
	msgs   []*Message
}

func (f *retentionHistoryFetcher) FetchGroupMsgHistory(_ context.Context, _ string, fromSeq int64, count int) ([]*Message, error) {
	if fromSeq < f.minSeq {
		return []*Message{}, nil
	}
	out := make([]*Message, 0, count)
	for _, m := range f.msgs {
		if m == nil || m.Seq <= fromSeq {
			continue
		}
		if len(out) >= count {
			break
		}
		out = append(out, m)
	}
	return out, nil
}

// TestLogGapEmptyFirstSegmentKeepsScanning_1118 锁定：缺口起点早于平台保留期时，
// 第一段空页不能让整个任务结束；后续保留段必须继续补录。
func TestLogGapEmptyFirstSegmentKeepsScanning_1118(t *testing.T) {
	const groupID = "QQ-Group:1118-retention"
	const senderID = "QQ:1118-retention-user"
	msgs := make([]*Message, 0, 1200)
	for seq := int64(3001); seq <= 4200; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "retained chat"))
	}
	fetcher := &retentionHistoryFetcher{minSeq: 3000, msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()
	g.resetLogSeq(1000, "m-1000")

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, fix6Msg(groupID, senderID, 5000, "after long offline"))
	task := popFix5GapTask(t, g)
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 3001, 4200); got != 1200 {
		t.Fatalf("retained rows = %d, want 1200", got)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending not cleared: %d..%d", g.LogGapPendingFrom, g.LogGapPendingTo)
	}
}

type shortPageFetcher struct {
	limit int64
}

func (f *shortPageFetcher) FetchGroupMsgHistory(_ context.Context, _ string, fromSeq int64, _ int) ([]*Message, error) {
	if fromSeq >= f.limit {
		return nil, nil
	}
	return []*Message{{Seq: fromSeq + 1, Sender: SenderBase{UserID: "QQ:1"}}}, nil
}

// TestLogGapPartialPageReportsCoverage_1118 锁定：段内空页返回部分数据时，
// coverage 必须小于段尾，run() 才会从实际覆盖位置继续而不是整段跳过。
func TestLogGapPartialPageReportsCoverage_1118(t *testing.T) {
	task := logGapFillTask{
		dice: &Dice{Logger: zap.NewNop().Sugar()}, group: &GroupInfo{GroupID: "QQ-Group:1118-partial"},
		fromSeq: 0, toSeq: 20,
	}
	msgs, coveredTo, err := task.fetchHistoryOnceWithCoverage(context.Background(), &shortPageFetcher{limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 10 || coveredTo != 10 {
		t.Fatalf("msgs=%d coveredTo=%d, want 10/10", len(msgs), coveredTo)
	}
	if coveredTo >= task.toSeq-1 {
		t.Fatalf("coveredTo=%d should be less than segment end %d", coveredTo, task.toSeq-1)
	}
}

type flakySegmentFetcher struct {
	msgs    []*Message
	okCalls int
	calls   []int64
}

func (f *flakySegmentFetcher) FetchGroupMsgHistory(_ context.Context, _ string, fromSeq int64, count int) ([]*Message, error) {
	f.calls = append(f.calls, fromSeq)
	if len(f.calls) > f.okCalls {
		return nil, context.DeadlineExceeded
	}
	out := make([]*Message, 0, count)
	for _, m := range f.msgs {
		if m == nil || m.Seq <= fromSeq {
			continue
		}
		if len(out) >= count {
			break
		}
		out = append(out, m)
	}
	return out, nil
}

// TestLogGapSegmentFailureKeepsProgress_1118 锁定：分段扫描中途失败时，
// 前面已写入的段保留，pending 起点前移到失败段，不再从原始 fromSeq 重来。
func TestLogGapSegmentFailureKeepsProgress_1118(t *testing.T) {
	const groupID = "QQ-Group:1118-progress"
	const senderID = "QQ:1118-progress-user"
	msgs := make([]*Message, 0, 6500)
	for seq := int64(1001); seq <= 7500; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	fetcher := &flakySegmentFetcher{msgs: msgs, okCalls: 45}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()
	g.resetLogSeq(1000, "m-1000")

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, fix6Msg(groupID, senderID, 7500, "trigger"))
	task := popFix5GapTask(t, g)
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1001, 5000); got != 4000 {
		t.Fatalf("rows from completed segments = %d, want 4000", got)
	}
	if g.LogGapPendingFrom != 5000 || g.LogGapPendingTo != 7500 {
		t.Fatalf("pending = %d..%d, want 5000..7500", g.LogGapPendingFrom, g.LogGapPendingTo)
	}
}

// TestHistoricalLogOffDoesNotBlockLaterOfflineOn_1118 锁定：补录按历史 .log off
// 关闭 live 日志不能留下 logOffRequested，否则之后的离线 .log on 永远不恢复。
func TestHistoricalLogOffDoesNotBlockLaterOfflineOn_1118(t *testing.T) {
	const groupID = "QQ-Group:1118-histon"
	const senderID = "QQ:1118-histon-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1005, ".log off"),
		fix6Msg(groupID, senderID, 1500, ".log on"),
	}
	for seq := int64(1501); seq <= 1600; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "on chat"))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, ep, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()
	g.resetLogSeq(1000, "m-1000")

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, fix6Msg(groupID, senderID, 1010, "after gap"))
	first := popFix5GapTask(t, g)
	first.run()
	g.logGapWorkerRunning = false
	if g.GetLogState().On {
		t.Fatal("precondition: historical .log off should close live log")
	}
	if g.logOffRequested() {
		t.Fatal("historical .log off must not set logOffRequested")
	}

	offState := g.GetLogState()
	g.logGapWorkerRunning = true
	g.detectOffStateLogGap(d, ep, offState, fix6Msg(groupID, senderID, 2000, "after second gap"))
	second := popFix5GapTask(t, g)
	second.run()
	g.logGapWorkerRunning = false

	if !g.GetLogState().On {
		t.Fatal("offline .log on in history was ignored")
	}
	if got := countFix5LogRows(t, d, logID, 1501, 1600); got != 100 {
		t.Fatalf("on segment rows = %d, want 100", got)
	}
}

// TestLogAppendGapFillDedupesBySeq_1118 锁定：平台 raw id 为 "0" 时，
// 补录条目仍按 (log_id, seq) 去重，重试/分段汇总不会重复落库。
func TestLogAppendGapFillDedupesBySeq_1118(t *testing.T) {
	const groupID = "QQ-Group:1118-seqdedupe"
	const senderID = "QQ:1118-seqdedupe-user"
	d, _, _, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()
	seq := int64(4321)
	item := &model.LogOneItem{Message: "dup", RawMsgID: "0", Seq: &seq, IsGapFill: true}
	if !LogAppend(ctx, groupID, logID, "run-a", item) {
		t.Fatal("first append failed")
	}
	if !LogAppend(ctx, groupID, logID, "run-a", item) {
		t.Fatal("duplicate append should be treated as success")
	}
	if got := countFix5LogRows(t, d, logID, seq, seq); got != 1 {
		t.Fatalf("rows for seq %d = %d, want 1", seq, got)
	}
}

func TestLogGapPendingOffFlagCleared_1118(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1118-flag"}
	g.setLogGapPendingRangeMode(100, 200, true)
	g.setLogGapPendingRange(300, 400)
	from, to, off := g.pendingLogGapRangeSnapshot()
	if from != 100 || to != 400 || off {
		t.Fatalf("pending = %d..%d off=%t, want 100..400 off=false", from, to, off)
	}
}
