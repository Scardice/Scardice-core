package dice

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedRangeAdapter 为测试提供完整的历史区间：按请求区间过滤预设消息，
// 同时实现 HistoryFetcher 与 HistoryRangeFetcher。
type scriptedRangeAdapter struct {
	*mockPlatformAdapter
	mu       sync.Mutex
	msgs     []*Message
	requests []HistoryRangeRequest
	calls    int
	failNext bool
}

func (a *scriptedRangeAdapter) FetchGroupMsgHistory(context.Context, string, int64, int) ([]*Message, error) {
	return nil, nil
}

func (a *scriptedRangeAdapter) FetchGroupMsgHistoryRange(_ context.Context, req HistoryRangeRequest) (HistoryRangeResult, error) {
	a.mu.Lock()
	a.calls++
	fail := a.failNext
	a.failNext = false
	a.requests = append(a.requests, req)
	a.mu.Unlock()
	if fail {
		return HistoryRangeResult{}, errors.New("transient range failure")
	}
	return HistoryRangeResult{
		Messages:     historyRangeFilter(a.msgs, req.FromSeq, req.ToSeq),
		ReachedStart: true,
	}, nil
}

// offReconcileAdapter 在区间历史之外提供“最新 seq”，用于启动对账测试。
type offReconcileAdapter struct {
	*scriptedRangeAdapter
	latest int64
}

func (a *offReconcileAdapter) FetchLatestHistorySeq(context.Context, string) (int64, interface{}, error) {
	return a.latest, "m-latest", nil
}

type alwaysErrHistoryFetcher struct{}

func (f *alwaysErrHistoryFetcher) FetchGroupMsgHistory(context.Context, string, int64, int) ([]*Message, error) {
	return nil, errors.New("temporary failure")
}

func newTask(d *Dice, ep *EndPointInfo, g *GroupInfo, logID uint64, from, to int64) logGapFillTask {
	return logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: from, toSeq: to, gap: to - from - 1,
		trigger: fix6Msg(g.GroupID, "QQ:fix3-user", to, "after"),
	}
}

func groupMsgsOf(ep *EndPointInfo) []string {
	var mock *mockPlatformAdapter
	switch a := ep.Adapter.(type) {
	case *fix6ScriptedAdapter:
		mock = a.mockPlatformAdapter
	case *scriptedRangeAdapter:
		mock = a.mockPlatformAdapter
	case *offReconcileAdapter:
		mock = a.mockPlatformAdapter
	}
	if mock == nil {
		return nil
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	return append([]string(nil), mock.groupMsgs...)
}

// TestDetectWindowLookbackFixesOffLeak_1120fix3 锁定 P1：识别窗口裁剪后
// 回看被丢弃前缀，找到窗口外的 .log off，窗口内的 off 段不能被补进日志。
func TestDetectWindowLookbackFixesOffLeak_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-lookback-on"
	const senderID = "QQ:fix3-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1001, ".log off")}
	for seq := int64(1002); seq <= 7000; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "off chat"))
	}
	msgs = append(msgs, fix6Msg(groupID, senderID, 7001, ".log on"))
	for seq := int64(7002); seq <= 7999; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "on chat"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1000, 8000)
	newTask(d, ep, g, logID, 1000, 8000).run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 6000, 7000); got != 0 {
		t.Fatalf("off-period rows = %d, want 0 (lookback must find .log off)", got)
	}
	if got := countFix5LogRows(t, d, logID, 7002, 7999); got != 998 {
		t.Fatalf("on-period rows = %d, want 998", got)
	}
	if !g.GetLogState().On {
		t.Fatal("history final state is on; live log must stay on")
	}
	adapter.mu.Lock()
	reqs := append([]HistoryRangeRequest(nil), adapter.requests...)
	adapter.mu.Unlock()
	if len(reqs) != 2 {
		t.Fatalf("requests = %#v, want lookback + prefetch", reqs)
	}
	if reqs[0].FromSeq != 1000 || reqs[0].ToSeq != 3000 {
		t.Fatalf("lookback request = %d..%d, want 1000..3000", reqs[0].FromSeq, reqs[0].ToSeq)
	}
}

// TestDetectWindowLookbackNoOnStaysOff_1120fix3 锁定 P1 的另一种形态：
// 窗口内没有 .log on 时，回看确认起点是 off，窗口内消息一条都不补，
// live 日志也按历史 .log off 关闭。
func TestDetectWindowLookbackNoOnStaysOff_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-lookback-off"
	const senderID = "QQ:fix3-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1001, ".log off")}
	for seq := int64(1002); seq <= 7999; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "off chat"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	ep.Adapter = &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs}
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1000, 8000)
	newTask(d, ep, g, logID, 1000, 8000).run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 6000, 7999); got != 0 {
		t.Fatalf("off-period rows = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("historical .log off outside window must close the live log")
	}
}

// TestDetectWindowLookbackFailureKeepsPending_1120fix3 锁定：回看失败时
// 不能按猜测写入，必须保留 pending 等重试。
func TestDetectWindowLookbackFailureKeepsPending_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-lookback-fail"
	const senderID = "QQ:fix3-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), failNext: true}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1000, 8000)
	newTask(d, ep, g, logID, 1000, 8000).run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 3000, 7999); got != 0 {
		t.Fatalf("rows written after lookback failure = %d, want 0", got)
	}
	// 回看失败时 pending 不能前移：重试仍要按原始缺口重新裁剪并回看。
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 1000 || to != 8000 {
		t.Fatalf("pending = %d..%d, want 1000..8000 (must not advance before lookback)", from, to)
	}
	found := false
	for _, m := range groupMsgsOf(ep) {
		if strings.Contains(m, "无法确认缺口起点状态") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing lookback failure notice, got %#v", groupMsgsOf(ep))
	}
}

// TestPrefetchRetriesTransientError_1120fix3 锁定 P2-1：大缺口预取遇到
// 瞬时错误会重试，而不是整段直接失败等 2 分钟退避。
func TestPrefetchRetriesTransientError_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-prefetch-retry"
	const senderID = "QQ:fix3-user"
	msgs := make([]*Message, 0, 2500)
	for seq := int64(1051); seq <= 3550; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs, failNext: true}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 3551)
	newTask(d, ep, g, logID, 1050, 3551).run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1551, 3550); got != 2000 {
		t.Fatalf("rows = %d, want 2000", got)
	}
	adapter.mu.Lock()
	calls := adapter.calls
	adapter.mu.Unlock()
	if calls != 2 {
		t.Fatalf("prefetch calls = %d, want 2 (one retry)", calls)
	}
}

// TestOffDiscoveryFillCapIncludesTrigger_1120fix3 锁定 P3-3：
// 触发消息也写入日志时，实际补录总数仍不超过 2000。
func TestOffDiscoveryFillCapIncludesTrigger_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-off-cap"
	const senderID = "QQ:fix3-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1101, ".log on")}
	for seq := int64(1102); seq <= 4000; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "on chat"))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, ep, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	task := offDiscoveryTask(t, d, g, ctx, fix6Msg(groupID, senderID, 4001, "after"))
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 2002, 4001); got != 2000 {
		t.Fatalf("rows including trigger = %d, want 2000", got)
	}
	if got := countFix5LogRows(t, d, logID, 1102, 2001); got != 0 {
		t.Fatalf("discarded early rows = %d, want 0", got)
	}
	found := false
	for _, m := range groupMsgsOf(ep) {
		if strings.Contains(m, "超过补录上限 2000 条，较早的 900 条不补录") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing discard notice, got %#v", groupMsgsOf(ep))
	}
}

// TestDiscardNoticeNotLostAcrossRetries_1120fix3 锁定 P3-1：
// pending 保留原始缺口，重试会重新计算丢弃条数；失败提示限频到期后，
// 丢弃说明仍会送达，不会永久丢失。
func TestDiscardNoticeNotLostAcrossRetries_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-discard"
	const senderID = "QQ:fix3-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &alwaysErrHistoryFetcher{})
	defer cleanup()

	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(100, 6000)
	g.logGapFailureNoticeAt.Store(time.Now().Unix())
	newTask(d, ep, g, logID, 100, 6000).run()

	if msgs := groupMsgsOf(ep); len(msgs) != 0 {
		t.Fatalf("rate-limited failure should not send, got %#v", msgs)
	}
	// pending 不随裁剪前移，重试仍按原始缺口重新裁剪。
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 100 || to != 6000 {
		t.Fatalf("pending = %d..%d, want 100..6000", from, to)
	}

	g.logGapFailureNoticeAt.Store(0)
	g.logGapRetryAt.Store(0)
	newTask(d, ep, g, logID, 100, 6000).run()
	msgs := groupMsgsOf(ep)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "超过识别上限 5000 条，较早的 899 条不补录") {
		t.Fatalf("retry should report discard after rate limit, got %#v", msgs)
	}
}

// TestBotHintZeroMissingNotifies_1120fix3 锁定 P3-2：
// .bot on/off 承诺过通知后，0 条补录也要发完成提示。
func TestBotHintZeroMissingNotifies_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-zero-notice"
	const senderID = "QQ:fix3-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(100, 200)
	g.requestLogGapNotifyOnComplete()
	newTask(d, ep, g, logID, 100, 200).run()
	g.logGapWorkerRunning = false

	msgs := groupMsgsOf(ep)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "日志补录完成，没有需要补录的消息") {
		t.Fatalf("missing zero-completion notice, got %#v", msgs)
	}
	if g.logGapNotifyOnCompleteRequested() {
		t.Fatal("notify flag should be cleared after completion notice")
	}
}

// TestOffLogStartupReconcile_1120fix3 锁定 P2-2：启动/重连时 off 日志
// 也会主动扫描离线期间的 .log on，不依赖下一条群消息。
func TestOffLogStartupReconcile_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-off-reconcile"
	const senderID = "QQ:fix3-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1001, ".log on")}
	for seq := int64(1002); seq <= 1060; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "on chat"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &offReconcileAdapter{
		scriptedRangeAdapter: &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs},
		latest:               1060,
	}
	ep.Adapter = adapter
	ep.Enable = true
	ep.State = StateConnected
	found := false
	for _, e := range d.ImSession.EndPoints {
		if e == ep {
			found = true
			break
		}
	}
	if !found {
		d.ImSession.EndPoints = append(d.ImSession.EndPoints, ep)
	}
	g.DiceIDActiveMap.Store(ep.UserID, true)
	if g.DiceIDExistsMap != nil {
		g.DiceIDExistsMap.Store(ep.UserID, true)
	}
	g.SetLogState(logID, "run-a", false)
	g.setLogSeenSeq(1000)

	// 让刚入队的 worker 立即退避，任务区间保留下来供断言；
	// 真正的 off discovery 执行已由 1116fix/1116fix2 用例覆盖。
	g.deferLogGapRetry(time.Hour)
	if !d.reconcileLogGapForGroup(g) {
		t.Fatal("off log should be reconciled at startup")
	}
	if from, to, off := g.pendingLogGapRangeSnapshot(); from != 1000 || to != 1061 || !off {
		t.Fatalf("pending = %d..%d off=%v, want 1000..1061 off=true", from, to, off)
	}
	if g.GetLogState().On {
		t.Fatal("startup reconcile must not open the log before scanning history")
	}
}

// TestWindowLookbackHasNoEffectOnSmallGap_1120fix3 对照：未裁剪的缺口
// 不应发起额外的回看请求。
func TestWindowLookbackHasNoEffectOnSmallGap_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-lookback-small"
	const senderID = "QQ:fix3-user"
	msgs := make([]*Message, 0, 100)
	for seq := int64(1051); seq <= 1150; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 1151)
	newTask(d, ep, g, logID, 1050, 1151).run()
	g.logGapWorkerRunning = false

	adapter.mu.Lock()
	reqs := append([]HistoryRangeRequest(nil), adapter.requests...)
	adapter.mu.Unlock()
	if len(reqs) != 1 || reqs[0].FromSeq != 1050 || reqs[0].ToSeq != 1151 {
		t.Fatalf("small gap requests = %#v, want one 1050..1151", reqs)
	}
}

// TestOffDiscoveryNilTriggerAdopts_1120fix3 锁定启动对账任务的执行形态：
// 没有真实触发消息时，只按历史补录 on 段并恢复日志，不伪造 bot 发言。
func TestOffDiscoveryNilTriggerAdopts_1120fix3(t *testing.T) {
	const groupID = "QQ-Group:1120fix3-off-nil-trigger"
	const senderID = "QQ:fix3-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1001, ".log on")}
	for seq := int64(1002); seq <= 1060; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "on chat"))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, ep, g, _, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	g.logGapWorkerRunning = true
	g.setLogGapPendingRangeMode(1000, 1061, true)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1000, toSeq: 1061, gap: 60,
		discoverFromOff: true,
	}
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1002, 1060); got != 59 {
		t.Fatalf("backfilled rows = %d, want 59", got)
	}
	if got := countFix5LogRows(t, d, logID, 1061, 1061); got != 0 {
		t.Fatalf("synthetic boundary row = %d, want 0", got)
	}
	if !g.GetLogState().On {
		t.Fatal("historical .log on should resume live logging")
	}
	found := false
	for _, m := range groupMsgsOf(ep) {
		if strings.Contains(m, "检测到离线期间的日志记录") && strings.Contains(m, "已补录 59 条") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing off-discovery notice, got %#v", groupMsgsOf(ep))
	}
}
