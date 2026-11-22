package dice

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

// TestPreOffPendingSurvivesRestart_1120fix2 锁定：.bot off 前遗留的 pending
// 在暂停期间重启后，仍能被识别为 off 前窗口并继续补录。
func TestPreOffPendingSurvivesRestart_1120fix2(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1120fix2-restart"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.setLogGapPendingRange(1050, 1200)
	g.logGapPending = &logGapFillTask{
		group: g, logID: 7, logName: "run-a", fromSeq: 1050, toSeq: 1200,
	}

	if !g.suspendLogForBotOffAtSeq(1500) {
		t.Fatal("suspend failed")
	}
	if g.LogPausedAtSeq != 1500 {
		t.Fatalf("LogPausedAtSeq = %d, want 1500", g.LogPausedAtSeq)
	}
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 1050 || to != 1200 {
		t.Fatalf("pending before restart = %d..%d, want 1050..1200", from, to)
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded GroupInfo
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	reloaded.GroupID = "QQ-Group:1120fix2-restart"
	reloaded.initLogSeqFromPersisted()

	from, to, ok := reloaded.authorizedPreOffGapRange()
	if !ok || from != 1050 || to != 1200 {
		t.Fatalf("pre-off window after restart = %d..%d ok=%v, want 1050..1200", from, to, ok)
	}

	// 暂停之后产生的 pending 不能被误判成 off 前窗口。
	reloaded.setLogGapPendingRange(1500, 1600)
	if _, _, ok := reloaded.authorizedPreOffGapRange(); ok {
		t.Fatal("off-period pending must not be treated as pre-off window")
	}
	reloaded.setLogGapPendingRange(1050, 1200)

	if !reloaded.resumeLogPausedByBotOff() {
		t.Fatal("resume failed")
	}
	if !reloaded.GetLogState().On || reloaded.LogPausedAtSeq != 0 {
		t.Fatalf("after resume on=%v pausedAtSeq=%d", reloaded.GetLogState().On, reloaded.LogPausedAtSeq)
	}
}

// TestGapDetectAndBackfillLimits_1120fix2 锁定新规则：识别最多 5000 条、
// 实际补录最多 2000 条；超出部分丢弃并明确告知。
func TestGapDetectAndBackfillLimits_1120fix2(t *testing.T) {
	const groupID = "QQ-Group:1120fix2-limits"
	const senderID = "QQ:u"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &segmentEchoAdapter{mockPlatformAdapter: newMockPlatformAdapter(), senderID: senderID}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(100, 20000)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 100, toSeq: 20000, gap: 19899,
		trigger: fix6Msg(groupID, senderID, 20000, "after"),
	}
	task.run()
	g.logGapWorkerRunning = false

	// 识别窗口 14999..20000（最近 5000 条）；实际写最近 2000 条 18000..19999。
	if got := countFix5LogRows(t, d, logID, 18000, 19999); got != 2000 {
		t.Fatalf("backfilled rows = %d, want 2000", got)
	}
	if got := countFix5LogRows(t, d, logID, 15000, 17999); got != 0 {
		t.Fatalf("rows beyond backfill cap = %d, want 0", got)
	}
	adapter.mu.Lock()
	msgs := strings.Join(adapter.groupMsgs, "\n")
	reqs := append([]HistoryRangeRequest(nil), adapter.requests...)
	adapter.mu.Unlock()
	// 先回看 9999..15000 确认裁剪窗口起点状态，再预取 14999..20000。
	if len(reqs) != 2 ||
		reqs[0].FromSeq != 9999 || reqs[0].ToSeq != 15000 ||
		reqs[1].FromSeq != 14999 || reqs[1].ToSeq != 20000 {
		t.Fatalf("requests = %#v, want lookback 9999..15000 + prefetch 14999..20000", reqs)
	}
	for _, want := range []string{"14899 条不补录", "3000 条不补录", "识别上限 5000", "补录上限 2000"} {
		if !strings.Contains(msgs, want) {
			t.Fatalf("notice %q missing %q", msgs, want)
		}
	}
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 0 || to != 0 {
		t.Fatalf("pending = %d..%d, want cleared", from, to)
	}
}

// TestLogGapDiscardNoticeOnlyWhenCapped_1120fix2 锁定：未超限时不多出丢弃提示。
func TestLogGapDiscardNoticeOnlyWhenCapped_1120fix2(t *testing.T) {
	var empty logGapFillTask
	if got := empty.logGapDiscardNotice(); got != "" {
		t.Fatalf("empty discard notice = %q", got)
	}

	detect := (logGapFillTask{discardedByDetect: 3}).logGapDiscardNotice()
	for _, want := range []string{"识别上限 5000", "3 条不补录"} {
		if !strings.Contains(detect, want) {
			t.Fatalf("detect discard notice %q missing %q", detect, want)
		}
	}
	limit := (logGapFillTask{discardedByLimit: 7}).logGapDiscardNotice()
	for _, want := range []string{"补录上限 2000", "7 条不补录"} {
		if !strings.Contains(limit, want) {
			t.Fatalf("limit discard notice %q missing %q", limit, want)
		}
	}

	gate := logGapUploadBlockText("结束日志")
	for _, want := range []string{"请等待补全完成通知", ".log halt"} {
		if !strings.Contains(gate, want) {
			t.Fatalf("gate text %q missing %q", gate, want)
		}
	}
}

// TestLogGapClosedStateNotice_1120fix2 锁定关闭时的提示必须说明后续状态：
// 暂停的日志会随 .bot on 恢复；历史 .log off 生效时 .bot on 不会重开。
func TestLogGapClosedStateNotice_1120fix2(t *testing.T) {
	newTask := func(logOn bool, pausedSeq int64, triggerText string) logGapFillTask {
		g := &GroupInfo{GroupID: "QQ-Group:1120fix2-notice"}
		g.SetLogState(1, "run-a", logOn)
		if pausedSeq > 0 {
			if !g.suspendLogForBotOffAtSeq(pausedSeq) {
				t.Fatal("suspend failed")
			}
		}
		task := logGapFillTask{
			group: g, dice: &Dice{CommandPrefix: []string{"."}}, logID: 1, logName: "run-a",
			endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:1"}},
		}
		if triggerText != "" {
			task.trigger = msgWithCommand(triggerText)
		}
		return task
	}

	paused := newTask(true, 10, "")
	if got := paused.logGapClosedStateNotice(0, logGapLifecycleInfo{}); !strings.Contains(got, "日志保持关闭") || !strings.Contains(got, ".bot on 后会恢复") {
		t.Fatalf("paused notice = %q", got)
	}

	botOn := newTask(false, 0, ".bot on")
	got := botOn.logGapClosedStateNotice(2, logGapLifecycleInfo{found: true, finalOn: false})
	for _, want := range []string{"离线期间的 .log off 已生效", "不会自动开启", "已补录关闭前 2 条"} {
		if !strings.Contains(got, want) {
			t.Fatalf("bot-on historical off notice %q missing %q", got, want)
		}
	}

	ordinary := newTask(false, 0, "chat")
	got = ordinary.logGapClosedStateNotice(0, logGapLifecycleInfo{found: true, finalOn: false})
	if !strings.Contains(got, "离线期间的 .log off 已生效，日志保持关闭") {
		t.Fatalf("ordinary historical off notice = %q", got)
	}

	liveOff := newTask(false, 0, ".log off")
	got = liveOff.logGapClosedStateNotice(1, logGapLifecycleInfo{found: true, finalOn: false})
	if !strings.Contains(got, "日志已关闭") || strings.Contains(got, "离线期间") {
		t.Fatalf("live .log off notice = %q", got)
	}
}

// TestBotOffReplyDoesNotPromiseAutoOnWhenGapUnsettled_1120fix2 锁定：有未完成
// 补录时，.bot off 不再承诺“ .bot on 后自动开启”，避免随后历史 .log off
// 生效造成自相矛盾。
func TestBotOffReplyDoesNotPromiseAutoOnWhenGapUnsettled_1120fix2(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	if err := d.DBOperator.GetLogDB(constant.WRITE).AutoMigrate(&model.AttributesItemModel{}); err != nil {
		t.Fatalf("migrate attrs: %v", err)
	}

	ctx, msg := newQuitCommandTestContext(t, d, ep, "QQ:9100", "QQ-Group:1120fix2-botoff", "TmpGroup")
	g := ctx.Group
	g.SetLogState(1, "run-a", true)
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(100, 200)
	g.logGapPending = &logGapFillTask{
		group: g, logID: 1, logName: "run-a", fromSeq: 100, toSeq: 200,
	}
	msg.Seq = 300

	res := d.CmdMap["bot"].Solve(ctx, msg, CommandParse(".bot off", []string{"bot"}, d.CommandPrefix, "QQ", false))
	if !res.Matched || !res.Solved {
		t.Fatalf("bot off result=%#v", res)
	}
	text, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("bot off reply not sent")
	}
	if strings.Contains(text, "bot on 后自动开启") {
		t.Fatalf("reply must not promise auto-on while gap unsettled: %q", text)
	}
	if !strings.Contains(text, "补录完成后会再通知日志状态") {
		t.Fatalf("reply missing unsettled hint: %q", text)
	}
	if !g.logGapNotifyOnCompleteRequested() {
		t.Fatal("bot off promise should set notify-on-complete flag")
	}
}
