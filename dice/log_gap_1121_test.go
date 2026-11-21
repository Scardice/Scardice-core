package dice

import (
	"strings"
	"testing"
)

// addFix1121ReconcileEndpoint 把端点挂到会话并标记为群内活跃，
// 让 reconcileLogGapForGroup 能选中它。
func addFix1121ReconcileEndpoint(t *testing.T, d *Dice, ep *EndPointInfo, g *GroupInfo) {
	t.Helper()
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
	if g.DiceIDActiveMap == nil {
		g.DiceIDActiveMap = new(SyncMap[string, bool])
	}
	g.DiceIDActiveMap.Store(ep.UserID, true)
	if g.DiceIDExistsMap != nil {
		g.DiceIDExistsMap.Store(ep.UserID, true)
	}
}

// TestStartupReconcileSingleLatestOn_1121 锁定：日志开启时，启动对账在
// “正好只漏 1 条”的情况下也必须入队并落库。旧守卫 latest <= last+1
// 会把唯一一条消息当成没有缺口，重启后没人说话就永久丢失。
func TestStartupReconcileSingleLatestOn_1121(t *testing.T) {
	const groupID = "QQ-Group:1121-reconcile-single-on"
	const senderID = "QQ:1121-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1051, "single missed chat")}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	ep.Adapter = &latestSeqAdapter{
		rangeOnlyStubAdapter: &rangeOnlyStubAdapter{
			mockPlatformAdapter: newMockPlatformAdapter(),
			msgs:                msgs,
			complete:            true,
		},
		seq:   1051,
		rawID: "m-1051",
	}
	addFix1121ReconcileEndpoint(t, d, ep, g)

	if !d.reconcileLogGapForGroup(g) {
		t.Fatal("single missing message must be reconciled at startup")
	}
	waitFix4GapIdle(g)

	if got := countFix5LogRows(t, d, logID, 1051, 1051); got != 1 {
		t.Fatalf("rows 1051..1051 = %d, want 1", got)
	}
	if logGapIncompleteForUpload(g) {
		t.Fatal("pending should be clear after single-message reconcile")
	}
}

// TestStartupReconcileSingleLatestOff_1121 锁定：日志关闭时，离线期间只
// 收到一条 .log on，启动对账也必须发现并恢复记录，而不是等下一句话。
func TestStartupReconcileSingleLatestOff_1121(t *testing.T) {
	const groupID = "QQ-Group:1121-reconcile-single-off"
	const senderID = "QQ:1121-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1051, ".log on")}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	ep.Adapter = &offReconcileAdapter{
		scriptedRangeAdapter: &scriptedRangeAdapter{
			mockPlatformAdapter: newMockPlatformAdapter(),
			msgs:                msgs,
		},
		latest: 1051,
	}
	addFix1121ReconcileEndpoint(t, d, ep, g)
	g.SetLogState(logID, "run-a", false)
	g.setLogSeenSeq(1050)

	if !d.reconcileLogGapForGroup(g) {
		t.Fatal("single offline .log on must be reconciled at startup")
	}
	waitFix4GapIdle(g)

	if !g.GetLogState().On {
		t.Fatal("single offline .log on should resume live logging")
	}
	if got := countFix5LogRows(t, d, logID, 1051, 1051); got != 0 {
		t.Fatalf("rows for .log on itself = %d, want 0", got)
	}
	found := false
	for _, m := range groupMsgsOf(ep) {
		if strings.Contains(m, "日志已恢复记录") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing off-discovery resume notice, got %#v", groupMsgsOf(ep))
	}
}

// TestOffDiscoveryDiscardOnlyNotice_1121 锁定：没有发现任何 .log on/off、
// 只是缺口超过识别上限时，不能谎报“检测到离线期间的日志记录”，
// 只发丢弃说明；若之前承诺过完成通知，再补一条完成提示。
func TestOffDiscoveryDiscardOnlyNotice_1121(t *testing.T) {
	const groupID = "QQ-Group:1121-discard-only"
	const senderID = "QQ:1121-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		discardedByDetect: 500,
	}
	task.sendOffDiscoveryResult(0, false, false, false, false, false)

	msgs := groupMsgsOf(ep)
	if len(msgs) != 1 {
		t.Fatalf("notices = %#v, want exactly one discard notice", msgs)
	}
	if strings.Contains(msgs[0], "检测到离线期间的日志记录") {
		t.Fatalf("discard-only notice must not claim a discovery, got %q", msgs[0])
	}
	if !strings.Contains(msgs[0], "超过识别上限 5000 条，较早的 500 条已丢弃") {
		t.Fatalf("missing discard detail, got %q", msgs[0])
	}

	g.requestLogGapNotifyOnComplete()
	task.sendOffDiscoveryResult(0, false, false, false, false, false)
	msgs = groupMsgsOf(ep)
	if len(msgs) != 2 {
		t.Fatalf("notices after promise = %#v, want two", msgs)
	}
	if !strings.Contains(msgs[1], "超过识别上限 5000 条") ||
		!strings.Contains(msgs[1], "日志补录完成，没有需要补录的消息。") {
		t.Fatalf("promise notice must include discard + completion, got %q", msgs[1])
	}
	if g.logGapNotifyOnCompleteRequested() {
		t.Fatal("notify flag should be cleared after completion notice")
	}
}

// TestOffDiscoveryStoppedOnlyLiveTrigger_1121fix1 锁定：实时触发消息本身是
// .log end/new/halt、历史缺口里没有任何 .log on/off 时，stopped 不能单独
// 被当成“发现了离线日志记录”。没有完成承诺时保持静默；有承诺时只发通用
// 完成提示，不冒充离线发现。
func TestOffDiscoveryStoppedOnlyLiveTrigger_1121fix1(t *testing.T) {
	const groupID = "QQ-Group:1121fix1-stopped-live"
	const senderID = "QQ:1121fix1-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	task := logGapFillTask{dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a"}
	task.sendOffDiscoveryResult(0, false, false, false, true, false)
	if msgs := groupMsgsOf(ep); len(msgs) != 0 {
		t.Fatalf("stopped-only without promise must stay silent, got %#v", msgs)
	}

	g.requestLogGapNotifyOnComplete()
	task.sendOffDiscoveryResult(0, false, false, false, true, false)
	msgs := groupMsgsOf(ep)
	if len(msgs) != 1 {
		t.Fatalf("notices = %#v, want one completion notice", msgs)
	}
	if strings.Contains(msgs[0], "检测到离线期间的日志记录") {
		t.Fatalf("stopped-only live trigger must not claim a discovery, got %q", msgs[0])
	}
	if strings.Contains(msgs[0], "离线期间有") {
		t.Fatalf("stopped-only live trigger must not claim offline log commands, got %q", msgs[0])
	}
	if !strings.Contains(msgs[0], "日志补录完成，没有需要补录的消息。") {
		t.Fatalf("missing completion promise notice, got %q", msgs[0])
	}
	if g.logGapNotifyOnCompleteRequested() {
		t.Fatal("notify flag should be cleared after completion notice")
	}
}

// TestOffDiscoveryStoppedHistoricalNotice_1121fix1 锁定：历史扫描确实发现了
// .log 命令并因此停止时，仍要发“检测到离线期间的日志记录”，并说明是
// 离线期间的日志命令导致停止，不能和实时触发消息混为一谈。
func TestOffDiscoveryStoppedHistoricalNotice_1121fix1(t *testing.T) {
	const groupID = "QQ-Group:1121fix1-stopped-historical"
	const senderID = "QQ:1121fix1-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	task := logGapFillTask{dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a"}
	task.sendOffDiscoveryResult(0, true, false, false, true, true)
	msgs := groupMsgsOf(ep)
	if len(msgs) != 1 {
		t.Fatalf("notices = %#v, want one discovery notice", msgs)
	}
	if !strings.Contains(msgs[0], "检测到离线期间的日志记录") ||
		!strings.Contains(msgs[0], "离线期间有 .log new/end/halt 或切换日志") {
		t.Fatalf("historical stop notice mismatch: %q", msgs[0])
	}

	// 历史有发现，但停止来自实时触发的日志命令：仍说“检测到”，
	// 但停止原因不能写成“离线期间有 .log ...”。
	task.sendOffDiscoveryResult(0, true, false, false, true, false)
	msgs = groupMsgsOf(ep)
	if len(msgs) != 2 {
		t.Fatalf("notices = %#v, want two", msgs)
	}
	if !strings.Contains(msgs[1], "检测到离线期间的日志记录") ||
		!strings.Contains(msgs[1], "已遇到新的日志命令") {
		t.Fatalf("live-trigger stop notice mismatch: %q", msgs[1])
	}
	if strings.Contains(msgs[1], "离线期间有 .log") {
		t.Fatalf("live-trigger stop must not claim historical log commands: %q", msgs[1])
	}
}
