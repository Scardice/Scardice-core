//nolint:testpackage
package dice

import (
	"strings"
	"testing"
	"time"
)

// TestOffDiscoveryBackfillSurvivesRealtimeLogOn_1116fix2 锁定 P1-1：
// 重连第一条实时消息又是 .log on 时，真实命令处理器会 reset 基线/epoch；
// 离线期间历史里的 on 段必须由 backfillOnly 任务补回来，不能随旧任务取消。
func TestOffDiscoveryBackfillSurvivesRealtimeLogOn_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-realtime-on"
	const senderID = "QQ:1116.fix2-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, ".log on"),
		fix6Msg(groupID, senderID, 1002, "on chat 1"),
		fix6Msg(groupID, senderID, 1003, "on chat 2"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	cmdLog := logExt.CmdMap["log"]
	if cmdLog == nil {
		t.Fatal("log command not registered")
	}

	trigger := fix6Msg(groupID, senderID, 1004, ".log on")
	g.logGapWorkerRunning = true // 把 worker 卡住，手工控制任务执行顺序
	logExt.OnMessageReceived(ctx, trigger)

	// 模拟真实 .log on 处理器先执行：它会开启日志并把基线重置到 1004。
	res := cmdLog.Solve(ctx, trigger, &CmdArgs{
		Args:      []string{"on", "run-a"},
		RawArgs:   "on run-a",
		CleanArgs: "on run-a",
	})
	if !res.Matched || !res.Solved {
		t.Fatalf("unexpected .log on result: %#v", res)
	}
	if !g.GetLogState().On {
		t.Fatal("live log should be on after real .log on")
	}

	// pending 应已替换成 backfillOnly（新 epoch），执行它补齐 1002/1003。
	task := popFix5GapTask(t, g)
	if !task.discoverFromOff || !task.backfillOnly {
		t.Fatalf("expected off-discovery backfillOnly task, got discoverFromOff=%v backfillOnly=%v",
			task.discoverFromOff, task.backfillOnly)
	}
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1001, 1003); got != 2 {
		t.Fatalf("offline on segment rows = %d, want 2", got)
	}
	if !g.GetLogState().On {
		t.Fatal("live log must stay on")
	}
	if g.LogSeqBaseline != 1004 || g.logLastSeq != 1004 {
		t.Fatalf("baseline after real .log on = (%d,%d), want 1004", g.LogSeqBaseline, g.logLastSeq)
	}
}

// TestOffDiscoveryDoesNotReopenAfterRealtimeBotOff_1116fix2 锁定 P1-2：
// 真实 .bot off 先执行（live 日志本来 off，suspend 不生效），随后 off 发现
// 任务不能把日志重新打开；应保留 bot-off 自动暂停标记，并只补历史 on 段。
func TestOffDiscoveryDoesNotReopenAfterRealtimeBotOff_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-realtime-botoff"
	const senderID = "QQ:1116.fix2-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, ".log on"),
		fix6Msg(groupID, senderID, 1002, "on chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1003, ".bot off")
	task := offDiscoveryTask(t, d, g, ctx, trigger)

	// 模拟真实 .bot off 处理器先执行：群失活；日志本来 off，suspend 返回 false。
	SetBotOffAtGroupAtSeq(ctx, groupID, trigger.Seq)
	if g.IsActiveRaw() {
		t.Fatal("precondition: group should be inactive after .bot off")
	}

	task.run()
	g.logGapWorkerRunning = false

	if g.GetLogState().On {
		t.Fatal("off discovery must not reopen the log after real .bot off")
	}
	if !g.isLogPausedByBotOff() {
		t.Fatal("log should be marked paused so .bot on auto-resumes it")
	}
	if got := countFix5LogRows(t, d, logID, 1001, 1003); got != 1 {
		t.Fatalf("backfilled off-window rows = %d, want 1 (chat only)", got)
	}
	if !g.resumeLogPausedByBotOff() {
		t.Fatal(".bot on should auto-resume the paused log")
	}
	if !g.GetLogState().On {
		t.Fatal("log should be on after .bot on auto-resume")
	}
}

// TestLogGapLongSpanScansFromStart_1116fix2 锁定 P1-3：
// 缺口超过 2000 条时不能只拉最近 2000 条再按 on 起点过滤；必须从缺口
// 起点分段扫描，跨段传递 on/off 状态，否则窗口前的 .log off 会被忽略。
func TestLogGapLongSpanScansFromStart_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-long-gap"
	const senderID = "QQ:1116.fix2-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1100, ".log off")}
	for seq := int64(1101); seq <= 4000; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "off chat"))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 4001, "trigger after long off")
	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1101, 4000); got != 0 {
		t.Fatalf("off-segment rows after long gap = %d, want 0", got)
	}
	// .log off 本身按实时语义保留（实时路径会先记录命令再关闭）。
	if got := countFix5LogRows(t, d, logID, 1100, 1100); got != 1 {
		t.Fatalf(".log off row after long gap = %d, want 1", got)
	}
	if g.GetLogState().On {
		t.Fatal("historical final state is off; live log must stay off")
	}
}

// TestOffDiscoveryResolvesLogAliasKey_1116fix2 锁定 P2-1：
// .log list 展示的 hash key 在历史扫描里也必须解析成同一本日志。
func TestOffDiscoveryResolvesLogAliasKey_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-alias"
	const senderID = "QQ:1116.fix2-user"
	key := logNameHashHex("run-a")[:minLogAliasKeyLength]
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, ".log on "+key),
		fix6Msg(groupID, senderID, 1002, "on chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1003, "after alias on")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1001, 1003); got != 2 {
		t.Fatalf("alias on rows = %d, want 2 (chat + trigger)", got)
	}
	if !g.GetLogState().On {
		t.Fatal("alias .log on should resume live logging")
	}
}

// TestOffStateLongSpanDiscoversLogOn_1116fix2 锁定 off 发现方向的长缺口：
// .log on 在缺口起点附近，远超单段 2000 条；跨段识别后只补最近 2000 条，
// 超出补录上限的较早消息丢弃并告知。
func TestOffStateLongSpanDiscoversLogOn_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-long-off-on"
	const senderID = "QQ:1116.fix2-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1100, ".log on")}
	for seq := int64(1101); seq <= 4000; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "on chat"))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 4001, "after long on")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()
	g.logGapWorkerRunning = false

	// 补录上限 2000 包含触发消息：最近 1999 条 on chat（2002..4000）
	// + 触发消息 4001；2001 让位给触发消息被丢弃。
	if got := countFix5LogRows(t, d, logID, 2002, 4001); got != 2000 {
		t.Fatalf("long off-state on segment rows = %d, want 2000", got)
	}
	if got := countFix5LogRows(t, d, logID, 1101, 2001); got != 0 {
		t.Fatalf("discarded early on rows = %d, want 0", got)
	}
	if !g.GetLogState().On {
		t.Fatal("long off-state .log on should resume live logging")
	}
}

// TestOffDiscoverySendsNotice_1116fix2 锁定 P2-2：补录完成要告知用户。
func TestOffDiscoverySendsNotice_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-notice"
	const senderID = "QQ:1116.fix2-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, ".log on"),
		fix6Msg(groupID, senderID, 1002, "on chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, ep, g, ctx, _, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1003, "after on")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()
	g.logGapWorkerRunning = false

	adapter, ok := ep.Adapter.(*fix6ScriptedAdapter)
	if !ok {
		t.Fatal("unexpected adapter type")
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	found := false
	for _, msg := range adapter.groupMsgs {
		if strings.Contains(msg, "检测到离线期间的日志记录") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("off discovery notice not sent, messages=%v", adapter.groupMsgs)
	}
}

// TestLogOffReplyDuringOffDiscovery_1116fix2 锁定 P2-3：
// 离线 .log on 后重连第一条是 .log off，不能回复“没有找到正在进行的记录”。
func TestLogOffReplyDuringOffDiscovery_1116fix2(t *testing.T) {
	const groupID = "QQ-Group:1116fix2-logoff-reply"
	const senderID = "QQ:1116.fix2-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, ".log on"),
		fix6Msg(groupID, senderID, 1002, "on chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, ep, g, ctx, _, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	cmdLog := logExt.CmdMap["log"]
	if cmdLog == nil {
		t.Fatal("log command not registered")
	}

	trigger := fix6Msg(groupID, senderID, 1003, ".log off")
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, trigger)
	popFix5GapTask(t, g) // pending 区间/标记仍保留，模拟任务尚未执行

	res := cmdLog.Solve(ctx, trigger, &CmdArgs{
		Args:      []string{"off"},
		RawArgs:   "off",
		CleanArgs: "off",
	})
	if !res.Matched || !res.Solved {
		t.Fatalf("unexpected .log off result: %#v", res)
	}
	adapter, ok := ep.Adapter.(*fix6ScriptedAdapter)
	if !ok {
		t.Fatal("unexpected adapter type")
	}
	reply, got := adapter.waitForMsg(3 * time.Second)
	if !got || !strings.Contains(reply, "正在补录") {
		adapter.mu.Lock()
		msgsSent := append([]string(nil), adapter.groupMsgs...)
		adapter.mu.Unlock()
		t.Fatalf(".log off during off discovery should not report missing log, reply=%q messages=%v", reply, msgsSent)
	}
	if !g.logOffRequested() {
		t.Fatal(".log off must leave an explicit-off marker")
	}
	g.logGapWorkerRunning = false
}
