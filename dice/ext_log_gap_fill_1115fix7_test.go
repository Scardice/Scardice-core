//nolint:testpackage
package dice

import (
	"testing"
)

// TestHistoricalBotOnOffIgnoredContinuesLogScan_1115fix7 锁定 1115.fix7：
// 掉线历史里的 .bot off/.bot on 完全按普通消息处理，不停止扫描；
// 后面的 .log on 仍能被找到并恢复补录。
func TestHistoricalBotOnOffIgnoredContinuesLogScan_1115fix7(t *testing.T) {
	const groupID = "QQ-Group:fix7-botignore"
	const senderID = "QQ:fix7-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "on chat 1"),
		fix6Msg(groupID, senderID, 1052, ".log off"),
		fix6Msg(groupID, senderID, 1053, "off chat 1"),
		fix6Msg(groupID, senderID, 1054, ".bot off"),
		fix6Msg(groupID, senderID, 1055, "off chat 2"),
		fix6Msg(groupID, senderID, 1056, ".bot on"),
		fix6Msg(groupID, senderID, 1057, "off chat 3"),
		fix6Msg(groupID, senderID, 1058, ".log on"),
		fix6Msg(groupID, senderID, 1059, "on chat 2"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1060, "trigger")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-off rows = %d, want 2", got)
	}
	// off 段（含 .bot off/.bot on/.log on 自身）都不补；.bot 命令没有造成停止，
	// 后面的 .log on 仍被识别，所以 1059 之后恢复。
	if got := countFix5LogRows(t, d, logID, 1053, 1058); got != 0 {
		t.Fatalf("off segment rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1059, 1060); got != 2 {
		t.Fatalf("post-on rows = %d, want 2", got)
	}
	if !g.GetLogState().On {
		t.Fatal("historical final state is on; live log must stay on")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalBotOffWithoutLogOffKeepsRecording_1115fix7 锁定离线语义：
// 核心离线期间 .bot off/.bot on 没有执行，不会暂停/恢复日志；只要没有
// .log off，缺口就按 on 段补录。
func TestHistoricalBotOffWithoutLogOffKeepsRecording_1115fix7(t *testing.T) {
	const groupID = "QQ-Group:fix7-botoff-ignore"
	const senderID = "QQ:fix7-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "chat 1"),
		fix6Msg(groupID, senderID, 1052, ".bot off"),
		fix6Msg(groupID, senderID, 1053, "chat 2"),
		fix6Msg(groupID, senderID, 1054, ".bot on"),
		fix6Msg(groupID, senderID, 1055, "chat 3"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1056, "trigger")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1056); got != 6 {
		t.Fatalf("rows with .bot off ignored = %d, want 6", got)
	}
	if !g.GetLogState().On {
		t.Fatal("live log must stay on")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalExtOffLogIgnoredNotStop_1120 离线 .ext off log 未执行：
// 不能当停止边界，后续消息仍按实际日志状态补录。
func TestHistoricalExtOffLogIgnoredNotStop_1120(t *testing.T) {
	const groupID = "QQ-Group:fix7-ext"
	const senderID = "QQ:fix7-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "chat 1"),
	}
	extOff := fix6Msg(groupID, senderID, 1052, ".ext off log")
	extOff.Sender.GroupRole = "admin"
	msgs = append(msgs,
		extOff,
		fix6Msg(groupID, senderID, 1053, "chat 2"),
	)
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1054, "trigger")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-.ext off log rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1053); got != 1 {
		t.Fatalf("post-.ext off log rows = %d, want 1 (command not executed)", got)
	}
	if !g.GetLogState().On {
		t.Fatal("ext stop boundary must not change live log state")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalBotOffLiveTriggerWithHistoricalOff_1115fix7 实时第一条是
// .bot off、缺口历史已经 .log off：历史最终 off 必须覆盖 .bot off 的自动暂停，
// 下次 .bot on 不能把日志重新打开。
func TestHistoricalBotOffLiveTriggerWithHistoricalOff_1115fix7(t *testing.T) {
	const groupID = "QQ-Group:fix7-live-botoff"
	const senderID = "QQ:fix7-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "on chat"),
		fix6Msg(groupID, senderID, 1052, ".log off"),
		fix6Msg(groupID, senderID, 1053, "off chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1054, ".bot off")
	trigger.Sender.GroupRole = "admin"
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	SetBotOffAtGroupAtSeq(ctx, groupID, trigger.Seq)

	task.run()

	if g.GetLogState().On || g.isLogPausedByBotOff() {
		t.Fatalf("historical .log off should clear bot-off pause: on=%v paused=%v",
			g.GetLogState().On, g.isLogPausedByBotOff())
	}
	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-off rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1053); got != 0 {
		t.Fatalf("historical off rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1054, 1054); got != 0 {
		t.Fatalf("live .bot off row = %d, want 0 (historical off applies)", got)
	}
	// 模拟随后 .bot on：历史 .log off 已清除暂停标记，不得自动恢复。
	SetBotOnAtGroup(ctx, groupID)
	if g.GetLogState().On {
		t.Fatal(".bot on must not reopen a log that historical .log off closed")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalBotOnOffParseNotUnsupported_1115fix7 直接锁定 .bot off/on
// 不再被 parseUnsupportedLogLifecycleCommand 识别为停止边界。
func TestHistoricalBotOnOffParseNotUnsupported_1115fix7(t *testing.T) {
	task := logGapFillTask{
		dice:     &Dice{CommandPrefix: []string{"!", ".", "。", "/"}},
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:100000"}},
		group:    &GroupInfo{GroupID: "QQ-Group:1", Players: new(SyncMap[string, *GroupPlayerInfo])},
		logName:  "run-a",
	}
	for _, text := range []string{".bot off", ".bot off 100000", ".bot on", ".boton", ".botoff"} {
		m := &Message{Platform: "QQ", Message: text}
		if kind, _, _ := task.parseUnsupportedLogLifecycleCommand(m); kind != "" {
			t.Errorf("%q must not be an unsupported stop boundary, got %q", text, kind)
		}
	}
}
