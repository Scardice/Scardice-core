//nolint:testpackage
package dice

import "testing"

// TestGapTriggerCloneSurvivesMessageRewrite_1116 确认补全任务保存的是触发消息
// 的快照：命令处理器/扩展后续改写原 msg 时，历史状态判断仍使用原始命令文本。
func TestGapTriggerCloneSurvivesMessageRewrite_1116(t *testing.T) {
	msg := &Message{
		Platform:    "QQ",
		MessageType: "group",
		Message:     ".log off",
		Sender:      SenderBase{UserID: "QQ:100"},
		Seq:         100,
	}
	task := logGapFillTask{
		dice:     &Dice{CommandPrefix: []string{".", "。"}},
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:999"}},
		trigger:  cloneGapTriggerMessage(msg),
	}
	// 模拟命令处理器/扩展改写原消息。
	msg.Message = ".r 1d100"
	msg.Sender.UserID = "QQ:200"

	kind, _, _ := task.parseLogLifecycleCommand(task.trigger)
	if kind != "off" {
		t.Fatalf("trigger snapshot kind = %q, want off", kind)
	}
	if task.trigger.Sender.UserID != "QQ:100" {
		t.Fatalf("trigger snapshot sender = %q, want QQ:100", task.trigger.Sender.UserID)
	}
}

// TestHistoricalLogOnDifferentNameStops_1116 .log on <另一本日志> 仍是停止
// 边界：只补它会话前的 on 段，之后不猜新日志，live 不变。
func TestHistoricalLogOnDifferentNameStops_1116(t *testing.T) {
	const groupID = "QQ-Group:1116-on-other"
	const senderID = "QQ:1116-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "on chat"),
		fix6Msg(groupID, senderID, 1052, ".log off"),
		fix6Msg(groupID, senderID, 1053, ".log on run-b"),
		fix6Msg(groupID, senderID, 1054, "new log chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1055, "trigger")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-switch rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1054); got != 0 {
		t.Fatalf("post-switch rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1055, 1055); got != 1 {
		t.Fatalf("live trigger rows = %d, want 1", got)
	}
	if !g.GetLogState().On {
		t.Fatal("log on other name must not change live log state")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalLogOnSameNameResumes_1116 .log on <当前日志名> 恢复 on 段。
func TestHistoricalLogOnSameNameResumes_1116(t *testing.T) {
	const groupID = "QQ-Group:1116-on-same"
	const senderID = "QQ:1116-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "on chat 1"),
		fix6Msg(groupID, senderID, 1052, ".log off"),
		fix6Msg(groupID, senderID, 1053, "off chat"),
		fix6Msg(groupID, senderID, 1054, ".log on run-a"),
		fix6Msg(groupID, senderID, 1055, "on chat 2"),
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

	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("first on segment rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1054); got != 0 {
		t.Fatalf("off segment/.log on rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1055, 1056); got != 2 {
		t.Fatalf("second on segment + trigger rows = %d, want 2", got)
	}
	if !g.GetLogState().On {
		t.Fatal("historical final state is on; live log must stay on")
	}
	g.logGapWorkerRunning = false
}
