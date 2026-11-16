//nolint:testpackage
package dice

import (
	"encoding/json"
	"testing"
)

// newOffDiscoveryEnv 建立一个“live 日志关闭、已见 seq=1000”的群，
// 用于测试核心离线前日志已 off、离线期间发送 .log on 的场景。
func newOffDiscoveryEnv(t *testing.T, groupID, senderID string, fetcher HistoryFetcher) (*Dice, *EndPointInfo, *GroupInfo, *MsgContext, uint64, func()) {
	t.Helper()
	d, ep, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	g.resetLogSeq(1000, "m-1000")
	g.SetLogState(logID, "run-a", false)
	g.setLogSeenSeq(1000)
	g.markLogSeqCalibrated()
	return d, ep, g, ctx, logID, cleanup
}

func offDiscoveryTask(t *testing.T, d *Dice, g *GroupInfo, ctx *MsgContext, trigger *Message) logGapFillTask {
	t.Helper()
	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	if !task.discoverFromOff {
		t.Fatal("expected an off-state discovery task")
	}
	return task
}

// TestOffStateDiscoversLogOnAndResumes_1116fix 掉线前日志 off，离线期间
// 发 .log on 后聊天：恢复后只补 .log on 之后的 on 段，并重新开启 live 日志。
func TestOffStateDiscoversLogOnAndResumes_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-off-on"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, "off chat 1"),
		fix6Msg(groupID, senderID, 1002, "off chat 2"),
		fix6Msg(groupID, senderID, 1003, ".log on"),
		fix6Msg(groupID, senderID, 1004, "on chat 1"),
		fix6Msg(groupID, senderID, 1005, "on chat 2"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1006, "first live message after on")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1003); got != 0 {
		t.Fatalf("pre-on/.log on rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1004, 1006); got != 3 {
		t.Fatalf("on segment + trigger rows = %d, want 3", got)
	}
	if !g.GetLogState().On {
		t.Fatal("historical .log on should resume live logging")
	}
	if g.LogSeqBaseline != 1006 || g.logLastSeq != 1006 {
		t.Fatalf("baseline after resume = (%d,%d), want 1006", g.LogSeqBaseline, g.logLastSeq)
	}
	if g.LogSeenSeq != 0 {
		t.Fatalf("LogSeenSeq after resume = %d, want 0", g.LogSeenSeq)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending after resume = %d..%d, want 0..0", g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	g.logGapWorkerRunning = false
}

// TestOffStateDiscoversLogOnThenOff_1116fix 离线期间 .log on 后又 .log off：
// 补中间的 on 段，但保持 live off。
func TestOffStateDiscoversLogOnThenOff_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-on-off"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, "off chat 1"),
		fix6Msg(groupID, senderID, 1002, ".log on"),
		fix6Msg(groupID, senderID, 1003, "on chat 1"),
		fix6Msg(groupID, senderID, 1004, ".log off"),
		fix6Msg(groupID, senderID, 1005, "off chat 2"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1006, "off period live message")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1002); got != 0 {
		t.Fatalf("pre-on rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1003, 1004); got != 2 {
		t.Fatalf("on segment + .log off rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1005, 1006); got != 0 {
		t.Fatalf("post-off rows = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("historical final state is off; live log must stay off")
	}
	if g.LogSeenSeq != 1006 {
		t.Fatalf("LogSeenSeq = %d, want 1006", g.LogSeenSeq)
	}
	g.logGapWorkerRunning = false
}

// TestOffStateTriggerLogOff_1116fix 离线期间已 .log on，恢复后第一条是
// .log off：补 on 段和这条 off 指令，live 保持 off。
func TestOffStateTriggerLogOff_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-trigger-off"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, "off chat"),
		fix6Msg(groupID, senderID, 1002, ".log on"),
		fix6Msg(groupID, senderID, 1003, "on chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1004, ".log off")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1002); got != 0 {
		t.Fatalf("pre-on/.log on rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1003, 1004); got != 2 {
		t.Fatalf("on segment + trigger .log off rows = %d, want 2", got)
	}
	if g.GetLogState().On {
		t.Fatal("trigger .log off must keep live log off")
	}
	if g.LogSeenSeq != 1004 {
		t.Fatalf("LogSeenSeq = %d, want 1004", g.LogSeenSeq)
	}
	g.logGapWorkerRunning = false
}

// TestOffStateTriggerLogOnAlreadyOn_1116fix 历史已 .log on，恢复后第一条又是
// .log on：这条命令会因“已经开启”失败但被记录，live 保持 on。
func TestOffStateTriggerLogOnAlreadyOn_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-trigger-on-on"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, ".log on"),
		fix6Msg(groupID, senderID, 1002, "on chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1003, ".log on")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1001); got != 0 {
		t.Fatalf("historical .log on rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1002, 1003); got != 2 {
		t.Fatalf("on chat + failed trigger .log on rows = %d, want 2", got)
	}
	if !g.GetLogState().On {
		t.Fatal("live log should be on")
	}
	g.logGapWorkerRunning = false
}

// TestOffStateNoLogOnDoesNotRecord_1116fix 离线期间没有 .log on：
// 整段都不补，live 保持 off。
func TestOffStateNoLogOnDoesNotRecord_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-no-on"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, "off chat 1"),
		fix6Msg(groupID, senderID, 1002, "off chat 2"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1003, "off chat 3")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1003); got != 0 {
		t.Fatalf("rows without .log on = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("live log must stay off")
	}
	if g.LogSeenSeq != 1003 {
		t.Fatalf("LogSeenSeq = %d, want 1003", g.LogSeenSeq)
	}
	g.logGapWorkerRunning = false
}

// TestOffStateTriggerLogOnResumes_1116fix 离线期间只有触发消息本身是 .log on：
// 缺口里没有可补内容，但 live 应从这条 .log on 起恢复记录。
func TestOffStateTriggerLogOnResumes_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-trigger-on"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, "off chat 1"),
		fix6Msg(groupID, senderID, 1002, "off chat 2"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1003, ".log on")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1003); got != 0 {
		t.Fatalf("rows with only trigger .log on = %d, want 0", got)
	}
	if !g.GetLogState().On {
		t.Fatal("trigger .log on should resume live logging")
	}
	if g.LogSeqBaseline != 1003 || g.logLastSeq != 1003 {
		t.Fatalf("baseline after trigger .log on = (%d,%d), want 1003", g.LogSeqBaseline, g.logLastSeq)
	}
	g.logGapWorkerRunning = false
}

// TestOffStateLogOnOtherNameStops_1116fix 离线期间 .log on <另一本日志>：
// 停止发现，不补、不恢复 live。
func TestOffStateLogOnOtherNameStops_1116fix(t *testing.T) {
	const groupID = "QQ-Group:1116fix-other-log"
	const senderID = "QQ:1116.fix-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1001, "off chat"),
		fix6Msg(groupID, senderID, 1002, ".log on run-b"),
		fix6Msg(groupID, senderID, 1003, "new log chat"),
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newOffDiscoveryEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	trigger := fix6Msg(groupID, senderID, 1004, "trigger")
	task := offDiscoveryTask(t, d, g, ctx, trigger)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1001, 1004); got != 0 {
		t.Fatalf("rows switching to another log = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("log on other name must not resume live logging")
	}
	g.logGapWorkerRunning = false
}

// TestOffStateSeenSeqPersistsAcrossReload_1116fix 已见 seq 持久化，重启后仍能
// 从离线前看到的位置开始发现缺口。
func TestOffStateSeenSeqPersistsAcrossReload_1116fix(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1116fix-seen"}
	g.SetLogState(7, "run-a", false)
	g.setLogSeenSeq(12345)

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded GroupInfo
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.logSeenSeqSnapshot(); got != 12345 {
		t.Fatalf("reloaded LogSeenSeq = %d, want 12345", got)
	}
}
