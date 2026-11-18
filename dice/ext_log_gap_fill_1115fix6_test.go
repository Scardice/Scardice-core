//nolint:testpackage
package dice

import (
	"context"
	"fmt"
	"testing"
)

// scriptedHistoryFetcher 按 seq 返回预置历史消息，用于构造离线 .log off/.log on。
type scriptedHistoryFetcher struct {
	msgs  []*Message
	calls int
}

func (f *scriptedHistoryFetcher) FetchGroupMsgHistory(_ context.Context, _ string, fromSeq int64, count int) ([]*Message, error) {
	f.calls++
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

// fix6ScriptedAdapter 让 endpoint.Adapter 满足 HistoryFetcher，fetcher 用接口类型，
// 便于脚本化返回任意历史消息。
type fix6ScriptedAdapter struct {
	*mockPlatformAdapter
	fetcher HistoryFetcher
}

func (a *fix6ScriptedAdapter) FetchGroupMsgHistory(ctx context.Context, groupID string, fromSeq int64, count int) ([]*Message, error) {
	return a.fetcher.FetchGroupMsgHistory(ctx, groupID, fromSeq, count)
}

func newFix6LogGapEnv(t *testing.T, groupID, senderID string, fetcher HistoryFetcher) (*Dice, *EndPointInfo, *GroupInfo, *MsgContext, uint64, func()) {
	t.Helper()
	d, ep, g, ctx, _, logID, cleanup := newLogSegmentTestEnv(t, groupID, senderID)
	g.SetLogState(logID, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")
	g.markLogSeqCalibrated()
	ep.Adapter = &fix6ScriptedAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		fetcher:             fetcher,
	}
	return d, ep, g, ctx, logID, cleanup
}

func fix6Msg(groupID, senderID string, seq int64, text string) *Message {
	m := newGroupMsg(groupID, senderID, text)
	m.Seq = seq
	m.RawID = fmt.Sprintf("m-%d", seq)
	return m
}

// TestHistoricalLogOffOnFiltersGap_1115fix6 缺口内 .log off → .log on：
// 只补 on 段，off 段不写；.log off 本身按实时语义保留，.log on 本身不补。
func TestHistoricalLogOffOnFiltersGap_1115fix6(t *testing.T) {
	const groupID = "QQ-Group:fix6-onoff"
	const senderID = "QQ:fix6-user"
	msgs := make([]*Message, 0, 30)
	for seq := int64(1051); seq <= 1060; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("chat %d", seq)))
	}
	msgs = append(msgs, fix6Msg(groupID, senderID, 1061, ".log off"))
	for seq := int64(1062); seq <= 1070; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("off chat %d", seq)))
	}
	msgs = append(msgs, fix6Msg(groupID, senderID, 1071, ".log on"))
	for seq := int64(1072); seq <= 1080; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("on chat %d", seq)))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1081, "after all")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1061); got != 11 {
		t.Fatalf("first on segment rows = %d, want 11", got)
	}
	if got := countFix5LogRows(t, d, logID, 1062, 1071); got != 0 {
		t.Fatalf("off segment/.log on rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1072, 1081); got != 10 {
		t.Fatalf("second on segment + trigger rows = %d, want 10", got)
	}
	if !g.GetLogState().On {
		t.Fatal("historical final state is on; live log must stay on")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalLogOffWithoutOnTurnsLiveOff_1115fix6 缺口内只有 .log off：
// 补 off 前区间，不补 off 段；历史最终 off 时关闭 live，并删除实时路径
// 已经写进日志的第一条 off 段消息。
func TestHistoricalLogOffWithoutOnTurnsLiveOff_1115fix6(t *testing.T) {
	const groupID = "QQ-Group:fix6-offonly"
	const senderID = "QQ:fix6-user"
	msgs := make([]*Message, 0, 30)
	for seq := int64(1051); seq <= 1060; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("chat %d", seq)))
	}
	msgs = append(msgs, fix6Msg(groupID, senderID, 1061, ".log off"))
	for seq := int64(1062); seq <= 1075; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("off chat %d", seq)))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1076, "off period first live message")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1061); got != 11 {
		t.Fatalf("pre-off rows = %d, want 11", got)
	}
	if got := countFix5LogRows(t, d, logID, 1062, 1076); got != 0 {
		t.Fatalf("off-period/trigger rows = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("historical final state is off; live log must be turned off")
	}
	if g.logOffGapAuthSnapshot() != nil || g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatal("off-gap auth/pending should be cleared after the task")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalLogOffTriggerDeleted_1115fix6 历史 off 段中的第一条实时消息
// 已被 OnMessageReceived 写入，任务必须按 logID+seq 精确删除。
func TestHistoricalLogOffTriggerDeleted_1115fix6(t *testing.T) {
	const groupID = "QQ-Group:fix6-delete"
	const senderID = "QQ:fix6-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "chat"),
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
	trigger := fix6Msg(groupID, senderID, 1054, "should be removed")
	logExt.OnMessageReceived(ctx, trigger)
	if got := countFix5LogRows(t, d, logID, 1054, 1054); got != 1 {
		t.Fatalf("setup trigger rows = %d, want 1", got)
	}
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-off rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1054); got != 0 {
		t.Fatalf("off-period/trigger rows = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("live log must be off")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalFilterAppliesToLiveLogOffTrigger_1115fix6 实时第一条是
// .log off、但缺口内还有历史的 off/on：live off 授权路径也必须按历史区间过滤，
// 不能把历史 off 段当成 off 前窗口补进去。
func TestHistoricalFilterAppliesToLiveLogOffTrigger_1115fix6(t *testing.T) {
	t.Run("historical final on", func(t *testing.T) {
		const groupID = "QQ-Group:fix6-liveoff-on"
		const senderID = "QQ:fix6-user"
		msgs := []*Message{
			fix6Msg(groupID, senderID, 1051, "on 1"),
			fix6Msg(groupID, senderID, 1052, "on 2"),
			fix6Msg(groupID, senderID, 1053, ".log off"),
			fix6Msg(groupID, senderID, 1054, "off 1"),
			fix6Msg(groupID, senderID, 1055, ".log on"),
			fix6Msg(groupID, senderID, 1056, "on again"),
		}
		fetcher := &scriptedHistoryFetcher{msgs: msgs}
		d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
		defer cleanup()

		logExt, ok := d.ExtRegistry.Load("log")
		if !ok {
			t.Fatal("log extension not registered")
		}
		g.logGapWorkerRunning = true
		trigger := fix6Msg(groupID, senderID, 1057, ".log off")
		logExt.OnMessageReceived(ctx, trigger)
		task := popFix5GapTask(t, g)
		if _, ok := g.logOffForUserAtSeq(trigger.Seq); !ok {
			t.Fatal("live .log off should close the log")
		}
		task.run()

		if got := countFix5LogRows(t, d, logID, 1051, 1053); got != 3 {
			t.Fatalf("first on segment rows = %d, want 3", got)
		}
		if got := countFix5LogRows(t, d, logID, 1054, 1055); got != 0 {
			t.Fatalf("historical off segment rows = %d, want 0", got)
		}
		if got := countFix5LogRows(t, d, logID, 1056, 1057); got != 2 {
			t.Fatalf("post-on + live .log off rows = %d, want 2", got)
		}
		if g.GetLogState().On {
			t.Fatal("live log should be off")
		}
		g.logGapWorkerRunning = false
	})

	t.Run("historical final off", func(t *testing.T) {
		const groupID = "QQ-Group:fix6-liveoff-off"
		const senderID = "QQ:fix6-user"
		msgs := []*Message{
			fix6Msg(groupID, senderID, 1051, "on 1"),
			fix6Msg(groupID, senderID, 1052, ".log off"),
			fix6Msg(groupID, senderID, 1053, "off 1"),
		}
		fetcher := &scriptedHistoryFetcher{msgs: msgs}
		d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
		defer cleanup()

		logExt, ok := d.ExtRegistry.Load("log")
		if !ok {
			t.Fatal("log extension not registered")
		}
		g.logGapWorkerRunning = true
		trigger := fix6Msg(groupID, senderID, 1054, ".log off")
		logExt.OnMessageReceived(ctx, trigger)
		task := popFix5GapTask(t, g)
		if _, ok := g.logOffForUserAtSeq(trigger.Seq); !ok {
			t.Fatal("live .log off should close the log")
		}
		task.run()

		if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
			t.Fatalf("pre-off rows = %d, want 2", got)
		}
		// 历史已经 off，实时重复的 .log off 也不该记录。
		if got := countFix5LogRows(t, d, logID, 1053, 1054); got != 0 {
			t.Fatalf("historical off/live .log off rows = %d, want 0", got)
		}
		if g.GetLogState().On {
			t.Fatal("live log should be off")
		}
		g.logGapWorkerRunning = false
	})
}

// TestHistoricalLogOnTriggerKeepsLiveOn_1115fix6 历史 off 后实时第一条是
// .log on：不关闭 live，删除这条本不该记录的 .log on 行，后续继续 on。
func TestHistoricalLogOnTriggerKeepsLiveOn_1115fix6(t *testing.T) {
	const groupID = "QQ-Group:fix6-on-trigger"
	const senderID = "QQ:fix6-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "chat"),
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
	trigger := fix6Msg(groupID, senderID, 1054, ".log on")
	logExt.OnMessageReceived(ctx, trigger)
	if got := countFix5LogRows(t, d, logID, 1054, 1054); got != 1 {
		t.Fatalf("setup .log on trigger rows = %d, want 1", got)
	}
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-off rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1054); got != 0 {
		t.Fatalf("off-period/.log on rows = %d, want 0", got)
	}
	if !g.GetLogState().On {
		t.Fatal("live log must stay on")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalLogNewIgnoredNotStop_1120 离线 .log new 未执行：
// 不能当停止边界，后续消息仍属于当前实际日志并补录。
func TestHistoricalLogNewIgnoredNotStop_1120(t *testing.T) {
	const groupID = "QQ-Group:fix6-new"
	const senderID = "QQ:fix6-user"
	msgs := make([]*Message, 0, 30)
	for seq := int64(1051); seq <= 1060; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("chat %d", seq)))
	}
	msgs = append(msgs, fix6Msg(groupID, senderID, 1061, ".log new run-b"))
	for seq := int64(1062); seq <= 1070; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, fmt.Sprintf("new log chat %d", seq)))
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1071, "trigger")
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1061); got != 11 {
		t.Fatalf("pre-.log new rows = %d, want 11", got)
	}
	if got := countFix5LogRows(t, d, logID, 1062, 1070); got != 9 {
		t.Fatalf("post-.log new rows = %d, want 9 (command not executed)", got)
	}
	if !g.GetLogState().On {
		t.Fatal("unsupported .log new must not change live log state")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalLogOffMentionOtherIgnored_1115fix6 @ 了别人的 .log off
// 不应改变历史状态，按普通消息记录。
func TestHistoricalLogOffMentionOtherIgnored_1115fix6(t *testing.T) {
	const groupID = "QQ-Group:fix6-mention"
	const senderID = "QQ:fix6-user"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "chat"),
		fix6Msg(groupID, senderID, 1052, "[CQ:at,qq=9999] .log off"),
		fix6Msg(groupID, senderID, 1053, "still on"),
	}
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

	if got := countFix5LogRows(t, d, logID, 1051, 1053); got != 3 {
		t.Fatalf("@ 别人的 .log off 不应切 off，rows = %d, want 3", got)
	}
	if !g.GetLogState().On {
		t.Fatal("live log must stay on")
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalUnsupportedLifecycleParse_1115fix6 锁定停止边界的识别：
// .log new/end/halt、.ext off/on log 会停止推断；.bot off/on 自 1115.fix7
// 起完全按普通消息处理，不再停止；无关扩展也不停止。
func TestHistoricalUnsupportedLifecycleParse_1115fix6(t *testing.T) {
	task := logGapFillTask{
		dice:     &Dice{CommandPrefix: []string{"!", ".", "。", "/"}},
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:100000"}},
		group:    &GroupInfo{GroupID: "QQ-Group:1", Players: new(SyncMap[string, *GroupPlayerInfo])},
		logName:  "run-a",
	}
	cases := []struct {
		text     string
		kind     string
		needPriv bool
	}{
		{".log new run-b", "log new", false},
		{".log end", "log end", false},
		{".log halt", "log halt", false},
		{".bot off", "", false},
		{".bot on", "", false},
		{".ext off log", "ext off log", true},
		{".ext on log", "ext on log", true},
		{".ext off all", "ext off all", true},
		{".ext off reply", "", false},
		{".logger off", "", false},
	}
	for _, tc := range cases {
		m := &Message{Platform: "QQ", Message: tc.text}
		kind, _, needPriv := task.parseUnsupportedLogLifecycleCommand(m)
		if kind != tc.kind || needPriv != tc.needPriv {
			t.Errorf("parseUnsupported(%q) = (%q,%v), want (%q,%v)",
				tc.text, kind, needPriv, tc.kind, tc.needPriv)
		}
	}
}

// TestHistoricalLogLifecycleParse_1115fix6 锁定命令解析的边界：
// 粘连写法、大小写、中文前缀、非 lifecycle 文本。
func TestHistoricalLogLifecycleParse_1115fix6(t *testing.T) {
	task := logGapFillTask{
		dice:     &Dice{CommandPrefix: []string{"!", ".", "。", "/"}},
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:100000"}},
		group:    &GroupInfo{GroupID: "QQ-Group:1"},
		logName:  "run-a",
	}
	cases := []struct {
		text string
		kind string
		name string
	}{
		{".log off", "off", ""},
		{".logoff", "off", ""},
		{".LOG OFF", "off", ""},
		{"。log on", "on", ""},
		{"。log on run-a", "on", "run-a"},
		{".log new run-b", "new", "run-b"},
		{".log end", "end", ""},
		{".log halt", "halt", ""},
		{".log off。", "", ""},
		{".logger off", "", ""},
		{"log off", "", ""},
	}
	for _, tc := range cases {
		m := &Message{Platform: "QQ", Message: tc.text}
		kind, name, _ := task.parseLogLifecycleCommand(m)
		if kind != tc.kind || name != tc.name {
			t.Errorf("parse(%q) = (%q,%q), want (%q,%q)", tc.text, kind, name, tc.kind, tc.name)
		}
	}
}
