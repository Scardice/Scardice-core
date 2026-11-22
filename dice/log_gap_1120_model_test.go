//nolint:testpackage
package dice

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	"Scardice-core/message"
)

// fixedRangeAdapter 返回预设的区间覆盖结果，用于锁定 1120 覆盖契约。
type fixedRangeAdapter struct {
	*mockPlatformAdapter
	result HistoryRangeResult
	err    error
}

func (a *fixedRangeAdapter) FetchGroupMsgHistory(context.Context, string, int64, int) ([]*Message, error) {
	return nil, nil
}

func (a *fixedRangeAdapter) FetchGroupMsgHistoryRange(context.Context, HistoryRangeRequest) (HistoryRangeResult, error) {
	return a.result, a.err
}

// pageThenEmptyStore 第一页返回 messages，第二页返回空页；用于验证
// “有进展后的空页”才是平台边界。
type pageThenEmptyStore struct {
	msgs  []*Message
	calls int
}

func (s *pageThenEmptyStore) fetch(_ context.Context, _ onebotHistoryParams) ([]*Message, error) {
	s.calls++
	if s.calls == 1 {
		return append([]*Message(nil), s.msgs...), nil
	}
	return nil, nil
}

// segmentEchoAdapter 按请求区间生成消息，模拟一个完整可覆盖的平台。
type segmentEchoAdapter struct {
	*mockPlatformAdapter
	senderID string
	mu       sync.Mutex
	requests []HistoryRangeRequest
}

func (a *segmentEchoAdapter) FetchGroupMsgHistory(context.Context, string, int64, int) ([]*Message, error) {
	return nil, nil
}

type latestSeqAdapter struct {
	*rangeOnlyStubAdapter
	seq   int64
	rawID interface{}
}

func (a *latestSeqAdapter) FetchLatestHistorySeq(context.Context, string) (int64, interface{}, error) {
	return a.seq, a.rawID, nil
}

func (a *segmentEchoAdapter) FetchGroupMsgHistoryRange(_ context.Context, req HistoryRangeRequest) (HistoryRangeResult, error) {
	a.mu.Lock()
	a.requests = append(a.requests, req)
	a.mu.Unlock()
	msgs := make([]*Message, 0, req.ToSeq-req.FromSeq)
	for seq := req.FromSeq + 1; seq <= req.ToSeq-1; seq++ {
		msgs = append(msgs, fix6Msg(req.GroupID, a.senderID, seq, "chat"))
	}
	return HistoryRangeResult{Messages: msgs, ReachedStart: true}, nil
}

func msgWithCommand(text string, segs ...message.IMessageElement) *Message {
	return &Message{
		Platform: "QQ",
		Message:  text,
		Segment:  segs,
		Sender:   SenderBase{UserID: "QQ:456"},
	}
}

// TestCoverageFirstEmptyPageIsUnknown_1120 锁定：首屏空页不能直接当成
// “平台边界”，否则 SnowLuma 服务端失败/本地库未就绪时会静默清 pending。
func TestCoverageFirstEmptyPageIsUnknown_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-empty"
	adapter := &fixedRangeAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		result:              HistoryRangeResult{},
	}
	task := logGapFillTask{
		group:   &GroupInfo{GroupID: groupID},
		fromSeq: 100,
		toSeq:   300,
	}
	msgs, coveredTo, err := task.fetchHistoryOnceWithCoverage(context.Background(), adapter)
	if !errors.Is(err, errLogGapHistoryNoProgress) {
		t.Fatalf("err = %v, want errLogGapHistoryNoProgress", err)
	}
	if len(msgs) != 0 || coveredTo != 100 {
		t.Fatalf("msgs=%d coveredTo=%d, want 0/100", len(msgs), coveredTo)
	}
}

// TestCoverageEmptyAfterProgressIsBoundary_1120 锁定：有进展后的空页才是
// 平台边界，调用方可以把本段视为“平台能给的就这些”。
func TestCoverageEmptyAfterProgressIsBoundary_1120(t *testing.T) {
	store := &pageThenEmptyStore{}
	for seq := int64(282); seq <= 300; seq++ {
		store.msgs = append(store.msgs, fix6Msg("QQ-Group:1120-page", "QQ:u", seq, "chat"))
	}
	msgs, reached, boundary, err := fetchOnebotRangeBySeq(context.Background(), HistoryRangeRequest{
		FromSeq: 100, ToSeq: 301,
	}, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if reached {
		t.Fatal("should not claim reached start")
	}
	if !boundary {
		t.Fatal("empty page after progress should be a boundary")
	}
	if len(msgs) != 19 {
		t.Fatalf("msgs = %d, want 19", len(msgs))
	}
}

// TestCoverageBoundaryCompletesSegment_1120 锁定：Boundary=true 时调用方
// 可以清除 pending，而不是只看 partial messages。
func TestCoverageBoundaryCompletesSegment_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-boundary"
	const senderID = "QQ:u"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	msgs := make([]*Message, 0, 19)
	for seq := int64(1181); seq <= 1199; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	ep.Adapter = &fixedRangeAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		result:              HistoryRangeResult{Messages: msgs, Boundary: true},
	}
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 1200)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1050, toSeq: 1200, gap: 149,
		trigger: fix6Msg(groupID, senderID, 1200, "after"),
	}
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1181, 1199); got != 19 {
		t.Fatalf("backfilled rows = %d, want 19", got)
	}
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 0 || to != 0 {
		t.Fatalf("pending = %d..%d, want cleared", from, to)
	}
}

// TestHistoricalCommandTextDifferential_1120 差分锁：历史文本与实时
// Segment 文本解析出的命令/参数必须一致（At 信息由 AtParse 另行处理）。
func TestHistoricalCommandTextDifferential_1120(t *testing.T) {
	reply := &message.ReplyElement{ReplySeq: "1"}
	image := &message.ImageElement{File: &message.FileElement{URL: "https://example.com/a.png"}}
	face := &message.FaceElement{FaceID: "1"}
	at := &message.AtElement{Target: "123"}

	cases := []struct {
		name string
		msg  *Message
	}{
		{"plain", msgWithCommand(".log off", &message.TextElement{Content: ".log off"})},
		{"reply", msgWithCommand("[CQ:reply,id=1].log off", reply, &message.TextElement{Content: ".log off"})},
		{"image", msgWithCommand("[CQ:image,file=x].log on run-a", image, &message.TextElement{Content: ".log on run-a"})},
		{"face", msgWithCommand("[CQ:face,id=1].log off", face, &message.TextElement{Content: ".log off"})},
		{"at", msgWithCommand("[CQ:at,qq=123].log off", at, &message.TextElement{Content: ".log off"})},
	}
	for _, tc := range cases {
		liveText := extractResultFromSegments(tc.msg.Segment)
		histText := historicalCommandText(tc.msg)
		live := CommandParse(liveText, []string{"log"}, []string{"."}, "QQ", false)
		hist := CommandParse(histText, []string{"log"}, []string{"."}, "QQ", false)
		if live == nil || hist == nil {
			t.Fatalf("%s: live=%v hist=%v (liveText=%q histText=%q)", tc.name, live, hist, liveText, histText)
		}
		if live.Command != hist.Command || strings.Join(live.Args, " ") != strings.Join(hist.Args, " ") {
			t.Fatalf("%s: live=(%q,%q) hist=(%q,%q)", tc.name,
				live.Command, strings.Join(live.Args, " "),
				hist.Command, strings.Join(hist.Args, " "))
		}
	}
}

// TestLogPhaseInvariants_1120 锁定日志生命周期的合法状态组合。
func TestLogPhaseInvariants_1120(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1120-phase"}
	if g.logPhase() != groupLogPhaseOff || !g.logPhaseValid() {
		t.Fatalf("initial phase=%v valid=%v", g.logPhase(), g.logPhaseValid())
	}
	g.SetLogState(1, "run-a", true)
	if g.logPhase() != groupLogPhaseRecording || !g.logPhaseValid() {
		t.Fatalf("recording phase=%v valid=%v", g.logPhase(), g.logPhaseValid())
	}
	if !g.suspendLogForBotOffAtSeq(10) {
		t.Fatal("suspend should pause an open log")
	}
	if g.logPhase() != groupLogPhasePausedByBotOff || !g.logPhaseValid() {
		t.Fatalf("paused phase=%v valid=%v", g.logPhase(), g.logPhaseValid())
	}
	if !g.resumeLogPausedByBotOff() {
		t.Fatal("resume should reopen")
	}
	if g.logPhase() != groupLogPhaseRecording || !g.logPhaseValid() {
		t.Fatalf("resumed phase=%v valid=%v", g.logPhase(), g.logPhaseValid())
	}
	if _, ok := g.logOffForUserAtSeq(20); !ok {
		t.Fatal("log off should close")
	}
	g.clearLogOffRequested()
	if !g.setLogPausedByBotOff() {
		t.Fatal("paused flag should be accepted on a closed named log")
	}
	if g.logPhase() != groupLogPhasePausedByBotOff || !g.logPhaseValid() {
		t.Fatalf("paused2 phase=%v valid=%v", g.logPhase(), g.logPhaseValid())
	}
	g.ClearLogState()
	if g.logPhase() != groupLogPhaseOff || !g.logPhaseValid() {
		t.Fatalf("cleared phase=%v valid=%v", g.logPhase(), g.logPhaseValid())
	}

	invalid := &GroupInfo{LogOn: true}
	if invalid.logPhaseValid() {
		t.Fatal("LogOn without name must be invalid")
	}
	invalid = &GroupInfo{LogCurName: "run-a", LogPausedByBotOff: true, LogOn: true}
	if invalid.logPhaseValid() {
		t.Fatal("LogOn + PausedByBotOff must be invalid")
	}
}

// TestGroupLiveDiceContract_1120 锁定“启用且仍在本群”的成员契约。
func TestGroupLiveDiceContract_1120(t *testing.T) {
	newGroup := func() *GroupInfo {
		return &GroupInfo{
			GroupID:         "QQ-Group:1120-live",
			DiceIDActiveMap: new(SyncMap[string, bool]),
			DiceIDExistsMap: new(SyncMap[string, bool]),
		}
	}
	session := func(id string, enable bool) *IMSession {
		return &IMSession{EndPoints: []*EndPointInfo{{
			EndPointInfoBase: EndPointInfoBase{UserID: id, Enable: enable},
		}}}
	}

	g := newGroup()
	g.DiceIDActiveMap.Store("QQ:other", true)
	g.DiceIDExistsMap.Store("QQ:me", true)
	g.DiceIDExistsMap.Store("QQ:other", true)
	if !groupHasOtherLiveDice(session("QQ:other", true), g, "QQ:me") {
		t.Fatal("enabled member should count as live")
	}

	g = newGroup()
	g.DiceIDActiveMap.Store("QQ:other", true)
	g.DiceIDExistsMap.Store("QQ:me", true)
	if groupHasOtherLiveDice(session("QQ:other", true), g, "QQ:me") {
		t.Fatal("enabled non-member must not count")
	}
	if g.DiceIDActiveMap.Exists("QQ:other") {
		t.Fatal("non-member active id should be pruned")
	}

	g = newGroup()
	g.DiceIDActiveMap.Store("QQ:other", true)
	g.DiceIDExistsMap.Store("QQ:me", true)
	g.DiceIDExistsMap.Store("QQ:other", true)
	if groupHasOtherLiveDice(session("QQ:other", false), g, "QQ:me") {
		t.Fatal("disabled endpoint must not count")
	}

	g = newGroup()
	g.DiceIDActiveMap.Store("QQ:other", true)
	if !groupHasOtherLiveDice(session("QQ:other", true), g, "QQ:me") {
		t.Fatal("empty ExistsMap should keep legacy behavior")
	}
}

// TestPreOffZeroNotice_1120 锁定：调用方承诺“完成后通知”时，0 条也要收尾。
func TestPreOffZeroNotice_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-zero"
	const senderID = "QQ:u"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &fixedRangeAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		result:              HistoryRangeResult{ReachedStart: true},
	}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 1200)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1050, toSeq: 1200, gap: 149,
		trigger:      fix6Msg(groupID, senderID, 1200, "after"),
		forceLogOnly: true, notifyOnComplete: true,
	}
	task.run()
	g.logGapWorkerRunning = false

	adapter.mu.Lock()
	msgs := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "没有需要补录") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing zero-completion notice, got %#v", msgs)
	}
}

// TestMultiSegmentNoticeCount_1120 锁定：整段只预取一次；补录上限 2000 条，
// 超出部分丢弃并在通知里说明。
func TestMultiSegmentNoticeCount_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-multi"
	const senderID = "QQ:u"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &segmentEchoAdapter{mockPlatformAdapter: newMockPlatformAdapter(), senderID: senderID}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 3551)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1050, toSeq: 3551, gap: 2500,
		trigger: fix6Msg(groupID, senderID, 3551, "after"),
	}
	task.run()
	g.logGapWorkerRunning = false

	// 只补最近的 2000 条：1051..1550 被丢弃，1551..3550 写入。
	if got := countFix5LogRows(t, d, logID, 1551, 3550); got != 2000 {
		t.Fatalf("rows = %d, want 2000 (backfill cap)", got)
	}
	if got := countFix5LogRows(t, d, logID, 1051, 1550); got != 0 {
		t.Fatalf("discarded old rows = %d, want 0", got)
	}
	adapter.mu.Lock()
	msgs := append([]string(nil), adapter.groupMsgs...)
	reqs := append([]HistoryRangeRequest(nil), adapter.requests...)
	adapter.mu.Unlock()
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "2000 条") && strings.Contains(m, "500 条不补录") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("notice should report 2000 backfilled and 500 discarded, got %#v", msgs)
	}
	if len(reqs) != 1 {
		t.Fatalf("prefetch requests = %d, want 1 (not one per segment)", len(reqs))
	}
	if reqs[0].FromSeq != 1050 || reqs[0].ToSeq != 3551 {
		t.Fatalf("prefetch request = %d..%d, want whole gap 1050..3551", reqs[0].FromSeq, reqs[0].ToSeq)
	}
}

// TestMultiSegmentIncompletePrefetchWritesNothing_1120 锁定：整段预取不完整时
// 一条都不写，避免按错误的 on/off 状态把 off 段写进日志。
func TestMultiSegmentIncompletePrefetchWritesNothing_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-multi-incomplete"
	const senderID = "QQ:u"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	partial := make([]*Message, 0, 20)
	for seq := int64(3031); seq <= 3050; seq++ {
		partial = append(partial, fix6Msg(groupID, senderID, seq, "chat"))
	}
	adapter := &fixedRangeAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		result:              HistoryRangeResult{Messages: partial},
	}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 3551)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1050, toSeq: 3551, gap: 2500,
		trigger: fix6Msg(groupID, senderID, 3551, "after"),
	}
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1051, 3550); got != 0 {
		t.Fatalf("rows = %d, want 0 (incomplete prefetch must not write)", got)
	}
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 1050 || to != 3551 {
		t.Fatalf("pending = %d..%d, want 1050..3551", from, to)
	}
	adapter.mu.Lock()
	msgs := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "未完成") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing failure notice, got %#v", msgs)
	}
}

// TestBotOnTriggerAppliesHistoricalOff_1120 实时第一条 .bot on、历史最终 off：
// 必须应用历史 .log off，删除触发消息，并让后续 .bot on 不再自动恢复。
func TestBotOnTriggerAppliesHistoricalOff_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-boton-off"
	const senderID = "QQ:u"
	msgs := []*Message{
		fix6Msg(groupID, senderID, 1051, "on chat"),
		fix6Msg(groupID, senderID, 1052, ".log off"),
		fix6Msg(groupID, senderID, 1053, "off chat"),
	}
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{msgs: msgs})
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1054, ".bot on")
	trigger.Sender.GroupRole = "admin"
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if g.GetLogState().On {
		t.Fatal("historical .log off must close the live log")
	}
	if got := countFix5LogRows(t, d, logID, 1051, 1052); got != 2 {
		t.Fatalf("pre-off rows = %d, want 2", got)
	}
	if got := countFix5LogRows(t, d, logID, 1053, 1053); got != 0 {
		t.Fatalf("off chat rows = %d, want 0", got)
	}
	if got := countFix5LogRows(t, d, logID, 1054, 1054); got != 0 {
		t.Fatalf("live .bot on trigger row = %d, want 0", got)
	}
	SetBotOnAtGroup(ctx, groupID)
	if g.GetLogState().On {
		t.Fatal(".bot on must not reopen after historical .log off")
	}
	g.logGapWorkerRunning = false
}

// TestLogEndBlockedWhileGapIncomplete_1120 补全未完成时 .log end 应阻止上传并提示。
func TestLogEndBlockedWhileGapIncomplete_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-endblock"
	const senderID = "QQ:u"
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()
	g.SetLogState(logID, "run-a", true)
	g.setLogGapPendingRange(1050, 1200)

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	cmdLog := logExt.CmdMap["log"]
	res := cmdLog.Solve(ctx, newGroupMsg(groupID, senderID, ".log end"), &CmdArgs{
		Args: []string{"end"}, RawArgs: "end", CleanArgs: "end",
	})
	if !res.Matched || !res.Solved {
		t.Fatalf("unexpected .log end result: %#v", res)
	}
	if !g.GetLogState().On || g.GetLogState().Name != "run-a" {
		t.Fatalf("log must stay open while gap incomplete: %+v", g.GetLogState())
	}
}

// TestEndpointSupportQQCHAndNoSeq_1120 QQ-CH 和无 message_seq 的纯 OneBot
// 不能再被宣称支持补全，且提示要区分原因。
func TestEndpointSupportQQCHAndNoSeq_1120(t *testing.T) {
	qqch := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "QQ-CH"}, Adapter: &PlatformAdapterGocq{}}
	if endpointSupportsLogGapFill(qqch) {
		t.Fatal("QQ-CH must not support gap fill")
	}
	if notice := logGapFillPlatformNotice(qqch); !strings.Contains(notice, "QQ 频道") {
		t.Fatalf("QQ-CH notice = %q", notice)
	}

	onebot := &PlatformAdapterOnebot{}
	onebot.seqMissing.Store(true)
	noSeq := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "QQ"}, Adapter: onebot}
	if endpointSupportsLogGapFill(noSeq) {
		t.Fatal("OneBot without message_seq must not support gap fill")
	}
	if notice := logGapFillPlatformNotice(noSeq); !strings.Contains(notice, "message_seq") {
		t.Fatalf("no-seq notice = %q", notice)
	}
}

// TestHistoricalCommandTextCQStringReply_1120 go-cqhttp 历史没有 Segment，
// CQ 字符串的引用前缀也必须被剥掉。
func TestHistoricalCommandTextCQStringReply_1120(t *testing.T) {
	task := logGapFillTask{
		dice:     &Dice{CommandPrefix: []string{"."}},
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:1"}},
	}
	m := &Message{Platform: "QQ", Message: "[CQ:reply,id=1].log off", Sender: SenderBase{UserID: "QQ:2"}}
	kind, _, ca := task.parseLogLifecycleCommand(m)
	if kind != "off" || !task.lifecycleCommandValid(m, ca) {
		t.Fatalf("CQ-string reply .log off = %q valid=%v", kind, task.lifecycleCommandValid(m, ca))
	}
	bot := &Message{Platform: "QQ", Message: "[CQ:reply,id=1].bot off", Sender: SenderBase{UserID: "QQ:2"}}
	if !task.isDeniedReplayCommand(bot) {
		t.Fatal("CQ-string reply .bot off must be denied")
	}
}

// TestLogGroupPrefixQQCH_1120 QQ-CH 的 .log list/masterget <id> 应补 QQ-CH-Group。
func TestLogGroupPrefixQQCH_1120(t *testing.T) {
	ctx := &MsgContext{
		PrivilegeLevel: 100,
		EndPoint:       &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "QQ-CH"}},
		Group:          &GroupInfo{GroupID: "QQ-CH-Group:g-c"},
	}
	got, another := getSpecifiedGroupIfMaster(ctx, &Message{}, &CmdArgs{Args: []string{"list", "123"}})
	if !another || got != "QQ-CH-Group:123" {
		t.Fatalf("prefix = %q another=%v", got, another)
	}
}

// TestSnowLumaHistoryWireFormat_1120 回放 SnowLuma get_group_msg_history 的
// 真实字段形状：message_id 为有符号 int32（允许负数）、message_seq 存在、
// message 为段数组。锁定“negative RawID + seq”能被正确解析。
func TestSnowLumaHistoryWireFormat_1120(t *testing.T) {
	const rawPage = `[
		{"message_id":-123456789,"message_seq":1051,"message_type":"group","group_id":123456,"time":1763000000,
		 "sender":{"user_id":456,"nickname":"Tester","card":"Card"},
		 "message":[{"type":"text","data":{"text":"hello"}}]},
		{"message_id":987654321,"message_seq":1052,"message_type":"group","group_id":123456,"time":1763000001,
		 "sender":{"user_id":456,"nickname":"Tester","card":"Card"},
		 "message":[{"type":"reply","data":{"id":"-123456789"}},{"type":"text","data":{"text":".log off"}}]}
	]`
	items := gjson.Parse(rawPage).Array()
	if len(items) != 2 {
		t.Fatalf("fixture messages = %d, want 2", len(items))
	}
	log := zap.NewNop().Sugar()
	first, err := arrayByte2ScardiceMessage(log, []byte(items[0].Raw))
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1051 || first.RawID != "-123456789" {
		t.Fatalf("first seq=%d rawID=%v, want 1051/-123456789", first.Seq, first.RawID)
	}
	if first.Message != "hello" || first.Sender.UserID != "QQ:456" {
		t.Fatalf("first message=%q sender=%q", first.Message, first.Sender.UserID)
	}
	if id, ok := rawIDToInt64(first.RawID); !ok || id != -123456789 {
		t.Fatalf("rawIDToInt64 = %d,%v", id, ok)
	}

	second, err := arrayByte2ScardiceMessage(log, []byte(items[1].Raw))
	if err != nil {
		t.Fatal(err)
	}
	if second.Seq != 1052 || second.Message != "[CQ:reply,id=-123456789].log off" {
		t.Fatalf("second seq=%d message=%q", second.Seq, second.Message)
	}
	if kind, _, _ := (&logGapFillTask{dice: &Dice{CommandPrefix: []string{"."}}}).parseLogLifecycleCommand(second); kind != "off" {
		t.Fatalf("reply-prefixed .log off kind=%q, want off", kind)
	}
}

// TestLogGapFetchFailureNotice_1120 单段拉取失败也要给群内限频提示，不能只写核心日志。
func TestLogGapFetchFailureNotice_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-failnotice"
	const senderID = "QQ:u"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &fixedRangeAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		err:                 errors.New("boom"),
	}
	ep.Adapter = adapter
	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 1200)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1050, toSeq: 1200, gap: 149,
		trigger: fix6Msg(groupID, senderID, 1200, "after"),
	}
	task.run()
	g.logGapWorkerRunning = false

	adapter.mu.Lock()
	msgs := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "拉取失败") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing fetch failure notice, got %#v", msgs)
	}
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 1050 || to != 1200 {
		t.Fatalf("pending = %d..%d, want 1050..1200", from, to)
	}
}

// TestStartupReconcileEnqueuesGap_1120 启动对账不依赖新消息：取最新历史 seq
// 与本地已记录 seq 比较，有缺口就入队。
func TestStartupReconcileEnqueuesGap_1120(t *testing.T) {
	const groupID = "QQ-Group:1120-startup"
	const senderID = "QQ:u"
	d, ep, g, _, _, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	adapter := &latestSeqAdapter{
		rangeOnlyStubAdapter: &rangeOnlyStubAdapter{mockPlatformAdapter: newMockPlatformAdapter()},
		seq:                  1060,
		rawID:                "m-1060",
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
	// 让 worker 立即退避，保留 pending 以便断言；对账本身不看 retryAt。
	g.deferLogGapRetry(time.Hour)

	if !d.reconcileLogGapForGroup(g) {
		t.Fatal("reconcile should enqueue a gap task")
	}
	from, to, _ := g.pendingLogGapRangeSnapshot()
	if from != 1050 || to != 1061 {
		t.Fatalf("pending = %d..%d, want 1050..1061 (latest included)", from, to)
	}
}
