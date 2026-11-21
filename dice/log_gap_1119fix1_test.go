//nolint:testpackage
package dice

import (
	"context"
	"testing"

	"Scardice-core/message"
)

// mixedDialectStore 模拟“忽略 message_id、只认 message_seq”的 OneBot 实现
// （例如经通用 OneBot 适配器接入的 go-cqhttp）。
type mixedDialectStore struct {
	msgs     []*Message
	emptySeq bool
}

func (s *mixedDialectStore) latest(limit int) []*Message {
	if limit <= 0 || limit > len(s.msgs) {
		limit = len(s.msgs)
	}
	return append([]*Message(nil), s.msgs[len(s.msgs)-limit:]...)
}

func (s *mixedDialectStore) fetch(_ context.Context, p onebotHistoryParams) ([]*Message, error) {
	if p.MessageID != 0 {
		// 忽略 message_id，总是返回最新一页（20 条）。
		return s.latest(20), nil
	}
	if p.MessageSeq > 0 {
		if s.emptySeq {
			return nil, nil
		}
		out := make([]*Message, 0, 19)
		for i := len(s.msgs) - 1; i >= 0 && len(out) < 19; i-- {
			if s.msgs[i].Seq <= p.MessageSeq {
				out = append(out, s.msgs[i])
			}
		}
		// 反转成升序，模拟 go-cqhttp 的返回。
		for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
			out[l], out[r] = out[r], out[l]
		}
		return out, nil
	}
	return s.latest(20), nil
}

// TestOnebotRangePartialFallsBackToSeq_1119fix1 锁定 1119 的 P0：
// message_id 路径返回了“最新一页”但没扫到起点时，必须继续走 message_seq
// 回退，不能因为非空就直接返回半段结果。
func TestOnebotRangePartialFallsBackToSeq_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-partial"
	store := &mixedDialectStore{}
	for seq := int64(1); seq <= 300; seq++ {
		store.msgs = append(store.msgs, fix6Msg(groupID, "QQ:1119fix1-user", seq, "chat"))
	}
	req := HistoryRangeRequest{FromSeq: 100, ToSeq: 301, ToRawID: 300}

	// message_id 路径单独跑只会拿到最新 20 条，不能宣称完成。
	msgIDMsgs, msgIDComplete, _, _ := fetchOnebotRangeByMessageID(context.Background(), req, store.fetch)
	if msgIDComplete || len(msgIDMsgs) == 0 {
		t.Fatalf("message_id path = %d msgs, complete=%v; want non-empty partial", len(msgIDMsgs), msgIDComplete)
	}

	result, err := fetchOnebotHistoryRange(context.Background(), req, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ReachedStart {
		t.Fatal("expected seq fallback to cover the whole range")
	}
	msgs := result.Messages
	if len(msgs) != 200 || msgs[0].Seq != 101 || msgs[len(msgs)-1].Seq != 300 {
		t.Fatalf("range = %d..%d (%d), want 101..300 (200)",
			msgs[0].Seq, msgs[len(msgs)-1].Seq, len(msgs))
	}
}

// TestOnebotRangeEmptySeqDoesNotUpgradePartial_1119fix1 锁定：seq 路径返回
// 空页时，不能把 message_id 路径的非空部分页升级成 complete。
func TestOnebotRangeEmptySeqDoesNotUpgradePartial_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-emptyseq"
	store := &mixedDialectStore{emptySeq: true}
	for seq := int64(1); seq <= 300; seq++ {
		store.msgs = append(store.msgs, fix6Msg(groupID, "QQ:1119fix1-user", seq, "chat"))
	}
	req := HistoryRangeRequest{FromSeq: 100, ToSeq: 301, ToRawID: 300}

	result, err := fetchOnebotHistoryRange(context.Background(), req, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if result.Boundary || result.ReachedStart {
		t.Fatalf("empty seq page must not upgrade partial message_id result: reached=%v boundary=%v msgs=%d",
			result.ReachedStart, result.Boundary, len(result.Messages))
	}
	if len(result.Messages) == 0 {
		t.Fatal("expected the partial message_id result to be kept")
	}
}

// TestFetchHistoryOnceWithCoverageIncompleteDoesNotClaimCoverage_1119fix1
// 锁定“未覆盖起点时不能把 maxSeq 当覆盖终点”。
func TestFetchHistoryOnceWithCoverageIncompleteDoesNotClaimCoverage_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-coverage"
	msgs := make([]*Message, 0, 9)
	for seq := int64(291); seq <= 299; seq++ {
		msgs = append(msgs, fix6Msg(groupID, "QQ:1119fix1-user", seq, "chat"))
	}
	stub := &rangeOnlyStubAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		msgs:                msgs,
		complete:            false,
	}
	task := logGapFillTask{
		group:   &GroupInfo{GroupID: groupID},
		fromSeq: 100,
		toSeq:   300,
	}
	got, coveredTo, err := task.fetchHistoryOnceWithCoverage(context.Background(), stub)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 9 {
		t.Fatalf("got %d messages, want 9", len(got))
	}
	if coveredTo != 100 {
		t.Fatalf("coveredTo = %d, want 100 (no forward coverage on incomplete fetch)", coveredTo)
	}
}

// TestLogGapPartialRangeRetainsPending_1119fix1 锁定单段缺口的 P0 表现：
// 只拿到尾部 19 条时必须保留 pending，不能清空后静默丢消息。
func TestLogGapPartialRangeRetainsPending_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-retain"
	const senderID = "QQ:1119fix1-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	msgs := make([]*Message, 0, 19)
	for seq := int64(1181); seq <= 1199; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	ep.Adapter = &rangeOnlyStubAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		msgs:                msgs,
		complete:            false,
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

	from, to, _ := g.pendingLogGapRangeSnapshot()
	if from != 1050 || to != 1200 {
		t.Fatalf("pending = %d..%d, want 1050..1200", from, to)
	}
}

// TestLogGapMultiSegmentPartialDoesNotAdvancePending_1119fix1 锁定大缺口
// 多段识别/重试时最危险的一条：部分页不能把 pending 起点前移到段尾。
func TestLogGapMultiSegmentPartialDoesNotAdvancePending_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-multi"
	const senderID = "QQ:1119fix1-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	msgs := make([]*Message, 0, 20)
	for seq := int64(3031); seq <= 3050; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	ep.Adapter = &rangeOnlyStubAdapter{
		mockPlatformAdapter: newMockPlatformAdapter(),
		msgs:                msgs,
		complete:            false,
	}

	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1050, 3600)
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 1050, toSeq: 3600, gap: 2549,
		trigger: fix6Msg(groupID, senderID, 3600, "after"),
	}
	task.run()
	g.logGapWorkerRunning = false

	from, to, _ := g.pendingLogGapRangeSnapshot()
	if from != 1050 || to != 3600 {
		t.Fatalf("pending = %d..%d, want 1050..3600 (must not advance to partial top)", from, to)
	}
	if got := countFix5LogRows(t, d, logID, 3031, 3050); got != 0 {
		t.Fatalf("partial segment rows = %d, want 0 (prefetch incomplete: write nothing)", got)
	}
}

// TestGroupHasOtherLiveDiceIgnoresDeparted_1119fix1 锁定“已退群但仍启用”的
// 端点不能阻止 .bot off 暂停日志。
func TestGroupHasOtherLiveDiceIgnoresDeparted_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-departed"
	const senderID = "QQ:2274869319"
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx, _ := newQuitCommandTestContext(t, d, ep, senderID, groupID, "DepartedGroup")
	g := ctx.Group
	g.SetLogState(1, "run-a", true)
	g.DiceIDActiveMap.Store("QQ:departed", true)
	g.DiceIDExistsMap.Store(senderID, true)
	d.ImSession.EndPoints = append(d.ImSession.EndPoints, &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{UserID: "QQ:departed", Enable: true},
	})

	SetBotOffAtGroupAtSeq(ctx, groupID, 100)
	if g.IsActiveRaw() || g.GetLogState().On || !g.isLogPausedByBotOff() {
		t.Fatalf("departed dice must not keep group active: active=%v logOn=%v paused=%v",
			g.IsActiveRaw(), g.GetLogState().On, g.isLogPausedByBotOff())
	}
	if g.DiceIDActiveMap.Exists("QQ:departed") {
		t.Fatal("departed dice id should be pruned from active map")
	}

	SetBotOnAtGroup(ctx, groupID)
	if !g.GetLogState().On || g.isLogPausedByBotOff() {
		t.Fatalf("log should auto-resume on .bot on: on=%v paused=%v",
			g.GetLogState().On, g.isLogPausedByBotOff())
	}
}

// TestHistoricalCommandTextReplyPrefix_1119fix1 锁定引用回复/前置非文本段的
// 历史指令识别：离线 .bot off 必须仍被禁执行，.log off 必须仍被识别。
func TestHistoricalCommandTextReplyPrefix_1119fix1(t *testing.T) {
	d := &Dice{CommandPrefix: []string{"."}}
	task := logGapFillTask{
		dice:     d,
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:123"}},
	}
	reply := &message.ReplyElement{ReplySeq: "1"}

	botMsg := &Message{
		Platform: "QQ",
		Message:  "[CQ:reply,id=1].bot off",
		Segment: []message.IMessageElement{
			reply,
			&message.TextElement{Content: ".bot off"},
		},
		Sender: SenderBase{UserID: "QQ:456"},
	}
	if !task.isDeniedReplayCommand(botMsg) {
		t.Fatal("reply-prefixed .bot off must still be denied during replay")
	}

	logMsg := &Message{
		Platform: "QQ",
		Message:  "[CQ:reply,id=1].log off",
		Segment: []message.IMessageElement{
			reply,
			&message.TextElement{Content: ".log off"},
		},
		Sender: SenderBase{UserID: "QQ:456"},
	}
	kind, _, ca := task.parseLogLifecycleCommand(logMsg)
	if kind != "off" {
		t.Fatalf("reply-prefixed .log off kind = %q, want off", kind)
	}
	if !task.lifecycleCommandValid(logMsg, ca) {
		t.Fatal("reply-prefixed .log off should be a valid lifecycle command")
	}

	otherAtMsg := &Message{
		Platform: "QQ",
		Message:  "[CQ:reply,id=1][CQ:at,qq=999].log off",
		Segment: []message.IMessageElement{
			reply,
			&message.AtElement{Target: "999"},
			&message.TextElement{Content: ".log off"},
		},
		Sender: SenderBase{UserID: "QQ:456"},
	}
	kind, _, ca = task.parseLogLifecycleCommand(otherAtMsg)
	if kind != "off" {
		t.Fatalf("leading @other .log off kind = %q, want off", kind)
	}
	if task.lifecycleCommandValid(otherAtMsg, ca) {
		t.Fatal("only @other .log off must not be treated as an executed lifecycle command")
	}
}

// TestRepairOffLogIDByName_1119fix1 锁定关闭日志的 LogCurID 自愈：
// 老群只有 logCurName、没有 logCurId 时，必须按名字补回 ID，离线发现才能工作。
func TestRepairOffLogIDByName_1119fix1(t *testing.T) {
	const groupID = "QQ-Group:1119fix1-offid"
	const senderID = "QQ:1119fix1-user"
	d, _, g, _, _, logID, cleanup := newLogSegmentTestEnv(t, groupID, senderID)
	defer cleanup()

	g.SetLogState(0, "run-a", false)
	g.resetLogSeqBaseline()
	repairPersistedLogState(d, g)
	state := g.GetLogState()
	if state.ID != logID || state.On || state.Name != "run-a" {
		t.Fatalf("repaired state = id:%d on:%v name:%q, want id:%d off run-a",
			state.ID, state.On, state.Name, logID)
	}

	// 名字不存在的关闭日志不能被自动创建。
	g.SetLogState(0, "missing-log", false)
	repairPersistedLogState(d, g)
	if got := g.GetLogState(); got.ID != 0 || got.Name != "missing-log" {
		t.Fatalf("missing log state = id:%d name:%q, want id:0 missing-log", got.ID, got.Name)
	}
}
