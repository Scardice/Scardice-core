//nolint:testpackage
package dice

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"Scardice-core/model"
)

// snowLumaHistoryStore 模拟 SnowLumaEx 的 get_group_msg_history：
// 只认 message_id；message_id=0 取最新 count 条；有锚点时返回锚点及更旧。
type snowLumaHistoryStore struct {
	msgs []*Message
	ids  map[int64]int64
}

func newSnowLumaHistoryStore(from, to int64) *snowLumaHistoryStore {
	s := &snowLumaHistoryStore{ids: map[int64]int64{}}
	for seq := from; seq <= to; seq++ {
		m := &Message{Seq: seq, RawID: fmt.Sprintf("%d", 100000+seq)}
		s.msgs = append(s.msgs, m)
		s.ids[seq] = 100000 + seq
	}
	return s
}

func (s *snowLumaHistoryStore) fetch(_ context.Context, p onebotHistoryParams) ([]*Message, error) {
	limit := p.Count
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	anchorSeq := int64(1<<62 - 1)
	if p.MessageID != 0 {
		found := false
		for seq, id := range s.ids {
			if id == p.MessageID {
				anchorSeq = seq
				found = true
				break
			}
		}
		if !found {
			anchorSeq = int64(1<<62 - 1) // 未知锚点：SnowLuma 回退到本地最新页
		}
	}
	out := make([]*Message, 0, limit)
	for i := len(s.msgs) - 1; i >= 0 && len(out) < limit; i-- {
		if s.msgs[i].Seq <= anchorSeq {
			out = append(out, s.msgs[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

func TestOnebotRangeMessageIDKeepsFirstMissing_1119(t *testing.T) {
	store := newSnowLumaHistoryStore(1001, 1081)
	req := HistoryRangeRequest{
		FromSeq:   1050,
		ToSeq:     1081,
		ToRawID:   fmt.Sprintf("%d", store.ids[1081]),
		FromRawID: fmt.Sprintf("%d", store.ids[1050]),
	}
	msgs, complete, _, err := fetchOnebotRangeByMessageID(context.Background(), req, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("expected complete")
	}
	if len(msgs) != 30 {
		t.Fatalf("got %d messages, want 30", len(msgs))
	}
	if msgs[0].Seq != 1051 {
		t.Fatalf("first seq = %d, want 1051 (the previously lost message)", msgs[0].Seq)
	}
}

func TestOnebotRangeMessageIDPagesLargeGap_1119(t *testing.T) {
	store := newSnowLumaHistoryStore(1, 501)
	req := HistoryRangeRequest{
		FromSeq: 100,
		ToSeq:   501,
		ToRawID: fmt.Sprintf("%d", store.ids[501]),
	}
	msgs, complete, _, err := fetchOnebotRangeByMessageID(context.Background(), req, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("expected complete")
	}
	if len(msgs) != 400 || msgs[0].Seq != 101 || msgs[len(msgs)-1].Seq != 500 {
		t.Fatalf("range = %d..%d (%d), want 101..500 (400)", msgs[0].Seq, msgs[len(msgs)-1].Seq, len(msgs))
	}
}

// gocqHistoryStore 模拟 go-cqhttp：message_seq 是窗口终点、向旧返回；
// 每页最多 19 条，count 被忽略。
type gocqHistoryStore struct {
	msgs []*Message
}

func newGocqHistoryStore(from, to int64) *gocqHistoryStore {
	s := &gocqHistoryStore{}
	for seq := from; seq <= to; seq++ {
		s.msgs = append(s.msgs, &Message{Seq: seq, RawID: seq})
	}
	return s
}

func (s *gocqHistoryStore) fetch(_ context.Context, anchor int64, _ int) ([]*Message, error) {
	out := make([]*Message, 0, 19)
	for i := len(s.msgs) - 1; i >= 0 && len(out) < 19; i-- {
		if s.msgs[i].Seq <= anchor {
			out = append(out, s.msgs[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

func TestFetchHistoryBySeqBackwardGocq_1119(t *testing.T) {
	store := newGocqHistoryStore(1, 300)
	msgs, complete, _, err := fetchHistoryBySeqBackward(context.Background(), 100, 301, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("expected complete")
	}
	if len(msgs) != 200 || msgs[0].Seq != 101 || msgs[len(msgs)-1].Seq != 300 {
		t.Fatalf("range = %d..%d (%d), want 101..300 (200)", msgs[0].Seq, msgs[len(msgs)-1].Seq, len(msgs))
	}
}

// seqOnlyHistoryStore 模拟“只认 message_seq、忽略 message_id”的实现。
type seqOnlyHistoryStore struct {
	msgs []*Message
}

func (s *seqOnlyHistoryStore) fetch(_ context.Context, p onebotHistoryParams) ([]*Message, error) {
	limit := p.Count
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	anchor := p.MessageSeq
	if anchor <= 0 {
		anchor = int64(1<<62 - 1) // 忽略 message_id，返回最新页
	}
	out := make([]*Message, 0, limit)
	for i := len(s.msgs) - 1; i >= 0 && len(out) < limit; i-- {
		if s.msgs[i].Seq <= anchor {
			out = append(out, s.msgs[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

func TestOnebotRangeFallsBackToSeq_1119(t *testing.T) {
	store := &seqOnlyHistoryStore{}
	// 多放 300 条 toSeq 之后的消息：忽略 message_id 的实现会一直返回
	// 这些最新页，窗口内一条都拿不到，必须回退到 message_seq。
	for seq := int64(1); seq <= 600; seq++ {
		store.msgs = append(store.msgs, &Message{Seq: seq, RawID: seq})
	}
	req := HistoryRangeRequest{FromSeq: 100, ToSeq: 301, ToRawID: 300}

	// message_id 语义下会反复拿到最新页，oldest 不前进 → 无进度/空结果。
	if msgs, complete, _, _ := fetchOnebotRangeByMessageID(context.Background(), req, store.fetch); complete || len(msgs) > 0 {
		t.Fatalf("message_id path should not make progress: complete=%v msgs=%d", complete, len(msgs))
	}
	msgs, complete, _, err := fetchOnebotRangeBySeq(context.Background(), req, store.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !complete || len(msgs) != 200 || msgs[0].Seq != 101 || msgs[len(msgs)-1].Seq != 300 {
		t.Fatalf("seq fallback = %d..%d (%d) complete=%v, want 101..300 (200)", msgs[0].Seq, msgs[len(msgs)-1].Seq, len(msgs), complete)
	}
}

func TestFilterAlreadyLoggedRawIDMismatch_1119(t *testing.T) {
	const groupID = "QQ-Group:1119-dedupe"
	const senderID = "QQ:1119-dedupe-user"
	d, _, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	seq := int64(500)
	old := &model.LogOneItem{Message: "old", RawMsgID: "old-id", Seq: &seq, IsGapFill: true}
	if !LogAppend(ctx, groupID, logID, "run-a", old) {
		t.Fatal("append old row failed")
	}
	task := logGapFillTask{dice: d, group: g, logID: logID, logName: "run-a", fromSeq: 400, toSeq: 600}

	// raw id 不同：平台 seq 重置后这是另一条消息，必须保留。
	kept, ok := task.filterAlreadyLogged([]*Message{{Seq: seq, RawID: "new-id"}})
	if !ok || len(kept) != 1 {
		t.Fatalf("raw id mismatch kept=%d ok=%v, want 1/true", len(kept), ok)
	}
	// raw id 不可用（"0"）时仍按 seq 去重。
	kept, ok = task.filterAlreadyLogged([]*Message{{Seq: seq, RawID: "0"}})
	if !ok || len(kept) != 0 {
		t.Fatalf("raw-id-unusable kept=%d ok=%v, want 0/true", len(kept), ok)
	}
}

func TestGroupHasOtherLiveDicePrunesStale_1119(t *testing.T) {
	const groupID = "QQ-Group:1119-stale"
	const senderID = "QQ:2274869319"
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx, _ := newQuitCommandTestContext(t, d, ep, senderID, groupID, "StaleGroup")
	g := ctx.Group
	g.SetLogState(1, "run-a", true)
	g.DiceIDActiveMap.Store("QQ:3632018625", true) // 已从端点列表删除
	g.DiceIDActiveMap.Store("QQ:3780648669", true) // 仍在列表但 Enable=false
	d.ImSession.EndPoints = append(d.ImSession.EndPoints, &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{UserID: "QQ:3780648669", Enable: false},
	})

	SetBotOffAtGroupAtSeq(ctx, groupID, 100)
	if g.IsActiveRaw() {
		t.Fatal("group should be deactivated after ignoring stale/disabled dice ids")
	}
	if g.GetLogState().On || !g.isLogPausedByBotOff() {
		t.Fatalf("log should be auto-paused: on=%v paused=%v", g.GetLogState().On, g.isLogPausedByBotOff())
	}
	if g.DiceIDActiveMap.Exists("QQ:3632018625") || g.DiceIDActiveMap.Exists("QQ:3780648669") {
		t.Fatalf("stale/disabled ids should be pruned: %v", keysOfMap(g.DiceIDActiveMap))
	}

	SetBotOnAtGroup(ctx, groupID)
	if !g.GetLogState().On || g.isLogPausedByBotOff() {
		t.Fatalf("log should auto-resume on .bot on: on=%v paused=%v", g.GetLogState().On, g.isLogPausedByBotOff())
	}
}

func keysOfMap(m *SyncMap[string, bool]) []string {
	var out []string
	m.Range(func(k string, _ bool) bool {
		out = append(out, k)
		return true
	})
	return out
}

func TestOfficialQQDropUnsupportedMedia_1119(t *testing.T) {
	units := []officialQQMsgUnit{
		{text: "a"},
		{text: "[CQ:image,file=x]", media: true},
		{text: "b"},
		{text: "[CQ:file,file=y]", media: true},
		{text: "c"},
	}
	if got := officialQQDropUnsupportedMedia(units, OpenQQCHChannel); len(got) != 3 {
		t.Fatalf("channel units = %d, want 3", len(got))
	}
	if got := officialQQDropUnsupportedMedia(units, OpenQQCHUser); len(got) != 3 {
		t.Fatalf("channel DM units = %d, want 3", len(got))
	}
	if got := officialQQDropUnsupportedMedia(units, OpenQQGroupOpenid); len(got) != 5 {
		t.Fatalf("group units = %d, want 5 (unchanged)", len(got))
	}
}

func TestMentionsOtherUserMixedAt_1119(t *testing.T) {
	task := logGapFillTask{endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:bot"}}}
	bot := &AtInfo{UserID: "QQ:bot"}
	other := &AtInfo{UserID: "QQ:other"}
	cases := []struct {
		name string
		at   []*AtInfo
		want bool
	}{
		{"none", nil, false},
		{"bot only", []*AtInfo{bot}, false},
		{"other only", []*AtInfo{other}, true},
		{"bot + other", []*AtInfo{bot, other}, false},
		{"other + bot", []*AtInfo{other, bot}, false},
	}
	for _, tc := range cases {
		if got := task.mentionsOtherUser(&CmdArgs{At: tc.at}); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

type rangeOnlyStubAdapter struct {
	*mockPlatformAdapter
	msgs     []*Message
	complete bool
}

func (a *rangeOnlyStubAdapter) FetchGroupMsgHistory(context.Context, string, int64, int) ([]*Message, error) {
	return nil, nil
}

func (a *rangeOnlyStubAdapter) FetchGroupMsgHistoryRange(context.Context, HistoryRangeRequest) (HistoryRangeResult, error) {
	return HistoryRangeResult{Messages: a.msgs, ReachedStart: a.complete}, nil
}

func TestLogGapRangeFetcherKeepsFirstMissing_1119(t *testing.T) {
	const groupID = "QQ-Group:1119-range"
	const senderID = "QQ:1119-range-user"
	d, ep, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()
	msgs := make([]*Message, 0, 30)
	for seq := int64(1051); seq <= 1080; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	ep.Adapter = &rangeOnlyStubAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs, complete: true}

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, fix6Msg(groupID, senderID, 1081, "after"))
	task := popFix5GapTask(t, g)
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1051, 1080); got != 30 {
		t.Fatalf("backfilled rows = %d, want 30 (first missing message must not be lost)", got)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("pending should be cleared: %d..%d", g.LogGapPendingFrom, g.LogGapPendingTo)
	}
}

func TestLogGapRangeFetcherNoProgressKeepsPending_1119(t *testing.T) {
	const groupID = "QQ-Group:1119-noprogress"
	const senderID = "QQ:1119-noprogress-user"
	d, ep, g, ctx, _, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()
	ep.Adapter = &rangeOnlyStubAdapter{mockPlatformAdapter: newMockPlatformAdapter(), complete: false}

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	logExt.OnMessageReceived(ctx, fix6Msg(groupID, senderID, 1081, "after"))
	task := popFix5GapTask(t, g)
	task.run()
	g.logGapWorkerRunning = false

	from, to, _ := g.pendingLogGapRangeSnapshot()
	if from != 1050 || to != 1081 {
		t.Fatalf("pending = %d..%d, want 1050..1081 (must not be cleared on no progress)", from, to)
	}
}

func TestPreOffBackfillAfterResume_1119(t *testing.T) {
	const groupID = "QQ-Group:1119-preoff"
	const senderID = "QQ:1119-preoff-user"
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()
	msgs := make([]*Message, 0, 30)
	for seq := int64(1051); seq <= 1080; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	ep.Adapter = &rangeOnlyStubAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs, complete: true}

	epoch := g.logEpoch.Load()
	oldTask := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: logID, logName: "run-a", epoch: epoch,
		fromSeq: 1050, toSeq: 1080, gap: 29,
	}
	g.logGapQueueMu.Lock()
	g.logGapPending = &oldTask
	g.logGapWorkerRunning = true
	g.logGapQueueMu.Unlock()
	g.setLogGapPendingRange(1050, 1080)
	if !g.armLogOffGapAuth(logID, "run-a", epoch, 1080) {
		t.Fatal("arm auth failed")
	}
	from, to, ok := g.authorizedPreOffGapRange()
	if !ok || from != 1050 || to != 1080 {
		t.Fatalf("authorized range = %d..%d ok=%v, want 1050..1080", from, to, ok)
	}

	// 模拟 .bot on：resume/reset 会取消旧任务并推进 epoch。
	g.cancelLogGapFill()
	if !g.enqueuePreOffBackfillAfterResume(d, ep, from, to) {
		t.Fatal("enqueue pre-off backfill failed")
	}
	task := popFix5GapTask(t, g)
	task.run()
	g.logGapWorkerRunning = false

	if got := countFix5LogRows(t, d, logID, 1051, 1079); got != 29 {
		t.Fatalf("pre-off rows = %d, want 29 (1051..1079; 1080 is the off command)", got)
	}
}

func TestEndpointSupportsLogGapFillBuiltinLagrange_1119(t *testing.T) {
	if endpointSupportsLogGapFill(&EndPointInfo{Adapter: &PlatformAdapterGocq{BuiltinMode: "lagrange"}}) {
		t.Fatal("built-in lagrange has no message_seq; must not claim gap fill")
	}
	if !endpointSupportsLogGapFill(&EndPointInfo{Adapter: &PlatformAdapterGocq{}}) {
		t.Fatal("gocq adapter should support gap fill")
	}
	if !endpointSupportsLogGapFill(&EndPointInfo{Adapter: &rangeOnlyStubAdapter{mockPlatformAdapter: newMockPlatformAdapter()}}) {
		t.Fatal("range-only adapter should support gap fill")
	}
	if endpointSupportsLogGapFill(&EndPointInfo{Adapter: &mockPlatformAdapter{}}) {
		t.Fatal("plain mock adapter should not support gap fill")
	}
}
