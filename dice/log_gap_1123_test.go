//nolint:testpackage
package dice

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"Scardice-core/dice/service"
	"Scardice-core/model"
)

// appendLiveLogRow_1123 模拟补录期间实时路径写入的一条日志。
func appendLiveLogRow_1123(t *testing.T, d *Dice, logID uint64, groupID string, seq, ts int64, text string) {
	t.Helper()
	item := &model.LogOneItem{
		Nickname:  "tester",
		IMUserID:  "10086",
		UniformID: "QQ:10086",
		Time:      ts,
		Message:   text,
		Seq:       ptrInt64(seq),
		RawMsgID:  fmt.Sprintf("live-%d", seq),
	}
	if !service.LogAppendByID(d.DBOperator, logID, groupID, item) {
		t.Fatalf("append live log row seq=%d failed", seq)
	}
}

// TestHistoricalOffCleansLiveRowsAfterOff_1123 锁定：离线 .log off 生效后，
// 补录期间实时写入的 off 段消息必须一起清理，不能只删触发那一条。
//
// 复现：历史 1051..1060 为 on 段，1061 为 .log off，1062..1075 为 off 段；
// 触发消息 1076 已被实时路径写入。补录拉历史期间又来了 1077/1078 两条实时
// 消息；任务收尾时 1076..1078 都应该从日志中移除，1051..1061 保留。
func TestHistoricalOffCleansLiveRowsAfterOff_1123(t *testing.T) {
	const groupID = "QQ-Group:1123-off-cleanup"
	const senderID = "QQ:1123-user"
	msgs := make([]*Message, 0, 30)
	for seq := int64(1051); seq <= 1060; seq++ {
		m := fix6Msg(groupID, senderID, seq, fmt.Sprintf("chat %d", seq))
		m.Time = 1000 + (seq - 1051)
		msgs = append(msgs, m)
	}
	off := fix6Msg(groupID, senderID, 1061, ".log off")
	off.Time = 1010
	msgs = append(msgs, off)
	for seq := int64(1062); seq <= 1075; seq++ {
		m := fix6Msg(groupID, senderID, seq, fmt.Sprintf("off chat %d", seq))
		m.Time = 1011 + (seq - 1062)
		msgs = append(msgs, m)
	}
	fetcher := &scriptedHistoryFetcher{msgs: msgs}
	d, ep, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1076, "off period first live message")
	trigger.Time = 1025
	logExt.OnMessageReceived(ctx, trigger)
	if got := countFix5LogRows(t, d, logID, 1076, 1076); got != 1 {
		t.Fatalf("setup trigger rows = %d, want 1", got)
	}

	// 补录拉历史期间实时到达的两条消息（B 路径：已经写进日志）。
	appendLiveLogRow_1123(t, d, logID, groupID, 1077, 1026, "live during backfill 1")
	appendLiveLogRow_1123(t, d, logID, groupID, 1078, 1027, "live during backfill 2")

	task := popFix5GapTask(t, g)
	task.run()

	if got := countFix5LogRows(t, d, logID, 1051, 1061); got != 11 {
		t.Fatalf("pre-off rows = %d, want 11", got)
	}
	if got := countFix5LogRows(t, d, logID, 1062, 1078); got != 0 {
		t.Fatalf("off-period/live rows = %d, want 0", got)
	}
	if g.GetLogState().On {
		t.Fatal("historical final state is off; live log must be turned off")
	}
	msgsOut := groupMsgsOf(ep)
	joined := strings.Join(msgsOut, "\n")
	if !strings.Contains(joined, "已移除关闭后误记的 2 条") {
		t.Fatalf("cleanup notice missing, got %#v", msgsOut)
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalOffEmptyMissingStillNotifies_1123 锁定：.log off 行已经被
// 上一次失败补录写过、这次被去重掉时，missing 为 0 也不能静默关闭日志；
// 群里必须收到“离线期间的 .log off 已生效”。
func TestHistoricalOffEmptyMissingStillNotifies_1123(t *testing.T) {
	const groupID = "QQ-Group:1123-off-empty-notice"
	const senderID = "QQ:1123-user"
	off := fix6Msg(groupID, senderID, 1061, ".log off")
	off.Time = 1010
	fetcher := &scriptedHistoryFetcher{msgs: []*Message{off}}
	d, ep, g, ctx, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	// 模拟上一次补录已经写入 .log off 行：本次 filterAlreadyLogged 会把它去重，
	// missing 变成 0，但历史状态仍是 off。
	if !service.LogAppendByID(d.DBOperator, logID, groupID, &model.LogOneItem{
		Nickname:  "tester",
		IMUserID:  "10086",
		UniformID: "QQ:10086",
		Time:      1010,
		Message:   ".log off",
		Seq:       ptrInt64(1061),
		RawMsgID:  "m-1061",
	}) {
		t.Fatal("append pre-existing .log off row failed")
	}

	logExt, ok := d.ExtRegistry.Load("log")
	if !ok {
		t.Fatal("log extension not registered")
	}
	g.logGapWorkerRunning = true
	trigger := fix6Msg(groupID, senderID, 1062, "first live message after off")
	trigger.Time = 1011
	logExt.OnMessageReceived(ctx, trigger)
	task := popFix5GapTask(t, g)
	task.run()

	if g.GetLogState().On {
		t.Fatal("historical final state is off; live log must be turned off")
	}
	if got := countFix5LogRows(t, d, logID, 1061, 1061); got != 1 {
		t.Fatalf("pre-existing .log off row = %d, want 1", got)
	}
	msgsOut := groupMsgsOf(ep)
	joined := strings.Join(msgsOut, "\n")
	if !strings.Contains(joined, "离线期间的 .log off 已生效") {
		t.Fatalf("closed-state notice missing, got %#v", msgsOut)
	}
	g.logGapWorkerRunning = false
}

// TestHistoricalOffCleanupWaitsForLogWriteLock_1123 锁定清理与 .log on 的串行化：
// cleanup 必须在 logWriteMu 读锁内复查状态并删除；持有写锁时 cleanup 必须等待，
// 不能先删行再让 .log on 打开新段。
func TestHistoricalOffCleanupWaitsForLogWriteLock_1123(t *testing.T) {
	const groupID = "QQ-Group:1123-cleanup-lock"
	const senderID = "QQ:1123-user"
	fetcher := &scriptedHistoryFetcher{}
	d, _, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, fetcher)
	defer cleanup()

	const logName = "run-a"
	g.SetLogState(logID, logName, false)
	appendLiveLogRow_1123(t, d, logID, groupID, 1077, 1026, "new segment row")

	task := logGapFillTask{
		dice:    d,
		group:   g,
		logID:   logID,
		logName: logName,
		epoch:   g.logEpoch.Load(),
	}
	hist := logGapLifecycleInfo{found: true, lastOffSeq: 1061, lastOffTime: 1010}

	g.logWriteMu.Lock()
	done := make(chan int64, 1)
	go func() {
		done <- task.cleanupRowsAfterHistoricalOff(hist)
	}()

	select {
	case removed := <-done:
		g.logWriteMu.Unlock()
		t.Fatalf("cleanup returned %d while logWriteMu was held; it must wait", removed)
	case <-time.After(100 * time.Millisecond):
	}

	g.logWriteMu.Unlock()

	select {
	case removed := <-done:
		if removed != 1 {
			t.Fatalf("removed = %d, want 1", removed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not finish after logWriteMu was released")
	}
	if got := countFix5LogRows(t, d, logID, 1077, 1077); got != 0 {
		t.Fatalf("row after off = %d, want 0", got)
	}
}
