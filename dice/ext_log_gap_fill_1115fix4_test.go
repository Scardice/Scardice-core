//nolint:testpackage
package dice

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

// TestLogGapAfterLogOffRestartNoOffPeriod_1115fix4 锁定 1115.fix4 的核心边界：
// 用户 .log off 后进程重启，再 .log on 时，off 段（含重启前遗留的 pending）
// 既不会被补进日志，也不会吞掉 on 之后新掉线的真实缺口。
func TestLogGapAfterLogOffRestartNoOffPeriod_1115fix4(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")  // .log on
	g.updateLogSeq(1050, "m-1050") // off 前最后一条已记录
	// 模拟 off 前还有一个未完成的补全区间：它必须随 .log on 一起失效。
	g.setLogGapPendingRange(1050, 1200)

	if _, ok := g.logOffForUser(); !ok {
		t.Fatal("setup: .log off failed")
	}
	if g.GetLogState().On {
		t.Fatal("setup: log should be off")
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded GroupInfo
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	reloaded.GroupID = "QQ-Group:1"
	reloaded.initLogSeqFromPersisted()

	if reloaded.GetLogState().On {
		t.Fatal("reloaded log must stay off")
	}
	if reloaded.LogGapPendingFrom != 1050 || reloaded.LogGapPendingTo != 1200 {
		t.Fatalf("setup: persisted pending = %d..%d, want 1050..1200",
			reloaded.LogGapPendingFrom, reloaded.LogGapPendingTo)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	offState := reloaded.GetLogState()
	// off 段消息不参与缺口计算，也不推进基线。
	for _, seq := range []int64{1051, 1100, 1200} {
		if from, _, gap := logGapFromMessage(d, &reloaded, offState, seq, "off"); gap != 0 || from != 0 {
			t.Fatalf("off-period seq=%d must not create a gap: from=%d gap=%d", seq, from, gap)
		}
	}

	// .log on（重启后的开启）：基线锚定在 on 指令，旧 pending 必须被清掉。
	reloaded.SetLogOn(true)
	reloaded.resetLogSeqForNewSegment(1201, "m-1201")
	if reloaded.LogGapPendingFrom != 0 || reloaded.LogGapPendingTo != 0 {
		t.Fatalf("pending after .log on = %d..%d, want cleared",
			reloaded.LogGapPendingFrom, reloaded.LogGapPendingTo)
	}

	onState := reloaded.GetLogState()
	// on 之后的第一条消息不应补 off 段（gap=0 时 from 只是当前基线）。
	if _, _, gap := logGapFromMessage(d, &reloaded, onState, 1202, "m-1202"); gap != 0 {
		t.Fatalf("first message after .log on must not create a gap: gap=%d", gap)
	}

	// on 之后的新掉线仍然能正常补：记到 1250，下一条 1301 → 补 1251..1300。
	reloaded.updateLogSeq(1250, "m-1250")
	from, _, gap := logGapFromMessage(d, &reloaded, onState, 1301, "m-1301")
	if from != 1250 || gap != 50 {
		t.Fatalf("gap after new outage = %d from=%d, want 50/1250", gap, from)
	}
}

// TestLogGapAfterBotOffRestartResumesWithoutOffPeriod_1115fix4 锁定 .bot off
// 自动暂停日志后进程重启的边界：.bot on 自动恢复时，恢复段不补录；
// 恢复后的新掉线仍然正常补。
func TestLogGapAfterBotOffRestartResumesWithoutOffPeriod_1115fix4(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.SetLogState(7, "run-a", true)
	g.resetLogSeq(1000, "m-1000")
	g.updateLogSeq(1050, "m-1050")

	if !g.suspendLogForBotOff() {
		t.Fatal("setup: suspend failed")
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded GroupInfo
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	reloaded.GroupID = "QQ-Group:1"
	reloaded.initLogSeqFromPersisted()

	if !reloaded.isLogPausedByBotOff() {
		t.Fatal("reloaded pause marker should be set")
	}
	if !reloaded.resumeLogPausedByBotOff() {
		t.Fatal(".bot on should resume the paused log")
	}
	if !reloaded.GetLogState().On {
		t.Fatal("log should be on after .bot on")
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	state := reloaded.GetLogState()

	// 没有 seq 的 .bot on：靠 skip 标记让第一条消息只重建基线。
	if from, _, gap := logGapFromMessage(d, &reloaded, state, 1201, "m-1201"); gap != 0 || from != 0 {
		t.Fatalf("first message after .bot on must not create a gap: from=%d gap=%d", from, gap)
	}

	// 恢复后的新掉线仍然正常补。
	reloaded.updateLogSeq(1250, "m-1250")
	from, _, gap := logGapFromMessage(d, &reloaded, state, 1301, "m-1301")
	if from != 1250 || gap != 50 {
		t.Fatalf("gap after new outage = %d from=%d, want 50/1250", gap, from)
	}
}
