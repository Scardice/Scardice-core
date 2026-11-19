package dice

import (
	"strings"
	"testing"
	"time"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

func waitFix4GapIdle(g *GroupInfo) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		from, to, _ := g.pendingLogGapRangeSnapshot()
		if from == 0 && to == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStartupReconcileWritesLatest_1120fix4 锁定 P1-1：启动对账必须把 latest
// 本身也补进日志；不能因为“latest 当 trigger、on 补录不写 trigger”而漏掉。
func TestStartupReconcileWritesLatest_1120fix4(t *testing.T) {
	const groupID = "QQ-Group:1120fix4-reconcile-latest"
	const senderID = "QQ:fix4-user"
	msgs := make([]*Message, 0, 10)
	for seq := int64(1051); seq <= 1060; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "chat"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()

	ep.Adapter = &latestSeqAdapter{
		rangeOnlyStubAdapter: &rangeOnlyStubAdapter{
			mockPlatformAdapter: newMockPlatformAdapter(),
			msgs:                msgs,
			complete:            true,
		},
		seq:   1060,
		rawID: "m-1060",
	}
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

	if !d.reconcileLogGapForGroup(g) {
		t.Fatal("reconcile should enqueue")
	}
	waitFix4GapIdle(g)

	if got := countFix5LogRows(t, d, logID, 1051, 1060); got != 10 {
		t.Fatalf("rows 1051..1060 = %d, want 10 (latest must be written)", got)
	}
	if got := countFix5LogRows(t, d, logID, 1060, 1060); got != 1 {
		t.Fatalf("latest row 1060 = %d, want 1", got)
	}
	if logGapIncompleteForUpload(g) {
		t.Fatal("pending should be clear after reconcile")
	}
}

// TestLookbackStoppedNotifies_1120fix4 锁定 P3-A：回看前缀遇到
// .log on 另一本日志、且 0 条可补时，也要明确提示停止补录。
func TestLookbackStoppedNotifies_1120fix4(t *testing.T) {
	const groupID = "QQ-Group:1120fix4-lookback-stopped"
	const senderID = "QQ:fix4-user"
	msgs := []*Message{fix6Msg(groupID, senderID, 1001, ".log off")}
	for seq := int64(1002); seq <= 2998; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "off chat"))
	}
	msgs = append(msgs, fix6Msg(groupID, senderID, 2999, ".log on other"))
	for seq := int64(3000); seq <= 7999; seq++ {
		msgs = append(msgs, fix6Msg(groupID, senderID, seq, "off chat 2"))
	}
	d, ep, g, _, logID, cleanup := newFix6LogGapEnv(t, groupID, senderID, &scriptedHistoryFetcher{})
	defer cleanup()
	ep.Adapter = &scriptedRangeAdapter{mockPlatformAdapter: newMockPlatformAdapter(), msgs: msgs}

	g.logGapWorkerRunning = true
	g.setLogGapPendingRange(1000, 8000)
	newTask(d, ep, g, logID, 1000, 8000).run()
	g.logGapWorkerRunning = false

	msgsOut := groupMsgsOf(ep)
	joined := strings.Join(msgsOut, "\n")
	t.Logf("stopped lookback msgs = %#v", msgsOut)
	if !strings.Contains(joined, "停止补录") {
		t.Fatalf("stopped lookback should notify user, got %#v", msgsOut)
	}
	if from, to, _ := g.pendingLogGapRangeSnapshot(); from != 0 || to != 0 {
		t.Fatalf("stopped lookback must clear pending, got %d..%d", from, to)
	}
}

// TestBotOnPromiseOffDiscoveryZeroNotifies_1120fix4 锁定 P3-B：
// .bot on 承诺通知后，off 发现任务 0 结果也要发完成提示并清标记。
func TestBotOnPromiseOffDiscoveryZeroNotifies_1120fix4(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	if err := d.DBOperator.GetLogDB(constant.WRITE).AutoMigrate(
		&model.AttributesItemModel{}, &model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const groupID = "QQ-Group:1120fix4-promise-off"
	const senderID = "QQ:9100"
	ctx, msg := newQuitCommandTestContext(t, d, ep, senderID, groupID, "TmpGroup")
	g := ctx.Group
	g.SetLogState(1, "run-a", false)
	g.setLogGapPendingRangeMode(100, 200, true)
	msg.Seq = 300

	res := d.CmdMap["bot"].Solve(ctx, msg, CommandParse(".bot on", []string{"bot"}, d.CommandPrefix, "QQ", false))
	if !res.Matched || !res.Solved {
		t.Fatalf("bot on result=%#v", res)
	}
	ad := ep.Adapter.(*mockPlatformAdapter)
	if _, ok := ad.waitForMsg(2 * time.Second); !ok {
		t.Fatal("bot on reply not sent")
	}
	if !g.logGapNotifyOnCompleteRequested() {
		t.Fatal("bot on should set notify flag while off-discovery pending")
	}

	// 空历史：off 发现 0 结果。
	ep.Adapter = &fix6ScriptedAdapter{mockPlatformAdapter: ad, fetcher: &scriptedHistoryFetcher{}}
	g.logGapWorkerRunning = true
	task := logGapFillTask{
		dice: d, endpoint: ep, group: g, logID: 1, logName: "run-a",
		epoch: g.logEpoch.Load(), fromSeq: 100, toSeq: 200, gap: 99,
		discoverFromOff: true,
	}
	task.run()
	g.logGapWorkerRunning = false

	ad.mu.Lock()
	msgs := append([]string(nil), ad.groupMsgs...)
	ad.mu.Unlock()
	joined := strings.Join(msgs, "\n")
	t.Logf("promise off-discovery msgs = %#v", msgs)
	if !strings.Contains(joined, "日志补录完成，没有需要补录的消息") {
		t.Fatalf("promise should be fulfilled with a completion notice, got %#v", msgs)
	}
	if g.logGapNotifyOnCompleteRequested() {
		t.Fatal("notify flag should be cleared after completion notice")
	}
}
