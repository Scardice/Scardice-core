package dice

import (
	"testing"

	"go.uber.org/zap"
)

func TestLogGapFillSwitchDefaultEnabled(t *testing.T) {
	d := &Dice{}
	d.Config = NewConfig(d)
	if !d.LogGapFillEnabled() {
		t.Fatal("log gap fill must be enabled by default")
	}
}

func TestEnqueueLogGapFillRespectsSwitch(t *testing.T) {
	d := &Dice{Config: NewConfig(nil), Logger: zap.NewNop().Sugar()}
	g := &GroupInfo{GroupID: "QQ-Group:log-gap-switch"}
	g.logGapWorkerRunning = true
	task := logGapFillTask{dice: d, group: g, fromSeq: 1, toSeq: 4}

	d.Config.LogGapFillEnable = false
	g.enqueueLogGapFill(task)
	if g.logGapPending != nil {
		t.Fatalf("pending task created while switch is off: %+v", g.logGapPending)
	}

	d.Config.LogGapFillEnable = true
	g.enqueueLogGapFill(task)
	if g.logGapPending == nil {
		t.Fatal("pending task was not created while switch is on")
	}
}

func TestDetectOffStateLogGapRespectsSwitch(t *testing.T) {
	newGroup := func() *GroupInfo {
		g := &GroupInfo{GroupID: "QQ-Group:log-gap-switch"}
		g.LogCurID = 1
		g.LogCurName = "run-a"
		g.LogOn = false
		g.LogSeenSeq = 1000
		g.logGapWorkerRunning = true
		return g
	}
	d := &Dice{Config: NewConfig(nil), Logger: zap.NewNop().Sugar()}
	ep := &EndPointInfo{}
	msg := &Message{Seq: 1010}

	d.Config.LogGapFillEnable = false
	g := newGroup()
	g.detectOffStateLogGap(d, ep, g.GetLogState(), msg)
	if got := g.logSeenSeqSnapshot(); got != msg.Seq {
		t.Fatalf("seen seq while switch off = %d, want %d", got, msg.Seq)
	}
	if g.logGapPending != nil {
		t.Fatalf("pending task created while switch is off: %+v", g.logGapPending)
	}

	d.Config.LogGapFillEnable = true
	g = newGroup()
	g.detectOffStateLogGap(d, ep, g.GetLogState(), msg)
	if g.logGapPending == nil {
		t.Fatal("pending task was not created while switch is on")
	}
}

func TestCancelLogGapFillTasksClearsQueue(t *testing.T) {
	d := &Dice{Config: NewConfig(nil), Logger: zap.NewNop().Sugar()}
	d.Config.LogGapFillEnable = false
	d.ImSession = &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	g := &GroupInfo{GroupID: "QQ-Group:log-gap-switch"}
	g.logGapPending = &logGapFillTask{dice: d, group: g, fromSeq: 1, toSeq: 4}
	g.LogGapPendingFrom, g.LogGapPendingTo = 1, 4
	d.ImSession.ServiceAtNew.Store(g.GroupID, g)
	beforeEpoch := g.logEpoch.Load()

	d.CancelLogGapFillTasks()

	if g.logGapPending != nil {
		t.Fatalf("in-memory pending task not cleared: %+v", g.logGapPending)
	}
	if g.LogGapPendingFrom != 0 || g.LogGapPendingTo != 0 {
		t.Fatalf("persistent pending range not cleared: %d..%d", g.LogGapPendingFrom, g.LogGapPendingTo)
	}
	if got := g.logEpoch.Load(); got != beforeEpoch+1 {
		t.Fatalf("epoch after cancel = %d, want %d", got, beforeEpoch+1)
	}
}
