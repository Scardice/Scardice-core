package dice

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// newReleasedCommandContext returns the context of a command that has already
// returned: its execution state is released, so anything still using it is
// refused by the reply and variable layers.
func newReleasedCommandContext(t *testing.T, noticeIDs ...string) (*MsgContext, *noticeCaptureAdapter, *observer.ObservedLogs) {
	t.Helper()
	adapter := &noticeCaptureAdapter{mockPlatformAdapter: newMockPlatformAdapter(), personIDs: make(chan string, 4)}
	logCore, logs := observer.New(zapcore.ErrorLevel)
	d, _ := newCanonicalTestDice(t)
	d.Logger = zap.New(logCore).Sugar()
	updateCanonicalTestConfig(t, d, func(config *Config) { config.NoticeIDs = append([]string(nil), noticeIDs...) })
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	endpoint.ID = "detached-report-endpoint"
	endpoint.Platform = "QQ"
	endpoint.ProtocolType = "onebot"
	endpoint.State = StateConnected
	endpoint.Adapter = adapter
	ctx := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: endpoint}
	ctx.releaseExecutionState()
	return ctx, adapter, logs
}

func awaitPerson(t *testing.T, adapter *noticeCaptureAdapter, what string) string {
	t.Helper()
	select {
	case id := <-adapter.personIDs:
		return id
	case <-time.After(2 * time.Second):
		t.Fatalf("%s was never delivered", what)
		return ""
	}
}

// A background goroutine that sends through the command's own context loses its
// message once the command has returned.
func TestNoticeIsDeliveredEvenWhenTheCommandContextWasAlreadyReleased(t *testing.T) {
	ctx, adapter, _ := newReleasedCommandContext(t, "QQ:1001")
	ctx.Notice("late notice")
	if got := awaitPerson(t, adapter, "the notice"); got != "QQ:1001" {
		t.Fatalf("notice went to %q, want QQ:1001", got)
	}
}

func TestCrossPlatformNoticeIsDeliveredEvenWhenTheCommandContextWasAlreadyReleased(t *testing.T) {
	ctx, adapter, _ := newReleasedCommandContext(t, "QQ:1001")
	ctx.NoticeCrossPlatform("late cross-platform notice")
	if got := awaitPerson(t, adapter, "the cross-platform notice"); got != "QQ:1001" {
		t.Fatalf("notice went to %q, want QQ:1001", got)
	}
}

func TestDetachedReportSpeaksAfterTheCommandContextIsReleased(t *testing.T) {
	ctx, adapter, _ := newReleasedCommandContext(t)
	msg := &Message{MessageType: "private", Sender: SenderBase{UserID: "QQ:2002"}}
	report := ctx.detach(msg)

	// The released context refuses both of these; the fresh one must not.
	report(func(reportCtx *MsgContext, reportMsg *Message) {
		if reportCtx.callbackTransaction == nil {
			t.Fatal("detached report did not create an explicit durable root")
		}
		if reportCtx.standaloneSendScope {
			t.Fatal("detached report bypassed its durable root with standalone send mode")
		}
		VarSetValueStr(reportCtx, "$t汇报", "done")
		ReplyToSender(reportCtx, reportMsg, "the work finished")
	})
	if got := awaitPerson(t, adapter, "the detached report"); got != "QQ:2002" {
		t.Fatalf("report went to %q, want the original sender QQ:2002", got)
	}
}
func TestDetachedReportInheritsLiveCallbackRoot(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	msg := &Message{
		MessageType: "group", GroupID: "QQ-Group:2002",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}
	ctx := newCanonicalTestMessageContext(t, d, endpoint, msg, "detached-live-child")
	transaction := ctx.callbackTransaction
	report := ctx.detach(msg)
	report(func(reportCtx *MsgContext, _ *Message) {
		if reportCtx.callbackTransaction != transaction {
			t.Fatal("live detached child opened a second root")
		}
		if reportCtx.Group == ctx.Group {
			t.Fatal("live detached child copied the old group facade")
		}
	})
	if err := ctx.getExecutionError(); err != nil {
		t.Fatal(err)
	}
}

func TestDetachedReportUsesASnapshotOfTheMessage(t *testing.T) {
	ctx, adapter, _ := newReleasedCommandContext(t)
	msg := &Message{MessageType: "private", Sender: SenderBase{UserID: "QQ:2002"}}
	report := ctx.detach(msg)
	msg.Sender.UserID = "QQ:9999" // the dispatcher reuses and edits its message

	report(func(reportCtx *MsgContext, reportMsg *Message) { ReplyToSender(reportCtx, reportMsg, "hi") })
	if got := awaitPerson(t, adapter, "the detached report"); got != "QQ:2002" {
		t.Fatalf("report went to %q, want the sender as it was when the command ran", got)
	}
}

// A failure while speaking only loses that line: it is logged, the process stays
// up, and the same reporter still works for the next one.
func TestDetachedReportContainsPanicsAndKeepsWorking(t *testing.T) {
	ctx, adapter, logs := newReleasedCommandContext(t)
	msg := &Message{MessageType: "private", Sender: SenderBase{UserID: "QQ:2002"}}
	report := ctx.detach(msg)

	report(func(*MsgContext, *Message) { panic("speaking failed") })
	entries := logs.FilterMessageSnippet("speaking failed").All()
	if len(entries) != 1 || !strings.Contains(entries[0].Message, "汇报") {
		t.Fatalf("logged errors = %v, want one entry describing the failed report", logs.All())
	}

	report(func(reportCtx *MsgContext, reportMsg *Message) { ReplyToSender(reportCtx, reportMsg, "second try") })
	if got := awaitPerson(t, adapter, "the report after a failed one"); got != "QQ:2002" {
		t.Fatalf("report went to %q", got)
	}
}

func TestDetachedReportWithoutALiveEndpointIsLoggedNotFatal(t *testing.T) {
	ctx, _, logs := newReleasedCommandContext(t)
	ctx.EndPoint.Session = nil // the endpoint's runtime is gone
	ctx.Session = &IMSession{Parent: ctx.Dice}
	report := ctx.detach(&Message{MessageType: "private", Sender: SenderBase{UserID: "QQ:2002"}})

	called := false
	report(func(*MsgContext, *Message) { called = true })
	if called {
		t.Fatal("speak ran without a context")
	}
	if logs.Len() != 1 {
		t.Fatalf("logged errors = %v, want exactly one", logs.All())
	}
}
