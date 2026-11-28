package dice

import (
	"path/filepath"
	"sync"
	"testing"

	"Scardice-core/dice/censor"
	"Scardice-core/model"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"go.uber.org/zap"
)

// Behavior tests for the outbound text hook. They call the real ReplyGroup /
// ReplyPerson helpers and assert the payload and destination at the adapter
// boundary.

type hookSent struct {
	kind   string
	target string
	text   string
	flag   string
}

type hookCaptureAdapter struct {
	*mockPlatformAdapter
	mu     sync.Mutex
	sent   []hookSent
	onSend func(ctx *MsgContext, sent hookSent)
}

var _ PlatformAdapter = (*hookCaptureAdapter)(nil)

func newHookCaptureAdapter() *hookCaptureAdapter {
	return &hookCaptureAdapter{mockPlatformAdapter: newMockPlatformAdapter()}
}

func (a *hookCaptureAdapter) SendToGroup(ctx *MsgContext, groupID, text, flag string) {
	a.record(ctx, hookSent{kind: "group", target: groupID, text: text, flag: flag})
}

func (a *hookCaptureAdapter) SendToPerson(ctx *MsgContext, userID, text, flag string) {
	a.record(ctx, hookSent{kind: "person", target: userID, text: text, flag: flag})
}

func (a *hookCaptureAdapter) record(ctx *MsgContext, sent hookSent) {
	a.mu.Lock()
	a.sent = append(a.sent, sent)
	a.mu.Unlock()
	if a.onSend != nil {
		a.onSend(ctx, sent)
	}
}

func (a *hookCaptureAdapter) messages() []hookSent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]hookSent(nil), a.sent...)
}

func newHookTestDice(t *testing.T) (*Dice, *EndPointInfo, *hookCaptureAdapter) {
	t.Helper()
	d := &Dice{
		Logger:      zap.NewNop().Sugar(),
		BaseConfig:  BaseConfig{DataDir: t.TempDir()},
		DirtyGroups: new(SyncMap[string, int64]),
		ExtRegistry: new(SyncMap[string, *ExtInfo]),
	}
	d.Config = NewConfig(d)
	d.Config.MessageDelayRangeStart = 0
	d.Config.MessageDelayRangeEnd = 0
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	adapter := newHookCaptureAdapter()
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{UserID: "QQ:100000", Nickname: "TestBot", Platform: "QQ", Enable: true},
		Adapter:          adapter,
	}
	ep.Session = d.ImSession
	d.ImSession.EndPoints = []*EndPointInfo{ep}
	return d, ep, adapter
}

func registerHookExt(d *Dice, name string, hook func(*MsgContext, *OutgoingMessage, string) goja.Value) *ExtInfo {
	ext := &ExtInfo{Name: name, AutoActive: true, OnBeforeMessageSend: hook}
	d.RegisterExtension(ext)
	return ext
}

func newHookGroup(d *Dice, ep *EndPointInfo, groupID, senderID string, exts ...*ExtInfo) (*MsgContext, *Message) {
	msg := &Message{
		Platform:    "QQ",
		MessageType: "group",
		GroupID:     groupID,
		Sender:      SenderBase{UserID: senderID, Nickname: "Tester"},
		Message:     "original",
	}
	ctx := &MsgContext{Dice: d, Session: d.ImSession, EndPoint: ep, MessageType: "group"}
	ctx.Group = SetBotOnAtGroup(ctx, groupID)
	ctx.Group.SetActivatedExtList(exts, nil)
	return ctx, msg
}

func TestBeforeMessageSendUsesGroupDestinationAndIgnoresSnapshotWrites(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	var seen []OutgoingMessage
	ext := registerHookExt(d, "outbound-group", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		seen = append(seen, *outgoing)
		outgoing.MessageType = "private"
		outgoing.TargetID = "QQ-Group:evil"
		outgoing.GroupID = "QQ-Group:evil"
		return vm.ToValue("hooked(" + outgoing.Message + ")")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", ext)

	ReplyGroup(ctx, msg, "plain")

	if sent := adapter.messages(); len(sent) != 1 || sent[0] != (hookSent{kind: "group", target: "QQ-Group:111", text: "hooked(plain)"}) {
		t.Fatalf("transport = %#v, want one group payload at QQ-Group:111", sent)
	}
	if len(seen) != 1 {
		t.Fatalf("hook calls = %d, want 1", len(seen))
	}
	got := seen[0]
	if got.Message != "plain" || got.MessageType != "group" || got.TargetID != "QQ-Group:111" ||
		got.GroupID != "QQ-Group:111" || got.Platform != "QQ" ||
		got.Sender.UserID != "QQ:100000" || got.Sender.Nickname != "TestBot" {
		t.Fatalf("outgoing snapshot = %#v", got)
	}
	if msg.MessageType != "group" || msg.GroupID != "QQ-Group:111" || msg.Message != "original" {
		t.Fatalf("inbound message changed: %#v", msg)
	}
}

func TestBeforeMessageSendHiddenRollUsesPrivateDestination(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	groupCalls := 0
	groupExt := registerHookExt(d, "group-only", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		groupCalls++
		return vm.ToValue("group(" + outgoing.Message + ")")
	})
	privateCalls := 0
	var privateSeen OutgoingMessage
	privateExt := registerHookExt(d, "private-only", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		privateCalls++
		privateSeen = *outgoing
		outgoing.MessageType = "group"
		outgoing.TargetID = "QQ-Group:evil"
		outgoing.GroupID = "QQ-Group:evil"
		return vm.ToValue("private(" + outgoing.Message + ")")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", groupExt)
	pg := SetBotOnAtGroup(ctx, "PG-QQ:9001")
	pg.SetActivatedExtList([]*ExtInfo{privateExt}, nil)

	ReplyPerson(ctx, msg, "hidden roll")

	if sent := adapter.messages(); len(sent) != 1 || sent[0] != (hookSent{kind: "person", target: "QQ:9001", text: "private(hidden roll)"}) {
		t.Fatalf("transport = %#v, want one private payload at QQ:9001", sent)
	}
	if groupCalls != 0 {
		t.Fatalf("source group hook ran %d times, want 0", groupCalls)
	}
	if privateCalls != 1 {
		t.Fatalf("private hook calls = %d, want 1", privateCalls)
	}
	if privateSeen.MessageType != "private" || privateSeen.TargetID != "QQ:9001" ||
		privateSeen.GroupID != "" || privateSeen.Platform != "QQ" {
		t.Fatalf("outgoing snapshot = %#v", privateSeen)
	}
	if msg.MessageType != "group" || msg.GroupID != "QQ-Group:111" || msg.Message != "original" || ctx.MessageType != "group" {
		t.Fatalf("inbound routing changed: msg=%#v ctx.MessageType=%q", msg, ctx.MessageType)
	}
}

func TestBeforeMessageSendMissingPrivateSessionSkipsHooksAndFallback(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	globalCalls := 0
	registerHookExt(d, "global-auto", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		globalCalls++
		return vm.ToValue("global(" + outgoing.Message + ")")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:7007")

	ReplyPerson(ctx, msg, "fresh")

	if sent := adapter.messages(); len(sent) != 1 || sent[0] != (hookSent{kind: "person", target: "QQ:7007", text: "fresh"}) {
		t.Fatalf("transport = %#v, want the original payload", sent)
	}
	if globalCalls != 0 {
		t.Fatalf("global extension ran %d times without a destination session", globalCalls)
	}
	if _, ok := d.ImSession.ServiceAtNew.Load("PG-QQ:7007"); ok {
		t.Fatal("hook lookup created the missing private session")
	}
	if msg.Message != "original" {
		t.Fatalf("inbound message changed to %q", msg.Message)
	}
}

func TestBeforeMessageSendChainsRewritesOnceBeforeSplit(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	firstCalls, secondCalls := 0, 0
	var firstSeen, secondSeen string
	first := registerHookExt(d, "chain-first", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		firstCalls++
		firstSeen = outgoing.Message
		return vm.ToValue("[" + outgoing.Message + "]")
	})
	second := registerHookExt(d, "chain-second", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		secondCalls++
		secondSeen = outgoing.Message
		return vm.ToValue(outgoing.Message + "!")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", first, second)
	logical := ctx.TranslateSplit("one#{SPLIT}two")

	ReplyGroup(ctx, msg, logical)

	sent := adapter.messages()
	if len(sent) != 2 {
		t.Fatalf("transport = %#v, want two split payloads", sent)
	}
	if sent[0] != (hookSent{kind: "group", target: "QQ-Group:111", text: "[one"}) ||
		sent[1] != (hookSent{kind: "group", target: "QQ-Group:111", text: "two]!"}) {
		t.Fatalf("transport = %#v", sent)
	}
	if firstCalls != 1 || secondCalls != 1 {
		t.Fatalf("hook calls = (%d, %d), want (1, 1)", firstCalls, secondCalls)
	}
	if firstSeen != logical {
		t.Fatalf("first hook saw %q, want the whole logical text %q", firstSeen, logical)
	}
	if secondSeen != "["+logical+"]" {
		t.Fatalf("second hook saw %q, want the first rewrite %q", secondSeen, "["+logical+"]")
	}
}

func TestBeforeMessageSendCancelStopsChainAndTransport(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	cancelCalls, laterCalls, notified := 0, 0, 0
	cancelExt := registerHookExt(d, "cancel-first", func(_ *MsgContext, _ *OutgoingMessage, _ string) goja.Value {
		cancelCalls++
		return vm.ToValue("")
	})
	laterExt := registerHookExt(d, "cancel-later", func(_ *MsgContext, _ *OutgoingMessage, _ string) goja.Value {
		laterCalls++
		return goja.Undefined()
	})
	d.RegisterExtension(&ExtInfo{
		Name: "legacy-notify",
		OnMessageSend: func(_ *MsgContext, _ *Message, _ string) {
			notified++
		},
	})
	adapter.onSend = func(ctx *MsgContext, sent hookSent) {
		messageType, groupID := "private", ""
		if sent.kind == "group" {
			messageType, groupID = "group", sent.target
		}
		d.ImSession.OnMessageSend(ctx, &Message{MessageType: messageType, GroupID: groupID, Message: sent.text}, sent.flag)
	}
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", cancelExt, laterExt)

	ReplyGroup(ctx, msg, "secret")

	if sent := adapter.messages(); len(sent) != 0 {
		t.Fatalf("transport = %#v, want nothing after cancellation", sent)
	}
	if cancelCalls != 1 || laterCalls != 0 {
		t.Fatalf("hook calls = (%d, %d), want cancellation to stop the chain", cancelCalls, laterCalls)
	}
	if notified != 0 {
		t.Fatalf("legacy send notification ran %d times after cancellation", notified)
	}
	if ctx.Group.RecentDiceSendTime != 0 {
		t.Fatalf("cancelled send updated RecentDiceSendTime to %d", ctx.Group.RecentDiceSendTime)
	}
	if !ctx.IsCommandReplied() {
		t.Fatal("cancelled reply should still count as a handled reply")
	}
	if msg.Message != "original" {
		t.Fatalf("inbound message changed to %q", msg.Message)
	}
}

func TestBeforeMessageSendRewriteDoesNotBypassCensor(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	db, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "censor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err = db.db.AutoMigrate(&model.CensorLog{}); err != nil {
		t.Fatal(err)
	}
	filter := &censor.Censor{SensitiveKeys: map[string]censor.WordInfo{
		"blockedtoken": {Level: censor.Warning, Origin: "blockedtoken"},
	}}
	if err = filter.Load(); err != nil {
		t.Fatal(err)
	}
	d.CensorManager = &CensorManager{Censor: filter, DB: db}
	d.Config.EnableCensor = true
	d.Config.CensorMode = OnlyOutputReply
	d.Config.CensorThresholds = map[censor.Level]int{censor.Warning: 0}
	d.Config.CensorHandlers = nil
	vm := goja.New()
	ext := registerHookExt(d, "outbound-censor", func(_ *MsgContext, _ *OutgoingMessage, _ string) goja.Value {
		return vm.ToValue("blockedtoken")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", ext)

	ReplyGroup(ctx, msg, "clean")
	if sent := adapter.messages(); len(sent) != 0 {
		t.Fatalf("censored rewrite reached transport: %#v", sent)
	}
}

func TestBeforeMessageSendJSRetiredLoopAllowsSend(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	d.ExtLoopManager = NewJsLoopManager()
	d.Config.JsEnable = true
	version := d.ExtLoopManager.SetLoop(eventloop.NewEventLoop())
	ext := registerHookExt(d, "obsolete-outbound", func(_ *MsgContext, _ *OutgoingMessage, _ string) goja.Value {
		t.Fatal("retired extension ran")
		return goja.Undefined()
	})
	ext.IsJsExt = true
	ext.JSLoopVersion = version
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", ext)
	d.ExtLoopManager.SetLoop(nil)

	ReplyGroup(ctx, msg, "original payload")
	if sent := adapter.messages(); len(sent) != 1 || sent[0].text != "original payload" {
		t.Fatalf("transport after retiring loop = %#v", sent)
	}
}

func TestBeforeMessageSendKeepsOrderWhenActivationChanges(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	first := registerHookExt(d, "first", func(ctx *MsgContext, _ *OutgoingMessage, _ string) goja.Value {
		ctx.Group.ExtInactiveByName("second")
		return goja.Undefined()
	})
	second := registerHookExt(d, "second", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		return vm.ToValue(outgoing.Message + " b")
	})
	third := registerHookExt(d, "third", func(_ *MsgContext, outgoing *OutgoingMessage, _ string) goja.Value {
		return vm.ToValue(outgoing.Message + " c")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", first, second, third)
	ReplyGroup(ctx, msg, "first message")
	ReplyGroup(ctx, msg, "next message")
	if sent := adapter.messages(); len(sent) != 2 || sent[0].text != "first message b c" || sent[1].text != "next message c" {
		t.Fatalf("deliveries after activation changed = %#v", sent)
	}
}

func TestBeforeMessageSendDoesNotFilterModeratorNotice(t *testing.T) {
	d, ep, adapter := newHookTestDice(t)
	vm := goja.New()
	ext := registerHookExt(d, "cancel-outbound", func(_ *MsgContext, _ *OutgoingMessage, _ string) goja.Value {
		return vm.ToValue("")
	})
	ctx, msg := newHookGroup(d, ep, "QQ-Group:111", "QQ:9001", ext)
	target := NoticeTarget{ID: msg.GroupID}
	sendNoticeToTarget(ctx, target, "normal notice", NoticeTypeSystem)
	sendNoticeToTarget(ctx, target, "moderator notice", NoticeTypeCensor)
	if sent := adapter.messages(); len(sent) != 1 || sent[0].text != "moderator notice" {
		t.Fatalf("notice deliveries = %#v", sent)
	}
}
