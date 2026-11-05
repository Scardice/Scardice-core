//nolint:testpackage
package dice

// Smoke tests for IMSession.ExecuteNew – the central message-dispatch function.
//
// This file builds a minimal but real Dice instance (commands + extensions +
// text map all loaded; SQLite operator pointing at a temp dir) together with a
// mockPlatformAdapter that captures every outbound message.  Each test then
// calls ExecuteNew with a crafted Message and asserts the expected behaviour.
//
// Why package dice (internal test)?
//   - Several functions used for setup (registerCoreCommands,
//     setupBaseTextTemplate, loadTextTemplate, NewConfig) are
//     unexported but needed to create a realistic test environment.
//   - Tests in the same package may call them directly without any extra
//     export shims.

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	sealdiceLogger "Scardice-core/logger"
	"Scardice-core/message"
	"Scardice-core/utils/constant"
)

// ---------------------------------------------------------------------------
// mockPlatformAdapter
// ---------------------------------------------------------------------------

// mockPlatformAdapter implements PlatformAdapter, recording every message that
// the bot tries to send.  A buffered channel makes it easy to wait for async
// replies from PreTriggerCommand.
type mockPlatformAdapter struct {
	mu         sync.Mutex
	groupMsgs  []string
	personMsgs []string
	quitGroups []string
	bans       []string
	kicks      []string
	files      []string
	fileResult *adapterapi.EffectResult
	msgCh      chan string
}

// compile-time check
var _ PlatformAdapter = (*mockPlatformAdapter)(nil)

func newMockPlatformAdapter() *mockPlatformAdapter {
	return &mockPlatformAdapter{msgCh: make(chan string, 32)}
}

// waitForMsg blocks until a message arrives or the timeout elapses.
func (m *mockPlatformAdapter) waitForMsg(timeout time.Duration) (string, bool) {
	select {
	case msg := <-m.msgCh:
		return msg, true
	case <-time.After(timeout):
		return "", false
	}
}

func (m *mockPlatformAdapter) SendToGroup(_ *MsgContext, _ string, text string, _ string) {
	m.mu.Lock()
	m.groupMsgs = append(m.groupMsgs, text)
	m.mu.Unlock()
	select {
	case m.msgCh <- text:
	default:
	}
}

func (m *mockPlatformAdapter) SendToPerson(_ *MsgContext, _ string, text string, _ string) {
	m.mu.Lock()
	m.personMsgs = append(m.personMsgs, text)
	m.mu.Unlock()
	select {
	case m.msgCh <- text:
	default:
	}
}

// Remaining PlatformAdapter methods – all no-ops for the smoke test.

func (m *mockPlatformAdapter) QuitGroup(_ *MsgContext, groupID string) {
	m.mu.Lock()
	m.quitGroups = append(m.quitGroups, groupID)
	m.mu.Unlock()
}
func (m *mockPlatformAdapter) SetGroupCardName(_ *MsgContext, _ string) {}
func (m *mockPlatformAdapter) MemberBan(groupID string, userID string, _ int64) {
	m.mu.Lock()
	m.bans = append(m.bans, groupID+":"+userID)
	m.mu.Unlock()
}
func (m *mockPlatformAdapter) MemberKick(groupID string, userID string) {
	m.mu.Lock()
	m.kicks = append(m.kicks, groupID+":"+userID)
	m.mu.Unlock()
}
func (m *mockPlatformAdapter) GetGroupInfoAsync(_ string)             {}
func (m *mockPlatformAdapter) EditMessage(_ *MsgContext, _, _ string) {}
func (m *mockPlatformAdapter) RecallMessage(_ *MsgContext, _ string)  {}
func (m *mockPlatformAdapter) SendSegmentToGroup(_ *MsgContext, _ string, _ []message.IMessageElement, _ string) {
}
func (m *mockPlatformAdapter) SendSegmentToPerson(_ *MsgContext, _ string, _ []message.IMessageElement, _ string) {
}
func (m *mockPlatformAdapter) SendFileToPerson(_ *MsgContext, _ string, path string, _ string) adapterapi.EffectResult {
	m.mu.Lock()
	m.files = append(m.files, path)
	result := m.fileResult
	m.mu.Unlock()
	return mockFileSendResult(result)
}
func (m *mockPlatformAdapter) SendFileToGroup(_ *MsgContext, _ string, path string, _ string) adapterapi.EffectResult {
	m.mu.Lock()
	m.files = append(m.files, path)
	result := m.fileResult
	m.mu.Unlock()
	return mockFileSendResult(result)
}

func mockFileSendResult(result *adapterapi.EffectResult) adapterapi.EffectResult {
	if result == nil {
		return adapterapi.AmbiguousResult("mock_file_send_unconfirmed", "mock provider does not acknowledge file upload")
	}
	return *result
}

// ---------------------------------------------------------------------------
// mockDatabaseOperator
// ---------------------------------------------------------------------------
// mockDatabaseOperator supplies the legacy log/censor SQL boundary used by
// command consumers. Canonical group, player, config, and attribute fixtures
// use the separate durable EventStore created by newCanonicalTestDice.
type mockDatabaseOperator struct {
	db *gorm.DB
}

func newMockDatabaseOperator(dbPath string) (*mockDatabaseOperator, error) {
	db, err := openTestGormDB(dbPath)
	if err != nil {
		return nil, err
	}
	return &mockDatabaseOperator{db: db}, nil
}

func (m *mockDatabaseOperator) Init(_ context.Context) error           { return nil }
func (m *mockDatabaseOperator) Type() string                           { return "mock-sqlite" }
func (m *mockDatabaseOperator) DBCheck()                               {}
func (m *mockDatabaseOperator) GetDataDB(_ constant.DBMode) *gorm.DB   { return m.db }
func (m *mockDatabaseOperator) GetLogDB(_ constant.DBMode) *gorm.DB    { return m.db }
func (m *mockDatabaseOperator) GetCensorDB(_ constant.DBMode) *gorm.DB { return m.db }
func (m *mockDatabaseOperator) Close() {
	if sqlDB, err := m.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// ---------------------------------------------------------------------------
// newExecuteNewTestDice – minimal Dice setup for smoke testing
// ---------------------------------------------------------------------------

// newExecuteNewTestDice constructs a Dice with enough infrastructure for
// ExecuteNew to run end-to-end. Durable group, player, config, and attribute
// state use the real SQLite EventStore and synchronous projections.
//
// Cleanup is registered automatically. The returned function is retained for
// existing callers and is idempotent.
func newExecuteNewTestDice(t *testing.T) (*Dice, *EndPointInfo, *mockPlatformAdapter, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	for _, sub := range []string{"configs", "extensions", "scripts", "extra", "log-exports"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	d, _ := newCanonicalTestDice(t)
	d.BaseConfig.DataDir = tmpDir
	mockDB, err := newMockDatabaseOperator(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator: %v", err)
	}

	// Minimal DiceManager – Cron is created but NOT started to avoid background
	// goroutines that would trigger goleak.
	dm := &DiceManager{Cron: cron.New()}
	d.Logger = sealdiceLogger.M()
	d.LogWriter = sealdiceLogger.NewUIWriter()
	d.DBOperator = mockDB
	d.Cron = cron.New()
	d.Parent = dm
	dm.Dice = []*Dice{d}
	d.ImSession.Parent = d

	updateCanonicalTestConfig(t, d, func(config *Config) {
		// Disable the per-message QQ sleep so tests are fast. Command prefixes
		// remain in the source-versioned config view.
		config.BaseConfig.Name = d.BaseConfig.Name
		config.DataDir = tmpDir
		config.MessageDelayRangeStart = 0
		config.MessageDelayRangeEnd = 0
		config.CommandPrefix = append([]string(nil), DefaultConfig.CommandPrefix...)
	})

	// ConfigManager
	d.ConfigManager = NewConfigManager(filepath.Join(tmpDir, "configs", "plugin-configs.json"))
	_ = d.ConfigManager.Load()

	// Register all core commands and built-in extensions.
	d.registerCoreCommands()
	d.RegisterBuiltinExt()

	// Text templates (setupBaseTextTemplate initialises d.TextMapRaw).
	setupBaseTextTemplate(d)
	// loadTextTemplate is a no-op when the file doesn't exist, which is fine.
	loadTextTemplate(d, "configs/text-template.yaml")
	d.GenerateTextMap()

	d.ApplyExtDefaultSettings()
	d.IsAlreadyLoadConfig = true

	// Mock platform adapter + endpoint
	adapter := newMockPlatformAdapter()
	ep := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID:       "test-ep-1",
			UserID:   "QQ:100000",
			Nickname: "TestBot",
			Platform: "QQ",
			Enable:   true,
		},
		Adapter: adapter,
	}
	ep.Session = d.ImSession

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if d.Parent != nil && d.Parent.Help != nil {
				d.Parent.Help.Close()
			}
			mockDB.Close()
		})
	}
	t.Cleanup(cleanup)
	return d, ep, adapter, cleanup
}

// ---------------------------------------------------------------------------
// Message helpers
// ---------------------------------------------------------------------------

func newGroupMsg(groupID, senderID, text string) *Message {
	return &Message{
		Platform:    "QQ",
		MessageType: "group",
		GroupID:     groupID,
		GroupName:   "TestGroup",
		Time:        time.Now().Unix(),
		Sender: SenderBase{
			UserID:   senderID,
			Nickname: "Tester",
		},
		Message: text,
		Segment: []message.IMessageElement{
			&message.TextElement{Content: text},
		},
	}
}

func newPrivateMsg(senderID, text string) *Message {
	return &Message{
		Platform:    "QQ",
		MessageType: "private",
		Time:        time.Now().Unix(),
		Sender: SenderBase{
			UserID:   senderID,
			Nickname: "Tester",
		},
		Message: text,
		Segment: []message.IMessageElement{
			&message.TextElement{Content: text},
		},
	}
}

func registerAutoActivePreprocessExt(d *Dice, name string, fn func(ctx *MsgContext, msg *Message) goja.Value) {
	d.RegisterExtension(&ExtInfo{
		Name:                name,
		AutoActive:          true,
		OnMessagePreprocess: fn,
	})
	d.ApplyExtDefaultSettings()
}

func activateCanonicalTestGroupExtensions(t *testing.T, d *Dice, endpoint *EndPointInfo, groupID, label string, extensions ...*ExtInfo) {
	t.Helper()
	for _, extension := range extensions {
		d.RegisterExtension(extension)
	}
	message := newGroupMsg(groupID, "QQ:fixture-owner", "")
	withCanonicalTestMessageContext(t, d, endpoint, message, label, func(ctx *MsgContext) error {
		for _, extension := range extensions {
			if err := ctx.Group.SetExtension(extension.Name, true); err != nil {
				return err
			}
		}
		return nil
	})
}

func awaitCanonicalGroupProjection(t *testing.T, d *Dice, groupID string, ready func(groupstate.State) bool) groupstate.State {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var (
		state groupstate.State
		err   error
	)
	for time.Now().Before(deadline) {
		state, err = groupstate.ReadProjected(context.Background(), d.DurableStore, d.BaseConfig.Name, groupID)
		if err == nil && (ready == nil || ready(state)) {
			return state
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("canonical group %q did not reach expected projection: state=%#v err=%v", groupID, state, err)
	return groupstate.State{}
}

// ---------------------------------------------------------------------------
// Smoke Tests
// ---------------------------------------------------------------------------

// TestExecuteNew_GroupCommand_Roll verifies that a dice-roll command sent to a
// group causes the bot to produce at least one reply via the adapter.
func TestExecuteNew_GroupCommand_Roll(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg("QQ-Group:111", "QQ:999", ".r 1d6"))

	_, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected a reply to '.r 1d6' but none arrived")
	}
}

func TestExecuteNew_GroupCommand_RollShapeStatus(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg("QQ-Group:112", "QQ:999", ".rollshape"))

	reply, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected a reply to '.rollshape'")
	}
	if !strings.Contains(reply, "Raw / Uniform") {
		t.Fatalf("rollshape reply = %q, want default Raw / Uniform", reply)
	}
}

func TestExecuteNew_PrivateCommand_RollShapeSet(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	executeNewAndWaitForCanonicalCommit(t, d, ep, newPrivateMsg("QQ:999", ".rollshape set soft"))

	reply, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected a reply to '.rollshape set soft'")
	}
	if !strings.Contains(reply, "Soft / Beta(1.35,1.35)") {
		t.Fatalf("rollshape reply = %q, want Soft mode", reply)
	}
	state := awaitCanonicalGroupProjection(t, d, "PG-QQ:999", func(state groupstate.State) bool {
		return state.RollShaperMode == string(DiceRollShaperModeSoft)
	})
	if state.RollShaperMode != string(DiceRollShaperModeSoft) {
		t.Fatalf("private rollshape state = %#v, want soft", state)
	}
}

// TestExecuteNew_GroupCommand_Roll_NoArgs verifies a bare .r command still
// produces a reply (uses the group's default dice expression).
func TestExecuteNew_GroupCommand_Roll_NoArgs(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg("QQ-Group:111", "QQ:999", ".r"))

	_, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected a reply to bare '.r' command")
	}
}

// TestExecuteNew_PrivateCommand_Roll verifies that a private message with a
// dice command produces a reply to the sender.
func TestExecuteNew_PrivateCommand_Roll(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	executeNewAndWaitForCanonicalCommit(t, d, ep, newPrivateMsg("QQ:999", ".r 1d6"))

	_, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected a reply to private '.r 1d6'")
	}
}

func TestExecuteNew_CustomHelpSections(t *testing.T) {
	tests := []struct {
		arg         string
		key         string
		placeholder string
		custom      string
	}{
		{"骰点", "骰子帮助文本_骰点", "骰主可以在这里写骰子的骰点命令使用教程", "自定义骰点教程"},
		{"房规", "骰子帮助文本_房规", "骰主可以在这里写骰子的房规说明", "自定义房规"},
		{"特色功能", "骰子帮助文本_特色功能", "骰主可以在这里写骰子的额外功能命令的使用教程", "自定义额外功能教程"},
	}

	for _, test := range tests {
		t.Run(test.arg, func(t *testing.T) {
			d, ep, adapter, cleanup := newExecuteNewTestDice(t)
			defer cleanup()

			items := d.TextMapRaw["核心"][test.key]
			if len(items) != 1 || items[0][0] != test.placeholder {
				t.Fatalf("default %s help = %#v, want %q", test.arg, items, test.placeholder)
			}
			d.TextMapRaw["核心"][test.key] = TextTemplateItemList{{test.custom, 1}}
			d.GenerateTextMap()
			executeNewAndWaitForCanonicalCommit(t, d, ep, newPrivateMsg("QQ:999", ".help "+test.arg))

			reply, ok := adapter.waitForMsg(2 * time.Second)
			if !ok {
				t.Fatalf("timeout: expected a reply to '.help %s'", test.arg)
			}
			if reply != test.custom {
				t.Fatalf(".help %s reply = %q, want %q", test.arg, reply, test.custom)
			}
			if got := d.TextMapHelpInfo["核心"][test.key].SubType; got != ".help" {
				t.Fatalf("%s help subtype = %q, want .help", test.arg, got)
			}
		})
	}
}

// TestExecuteNew_GroupMessage_NonCommand verifies that a plain chat message
// (no command prefix) does NOT produce a bot reply.
func TestExecuteNew_GroupMessage_NonCommand(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg("QQ-Group:111", "QQ:999", "just chatting"))

	select {
	case unexpected := <-adapter.msgCh:
		t.Errorf("unexpected reply to non-command message: %q", unexpected)
	case <-time.After(400 * time.Millisecond):
		// expected: no reply
	}
}

// TestExecuteNew_GroupStateCreated verifies that ExecuteNew creates the
// canonical aggregate for a previously unseen group.
func TestExecuteNew_GroupStateCreated(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	const groupID = "QQ-Group:654321"
	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg(groupID, "QQ:111", ".r"))
	if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for group command")
	}

	state := awaitCanonicalGroupProjection(t, d, groupID, func(state groupstate.State) bool {
		return state.GroupID == groupID && state.Active
	})
	if state.GroupID != groupID {
		t.Errorf("GroupID = %q, want %q", state.GroupID, groupID)
	}
	if !state.Active {
		t.Error("new canonical group should be active")
	}
}

func TestOnMessageDeletedWritesUILog(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.NameKey = "module"
	encoderConfig.EncodeName = zapcore.FullNameEncoder
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), zapcore.AddSync(d.LogWriter), zapcore.InfoLevel)
	d.Logger = zap.New(core).Named(sealdiceLogger.LogKeyMain).Sugar()

	msg := &Message{
		Platform:    "QQ",
		MessageType: "group",
		GroupID:     "QQ-Group:10001",
		GroupName:   "TestGroup",
		Time:        time.Now().Unix(),
		Sender: SenderBase{
			UserID:   "QQ:20001",
			Nickname: "Alice",
		},
		Message: "这是一条被撤回的消息",
		RawID:   "raw-delete-1",
	}
	ctx := newCanonicalTestMessageContext(t, d, ep, msg, "message-deleted")
	if err := ctx.Group.SetGroupName(msg.GroupName); err != nil {
		t.Fatal(err)
	}

	d.ImSession.OnMessageDeleted(ctx, msg)

	var found bool
	logItems := d.LogWriter.Snapshot()
	for _, item := range logItems {
		if item == nil {
			continue
		}
		if strings.Contains(item.Msg, "撤回消息事件") &&
			strings.Contains(item.Msg, msg.GroupID) &&
			strings.Contains(item.Msg, msg.Sender.UserID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected UI log to contain message delete event, got %+v", logItems)
	}
}

// TestExecuteNew_Segment_TextReconstructed verifies that when Message.Message
// is empty, ExecuteNew reconstructs the text from Segment elements and still
// handles the command.
func TestExecuteNew_Segment_TextReconstructed(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	msg := &Message{
		Platform:    "QQ",
		MessageType: "group",
		GroupID:     "QQ-Group:789",
		GroupName:   "TestGroup",
		Time:        time.Now().Unix(),
		Sender:      SenderBase{UserID: "QQ:222", Nickname: "Tester"},
		Message:     "", // intentionally empty – should be filled from Segment
		Segment: []message.IMessageElement{
			&message.TextElement{Content: ".r 2d6"},
		},
	}

	executeNewAndWaitForCanonicalCommit(t, d, ep, msg)

	_, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: command in text segment was not processed")
	}
}

// observeCommandMessages records, per delivery, the message the command hook of
// every activated extension sees. ExecuteNew preprocesses a private copy of the
// caller's message, and this hook runs after that rewrite.
func observeCommandMessages(d *Dice, name string) <-chan Message {
	received := make(chan Message, 4)
	d.RegisterExtension(&ExtInfo{
		Name:       name,
		AutoActive: true,
		OnCommandReceived: func(_ *MsgContext, msg *Message, _ *CmdArgs) {
			snapshot := *msg
			snapshot.Segment = slices.Clone(msg.Segment)
			received <- snapshot
		},
	})
	d.ApplyExtDefaultSettings()
	return received
}

func TestExecuteNew_MessagePreprocess_RewritesBeforeCommandParse(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	vm := goja.New()
	registerAutoActivePreprocessExt(d, "preprocess-rewrite-test", func(_ *MsgContext, msg *Message) goja.Value {
		if msg.Message != "roll-alias" {
			return goja.Undefined()
		}
		return vm.ToValue(map[string]interface{}{"message": ".r 1d6"})
	})
	received := observeCommandMessages(d, "preprocess-rewrite-observer")

	msg := newGroupMsg("QQ-Group:rewrite", "QQ:999", "roll-alias")
	executeNewAndWaitForCanonicalCommit(t, d, ep, msg)

	_, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected rewritten command to produce a reply")
	}
	select {
	case got := <-received:
		if got.Message != ".r 1d6" {
			t.Fatalf("message was not rewritten, got %q", got.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("command hook did not observe the preprocessed message")
	}
}

func TestExecuteNew_MessagePreprocess_RebuildsSegmentFromCQCode(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	vm := goja.New()
	registerAutoActivePreprocessExt(d, "preprocess-cq-test", func(_ *MsgContext, msg *Message) goja.Value {
		if msg.Message != "mention-roll" {
			return goja.Undefined()
		}
		return vm.ToValue(map[string]interface{}{"message": "[CQ:at,qq=100000] .r 1d6"})
	})
	received := observeCommandMessages(d, "preprocess-cq-observer")

	msg := newGroupMsg("QQ-Group:cq", "QQ:999", "mention-roll")
	executeNewAndWaitForCanonicalCommit(t, d, ep, msg)

	_, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected rewritten CQ-at command to produce a reply")
	}
	select {
	case got := <-received:
		if len(got.Segment) < 2 {
			t.Fatalf("expected rewritten message to rebuild segments, got %d segment(s)", len(got.Segment))
		}
		if _, ok := got.Segment[0].(*message.AtElement); !ok {
			t.Fatalf("first segment = %T, want *message.AtElement", got.Segment[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("command hook did not observe the preprocessed message")
	}
}

func TestExecuteNew_MessagePreprocess_EmptyMessageIntercepts(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	vm := goja.New()
	registerAutoActivePreprocessExt(d, "preprocess-empty-intercept-test", func(_ *MsgContext, _ *Message) goja.Value {
		return vm.ToValue(map[string]interface{}{"message": ""})
	})

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg("QQ-Group:intercept-empty", "QQ:999", ".r 1d6"))

	select {
	case got := <-adapter.msgCh:
		t.Fatalf("unexpected reply after empty-message intercept: %q", got)
	case <-time.After(400 * time.Millisecond):
	}
}

// TestExecuteNew_InvalidMessageType verifies that messages with an unsupported
// MessageType (neither "group" nor "private") are silently discarded.
func TestExecuteNew_InvalidMessageType(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	msg := &Message{
		Platform:    "QQ",
		MessageType: "channel", // unsupported
		GroupID:     "QQ-Group:111",
		Time:        time.Now().Unix(),
		Sender:      SenderBase{UserID: "QQ:999", Nickname: "Tester"},
		Message:     ".r",
		Segment:     []message.IMessageElement{&message.TextElement{Content: ".r"}},
	}

	executeNewAndWaitForCanonicalCommit(t, d, ep, msg)

	select {
	case got := <-adapter.msgCh:
		t.Errorf("unexpected reply for unsupported MessageType: %q", got)
	case <-time.After(300 * time.Millisecond):
		// expected: silently ignored
	}
}

// TestExecuteNew_MultipleGroups verifies that two independent canonical
// aggregates are created and commands do not bleed between them.
func TestExecuteNew_MultipleGroups(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	const (
		groupA = "QQ-Group:AAAA"
		groupB = "QQ-Group:BBBB"
	)

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg(groupA, "QQ:001", ".r"))
	_, okA := adapter.waitForMsg(2 * time.Second)

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg(groupB, "QQ:002", ".r"))
	_, okB := adapter.waitForMsg(2 * time.Second)

	if !okA {
		t.Error("group A: timeout waiting for reply")
	}
	if !okB {
		t.Error("group B: timeout waiting for reply")
	}

	stateA := awaitCanonicalGroupProjection(t, d, groupA, func(state groupstate.State) bool {
		return state.Active && state.GroupID == groupA
	})
	stateB := awaitCanonicalGroupProjection(t, d, groupB, func(state groupstate.State) bool {
		return state.Active && state.GroupID == groupB
	})
	if !stateA.Active || stateA.GroupID != groupA {
		t.Errorf("group A state = %#v", stateA)
	}
	if !stateB.Active || stateB.GroupID != groupB {
		t.Errorf("group B state = %#v", stateB)
	}
}
func TestExecuteWrappersShareCommandReplyAndUnsupportedOutcome(t *testing.T) {
	run := func(useNew bool) string {
		d, ep, adapter, cleanup := newExecuteNewTestDice(t)
		defer cleanup()
		msg := newPrivateMsg("QQ:999", ".help 骰点")
		if useNew {
			executeNewAndWaitForCanonicalCommit(t, d, ep, msg)
		} else {
			d.ImSession.Execute(ep, msg, true)
		}
		reply, ok := adapter.waitForMsg(2 * time.Second)
		if !ok {
			t.Fatalf("wrapper=%t did not reply to deterministic command", useNew)
		}
		return reply
	}
	legacyReply := run(false)
	segmentReply := run(true)
	if legacyReply != segmentReply {
		t.Fatalf("wrapper replies differ: legacy=%q segment=%q", legacyReply, segmentReply)
	}

	for _, useNew := range []bool{false, true} {
		d, ep, adapter, cleanup := newExecuteNewTestDice(t)
		msg := newPrivateMsg("QQ:999", ".unsupported-command")
		if useNew {
			executeNewAndWaitForCanonicalCommit(t, d, ep, msg)
		} else {
			d.ImSession.Execute(ep, msg, true)
		}
		select {
		case got := <-adapter.msgCh:
			t.Fatalf("wrapper=%t replied to unsupported command: %q", useNew, got)
		case <-time.After(300 * time.Millisecond):
		}
		cleanup()
	}
}

func TestExecuteNewPreservesSegmentMentionCommand(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	msg := newGroupMsg("QQ-Group:segment-mention", "QQ:999", "")
	msg.Message = ""
	msg.Segment = []message.IMessageElement{
		&message.AtElement{Target: "100000"},
		&message.TextElement{Content: ".help 骰点"},
	}
	executeNewAndWaitForCanonicalCommit(t, d, ep, msg)
	if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
		t.Fatal("segment-aware mention command did not produce a reply")
	}
}

func TestExecuteRunInSyncControlsNonCommandHookScheduling(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	groupID := "QQ-Group:sync-hook"
	hookCalls := make(chan struct{}, 2)
	extension := &ExtInfo{
		Name:                 "execute-sync-hook-test",
		OnNotCommandReceived: func(_ *MsgContext, _ *Message) { hookCalls <- struct{}{} },
	}
	activateCanonicalTestGroupExtensions(t, d, ep, groupID, "seed-sync-hook", extension)

	d.ImSession.Execute(ep, newGroupMsg(groupID, "QQ:999", "plain text"), true)
	select {
	case <-hookCalls:
	default:
		t.Fatal("Execute(..., true) returned before non-command hook ran")
	}

	asyncMessage := newGroupMsg(groupID, "QQ:998", "plain text")
	asyncIdentity := canonicalTestMessageExecutionIdentity(t, d, ep, asyncMessage, messageParserLegacy)
	d.ImSession.Execute(ep, asyncMessage, false)
	select {
	case <-hookCalls:
	case <-time.After(2 * time.Second):
		t.Fatal("Execute(..., false) did not schedule non-command hook")
	}
	awaitCanonicalTestExecutionCommit(t, d, asyncIdentity)
}

func TestExecuteMessageReleasesExecutionStateAfterSynchronousHooks(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	groupID := "QQ-Group:sync-release"
	extension := &ExtInfo{
		Name: "execute-sync-release-test",
		OnNotCommandReceived: func(ctx *MsgContext, _ *Message) {
			ctx.CreateVmIfNotExists()
			ctx.CommandInfo = make([]byte, 1024)
			ctx.DeckPools = map[*DeckInfo]map[string]*ShuffleRandomPool{}
		},
	}
	activateCanonicalTestGroupExtensions(t, d, ep, groupID, "seed-sync-release", extension)
	result := executeCanonicalTestMessage(context.Background(), d, ep, newGroupMsg(groupID, "QQ:999", "plain text"), messageExecutionOptions{
		parser:    messageParserLegacy,
		runInSync: true,
	})
	if result.err != nil {
		t.Fatalf("synchronous execution failed: %v", result.err)
	}
	if result.context == nil || !result.context.executionReleased.Load() {
		t.Fatal("synchronous execution returned before releasing transient state")
	}
	if result.context.vm != nil || result.context.CommandInfo != nil || result.context.DeckPools != nil {
		t.Fatalf("transient state retained after synchronous execution: vm=%p command=%T decks=%v", result.context.vm, result.context.CommandInfo, result.context.DeckPools)
	}
}

func TestExecuteMessageReleasesExecutionStateAfterLastAsynchronousHook(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	groupID := "QQ-Group:async-release"
	started := make(chan int, 2)
	finished := make(chan int, 2)
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	first := &ExtInfo{
		Name: "execute-async-release-first",
		OnNotCommandReceived: func(ctx *MsgContext, _ *Message) {
			ctx.CreateVmIfNotExists()
			ctx.CommandInfo = make([]byte, 1024)
			started <- 1
			<-releaseFirst
			finished <- 1
		},
	}
	second := &ExtInfo{
		Name: "execute-async-release-second",
		OnNotCommandReceived: func(_ *MsgContext, _ *Message) {
			started <- 2
			<-releaseSecond
			finished <- 2
		},
	}
	activateCanonicalTestGroupExtensions(t, d, ep, groupID, "seed-async-release", first, second)
	root := newCanonicalTestRoot(t, d, "async-release-execution")

	result := d.ImSession.executeMessage(ep, newGroupMsg(groupID, "QQ:999", "plain text"), messageExecutionOptions{
		parser:              messageParserLegacy,
		runInSync:           false,
		callbackTransaction: root.Transaction,
	})
	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("asynchronous hook did not start")
		}
	}
	if result.context == nil {
		t.Fatal("asynchronous execution did not return its context")
	}
	if result.context.executionReleased.Load() || result.context.vm == nil {
		t.Fatalf("execution state released while hooks are active: released=%v vm=%p", result.context.executionReleased.Load(), result.context.vm)
	}

	close(releaseFirst)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("first asynchronous hook did not finish")
	}
	if result.context.executionReleased.Load() {
		t.Fatal("execution state released before the last hook")
	}

	close(releaseSecond)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("second asynchronous hook did not finish")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !result.context.executionReleased.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !result.context.executionReleased.Load() {
		t.Fatal("execution state was not released after all hooks")
	}
	// The release flag closes admission before cleanup finishes.
	result.context.executionReleaseOnce.Do(func() {
		t.Fatal("release flag was published outside the cleanup fence")
	})
	if result.context.vm != nil || result.context.CommandInfo != nil {
		t.Fatalf("transient state retained after asynchronous execution: vm=%p command=%T", result.context.vm, result.context.CommandInfo)
	}
}

func TestExecuteLeavesUnsupportedMessageUnchanged(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	msg := &Message{
		Platform:    "QQ",
		MessageType: "channel",
		Sender:      SenderBase{UserID: "QQ:999", Nickname: "Tester"},
		Segment:     []message.IMessageElement{&message.TextElement{Content: ".r 1d1"}},
	}
	d.ImSession.Execute(ep, msg, true)
	if msg.Message != "" {
		t.Fatalf("unsupported Execute mutated Message to %q", msg.Message)
	}
	select {
	case got := <-adapter.msgCh:
		t.Fatalf("unsupported Execute replied: %q", got)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestExecuteSetsTempVarsBeforeNonCommandHook(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	groupID := "QQ-Group:temp-vars-hook"
	seen := make(chan string, 1)
	extension := &ExtInfo{
		Name: "execute-temp-vars-test",
		OnNotCommandReceived: func(ctx *MsgContext, _ *Message) {
			value, _ := VarGetValueStr(ctx, "$tQQ昵称")
			seen <- value
		},
	}
	activateCanonicalTestGroupExtensions(t, d, ep, groupID, "seed-temp-vars", extension)

	d.ImSession.Execute(ep, newGroupMsg(groupID, "QQ:999", "plain text"), true)
	select {
	case value := <-seen:
		if value != "<Tester>" {
			t.Fatalf("hook saw $tQQ昵称=%q, want <Tester>", value)
		}
	default:
		t.Fatal("non-command hook ran before temporary variables were initialized")
	}
}

func TestBanAddCommandReportsPersistenceFailure(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	_, store := openBanListEventStore(t, filepath.Join(d.BaseConfig.DataDir, "events.db"), true)
	d.BaseConfig.Name = banListEventStoreTestDiceID
	d.DurableStore = store
	d.DBOperator = nil
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := &MsgContext{Dice: d, EndPoint: ep, Session: d.ImSession, PrivilegeLevel: 100}
	msg := newPrivateMsg("QQ:999", ".ban add user QQ:storage-failure reason")
	result := d.CmdMap["ban"].Solve(ctx, msg, &CmdArgs{
		Args:    []string{"add", "user", "QQ:storage-failure", "reason"},
		RawArgs: "add user QQ:storage-failure reason",
	})
	if !result.Matched || !result.Solved {
		t.Fatalf("ban add result = %#v", result)
	}
	reply, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("ban add did not report the persistence failure")
	}
	if !strings.Contains(reply, "加入黑名单失败") || strings.Contains(reply, "已将") {
		t.Fatalf("ban add reply = %q, must report failure without confirmation", reply)
	}
}
