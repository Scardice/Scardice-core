package dice

import (
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func newJSLoadGateFixture(t *testing.T) (*Dice, *ExtInfo, jsengine.Loop, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zapcore.WarnLevel)
	manager := NewJsLoopManager()
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	generation := manager.SetLoop(loop)
	d := &Dice{
		Logger:         zap.New(core).Sugar(),
		ExtLoopManager: manager,
		Config:         Config{JsConfig: JsConfig{JsEnable: true}},
	}
	ext := &ExtInfo{Name: "late-plugin", IsJsExt: true, JSLoopVersion: generation}
	return d, ext, loop, logs
}

func TestJSCallbacksAreDroppedWithLogUntilScriptLoadCompletes(t *testing.T) {
	d, ext, _, logs := newJSLoadGateFixture(t)
	var calls atomic.Int64

	d.setJsReloading(true)
	ext.callWithJsCheck(d, func() { calls.Add(1) },
		jsCallbackDispatch{kind: jsCallbackMessage, providerEventID: "1\x00event-before-load"})
	ext.notifyWithJsCheck(d, func() { calls.Add(1) },
		jsCallbackDispatch{kind: jsCallbackSend, providerEventID: "event-send-before-load"})

	if got := calls.Load(); got != 0 {
		t.Fatalf("callbacks delivered while scripts were still loading: %d", got)
	}
	entries := logs.FilterMessageSnippet("已丢弃回调").All()
	if len(entries) != 2 {
		t.Fatalf("drop log count = %d, want one per dropped callback; logs=%v", len(entries), logs.All())
	}
	for index, want := range []struct{ kind, event string }{
		{string(jsCallbackMessage), "1:event-before-load"},
		{string(jsCallbackSend), "event-send-before-load"},
	} {
		entry := entries[index]
		if entry.Level != zapcore.WarnLevel {
			t.Errorf("drop log level = %v, want warn", entry.Level)
		}
		for _, field := range []string{"late-plugin", want.kind, want.event} {
			if !strings.Contains(entry.Message, field) {
				t.Errorf("drop log %q does not identify %q", entry.Message, field)
			}
		}
		if strings.ContainsRune(entry.Message, 0) {
			t.Errorf("drop log contains a raw NUL separator: %q", entry.Message)
		}
	}
	if errorLogs := logs.FilterMessageSnippet("JS脚本异常").Len(); errorLogs != 0 {
		t.Fatalf("a deliberate drop was reported as a script exception %d times", errorLogs)
	}

	d.setJsReloading(false)
	ext.callWithJsCheck(d, func() { calls.Add(1) },
		jsCallbackDispatch{kind: jsCallbackMessage, providerEventID: "event-after-load"})
	if got := calls.Load(); got != 1 {
		t.Fatalf("callbacks after load completion = %d, want exactly the post-load callback", got)
	}
	if logs.FilterMessageSnippet("已丢弃回调").Len() != 2 {
		t.Fatal("post-load delivery produced another drop log")
	}
}

func TestJSCallbacksRaisedByLoadingScriptsStillRunInsideTheirRealm(t *testing.T) {
	d, ext, loop, logs := newJSLoadGateFixture(t)
	var calls atomic.Int64

	d.setJsReloading(true)
	if err := jsengine.RunWithContext(loop, jsContextForPlugin(ext), func(jsengine.Runtime) error {
		ext.callWithJsCheck(d, func() { calls.Add(1) }, jsCallbackDispatch{kind: jsCallbackSend})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback raised from the owner loop during load ran %d times, want 1", got)
	}
	if logs.Len() != 0 {
		t.Fatalf("owner-loop callback produced logs: %v", logs.All())
	}
}

func TestJSLoadDropSummaryIsLoggedOnceAndOnlyWhenSomethingWasDropped(t *testing.T) {
	d, ext, _, logs := newJSLoadGateFixture(t)
	other := &ExtInfo{Name: "other-plugin", IsJsExt: true, JSLoopVersion: ext.JSLoopVersion}
	noop := func() {}

	d.setJsReloading(true)
	d.setJsReloading(false)
	if logs.Len() != 0 {
		t.Fatalf("a load that dropped nothing logged: %v", logs.All())
	}

	d.setJsReloading(true)
	for range 3 {
		ext.callWithJsCheck(d, noop, jsCallbackDispatch{kind: jsCallbackMessage})
	}
	other.notifyWithJsCheck(d, noop, jsCallbackDispatch{kind: jsCallbackSend})
	ext.notifyWithJsCheck(d, noop, jsCallbackDispatch{kind: jsCallbackSend})
	d.setJsReloading(false)
	if got := logs.FilterMessageSnippet("已丢弃回调").Len(); got != 3 {
		t.Fatalf("per-drop log count = %d, want one per plugin and callback kind (3); logs=%v", got, logs.All())
	}
	summaries := logs.FilterMessageSnippet("加载期间共丢弃").All()
	if len(summaries) != 1 {
		t.Fatalf("summary count = %d, want 1; logs=%v", len(summaries), logs.All())
	}
	if summaries[0].Level != zapcore.WarnLevel {
		t.Errorf("summary level = %v, want warn", summaries[0].Level)
	}
	for _, want := range []string{"共丢弃 5 个回调", "「late-plugin」message×3", "「late-plugin」send×1", "「other-plugin」send×1"} {
		if !strings.Contains(summaries[0].Message, want) {
			t.Errorf("summary %q does not contain %q", summaries[0].Message, want)
		}
	}

	d.setJsReloading(true)
	ext.callWithJsCheck(d, noop, jsCallbackDispatch{kind: jsCallbackMessage})
	d.setJsReloading(false)
	if got := logs.FilterMessageSnippet("已丢弃回调").Len(); got != 4 {
		t.Fatalf("a new load did not log its first drop again: %d per-drop logs", got)
	}
	summaries = logs.FilterMessageSnippet("加载期间共丢弃").All()
	if len(summaries) != 2 || !strings.Contains(summaries[1].Message, "共丢弃 1 个回调") {
		t.Fatalf("the second load reused the first load's counters: %v", summaries)
	}
}

func TestJSCommandsIssuedDuringScriptLoadAreDroppedAndLogged(t *testing.T) {
	calls := 0
	pluginExt := &ExtInfo{
		Name:    "cmd-plugin",
		IsJsExt: true,
		CmdMap: CmdMapCls{"probecmd": {Name: "probecmd", Solve: func(*MsgContext, *Message, *CmdArgs) CmdExecuteResult {
			calls++
			return CmdExecuteResult{Matched: true, Solved: true}
		}}},
		DefaultSetting: &ExtDefaultSettingItem{DisabledCommand: map[string]bool{}},
	}
	wrapper := &ExtInfo{
		Name: "cmd-plugin", TargetName: "cmd-plugin", IsWrapper: true,
		DefaultSetting: &ExtDefaultSettingItem{DisabledCommand: map[string]bool{}},
	}
	core, logs := observer.New(zapcore.WarnLevel)
	d := newTestDice([]*ExtInfo{wrapper})
	d.Logger = zap.New(core).Sugar()
	d.CmdMap = CmdMapCls{}
	d.JsExtRegistry = new(SyncMap[string, *ExtInfo])
	d.JsExtRegistry.Store("cmd-plugin", pluginExt)
	group := newTestGroupInfo()
	group.SetActivatedExtList([]*ExtInfo{wrapper}, d)
	group.Active = true
	session := &IMSession{Parent: d}
	ctx := &MsgContext{Dice: d, Session: session, Group: group, IsPrivate: true}
	msg := &Message{}

	d.setJsReloading(true)
	if result := session.commandSolve(ctx, msg, &CmdArgs{Command: "probecmd"}); result.Status == commandSolveSolved || calls != 0 {
		t.Fatalf("plugin command ran while scripts were loading: status=%v calls=%d", result.Status, calls)
	}
	drops := logs.FilterMessageSnippet("已丢弃回调").All()
	if len(drops) != 1 {
		t.Fatalf("drop log count = %d, want 1 for the issued command; logs=%v", len(drops), logs.All())
	}
	for _, want := range []string{"cmd-plugin", string(jsCallbackCommand), "probecmd"} {
		if !strings.Contains(drops[0].Message, want) {
			t.Errorf("drop log %q does not identify %q", drops[0].Message, want)
		}
	}
	session.commandSolve(ctx, msg, &CmdArgs{Command: "probecmd"})
	session.commandSolve(ctx, msg, &CmdArgs{Command: "unrelated"})
	if logs.FilterMessageSnippet("已丢弃回调").Len() != 1 {
		t.Fatalf("a command no plugin registered was logged: %v", logs.All())
	}

	d.setJsReloading(false)
	summaries := logs.FilterMessageSnippet("加载期间共丢弃").All()
	if len(summaries) != 1 || !strings.Contains(summaries[0].Message, "「cmd-plugin」command×2") {
		t.Fatalf("summary missing the dropped command: %v", summaries)
	}
	if result := session.commandSolve(ctx, msg, &CmdArgs{Command: "probecmd"}); result.Status != commandSolveSolved || calls != 1 {
		t.Fatalf("plugin command after load: status=%v calls=%d", result.Status, calls)
	}
	if logs.Len() != 2 {
		t.Fatalf("post-load command produced extra logs: %v", logs.All())
	}
}
