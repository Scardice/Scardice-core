package dice

import (
	"context"
	"testing"

	"Scardice-core/dice/jsengine"
	"Scardice-core/logger"
)

type mockQuickJSScriptEngine struct {
	lastExtName      string
	lastCmdName      string
	lastCallbackName string
	lastRuntime      map[string]any
}

func (m *mockQuickJSScriptEngine) Name() jsengine.EngineName { return jsengine.EngineQuickJS }
func (m *mockQuickJSScriptEngine) Init(context.Context, jsengine.Config) error {
	return nil
}
func (m *mockQuickJSScriptEngine) Dispose() error { return nil }
func (m *mockQuickJSScriptEngine) Eval(string) error {
	return nil
}
func (m *mockQuickJSScriptEngine) Require(string) error { return nil }
func (m *mockQuickJSScriptEngine) RegisterHostAPI(jsengine.HostAPI) error {
	return nil
}
func (m *mockQuickJSScriptEngine) Reset() error { return nil }
func (m *mockQuickJSScriptEngine) InvokeStoredSolve(extName string, cmdName string, runtime map[string]any) (map[string]any, error) {
	m.lastExtName = extName
	m.lastCmdName = cmdName
	m.lastRuntime = runtime
	return map[string]any{"matched": true, "solved": true}, nil
}
func (m *mockQuickJSScriptEngine) InvokeStoredCmdHelp(extName string, cmdName string, isShort bool) (string, error) {
	m.lastExtName = extName
	m.lastCmdName = cmdName
	if isShort {
		return "short", nil
	}
	return "long", nil
}
func (m *mockQuickJSScriptEngine) InvokeStoredExtCallback(extName string, callbackName string, runtime map[string]any) error {
	m.lastExtName = extName
	m.lastCallbackName = callbackName
	m.lastRuntime = runtime
	return nil
}
func (m *mockQuickJSScriptEngine) Quiesce() error { return nil }

type mockClearEngine struct {
	name           jsengine.EngineName
	disposeCalled  bool
	quiesceCalled  bool
	panicOnQuiesce bool
}

func (m *mockClearEngine) Name() jsengine.EngineName { return m.name }
func (m *mockClearEngine) Init(context.Context, jsengine.Config) error {
	return nil
}
func (m *mockClearEngine) Dispose() error {
	m.disposeCalled = true
	return nil
}
func (m *mockClearEngine) Eval(string) error                      { return nil }
func (m *mockClearEngine) Require(string) error                   { return nil }
func (m *mockClearEngine) RegisterHostAPI(jsengine.HostAPI) error { return nil }
func (m *mockClearEngine) Reset() error                           { return nil }
func (m *mockClearEngine) Quiesce() error {
	m.quiesceCalled = true
	if m.panicOnQuiesce {
		panic("boom")
	}
	return nil
}

func TestBuildQuickJSCmdInfoRestoresMetadataAndRuntime(t *testing.T) {
	engine := &mockQuickJSScriptEngine{}
	d := &Dice{
		ScriptEngine: engine,
		Logger:       logger.M(),
	}

	cmdInfo := buildQuickJSCmdInfo(d, "demo", "ping", map[string]any{
		"shortHelp":               ".ping // pong",
		"help":                    "long help",
		"allowDelegate":           true,
		"disabledInPrivate":       true,
		"enableExecuteTimesParse": true,
		"raw":                     true,
		"checkCurrentBotOn":       true,
		"checkMentionOthers":      true,
		"__sdHasHelpFunc":         true,
	})

	if cmdInfo.ShortHelp != ".ping // pong" {
		t.Fatalf("ShortHelp 未恢复: %q", cmdInfo.ShortHelp)
	}
	if !cmdInfo.AllowDelegate || !cmdInfo.DisabledInPrivate || !cmdInfo.EnableExecuteTimesParse {
		t.Fatalf("命令标志未完整恢复: %+v", cmdInfo)
	}
	if !cmdInfo.Raw || !cmdInfo.CheckCurrentBotOn || !cmdInfo.CheckMentionOthers {
		t.Fatalf("QuickJS 扩展标志未恢复: %+v", cmdInfo)
	}
	if cmdInfo.HelpFunc == nil {
		t.Fatalf("HelpFunc 未恢复: %+v", cmdInfo)
	}
	if got := cmdInfo.HelpFunc(true); got != "short" {
		t.Fatalf("HelpFunc 返回值异常: %q", got)
	}

	ctx := &MsgContext{MessageType: "group", PrivilegeLevel: 70}
	msg := &Message{
		MessageType: "group",
		Message:     ".ping",
		Platform:    "QQ",
		GroupID:     "group-1",
		Sender: SenderBase{
			Nickname: "tester",
			UserID:   "user-1",
		},
	}
	cmdArgs := &CmdArgs{
		Command: "ping",
		Args:    []string{"a", "b"},
		RawArgs: "a b",
	}

	ret := cmdInfo.Solve(ctx, msg, cmdArgs)
	if !ret.Matched || !ret.Solved {
		t.Fatalf("Solve 返回值异常: %+v", ret)
	}
	if engine.lastExtName != "demo" || engine.lastCmdName != "ping" {
		t.Fatalf("未正确转发命令调用: ext=%s cmd=%s", engine.lastExtName, engine.lastCmdName)
	}
	if engine.lastRuntime["ctx"] != ctx || engine.lastRuntime["msg"] != msg || engine.lastRuntime["cmdArgs"] != cmdArgs {
		t.Fatal("未传递原始运行时引用")
	}
	ctxData, ok := engine.lastRuntime["ctxData"].(map[string]any)
	if !ok || ctxData["privilegeLevel"] != 70 {
		t.Fatalf("ctxData 快照异常: %#v", engine.lastRuntime["ctxData"])
	}
	msgData, ok := engine.lastRuntime["msgData"].(map[string]any)
	if !ok || msgData["message"] != ".ping" {
		t.Fatalf("msgData 快照异常: %#v", engine.lastRuntime["msgData"])
	}
	cmdArgsData, ok := engine.lastRuntime["cmdArgsData"].(map[string]any)
	if !ok || cmdArgsData["command"] != "ping" {
		t.Fatalf("cmdArgsData 快照异常: %#v", engine.lastRuntime["cmdArgsData"])
	}
}

func TestConvertJsExtInfoBindsQuickJSCallbacks(t *testing.T) {
	engine := &mockQuickJSScriptEngine{}
	d := &Dice{
		ScriptEngine: engine,
		Logger:       logger.M(),
	}

	ext, err := convertJsExtInfo(d, map[string]any{
		"name":          "demo",
		"aliases":       []any{"alias1"},
		"activeWith":    []any{"base"},
		"__sdCallbacks": []any{"onLoad", "onMessageReceived", "onMessageSend"},
	})
	if err != nil {
		t.Fatalf("convertJsExtInfo 返回错误: %v", err)
	}
	if ext == nil {
		t.Fatal("convertJsExtInfo 返回 nil")
	}
	if len(ext.Aliases) != 1 || ext.Aliases[0] != "alias1" {
		t.Fatalf("别名未恢复: %+v", ext.Aliases)
	}
	if len(ext.ActiveWith) != 1 || ext.ActiveWith[0] != "base" {
		t.Fatalf("ActiveWith 未恢复: %+v", ext.ActiveWith)
	}
	if ext.OnLoad != nil {
		t.Fatalf("OnLoad 不应通过 Go 侧桥接，避免注册期重入: %+v", ext)
	}
	if ext.OnMessageReceived == nil {
		t.Fatalf("QuickJS 回调未正确桥接: %+v", ext)
	}
	if ext.OnMessageSend != nil {
		t.Fatalf("OnMessageSend 不应通过 Go 侧桥接，避免 runtimeMu 重入死锁: %+v", ext)
	}

	msg := &Message{Message: "hello", MessageType: "group"}
	ctx := &MsgContext{PrivilegeLevel: 50}
	ext.OnMessageReceived(ctx, msg)
	if engine.lastCallbackName != "onMessageReceived" {
		t.Fatalf("OnMessageReceived 未桥接到 QuickJS: %s", engine.lastCallbackName)
	}
	ctxData, ok := engine.lastRuntime["ctxData"].(map[string]any)
	if !ok || ctxData["privilegeLevel"] != 50 {
		t.Fatalf("回调 ctxData 快照异常: %#v", engine.lastRuntime["ctxData"])
	}
	msgData, ok := engine.lastRuntime["msgData"].(map[string]any)
	if !ok || msgData["message"] != "hello" {
		t.Fatalf("回调 msgData 快照异常: %#v", engine.lastRuntime["msgData"])
	}
}

func TestJsClearQuiescesQuickJSInsteadOfDispose(t *testing.T) {
	engine := &mockClearEngine{name: jsengine.EngineQuickJS}
	d := &Dice{
		ScriptEngine: engine,
		Logger:       logger.M(),
	}

	d.jsClear()

	if !engine.quiesceCalled {
		t.Fatal("QuickJS 引擎应走 Quiesce 路径")
	}
	if engine.disposeCalled {
		t.Fatal("QuickJS 引擎不应直接 Dispose")
	}
	if d.ScriptEngine != nil {
		t.Fatal("jsClear 后 ScriptEngine 应为空")
	}
	if len(d.RetiredJSEngines) != 1 {
		t.Fatalf("退役引擎应被保留，实际=%d", len(d.RetiredJSEngines))
	}
}

func TestJsClearDisposesOlderRetiredEngines(t *testing.T) {
	oldEngine := &mockClearEngine{name: jsengine.EngineQuickJS}
	newEngine := &mockClearEngine{name: jsengine.EngineQuickJS}
	d := &Dice{
		ScriptEngine:     newEngine,
		RetiredJSEngines: []jsengine.Engine{oldEngine},
		Logger:           logger.M(),
	}

	d.jsClear()

	if !oldEngine.disposeCalled {
		t.Fatal("旧退役引擎应在下一次清理时释放")
	}
	if len(d.RetiredJSEngines) != 1 {
		t.Fatalf("应只保留一个新的退役引擎，实际=%d", len(d.RetiredJSEngines))
	}
}

func TestJsClearRecoversEnginePanic(t *testing.T) {
	engine := &mockClearEngine{name: jsengine.EngineQuickJS, panicOnQuiesce: true}
	d := &Dice{
		ScriptEngine: engine,
		Logger:       logger.M(),
	}

	d.jsClear()

	if !engine.quiesceCalled {
		t.Fatal("应尝试调用 Quiesce")
	}
	if d.ScriptEngine != nil {
		t.Fatal("发生 panic 后也应清空 ScriptEngine")
	}
	if d.JsExtRegistry == nil {
		t.Fatal("发生 panic 后应完成状态清理")
	}
}
