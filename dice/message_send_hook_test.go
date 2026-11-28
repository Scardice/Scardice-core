package dice

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/dop251/goja"
	"go.uber.org/zap/zaptest"
)

func TestBeforeMessageSendJSRewriteAndCancel(t *testing.T) {
	d := &Dice{
		Logger: zaptest.NewLogger(t).Sugar(), BaseConfig: BaseConfig{DataDir: t.TempDir()},
		DirtyGroups: new(SyncMap[string, int64]), AttrsManager: &AttrsManager{},
		ExtRegistry: new(SyncMap[string, *ExtInfo]),
	}
	session := &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	d.ImSession = session
	d.Config = NewConfig(d)
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "UI:bot", Platform: "UI"}}
	ep.Session = session
	adapter := &PlatformAdapterHTTP{EndPoint: ep}
	ep.Adapter = adapter
	ctx := &MsgContext{Dice: d, Session: session, EndPoint: ep}
	msg := &Message{MessageType: "group", GroupID: "UI-Group:2001", Message: ".original", Sender: SenderBase{UserID: "UI:user"}}
	hookEntered := make(chan struct{})
	releaseHook := make(chan struct{})

	d.JsInit()
	loop := d.ExtLoopManager.GetWebLoop()
	done := make(chan error, 1)
	if !loop.RunOnLoop(func(vm *goja.Runtime) {
		_ = vm.Set("testCtx", ctx)
		_ = vm.Set("testMsg", msg)
		_ = vm.Set("holdSendHook", func() {
			close(hookEntered)
			<-releaseHook
		})
		_ = vm.Set("finishSendTest", func(reason string) {
			if reason != "" {
				done <- errors.New(reason)
			} else {
				done <- nil
			}
		})
		_, err := vm.RunString(`
			const ext = seal.ext.new("test-send", "test", "1");
			if (!("onBeforeMessageSend" in ext)) throw new Error("missing outbound hook");
			let observed = [];
			let checkAsync = false;
			ext.onBeforeMessageSend = (ctx, outgoing) => {
				if (outgoing.message === "nested") seal.replyGroup(ctx, testMsg, "unexpected nested send");
				if (outgoing.message === "promise") {
					return Object.assign(Promise.resolve(), {message: "not a synchronous result"});
				}
				if (outgoing.message === "slow cancel") {
					holdSendHook();
					return "";
				}
				if (outgoing.message === "go") {
					Promise.resolve().then(() => seal.replyGroup(ctx, testMsg, "deferred"));
				}
				if (outgoing.message === "cancel") return "";
				if (outgoing.message === "prefix") {
					ctx.delegateText = "unexpected prefix ";
					return;
				}
				return outgoing.targetId + " " + outgoing.message;
			};
			ext.onMessageSend = (ctx, msg) => {
				observed.push(msg.message);
				if (checkAsync) {
					checkAsync = false;
					finishSendTest(msg.message === "UI-Group:2001 async" ? "" : "async send: " + msg.message);
				}
			};
			const cmd = seal.ext.newCmdItemInfo();
			cmd.name = "cancelreply";
			cmd.solve = (ctx, msg) => { seal.replyToSender(ctx, msg, "slow cancel"); };
			ext.cmdMap = { cancelreply: cmd };
			seal.ext.register(ext);
		`)
		if err == nil {
			d.ApplyExtDefaultSettings()
			ctx.Group = SetBotOnAtGroup(ctx, msg.GroupID)
			ctx.IsCurGroupBotOn = true
			SetBotOnAtGroup(ctx, "PG-UI:user")
			_, err = vm.RunString(`
				seal.replyGroup(testCtx, testMsg, "hello");
				seal.replyGroup(testCtx, testMsg, "cancel");
				seal.replyGroup(testCtx, testMsg, "nested");
				seal.replyGroup(testCtx, testMsg, "promise");
				seal.replyGroup(testCtx, testMsg, "prefix");
				(async () => {
					await new Promise(resolve => setTimeout(resolve, 1));
					seal.replyPerson(testCtx, testMsg, "private");
					if (observed.join(",") !== "UI-Group:2001 hello,nested,promise,prefix,UI:user private") {
						throw new Error("unexpected sends: " + observed);
					}
					checkAsync = true;
					seal.replyToSender(testCtx, testMsg, "async");
				})().catch(err => finishSendTest(String(err)));
			`)
		}
		if err != nil {
			done <- err
		}
	}) {
		t.Fatal("JS loop rejected validation task")
	}
	select {
	case err := <-done:
		t.Cleanup(func() {
			d.JsScriptCron.Stop()
			d.ExtLoopManager.SetLoop(nil)
		})
		if err != nil {
			t.Fatalf("%v; transport = %#v", err, adapter.RecentMessage)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reply did not return on the JS loop")
	}
	go func() {
		ReplyGroup(ctx, msg, "go")
		done <- nil
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reply from Go did not return")
	}
	want := []HTTPSimpleMessage{
		{"UI-Group:2001", "UI-Group:2001 hello", "group"},
		{"UI-Group:2001", "nested", "group"},
		{"UI-Group:2001", "promise", "group"},
		{"UI-Group:2001", "prefix", "group"},
		{"UI:user", "UI:user private", "private"},
		{"UI-Group:2001", "UI-Group:2001 async", "group"},
		{"UI-Group:2001", "UI-Group:2001 deferred", "group"},
		{"UI-Group:2001", "UI-Group:2001 go", "group"},
	}
	if !slices.Equal(adapter.RecentMessage, want) {
		t.Fatalf("outbound messages = %#v, want %#v", adapter.RecentMessage, want)
	}
	if msg.Message != ".original" {
		t.Fatalf("inbound message changed to %q", msg.Message)
	}

	result := make(chan commandSolveResult, 1)
	go func() { result <- session.commandSolve(ctx, msg, &CmdArgs{Command: "cancelreply"}) }()
	select {
	case <-hookEntered:
	case <-time.After(5 * time.Second):
		close(releaseHook)
		t.Fatal("legacy command did not reach the outbound hook")
	}
	select {
	case got := <-result:
		close(releaseHook)
		if got.Status != commandSolveSolved {
			t.Fatalf("cancelled asynchronous reply left command in state %v", got.Status)
		}
	case <-time.After(5 * time.Second):
		close(releaseHook)
		t.Fatal("legacy command waited for the outbound hook to finish")
	}
}
