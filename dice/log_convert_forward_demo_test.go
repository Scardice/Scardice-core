package dice

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dop251/goja"
	"go.uber.org/zap"

	"Scardice-core/message"
)

func TestLogConvertForwardDemoLoadsAndCollectsInGoja(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "docs", "examples", "logConvertForwardDemo.js"))
	if err != nil {
		t.Fatal(err)
	}

	adapter := newForwardCaptureAdapter()
	d := &Dice{
		Logger: zap.NewNop().Sugar(), BaseConfig: BaseConfig{DataDir: t.TempDir()},
		ImSession:   &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo]), EndPoints: []*EndPointInfo{}},
		DirtyGroups: new(SyncMap[string, int64]), AttrsManager: &AttrsManager{},
	}
	endpoint := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{ID: "demo-endpoint", UserID: "QQ:4242", Platform: "QQ"},
		Adapter:          adapter,
	}
	ctx := &MsgContext{Dice: d, EndPoint: endpoint}

	d.JsInit()
	defer func() {
		if d.JsScriptCron != nil {
			d.JsScriptCron.Stop()
		}
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	}()

	done := make(chan error, 1)
	loop := d.ExtLoopManager.GetWebLoop()
	if !loop.RunOnLoop(func(vm *goja.Runtime) {
		if _, runErr := vm.RunString(string(script)); runErr != nil {
			done <- runErr
			return
		}

		startMsg := &Message{
			Time: 100, MessageType: "group", GroupID: "QQ-Group:9000", Platform: "QQ",
			Sender: SenderBase{UserID: "QQ:7", Nickname: "operator"},
		}
		forwardMsg := &Message{
			Time: 101, MessageType: "group", GroupID: "QQ-Group:9000", Platform: "QQ",
			Sender: SenderBase{UserID: "QQ:7", Nickname: "operator"},
			Segment: []message.IMessageElement{&message.ForwardElement{
				Kind: "forward", Loaded: true,
				Nodes: []message.ForwardNode{{
					SenderID: "10001", SenderName: "Alice", Time: 102,
					Elements: message.ConvertStringMessage("hello from forward"),
				}},
			}},
		}
		_ = vm.Set("demoCtx", ctx)
		_ = vm.Set("demoStartMsg", startMsg)
		_ = vm.Set("demoStartArgs", &CmdArgs{Args: []string{"开始"}})
		_ = vm.Set("demoForwardMsg", forwardMsg)
		if _, runErr := vm.RunString(`
			if (!ext.cmdMap.logconvert || !ext.cmdMap["log转写"]) throw new Error("missing command aliases");
			ext.cmdMap.logconvert.solve(demoCtx, demoStartMsg, demoStartArgs);
			ext.onMessageReceived(demoCtx, demoForwardMsg);
		`); runErr != nil {
			done <- runErr
			return
		}

		value, runErr := vm.RunString(`(() => {
			let captured = "";
			collectingSessions.forEach((session) => {
				if (session.items.length === 1) captured = session.items[0].IMUserId + "|" + session.items[0].message;
			});
			if (captured) return captured;
			return "sessions=" + collectingSessions.size +
				";segments=" + (demoForwardMsg.segment && demoForwardMsg.segment.length) +
				";nodes=" + (demoForwardMsg.segment && demoForwardMsg.segment[0] && demoForwardMsg.segment[0].nodes && demoForwardMsg.segment[0].nodes.length);
		})()`)
		if runErr != nil {
			done <- runErr
			return
		}
		if value.String() != "QQ:10001|hello from forward" {
			done <- &logConvertDemoValueError{got: value.String()}
			return
		}
		done <- nil
	}) {
		t.Fatal("JS loop rejected demo validation task")
	}

	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatal(runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("log converter demo validation timed out")
	}
}

type logConvertDemoValueError struct{ got string }

func (e *logConvertDemoValueError) Error() string {
	return "unexpected log converter demo value: " + e.got
}
