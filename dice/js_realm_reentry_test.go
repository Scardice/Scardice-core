package dice

import (
	"testing"
	"time"

	"Scardice-core/dice/sealpack"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

// A JS plugin calling seal.replyToSender runs on the realm goroutine, and the
// adapter answers with OnMessageSend. Waiting for that hook to switch back into
// the realm would block on a job the busy realm can never dequeue.
func TestJSExtMessageSendHookFromInsideRealmDoesNotDeadlock(t *testing.T) {
	const packageID = "author/send-hook"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{})
	d.Config.JsEnable = true
	rawLoop := startFsTestLoop(t)
	engineLoop := gojaengine.WrapEventLoop(rawLoop)
	d.ExtLoopManager = NewJsLoopManager()
	version := d.ExtLoopManager.SetLoop(engineLoop)
	t.Cleanup(func() {
		d.ExtLoopManager.SetLoop(nil)
	})

	hookRan := make(chan string, 1)
	ext := &ExtInfo{
		Name:          "send-hook",
		IsJsExt:       true,
		JSLoopVersion: version,
		OnMessageSend: func(_ *MsgContext, msg *Message, _ string) {
			hookRan <- msg.Message
		},
	}
	d.ExtList = []*ExtInfo{ext}
	d.ImSession.Parent = d

	ctx := &MsgContext{Dice: d, Session: d.ImSession}
	if err := jsengine.RunWithContext(engineLoop, jsContextForPlugin(ext), func(jsengine.Runtime) error {
		d.ImSession.OnMessageSend(ctx, &Message{Message: "from realm", MessageType: "private"}, "")
		return nil
	}); err != nil {
		t.Fatalf("realm callback error = %v", err)
	}

	select {
	case text := <-hookRan:
		if text != "from realm" {
			t.Fatalf("hook message = %q, want from realm", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnMessageSend hook never ran")
	}
}

// The same hook must still reach a JS extension when the send originates
// outside the realm, which is the ordinary platform-adapter path.
func TestJSExtMessageSendHookFromOutsideRealmStillRuns(t *testing.T) {
	const packageID = "author/send-hook-external"
	d := newPermissionTestDice(t, packageID, sealpack.Permissions{})
	d.Config.JsEnable = true
	rawLoop := startFsTestLoop(t)
	engineLoop := gojaengine.WrapEventLoop(rawLoop)
	d.ExtLoopManager = NewJsLoopManager()
	version := d.ExtLoopManager.SetLoop(engineLoop)
	t.Cleanup(func() {
		d.ExtLoopManager.SetLoop(nil)
	})

	seen := make(chan any, 1)
	ext := &ExtInfo{
		Name:          "send-hook-external",
		IsJsExt:       true,
		JSLoopVersion: version,
		OnMessageSend: func(*MsgContext, *Message, string) {
			seen <- jsengine.CurrentContext(engineLoop)
		},
	}
	d.ExtList = []*ExtInfo{ext}
	d.ImSession.Parent = d

	ctx := &MsgContext{Dice: d, Session: d.ImSession}
	d.ImSession.OnMessageSend(ctx, &Message{Message: "external", MessageType: "private"}, "")

	select {
	case context := <-seen:
		plugin, ok := context.(*jsExecutionContext)
		if !ok || plugin == nil || plugin.Plugin != ext {
			t.Fatalf("hook context = %#v, want the extension plugin context", context)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnMessageSend hook never ran")
	}
}
