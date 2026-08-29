package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	milky "github.com/Szzrain/Milky-go-sdk"
	"github.com/dop251/goja"
	"go.uber.org/zap"

	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/message"
)

type forwardCaptureAdapter struct {
	*mockPlatformAdapter
	muForward      sync.Mutex
	groupForwards  [][]message.ForwardNode
	personForwards [][]message.ForwardNode
}

func newForwardCaptureAdapter() *forwardCaptureAdapter {
	return &forwardCaptureAdapter{mockPlatformAdapter: newMockPlatformAdapter()}
}

func (a *forwardCaptureAdapter) SendGroupForwardMsg(_ *MsgContext, _ string, nodes []message.ForwardNode) bool {
	a.muForward.Lock()
	a.groupForwards = append(a.groupForwards, nodes)
	a.muForward.Unlock()
	return true
}

func (a *forwardCaptureAdapter) SendPrivateForwardMsg(_ *MsgContext, _ string, nodes []message.ForwardNode) bool {
	a.muForward.Lock()
	a.personForwards = append(a.personForwards, nodes)
	a.muForward.Unlock()
	return true
}

func TestForwardMixedDeliveryUsesSelfIdentityAndInternalSplit(t *testing.T) {
	adapter := newForwardCaptureAdapter()
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		UserID: "QQ:4242", Nickname: "SelfBot", Platform: "TEST",
	}, Adapter: adapter}
	ctx := &MsgContext{EndPoint: endpoint}
	msg := &Message{MessageType: "group", GroupID: "QQ-Group:9000"}
	inside := ctx.TranslateSplit("first#{SPLIT}second")
	deliverReplyPlan(ctx, msg, "before\n"+ctx.wrapForward(inside)+"\nafter", "", true)

	adapter.mu.Lock()
	ordinary := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	if len(ordinary) != 2 || ordinary[0] != "before" || ordinary[1] != "after" {
		t.Fatalf("ordinary deliveries = %#v", ordinary)
	}
	adapter.muForward.Lock()
	defer adapter.muForward.Unlock()
	if len(adapter.groupForwards) != 1 || len(adapter.groupForwards[0]) != 2 {
		t.Fatalf("forward deliveries = %#v", adapter.groupForwards)
	}
	for index, node := range adapter.groupForwards[0] {
		if node.SenderID != "4242" || node.SenderName != "SelfBot" {
			t.Fatalf("node %d identity = (%q, %q)", index, node.SenderID, node.SenderName)
		}
	}
}

type onebotForwardRawEmitter struct {
	*onebotRecallTestEmitter
	muRaw       sync.Mutex
	action      emitter.Action
	params      any
	response    []byte
	responseErr error
}

func (e *onebotForwardRawEmitter) Raw(_ context.Context, action emitter.Action, params any) ([]byte, error) {
	e.muRaw.Lock()
	e.action, e.params = action, params
	e.muRaw.Unlock()
	return e.response, e.responseErr
}

func TestOnebotForwardSendAndExpandProtocolPayloads(t *testing.T) {
	em := &onebotForwardRawEmitter{onebotRecallTestEmitter: &onebotRecallTestEmitter{}}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:4242", Nickname: "SelfBot"}}
	adapter := &PlatformAdapterOnebot{EndPoint: endpoint, sendEmitter: em, ctx: context.Background(), logger: zap.NewNop().Sugar()}
	nodes := []message.ForwardNode{{SenderID: "4242", SenderName: "SelfBot", Elements: message.ConvertStringMessage("hello")}}
	if !adapter.SendGroupForwardMsg(&MsgContext{EndPoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Platform: "TEST"}}}, "QQ-Group:9000", nodes) {
		t.Fatal("OneBot forward send failed")
	}
	em.muRaw.Lock()
	if em.action != "send_group_forward_msg" {
		t.Fatalf("action = %q", em.action)
	}
	payload, err := json.Marshal(em.params)
	em.muRaw.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var sent struct {
		GroupID  int64 `json:"group_id"`
		Messages []struct {
			Type string `json:"type"`
			Data struct {
				UserID   int64  `json:"user_id"`
				Nickname string `json:"nickname"`
				Content  []struct {
					Type string `json:"type"`
				} `json:"content"`
			} `json:"data"`
		} `json:"messages"`
	}
	if err = json.Unmarshal(payload, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.GroupID != 9000 || len(sent.Messages) != 1 || sent.Messages[0].Type != "node" || sent.Messages[0].Data.UserID != 4242 || sent.Messages[0].Data.Nickname != "SelfBot" || len(sent.Messages[0].Data.Content) != 1 || sent.Messages[0].Data.Content[0].Type != "text" {
		t.Fatalf("unexpected OneBot payload: %s", payload)
	}

	em.response = []byte(`{"status":"ok","retcode":0,"data":{"message":[{"type":"node","data":{"user_id":10001,"nickname":"nested","content":[{"type":"text","data":{"text":".r 9d9"}}]}}]}}`)
	msg := &Message{Segment: []message.IMessageElement{&message.ForwardElement{Kind: "forward", ForwardID: "forward-1"}}}
	adapter.expandOnebotForwards(msg)
	forward := msg.Segment[0].(*message.ForwardElement)
	if !forward.Loaded || len(forward.Nodes) != 1 || message.ConvertMessageElementsToString(forward.Nodes[0].Elements) != ".r 9d9" {
		t.Fatalf("OneBot expansion = %#v", forward)
	}
	ensureMessageTextFromSegments(msg)
	if msg.Message == ".r 9d9" {
		t.Fatalf("expanded command leaked into routing text")
	}
}

func TestMilkyForwardExpandProtocolAndIsolation(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","retcode":0,"data":{"messages":[{"message_seq":7,"sender_id":10001,"sender_name":"nested","time":123,"segments":[{"type":"text","data":{"text":".help"}}]}]}}`))
	}))
	defer server.Close()
	session, err := milky.New("ws://127.0.0.1", server.URL, "", zap.NewNop().Sugar())
	if err != nil {
		t.Fatal(err)
	}
	adapter := &PlatformAdapterMilky{IntentSession: session}
	forward := adapter.loadMilkyForward("milky-forward-1", 0)
	if gotPath != "/get_forwarded_messages" || !forward.Loaded || len(forward.Nodes) != 1 || forward.Nodes[0].SenderName != "nested" || message.ConvertMessageElementsToString(forward.Nodes[0].Elements) != ".help" {
		t.Fatalf("Milky expansion path=%q forward=%#v", gotPath, forward)
	}
	msg := &Message{Segment: []message.IMessageElement{forward}}
	ensureMessageTextFromSegments(msg)
	if msg.Message == ".help" {
		t.Fatal("Milky forward command leaked into routing text")
	}
}

func TestExpandedForwardCommandDoesNotReachExecuteNewCommandRouter(t *testing.T) {
	d, endpoint, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	msg := newPrivateMsg("QQ:10001", "")
	msg.Segment = []message.IMessageElement{&message.ForwardElement{
		Kind: "forward", Loaded: true, Nodes: []message.ForwardNode{{
			SenderID: "10002", SenderName: "nested", Elements: message.ConvertStringMessage(".r 100d100"),
		}},
	}}
	before := endpoint.CmdExecutedNum
	d.ImSession.ExecuteNew(endpoint, msg)
	if _, ok := adapter.waitForMsg(300 * time.Millisecond); ok {
		t.Fatal("expanded forward command unexpectedly produced a reply")
	}
	if endpoint.CmdExecutedNum != before {
		t.Fatalf("command counter changed from %d to %d", before, endpoint.CmdExecutedNum)
	}
}

func TestPluginForwardAPIBindingsCanConstructAndSend(t *testing.T) {
	adapter := newForwardCaptureAdapter()
	d := &Dice{
		Logger: zap.NewNop().Sugar(), BaseConfig: BaseConfig{DataDir: t.TempDir()},
		ImSession:   &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo]), EndPoints: []*EndPointInfo{}},
		DirtyGroups: new(SyncMap[string, int64]), AttrsManager: &AttrsManager{},
	}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:4242", Nickname: "SelfBot", Platform: "TEST"}, Adapter: adapter}
	ctx := &MsgContext{Dice: d, EndPoint: endpoint}
	msg := &Message{MessageType: "group", GroupID: "QQ-Group:9000"}
	d.JsInit()
	defer func() {
		if d.JsScriptCron != nil {
			d.JsScriptCron.Stop()
		}
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
	}()
	loop := d.ExtLoopManager.GetWebLoop()
	done := make(chan error, 1)
	if !loop.RunOnLoop(func(vm *goja.Runtime) {
		_ = vm.Set("testCtx", ctx)
		_ = vm.Set("testMsg", msg)
		_, runErr := vm.RunString(`seal.replyForward(testCtx, testMsg, [seal.newForwardNode("", "", "plugin text")])`)
		done <- runErr
	}) {
		t.Fatal("JS loop rejected validation task")
	}
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatal(runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("plugin forward API validation timed out")
	}
	adapter.muForward.Lock()
	defer adapter.muForward.Unlock()
	if len(adapter.groupForwards) != 1 || len(adapter.groupForwards[0]) != 1 || message.ConvertMessageElementsToString(adapter.groupForwards[0][0].Elements) != "plugin text" || adapter.groupForwards[0][0].SenderID != "4242" {
		t.Fatalf("plugin forward output = %#v", adapter.groupForwards)
	}
}
