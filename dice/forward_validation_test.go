package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestWelcomeReplyKeepsForwardBoundariesUntilDelivery(t *testing.T) {
	adapter := newForwardCaptureAdapter()
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		UserID: "QQ:4242", Nickname: "SelfBot", Platform: "TEST",
	}, Adapter: adapter}
	ctx := &MsgContext{EndPoint: endpoint, Dice: &Dice{Logger: zap.NewNop().Sugar()}}
	msg := &Message{MessageType: "group", GroupID: "QQ-Group:9000"}
	inside := ctx.TranslateSplit("notice one#{SPLIT}\nnotice two#{SPLIT}\nnotice three")

	ReplyGroup(ctx, msg, "ordinary welcome\n"+ctx.wrapForward(inside))

	adapter.mu.Lock()
	ordinary := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	if len(ordinary) != 1 || ordinary[0] != "ordinary welcome" {
		t.Fatalf("ordinary welcome deliveries = %#v", ordinary)
	}
	adapter.muForward.Lock()
	defer adapter.muForward.Unlock()
	if len(adapter.groupForwards) != 1 || len(adapter.groupForwards[0]) != 3 {
		t.Fatalf("welcome forward deliveries = %#v", adapter.groupForwards)
	}
	for _, node := range adapter.groupForwards[0] {
		text := message.ConvertMessageElementsToString(node.Elements)
		if strings.Contains(text, "FORWARD-BEGIN") || strings.Contains(text, "FORWARD-END") {
			t.Fatalf("forward control marker leaked into welcome node: %q", text)
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

func TestOnebotForwardQueueIsAsyncAndFIFO(t *testing.T) {
	adapter := &PlatformAdapterOnebot{logger: zap.NewNop().Sugar()}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	order := make(chan int, 2)

	if !adapter.enqueueOnebotForwardJob(func() {
		close(firstStarted)
		<-releaseFirst
		order <- 1
	}) {
		t.Fatal("first forward job was not queued")
	}

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("forward queue worker did not start")
	}

	queued := make(chan bool, 1)
	go func() {
		queued <- adapter.enqueueOnebotForwardJob(func() { order <- 2 })
	}()
	select {
	case ok := <-queued:
		if !ok {
			t.Fatal("second forward job was not queued")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("enqueue blocked behind the running forward request")
	}

	select {
	case got := <-order:
		t.Fatalf("job %d completed before the first job was released", got)
	default:
	}

	close(releaseFirst)
	for want := 1; want <= 2; want++ {
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("completion order = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for job %d", want)
		}
	}
}

func TestOnebotForwardQueueRejectsOverflow(t *testing.T) {
	adapter := &PlatformAdapterOnebot{
		forwardQueue:        make([]func(), maxOnebotForwardQueueSize),
		forwardQueueRunning: true,
	}
	if adapter.enqueueOnebotForwardJob(func() {}) {
		t.Fatal("full forward queue accepted another job")
	}
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
				UserID   string `json:"user_id"`
				Nickname string `json:"nickname"`
				Uin      string `json:"uin"`
				Name     string `json:"name"`
				Content  []struct {
					Type string `json:"type"`
				} `json:"content"`
			} `json:"data"`
		} `json:"messages"`
	}
	if err = json.Unmarshal(payload, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.GroupID != 9000 || len(sent.Messages) != 1 || sent.Messages[0].Type != "node" || sent.Messages[0].Data.UserID != "4242" || sent.Messages[0].Data.Uin != "4242" || sent.Messages[0].Data.Nickname != "SelfBot" || sent.Messages[0].Data.Name != "SelfBot" || len(sent.Messages[0].Data.Content) != 1 || sent.Messages[0].Data.Content[0].Type != "text" {
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

func TestGocqForwardCustomNodeUsesOneBotStringUserID(t *testing.T) {
	nodes := buildGocqForwardNodes([]message.ForwardNode{{
		SenderID: "4242", SenderName: "SelfBot", Elements: message.ConvertStringMessage("hello"),
	}})
	if len(nodes) != 1 {
		t.Fatalf("forward nodes = %#v", nodes)
	}
	payload, err := json.Marshal(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Data struct {
			UserID   string `json:"user_id"`
			Nickname string `json:"nickname"`
			Uin      string `json:"uin"`
			Name     string `json:"name"`
		} `json:"data"`
	}
	if err = json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Data.UserID != "4242" || wire.Data.Uin != "4242" || wire.Data.Nickname != "SelfBot" || wire.Data.Name != "SelfBot" {
		t.Fatalf("unexpected OneBot custom-node payload: %s", payload)
	}
}

func TestOnebotForwardResponseSupportsNapCatMessageShapeAndLogsNodes(t *testing.T) {
	raw := []byte(`{"status":"ok","retcode":0,"data":{"messages":[{"message_id":7,"time":123,"sender":{"user_id":10001,"nickname":"nested"},"message":[{"type":"text","data":{"text":"inside text"}}]}]}}`)
	nodes, err := parseOnebotForwardResponse(zap.NewNop().Sugar(), raw)
	if err != nil {
		t.Fatal(err)
	}
	msg := &Message{
		Message: "[CQ:forward,id=forward-1]",
		Segment: []message.IMessageElement{&message.ForwardElement{
			Kind: "forward", ForwardID: "forward-1", Loaded: true, Nodes: nodes,
		}},
	}
	logged := incomingMessageLogText(msg)
	if !strings.Contains(logged, "[合并转发解析]") || !strings.Contains(logged, "<nested>(10001): inside text") {
		t.Fatalf("forward log text = %q", logged)
	}
	if strings.Contains(msg.Message, "inside text") {
		t.Fatalf("expanded forward leaked into routing text: %q", msg.Message)
	}
}

func TestGocqArrayMessagePreservesForwardID(t *testing.T) {
	raw := `{"message_type":"group","message_id":1,"message":[{"type":"forward","data":{"id":"forward-1"}}]}`
	msg := new(MessageQQ)
	if err := tryParseOneBot11ArrayMessage(zap.NewNop().Sugar(), raw, msg); err != nil {
		t.Fatal(err)
	}
	if msg.Message != "[CQ:forward,id=forward-1]" {
		t.Fatalf("converted message = %q", msg.Message)
	}
}

func TestGocqWaitEchoRegistersBeforeRequest(t *testing.T) {
	adapter := &PlatformAdapterGocq{}
	echo := adapter.getCustomEcho()
	var response struct {
		Status string `json:"status"`
	}
	err := adapter.waitEcho2(echo, &response, func(emi *echoMapInfo) {
		keyBytes, marshalErr := json.Marshal(echo)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, ok := adapter.echoMap2.Load(string(keyBytes)); !ok {
			t.Fatal("echo was not registered before request dispatch")
		}
		emi.ch <- `{"status":"ok"}`
	})
	if err != nil || response.Status != "ok" {
		t.Fatalf("waitEcho2 response=%#v err=%v", response, err)
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

func TestReplyForwardFallsBackToOneOrdinaryMessage(t *testing.T) {
	adapter := newMockPlatformAdapter()
	ctx := &MsgContext{EndPoint: &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{Platform: "Discord", Nickname: "bot", UserID: "QQ:9"},
		Adapter:          adapter,
	}}
	msg := &Message{MessageType: "group", GroupID: "Discord-Channel:1", Sender: SenderBase{UserID: "Discord:2"}}
	nodes := []message.ForwardNode{
		{Elements: message.ConvertStringMessage("first")},
		{Elements: message.ConvertStringMessage("second")},
	}
	if !ReplyForward(ctx, msg, nodes) {
		t.Fatal("fallback forward reply failed")
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if len(adapter.groupMsgs) != 1 || adapter.groupMsgs[0] != "first\nsecond" {
		t.Fatalf("fallback messages = %#v", adapter.groupMsgs)
	}
}

func TestDiceScriptForwardFallbackIgnoresInternalSplit(t *testing.T) {
	adapter := newMockPlatformAdapter()
	ctx := &MsgContext{EndPoint: &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{Platform: "KOOK"},
		Adapter:          adapter,
	}}
	msg := &Message{MessageType: "group", GroupID: "KOOK-Channel:1"}
	ctx.InitSplitKey()
	inside := "first\n" + ctx.getSplitKey() + "\nsecond"
	deliverReplyPlan(ctx, msg, ctx.wrapForward(inside), "", true)
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if len(adapter.groupMsgs) != 1 || adapter.groupMsgs[0] != "first\nsecond" {
		t.Fatalf("fallback messages = %#v", adapter.groupMsgs)
	}
}

func TestTextMapCompatibilityAcceptsMultilineForward(t *testing.T) {
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	d.UIEndpoint = endpoint
	const expr = "帮助:娱乐\n{forward(`.gugu // 一 #{SPLIT}\n.jrrp // 二`)}"
	TextMapCompatibleCheck(d, "测试", "合并转发", []TextTemplateItem{{expr, 1}})
	items, ok := d.TextMapCompatible.Load("测试:合并转发")
	if !ok {
		t.Fatal("compatibility result missing")
	}
	info, ok := items.Load(expr)
	if !ok {
		t.Fatal("compatibility item missing")
	}
	if info.Version != "v2" || info.ErrV2 != "" {
		t.Fatalf("compatibility result = %#v", info)
	}
	adapter := newMockPlatformAdapter()
	fallbackCtx := &MsgContext{EndPoint: &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{Platform: "DISCORD"}, Adapter: adapter,
	}}
	fallbackCtx.SetSplitKey("###SPLIT-KEY###")
	deliverReplyPlan(fallbackCtx, &Message{MessageType: "group", GroupID: "Discord-Channel:1"}, info.TextV2, "", true)
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if len(adapter.groupMsgs) != 2 || adapter.groupMsgs[0] != "帮助:娱乐" || adapter.groupMsgs[1] != ".gugu // 一\n.jrrp // 二" {
		t.Fatalf("Discord fallback messages = %#v", adapter.groupMsgs)
	}
}

func TestForwardFallbackPreservesInlineSplitLayout(t *testing.T) {
	const key = "###SPLIT-KEY###"
	if got := stripForwardSplitMarkers("first "+key+" second", key); got != "first\nsecond" {
		t.Fatalf("inline fallback = %q", got)
	}
	if got := stripForwardSplitMarkers("first "+key+"\nsecond", key); got != "first\nsecond" {
		t.Fatalf("line-end fallback = %q", got)
	}
	if got := stripForwardSplitMarkers("first\r\n  "+key+"  \r\nsecond", key); got != "first\r\nsecond" {
		t.Fatalf("CRLF fallback = %q", got)
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
