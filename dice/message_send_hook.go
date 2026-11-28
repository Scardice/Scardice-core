package dice

import (
	"reflect"
	"slices"
	"sync/atomic"

	"Scardice-core/message"

	"github.com/dop251/goja"
)

type OutgoingMessage struct {
	Message     string     `jsbind:"message"`
	MessageType string     `jsbind:"messageType"`
	TargetID    string     `jsbind:"targetId"`
	GroupID     string     `jsbind:"groupId"`
	Platform    string     `jsbind:"platform"`
	Sender      SenderBase `jsbind:"sender"`
}

type sendLoopState struct {
	version   int64
	registry  *SyncMap[string, *ExtInfo]
	runFilter goja.Callable
	stopped   atomic.Bool
	filtering bool // Only accessed from the owning runtime.
}

// sendOrigin travels only through the synchronous send initiated by a JS binding.
type sendOrigin struct {
	dice    *Dice
	version int64
	vm      *goja.Runtime
	state   *sendLoopState
}

func (origin *sendOrigin) requireCanSend() {
	if origin.state.filtering {
		panic(origin.vm.NewTypeError("不能在 onBeforeMessageSend 中同步发送消息"))
	}
}

func runSendJS(d *Dice, ext *ExtInfo, fn func()) {
	prev := d.JsCurrentPlugin
	d.JsCurrentPlugin = ext
	defer func() {
		d.JsCurrentPlugin = prev
		if err := recover(); err != nil {
			d.Logger.Error("JS脚本异常:", err)
		}
	}()
	fn()
}

func (origin *sendOrigin) callBefore(d *Dice, candidate *ExtInfo, ctx *MsgContext, msg OutgoingMessage, flag string) (decision messagePreprocessDecision) {
	if !candidate.IsJsExt {
		return parseMessagePreprocessValue(nil, candidate.OnBeforeMessageSend(ctx, &msg, flag))
	}
	run := func(vm *goja.Runtime, state *sendLoopState) {
		if state.stopped.Load() || state.filtering || state.runFilter == nil {
			return
		}
		ext := candidate
		if candidate.IsWrapper {
			ext, _ = state.registry.Load(candidate.TargetName)
		}
		if ext == nil || ext.JSLoopVersion != state.version || ext.OnBeforeMessageSend == nil {
			return
		}
		// Goja drains Promise jobs when the outer JS frame exits. End the guard inside that frame.
		_, err := state.runFilter(goja.Undefined(), vm.ToValue(func() {
			runSendJS(d, ext, func() {
				value := ext.OnBeforeMessageSend(ctx, &msg, flag)
				if value != nil && value.ExportType() == reflect.TypeFor[*goja.Promise]() {
					return
				}
				decision = parseMessagePreprocessValue(vm, value)
			})
		}))
		if err != nil {
			d.Logger.Error("JS脚本异常:", err)
		}
	}
	if origin != nil && origin.dice == d {
		run(origin.vm, origin.state)
		return decision
	}
	if d.ExtLoopManager == nil {
		return decision
	}
	loop, state := d.ExtLoopManager.getSendLoop(0)
	if loop == nil {
		return decision
	}
	done := make(chan struct{})
	if loop.RunOnLoop(func(vm *goja.Runtime) {
		defer close(done)
		run(vm, state)
	}) {
		<-done
	}
	return decision
}

func prepareOutboundText(ctx *MsgContext, endpoint *EndPointInfo, targetID, text, flag string, group bool, origin *sendOrigin) (string, bool) {
	if endpoint == nil || endpoint.Adapter == nil {
		return text, true
	}
	session := endpoint.Session
	if session == nil {
		session = ctx.Session
	}
	if session == nil || session.Parent == nil || session.ServiceAtNew == nil {
		return text, true
	}
	groupID := targetID
	if !group {
		groupID = "PG-" + targetID
	}
	destination, ok := session.ServiceAtNew.Load(groupID)
	if !ok || !destination.IsActive(&MsgContext{EndPoint: endpoint}) {
		return text, true
	}

	d := session.Parent
	_ = destination.GetActivatedExtList(d)
	destination.extInitMu.Lock()
	candidates := slices.Clone(destination.activatedExtList)
	destination.extInitMu.Unlock()

	outgoing := OutgoingMessage{
		MessageType: "private", TargetID: targetID, Platform: endpoint.Platform,
		Sender: SenderBase{UserID: endpoint.UserID, Nickname: endpoint.Nickname},
	}
	if group {
		outgoing.MessageType = "group"
		outgoing.GroupID = targetID
	}
	for _, ext := range candidates {
		if ext == nil || (!ext.IsJsExt && ext.OnBeforeMessageSend == nil) {
			continue
		}
		outgoing.Message = text
		decision := origin.callBefore(d, ext, ctx, outgoing, flag)
		switch decision.action {
		case messagePreprocessRewrite:
			text = decision.message
		case messagePreprocessIntercept:
			if decision.reason != "" {
				d.Logger.Infof("扩展<%s>取消发送消息: %s", ext.Name, decision.reason)
			} else {
				d.Logger.Infof("扩展<%s>取消发送消息", ext.Name)
			}
			return "", false
		}
	}
	return text, true
}

func (origin *sendOrigin) callObserver(d *Dice, ext *ExtInfo, fn func()) {
	if origin == nil || origin.dice != d || !ext.IsJsExt {
		ext.callWithJsCheck(d, fn)
		return
	}
	if origin.version == ext.JSLoopVersion && !origin.state.stopped.Load() {
		runSendJS(d, ext, fn)
	}
}

func (origin *sendOrigin) notify(s *IMSession, ctx *MsgContext, msg *Message, flag string) {
	if origin == nil {
		s.OnMessageSend(ctx, msg, flag)
		return
	}
	for _, wrapper := range s.Parent.ExtList {
		ext := wrapper.GetRealExt()
		if ext != nil && ext.OnMessageSend != nil {
			origin.callObserver(ctx.Dice, ext, func() { ext.OnMessageSend(ctx, msg, flag) })
		}
	}
}

func (origin *sendOrigin) notifyGroup(g *GroupInfo, ctx *MsgContext, msg *Message, flag string) {
	for _, wrapper := range g.GetActivatedExtList(ctx.Dice) {
		ext := wrapper.GetRealExt()
		if ext != nil && ext.OnMessageSend != nil {
			origin.callObserver(ctx.Dice, ext, func() { ext.OnMessageSend(ctx, msg, flag) })
		}
	}
}

func (origin *sendOrigin) sendText(adapter PlatformAdapter, ctx *MsgContext, id, text, flag string, group bool) {
	if group {
		if scoped, ok := adapter.(interface {
			sendToGroup(*MsgContext, string, string, string, *sendOrigin)
		}); origin != nil && ok {
			scoped.sendToGroup(ctx, id, text, flag, origin)
			return
		}
		adapter.SendToGroup(ctx, id, text, flag)
		return
	}
	if scoped, ok := adapter.(interface {
		sendToPerson(*MsgContext, string, string, string, *sendOrigin)
	}); origin != nil && ok {
		scoped.sendToPerson(ctx, id, text, flag, origin)
		return
	}
	adapter.SendToPerson(ctx, id, text, flag)
}

func (origin *sendOrigin) sendForward(sender forwardMsgSender, ctx *MsgContext, id string, nodes []message.ForwardNode, group bool) bool {
	if group {
		if scoped, ok := sender.(interface {
			sendGroupForwardMsg(*MsgContext, string, []message.ForwardNode, *sendOrigin) bool
		}); origin != nil && ok {
			return scoped.sendGroupForwardMsg(ctx, id, nodes, origin)
		}
		return sender.SendGroupForwardMsg(ctx, id, nodes)
	}
	if scoped, ok := sender.(interface {
		sendPrivateForwardMsg(*MsgContext, string, []message.ForwardNode, *sendOrigin) bool
	}); origin != nil && ok {
		return scoped.sendPrivateForwardMsg(ctx, id, nodes, origin)
	}
	return sender.SendPrivateForwardMsg(ctx, id, nodes)
}
