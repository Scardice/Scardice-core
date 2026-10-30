package dice

import (
	"context"
	"errors"

	"github.com/dop251/goja"

	"Scardice-core/dice/events"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

type jsHookValueCallback func(jsengine.Runtime) (jsengine.Value, error)

func selectJSHookValueCallback(
	hasNeutral bool,
	neutral func() (jsengine.Value, error),
	hasLegacy bool,
	legacy func() goja.Value,
) jsHookValueCallback {
	switch {
	case hasNeutral:
		return func(jsengine.Runtime) (jsengine.Value, error) { return neutral() }
	case hasLegacy:
		return func(runtime jsengine.Runtime) (jsengine.Value, error) {
			return gojaengine.WrapValueForRuntime(runtime, legacy())
		}
	default:
		return nil
	}
}

func jsHookScopeExpired(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, errJSExecutionCompleted) ||
		errors.Is(err, errJSRuntimeUnavailable) ||
		errors.Is(err, errJSCallbackStaleGeneration) ||
		errors.Is(err, errJSCallbackWrongRealm)
}

func (i *ExtInfo) dispatchValueWithJsCheck(
	d *Dice,
	kind jsCallbackKind,
	providerEventID string,
	schedule bool,
	callback jsHookValueCallback,
	consume func(jsengine.Value) error,
	message *MsgContext,
) error {
	return i.dispatchValueWithJsCheckFiltered(d, kind, providerEventID, schedule, callback, consume, message, nil)
}

func (i *ExtInfo) dispatchValueWithJsCheckFiltered(
	d *Dice,
	kind jsCallbackKind,
	providerEventID string,
	schedule bool,
	callback jsHookValueCallback,
	consume func(jsengine.Value) error,
	message *MsgContext,
	shouldRecord func(error) bool,
) error {
	if i == nil || callback == nil {
		return nil
	}
	if d == nil || d.ExtLoopManager == nil {
		return errors.New("JavaScript runtime is unavailable")
	}
	if i.IsJsExt && !d.Config.JsEnable {
		if d.Logger != nil {
			d.Logger.Infof("当前已关闭js扩展<%v>", i.Name)
		}
		return nil
	}
	if i.IsJsExt && i.dropJSCallbackBeforeLoad(d, kind, providerEventID) {
		return nil
	}
	report := func(err error) {
		if shouldRecord == nil || shouldRecord(err) {
			message.recordJSExecutionError(err)
		}
		if d.Logger != nil {
			d.Logger.Errorf("JS脚本异常: %v", err)
		}
	}
	request := jsCallbackRequest{
		Generation:       i.JSLoopVersion,
		Realm:            jsContextForMessage(i, message),
		Kind:             kind,
		ProviderEventID:  providerEventID,
		CallbackIdentity: jsCallbackIdentity(i, kind),
		ValueCallback:    callback,
		ConsumeValue:     consume,
		Message:          message,
		OnError:          report,
	}
	err := d.ExtLoopManager.dispatchJSCallback(request, schedule)
	if err != nil {
		report(err)
	}
	return err
}

func (i *ExtInfo) HasOnNotCommandReceived() bool {
	ext := i.GetRealExt()
	return ext != nil && (ext.OnNotCommandReceived != nil || ext.OnNotCommandReceivedGoja != nil || ext.OnNotCommandReceivedCallback != nil)
}

func (i *ExtInfo) HasOnMessagePreprocess() bool {
	ext := i.GetRealExt()
	return ext != nil && (ext.OnMessagePreprocess != nil || ext.OnMessagePreprocessCallback != nil || ext.OnMessagePreprocessEngine != nil)
}

func (i *ExtInfo) HasOnMessageSend() bool {
	ext := i.GetRealExt()
	return ext != nil && (ext.OnMessageSend != nil || ext.OnMessageSendGoja != nil || ext.OnMessageSendCallback != nil)
}

func (i *ExtInfo) CallOnNotCommandReceived(d *Dice, ctx *MsgContext, msg *Message) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnNotCommandReceived != nil {
		ext.callWithJsCheck(d, func() { ext.OnNotCommandReceived(ctx, msg) }, jsCallbackDispatch{kind: jsCallbackMessage, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnNotCommandReceivedCallback != nil,
		func() (jsengine.Value, error) { return ext.OnNotCommandReceivedCallback(ctx, msg) },
		ext.OnNotCommandReceivedGoja != nil,
		func() goja.Value { return ext.OnNotCommandReceivedGoja(ctx, msg) },
	)
	if ext.OnNotCommandReceivedCallback == nil && ext.OnNotCommandReceivedGoja == nil {
		return
	}
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackMessage, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnCommandOverride(d *Dice, ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) bool {
	ext := i.GetRealExt()
	if ext == nil {
		return false
	}
	if ext.OnCommandOverride != nil {
		handled := false
		ext.callWithJsCheck(d, func() { handled = ext.OnCommandOverride(ctx, msg, cmdArgs) }, jsCallbackDispatch{kind: jsCallbackCommand, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return handled
	}
	if ext.OnCommandOverrideCallback == nil && ext.OnCommandOverrideGoja == nil {
		return false
	}
	handled := false
	callback := selectJSHookValueCallback(
		ext.OnCommandOverrideCallback != nil,
		func() (jsengine.Value, error) { return ext.OnCommandOverrideCallback(ctx, msg, cmdArgs) },
		ext.OnCommandOverrideGoja != nil,
		func() goja.Value { return ext.OnCommandOverrideGoja(ctx, msg, cmdArgs) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackCommand, callbackEventIDForMessage(ctx, msg), false, callback, func(value jsengine.Value) error {
		handled = engineValueToBoolean(value)
		return nil
	}, ctx)
	return handled
}

func (i *ExtInfo) CallOnCommandReceived(d *Dice, ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnCommandReceived != nil {
		ext.callWithJsCheck(d, func() { ext.OnCommandReceived(ctx, msg, cmdArgs) }, jsCallbackDispatch{kind: jsCallbackCommand, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return
	}
	if ext.OnCommandReceivedCallback == nil && ext.OnCommandReceivedGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnCommandReceivedCallback != nil,
		func() (jsengine.Value, error) { return ext.OnCommandReceivedCallback(ctx, msg, cmdArgs) },
		ext.OnCommandReceivedGoja != nil,
		func() goja.Value { return ext.OnCommandReceivedGoja(ctx, msg, cmdArgs) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackCommand, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnMessageReceived(d *Dice, ctx *MsgContext, msg *Message) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnMessageReceived != nil {
		ext.callWithJsCheck(d, func() { ext.OnMessageReceived(ctx, msg) }, jsCallbackDispatch{kind: jsCallbackMessage, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return
	}
	if ext.OnMessageReceivedCallback == nil && ext.OnMessageReceivedGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnMessageReceivedCallback != nil,
		func() (jsengine.Value, error) { return ext.OnMessageReceivedCallback(ctx, msg) },
		ext.OnMessageReceivedGoja != nil,
		func() goja.Value { return ext.OnMessageReceivedGoja(ctx, msg) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackMessage, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnMessageSend(d *Dice, ctx *MsgContext, msg *Message, flag string) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnMessageSend != nil {
		ext.notifyWithJsCheck(d, func() { ext.OnMessageSend(ctx, msg, flag) }, jsCallbackDispatch{kind: jsCallbackSend, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return
	}
	if ext.OnMessageSendCallback == nil && ext.OnMessageSendGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnMessageSendCallback != nil,
		func() (jsengine.Value, error) { return ext.OnMessageSendCallback(ctx, msg, flag) },
		ext.OnMessageSendGoja != nil,
		func() goja.Value { return ext.OnMessageSendGoja(ctx, msg, flag) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackSend, callbackEventIDForMessage(ctx, msg), true, callback, nil, ctx)
}

func (i *ExtInfo) CallOnMessageDeleted(d *Dice, ctx *MsgContext, msg *Message) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnMessageDeleted != nil {
		ext.callWithJsCheck(d, func() { ext.OnMessageDeleted(ctx, msg) }, jsCallbackDispatch{kind: jsCallbackMessage, message: ctx})
		return
	}
	if ext.OnMessageDeletedCallback == nil && ext.OnMessageDeletedGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnMessageDeletedCallback != nil,
		func() (jsengine.Value, error) { return ext.OnMessageDeletedCallback(ctx, msg) },
		ext.OnMessageDeletedGoja != nil,
		func() goja.Value { return ext.OnMessageDeletedGoja(ctx, msg) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackMessage, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnMessageEdit(d *Dice, ctx *MsgContext, msg *Message) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnMessageEdit != nil {
		ext.callWithJsCheck(d, func() { ext.OnMessageEdit(ctx, msg) }, jsCallbackDispatch{kind: jsCallbackMessage, message: ctx})
		return
	}
	if ext.OnMessageEditCallback == nil && ext.OnMessageEditGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnMessageEditCallback != nil,
		func() (jsengine.Value, error) { return ext.OnMessageEditCallback(ctx, msg) },
		ext.OnMessageEditGoja != nil,
		func() goja.Value { return ext.OnMessageEditGoja(ctx, msg) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackMessage, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnGroupJoined(d *Dice, ctx *MsgContext, msg *Message) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnGroupJoined != nil {
		ext.callWithJsCheck(d, func() { ext.OnGroupJoined(ctx, msg) }, jsCallbackDispatch{kind: jsCallbackGroup, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return
	}
	if ext.OnGroupJoinedCallback == nil && ext.OnGroupJoinedGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnGroupJoinedCallback != nil,
		func() (jsengine.Value, error) { return ext.OnGroupJoinedCallback(ctx, msg) },
		ext.OnGroupJoinedGoja != nil,
		func() goja.Value { return ext.OnGroupJoinedGoja(ctx, msg) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackGroup, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnBecomeFriend(d *Dice, ctx *MsgContext, msg *Message) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnBecomeFriend != nil {
		ext.callWithJsCheck(d, func() { ext.OnBecomeFriend(ctx, msg) }, jsCallbackDispatch{kind: jsCallbackActivation, providerEventID: callbackEventIDForMessage(ctx, msg), message: ctx})
		return
	}
	if ext.OnBecomeFriendCallback == nil && ext.OnBecomeFriendGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnBecomeFriendCallback != nil,
		func() (jsengine.Value, error) { return ext.OnBecomeFriendCallback(ctx, msg) },
		ext.OnBecomeFriendGoja != nil,
		func() goja.Value { return ext.OnBecomeFriendGoja(ctx, msg) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackActivation, callbackEventIDForMessage(ctx, msg), false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnPoke(d *Dice, ctx *MsgContext, event *events.PokeEvent) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnPoke != nil {
		ext.callWithJsCheck(d, func() { ext.OnPoke(ctx, event) }, jsCallbackDispatch{kind: jsCallbackMember, message: ctx})
		return
	}
	if ext.OnPokeCallback == nil && ext.OnPokeGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnPokeCallback != nil,
		func() (jsengine.Value, error) { return ext.OnPokeCallback(ctx, event) },
		ext.OnPokeGoja != nil,
		func() goja.Value { return ext.OnPokeGoja(ctx, event) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackMember, "", false, callback, nil, ctx)
}

func (i *ExtInfo) CallOnGroupLeave(d *Dice, ctx *MsgContext, event *events.GroupLeaveEvent) {
	ext := i.GetRealExt()
	if ext == nil {
		return
	}
	if ext.OnGroupLeave != nil {
		ext.callWithJsCheck(d, func() { ext.OnGroupLeave(ctx, event) }, jsCallbackDispatch{kind: jsCallbackGroup, message: ctx})
		return
	}
	if ext.OnGroupLeaveCallback == nil && ext.OnGroupLeaveGoja == nil {
		return
	}
	callback := selectJSHookValueCallback(
		ext.OnGroupLeaveCallback != nil,
		func() (jsengine.Value, error) { return ext.OnGroupLeaveCallback(ctx, event) },
		ext.OnGroupLeaveGoja != nil,
		func() goja.Value { return ext.OnGroupLeaveGoja(ctx, event) },
	)
	_ = ext.dispatchValueWithJsCheck(d, jsCallbackGroup, "", false, callback, nil, ctx)
}
