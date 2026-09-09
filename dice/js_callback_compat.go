package dice

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"Scardice-core/utils/jsengine"
)

// jsCallbackKind is deliberately closed: callback ordering is part of the
// compatibility contract and new callback classes must be named explicitly.
type jsCallbackKind string

const (
	jsCallbackPreprocess jsCallbackKind = "preprocess"
	jsCallbackMessage    jsCallbackKind = "message"
	jsCallbackCommand    jsCallbackKind = "command"
	jsCallbackGroup      jsCallbackKind = "group"
	jsCallbackMember     jsCallbackKind = "member"
	jsCallbackActivation jsCallbackKind = "activation"
	jsCallbackSend       jsCallbackKind = "send"
)

var (
	errJSCallbackStaleGeneration = errors.New("JavaScript callback generation is stale")
	errJSCallbackWrongRealm      = errors.New("JavaScript callback belongs to another realm")
	errJSCallbackDuplicate       = errors.New("JavaScript callback is already scheduled")
)

// jsCallbackRequest is request-local. In particular, Callback closes over the
// message/context snapshot for this delivery; dispatch never reads a callback
// field again after admission.
type jsCallbackRequest struct {
	Generation       int64
	Realm            any
	Kind             jsCallbackKind
	ProviderEventID  string
	CallbackIdentity string
	Callback         func()
	OnError          func(error)
}

type jsCallbackDispatch struct {
	kind            jsCallbackKind
	providerEventID string
}

type jsCallbackKey struct {
	generation      int64
	kind            jsCallbackKind
	providerEventID string
	callbackID      string
}

func sameJSRealm(expected, actual any) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}
	if keyer, ok := expected.(jsengine.ContextKeyer); ok {
		expected = keyer.ContextKey()
	}
	if keyer, ok := actual.(jsengine.ContextKeyer); ok {
		actual = keyer.ContextKey()
	}
	if reflect.TypeOf(expected) != reflect.TypeOf(actual) {
		return false
	}
	valueType := reflect.TypeOf(expected)
	if valueType.Comparable() {
		return expected == actual
	}
	return reflect.DeepEqual(expected, actual)
}

func messageRawID(msg *Message) any {
	if msg == nil {
		return nil
	}
	return msg.RawID
}
func callbackEventID(value any) string {
	if value == nil {
		return ""
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return ""
	}
	return text
}

func callbackEventIDForMessage(ctx *MsgContext, msg *Message) string {
	eventID := callbackEventID(messageRawID(msg))
	if eventID == "" || ctx == nil || ctx.EndPoint == nil || ctx.EndPoint.ID == "" {
		return eventID
	}
	return ctx.EndPoint.ID + "\x00" + eventID
}

func jsCallbackIdentity(ext *ExtInfo, kind jsCallbackKind) string {
	return fmt.Sprintf("%p:%s", ext, kind)
}

func (m *JsLoopManager) dispatchJSCallback(request jsCallbackRequest, schedule bool) error {
	if m == nil || request.Callback == nil {
		return nil
	}
	if err := jsCompatibilitySchedulingAllowed(request.Realm); err != nil {
		return err
	}
	loop, err := m.GetLoop(request.Generation)
	if err != nil || loop == nil {
		if err != nil {
			return fmt.Errorf("%w: %v", errJSCallbackStaleGeneration, err)
		}
		return errJSCallbackStaleGeneration
	}
	inOwner := jsengine.InOwner(loop)
	current := jsengine.CurrentContext(loop)
	if inOwner && !sameJSRealm(request.Realm, current) {
		return errJSCallbackWrongRealm
	}
	if schedule {
		if request.ProviderEventID != "" && request.CallbackIdentity != "" {
			key := jsCallbackKey{generation: request.Generation, kind: request.Kind, providerEventID: request.ProviderEventID, callbackID: request.CallbackIdentity}
			if !m.admitJSCallback(key) {
				return errJSCallbackDuplicate
			}
			run := func(jsengine.Runtime) error {
				defer m.releaseJSCallback(key)
				callbackErr := runEngineCallback(func() error { request.Callback(); return nil })
				if callbackErr != nil && request.OnError != nil {
					request.OnError(callbackErr)
				}
				return callbackErr
			}
			if err := jsengine.ScheduleWithContext(loop, request.Realm, run); err != nil {
				m.releaseJSCallback(key)
				return err
			}
			return nil
		}
		run := func(jsengine.Runtime) error {
			callbackErr := runEngineCallback(func() error { request.Callback(); return nil })
			if callbackErr != nil && request.OnError != nil {
				request.OnError(callbackErr)
			}
			return callbackErr
		}
		return jsengine.ScheduleWithContext(loop, request.Realm, run)
	}
	// A synchronous callback already running on its owner realm executes
	// directly. Calling RunWithContext here would wait for the same realm and
	// deadlock. A different active realm is rejected above.
	if inOwner {
		return runEngineCallback(func() error { request.Callback(); return nil })
	}
	return jsengine.RunWithContext(loop, request.Realm, func(jsengine.Runtime) error {
		return runEngineCallback(func() error { request.Callback(); return nil })
	})
}

func (m *JsLoopManager) admitJSCallback(key jsCallbackKey) bool {
	m.loopLock.Lock()
	defer m.loopLock.Unlock()
	if m.callbackKeys == nil {
		m.callbackKeys = make(map[jsCallbackKey]struct{})
	}
	if _, exists := m.callbackKeys[key]; exists {
		return false
	}
	m.callbackKeys[key] = struct{}{}
	return true
}

func (m *JsLoopManager) releaseJSCallback(key jsCallbackKey) {
	m.loopLock.Lock()
	delete(m.callbackKeys, key)
	m.loopLock.Unlock()
}

func (i *ExtInfo) dispatchWithJsCheck(d *Dice, kind jsCallbackKind, providerEventID string, schedule bool, callback func()) {
	if callback == nil {
		return
	}
	if i == nil || !i.IsJsExt {
		callback()
		return
	}
	if d == nil || !d.Config.JsEnable || d.ExtLoopManager == nil {
		return
	}
	request := jsCallbackRequest{
		Generation:       i.JSLoopVersion,
		Realm:            jsContextForPlugin(i),
		Kind:             kind,
		ProviderEventID:  providerEventID,
		CallbackIdentity: jsCallbackIdentity(i, kind),
		Callback:         callback,
		OnError: func(err error) {
			if d.Logger != nil {
				d.Logger.Errorf("JS脚本异常: %v", err)
			}
		},
	}
	if err := d.ExtLoopManager.dispatchJSCallback(request, schedule); err != nil && d.Logger != nil {
		d.Logger.Errorf("JS脚本异常: %v", err)
	}
}
