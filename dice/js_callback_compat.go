package dice

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"

	"Scardice-core/utils/jsengine"
)

// jsCallbackKind is deliberately closed: callback ordering is part of the
// compatibility contract and new callback classes must be named explicitly.
type jsCallbackKind string

const (
	jsCallbackPreprocess   jsCallbackKind = "preprocess"
	jsCallbackMessage      jsCallbackKind = "message"
	jsCallbackCommand      jsCallbackKind = "command"
	jsCallbackGroup        jsCallbackKind = "group"
	jsCallbackMember       jsCallbackKind = "member"
	jsCallbackActivation   jsCallbackKind = "activation"
	jsCallbackSend         jsCallbackKind = "send"
	jsCallbackAdapterEvent jsCallbackKind = "adapter-event"
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
	ValueCallback    func(jsengine.Runtime) (jsengine.Value, error)
	ConsumeValue     func(jsengine.Value) error
	Message          *MsgContext
	OnError          func(error)
}

type jsCallbackDispatch struct {
	kind            jsCallbackKind
	providerEventID string
	message         *MsgContext
}

type jsCallbackKey struct {
	generation      int64
	kind            jsCallbackKind
	providerEventID string
	callbackID      string
}

// jsCallbackCompletion serializes lifecycle cancellation with owner-side
// callback/result consumption. Cancellation may win before work starts, or
// join work already running, but it never publishes completion while captured
// Go results are still being mutated.
type jsCallbackCompletion struct {
	mu         sync.Mutex
	finished   bool
	err        error
	active     int
	delivered  bool
	unregister func()
	releaseKey func()
	deliver    func(error)
}

func (c *jsCallbackCompletion) takeDeliveryLocked() (func(), func(), func(error), error, bool) {
	if !c.finished || c.active != 0 || c.delivered {
		return nil, nil, nil, nil, false
	}
	c.delivered = true
	unregister, releaseKey, deliver, err := c.unregister, c.releaseKey, c.deliver, c.err
	c.unregister, c.releaseKey = nil, nil
	return unregister, releaseKey, deliver, err, true
}

func runJSCallbackDelivery(unregister, releaseKey func(), deliver func(error), err error, ready bool) {
	if !ready {
		return
	}
	if unregister != nil {
		unregister()
	}
	if releaseKey != nil {
		releaseKey()
	}
	if deliver != nil {
		deliver(err)
	}
}

func (c *jsCallbackCompletion) finish(err error) {
	c.mu.Lock()
	if !c.finished {
		c.finished = true
		c.err = err
	}
	unregister, releaseKey, deliver, completionErr, ready := c.takeDeliveryLocked()
	c.mu.Unlock()
	runJSCallbackDelivery(unregister, releaseKey, deliver, completionErr, ready)
}

func (c *jsCallbackCompletion) settle(work func() error) {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return
	}
	c.active++
	c.mu.Unlock()

	err := work()

	c.mu.Lock()
	c.active--
	if !c.finished {
		c.finished = true
		c.err = err
	}
	unregister, releaseKey, deliver, completionErr, ready := c.takeDeliveryLocked()
	c.mu.Unlock()
	runJSCallbackDelivery(unregister, releaseKey, deliver, completionErr, ready)
}

func (c *jsCallbackCompletion) begin() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return false, c.err
	}
	c.active++
	return true, nil
}

func (c *jsCallbackCompletion) end() {
	c.mu.Lock()
	c.active--
	unregister, releaseKey, deliver, completionErr, ready := c.takeDeliveryLocked()
	c.mu.Unlock()
	runJSCallbackDelivery(unregister, releaseKey, deliver, completionErr, ready)
}

func (c *jsCallbackCompletion) installUnregister(unregister func()) (bool, error) {
	c.mu.Lock()
	if c.finished {
		err := c.err
		c.mu.Unlock()
		if unregister != nil {
			unregister()
		}
		return false, err
	}
	c.unregister = unregister
	c.mu.Unlock()
	return true, nil
}

func (c *jsCallbackCompletion) installReleaseKey(releaseKey func()) (bool, error) {
	c.mu.Lock()
	if c.finished {
		err := c.err
		c.mu.Unlock()
		if releaseKey != nil {
			releaseKey()
		}
		return false, err
	}
	c.releaseKey = releaseKey
	c.mu.Unlock()
	return true, nil
}

func (c *jsCallbackCompletion) status() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.finished, c.err
}
func sameJSRealm(expected, actual any) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}
	// Realm affinity is plugin ownership, not invocation lifetime identity.
	if left, ok := expected.(*jsExecutionContext); ok {
		if right, ok := actual.(*jsExecutionContext); ok {
			if left == nil || right == nil {
				return left == right
			}
			return left.Plugin == right.Plugin && left.Script == right.Script
		}
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

func executeJSCallbackRequest(runtime jsengine.Runtime, request jsCallbackRequest, settle func(func() error)) (bool, error) {
	if request.ValueCallback == nil {
		err := runEngineCallback(func() error {
			if request.Callback != nil {
				request.Callback()
			}
			return nil
		})
		if err != nil {
			return false, err
		}
		settle(func() error { return nil })
		return false, nil
	}

	var value jsengine.Value
	err := runEngineCallback(func() error {
		var callbackErr error
		value, callbackErr = request.ValueCallback(runtime)
		return callbackErr
	})
	if err != nil {
		return false, err
	}
	consume := func(settled jsengine.Value, settleErr error) {
		settle(func() error {
			if settleErr != nil {
				return settleErr
			}
			if request.ConsumeValue == nil {
				return nil
			}
			return runEngineCallback(func() error { return request.ConsumeValue(settled) })
		})
	}
	var observed bool
	err = runEngineCallback(func() error {
		var observeErr error
		observed, observeErr = jsengine.ObservePromise(runtime, value, consume)
		return observeErr
	})
	if err != nil {
		return false, err
	}
	if observed {
		return true, nil
	}
	consume(value, nil)
	return false, nil
}

func (m *JsLoopManager) dispatchJSCallback(request jsCallbackRequest, schedule bool) error {
	if m == nil || (request.Callback == nil && request.ValueCallback == nil) {
		return nil
	}
	if err := jsCompatibilitySchedulingAllowed(request.Realm); err != nil {
		return err
	}
	loop, err := m.GetLoop(request.Generation)
	if err != nil || loop == nil {
		if err != nil {
			return fmt.Errorf("%w: %w", errJSCallbackStaleGeneration, err)
		}
		return errJSCallbackStaleGeneration
	}
	inOwner := jsengine.InOwner(loop)
	current := jsengine.CurrentContext(loop)
	if inOwner && !sameJSRealm(request.Realm, current) {
		return errJSCallbackWrongRealm
	}

	if schedule {
		releaseChild, err := request.Message.beginJSCallbackChild()
		if err != nil {
			return err
		}
		completion := &jsCallbackCompletion{
			deliver: func(callbackErr error) {
				// Publish the callback failure before releasing the message
				// child so finalization cannot race past the original error.
				if callbackErr != nil && request.OnError != nil {
					request.OnError(callbackErr)
				}
				releaseChild()
			},
		}
		registered, err := m.registerJSCallbackWaiter(request.Generation, completion.finish)
		if err != nil {
			completion.finish(err)
			return err
		}
		if installed, completionErr := completion.installUnregister(registered); !installed {
			return completionErr
		}

		if request.ProviderEventID != "" && request.CallbackIdentity != "" {
			key := jsCallbackKey{generation: request.Generation, kind: request.Kind, providerEventID: request.ProviderEventID, callbackID: request.CallbackIdentity}
			if !m.admitJSCallback(key) {
				completion.finish(errJSCallbackDuplicate)
				return errJSCallbackDuplicate
			}
			if installed, completionErr := completion.installReleaseKey(func() { m.releaseJSCallback(key) }); !installed {
				return completionErr
			}
		}
		execution := jsengine.ContextForExecution(request.Realm)
		if execution.Done() != nil {
			context.AfterFunc(execution, func() { completion.finish(execution.Err()) })
		}
		if completed, completionErr := completion.status(); completed {
			return completionErr
		}
		run := func(runtime jsengine.Runtime) error {
			started, callbackErr := completion.begin()
			if !started {
				return callbackErr
			}
			defer completion.end()
			_, callbackErr = executeJSCallbackRequest(runtime, request, completion.settle)
			if callbackErr != nil {
				completion.finish(callbackErr)
			}
			return callbackErr
		}
		if err := jsengine.ScheduleWithContext(loop, request.Realm, run); err != nil {
			completion.finish(err)
			return err
		}
		return nil
	}

	if inOwner {
		if request.ValueCallback != nil {
			return errors.New("Promise-aware JavaScript callback cannot synchronously re-enter its owner")
		}
		return runEngineCallback(func() error {
			request.Callback()
			return nil
		})
	}

	if request.ValueCallback == nil {
		return jsengine.RunWithContext(loop, request.Realm, func(jsengine.Runtime) error {
			return runEngineCallback(func() error {
				request.Callback()
				return nil
			})
		})
	}

	completed := make(chan error, 1)
	completion := &jsCallbackCompletion{
		deliver: func(callbackErr error) { completed <- callbackErr },
	}
	registered, err := m.registerJSCallbackWaiter(request.Generation, completion.finish)
	if err != nil {
		return err
	}
	if installed, completionErr := completion.installUnregister(registered); !installed {
		return completionErr
	}
	started, completionErr := completion.begin()
	if !started {
		return completionErr
	}
	err = jsengine.RunWithContext(loop, request.Realm, func(runtime jsengine.Runtime) error {
		if completed, callbackErr := completion.status(); completed {
			return callbackErr
		}
		var callbackErr error
		_, callbackErr = executeJSCallbackRequest(runtime, request, completion.settle)
		return callbackErr
	})
	completion.end()
	if err != nil {
		completion.finish(err)
		return err
	}
	ctx := jsengine.ContextForExecution(request.Realm)
	select {
	case callbackErr := <-completed:
		return callbackErr
	case <-ctx.Done():
		contextErr := context.Cause(ctx)
		if contextErr == nil {
			contextErr = ctx.Err()
		}
		completion.finish(contextErr)
		return <-completed
	}
}

func (m *JsLoopManager) registerJSCallbackWaiter(generation int64, waiter func(error)) (func(), error) {
	m.loopLock.Lock()
	defer m.loopLock.Unlock()
	if m.stopped {
		return nil, errJSRuntimeUnavailable
	}
	if instance := m.instances[generation]; instance == nil || instance.loop == nil {
		return nil, errJSCallbackStaleGeneration
	}
	if m.callbackWaiters == nil {
		m.callbackWaiters = make(map[int64]map[uint64]func(error))
	}
	waiters := m.callbackWaiters[generation]
	if waiters == nil {
		waiters = make(map[uint64]func(error))
		m.callbackWaiters[generation] = waiters
	}
	m.nextCallbackWaiter++
	token := m.nextCallbackWaiter
	waiters[token] = waiter
	return func() {
		m.loopLock.Lock()
		if current := m.callbackWaiters[generation]; current != nil {
			delete(current, token)
			if len(current) == 0 {
				delete(m.callbackWaiters, generation)
			}
		}
		m.loopLock.Unlock()
	}, nil
}

// takeJSCallbackWaitersLocked removes waiters while the manager lifecycle lock
// is held. Callers notify them only after unlocking.
func (m *JsLoopManager) takeJSCallbackWaitersLocked(generation int64) []func(error) {
	current := m.callbackWaiters[generation]
	delete(m.callbackWaiters, generation)
	waiters := make([]func(error), 0, len(current))
	for _, waiter := range current {
		waiters = append(waiters, waiter)
	}
	return waiters
}

func (m *JsLoopManager) takeAllJSCallbackWaitersLocked() []func(error) {
	var waiters []func(error)
	for generation := range m.callbackWaiters {
		waiters = append(waiters, m.takeJSCallbackWaitersLocked(generation)...)
	}
	m.callbackWaiters = make(map[int64]map[uint64]func(error))
	return waiters
}

func notifyJSCallbackWaiters(waiters []func(error), err error) {
	for _, waiter := range waiters {
		if waiter != nil {
			waiter(err)
		}
	}
}

func (m *JsLoopManager) admitJSCallback(key jsCallbackKey) bool {
	m.loopLock.Lock()
	defer m.loopLock.Unlock()
	if m.stopped {
		return false
	}
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

// inLoopOwner reports whether the caller is already running on the owner of the
// runtime generation. Such callbacks are synchronous and never wait in the queue.
func (m *JsLoopManager) inLoopOwner(generation int64) bool {
	loop, err := m.GetLoop(generation)
	return err == nil && loop != nil && jsengine.InOwner(loop)
}

// dropJSCallbackBeforeLoad drops callbacks that would queue behind script
// loading. A message callback waiting on the busy loop would otherwise consume
// its deadline and fail; scripts raising callbacks from inside their own loop
// still run because they never wait.
// TODO(局部重载/通用): 回调门控目前是全局的（Dice.jsCallbacksGated，随 JsReloading 开关）。
// subTODO(局部重载): 改为按插件门控，局部更新/卸载时只丢弃受影响插件的回调。
func (i *ExtInfo) dropJSCallbackBeforeLoad(d *Dice, kind jsCallbackKind, providerEventID string) bool {
	if !d.jsCallbacksGated.Load() || d.ExtLoopManager.inLoopOwner(i.JSLoopVersion) {
		return false
	}
	d.recordJSLoadDrop(i.Name, kind, jsDropEventDetail(providerEventID))
	return true
}

// dropJSCommandBeforeLoad records a plugin command that was actually issued
// while scripts are loading. The wrapper hides its command map during loading,
// so the command is looked up on the already registered real extension; plugins
// that have not registered yet cannot be recognised and stay silent.
func (i *ExtInfo) dropJSCommandBeforeLoad(ctx *MsgContext, msg *Message, command string) {
	d := ctx.Dice
	if d == nil || !d.jsCallbacksGated.Load() {
		return
	}
	registered := i.GetRealExt()
	if registered == nil || !registered.IsJsExt {
		return
	}
	if _, issued := registered.CmdMapSnapshot()[command]; !issued {
		return
	}
	d.recordJSLoadDrop(i.Name, jsCallbackCommand, " 指令="+command+jsDropEventDetail(callbackEventIDForMessage(ctx, msg)))
}

func jsDropEventDetail(providerEventID string) string {
	if providerEventID == "" {
		return ""
	}
	return " 事件=" + strings.ReplaceAll(providerEventID, "\x00", ":")
}

type jsLoadDropKey struct {
	extension string
	kind      jsCallbackKind
}

// jsLoadDropTracker counts the callbacks dropped during one script-loading phase.
type jsLoadDropTracker struct {
	mu     sync.Mutex
	counts map[jsLoadDropKey]int
}

// add counts one drop and reports whether it is the first for its plugin and callback kind.
func (t *jsLoadDropTracker) add(key jsLoadDropKey) (first bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.counts == nil {
		t.counts = make(map[jsLoadDropKey]int)
	}
	t.counts[key]++
	return t.counts[key] == 1
}

func (t *jsLoadDropTracker) take() map[jsLoadDropKey]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	counts := t.counts
	t.counts = nil
	return counts
}

// recordJSLoadDrop counts every dropped callback for the end-of-load summary but
// logs only the first drop of each plugin and callback kind; later ones stay silent.
func (d *Dice) recordJSLoadDrop(extension string, kind jsCallbackKind, detail string) {
	first := d.jsLoadDrops.add(jsLoadDropKey{extension: extension, kind: kind})
	if first && d.Logger != nil {
		d.Logger.Warnf("JS 扩展脚本尚未加载完成，已丢弃回调：扩展「%s」类型=%s%s", extension, kind, detail)
	}
}

const maxJSLoadDropSummaryItems = 20

// logJSLoadDropSummary reports what script loading dropped; it stays silent when nothing was dropped.
func (d *Dice) logJSLoadDropSummary() {
	counts := d.jsLoadDrops.take()
	if len(counts) == 0 || d.Logger == nil {
		return
	}
	keys := make([]jsLoadDropKey, 0, len(counts))
	total := 0
	for key, count := range counts {
		keys = append(keys, key)
		total += count
	}
	slices.SortFunc(keys, func(a, b jsLoadDropKey) int {
		return cmp.Or(strings.Compare(a.extension, b.extension), strings.Compare(string(a.kind), string(b.kind)))
	})
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if len(parts) == maxJSLoadDropSummaryItems {
			parts = append(parts, fmt.Sprintf("另有 %d 项", len(keys)-maxJSLoadDropSummaryItems))
			break
		}
		parts = append(parts, fmt.Sprintf("「%s」%s×%d", key.extension, key.kind, counts[key]))
	}
	d.Logger.Warnf("JS 扩展脚本加载结束，加载期间共丢弃 %d 个回调：%s", total, strings.Join(parts, "、"))
}

func (i *ExtInfo) dispatchWithJsCheck(d *Dice, kind jsCallbackKind, providerEventID string, schedule bool, callback func(), message *MsgContext) {
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
	if i.dropJSCallbackBeforeLoad(d, kind, providerEventID) {
		return
	}
	request := jsCallbackRequest{
		Generation:       i.JSLoopVersion,
		Realm:            jsContextForMessage(i, message),
		Kind:             kind,
		ProviderEventID:  providerEventID,
		CallbackIdentity: jsCallbackIdentity(i, kind),
		Callback:         callback,
		Message:          message,
		OnError: func(err error) {
			message.recordJSExecutionError(err)
			if d.Logger != nil {
				d.Logger.Errorf("JS脚本异常: %v", err)
			}
		},
	}
	if err := d.ExtLoopManager.dispatchJSCallback(request, schedule); err != nil {
		message.recordJSExecutionError(err)
		if d.Logger != nil {
			d.Logger.Errorf("JS脚本异常: %v", err)
		}
	}
}
