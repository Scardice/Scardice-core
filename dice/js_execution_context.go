package dice

import (
	"context"
	"sync"

	"Scardice-core/utils/jsengine"
)

// jsExecutionContext is the request-local authority carried by one realm
// entry. Transaction and registry state never live on Dice, so concurrent
// roots and runtime generations cannot overwrite one another.
type jsExecutionContext struct {
	Dice        *Dice
	Plugin      *ExtInfo
	Script      *JsScriptInfo
	Message     *MsgContext
	Transaction *DurableCallbackTransaction

	// PersistentBinding is used only while a script registers long-lived hook
	// and task functions. Their codec scope resolves the active same-generation
	// invocation each time the registered callback is called.
	PersistentBinding bool

	// PersistentAsync marks a root that PromotePersistentAsync opened for a
	// persistent binding's timer or host-I/O continuation. It stays tied to the
	// binding's lineage: host I/O it starts follows the binding, not the root,
	// and its completions resume in a new independent root once this one ends.
	PersistentAsync bool

	// CompatibilityMode is live by default for existing callers. Replay and
	// rebuild callers must set it explicitly before entering host services.
	CompatibilityMode JSCompatibilityExecutionMode
	ExternalEffects   *JSExternalEffectTracker
	// Completion marks a context captured earlier and re-entered by a host
	// service when its work finished (fetch, filesystem, ...). It only changes
	// how the invocation is classified for accounting; identity is unchanged.
	Completion bool

	execution     *jsMessageExecution
	registry      *jsInvocationRegistry
	activeRuntime jsengine.Runtime
	binding       *jsPersistentBindingLifecycle
}

type jsPersistentBindingLifecycle struct {
	mu         sync.RWMutex
	scheduler  bool
	retired    bool
	err        error
	ready      chan struct{}
	readyOnce  sync.Once
	context    context.Context
	cancel     context.CancelCauseFunc
	active     []*jsExecutionContext
	loop       jsengine.Loop
	roots      sync.WaitGroup
	joinOnce   sync.Once
	drained    chan struct{}
	requests   map[uint64]*jsPersistentAsyncRequest
	unregister func()
}

type jsPersistentAsyncRequest struct {
	pending  []func()
	terminal bool
	finish   func()
}

func newJSPersistentBindingLifecycle(parent context.Context) *jsPersistentBindingLifecycle {
	lifetime, cancel := context.WithCancelCause(parent)
	return &jsPersistentBindingLifecycle{
		ready: make(chan struct{}), context: lifetime, cancel: cancel, drained: make(chan struct{}),
	}
}

func (l *jsPersistentBindingLifecycle) setUnregister(unregister func()) {
	l.mu.Lock()
	if !l.retired {
		l.unregister = unregister
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	unregister()
}

// Admission and retirement share the lock: no root can be added after a
// retirement starts waiting for the ones it owns.
func (l *jsPersistentBindingLifecycle) startRoot(run func()) error {
	l.mu.Lock()
	if l.retired || l.context.Err() != nil {
		l.mu.Unlock()
		return ErrJSInvocationExpired
	}
	l.roots.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.roots.Done()
		run()
	}()
	return nil
}

// Only events of the same service request wait for one another. Keeping
// separate pumps lets a root await I/O whose completion uses another request.
func (l *jsPersistentBindingLifecycle) enqueueRequest(id uint64, terminal bool, run func()) error {
	l.mu.Lock()
	request := l.requests[id]
	if (l.retired || l.context.Err() != nil) && (!terminal || request == nil) {
		l.mu.Unlock()
		return ErrJSInvocationExpired
	}
	start := request == nil
	if start {
		if l.requests == nil {
			l.requests = make(map[uint64]*jsPersistentAsyncRequest)
		}
		request = &jsPersistentAsyncRequest{}
		l.requests[id] = request
		l.roots.Add(1)
	} else if request.terminal {
		l.mu.Unlock()
		return ErrJSInvocationExpired
	}
	if terminal {
		request.terminal = true
		request.finish = run
	} else {
		request.pending = append(request.pending, run)
	}
	l.mu.Unlock()
	if start {
		go l.drainRequest(id, request)
	}
	return nil
}

func (l *jsPersistentBindingLifecycle) drainRequest(id uint64, request *jsPersistentAsyncRequest) {
	defer l.roots.Done()
	for {
		l.mu.Lock()
		if l.retired || l.context.Err() != nil {
			request.pending = nil
		}
		var run func()
		if len(request.pending) != 0 {
			run = request.pending[0]
			request.pending[0] = nil
			request.pending = request.pending[1:]
		} else if request.finish != nil {
			run = request.finish
			request.finish = nil
		} else {
			delete(l.requests, id)
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		run()
	}
}

func (l *jsPersistentBindingLifecycle) activateScheduler() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.scheduler = true
	l.mu.Unlock()
}

func (l *jsPersistentBindingLifecycle) schedulerContext() (context.Context, bool) {
	if l == nil {
		return nil, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.context, l.scheduler
}
func (l *jsPersistentBindingLifecycle) pushInvocation(invocation *jsExecutionContext) {
	if l == nil || invocation == nil {
		return
	}
	l.mu.Lock()
	if !l.retired {
		l.active = append(l.active, invocation)
	}
	l.mu.Unlock()
}

func (l *jsPersistentBindingLifecycle) popInvocation(invocation *jsExecutionContext) {
	if l == nil || invocation == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for index := len(l.active) - 1; index >= 0; index-- {
		if l.active[index] != invocation {
			continue
		}
		copy(l.active[index:], l.active[index+1:])
		l.active[len(l.active)-1] = nil
		l.active = l.active[:len(l.active)-1]
		return
	}
}

func (l *jsPersistentBindingLifecycle) activeInvocation() *jsExecutionContext {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.retired || len(l.active) == 0 {
		return nil
	}
	return l.active[len(l.active)-1]
}

func (l *jsPersistentBindingLifecycle) complete(err error) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.retired {
		l.mu.Unlock()
		return
	}
	l.err = err
	l.mu.Unlock()
	l.readyOnce.Do(func() { close(l.ready) })
	if err != nil {
		l.cancel(err)
		l.retire()
	}
}

func (l *jsPersistentBindingLifecycle) wait() error {
	if l == nil {
		return ErrJSInvocationExpired
	}
	select {
	case <-l.ready:
	case <-l.context.Done():
		return context.Cause(l.context)
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.err
}

func (l *jsPersistentBindingLifecycle) retire() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.retired = true
	if l.err == nil {
		l.err = ErrJSInvocationExpired
	}
	l.active = nil
	for _, request := range l.requests {
		request.pending = nil
	}
	l.cancel(ErrJSInvocationExpired)
	l.mu.Unlock()
	l.readyOnce.Do(func() { close(l.ready) })
	// A host action can retire its own binding from the VM owner. Cancel
	// immediately, but leave joining to an outside goroutine in that case.
	// The generation waiter remains registered until every root has exited.
	if jsengine.InOwner(l.loop) {
		l.joinOnce.Do(func() { go l.finishRetirement() })
		return
	}
	l.joinOnce.Do(l.finishRetirement)
	<-l.drained
}

func (l *jsPersistentBindingLifecycle) finishRetirement() {
	l.roots.Wait()
	l.mu.Lock()
	unregister := l.unregister
	l.unregister = nil
	l.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	close(l.drained)
}

func (c *jsExecutionContext) activatePersistentScheduler() {
	if c != nil && c.PersistentBinding {
		c.binding.activateScheduler()
	}
}

func (c *jsExecutionContext) completePersistentBinding(err error) {
	if c != nil && c.PersistentBinding {
		c.binding.complete(err)
	}
}

// jsCompletionContext derives the context under which a host service resumes
// script after asynchronous work. The original context is left untouched
// because the callback that started the work may still be running under it.
func jsCompletionContext(context any) any {
	original, ok := context.(*jsExecutionContext)
	if !ok || original == nil || original.Completion {
		return context
	}
	original.invocationRegistry()
	// Listed field by field: activeRuntime belongs to the owner thread and a
	// completion runs on a host goroutine while the original may still be
	// entering or leaving its realm.
	return &jsExecutionContext{
		Dice:              original.Dice,
		Plugin:            original.Plugin,
		Script:            original.Script,
		Message:           original.Message,
		Transaction:       original.Transaction,
		PersistentBinding: original.PersistentBinding,
		PersistentAsync:   original.PersistentAsync,
		CompatibilityMode: original.CompatibilityMode,
		ExternalEffects:   original.ExternalEffects,
		Completion:        true,
		execution:         original.execution,
		registry:          original.registry,
		binding:           original.binding,
	}
}

func (c *jsExecutionContext) ContextKey() any {
	if c == nil {
		return nil
	}
	return c.invocationRegistry()
}

// HostScopeIdentity implements hostbridge.ScopeIdentifier. A persistent binding
// wraps host values through the invocation currently entering its generation,
// so every scope resolving to one invocation registry shares one proxy identity.
func (c *jsExecutionContext) HostScopeIdentity() any {
	if c == nil {
		return nil
	}
	if target, err := c.persistentInvocation(); err == nil && target != nil {
		return target.invocationRegistry()
	}
	return c.invocationRegistry()
}

type jsExecutionContextKey struct{}

var revokedJSExecutionContext = func() *jsExecutionContext {
	message := &MsgContext{}
	message.executionReleased.Store(true)
	return &jsExecutionContext{Message: message}
}()

func jsOpaqueExecutionContext(value any) *jsExecutionContext {
	switch context := value.(type) {
	case *jsExecutionContext:
		return context
	case jsengine.RevokedExecutionScope, *jsengine.RevokedExecutionScope:
		return revokedJSExecutionContext
	default:
		return nil
	}
}

func jsContextForPlugin(plugin *ExtInfo) *jsExecutionContext {
	if plugin == nil {
		return nil
	}
	resolved := plugin.GetRealExt()
	if resolved == nil {
		resolved = plugin
	}
	return &jsExecutionContext{Dice: resolved.dice, Plugin: resolved, Script: resolved.Source, binding: resolved.Source.currentPersistentBinding()}
}

func jsContextForMessage(plugin *ExtInfo, message *MsgContext) *jsExecutionContext {
	context := jsContextForPlugin(plugin)
	if context == nil {
		context = &jsExecutionContext{}
	}
	context.Message = message
	if message != nil {
		context.Dice = message.Dice
		context.Transaction = message.callbackTransaction
		message.messageJSExecution()
	}
	context.invocationRegistry()
	return context
}

func jsContextForRoot(parent context.Context, d *Dice, plugin *ExtInfo, script *JsScriptInfo, transaction *DurableCallbackTransaction, persistentBinding bool) *jsExecutionContext {
	execution := newJSMessageExecution(parent)
	realm := &jsExecutionContext{
		Dice: d, Plugin: plugin, Script: script, Transaction: transaction,
		PersistentBinding: persistentBinding, execution: execution,
	}
	if realm.Script == nil && plugin != nil {
		realm.Script = plugin.Source
	}
	if persistentBinding {
		lifetime := parent
		if d != nil {
			lifetime = d.jsRuntimeContext()
		} else if lifetime == nil {
			lifetime = context.Background()
		}
		binding := newJSPersistentBindingLifecycle(lifetime)
		realm.binding = binding
		execution.stopBinding = context.AfterFunc(binding.context, func() {
			execution.cancel(context.Cause(binding.context))
		})
		if generation := jsContextGeneration(realm); d != nil && d.ExtLoopManager != nil && generation != 0 {
			loop, loopErr := d.ExtLoopManager.GetLoop(generation)
			binding.loop = loop
			if loopErr == nil {
				unregister, err := d.ExtLoopManager.registerJSCallbackWaiter(generation, func(error) { binding.retire() })
				if err == nil {
					binding.setUnregister(unregister)
				} else {
					binding.complete(err)
				}
			} else {
				binding.complete(loopErr)
			}
		}
	} else if realm.Script != nil {
		realm.binding = realm.Script.currentPersistentBinding()
	}
	realm.invocationRegistry()
	return realm
}

func (c *jsExecutionContext) withRuntime(runtime jsengine.Runtime, run func() error) error {
	if c == nil {
		return run()
	}
	previous := c.activeRuntime
	c.activeRuntime = runtime
	if c.binding != nil {
		c.binding.pushInvocation(c)
	}
	defer func() {
		if c.binding != nil {
			c.binding.popInvocation(c)
		}
		c.activeRuntime = previous
	}()
	return run()
}

func jsExecutionContextFor(loop jsengine.Loop) *jsExecutionContext {
	if loop == nil {
		return nil
	}
	return jsOpaqueExecutionContext(jsengine.CurrentContext(loop))
}

func jsContextPlugin(context *jsExecutionContext) *ExtInfo {
	if context == nil {
		return nil
	}
	if context.Plugin != nil {
		return context.Plugin.GetRealExt()
	}
	return nil
}

func jsContextScript(context *jsExecutionContext) *JsScriptInfo {
	if context == nil {
		return nil
	}
	if context.Script != nil {
		return context.Script
	}
	if plugin := jsContextPlugin(context); plugin != nil {
		return plugin.Source
	}
	return nil
}

func jsContextSource(context *jsExecutionContext) *JsScriptInfo {
	if script := jsContextScript(context); script != nil {
		return script
	}
	if plugin := jsContextPlugin(context); plugin != nil {
		return plugin.Source
	}
	return nil
}
