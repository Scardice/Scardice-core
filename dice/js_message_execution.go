package dice

import (
	"context"
	"errors"
	"sync"

	"Scardice-core/utils/jsengine"
)

// Shared by every realm entered for one invocation, including delayed
// callbacks. The root and its admitted children use one completion barrier,
// but no callback holds the realm while a Promise is pending.
type jsMessageExecution struct {
	ctx            context.Context
	cancel         context.CancelCauseFunc
	cancelDeadline context.CancelFunc
	stopBinding    func() bool
	errMu          sync.Mutex
	err            error

	registryMu    sync.Mutex
	registries    map[jsInvocationRegistryKey]*jsInvocationRegistry
	pendingMu     sync.Mutex
	pending       int
	running       int
	stopping      bool
	pendingDone   chan struct{}
	pendingClosed bool
}

var errJSExecutionCompleted = errors.New("javascript execution completed")

func newJSMessageExecution(parent context.Context) *jsMessageExecution {
	if parent == nil {
		parent = context.Background()
	}
	deadline, cancelDeadline := context.WithTimeout(parent, jsSolveAwaitTimeout)
	lifetime, cancel := context.WithCancelCause(deadline)
	return &jsMessageExecution{
		ctx:            lifetime,
		cancel:         cancel,
		cancelDeadline: cancelDeadline,
		pendingDone:    make(chan struct{}),
	}
}

func (ctx *MsgContext) messageJSExecution() *jsMessageExecution {
	if ctx == nil {
		return nil
	}
	if ctx.executionParent != nil {
		return ctx.executionParent.messageJSExecution()
	}
	ctx.jsExecutionMu.Lock()
	defer ctx.jsExecutionMu.Unlock()
	if ctx.jsExecution == nil {
		parent := ctx.executionContext
		if ctx.callbackTransaction != nil && ctx.callbackTransaction.executionContext != nil {
			parent = ctx.callbackTransaction.executionContext
		}
		ctx.jsExecution = newJSMessageExecution(parent)
		if ctx.executionReleased.Load() {
			ctx.jsExecution.cancel(context.Canceled)
			ctx.jsExecution.cancelDeadline()
		}
	}
	return ctx.jsExecution
}

// beginChild accounts for an admitted asynchronous child until its Promise or
// host completion settles. During stop, descendants may still join while an
// admitted child/turn is alive; admission closes atomically at zero.
func (execution *jsMessageExecution) beginChild() (func(), error) {
	if execution == nil {
		return func() {}, nil
	}
	execution.pendingMu.Lock()
	if err := execution.ctx.Err(); err != nil {
		execution.pendingMu.Unlock()
		return nil, err
	}
	if execution.stopping && execution.pending == 0 && execution.running == 0 {
		execution.pendingMu.Unlock()
		return nil, context.Canceled
	}
	execution.pending++
	execution.pendingMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			execution.pendingMu.Lock()
			execution.pending--
			execution.finishIfDrainedLocked()
			execution.pendingMu.Unlock()
		})
	}, nil
}

func (execution *jsMessageExecution) finishIfDrainedLocked() {
	if execution == nil || !execution.stopping || execution.pending != 0 || execution.running != 0 || execution.pendingClosed {
		return
	}
	execution.cancel(errJSExecutionCompleted)
	execution.cancelDeadline()
	close(execution.pendingDone)
	execution.pendingClosed = true
}

func (execution *jsMessageExecution) beginStop() <-chan struct{} {
	execution.pendingMu.Lock()
	if execution.pendingDone == nil {
		execution.pendingDone = make(chan struct{})
	}
	execution.stopping = true
	execution.finishIfDrainedLocked()
	done := execution.pendingDone
	execution.pendingMu.Unlock()
	return done
}

func (execution *jsMessageExecution) enter() (func(), error) {
	if execution == nil {
		return func() {}, nil
	}
	execution.pendingMu.Lock()
	if err := execution.ctx.Err(); err != nil {
		execution.pendingMu.Unlock()
		return nil, err
	}
	if execution.stopping && execution.pending == 0 && execution.running == 0 {
		execution.pendingMu.Unlock()
		return nil, context.Canceled
	}
	execution.running++
	execution.pendingMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			execution.pendingMu.Lock()
			execution.running--
			execution.finishIfDrainedLocked()
			execution.pendingMu.Unlock()
		})
	}, nil
}

func (ctx *MsgContext) beginJSCallbackChild() (func(), error) {
	if ctx == nil {
		return func() {}, nil
	}
	if ctx.executionParent != nil {
		return ctx.executionParent.beginJSCallbackChild()
	}
	if ctx.executionReleased.Load() {
		return nil, context.Canceled
	}
	return ctx.messageJSExecution().beginChild()
}

// beginJSCallbackOwnerScope creates a host-owned completion root. Its sentinel
// keeps admission open while the host discovers hooks, without holding the
// realm or blocking Promise continuations.
func (ctx *MsgContext) beginJSCallbackOwnerScope() (func(), error) {
	if ctx == nil {
		return func() {}, nil
	}
	execution := ctx.messageJSExecution()
	release, err := execution.beginChild()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			execution.beginStop()
			release()
		})
	}, nil
}

// runStandaloneMessageScope owns a fresh host context through every scheduled
// hook, then revokes it. It must only be used for contexts that have no caller
// responsible for finalization.
func (ctx *MsgContext) runStandaloneMessageScope(run func()) error {
	if ctx == nil {
		return context.Canceled
	}
	defer ctx.releaseExecutionState()
	releaseOwner, err := ctx.beginJSCallbackOwnerScope()
	if err != nil {
		return err
	}
	defer releaseOwner()
	if run != nil {
		run()
	}
	releaseOwner()
	return ctx.stopJSExecution()
}

func (c *jsExecutionContext) executionScope() *jsMessageExecution {
	if c == nil {
		return nil
	}
	if c.execution != nil {
		return c.execution
	}
	if c.Message != nil {
		return c.Message.messageJSExecution()
	}
	return nil
}

func (c *jsExecutionContext) ExecutionContext() context.Context {
	if c.persistentScope() {
		// The load's execution remains deadline-bound until its successful
		// handoff. Host I/O uses AsyncWorkContext instead of borrowing this
		// scheduler lifetime while the entry is still evaluating.
		if scheduler, active := c.binding.schedulerContext(); active {
			// Providers restore the token captured when a timer or service
			// handler was registered. While that handler runs inside a new
			// root, its binding token must not bypass that root's deadline.
			// Retirement watchers run off-owner and follow the stable binding
			// lifetime, never the unrelated request currently occupying the VM.
			if jsengine.InOwner(c.binding.loop) {
				if active := c.binding.activeInvocation(); active != nil && active != c && active.binding == c.binding && !active.persistentScope() {
					return active.ExecutionContext()
				}
			}
			return scheduler
		}
	}
	if execution := c.executionScope(); execution != nil {
		return execution.ctx
	}
	return context.Background()
}

func (c *jsExecutionContext) EnterExecution() (func(), error) {
	if c.persistentScope() {
		if leave, ok, err := c.enterPersistentScheduler(); ok {
			return leave, err
		}
	}
	if execution := c.executionScope(); execution != nil {
		leave, err := execution.enter()
		// A promoted root can finish normally between the scope check above and
		// the admission attempt. Its pending continuations then belong to the
		// binding, exactly as if they had been resumed a moment later.
		if err != nil && c.persistentScope() {
			if leave, ok, err := c.enterPersistentScheduler(); ok {
				return leave, err
			}
		}
		return leave, err
	}
	return func() {}, nil
}

// enterPersistentScheduler admits work under the binding's scheduler once it is
// active; ok is false while the binding has not started scheduling yet.
func (c *jsExecutionContext) enterPersistentScheduler() (leave func(), ok bool, err error) {
	scheduler, active := c.binding.schedulerContext()
	if !active {
		return nil, false, nil
	}
	if err := scheduler.Err(); err != nil {
		return nil, true, err
	}
	return func() {}, true, nil
}

func runJSExecutionRoot(realm *jsExecutionContext, run func() error) error {
	if realm == nil {
		return context.Canceled
	}
	execution := realm.executionScope()
	if execution == nil {
		return ErrJSInvocationExpired
	}
	if execution.stopBinding != nil {
		defer execution.stopBinding()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			execution.cancel(context.Canceled)
			_ = execution.stop()
			if realm.PersistentBinding {
				realm.completePersistentBinding(context.Canceled)
			}
			panic(recovered)
		}
	}()
	var runErr error
	if run != nil {
		runErr = run()
	}
	if runErr != nil {
		execution.cancel(runErr)
		_ = execution.stop()
		return runErr
	}
	if realm.PersistentBinding {
		realm.activatePersistentScheduler()
	}
	return execution.stop()
}

func (ctx *MsgContext) recordJSExecutionError(err error) {
	if ctx == nil || err == nil {
		return
	}
	execution := ctx.messageJSExecution()
	execution.errMu.Lock()
	if execution.err == nil {
		execution.err = err
	}
	execution.errMu.Unlock()
}

// jsCallbackFailure reports the first callback error before consulting scope
// cancellation. This preserves a Promise rejection when finalization also
// cancels the invocation.
func (ctx *MsgContext) jsCallbackFailure() error {
	if ctx == nil {
		return nil
	}
	root := ctx
	for root.executionParent != nil {
		root = root.executionParent
	}
	root.jsExecutionMu.Lock()
	execution := root.jsExecution
	root.jsExecutionMu.Unlock()
	if execution != nil {
		execution.errMu.Lock()
		err := execution.err
		execution.errMu.Unlock()
		if err != nil {
			return err
		}
	}
	return ctx.checkExecution()
}

func (ctx *MsgContext) abortAfterJSCallback() bool {
	err := ctx.jsCallbackFailure()
	if err == nil {
		return false
	}
	ctx.recordJSExecutionError(err)
	return true
}

func (execution *jsMessageExecution) stop() error {
	if execution == nil {
		return nil
	}
	done := execution.beginStop()
	// Cancellation seals admission, but does not mean an admitted owner entry
	// has returned from its Go host call. Finalizers run outside the VM owner
	// and must join the same pending-and-running barrier on every exit.
	<-done
	contextErr := context.Cause(execution.ctx)
	execution.cancel(errJSExecutionCompleted)
	execution.cancelDeadline()
	execution.errMu.Lock()
	defer execution.errMu.Unlock()
	if execution.err != nil {
		return execution.err
	}
	if errors.Is(contextErr, errJSExecutionCompleted) {
		return nil
	}
	return contextErr
}

func (ctx *MsgContext) stopJSExecution() error {
	if ctx == nil {
		return nil
	}
	if ctx.executionParent != nil {
		return ctx.executionParent.stopJSExecution()
	}
	ctx.jsExecutionMu.Lock()
	execution := ctx.jsExecution
	ctx.jsExecutionMu.Unlock()
	return execution.stop()
}

func (ctx *MsgContext) checkExecution() error {
	if ctx == nil || ctx.executionReleased.Load() {
		return context.Canceled
	}
	if ctx.executionParent != nil {
		return ctx.executionParent.checkExecution()
	}
	ctx.jsExecutionMu.Lock()
	execution := ctx.jsExecution
	ctx.jsExecutionMu.Unlock()
	if execution != nil {
		if err := execution.ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}
