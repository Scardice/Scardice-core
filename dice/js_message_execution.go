package dice

import (
	"context"
	"errors"
	"sync"
)

// Shared by every realm entered for one message, including delayed callbacks.
// Revocation joins active JS entries before the host snapshots or releases state.
type jsMessageExecution struct {
	ctx            context.Context
	cancel         context.CancelCauseFunc
	cancelDeadline context.CancelFunc
	gate           sync.RWMutex
	errMu          sync.Mutex
	err            error

	pendingMu     sync.Mutex
	pending       int
	stopping      bool
	pendingDone   chan struct{}
	pendingClosed bool
}

var errJSExecutionCompleted = errors.New("javascript execution completed")

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
		if parent == nil {
			parent = context.Background()
		}
		if ctx.callbackTransaction != nil && ctx.callbackTransaction.executionContext != nil {
			parent = ctx.callbackTransaction.executionContext
		}
		deadline, cancelDeadline := context.WithTimeout(parent, jsSolveAwaitTimeout)
		lifetime, cancel := context.WithCancelCause(deadline)
		ctx.jsExecution = &jsMessageExecution{
			ctx:            lifetime,
			cancel:         cancel,
			cancelDeadline: cancelDeadline,
			pendingDone:    make(chan struct{}),
		}
		if ctx.executionReleased.Load() {
			cancel(context.Canceled)
			cancelDeadline()
		}
	}
	return ctx.jsExecution
}

// beginJSCallbackChild accounts for a scheduled or owner-reentrant hook until
// its returned Promise settles. Descendants may join while another child is
// still pending; once the count drains during stop, admission stays closed.
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
	execution := ctx.messageJSExecution()
	execution.pendingMu.Lock()
	if execution.pendingDone == nil {
		execution.pendingDone = make(chan struct{})
	}
	if err := execution.ctx.Err(); err != nil {
		execution.pendingMu.Unlock()
		return nil, err
	}
	if execution.stopping && execution.pending == 0 {
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
			if execution.stopping && execution.pending == 0 && !execution.pendingClosed {
				// Revoke the scope on the owner before the event loop can run
				// a floated timer queued by the just-settled child.
				execution.cancel(errJSExecutionCompleted)
				execution.cancelDeadline()
				close(execution.pendingDone)
				execution.pendingClosed = true
			}
			execution.pendingMu.Unlock()
		})
	}, nil
}

// beginJSCallbackOwnerScope creates a host-owned completion root. Descendant
// hooks may join while the root is active, and the last release revokes the
// standalone scope synchronously before floated work can run.
func (ctx *MsgContext) beginJSCallbackOwnerScope() (func(), error) {
	if ctx == nil {
		return func() {}, nil
	}
	release, err := ctx.beginJSCallbackChild()
	if err != nil {
		return nil, err
	}
	execution := ctx.messageJSExecution()
	// Keep scheduled children behind the owner gate until the host has admitted
	// every hook. Otherwise a synchronously settled hook could queue floated
	// work before the owner root has a chance to close admission.
	execution.gate.Lock()
	execution.pendingMu.Lock()
	execution.stopping = true
	execution.pendingMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			release()
			execution.gate.Unlock()
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

// TODO(局部重载/禁用与删除): 没有消息的脚本级上下文返回 context.Background()，永不取消，
// 所以脚本顶层注册的 setTimeout/setInterval/Promise 回调无法随脚本卸载而撤销。
// subTODO(局部重载): 为每个脚本提供可取消的生命周期上下文（卸载时取消），并登记定时器句柄以便 clearInterval。
func (c *jsExecutionContext) ExecutionContext() context.Context {
	if c != nil && c.Message != nil {
		return c.Message.messageJSExecution().ctx
	}
	return context.Background()
}

func (c *jsExecutionContext) EnterExecution() (func(), error) {
	if c == nil || c.Message == nil {
		return func() {}, nil
	}
	execution := c.Message.messageJSExecution()
	execution.gate.RLock()
	if err := execution.ctx.Err(); err != nil {
		execution.gate.RUnlock()
		return nil, err
	}
	return execution.gate.RUnlock, nil
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
	if execution == nil {
		return nil
	}
	contextErr := context.Cause(execution.ctx)
	execution.pendingMu.Lock()
	if execution.pendingDone == nil {
		execution.pendingDone = make(chan struct{})
	}
	execution.stopping = true
	if execution.pending == 0 && !execution.pendingClosed {
		execution.cancel(errJSExecutionCompleted)
		execution.cancelDeadline()
		close(execution.pendingDone)
		execution.pendingClosed = true
	}
	pendingDone := execution.pendingDone
	execution.pendingMu.Unlock()
	if contextErr == nil {
		select {
		case <-pendingDone:
		case <-execution.ctx.Done():
			contextErr = context.Cause(execution.ctx)
		}
	}
	execution.cancel(errJSExecutionCompleted)
	execution.cancelDeadline()
	execution.gate.Lock()
	defer execution.gate.Unlock()
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
	if active := ctx.Dice.currentJSMessageContext(); active != nil {
		return active.messageJSExecution().ctx.Err()
	}
	return nil
}
