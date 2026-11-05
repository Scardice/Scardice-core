package dice

import (
	"context"
	"errors"

	"Scardice-core/utils/jsengine"
)

// persistentLineage reports whether the context belongs to a persistent
// binding: its load root, or a root PromotePersistentAsync opened for one of the
// binding's asynchronous continuations.
func (c *jsExecutionContext) persistentLineage() bool {
	return c != nil && (c.PersistentBinding || c.PersistentAsync)
}

// persistentScope reports that the context stands for the persistent binding
// itself rather than for one live root: the load root, and a promoted root once
// it has finished normally. Work captured under such a scope resolves the root
// currently entering the same generation; it never writes into a finished
// transaction. Cancellation, a failed callback and the invocation timeout carry
// a different cause and leave a promoted root revoked.
func (c *jsExecutionContext) persistentScope() bool {
	if c == nil || c.binding == nil {
		return false
	}
	if c.PersistentBinding {
		return true
	}
	if !c.PersistentAsync {
		return false
	}
	execution := c.executionScope()
	return execution != nil && execution.ctx.Err() != nil && errors.Is(context.Cause(execution.ctx), errJSExecutionCompleted)
}

// AsyncWorkContext keeps load- and timer-started I/O alive after a successful
// root, without granting the same unbounded lifetime to JS execution. Explicit
// root cancellation, failure and binding retirement still abort that work.
func (c *jsExecutionContext) AsyncWorkContext() (context.Context, context.CancelFunc) {
	execution := c.executionScope()
	if !c.persistentLineage() || c.binding == nil {
		return c.ExecutionContext(), func() {}
	}
	// A provider can restore the load-time token while invoking a callback
	// inside a promoted root. Its unawaited I/O survives a normal completion
	// of that root, but must still observe a failure of that same root.
	if c.persistentScope() {
		if active := c.binding.activeInvocation(); active != nil && active != c && active.binding == c.binding && !active.persistentScope() {
			execution = active.executionScope()
		}
	}
	if execution == nil {
		return c.binding.context, func() {}
	}
	lifetime, cancel := context.WithCancelCause(c.binding.context)
	root := execution.ctx
	stop := context.AfterFunc(root, func() {
		if cause := context.Cause(root); !errors.Is(cause, errJSExecutionCompleted) {
			cancel(cause)
		}
	})
	return lifetime, func() {
		stop()
		cancel(context.Canceled)
	}
}

// DeliverHostCompletion implements jsengine.HostCompletionDeliverer for
// engines that deliver host completions from their owner thread.
func (c *jsExecutionContext) DeliverHostCompletion(deliver func() error) error {
	if c == nil || !c.PersistentAsync {
		return deliver()
	}
	// Admission is the barrier against the root ending: while it is held the
	// completion belongs to the root, and a refusal means the root is over.
	leave, err := c.executionScope().enter()
	if err == nil {
		defer leave()
		return deliver()
	}
	if c.persistentScope() {
		return c.PromotePersistentAsync(func() (jsengine.Value, error) { return nil, deliver() })
	}
	// A cancelled invocation still hands its completion to the engine, which
	// retires the request under the revoked scope.
	return deliver()
}

// scheduleJSCompletion resumes script after host I/O started under owner has
// finished. The completion runs under the original invocation while it is live
// (an awaited fetch continues inside its callback's root and transaction).
// Persistent load roots, and promoted roots that ended before the I/O, resume in
// a fresh independent root instead, so a completion never writes into a finished
// transaction.
func scheduleJSCompletion(loop jsengine.Loop, owner any, run func(jsengine.Runtime) error) error {
	if err := jsCompatibilitySchedulingAllowed(owner); err != nil {
		return err
	}
	execution := jsOpaqueExecutionContext(owner)
	promote := func() error {
		return execution.PromotePersistentAsync(func() (jsengine.Value, error) {
			active := jsExecutionContextFor(loop)
			if active == nil || active.activeRuntime == nil {
				return nil, ErrJSInvocationExpired
			}
			return nil, run(active.activeRuntime)
		})
	}
	switch {
	case execution != nil && execution.PersistentBinding:
		return promote()
	case execution != nil && execution.PersistentAsync:
		return jsengine.ScheduleWithContext(loop, jsCompletionContext(owner), func(runtime jsengine.Runtime) error {
			// Entering a promoted root that already finished normally is
			// allowed (it is the binding's scope); the completion must not run
			// in it. A live root is held by its admission while this runs.
			if execution.persistentScope() {
				return promote()
			}
			return run(runtime)
		})
	}
	return jsengine.ScheduleWithContext(loop, jsCompletionContext(owner), run)
}
