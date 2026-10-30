package jsengine

// InvocationPhase names the mechanism by which an engine entered a realm on
// behalf of a host context. The engine cannot know why the host asked; the host
// refines these into its own categories using the context it supplied.
type InvocationPhase uint8

const (
	// InvocationLoad evaluates an entry (LoadEntry*).
	InvocationLoad InvocationPhase = iota + 1
	// InvocationRun is a callback the host waited for (Run, RunWithContext).
	InvocationRun
	// InvocationSchedule is a callback the host queued without waiting for it.
	InvocationSchedule
	// InvocationReaction is engine-owned asynchronous work: timers,
	// microtasks and Promise reactions registered by script.
	InvocationReaction
)

func (p InvocationPhase) String() string {
	switch p {
	case InvocationLoad:
		return "load"
	case InvocationRun:
		return "run"
	case InvocationSchedule:
		return "schedule"
	case InvocationReaction:
		return "reaction"
	default:
		return "unknown"
	}
}

// InvocationObserver brackets each outermost execution inside a realm. run
// performs the execution and its error is returned unchanged; an observer
// that does not want to measure an invocation simply returns run().
//
// The engine calls the observer once per outermost invocation. Work that runs
// nested inside an already observed invocation (for example Promise
// continuations drained by it) belongs to that window and is not reported
// again, so windows never overlap within one loop.
//
// Observers run on the loop's owner goroutine inside the realm and MUST NOT
// call back into the same loop.
type InvocationObserver interface {
	ObserveInvocation(context any, phase InvocationPhase, run func() error) error
}

// ObservableLoop is implemented by loops that report invocations.
type ObservableLoop interface {
	SetInvocationObserver(InvocationObserver)
}

// SetInvocationObserver attaches observer to loop, replacing any previous one;
// nil detaches. It reports false for loops that cannot be observed.
func SetInvocationObserver(loop Loop, observer InvocationObserver) bool {
	observable, ok := loop.(ObservableLoop)
	if !ok {
		return false
	}
	observable.SetInvocationObserver(observer)
	return true
}
