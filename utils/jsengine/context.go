package jsengine

import "errors"

var ErrUnsupportedEntryKind = errors.New("unsupported JavaScript entry kind")

// ErrScheduleUnsupported reports a Loop that cannot accept a callback without
// waiting for its result. Callers MUST NOT fall back to Loop.Run, because a
// blocking call issued from inside a realm callback can never complete.
var ErrScheduleUnsupported = errors.New("JavaScript loop does not support asynchronous scheduling")

// SchedulableLoop accepts realm callbacks without waiting for them to finish.
//
// Loop.Run and RunWithContext wait for completion, so they are valid only from
// outside the realm. Code that may already be executing inside a realm
// callback — host functions, timers, Promise continuations, service
// completions — MUST enter the realm through Schedule instead.
type SchedulableLoop interface {
	Loop
	Schedule(run func(Runtime) error) error
}

// ContextKeyer lets a host execution context declare a comparable identity.
// Providers intern contexts by that identity, so a freshly allocated context
// describing the same plugin reuses one provider-side token instead of growing
// the token table on every realm entry.
type ContextKeyer interface {
	ContextKey() any
}

// ContextAwareLoop carries an opaque host execution context across the
// synchronous callback and engine-owned asynchronous callbacks of one realm.
// The engine-neutral package never interprets the value.
type ContextAwareLoop interface {
	SchedulableLoop
	RunWithContext(context any, run func(Runtime) error) error
	ScheduleWithContext(context any, run func(Runtime) error) error
	CurrentContext() any
	LoadEntryWithContext(context any, entry Entry) error
}

// LoadEntryWithContext evaluates an entry while retaining its opaque context
// across engine-owned asynchronous callbacks.
func LoadEntryWithContext(loop Loop, context any, entry Entry) error {
	if aware, ok := loop.(ContextAwareLoop); ok {
		return aware.LoadEntryWithContext(context, entry)
	}
	return loop.LoadEntry(entry)
}

// RunWithContext executes run with context when the loop supports context
// propagation. Providers that do not implement it retain the ordinary Loop
// behavior rather than silently manufacturing a context.
//
// It waits for run to finish and therefore MUST NOT be called from inside a
// realm callback of the same loop. Use ScheduleWithContext there.
func RunWithContext(loop Loop, context any, run func(Runtime) error) error {
	if aware, ok := loop.(ContextAwareLoop); ok {
		return aware.RunWithContext(context, run)
	}
	return loop.Run(run)
}

// Schedule queues run on loop without waiting for it. It is safe to call from
// inside a realm callback of the same loop.
func Schedule(loop Loop, run func(Runtime) error) error {
	if schedulable, ok := loop.(SchedulableLoop); ok {
		return schedulable.Schedule(run)
	}
	return ErrScheduleUnsupported
}

// ScheduleWithContext queues run on loop with context restored, without
// waiting for it. It is safe to call from inside a realm callback of the same
// loop.
func ScheduleWithContext(loop Loop, context any, run func(Runtime) error) error {
	if aware, ok := loop.(ContextAwareLoop); ok {
		return aware.ScheduleWithContext(context, run)
	}
	return Schedule(loop, run)
}

// CurrentContext returns the context active on loop, or nil for providers that
// do not expose context propagation.
func CurrentContext(loop Loop) any {
	if aware, ok := loop.(ContextAwareLoop); ok {
		return aware.CurrentContext()
	}
	return nil
}
