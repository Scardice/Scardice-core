package dice

import (
	"errors"
	"fmt"
	"sync/atomic"

	"Scardice-core/eventstore"
)

// JSCompatibilityExecutionMode is the explicit execution mode for the legacy
// JavaScript compatibility seam. Replay and rebuild are intentionally
// side-effect-free; only Live may enter a legacy callback.
type JSCompatibilityExecutionMode uint8

const (
	JSCompatibilityLive JSCompatibilityExecutionMode = iota
	JSCompatibilityReplay
	JSCompatibilityRebuild
)

func (m JSCompatibilityExecutionMode) String() string {
	switch m {
	case JSCompatibilityLive:
		return "live"
	case JSCompatibilityReplay:
		return "replay"
	case JSCompatibilityRebuild:
		return "rebuild"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// JSCompatibilityDecision is the decision boundary shared by callback,
// scheduler, and effect adapters. Keeping the three permissions together
// prevents a replay caller from accidentally enabling one side-effect path.
type JSCompatibilityDecision struct {
	Mode               JSCompatibilityExecutionMode
	LegacyCallback     bool
	CallbackScheduling bool
	EffectCapture      bool
}

func DecideJSCompatibility(mode JSCompatibilityExecutionMode) JSCompatibilityDecision {
	allowed := mode == JSCompatibilityLive
	return JSCompatibilityDecision{
		Mode: mode, LegacyCallback: allowed,
		CallbackScheduling: allowed, EffectCapture: allowed,
	}
}

func (d JSCompatibilityDecision) AllowsLegacyCallback() bool     { return d.LegacyCallback }
func (d JSCompatibilityDecision) AllowsCallbackScheduling() bool { return d.CallbackScheduling }
func (d JSCompatibilityDecision) AllowsEffectCapture() bool      { return d.EffectCapture }

var (
	// ErrJSCompatibilityReplaySuppressed is stable and lets callers distinguish
	// a deliberate replay/rebuild suppression from a callback validation error.
	ErrJSCompatibilityReplaySuppressed = errors.New("dice: JS compatibility work suppressed during replay or rebuild")
	// ErrJSValidation denotes deterministic input/contract rejection.
	ErrJSValidation = errors.New("dice: JS compatibility validation failed")
	// ErrJSExternalEffectAmbiguous denotes a callback that may have crossed an
	// external filesystem/network boundary before its outcome was lost.
	ErrJSExternalEffectAmbiguous = errors.New("dice: JS compatibility external effect outcome is ambiguous")
)

// JSCompatibilityBoundary is the narrow adapter boundary used by live
// compatibility callers. Replay/rebuild callers must use the same boundary;
// it refuses callback entry, scheduling, and effect construction before the
// supplied function can run.
type JSCompatibilityBoundary struct {
	decision JSCompatibilityDecision
}

func NewJSCompatibilityBoundary(mode JSCompatibilityExecutionMode) JSCompatibilityBoundary {
	return JSCompatibilityBoundary{decision: DecideJSCompatibility(mode)}
}

func (b JSCompatibilityBoundary) Decision() JSCompatibilityDecision { return b.decision }

func (b JSCompatibilityBoundary) InvokeLegacyCallback(callback func() error) (err error) {
	if !b.decision.AllowsLegacyCallback() {
		return ErrJSCompatibilityReplaySuppressed
	}
	if callback == nil {
		return ErrJSValidation
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: callback panic", ErrJSExternalEffectAmbiguous)
		}
	}()
	return callback()
}

func (b JSCompatibilityBoundary) ScheduleCallback(schedule func() error) error {
	if !b.decision.AllowsCallbackScheduling() {
		return ErrJSCompatibilityReplaySuppressed
	}
	if schedule == nil {
		return ErrJSValidation
	}
	return schedule()
}

func (b JSCompatibilityBoundary) BuildEffect(request JSEffectRequest) (eventstore.NewEffect, error) {
	if !b.decision.AllowsEffectCapture() {
		return eventstore.NewEffect{}, ErrJSCompatibilityReplaySuppressed
	}
	return BuildJSEffect(request)
}

func (b JSCompatibilityBoundary) CaptureEffect(capture func() error) error {
	if !b.decision.AllowsEffectCapture() {
		return ErrJSCompatibilityReplaySuppressed
	}
	if capture == nil {
		return ErrJSValidation
	}
	return capture()
}

// JSExternalEffectTracker records the point at which a live callback has
// passed permission validation and may have entered filesystem/network I/O.
// It is deliberately monotonic: once possible, recovery must not treat the
// callback as safely rerunnable.
type JSExternalEffectTracker struct{ possible atomic.Bool }

func NewJSExternalEffectTracker() *JSExternalEffectTracker { return &JSExternalEffectTracker{} }
func (t *JSExternalEffectTracker) MarkPossible() {
	if t != nil {
		t.possible.Store(true)
	}
}
func (t *JSExternalEffectTracker) PossiblyStarted() bool { return t != nil && t.possible.Load() }

func ClassifyJSCompatibilityFailure(tracker *JSExternalEffectTracker, cause error) error {
	if cause == nil {
		return nil
	}
	if tracker != nil && tracker.PossiblyStarted() {
		return errors.Join(ErrJSExternalEffectAmbiguous, cause)
	}
	return cause
}

func (b JSCompatibilityBoundary) InvokeLegacyCallbackWithTracker(tracker *JSExternalEffectTracker, callback func() error) (err error) {
	if !b.decision.AllowsLegacyCallback() {
		return ErrJSCompatibilityReplaySuppressed
	}

	if callback == nil {
		return ErrJSValidation
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = ClassifyJSCompatibilityFailure(tracker, fmt.Errorf("callback panic: %v", recovered))
		} else {
			err = ClassifyJSCompatibilityFailure(tracker, err)
		}
	}()
	return callback()
}

func jsCompatibilityExternalAccess(context *jsExecutionContext) error {
	if context == nil {
		return nil
	}
	decision := DecideJSCompatibility(context.CompatibilityMode)
	if !decision.AllowsEffectCapture() {
		return ErrJSCompatibilityReplaySuppressed
	}
	if context.ExternalEffects != nil {
		context.ExternalEffects.MarkPossible()
	}
	return nil
}

func jsCompatibilitySchedulingAllowed(value any) error {
	context := jsOpaqueExecutionContext(value)
	if context == nil {
		return nil
	}
	if !DecideJSCompatibility(context.CompatibilityMode).AllowsCallbackScheduling() {
		return ErrJSCompatibilityReplaySuppressed
	}
	return nil
}
