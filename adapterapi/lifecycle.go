package adapterapi

import (
	"fmt"
	"time"
)

// ObservedState is the runtime's fenced lifecycle fact. Desired state remains
// Core-owned and is not represented here.
type ObservedState uint8

const (
	ObservedStateInvalid ObservedState = iota
	ObservedStateStopped
	ObservedStateStarting
	ObservedStateConnected
	ObservedStateStopping
	ObservedStateFailed
	ObservedStateAmbiguous
)

func (state ObservedState) Valid() bool {
	return state >= ObservedStateStopped && state <= ObservedStateAmbiguous
}

// LifecycleObservationKind describes what changed without exposing a worker
// generation selected by an adapter.
type LifecycleObservationKind uint8

const (
	LifecycleObservationInvalid LifecycleObservationKind = iota
	LifecycleObservationState
	LifecycleObservationIdentity
	LifecycleObservationDiagnostic
)

func (kind LifecycleObservationKind) Valid() bool {
	return kind >= LifecycleObservationState && kind <= LifecycleObservationDiagnostic
}

const MaxObservationDetailBytes = 16 * 1024

// LifecycleObservation contains provider facts; Supervisor attaches endpoint,
// generation, and desired-version fences in its CorePort wrapper.
type LifecycleObservation struct {
	Kind       LifecycleObservationKind `json:"kind"`
	State      ObservedState            `json:"state"`
	ProviderID PrincipalID              `json:"providerId,omitempty"`
	Code       string                   `json:"code,omitempty"`
	Detail     string                   `json:"detail,omitempty"`
	Retryable  bool                     `json:"retryable,omitempty"`
	OccurredAt time.Time                `json:"occurredAt"`
}

func (observation LifecycleObservation) Validate() error {
	if !observation.Kind.Valid() || !observation.State.Valid() {
		return fmt.Errorf("%w: lifecycle kind or state", ErrInvalidContract)
	}
	if observation.ProviderID != "" && !observation.ProviderID.Valid() {
		return fmt.Errorf("%w: invalid optional lifecycle provider id", ErrInvalidContract)
	}
	if !observation.OccurredAt.IsZero() {
		if _, err := observation.OccurredAt.MarshalJSON(); err != nil {
			return fmt.Errorf("%w: invalid lifecycle timestamp", ErrInvalidContract)
		}
	}
	if len(observation.Code) > MaxInboundFieldBytes || len(observation.Detail) > MaxObservationDetailBytes {
		return fmt.Errorf("%w: lifecycle detail exceeds bounds", ErrInvalidContract)
	}
	return nil
}
