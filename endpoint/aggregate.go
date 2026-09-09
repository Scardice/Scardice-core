package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"Scardice-core/adapterapi"
)

// Decide computes endpoint events/effects without mutating state or performing
// I/O. All lifecycle side effects are represented as intents for Supervisor.
// Decide is also available as a value method for callers that keep the
// aggregate state behind an explicit EndpointAggregate name.
func (state State) Decide(command Command) (Decision, error) {
	return Decide(state, command)
}

func Decide(state State, command Command) (Decision, error) {
	if err := validateCommandAliases(command); err != nil {
		return Decision{}, reject(RejectInvalidCommand, commandID(command), state.Version, 0, ErrInvalidCommand, err.Error())
	}
	kind := commandKind(command)
	commandID := commandID(command)
	if commandID == "" || !kind.Valid() {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "command id and kind are required")
	}
	correlationID := command.CorrelationID
	if correlationID == "" {
		// A missing correlation is still deterministic and keeps old callers
		// compatible; service boundaries should normally provide one explicitly.
		correlationID = commandID
	}
	if err := validateConfigAliases(command); err != nil {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, err.Error())
	}
	if state.Version == 0 && (state.Config.Version != 0 || len(state.Config.Canonical) != 0 || state.Config.SecretRefs != nil) {
		return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrInvalidState, "empty aggregate has config payload")
	}
	if state.Version > 0 {
		if !state.EndpointID.Valid() || !state.AdapterKey.Valid() || !state.DesiredState.Valid() || !state.OperationState.Valid() || !state.ObservedState.Valid() || state.OperationID == "" || state.CorrelationID == "" || state.DesiredVersion != state.Version {
			return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrInvalidState, "state contains invalid durable values")
		}
		if state.Config.Version == 0 || len(state.Config.Canonical) == 0 {
			return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrInvalidState, "state is missing validated config")
		}
		if err := state.Config.Validate(); err != nil {
			return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrInvalidState, err.Error())
		}
		if command.EndpointID == "" { command.EndpointID = state.EndpointID }
		if command.AdapterKey == "" {
			command.AdapterKey = state.AdapterKey
		} else if !command.AdapterKey.Valid() || command.AdapterKey != state.AdapterKey {
			return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "command adapter key does not match aggregate")
		}
	}
	if (kind == CommandResolve || kind == CommandComplete) && state.Version > 0 {
		if command.OperationID != "" && command.OperationID != state.OperationID {
			return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "operation mismatch")
		}
		command.OperationID = state.OperationID
	}
	command.Config = commandConfig(command)
	digest, digestErr := commandDigest(command, kind, commandID, correlationID)
	if digestErr != nil {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, digestErr.Error())
	}
	if record, ok := state.ProcessedCommands[commandID]; ok {
		if record.Digest != digest {
			return Decision{}, reject(RejectCommandConflict, commandID, state.Version, 0, ErrCommandConflict, "command id was already used with different input")
		}
		return Decision{Replay: true}, nil
	}
	expectedVersion, expectedSet := expectedVersion(command)
	if expectedSet && expectedVersion != state.Version {
		return Decision{}, reject(RejectStaleVersion, commandID, state.Version, expectedVersion, ErrStaleExpectedVersion, fmt.Sprintf("expected %d, actual %d", expectedVersion, state.Version))
	}
	if state.Version == 0 {
		if kind != CommandCreate {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "only create is valid for an empty aggregate")
		}
		return decideCreate(state, command, commandID, correlationID, digest)
	}
	if kind == CommandCreate {
		return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "endpoint already exists")
	}
	if state.DesiredState == DesiredStateDeleted {
		return Decision{}, reject(RejectDeleted, commandID, state.Version, 0, ErrDeletedEndpoint, "deleted endpoints cannot accept commands")
	}
	if command.EndpointID != "" && command.EndpointID != state.EndpointID {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "command endpoint does not match aggregate")
	}
	if (state.OperationState == OperationStatePending || state.OperationState == OperationStateFailed || state.OperationState == OperationStateAmbiguous) && kind != CommandResolve && kind != CommandComplete {
		return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "operation requires explicit completion or resolution")
	}

	switch kind {
	case CommandUpdateConfig:
		return decideUpdateConfig(state, command, commandID, correlationID, digest)
	case CommandEnable:
		if state.DesiredState != DesiredStateDisabled {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "enable requires disabled desired state")
		}
		if state.ObservedState == adapterapi.ObservedStateStarting || state.ObservedState == adapterapi.ObservedStateStopping {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "enable cannot overlap an active observation")
		}
		return decideLifecycle(state, command, commandID, correlationID, digest, EventDesiredEnabled, DesiredStateEnabled, EffectStart)
	case CommandDisable:
		if state.DesiredState != DesiredStateEnabled {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "disable requires enabled desired state")
		}
		return decideLifecycle(state, command, commandID, correlationID, digest, EventDesiredDisabled, DesiredStateDisabled, EffectStop)
	case CommandRelogin:
		if state.DesiredState != DesiredStateEnabled {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "relogin requires enabled desired state")
		}
		return decideLifecycle(state, command, commandID, correlationID, digest, EventReloginRequested, DesiredStateEnabled, EffectRelogin)
	case CommandRemove:
		if state.DesiredState != DesiredStateEnabled && state.DesiredState != DesiredStateDisabled {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "remove requires enabled or disabled desired state")
		}
		effect := EffectDelete
		if state.DesiredState == DesiredStateEnabled { effect = EffectStop }
		return decideLifecycle(state, command, commandID, correlationID, digest, EventRemovalRequested, DesiredStateRemoving, effect)
	case CommandComplete:
		return decideCompletion(state, command, commandID, correlationID, digest)
	case CommandResolve:
		if state.DesiredState != DesiredStateRemoving || state.ObservedState != adapterapi.ObservedStateStopped ||
			(state.OperationState != OperationStatePending && state.OperationState != OperationStateFailed && state.OperationState != OperationStateAmbiguous && state.OperationState != OperationStateSucceeded) {
			return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "resolve requires removing desired state and durable stopped observation")
		}
		return decideLifecycle(state, command, commandID, correlationID, digest, EventEndpointDeleted, DesiredStateDeleted, "")
	default:
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "unsupported command kind")
	}
}
func decideCompletion(state State, command Command, commandID, correlationID, digest string) (Decision, error) {
	operationActive := state.OperationState == OperationStatePending || state.OperationState == OperationStateFailed || state.OperationState == OperationStateAmbiguous
	observationRefresh := state.OperationState == OperationStateSucceeded && command.CompletionState == OperationStateSucceeded
	if (!operationActive && !observationRefresh) || state.OperationID == "" || command.Generation != state.Generation {
		return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "completion requires matching operation generation")
	}
	if command.OperationID != "" && command.OperationID != state.OperationID {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "completion operation mismatch")
	}
	if command.CompletionState != OperationStateSucceeded && command.CompletionState != OperationStateFailed && command.CompletionState != OperationStateAmbiguous {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "invalid completion state")
	}
	if !command.ObservedState.Valid() {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "completion requires observation")
	}
	sequence, err := nextVersion(state.Version)
	if err != nil { return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrVersionExhausted, err.Error()) }
	desiredVersion, err := nextVersion(state.DesiredVersion)
	if err != nil { return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrVersionExhausted, err.Error()) }
	eventIDValue := eventID(state.EndpointID, commandID, correlationID, sequence, EventOperationCompleted)
	event := Event{
		ID: eventIDValue, EventID: eventIDValue, Type: EventOperationCompleted, Kind: EventOperationCompleted,
		Sequence: sequence, AggregateVersion: sequence, CommandID: commandID, CommandDigest: digest,
		CorrelationID: correlationID, OperationID: state.OperationID, Generation: state.Generation,
		DesiredVersion: desiredVersion, DesiredState: state.DesiredState,
		ObservedState: command.ObservedState, OperationState: command.CompletionState,
		EndpointID: state.EndpointID, AdapterKey: state.AdapterKey,
	}
	return Decision{Events: []Event{event}}, nil
}


func decideCreate(state State, command Command, commandID, correlationID, digest string) (Decision, error) {
	if !command.EndpointID.Valid() || !command.AdapterKey.Valid() {
		return Decision{}, reject(RejectInvalidCommand, commandID, state.Version, 0, ErrInvalidCommand, "create requires valid endpoint and adapter identifiers")
	}
	if state.AllowedAdapters != nil {
		if _, ok := state.AllowedAdapters[command.AdapterKey]; !ok {
			return Decision{}, reject(RejectUnknownAdapter, commandID, state.Version, 0, ErrUnknownAdapter, "adapter is not registered")
		}
	}
	if err := command.Config.Validate(); err != nil {
		return Decision{}, reject(RejectInvalidConfig, commandID, state.Version, 0, adapterapi.ErrInvalidConfig, err.Error())
	}
	eventIDValue := eventID(command.EndpointID, commandID, correlationID, 1, EventEndpointCreated)
	event := Event{
		ID: eventIDValue, EventID: eventIDValue, Type: EventEndpointCreated, Kind: EventEndpointCreated,
		Sequence: 1, AggregateVersion: 1, CommandID: commandID, CommandDigest: digest, CorrelationID: correlationID, OperationID: operationID(command.OperationID, commandID),
		DesiredVersion: 1, DesiredState: DesiredStateDisabled, ObservedState: adapterapi.ObservedStateStopped, OperationState: OperationStateIdle,
		EndpointID: command.EndpointID, AdapterKey: command.AdapterKey, Config: command.Config.Clone(), ConfigSet: true,
	}
	return Decision{Events: []Event{event}}, nil
}

func decideUpdateConfig(state State, command Command, commandID, correlationID, digest string) (Decision, error) {
	if state.DesiredState == DesiredStateRemoving {
		return Decision{}, reject(RejectInvalidTransition, commandID, state.Version, 0, ErrInvalidTransition, "config cannot change while removing")
	}
	if err := command.Config.Validate(); err != nil {
		return Decision{}, reject(RejectInvalidConfig, commandID, state.Version, 0, adapterapi.ErrInvalidConfig, err.Error())
	}
	effect := EffectKind("")
	if state.DesiredState == DesiredStateEnabled { effect = EffectReplace }
	return decideLifecycleWithConfig(state, command, commandID, correlationID, digest, EventConfigUpdated, state.DesiredState, effect, command.Config)
}

func decideLifecycle(state State, command Command, commandID, correlationID, digest string, eventType EventType, desired DesiredState, effect EffectKind) (Decision, error) {
	return decideLifecycleWithConfig(state, command, commandID, correlationID, digest, eventType, desired, effect, adapterapi.ValidatedConfig{})
}

func decideLifecycleWithConfig(state State, command Command, commandID, correlationID, digest string, eventType EventType, desired DesiredState, effect EffectKind, config adapterapi.ValidatedConfig) (Decision, error) {
	sequence, err := nextVersion(state.Version)
	if err != nil { return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrVersionExhausted, err.Error()) }
	desiredVersion, err := nextVersion(state.DesiredVersion)
	if err != nil { return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrVersionExhausted, err.Error()) }
	generation := state.Generation
	if effect == EffectStart || effect == EffectRelogin || effect == EffectReplace {
		if state.Generation == ^uint64(0) {
			return Decision{}, reject(RejectInvalidState, commandID, state.Version, 0, ErrVersionExhausted, ErrVersionExhausted.Error())
		}
		generation++
	}
	eventIDValue := eventID(state.EndpointID, commandID, correlationID, sequence, eventType)
	event := Event{
		ID: eventIDValue, EventID: eventIDValue, Type: eventType, Kind: eventType, Sequence: sequence, AggregateVersion: sequence,
		CommandID: commandID, CommandDigest: digest, CorrelationID: correlationID, OperationID: operationID(command.OperationID, commandID),
		DesiredVersion: desiredVersion, Generation: generation, DesiredState: desired, ObservedState: state.ObservedState, OperationState: OperationStateIdle,
		EndpointID: state.EndpointID, AdapterKey: state.AdapterKey, EffectKind: effect,
	}
	if eventType != EventEndpointDeleted && effect != "" { event.OperationState = OperationStatePending }
	if config.Version != 0 { event.Config = config.Clone(); event.ConfigSet = true }
	decision := Decision{Events: []Event{event}}
	if effect != "" {
		effectIDValue := effectID(event.ID, effect)
		event.EffectID = effectIDValue
		decision.Events[0].EffectID = effectIDValue
		decision.Effects = []LifecycleEffect{{
			ID: effectIDValue, EffectID: effectIDValue, Kind: effect, EndpointID: state.EndpointID, Generation: generation, DesiredState: desired,
			DesiredVersion: desiredVersion, OperationID: event.OperationID, CorrelationID: correlationID, CommandID: commandID,
		}}
	}
	return decision, nil
}

// Apply is the value-method form of the pure reducer.
func (state State) Apply(event Event) (State, error) {
	return Apply(state, event)
}

// Apply folds one durable event into a fresh state. It never mutates the input
// state's maps, config bytes, or reference slices.
func Apply(state State, event Event) (State, error) {
	if state.Version == 0 {
		if state.Generation != 0 || state.EndpointID != "" || state.AdapterKey != "" || state.Config.Version != 0 || len(state.Config.Canonical) != 0 || state.Config.SecretRefs != nil || state.DesiredState != DesiredStateInvalid || state.ObservedState != adapterapi.ObservedStateInvalid || state.OperationState != OperationStateInvalid || state.DesiredVersion != 0 || state.OperationID != "" || state.CorrelationID != "" || state.PendingEffectID != "" || state.PendingEffectKind != "" || state.PendingCommandID != "" || state.ProcessedCommands != nil || state.AppliedEffects != nil {
			return State{}, fmt.Errorf("%w: invalid empty aggregate state", ErrInvalidState)
		}
	} else {
		if !state.EndpointID.Valid() || !state.AdapterKey.Valid() || !state.DesiredState.Valid() || !state.OperationState.Valid() || !state.ObservedState.Valid() || state.OperationID == "" || state.CorrelationID == "" || state.DesiredVersion != state.Version || state.Config.Version == 0 || len(state.Config.Canonical) == 0 {
			return State{}, fmt.Errorf("%w: invalid current aggregate state", ErrInvalidState)
		}
		if err := state.Config.Validate(); err != nil {
			return State{}, fmt.Errorf("%w: invalid current config: %v", ErrInvalidState, err)
		}
	}
	typ := event.Type
	if typ != "" && event.Kind != "" && typ != event.Kind {
		return State{}, fmt.Errorf("%w: event type aliases conflict", ErrInvalidState)
	}
	if typ == "" { typ = event.Kind }
	eventIDValue := event.ID
	if eventIDValue != "" && event.EventID != "" && eventIDValue != event.EventID {
		return State{}, fmt.Errorf("%w: event id aliases conflict", ErrInvalidState)
	}
	if eventIDValue == "" { eventIDValue = event.EventID }
	sequence := event.Sequence
	if sequence != 0 && event.AggregateVersion != 0 && sequence != event.AggregateVersion {
		return State{}, fmt.Errorf("%w: event version aliases conflict", ErrInvalidState)
	}
	if sequence == 0 { sequence = event.AggregateVersion }
	if !typ.Valid() || sequence == 0 || eventIDValue == "" || event.CommandID == "" || event.CorrelationID == "" || event.OperationID == "" || !event.EndpointID.Valid() || event.CommandDigest == "" || !event.OperationState.Valid() || !event.ObservedState.Valid() {
		return State{}, fmt.Errorf("%w: malformed event", ErrInvalidState)
	}
	if expected := eventID(event.EndpointID, event.CommandID, event.CorrelationID, sequence, typ); eventIDValue != expected {
		return State{}, fmt.Errorf("%w: nondeterministic event id", ErrInvalidState)
	}
	fingerprint, fingerprintErr := eventFingerprint(event, typ, eventIDValue, sequence)
	if fingerprintErr != nil {
		return State{}, fmt.Errorf("%w: malformed event payload: %v", ErrInvalidState, fingerprintErr)
	}
	if record, ok := state.ProcessedCommands[event.CommandID]; ok {
		if record.Digest == event.CommandDigest && record.EventFingerprint == fingerprint {
			return cloneState(state), nil
		}
		return State{}, fmt.Errorf("%w: command digest or event fingerprint conflict", ErrInvalidState)
	}
	if event.EffectID != "" {
		if !event.EffectKind.Valid() || event.EffectID != effectID(eventIDValue, event.EffectKind) {
			return State{}, fmt.Errorf("%w: nondeterministic effect id", ErrInvalidState)
		}
		if _, exists := state.AppliedEffects[event.EffectID]; exists {
			return State{}, fmt.Errorf("%w: duplicate effect id", ErrInvalidState)
		}
	} else if event.EffectKind != "" {
		return State{}, fmt.Errorf("%w: missing effect id", ErrInvalidState)
	}
	if state.Version == ^uint64(0) || state.DesiredVersion == ^uint64(0) {
		return State{}, fmt.Errorf("%w: %v", ErrInvalidState, ErrVersionExhausted)
	}
	if !typ.Valid() || sequence == 0 || sequence != state.Version+1 {
		return State{}, fmt.Errorf("%w: malformed event", ErrInvalidState)
	}
	if state.Version > 0 && event.EndpointID != state.EndpointID {
		return State{}, fmt.Errorf("%w: endpoint mismatch", ErrInvalidState)
	}
	if state.Version > 0 && (!event.AdapterKey.Valid() || event.AdapterKey != state.AdapterKey) {
		return State{}, fmt.Errorf("%w: adapter key mismatch", ErrInvalidState)
	}
	if state.Version > 0 && event.Generation < state.Generation {
		return State{}, fmt.Errorf("%w: generation regressed", ErrInvalidState)
	}
	if event.DesiredVersion != state.DesiredVersion+1 {
		return State{}, fmt.Errorf("%w: non-monotonic desired version", ErrInvalidState)
	}
	if event.ConfigSet {
		if typ != EventEndpointCreated && typ != EventConfigUpdated {
			return State{}, fmt.Errorf("%w: unexpected config payload", ErrInvalidState)
		}
		if err := event.Config.Validate(); err != nil { return State{}, fmt.Errorf("%w: event config: %v", ErrInvalidState, err) }
	} else {
		if event.Config.Version != 0 || len(event.Config.Canonical) != 0 || event.Config.SecretRefs != nil {
			return State{}, fmt.Errorf("%w: config bytes without config flag", ErrInvalidState)
		}
		if typ == EventEndpointCreated || typ == EventConfigUpdated {
			return State{}, fmt.Errorf("%w: missing config payload", ErrInvalidState)
		}
	}
	if !validEventTransition(state, typ, event) {
		return State{}, fmt.Errorf("%w: invalid event transition", ErrInvalidState)
	}
	next := cloneState(state)
	next.Version = sequence
	next.Generation = event.Generation
	next.EndpointID = event.EndpointID
	if event.AdapterKey != "" { next.AdapterKey = event.AdapterKey }
	if event.ConfigSet { next.Config = event.Config.Clone() }
	next.DesiredState = event.DesiredState
	next.ObservedState = event.ObservedState
	next.OperationState = event.OperationState
	next.DesiredVersion = event.DesiredVersion
	next.OperationID = event.OperationID
	next.CorrelationID = event.CorrelationID
	if event.EffectID != "" && event.EffectKind != "" {
		next.PendingEffectID = event.EffectID
		next.PendingEffectKind = event.EffectKind
		next.PendingCommandID = event.CommandID
	}
	if typ == EventOperationCompleted && event.OperationState == OperationStateSucceeded {
		next.PendingEffectID = ""
		next.PendingEffectKind = ""
		next.PendingCommandID = ""
	}
	if next.ProcessedCommands == nil { next.ProcessedCommands = make(map[string]CommandRecord) }
	if next.AppliedEffects == nil { next.AppliedEffects = make(map[string]struct{}) }
	record := next.ProcessedCommands[event.CommandID]
	if record.Digest != "" && record.Digest != event.CommandDigest {
		return State{}, fmt.Errorf("%w: command digest conflict", ErrInvalidState)
	}
	record.Digest = event.CommandDigest
	record.EventFingerprint = fingerprint
	record.EventIDs = append(record.EventIDs, eventIDValue)
	if event.EffectID != "" {
		record.EffectIDs = append(record.EffectIDs, event.EffectID)
		next.AppliedEffects[event.EffectID] = struct{}{}
	}
	record.DesiredVersion = event.DesiredVersion
	next.ProcessedCommands[event.CommandID] = record
	return next, nil
}

func validEventTransition(state State, typ EventType, event Event) bool {
	if state.Version == 0 {
		return typ == EventEndpointCreated && event.AdapterKey.Valid() && event.ConfigSet &&
			event.DesiredState == DesiredStateDisabled && event.ObservedState == adapterapi.ObservedStateStopped &&
			event.OperationState == OperationStateIdle && event.Generation == 0 && event.EffectID == "" && event.EffectKind == ""
	}
	if event.AdapterKey != state.AdapterKey { return false }
	if typ != EventOperationCompleted && typ != EventEndpointDeleted && (state.OperationState == OperationStatePending || state.OperationState == OperationStateFailed || state.OperationState == OperationStateAmbiguous) {
		return false
	}
	if typ != EventOperationCompleted && event.ObservedState != state.ObservedState { return false }
	switch typ {
	case EventConfigUpdated:
		if state.DesiredState == DesiredStateRemoving || state.DesiredState == DesiredStateDeleted || event.DesiredState != state.DesiredState { return false }
		if state.DesiredState == DesiredStateEnabled {
			return event.OperationState == OperationStatePending && event.Generation == state.Generation+1 && event.EffectKind == EffectReplace && event.EffectID != ""
		}
		return event.OperationState == OperationStateIdle && event.Generation == state.Generation && event.EffectKind == "" && event.EffectID == ""
	case EventDesiredEnabled:
		return state.DesiredState == DesiredStateDisabled && event.DesiredState == DesiredStateEnabled &&
			event.OperationState == OperationStatePending && event.Generation == state.Generation+1 && event.EffectKind == EffectStart && event.EffectID != ""
	case EventDesiredDisabled:
		return state.DesiredState == DesiredStateEnabled && event.DesiredState == DesiredStateDisabled &&
			event.OperationState == OperationStatePending && event.Generation == state.Generation && event.EffectKind == EffectStop && event.EffectID != ""
	case EventReloginRequested:
		return state.DesiredState == DesiredStateEnabled && event.DesiredState == DesiredStateEnabled &&
			event.OperationState == OperationStatePending && event.Generation == state.Generation+1 && event.EffectKind == EffectRelogin && event.EffectID != ""
	case EventRemovalRequested:
		return (state.DesiredState == DesiredStateEnabled || state.DesiredState == DesiredStateDisabled) &&
			event.DesiredState == DesiredStateRemoving && event.OperationState == OperationStatePending &&
			event.Generation == state.Generation && event.EffectID != "" &&
			((state.DesiredState == DesiredStateEnabled && event.EffectKind == EffectStop) || (state.DesiredState == DesiredStateDisabled && event.EffectKind == EffectDelete))
	case EventOperationCompleted:
		operationActive := state.OperationState == OperationStatePending || state.OperationState == OperationStateFailed || state.OperationState == OperationStateAmbiguous
		observationRefresh := state.OperationState == OperationStateSucceeded && event.OperationState == OperationStateSucceeded
		return (operationActive || observationRefresh) &&
			event.OperationID == state.OperationID && event.DesiredState == state.DesiredState && event.Generation == state.Generation &&
			event.EffectID == "" && event.EffectKind == "" && event.OperationState != OperationStateIdle && event.OperationState != OperationStatePending
	case EventEndpointDeleted:
		return state.DesiredState == DesiredStateRemoving && event.OperationID == state.OperationID &&
			(state.OperationState == OperationStatePending || state.OperationState == OperationStateFailed || state.OperationState == OperationStateAmbiguous || state.OperationState == OperationStateSucceeded) &&
			event.DesiredState == DesiredStateDeleted && event.ObservedState == adapterapi.ObservedStateStopped && event.OperationState == OperationStateIdle &&
			event.Generation == state.Generation && event.EffectID == "" && event.EffectKind == ""
	default:
		return false
	}
}

func cloneState(state State) State {
	next := state
	next.Config = state.Config.Clone()
	if state.ProcessedCommands != nil {
		next.ProcessedCommands = make(map[string]CommandRecord, len(state.ProcessedCommands))
		for key, record := range state.ProcessedCommands {
			record.EventIDs = append([]string(nil), record.EventIDs...)
			record.EffectIDs = append([]string(nil), record.EffectIDs...)
			next.ProcessedCommands[key] = record
		}
	}
	if state.AppliedEffects != nil {
		next.AppliedEffects = make(map[string]struct{}, len(state.AppliedEffects))
		for key := range state.AppliedEffects { next.AppliedEffects[key] = struct{}{} }
	}
	if state.AllowedAdapters != nil {
		next.AllowedAdapters = make(map[adapterapi.AdapterKey]struct{}, len(state.AllowedAdapters))
		for key := range state.AllowedAdapters { next.AllowedAdapters[key] = struct{}{} }
	}
	return next
}

func validateConfigAliases(command Command) error {
	if command.SecretRefs == nil || command.Config.SecretRefs == nil {
		return nil
	}
	if len(command.SecretRefs) != len(command.Config.SecretRefs) {
		return fmt.Errorf("secret reference aliases conflict")
	}
	for index, ref := range command.SecretRefs {
		if ref != command.Config.SecretRefs[index] {
			return fmt.Errorf("secret reference aliases conflict")
		}
	}
	return nil
}

func commandConfig(command Command) adapterapi.ValidatedConfig {
	config := command.Config.Clone()
	if command.SecretRefs != nil {
		config.SecretRefs = append([]adapterapi.SecretRef(nil), command.SecretRefs...)
	}
	return config
}
func expectedVersion(command Command) (uint64, bool) {
	if command.ExpectedAggregateVersion != 0 {
		return command.ExpectedAggregateVersion, true
	}
	return command.ExpectedVersion, command.ExpectedVersionSet
}


func validateCommandAliases(command Command) error {
	if command.Kind != "" && command.Type != "" && command.Kind != command.Type {
		return fmt.Errorf("kind and type aliases conflict")
	}
	if command.CommandID != "" && command.ID != "" && command.CommandID != command.ID {
		return fmt.Errorf("command id aliases conflict")
	}
	if command.ExpectedAggregateVersion != 0 && (command.ExpectedVersionSet || command.ExpectedVersion != 0) && command.ExpectedVersion != command.ExpectedAggregateVersion {
		return fmt.Errorf("expected version aliases conflict")
	}
	return nil
}

func commandKind(command Command) CommandKind {
	if command.Kind != "" { return command.Kind }
	return command.Type
}
func commandID(command Command) string {
	if command.CommandID != "" { return command.CommandID }
	return command.ID
}
func operationID(value, commandID string) string {
	if value != "" { return value }
	return "operation-" + shortHash(commandID)
}
func nextVersion(value uint64) (uint64, error) {
	if value == ^uint64(0) { return 0, ErrVersionExhausted }
	return value + 1, nil
}
func commandDigest(command Command, kind CommandKind, commandID, correlationID string) (string, error) {
	expected, expectedSet := expectedVersion(command)
	canonical := struct {
		Kind CommandKind `json:"kind"`

		CommandID string `json:"commandId"`
		CorrelationID string `json:"correlationId"`
		OperationID string `json:"operationId"`
		EndpointID adapterapi.EndpointID `json:"endpointId"`
		AdapterKey adapterapi.AdapterKey `json:"adapterKey"`
		Config adapterapi.ValidatedConfig `json:"config"`
		SecretDigest string `json:"secretDigest"`
		ExpectedVersion uint64 `json:"expectedVersion"`
		ExpectedVersionSet bool `json:"expectedVersionSet"`
		ObservedState adapterapi.ObservedState `json:"observedState"`
		Generation uint64 `json:"generation"`
		CompletionState OperationState `json:"completionState"`
	}{kind, commandID, correlationID, operationID(command.OperationID, commandID), command.EndpointID, command.AdapterKey, command.Config.Clone(), command.SecretDigest, expected, expectedSet, command.ObservedState, command.Generation, command.CompletionState}
	bytes, err := json.Marshal(canonical)
	if err != nil { return "", fmt.Errorf("invalid command digest payload: %w", err) }
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
func eventFingerprint(event Event, typ EventType, eventIDValue string, sequence uint64) (string, error) {
	canonical := struct {
		ID string
		Type EventType
		Sequence uint64
		CommandID string
		CommandDigest string
		CorrelationID string
		OperationID string
		EffectID string
		EffectKind EffectKind
		Generation uint64
		DesiredVersion uint64
		DesiredState DesiredState
		ObservedState adapterapi.ObservedState
		OperationState OperationState
		EndpointID adapterapi.EndpointID
		AdapterKey adapterapi.AdapterKey
		Config adapterapi.ValidatedConfig
		ConfigSet bool
	}{eventIDValue, typ, sequence, event.CommandID, event.CommandDigest, event.CorrelationID, event.OperationID, event.EffectID, event.EffectKind, event.Generation, event.DesiredVersion, event.DesiredState, event.ObservedState, event.OperationState, event.EndpointID, event.AdapterKey, event.Config.Clone(), event.ConfigSet}
	bytes, err := json.Marshal(canonical)
	if err != nil { return "", err }
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
func eventID(endpointID adapterapi.EndpointID, commandID, correlationID string, sequence uint64, typ EventType) string {
	sum := sha256.New()
	writeIdentityPart(sum, string(endpointID))
	writeIdentityPart(sum, commandID)
	writeIdentityPart(sum, correlationID)
	writeIdentityPart(sum, fmt.Sprintf("%d", sequence))
	writeIdentityPart(sum, string(typ))
	return "event-" + hex.EncodeToString(sum.Sum(nil))[:32]
}
func effectID(eventID string, kind EffectKind) string {
	sum := sha256.New()
	writeIdentityPart(sum, eventID)
	writeIdentityPart(sum, string(kind))
	return "effect-" + hex.EncodeToString(sum.Sum(nil))[:32]
}
func writeIdentityPart(sum interface{ Write([]byte) (int, error) }, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = sum.Write(length[:])
	_, _ = sum.Write([]byte(value))
}
func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:32]
}
func reject(code RejectCode, commandID string, actual, expected uint64, cause error, reason string) error {
	return &RejectError{Code: code, CommandID: commandID, ExpectedVersion: expected, ActualVersion: actual, Cause: cause, Reason: reason}
}
