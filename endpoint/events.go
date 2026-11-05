package endpoint

import (
	"errors"
	"fmt"

	"Scardice-core/adapterapi"
)

// DesiredState is the durable intent for an endpoint. It deliberately has no
// provider-specific states.
type DesiredState string

const (
	DesiredStateInvalid  DesiredState = ""
	DesiredStateDisabled DesiredState = "disabled"
	DesiredStateEnabled  DesiredState = "enabled"
	DesiredStateRemoving DesiredState = "removing"
	DesiredStateDeleted  DesiredState = "deleted"
)

// Short aliases make the transition table easy to read while retaining the
// explicit DesiredState-prefixed names for public callers.
const (
	Disabled DesiredState = DesiredStateDisabled
	Enabled  DesiredState = DesiredStateEnabled
	Removing DesiredState = DesiredStateRemoving
	Deleted  DesiredState = DesiredStateDeleted
)

func (state DesiredState) Valid() bool {
	return state == DesiredStateDisabled || state == DesiredStateEnabled || state == DesiredStateRemoving || state == DesiredStateDeleted
}

// OperationState describes the durable command/effect lane, independently from
// desired and provider-observed lifecycle state.
type OperationState string

const (
	OperationStateInvalid   OperationState = ""
	OperationStateIdle      OperationState = "idle"
	OperationStatePending   OperationState = "pending"
	OperationStateSucceeded OperationState = "succeeded"
	OperationStateFailed    OperationState = "failed"
	OperationStateAmbiguous OperationState = "ambiguous"
)

func (state OperationState) Valid() bool {
	return state == OperationStateIdle || state == OperationStatePending || state == OperationStateSucceeded || state == OperationStateFailed || state == OperationStateAmbiguous
}

// CommandKind is the closed set of aggregate commands.
type CommandKind string

const (
	CommandCreate          CommandKind = "create"
	CommandUpdateConfig    CommandKind = "update_config"
	CommandEnable          CommandKind = "enable"
	CommandDisable         CommandKind = "disable"
	CommandRelogin         CommandKind = "relogin"
	CommandRemove          CommandKind = "remove"
	CommandResolve         CommandKind = "resolve"
	CommandComplete        CommandKind = "complete"
	CommandObserveIdentity CommandKind = "observe_identity"
)

// Completion is a Supervisor-owned pure fact transition from pending to a
// terminal operation state; it performs no external work.
func (kind CommandKind) Valid() bool {
	return kind == CommandCreate || kind == CommandUpdateConfig || kind == CommandEnable || kind == CommandDisable || kind == CommandRelogin || kind == CommandRemove || kind == CommandResolve || kind == CommandComplete || kind == CommandObserveIdentity
}

// SecretInput is a transient command input. Only its reference enters endpoint
// events and projections; Repository.CommitWithSecret persists the value in
// the same UnitOfWork as the endpoint event.
type SecretInput struct {
	Ref             string
	Version         uint64
	ExpectedVersion uint64
	Plaintext       []byte
}

// Statistics preserves account counters across migration without coupling the
// endpoint aggregate to provider-specific runtime objects.
type Statistics struct {
	GroupCount    int64 `json:"groupCount,omitempty"`
	CommandCount  int64 `json:"commandCount,omitempty"`
	LastCommandAt int64 `json:"lastCommandAt,omitempty"`
	OnlineSeconds int64 `json:"onlineSeconds,omitempty"`
}

func (statistics Statistics) valid() bool {
	return statistics.GroupCount >= 0 && statistics.CommandCount >= 0 && statistics.LastCommandAt >= 0 && statistics.OnlineSeconds >= 0
}

func (statistics Statistics) empty() bool {
	return statistics == (Statistics{})
}

type Command struct {
	Kind                     CommandKind
	Type                     CommandKind
	CommandID                string
	ID                       string
	CorrelationID            string
	OperationID              string
	PrincipalID              string
	RequestID                string
	IdempotencyScope         string
	IdempotencyKey           string
	RequestDigest            []byte `json:"-"`
	EndpointID               adapterapi.EndpointID
	DisplayName              string
	Statistics               Statistics
	AdapterKey               adapterapi.AdapterKey
	Config                   adapterapi.ValidatedConfig
	SecretRefs               []adapterapi.SecretRef
	SecretDigest             string        `json:"-" yaml:"-"`
	SecretInput              *SecretInput  `json:"-" yaml:"-"`
	SecretInputs             []SecretInput `json:"-" yaml:"-"`
	ExpectedVersion          uint64
	ExpectedAggregateVersion uint64
	ExpectedVersionSet       bool
	ObservedState            adapterapi.ObservedState
	Generation               uint64
	DesiredVersion           uint64
	ProviderID               adapterapi.PrincipalID
	CompletionState          OperationState
}

// EventType names durable endpoint facts. Event payload fields contain only
// canonical non-secret config and references, never resolved secret values.
type EventType string

const (
	EventEndpointCreated          EventType = "endpoint.created"
	EventBaselineImported         EventType = "endpoint.baseline_imported"
	EventConfigUpdated            EventType = "endpoint.config_updated"
	EventDesiredEnabled           EventType = "endpoint.enabled"
	EventDesiredDisabled          EventType = "endpoint.disabled"
	EventReloginRequested         EventType = "endpoint.relogin_requested"
	EventRemovalRequested         EventType = "endpoint.removal_requested"
	EventEndpointDeleted          EventType = "endpoint.deleted"
	EventOperationCompleted       EventType = "endpoint.operation_completed"
	EventEndpointIdentityObserved EventType = "endpoint.identity_observed"
)

const (
	EndpointCreated          = EventEndpointCreated
	ConfigUpdated            = EventConfigUpdated
	DesiredEnabled           = EventDesiredEnabled
	DesiredDisabled          = EventDesiredDisabled
	ReloginRequested         = EventReloginRequested
	RemovalRequested         = EventRemovalRequested
	EndpointDeleted          = EventEndpointDeleted
	OperationCompleted       = EventOperationCompleted
	EndpointIdentityObserved = EventEndpointIdentityObserved
)

func (kind EventType) Valid() bool {
	return kind == EventEndpointCreated || kind == EventBaselineImported || kind == EventConfigUpdated || kind == EventDesiredEnabled || kind == EventDesiredDisabled || kind == EventReloginRequested || kind == EventRemovalRequested || kind == EventEndpointDeleted || kind == EventOperationCompleted || kind == EventEndpointIdentityObserved
}

// EffectKind is an intent for Supervisor. It is not execution and carries no
// runtime, SDK, credential, or artifact data.
type EffectKind string

const (
	EffectStart   EffectKind = "start"
	EffectStop    EffectKind = "stop"
	EffectRelogin EffectKind = "relogin"
	EffectReplace EffectKind = "replace"
	EffectDelete  EffectKind = "delete"
)

func (kind EffectKind) Valid() bool {
	return kind == EffectStart || kind == EffectStop || kind == EffectRelogin || kind == EffectReplace || kind == EffectDelete
}

// LifecycleEffect is a deterministic lifecycle intent emitted alongside the
// event that changes desired intent.
type LifecycleEffect struct {
	ID             string
	EffectID       string
	Kind           EffectKind
	EndpointID     adapterapi.EndpointID
	Generation     uint64
	DesiredState   DesiredState
	DesiredVersion uint64
	OperationID    string
	CorrelationID  string
	CommandID      string
}

// Event is the aggregate's durable fact. Sequence is the aggregate version;
// DesiredVersion fences lifecycle work across relogin/replace races.
type Event struct {
	ID               string
	EventID          string
	Type             EventType
	Kind             EventType
	Sequence         uint64
	AggregateVersion uint64
	CommandID        string
	CommandDigest    string
	CorrelationID    string
	OperationID      string
	EffectID         string
	EffectKind       EffectKind
	Generation       uint64
	DesiredVersion   uint64
	ProviderID       adapterapi.PrincipalID
	DisplayName      string
	Statistics       Statistics
	DesiredState     DesiredState
	ObservedState    adapterapi.ObservedState
	OperationState   OperationState
	EndpointID       adapterapi.EndpointID
	AdapterKey       adapterapi.AdapterKey
	Config           adapterapi.ValidatedConfig
	ConfigSet        bool
}

func validEventOperation(kind EventType, state OperationState, operationID string) bool {
	if kind == EventBaselineImported {
		return state == OperationStateIdle && operationID == ""
	}
	return operationID != "" || state == OperationStateIdle && kind == EventEndpointIdentityObserved
}

// NewBaselineImported preserves an endpoint's current durable intent while
// dropping runtime observations, fences and transient operation references.
// Startup admits fresh lifecycle work before an enabled endpoint can run.
func NewBaselineImported(view EndpointView, commandID, correlationID string) (Event, error) {
	if commandID == "" || correlationID == "" || !view.EndpointID.Valid() || !view.AdapterKey.Valid() ||
		!view.DesiredState.Valid() || !validDisplayName(view.DisplayName) || !view.Statistics.valid() ||
		(view.ProviderID != "" && !view.ProviderID.Valid()) {
		return Event{}, fmt.Errorf("%w: invalid endpoint baseline identity", ErrInvalidState)
	}
	if err := view.Config.Validate(); err != nil {
		return Event{}, fmt.Errorf("%w: invalid endpoint baseline config: %w", ErrInvalidState, err)
	}
	id := eventID(view.EndpointID, commandID, correlationID, 1, EventBaselineImported)
	event := Event{
		ID: id, EventID: id, Type: EventBaselineImported, Kind: EventBaselineImported,
		Sequence: 1, AggregateVersion: 1, CommandID: commandID, CorrelationID: correlationID,
		EndpointID: view.EndpointID, AdapterKey: view.AdapterKey, Config: view.Config.Clone(), ConfigSet: true,
		DisplayName: view.DisplayName, Statistics: view.Statistics, ProviderID: view.ProviderID,
		DesiredState: view.DesiredState, DesiredVersion: 1,
		ObservedState: adapterapi.ObservedStateStopped, OperationState: OperationStateIdle,
	}
	digest, err := eventFingerprint(event, EventBaselineImported, id, 1)
	if err != nil {
		return Event{}, err
	}
	event.CommandDigest = digest
	return event, nil
}

// CommandRecord is the replay/idempotency ledger. It stores only digests and
// deterministic IDs, not command payloads or sensitive values.
type CommandRecord struct {
	Digest           string
	EventFingerprint string
	EventIDs         []string
	EffectIDs        []string
	DesiredVersion   uint64
}

// State is all durable aggregate state. No adapter instance, clock, resolver,
type State struct {
	Version           uint64
	Generation        uint64
	EndpointID        adapterapi.EndpointID
	AdapterKey        adapterapi.AdapterKey
	Config            adapterapi.ValidatedConfig
	DesiredState      DesiredState
	ObservedState     adapterapi.ObservedState
	OperationState    OperationState
	DesiredVersion    uint64
	ProviderID        adapterapi.PrincipalID
	DisplayName       string
	Statistics        Statistics
	OperationID       string
	CorrelationID     string
	PendingEffectID   string
	PendingEffectKind EffectKind
	PendingCommandID  string
	ProcessedCommands map[string]CommandRecord
	AppliedEffects    map[string]struct{}
	// AllowedAdapters is optional pure input supplied by a registry boundary.
	// A nil map means the aggregate performs only adapter-key validation.
	AllowedAdapters map[adapterapi.AdapterKey]struct{}
}

// Decision is the complete pure result of a command. Replay is true when the
// same command identity and digest have already been applied.
type Decision struct {
	Events  []Event
	Effects []LifecycleEffect
	Replay  bool
	// PrincipalID and RequestID are audit/operation metadata. They are not
	// part of the immutable aggregate event or its deterministic digest.
	PrincipalID      string
	RequestID        string
	IdempotencyScope string
	IdempotencyKey   string
	RequestDigest    []byte
}

var (
	ErrRejected             = errors.New("endpoint: command rejected")
	ErrInvalidState         = errors.New("endpoint: invalid aggregate state")
	ErrInvalidCommand       = errors.New("endpoint: invalid command")
	ErrStaleExpectedVersion = errors.New("endpoint: stale expected version")
	ErrCommandConflict      = errors.New("endpoint: command identity conflict")
	ErrDeletedEndpoint      = errors.New("endpoint: endpoint is deleted")
	ErrUnknownAdapter       = errors.New("endpoint: unknown adapter")
	ErrInvalidTransition    = errors.New("endpoint: invalid transition")
	ErrVersionExhausted     = errors.New("endpoint: version exhausted")
)

type RejectCode string

const (
	RejectInvalidCommand    RejectCode = "invalid_command"
	RejectInvalidState      RejectCode = "invalid_state"
	RejectStaleVersion      RejectCode = "stale_expected_version"
	RejectCommandConflict   RejectCode = "command_conflict"
	RejectDeleted           RejectCode = "deleted"
	RejectUnknownAdapter    RejectCode = "unknown_adapter"
	RejectInvalidTransition RejectCode = "invalid_transition"
	RejectInvalidConfig     RejectCode = "invalid_config"
)

// RejectError is stable and inspectable by API/service layers without parsing
// strings. Unwrap preserves errors.Is checks against the sentinel causes.
type RejectError struct {
	Code            RejectCode
	CommandID       string
	ExpectedVersion uint64
	ActualVersion   uint64
	Reason          string
	Cause           error
}

func (e *RejectError) Error() string {
	if e == nil {
		return "endpoint: command rejected"
	}
	if e.Reason == "" {
		return fmt.Sprintf("endpoint: %s", e.Code)
	}
	return fmt.Sprintf("endpoint: %s: %s", e.Code, e.Reason)
}
func (e *RejectError) Unwrap() error {
	if e == nil || e.Cause == nil {
		return ErrRejected
	}
	return errors.Join(ErrRejected, e.Cause)
}
