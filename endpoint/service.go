package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

var (
	ErrNotFound      = errors.New("endpoint: not found")
	ErrConflict      = errors.New("endpoint: conflict")
	ErrInvalid       = errors.New("endpoint: invalid request")
	ErrInvalidConfig = errors.New("endpoint: invalid config")
)
var (
	ErrEndpointNotFound      = ErrNotFound
	ErrEndpointConflict      = ErrConflict
	ErrEndpointInvalid       = ErrInvalid
	ErrEndpointInvalidConfig = ErrInvalidConfig
)

type ServiceError struct {
	Kind  string
	Cause error
}

func (e *ServiceError) Error() string {
	if e == nil {
		return "endpoint: service error"
	}
	if e.Cause != nil {
		return fmt.Sprintf("endpoint: %s: %v", e.Kind, e.Cause)
	}
	return "endpoint: " + e.Kind
}
func (e *ServiceError) Unwrap() error {
	if e == nil || e.Cause == nil {
		return ErrInvalid
	}
	return errors.Join(e.Cause, serviceSentinel(e.Kind))
}
func serviceSentinel(kind string) error {
	switch kind {
	case "not_found":
		return ErrNotFound
	case "conflict":
		return ErrConflict
	case "invalid":
		return ErrInvalid
	case "invalid_config":
		return ErrInvalidConfig
	case "unknown_adapter":
		return ErrUnknownAdapter
	default:
		return ErrInvalid
	}
}

// DescriptorRegistry is intentionally narrow: service validates configuration
// and adapter identity without constructing a runtime or acquiring resources.
type DescriptorRegistry interface {
	Lookup(context.Context, adapterapi.AdapterKey) (adapterapi.Descriptor, bool)
}
type DescriptorLookup func(context.Context, adapterapi.AdapterKey) (adapterapi.Descriptor, error)

type Service struct {
	Repository *Repository
	Store      eventstore.Store
	Registry   any
	InitError  error
}
type Result struct {
	State     State
	Operation eventstore.OperationView
	Commit    eventstore.CommitResult
	Replay    bool
	Effects   []LifecycleEffect
}
type CommandResult = Result

type CommandRequest struct {
	Command     Command
	PrincipalID string
	RequestID   string
}

func NewService(store eventstore.Store, registry any, codecs ...BoundPayloadCodec) *Service {
	s := &Service{Repository: NewRepository(store, codecs...), Store: store, Registry: registry}
	if gormStore, ok := store.(*eventstore.GORMStore); ok {
		s.InitError = RegisterEndpointProjections(gormStore)
	}
	return s
}
func NewEndpointService(store eventstore.Store, registry any, codecs ...BoundPayloadCodec) *Service {
	return NewService(store, registry, codecs...)
}

func (s *Service) descriptor(ctx context.Context, key adapterapi.AdapterKey) (adapterapi.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !key.Valid() {
		return nil, &ServiceError{Kind: "unknown_adapter", Cause: ErrUnknownAdapter}
	}
	accept := func(descriptor adapterapi.Descriptor) (adapterapi.Descriptor, error) {
		if descriptor == nil || descriptor.Key() != key {
			return nil, &ServiceError{Kind: "unknown_adapter", Cause: ErrUnknownAdapter}
		}
		return descriptor, nil
	}
	switch registry := s.Registry.(type) {
	case DescriptorRegistry:
		if descriptor, ok := registry.Lookup(ctx, key); ok {
			return accept(descriptor)
		}
	case DescriptorLookup:
		descriptor, err := registry(ctx, key)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, &ServiceError{Kind: "unknown_adapter", Cause: err}
		}
		return accept(descriptor)
	case func(context.Context, adapterapi.AdapterKey) (adapterapi.Descriptor, error):
		descriptor, err := registry(ctx, key)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, &ServiceError{Kind: "unknown_adapter", Cause: err}
		}
		return accept(descriptor)
	case func(adapterapi.AdapterKey) (adapterapi.Descriptor, bool):
		descriptor, ok := registry(key)
		if !ok {
			return nil, &ServiceError{Kind: "unknown_adapter", Cause: ErrUnknownAdapter}
		}
		return accept(descriptor)
	case map[adapterapi.AdapterKey]adapterapi.Descriptor:
		return accept(registry[key])
	case map[string]adapterapi.Descriptor:
		return accept(registry[string(key)])
	}
	return nil, &ServiceError{Kind: "unknown_adapter", Cause: ErrUnknownAdapter}
}

func (s *Service) validateCommand(ctx context.Context, command *Command) error {
	key := command.AdapterKey
	if key == "" && command.EndpointID.Valid() && s.Repository != nil {
		return nil
	}
	descriptor, err := s.descriptor(ctx, key)
	if err != nil {
		return err
	}
	if descriptor == nil {
		return nil
	}
	if command.Kind == CommandCreate || command.Type == CommandCreate || command.Kind == CommandUpdateConfig || command.Type == CommandUpdateConfig {
		validated, validateErr := descriptor.ValidateConfig(ctx, command.Config.Canonical)
		if validateErr != nil {
			return &ServiceError{Kind: "invalid_config", Cause: errors.Join(ErrInvalidConfig, validateErr)}
		}
		provided := command.SecretRefs
		if provided == nil {
			provided = command.Config.SecretRefs
		}
		if command.SecretRefs != nil && command.Config.SecretRefs != nil && !sameSecretRefs(command.SecretRefs, command.Config.SecretRefs) {
			return &ServiceError{Kind: "invalid_config", Cause: fmt.Errorf("%w: secret reference aliases conflict", ErrInvalidConfig)}
		}
		strictRefs := len(validated.SecretRefs) > 0 || string(key) == "pureonebot"
		if strictRefs && provided != nil && !sameSecretRefs(provided, validated.SecretRefs) {
			return &ServiceError{Kind: "invalid_config", Cause: fmt.Errorf("%w: secret references do not match canonical config", ErrInvalidConfig)}
		}
		if provided != nil && !strictRefs {
			validated.SecretRefs = append([]adapterapi.SecretRef(nil), provided...)
		}
		if strictRefs {
			validated.SecretRefs = append([]adapterapi.SecretRef(nil), validated.SecretRefs...)
		}
		command.Config = validated
	}
	return nil
}
func (s *Service) ValidateConfig(ctx context.Context, key adapterapi.AdapterKey, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	descriptor, err := s.descriptor(ctx, key)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if descriptor == nil {
		return adapterapi.ValidatedConfig{}, &ServiceError{Kind: "unknown_adapter", Cause: ErrUnknownAdapter}
	}
	return descriptor.ValidateConfig(ctx, raw)
}
func (s *Service) Execute(ctx context.Context, command Command) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	secretInputs := command.SecretInputs
	if command.SecretInput != nil {
		secretInputs = append(secretInputs, *command.SecretInput)
	}
	if len(secretInputs) > 0 {
		command.SecretDigest = secretInputsDigest(secretInputs)
		defer zeroSecretInputs(secretInputs)
		defer zeroSecretInputs(command.SecretInputs)
		defer zeroSecretInput(command.SecretInput)
	}
	if s.InitError != nil {
		return Result{}, s.InitError
	}

	state, loadErr := s.Repository.Load(ctx, command.EndpointID)
	if loadErr != nil && !errors.Is(loadErr, ErrNotFound) {
		return Result{}, loadErr
	}
	if errors.Is(loadErr, ErrNotFound) {
		if command.Kind != CommandCreate && command.Type != CommandCreate {
			return Result{}, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
		}
		state = State{}
	}
	replayCandidate := false
	registryIndependent := commandKind(command) == CommandComplete || commandKind(command) == CommandResolve
	if state.Version > 0 {
		_, replayCandidate = state.ProcessedCommands[commandID(command)]
		if !replayCandidate && !registryIndependent {
			if descriptor, descriptorErr := s.descriptor(ctx, state.AdapterKey); descriptorErr != nil {
				return Result{}, descriptorErr
			} else if descriptor != nil {
				state.AllowedAdapters = map[adapterapi.AdapterKey]struct{}{state.AdapterKey: {}}
			}
		}
		if command.AdapterKey == "" {
			command.AdapterKey = state.AdapterKey
		}
	}
	if !replayCandidate && !registryIndependent {
		if err := s.validateCommand(ctx, &command); err != nil {
			return Result{}, err
		}
	}
	decision, decideErr := Decide(state, command)
	if decideErr != nil {
		return Result{}, mapServiceError(decideErr)
	}
	decision.PrincipalID = command.PrincipalID
	decision.RequestID = command.RequestID
	decision.IdempotencyScope = command.IdempotencyScope
	decision.IdempotencyKey = command.IdempotencyKey
	decision.RequestDigest = append([]byte(nil), command.RequestDigest...)
	if replayCandidate {
		result := Result{State: state, Replay: true, Commit: eventstore.CommitResult{Idempotent: true, Deduplicated: true}}
		if state.OperationState == OperationStatePending || state.OperationState == OperationStateAmbiguous || state.OperationState == OperationStateFailed {
			result.Effects = pendingLifecycleEffect(state)
		}
		operationID := operationForCommand(command)
		if registryIndependent && state.OperationID != "" {
			operationID = state.OperationID
		}
		operation, operationErr := s.operation(ctx, operationID)
		if operationErr != nil {
			return Result{}, mapOperationError(operationErr)
		}
		result.Operation = operation
		return result, nil
	}
	var commit eventstore.CommitResult
	var commitErr error
	if len(secretInputs) > 0 {
		commit, commitErr = s.Repository.CommitWithSecrets(ctx, state, decision, secretInputs)
	} else {
		commit, commitErr = s.Repository.Commit(ctx, state, decision)
	}
	if commitErr != nil {
		return Result{}, mapCommitError(commitErr)
	}
	next, nextErr := ApplyDecision(state, decision)
	if nextErr != nil {
		return Result{}, nextErr
	}
	result := Result{State: next, Commit: commit, Effects: append([]LifecycleEffect(nil), decision.Effects...)}
	operation, operationErr := s.operation(ctx, next.OperationID)
	if operationErr != nil {
		return Result{}, mapOperationError(operationErr)
	}
	result.Operation = operation
	return result, nil
}
func secretDigest(input *SecretInput) string {
	if input == nil {
		return ""
	}
	sum := sha256.Sum256(append(append([]byte(input.Ref+"|"), byte(input.Version>>56), byte(input.Version>>48), byte(input.Version>>40), byte(input.Version>>32), byte(input.Version>>24), byte(input.Version>>16), byte(input.Version>>8), byte(input.Version)), input.Plaintext...))
	return hex.EncodeToString(sum[:])
}
func secretInputsDigest(inputs []SecretInput) string {
	if len(inputs) == 0 {
		return ""
	}
	if len(inputs) == 1 {
		return secretDigest(&inputs[0])
	}
	sum := sha256.New()
	for _, input := range inputs {
		var version [8]byte
		binary.BigEndian.PutUint64(version[:], input.Version)
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(input.Ref)))
		_, _ = sum.Write(length[:])
		_, _ = sum.Write([]byte(input.Ref))
		_, _ = sum.Write(version[:])
		_, _ = sum.Write(input.Plaintext)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func zeroSecretInputs(inputs []SecretInput) {
	for index := range inputs {
		zeroSecretInput(&inputs[index])
	}
}
func zeroSecretInput(input *SecretInput) {
	if input == nil {
		return
	}
	for index := range input.Plaintext {
		input.Plaintext[index] = 0
	}
}

func pendingLifecycleEffect(state State) []LifecycleEffect {
	kind := state.PendingEffectKind
	effectID := state.PendingEffectID
	commandID := state.PendingCommandID
	if kind == "" {
		kind = EffectStart
		if state.DesiredState == DesiredStateDisabled || state.DesiredState == DesiredStateRemoving {
			kind = EffectStop
		}
	}
	if effectID == "" {
		effectID = "replay:" + state.OperationID
	}
	if commandID == "" {
		commandID = state.CorrelationID
	}
	if !kind.Valid() || (state.DesiredState != DesiredStateEnabled && state.DesiredState != DesiredStateDisabled && state.DesiredState != DesiredStateRemoving) {
		return nil
	}
	return []LifecycleEffect{{ID: effectID, EffectID: effectID, Kind: kind, EndpointID: state.EndpointID, Generation: state.Generation, DesiredVersion: state.DesiredVersion, DesiredState: state.DesiredState, OperationID: state.OperationID, CorrelationID: state.CorrelationID, CommandID: commandID}}
}

func sameSecretRefs(left, right []adapterapi.SecretRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (s *Service) ExecuteCommand(ctx context.Context, command Command) (Result, error) {
	return s.Execute(ctx, command)
}

func operationForCommand(command Command) string {
	if command.OperationID != "" {
		return command.OperationID
	}
	if command.CommandID != "" {
		return operationID("", command.CommandID)
	}
	return operationID("", command.ID)
}
func (s *Service) operation(ctx context.Context, id string) (eventstore.OperationView, error) {
	if repository, ok := s.Store.(eventstore.OperationRepository); ok {
		view, err := repository.GetOperation(ctx, id)
		if err != nil {
			return eventstore.OperationView{}, err
		}
		return view, nil
	}
	return eventstore.OperationView{OperationID: id}, nil
}

func mapServiceError(err error) error {
	var rejected *RejectError
	if errors.As(err, &rejected) {
		switch rejected.Code {
		case RejectStaleVersion, RejectCommandConflict:
			return &ServiceError{Kind: "conflict", Cause: err}
		case RejectUnknownAdapter:
			return &ServiceError{Kind: "unknown_adapter", Cause: err}
		case RejectInvalidConfig:
			return &ServiceError{Kind: "invalid_config", Cause: err}
		default:
			return &ServiceError{Kind: "invalid", Cause: err}
		}
	}
	return err
}
func mapCommitError(err error) error {
	if errors.Is(err, eventstore.ErrConflict) || errors.Is(err, eventstore.ErrParticipantConflict) {
		return &ServiceError{Kind: "conflict", Cause: err}
	}
	if errors.Is(err, eventstore.ErrInvalidMetadata) || errors.Is(err, eventstore.ErrInvalidEvent) {
		return &ServiceError{Kind: "invalid", Cause: err}
	}
	return err
}

func mapOperationError(err error) error {
	if errors.Is(err, eventstore.ErrNotFound) {
		return &ServiceError{Kind: "not_found", Cause: err}
	}
	if errors.Is(err, eventstore.ErrParticipantConflict) || errors.Is(err, eventstore.ErrConflict) {
		return &ServiceError{Kind: "conflict", Cause: err}
	}
	return err
}
func (s *Service) Create(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandCreate
	command.Type = CommandCreate
	return s.Execute(ctx, command)
}
func (s *Service) UpdateConfig(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandUpdateConfig
	command.Type = CommandUpdateConfig
	return s.Execute(ctx, command)
}
func (s *Service) Enable(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandEnable
	command.Type = CommandEnable
	return s.Execute(ctx, command)
}
func (s *Service) Disable(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandDisable
	command.Type = CommandDisable
	return s.Execute(ctx, command)
}
func (s *Service) Relogin(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandRelogin
	command.Type = CommandRelogin
	return s.Execute(ctx, command)
}
func (s *Service) Remove(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandRemove
	command.Type = CommandRemove
	return s.Execute(ctx, command)
}
func (s *Service) Resolve(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandResolve
	command.Type = CommandResolve
	return s.Execute(ctx, command)
}
func (s *Service) Complete(ctx context.Context, command Command) (Result, error) {
	command.Kind = CommandComplete
	command.Type = CommandComplete
	return s.Execute(ctx, command)
}

func (s *Service) Get(ctx context.Context, id adapterapi.EndpointID) (EndpointView, error) {
	if s == nil || s.Store == nil || !id.Valid() {
		return EndpointView{}, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
	}
	if reader, ok := s.Store.(interface {
		ReadProjectionRow(context.Context, string, string) (eventstore.ProjectionRow, error)
	}); ok {
		row, err := reader.ReadProjectionRow(ctx, EndpointProjectionName, string(id))
		if err == nil {
			var view EndpointView
			if decodeErr := json.Unmarshal(row.Payload, &view); decodeErr != nil {
				return EndpointView{}, decodeErr
			}
			return view, nil
		}
		if !errors.Is(err, eventstore.ErrNotFound) {
			return EndpointView{}, err
		}
	}
	state, err := s.Repository.Load(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return EndpointView{}, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
		}
		return EndpointView{}, err
	}
	return endpointViewFromState(state), nil
}

func (s *Service) List(ctx context.Context) ([]EndpointView, error) {
	if s == nil || s.Store == nil {
		return nil, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
	}
	reader, ok := s.Store.(interface {
		ListProjectionRows(context.Context, string) ([]eventstore.ProjectionRow, error)
	})
	if !ok {
		return nil, errors.New("endpoint: store does not expose endpoint projection listing")
	}
	rows, err := reader.ListProjectionRows(ctx, EndpointProjectionName)
	if err != nil {
		return nil, err
	}
	views := make([]EndpointView, 0, len(rows))
	for _, row := range rows {
		var view EndpointView
		if err := json.Unmarshal(row.Payload, &view); err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

func endpointViewFromState(state State) EndpointView {
	return EndpointView{EndpointID: state.EndpointID, AdapterKey: state.AdapterKey, Config: state.Config.Clone(), DesiredState: state.DesiredState, ObservedState: state.ObservedState, OperationState: state.OperationState, DesiredVersion: state.DesiredVersion, Generation: state.Generation, OperationID: state.OperationID, CorrelationID: state.CorrelationID, Version: state.Version}
}

func (s *Service) GetOperation(ctx context.Context, id string) (eventstore.OperationView, error) {
	if s == nil || s.Store == nil {
		return eventstore.OperationView{}, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
	}
	if repository, ok := s.Store.(eventstore.OperationRepository); ok {
		view, err := repository.GetOperation(ctx, strings.TrimSpace(id))
		if errors.Is(err, eventstore.ErrNotFound) {
			return view, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
		}
		return view, err
	}
	return eventstore.OperationView{}, &ServiceError{Kind: "not_found", Cause: ErrNotFound}
}
