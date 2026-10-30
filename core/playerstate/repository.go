package playerstate

import (
	"context"

	"Scardice-core/eventstore"
)

type Repository struct {
	Store   eventstore.Store
	Factory eventstore.EventFactory
}

func NewRepository(store eventstore.Store) *Repository {
	return &Repository{Store: store, Factory: eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}}
}
func NewRepositoryWithFactory(store eventstore.Store, factory eventstore.EventFactory) *Repository {
	return &Repository{Store: store, Factory: factory}
}

func (r *Repository) appendWithSecrets(ctx context.Context, stream eventstore.StreamID, expected uint64, events []eventstore.NewEvent, secretUpdates []eventstore.SecretUpdate) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
	if stream.AggregateID == "" {
		return eventstore.CommitResult{}, ErrInvalidIdentity
	}
	if len(events) == 0 {
		return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork
	}
	persisted, err := r.Store.Load(ctx, stream, 1)
	if err != nil {
		return eventstore.CommitResult{}, err
	}
	if uint64(len(persisted)) != expected {
		return eventstore.CommitResult{}, eventstore.ErrConflict
	}
	if err := validateAppendStream(stream, persisted, events); err != nil {
		return eventstore.CommitResult{}, err
	}
	seen := map[string]bool{}
	for _, event := range events {
		if event.SchemaVersion != EventSchemaVersion || event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "" {
			return eventstore.CommitResult{}, eventstore.ErrInvalidMetadata
		}
		if seen[event.Metadata.EventID] {
			return eventstore.CommitResult{}, eventstore.ErrConflict
		}
		seen[event.Metadata.EventID] = true
	}
	return r.Store.Commit(ctx, eventstore.UnitOfWork{
		Streams:       []eventstore.StreamAppend{{Stream: stream, ExpectedVersion: expected, Events: append([]eventstore.NewEvent(nil), events...)}},
		SecretUpdates: append([]eventstore.SecretUpdate(nil), secretUpdates...),
	})
}

func validateAppendStream(stream eventstore.StreamID, persisted []eventstore.Envelope, pending []eventstore.NewEvent) error {
	switch stream.AggregateType {
	case PlayerAggregateType:
		state := PlayerState{}
		for _, event := range persisted {
			var err error
			state, err = ApplyPlayerEnvelope(state, event, stream)
			if err != nil {
				return err
			}
		}
		for index, event := range pending {
			envelope := eventstore.Envelope{Stream: stream, StreamVersion: uint64(len(persisted) + index + 1), EventType: event.EventType, SchemaVersion: event.SchemaVersion, Payload: event.Payload}
			var err error
			state, err = ApplyPlayerEnvelope(state, envelope, stream)
			if err != nil {
				return err
			}
		}
	case GroupUserAttrsAggregateType:
		state := GroupUserAttrsState{}
		for _, event := range persisted {
			var err error
			state, err = ApplyGroupUserAttrsEnvelope(state, event, stream)
			if err != nil {
				return err
			}
		}
		for index, event := range pending {
			envelope := eventstore.Envelope{Stream: stream, StreamVersion: uint64(len(persisted) + index + 1), EventType: event.EventType, SchemaVersion: event.SchemaVersion, Payload: event.Payload}
			var err error
			state, err = ApplyGroupUserAttrsEnvelope(state, envelope, stream)
			if err != nil {
				return err
			}
		}
	case CharacterAggregateType:
		state := CharacterState{}
		for _, event := range persisted {
			var err error
			state, err = ApplyCharacterEnvelope(state, event, stream)
			if err != nil {
				return err
			}
		}
		for index, event := range pending {
			envelope := eventstore.Envelope{Stream: stream, StreamVersion: uint64(len(persisted) + index + 1), EventType: event.EventType, SchemaVersion: event.SchemaVersion, Payload: event.Payload}
			var err error
			state, err = ApplyCharacterEnvelope(state, envelope, stream)
			if err != nil {
				return err
			}
		}
	case ModerationAggregateType:
		state := ModerationState{}
		for _, event := range persisted {
			var err error
			state, err = ApplyModerationEnvelope(state, event, stream)
			if err != nil {
				return err
			}
		}
		for index, event := range pending {
			envelope := eventstore.Envelope{Stream: stream, StreamVersion: uint64(len(persisted) + index + 1), EventType: event.EventType, SchemaVersion: event.SchemaVersion, Payload: event.Payload}
			var err error
			state, err = ApplyModerationEnvelope(state, envelope, stream)
			if err != nil {
				return err
			}
		}
	default:
		return ErrInvalidIdentity
	}
	return nil
}

func (r *Repository) typed(ctx context.Context, stream eventstore.StreamID, expected uint64, metadata eventstore.Metadata, events []any) (eventstore.CommitResult, error) {
	return r.typedWithSecrets(ctx, stream, expected, metadata, events, nil)
}

func (r *Repository) typedWithSecrets(ctx context.Context, stream eventstore.StreamID, expected uint64, metadata eventstore.Metadata, events []any, secretUpdates []eventstore.SecretUpdate) (eventstore.CommitResult, error) {
	if len(events) == 0 {
		return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork
	}
	factory := r.Factory
	if factory.Clock == nil {
		factory.Clock = eventstore.SystemClock{}
	}
	if factory.IDs == nil {
		factory.IDs = eventstore.UUIDGenerator{}
	}
	out := make([]eventstore.NewEvent, 0, len(events))
	seen := map[string]bool{}
	for _, raw := range events {
		if isNilEvent(raw) {
			return eventstore.CommitResult{}, ErrInvalidEvent
		}
		var payload []byte
		var typ EventType
		var err error
		switch event := raw.(type) {
		case PlayerEvent:
			typ = event.EventType()
			payload, err = MarshalPlayerEvent(event)
		case GroupUserAttrsEvent:
			typ = event.EventType()
			payload, err = MarshalGroupUserAttrsEvent(event)
		case CharacterEvent:
			typ = event.EventType()
			payload, err = MarshalCharacterEvent(event)
		case ModerationEvent:
			typ = event.EventType()
			payload, err = MarshalModerationEvent(event)
		default:
			err = ErrInvalidEvent
		}
		if err != nil {
			return eventstore.CommitResult{}, err
		}
		item, err := factory.NewEvent(string(typ), EventSchemaVersion, payload, metadata)
		if err != nil {
			return eventstore.CommitResult{}, err
		}
		if seen[item.Metadata.EventID] {
			return eventstore.CommitResult{}, eventstore.ErrConflict
		}
		seen[item.Metadata.EventID] = true
		out = append(out, item)
		metadata.EventID = ""
	}
	return r.appendWithSecrets(ctx, stream, expected, out, secretUpdates)
}
func (r *Repository) AppendPlayerTyped(ctx context.Context, diceID, groupID, userID string, expected uint64, metadata eventstore.Metadata, events []PlayerEvent) (eventstore.CommitResult, error) {
	items := make([]any, len(events))
	for i, event := range events {
		items[i] = event
	}
	return r.typed(ctx, PlayerStream(diceID, groupID, userID), expected, metadata, items)
}
func (r *Repository) AppendGroupUserAttrsTyped(ctx context.Context, diceID, groupID, userID string, expected uint64, metadata eventstore.Metadata, events []GroupUserAttrsEvent) (eventstore.CommitResult, error) {
	items := make([]any, len(events))
	for i, event := range events {
		items[i] = event
	}
	return r.typed(ctx, GroupUserAttrsStream(diceID, groupID, userID), expected, metadata, items)
}
func (r *Repository) AppendCharacterTyped(ctx context.Context, diceID, userID, characterID string, expected uint64, metadata eventstore.Metadata, events []CharacterEvent) (eventstore.CommitResult, error) {
	items := make([]any, len(events))
	for i, event := range events {
		items[i] = event
	}
	return r.typed(ctx, CharacterStream(diceID, userID, characterID), expected, metadata, items)
}
func (r *Repository) AppendModerationTyped(ctx context.Context, diceID, groupID, subjectID string, expected uint64, metadata eventstore.Metadata, events []ModerationEvent) (eventstore.CommitResult, error) {
	items := make([]any, len(events))
	for i, event := range events {
		items[i] = event
	}
	return r.typed(ctx, ModerationStream(diceID, groupID, subjectID), expected, metadata, items)
}
func (r *Repository) AppendModerationTypedWithSecret(ctx context.Context, diceID, groupID, subjectID string, expected uint64, metadata eventstore.Metadata, events []ModerationEvent, request eventstore.SecretPutRequest) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
	preparer, ok := r.Store.(interface {
		PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
	})
	if !ok {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
	update, err := preparer.PrepareSecretUpdate(ctx, request)
	if err != nil {
		return eventstore.CommitResult{}, err
	}
	items := make([]any, len(events))
	for i, event := range events {
		items[i] = event
	}
	return r.typedWithSecrets(ctx, ModerationStream(diceID, groupID, subjectID), expected, metadata, items, []eventstore.SecretUpdate{update})
}
func (r *Repository) load(ctx context.Context, stream eventstore.StreamID) ([]eventstore.Envelope, error) {
	if r == nil || r.Store == nil {
		return nil, ErrRepositoryUnavailable
	}
	if stream.AggregateID == "" {
		return nil, ErrInvalidIdentity
	}
	return r.Store.Load(ctx, stream, 1)
}
func (r *Repository) LoadPlayer(ctx context.Context, diceID, groupID, userID string) (PlayerState, error) {
	stream := PlayerStream(diceID, groupID, userID)
	events, err := r.load(ctx, stream)
	if err != nil {
		return PlayerState{}, err
	}
	var state PlayerState
	for _, event := range events {
		state, err = ApplyPlayerEnvelope(state, event, stream)
		if err != nil {
			return PlayerState{}, err
		}
	}
	return state, nil
}
func (r *Repository) LoadGroupUserAttrs(ctx context.Context, diceID, groupID, userID string) (GroupUserAttrsState, error) {
	stream := GroupUserAttrsStream(diceID, groupID, userID)
	events, err := r.load(ctx, stream)
	if err != nil {
		return GroupUserAttrsState{}, err
	}
	var state GroupUserAttrsState
	for _, event := range events {
		state, err = ApplyGroupUserAttrsEnvelope(state, event, stream)
		if err != nil {
			return GroupUserAttrsState{}, err
		}
	}
	return state, nil
}
func (r *Repository) LoadCharacter(ctx context.Context, diceID, userID, characterID string) (CharacterState, error) {
	stream := CharacterStream(diceID, userID, characterID)
	events, err := r.load(ctx, stream)
	if err != nil {
		return CharacterState{}, err
	}
	var state CharacterState
	for _, event := range events {
		state, err = ApplyCharacterEnvelope(state, event, stream)
		if err != nil {
			return CharacterState{}, err
		}
	}
	return state, nil
}
func (r *Repository) LoadModeration(ctx context.Context, diceID, groupID, subjectID string) (ModerationState, error) {
	stream := ModerationStream(diceID, groupID, subjectID)
	events, err := r.load(ctx, stream)
	if err != nil {
		return ModerationState{}, err
	}
	var state ModerationState
	for _, event := range events {
		state, err = ApplyModerationEnvelope(state, event, stream)
		if err != nil {
			return ModerationState{}, err
		}
	}
	return state, nil
}

type Scope string

const (
	ScopePlayers    Scope = "players"
	ScopeAttrs      Scope = "attrs"
	ScopeCharacters Scope = "characters"
	ScopeModeration Scope = "moderation"
)

type DeletePlan struct {
	DiceID         string
	GroupID        string
	Scopes         []Scope
	Streams        []eventstore.StreamID
	StreamPrefixes []StreamPrefix
}

func PlanDelete(diceID, groupID string, scopes []Scope) (DeletePlan, error) {
	return planDelete(diceID, groupID, "", scopes)
}
func PlanDeleteForUser(diceID, groupID, userID string, scopes []Scope) (DeletePlan, error) {
	if !validParts(diceID, groupID, userID) {
		return DeletePlan{}, ErrInvalidIdentity
	}
	return planDelete(diceID, groupID, userID, scopes)
}
func planDelete(diceID, groupID, userID string, scopes []Scope) (DeletePlan, error) {
	if !validParts(diceID, groupID) {
		return DeletePlan{}, ErrInvalidIdentity
	}
	seen := make(map[Scope]bool)
	plan := DeletePlan{DiceID: diceID, GroupID: groupID}
	for _, scope := range scopes {
		if seen[scope] {
			continue
		}
		seen[scope] = true
		plan.Scopes = append(plan.Scopes, scope)
		switch scope {
		case ScopePlayers:
			plan.StreamPrefixes = append(plan.StreamPrefixes, PlayerStreamPrefix(diceID, groupID))
		case ScopeAttrs:
			plan.StreamPrefixes = append(plan.StreamPrefixes, GroupUserAttrsStreamPrefix(diceID, groupID))
		case ScopeCharacters:
			if userID == "" {
				return DeletePlan{}, ErrInvalidIdentity
			}
			plan.StreamPrefixes = append(plan.StreamPrefixes, CharacterStreamPrefix(diceID, userID))
		case ScopeModeration:
			plan.StreamPrefixes = append(plan.StreamPrefixes, ModerationStreamPrefix(diceID, groupID))
		default:
			return DeletePlan{}, ErrInvalidCommand
		}
	}
	return plan, nil
}
func CharacterStreamPrefix(diceID, userID string) StreamPrefix {
	return streamPrefix(CharacterAggregateType, diceID, userID)
}
func ModerationStreamPrefix(diceID, groupID string) StreamPrefix {
	return streamPrefix(ModerationAggregateType, diceID, groupID)
}
func (r *Repository) DecideAndAppendPlayer(ctx context.Context, state PlayerState, expected uint64, metadata eventstore.Metadata, command PlayerCommand) (eventstore.CommitResult, error) {
	decision, err := DecidePlayer(state, command)
	if err != nil {
		return eventstore.CommitResult{}, err
	}
	diceID, groupID, userID := state.DiceID, state.GroupID, state.UserID
	if command.Kind == CommandPlayerCreate {
		diceID, groupID, userID = command.DiceID, command.GroupID, command.UserID
	}
	return r.AppendPlayerTyped(ctx, diceID, groupID, userID, expected, metadata, decision.Events)
}
