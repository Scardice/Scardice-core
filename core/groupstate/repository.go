package groupstate

import (
	"context"
	"errors"
	"strings"

	"Scardice-core/eventstore"
)

var ErrRepositoryUnavailable = errors.New("groupstate: repository unavailable")

type Repository struct {
	Store eventstore.Store
	Factory eventstore.EventFactory
}
func NewRepository(store eventstore.Store) *Repository {
	return &Repository{Store: store, Factory: eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}}
}
func NewRepositoryWithFactory(store eventstore.Store, factory eventstore.EventFactory) *Repository {
	return &Repository{Store: store, Factory: factory}
}
type GroupRepository = Repository
func (r *Repository) Load(ctx context.Context, diceID, groupID string) (State, error) {
	if r == nil || r.Store == nil { return State{}, ErrRepositoryUnavailable }
	if err := ValidateIdentity(diceID, groupID); err != nil { return State{}, err }
	events, err := r.Store.Load(ctx, GroupStream(diceID, groupID), 1)
	if err != nil { return State{}, err }
	if len(events) == 0 { return State{}, nil }
	return ReplayEnvelopes(events)
}

func (r *Repository) Append(ctx context.Context, diceID, groupID string, expectedVersion uint64, events []eventstore.NewEvent) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil { return eventstore.CommitResult{}, ErrRepositoryUnavailable }
	if err := ValidateIdentity(diceID, groupID); err != nil { return eventstore.CommitResult{}, err }
	if len(events) == 0 { return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork }
	stream := GroupStream(diceID, groupID)
	if err := r.validateAppend(ctx, stream, expectedVersion, events); err != nil {
		return eventstore.CommitResult{}, err
	}
	return r.Store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: stream, ExpectedVersion: expectedVersion, Events: append([]eventstore.NewEvent(nil), events...)}}})
}

func (r *Repository) validateAppend(ctx context.Context, stream eventstore.StreamID, expectedVersion uint64, events []eventstore.NewEvent) error {
	persisted, err := r.Store.Load(ctx, stream, 1)
	if err != nil { return err }
	state := State{}
	if len(persisted) > 0 {
		state, err = ReplayEnvelopes(persisted)
		if err != nil { return err }
	}
	if state.Version != expectedVersion { return eventstore.ErrConflict }
	seenEventIDs := make(map[string]struct{}, len(events))
	for _, event := range events {
		if !eventMetadataValid(event.Metadata) { return eventstore.ErrInvalidMetadata }
		if _, duplicate := seenEventIDs[event.Metadata.EventID]; duplicate { return eventstore.ErrConflict }
		seenEventIDs[event.Metadata.EventID] = struct{}{}
		if event.SchemaVersion != GroupEventSchemaVersion {
			return ErrInvalidEvent
		}
		if len(event.Payload) > MaxGroupEventPayloadBytes {
			return &eventstore.OversizeError{Bound: "group event payload", Limit: MaxGroupEventPayloadBytes, Actual: len(event.Payload)}
		}
		typed, err := DecodeTypedEvent(EventType(event.EventType), event.Payload)
		if err != nil { return err }
		if state.Version == 0 && typed.EventType() != EventGroupCreated {
			return ErrInvalidState
		}
		if state.Version > 0 && typed.EventType() == EventGroupCreated {
			return ErrInvalidState
		}
		if created, ok := typed.(*GroupCreatedV1); ok && canonicalAggregateID(created.DiceID, created.GroupID) != stream.AggregateID {
			return ErrInvalidIdentity
		}
		state, err = Reduce(state, typed)
		if err != nil { return err }
	}
	return ValidateState(state)
}

func (r *Repository) AppendTyped(ctx context.Context, diceID, groupID string, expectedVersion uint64, metadata eventstore.Metadata, events []TypedEvent) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil { return eventstore.CommitResult{}, ErrRepositoryUnavailable }
	if len(events) == 0 { return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork }
	factory := r.Factory
	if factory.Clock == nil { factory.Clock = eventstore.SystemClock{} }
	if factory.IDs == nil { factory.IDs = eventstore.UUIDGenerator{} }
	encoded := make([]eventstore.NewEvent, 0, len(events))
	seen := make(map[string]struct{}, len(events))
	for _, event := range events {
		itemMetadata := metadata
		if itemMetadata.EventID != "" {
			if _, duplicate := seen[itemMetadata.EventID]; duplicate { itemMetadata.EventID = "" }
		}
		item, err := NewEventWithFactory(factory, event, itemMetadata)
		if err != nil { return eventstore.CommitResult{}, err }
		if _, duplicate := seen[item.Metadata.EventID]; duplicate { return eventstore.CommitResult{}, eventstore.ErrConflict }
		seen[item.Metadata.EventID] = struct{}{}
		encoded = append(encoded, item)
	}
	return r.Append(ctx, diceID, groupID, expectedVersion, encoded)
}

// DecideAndAppend is the one repository write seam for all group-record
// writers. Callers choose a typed Command; attrs and moderation use other
// repositories and cannot accidentally share this stream.
func (r *Repository) DecideAndAppend(ctx context.Context, state State, expectedVersion uint64, metadata eventstore.Metadata, command Command) (eventstore.CommitResult, error) {
	decision, err := Decide(state, command)
	if err != nil { return eventstore.CommitResult{}, err }
	diceID, groupID := state.DiceID, state.GroupID
	kind := command.Kind
	if kind == "" { kind = command.Type }
	if kind == CommandCreate {
		diceID, groupID = command.DiceID, command.GroupID
	}
	if ValidateIdentity(diceID, groupID) != nil { return eventstore.CommitResult{}, ErrInvalidCommand }
	return r.AppendTyped(ctx, diceID, groupID, expectedVersion, metadata, decision.Events)
}

// Scope matches the existing /group/local_data/delete contract. Group record,
// attrs, and moderation are never represented by one shared stream.
type Scope string
const (
	ScopeGroupRecord Scope = "group_record"
	ScopePlayers     Scope = "players"
	ScopeAttrs       Scope = "attrs"
)

var ScopeOrder = []Scope{ScopeGroupRecord, ScopePlayers, ScopeAttrs}

func NormalizeScopes(scopes []Scope) ([]Scope, error) {
	if len(scopes) == 0 { return []Scope{ScopeGroupRecord}, nil }
	seen := map[Scope]bool{}
	for _, scope := range scopes {
		scope = Scope(strings.TrimSpace(string(scope)))
		if scope != ScopeGroupRecord && scope != ScopePlayers && scope != ScopeAttrs { return nil, errors.New("groupstate: unsupported deletion scope") }
		seen[scope] = true
	}
	result := make([]Scope, 0, len(seen)); for _, scope := range ScopeOrder { if seen[scope] { result = append(result, scope) } }; return result, nil
}
func ScopeSelected(scopes []Scope, scope Scope) bool { for _, item := range scopes { if item == scope { return true } }; return false }

var ErrActiveGroup = errors.New("groupstate: active group requires allowActive")

type DeleteRequest struct {
	DiceID string
	GroupID string
	Scopes []Scope
	AllowActive bool
	DryRun bool
}
type StreamPrefix struct {
	AggregateType string
	Prefix string
}
type DeletePlan struct {
	DiceID string
	GroupID string
	Scopes []Scope
	AllowActive bool
	DryRun bool
	ActiveDiceIDs []string
	ExistingDiceIDs []string
	Streams []eventstore.StreamID
	StreamPrefixes []StreamPrefix
	IncludesAttrs bool
	IncludesPlayers bool
	IncludesModeration bool
}

func trueKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values)); for key, value := range values { if value { result = append(result, key) } }; sortStrings(result); return result
}
func sortStrings(values []string) { for i := 1; i < len(values); i++ { for j := i; j > 0 && values[j] < values[j-1]; j-- { values[j], values[j-1] = values[j-1], values[j] } } }

func PlanDelete(state State, request DeleteRequest) (DeletePlan, error) {
	scopes, err := NormalizeScopes(request.Scopes)
	if err != nil { return DeletePlan{}, err }
	if state.Version > 0 && ((request.DiceID != "" && request.DiceID != state.DiceID) || (request.GroupID != "" && request.GroupID != state.GroupID)) {
		return DeletePlan{}, ErrInvalidIdentity
	}
	plan := DeletePlan{
		DiceID: request.DiceID, GroupID: request.GroupID, Scopes: scopes,
		AllowActive: request.AllowActive, DryRun: request.DryRun,
		ActiveDiceIDs: trueKeys(state.DiceIDActive), ExistingDiceIDs: trueKeys(state.DiceIDExists),
	}
	if plan.DiceID == "" { plan.DiceID = state.DiceID }
	if plan.GroupID == "" { plan.GroupID = state.GroupID }
	if err := ValidateIdentity(plan.DiceID, plan.GroupID); err != nil { return DeletePlan{}, err }
	if (state.Active || len(plan.ActiveDiceIDs) > 0) && !request.AllowActive { return plan, ErrActiveGroup }
	for _, scope := range scopes {
		switch scope {
		case ScopeGroupRecord:
			plan.Streams = append(plan.Streams, GroupStream(plan.DiceID, plan.GroupID))
		case ScopeAttrs:
			plan.Streams = append(plan.Streams, AttrsStream(plan.DiceID, plan.GroupID))
			plan.StreamPrefixes = append(plan.StreamPrefixes, GroupUserAttrsStreamPrefix(plan.DiceID, plan.GroupID))
			plan.IncludesAttrs = true
		case ScopePlayers:
			plan.StreamPrefixes = append(plan.StreamPrefixes, PlayerStreamPrefix(plan.DiceID, plan.GroupID))
			plan.IncludesPlayers = true
		}
	}
	return plan, nil
}
func PlayerStream(diceID, groupID, userID string) eventstore.StreamID {
	return boundedStream("player", diceID, groupID, userID)
}
func boundedPrefix(aggregateType string, parts ...string) StreamPrefix {
	if validateCanonicalParts(parts...) != nil { return StreamPrefix{AggregateType: aggregateType} }
	return StreamPrefix{AggregateType: aggregateType, Prefix: canonicalAggregateParts(parts...)}
}
func PlayerStreamPrefix(diceID, groupID string) StreamPrefix {
	return boundedPrefix("player", diceID, groupID)
}
func GroupUserAttrsStreamPrefix(diceID, groupID string) StreamPrefix {
	return boundedPrefix("attrs/group-user", diceID, groupID)
}
func AttrsStream(diceID, groupID string) eventstore.StreamID {
	return boundedStream("attrs/group", diceID, groupID)
}
func GroupUserAttrsStream(diceID, groupID, userID string) eventstore.StreamID {
	return boundedStream("attrs/group-user", diceID, groupID, userID)
}
func ModerationStream(diceID, groupID string) eventstore.StreamID {
	return boundedStream("moderation/group", diceID, groupID)
}
