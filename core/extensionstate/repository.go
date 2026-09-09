package extensionstate

import (
	"context"
	"errors"

	"Scardice-core/eventstore"
)

var ErrRepositoryUnavailable = errors.New("extensionstate: repository unavailable")

type Repository struct {
	Store   eventstore.Store
	Factory eventstore.EventFactory
}
type ExtensionRepository = Repository

func NewRepository(store eventstore.Store) *Repository {
	return &Repository{Store: store, Factory: eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}}
}
func NewRepositoryWithFactory(store eventstore.Store, factory eventstore.EventFactory) *Repository {
	return &Repository{Store: store, Factory: factory}
}
func ExtensionStream(diceID string) eventstore.StreamID {
	if validateIdentity(diceID) != nil {
		return eventstore.StreamID{AggregateType: ExtensionAggregateType}
	}
	return eventstore.StreamID{AggregateType: ExtensionAggregateType, AggregateID: diceID}
}
func Stream(diceID string) eventstore.StreamID { return ExtensionStream(diceID) }

func (r *Repository) Load(ctx context.Context, diceID string) (State, error) {
	if r == nil || r.Store == nil {
		return State{}, ErrRepositoryUnavailable
	}
	if err := validateIdentity(diceID); err != nil {
		return State{}, err
	}
	events, err := r.Store.Load(ctx, ExtensionStream(diceID), 1)
	if err != nil {
		return State{}, err
	}
	if len(events) == 0 {
		return State{}, nil
	}
	return ReplayEnvelopes(events)
}
func (r *Repository) LoadExtensionState(ctx context.Context, diceID string) (State, error) {
	return r.Load(ctx, diceID)
}
func (r *Repository) AppendExtensionStateTyped(ctx context.Context, diceID string, expectedVersion uint64, metadata eventstore.Metadata, events []TypedEvent) (eventstore.CommitResult, error) {
	return r.AppendTyped(ctx, diceID, expectedVersion, metadata, events)
}
func (r *Repository) Append(ctx context.Context, diceID string, expectedVersion uint64, events []eventstore.NewEvent) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
	if err := validateIdentity(diceID); err != nil {
		return eventstore.CommitResult{}, err
	}
	if len(events) == 0 {
		return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork
	}
	stream := ExtensionStream(diceID)
	if err := r.validateAppend(ctx, stream, expectedVersion, events); err != nil {
		return eventstore.CommitResult{}, err
	}
	return r.Store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: stream, ExpectedVersion: expectedVersion, Events: append([]eventstore.NewEvent(nil), events...)}}})
}
func (r *Repository) validateAppend(ctx context.Context, stream eventstore.StreamID, expected uint64, events []eventstore.NewEvent) error {
	persisted, err := r.Store.Load(ctx, stream, 1)
	if err != nil {
		return err
	}
	state := State{}
	if len(persisted) > 0 {
		state, err = ReplayEnvelopes(persisted)
		if err != nil {
			return err
		}
	}
	if state.Version != expected {
		return eventstore.ErrConflict
	}
	seen := map[string]bool{}
	for _, event := range events {
		if !eventMetadataValid(event.Metadata) {
			return eventstore.ErrInvalidMetadata
		}
		if seen[event.Metadata.EventID] {
			return eventstore.ErrConflict
		}
		seen[event.Metadata.EventID] = true
		if event.SchemaVersion != ExtensionEventSchemaVersion {
			return ErrInvalidEvent
		}
		if len(event.Payload) > MaxExtensionEventPayloadBytes {
			return &eventstore.OversizeError{Bound: "extensionstate event payload", Limit: MaxExtensionEventPayloadBytes, Actual: len(event.Payload)}
		}
		envelope := eventstore.Envelope{Stream: stream, StreamVersion: state.Version + 1, EventType: event.EventType, SchemaVersion: event.SchemaVersion, Payload: event.Payload}
		state, err = ApplyEnvelope(state, envelope)
		if err != nil {
			return err
		}
	}
	return ValidateState(state)
}
func eventMetadataValid(metadata eventstore.Metadata) bool {
	return metadata.EventID != "" && metadata.CommandID != "" && metadata.CorrelationID != "" && (!metadata.OccurredAt.IsZero() || metadata.OccurredAtUnixNanoSet || metadata.OccurredAtUnixNanoUTC != 0) && (!(!metadata.OccurredAt.IsZero() && (metadata.OccurredAtUnixNanoSet || metadata.OccurredAtUnixNanoUTC != 0)) || metadata.OccurredAt.UTC().UnixNano() == metadata.OccurredAtUnixNanoUTC)
}
func (r *Repository) AppendTyped(ctx context.Context, diceID string, expectedVersion uint64, metadata eventstore.Metadata, events []TypedEvent) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
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
	encoded := make([]eventstore.NewEvent, 0, len(events))
	seen := map[string]bool{}
	explicit := map[string]bool{}
	for _, event := range events {
		itemMetadata := metadata
		if itemMetadata.EventID != "" {
			if explicit[itemMetadata.EventID] {
				return eventstore.CommitResult{}, eventstore.ErrConflict
			}
			explicit[itemMetadata.EventID] = true
		}
		item, err := NewEventWithFactory(factory, event, itemMetadata)
		if err != nil {
			return eventstore.CommitResult{}, err
		}
		if seen[item.Metadata.EventID] {
			return eventstore.CommitResult{}, eventstore.ErrConflict
		}
		seen[item.Metadata.EventID] = true
		encoded = append(encoded, item)
		metadata.EventID = ""
	}
	return r.Append(ctx, diceID, expectedVersion, encoded)
}
func (r *Repository) DecideAndAppend(ctx context.Context, state State, expectedVersion uint64, metadata eventstore.Metadata, command Command) (eventstore.CommitResult, error) {
	if state.Version != expectedVersion {
		return eventstore.CommitResult{}, eventstore.ErrConflict
	}
	decision, err := Decide(state, command)
	if err != nil {
		return eventstore.CommitResult{}, err
	}
	if len(decision.Events) == 0 {
		return eventstore.CommitResult{Idempotent: true}, nil
	}
	diceID := state.DiceID
	if command.Kind == CommandDiscover || command.Type == CommandDiscover || command.Kind == CommandImportBaseline || command.Type == CommandImportBaseline {
		diceID = command.DiceID
	}
	if err := validateIdentity(diceID); err != nil {
		return eventstore.CommitResult{}, ErrInvalidCommand
	}
	return r.AppendTyped(ctx, diceID, expectedVersion, metadata, decision.Events)
}
func NewEvent(event TypedEvent, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	if !eventMetadataValid(metadata) {
		return eventstore.NewEvent{}, eventstore.ErrInvalidMetadata
	}
	payload, err := MarshalEvent(event)
	if err != nil {
		return eventstore.NewEvent{}, err
	}
	return eventstore.NewEvent{EventType: string(event.EventType()), SchemaVersion: ExtensionEventSchemaVersion, Payload: payload, Metadata: metadata}, nil
}
func NewEventWithFactory(factory eventstore.EventFactory, event TypedEvent, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	payload, err := MarshalEvent(event)
	if err != nil {
		return eventstore.NewEvent{}, err
	}
	return factory.NewEvent(string(event.EventType()), ExtensionEventSchemaVersion, payload, metadata)
}
