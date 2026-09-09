package configstate

import (
	"context"

	"Scardice-core/eventstore"
)

func validMetadata(m eventstore.Metadata) bool {
	if m.EventID == "" || m.CommandID == "" || m.CorrelationID == "" {
		return false
	}
	if m.OccurredAt.IsZero() && m.OccurredAtUnixNanoUTC == 0 && !m.OccurredAtUnixNanoSet {
		return false
	}
	if !m.OccurredAt.IsZero() && (m.OccurredAtUnixNanoSet || m.OccurredAtUnixNanoUTC != 0) && m.OccurredAt.UTC().UnixNano() != m.OccurredAtUnixNanoUTC {
		return false
	}
	return true
}

type Repository struct {
	Store   eventstore.Store
	Factory eventstore.EventFactory
}
type ConfigRepository = Repository

func NewRepository(store eventstore.Store) *Repository {
	return &Repository{Store: store, Factory: eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}}
}
func NewRepositoryWithFactory(store eventstore.Store, factory eventstore.EventFactory) *Repository {
	return &Repository{Store: store, Factory: factory}
}
func (r *Repository) Load(ctx context.Context, diceID string) (State, error) {
	if r == nil || r.Store == nil {
		return State{}, ErrRepositoryUnavailable
	}
	if !validID(diceID) {
		return State{}, ErrInvalidIdentity
	}
	stream := ConfigStream(diceID)
	if stream.AggregateID == "" {
		return State{}, ErrInvalidIdentity
	}
	events, err := r.Store.Load(ctx, stream, 1)
	if err != nil {
		return State{}, err
	}
	if len(events) == 0 {
		return State{}, nil
	}
	return ReplayEnvelopes(events)
}
func (r *Repository) Append(ctx context.Context, diceID string, expected uint64, events []eventstore.NewEvent) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
	if !validID(diceID) {
		return eventstore.CommitResult{}, ErrInvalidIdentity
	}
	stream := ConfigStream(diceID)
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
	state := State{}
	if len(persisted) > 0 {
		state, err = ReplayEnvelopes(persisted)
		if err != nil {
			return eventstore.CommitResult{}, err
		}
	}
	if state.Version != expected {
		return eventstore.CommitResult{}, eventstore.ErrConflict
	}
	for _, event := range events {
		if !validMetadata(event.Metadata) {
			return eventstore.CommitResult{}, eventstore.ErrInvalidMetadata
		}
		if event.SchemaVersion != ConfigEventSchemaVersion {
			return eventstore.CommitResult{}, ErrInvalidEvent
		}
		if len(event.Payload) > eventstore.MaxEventPayloadBytes {
			return eventstore.CommitResult{}, &eventstore.OversizeError{Bound: "config event payload", Limit: eventstore.MaxEventPayloadBytes, Actual: len(event.Payload)}
		}
		typed, decodeErr := DecodeTypedEvent(EventType(event.EventType), event.Payload)
		if decodeErr != nil {
			return eventstore.CommitResult{}, decodeErr
		}
		state, err = Reduce(state, typed)
		if err != nil {
			return eventstore.CommitResult{}, err
		}
	}
	if err := ValidateState(state); err != nil {
		return eventstore.CommitResult{}, err
	}
	return r.Store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: stream, ExpectedVersion: expected, Events: append([]eventstore.NewEvent(nil), events...)}}})
}
func (r *Repository) DecideAndAppend(ctx context.Context, state State, expected uint64, metadata eventstore.Metadata, command Command) (eventstore.CommitResult, error) {
	if state.Version != expected {
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
	if command.Kind == CommandImportBaseline || command.Type == CommandImportBaseline {
		if command.Baseline == nil {
			return eventstore.CommitResult{}, ErrInvalidCommand
		}
		diceID = command.Baseline.DiceID
	}
	return r.AppendTyped(ctx, diceID, expected, metadata, decision.Events)
}
func (r *Repository) AppendTyped(ctx context.Context, diceID string, expected uint64, metadata eventstore.Metadata, events []TypedEvent) (eventstore.CommitResult, error) {
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, ErrRepositoryUnavailable
	}
	if len(events) == 0 {
		return eventstore.CommitResult{}, eventstore.ErrEmptyUnitOfWork
	}
	if metadata.EventID != "" && !validMetadata(metadata) {
		return eventstore.CommitResult{}, eventstore.ErrInvalidMetadata
	}
	factory := r.Factory
	if factory.Clock == nil {
		factory.Clock = eventstore.SystemClock{}
	}
	if factory.IDs == nil {
		factory.IDs = eventstore.UUIDGenerator{}
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	seen := map[string]struct{}{}
	explicit := map[string]struct{}{}
	for _, event := range events {
		itemMetadata := metadata
		if itemMetadata.EventID != "" {
			if _, ok := explicit[itemMetadata.EventID]; ok {
				return eventstore.CommitResult{}, eventstore.ErrConflict
			}
			explicit[itemMetadata.EventID] = struct{}{}
		}
		item, err := NewEventWithFactory(factory, event, itemMetadata)
		if err != nil {
			return eventstore.CommitResult{}, err
		}
		if _, ok := seen[item.Metadata.EventID]; ok {
			return eventstore.CommitResult{}, eventstore.ErrConflict
		}
		seen[item.Metadata.EventID] = struct{}{}
		encoded = append(encoded, item)
		metadata.EventID = ""
	}
	return r.Append(ctx, diceID, expected, encoded)
}
func NewEvent(event TypedEvent, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	if event == nil {
		return eventstore.NewEvent{}, eventstore.ErrInvalidEvent
	}
	if !validMetadata(metadata) {
		return eventstore.NewEvent{}, eventstore.ErrInvalidMetadata
	}
	payload, err := MarshalTypedEvent(event)
	if err != nil {
		return eventstore.NewEvent{}, err
	}
	return eventstore.NewEvent{EventType: string(event.EventType()), SchemaVersion: ConfigEventSchemaVersion, Payload: payload, Metadata: metadata}, nil
}
func NewEventWithFactory(factory eventstore.EventFactory, event TypedEvent, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	if event == nil {
		return eventstore.NewEvent{}, eventstore.ErrInvalidEvent
	}
	payload, err := MarshalTypedEvent(event)
	if err != nil {
		return eventstore.NewEvent{}, err
	}
	return factory.NewEvent(string(event.EventType()), ConfigEventSchemaVersion, payload, metadata)
}
