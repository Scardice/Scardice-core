package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

const EndpointAggregateType = "endpoint"

// Repository is the endpoint aggregate's event-store boundary. It deliberately
// deals in eventstore.Store only; projections and participants remain owned by
// the store transaction.
type BoundPayloadCodec interface {
	EncryptBound(ctx context.Context, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error)
}
type Repository struct {
	Store       eventstore.Store
	Clock       eventstore.Clock
	Producer    string
	EffectCodec BoundPayloadCodec
}

func NewRepository(store eventstore.Store, codecs ...BoundPayloadCodec) *Repository {
	repository := &Repository{Store: store, Clock: eventstore.SystemClock{}, Producer: "endpoint"}
	if len(codecs) > 0 {
		repository.EffectCodec = codecs[0]
	} else if provider, ok := store.(BoundPayloadCodec); ok {
		repository.EffectCodec = provider
	}
	return repository
}

func endpointStream(id adapterapi.EndpointID) eventstore.StreamID {
	return eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: string(id)}
}

// Load replays the complete stream. Loading starts at version zero because
// snapshots are intentionally deferred; the resulting State.Version is the
// optimistic version that must be supplied to Commit.
func (r *Repository) Load(ctx context.Context, id adapterapi.EndpointID) (State, error) {
	if r == nil || r.Store == nil || !id.Valid() {
		return State{}, ErrNotFound
	}
	envelopes, err := r.Store.Load(ctx, endpointStream(id), 0)
	if err != nil {
		if errors.Is(err, eventstore.ErrNotFound) {
			return State{}, ErrNotFound
		}
		return State{}, err
	}
	if len(envelopes) == 0 {
		return State{}, ErrNotFound
	}
	state := State{}
	for _, envelope := range envelopes {
		envelopeType := EventType(envelope.EventType)
		if !adapterapi.EndpointID(envelope.Stream.AggregateID).Valid() || envelope.EventID == "" || !envelopeType.Valid() || envelope.StreamVersion == 0 || envelope.SchemaVersion != 1 {
			return State{}, fmt.Errorf("%w: invalid persisted envelope identity", ErrInvalidState)
		}
		var event Event
		if err := json.Unmarshal(envelope.Payload, &event); err != nil {
			return State{}, fmt.Errorf("endpoint: decode event: %w", err)
		}
		if event.ID != "" && event.ID != envelope.EventID || event.EventID != "" && event.EventID != envelope.EventID {
			return State{}, fmt.Errorf("%w: persisted event id mismatch", ErrInvalidState)
		}
		if event.Type != "" && string(event.Type) != envelope.EventType || event.Kind != "" && string(event.Kind) != envelope.EventType {
			return State{}, fmt.Errorf("%w: persisted event type mismatch", ErrInvalidState)
		}
		if event.Sequence != 0 && event.Sequence != envelope.StreamVersion || event.AggregateVersion != 0 && event.AggregateVersion != envelope.StreamVersion {
			return State{}, fmt.Errorf("%w: persisted event version mismatch", ErrInvalidState)
		}
		if event.CommandID != "" && event.CommandID != envelope.Metadata.CommandID || event.CorrelationID != "" && event.CorrelationID != envelope.Metadata.CorrelationID {
			if !acceptsEarlyImporterEnvelopeMetadata(event, envelopeType, envelope) {
				return State{}, fmt.Errorf("%w: persisted event metadata mismatch", ErrInvalidState)
			}
		}
		if event.ID == "" {
			event.ID = envelope.EventID
		}
		if event.EventID == "" {
			event.EventID = envelope.EventID
		}
		if !event.ConfigSet {
			event.Config = adapterapi.ValidatedConfig{}
		}
		if event.Sequence == 0 {
			event.Sequence = envelope.StreamVersion
		}
		if event.AggregateVersion == 0 {
			event.AggregateVersion = envelope.StreamVersion
		}
		if event.Type == "" {
			event.Type = EventType(envelope.EventType)
		}
		if event.Kind == "" {
			event.Kind = event.Type
		}
		if event.CommandID == "" {
			event.CommandID = envelope.Metadata.CommandID
		}
		if event.CorrelationID == "" {
			event.CorrelationID = envelope.Metadata.CorrelationID
		}
		if err := validateLoadedEvent(event, envelope); err != nil {
			return State{}, err
		}
		state, err = Apply(state, event)
		if err != nil {
			return State{}, err
		}
	}
	return state, nil
}

func validateLoadedEvent(event Event, envelope eventstore.Envelope) error {
	if envelope.Stream.AggregateType != EndpointAggregateType || event.EndpointID != adapterapi.EndpointID(envelope.Stream.AggregateID) {
		return fmt.Errorf("endpoint: event stream mismatch: %w", ErrInvalidState)
	}
	return nil
}

func acceptsEarlyImporterEnvelopeMetadata(event Event, eventType EventType, envelope eventstore.Envelope) bool {
	if envelope.Metadata.Producer != "eventsourcing-importer" ||
		envelope.Metadata.CommandID != envelope.EventID+"-command" ||
		envelope.Metadata.CorrelationID != envelope.EventID+"-correlation" {
		return false
	}
	endpointID := string(event.EndpointID)
	var expectedCommandID string
	switch eventType {
	case EventEndpointCreated:
		expectedCommandID = "legacy-create-" + endpointID
	case EventDesiredEnabled:
		expectedCommandID = "legacy-enable-" + endpointID
	case EventOperationCompleted:
		expectedCommandID = "legacy-complete-" + endpointID
	default:
		return false
	}
	const correlationPrefix = "legacy-import-"
	return event.CommandID == expectedCommandID &&
		strings.HasPrefix(event.CorrelationID, correlationPrefix) &&
		len(event.CorrelationID) > len(correlationPrefix)
}

func validateDecisionEffects(decision Decision) error {
	seen := make(map[string]struct{}, len(decision.Effects))
	effects := make(map[string]LifecycleEffect, len(decision.Effects))
	for _, effect := range decision.Effects {
		if effect.ID == "" || effect.EffectID != effect.ID || !effect.Kind.Valid() || !effect.EndpointID.Valid() {
			return fmt.Errorf("%w: malformed decision effect", ErrInvalidState)
		}
		if _, ok := seen[effect.ID]; ok {
			return fmt.Errorf("%w: duplicate decision effect", ErrInvalidState)
		}
		seen[effect.ID] = struct{}{}
		effects[effect.ID] = effect
	}
	for _, event := range decision.Events {
		if event.EffectID == "" {
			if event.EffectKind != "" {
				return fmt.Errorf("%w: event effect mismatch", ErrInvalidState)
			}
			continue
		}
		effect, ok := effects[event.EffectID]
		if !ok || effect.Kind != event.EffectKind || effect.EndpointID != event.EndpointID || effect.Generation != event.Generation || effect.DesiredState != event.DesiredState || effect.DesiredVersion != event.DesiredVersion || effect.OperationID != event.OperationID || effect.CorrelationID != event.CorrelationID || effect.CommandID != event.CommandID {
			return fmt.Errorf("%w: event effect mismatch", ErrInvalidState)
		}
		delete(effects, event.EffectID)
	}
	if len(effects) != 0 {
		return fmt.Errorf("%w: unbound decision effect", ErrInvalidState)
	}
	return nil
}

// Commit persists the decision and its operation/effect metadata in one UoW.
// previous is the loaded state, so its version is always used as the stream
// expected version (never a caller-supplied or recomputed version).
func validateDecisionEvent(previous State, streamID adapterapi.EndpointID, event Event, index int) error {
	if event.EndpointID != streamID || !event.EndpointID.Valid() {
		return fmt.Errorf("%w: decision endpoint mismatch", ErrInvalidState)
	}
	if event.ID == "" || event.EventID == "" || event.ID != event.EventID {
		return fmt.Errorf("%w: decision event id mismatch", ErrInvalidState)
	}
	if event.Type == "" || event.Kind == "" || event.Type != event.Kind || !event.Type.Valid() {
		return fmt.Errorf("%w: decision event type mismatch", ErrInvalidState)
	}
	if event.Sequence == 0 || event.AggregateVersion == 0 || event.Sequence != event.AggregateVersion || event.Sequence != previous.Version+uint64(index)+1 {
		return fmt.Errorf("%w: decision event version mismatch", ErrInvalidState)
	}
	if event.CommandID == "" || event.CorrelationID == "" || event.OperationID == "" || event.CommandDigest == "" {
		return fmt.Errorf("%w: decision event metadata missing", ErrInvalidState)
	}
	expectedID := eventID(event.EndpointID, event.CommandID, event.CorrelationID, event.Sequence, event.Type)
	if event.ID != expectedID {
		return fmt.Errorf("%w: nondeterministic decision event id", ErrInvalidState)
	}
	return nil
}
func (r *Repository) Commit(ctx context.Context, previous State, decision Decision) (eventstore.CommitResult, error) {
	return r.commitWithSecrets(ctx, previous, decision, nil)
}

// CommitWithSecret encrypts one transient secret and adds its SecretUpdate to
// the same UnitOfWork as the endpoint event. It never stores or serializes the
// plaintext. A Store.Commit failure therefore rolls back both participants.
func (r *Repository) CommitWithSecret(ctx context.Context, previous State, decision Decision, input *SecretInput) (eventstore.CommitResult, error) {
	if input == nil {
		return r.commitWithSecrets(ctx, previous, decision, nil)
	}
	return r.commitWithSecrets(ctx, previous, decision, []SecretInput{*input})
}

// CommitWithSecrets atomically encrypts all transient secret updates together
// with the endpoint event. The caller owns the plaintext lifetime; this method
// scrubs every input before returning.
func (r *Repository) CommitWithSecrets(ctx context.Context, previous State, decision Decision, inputs []SecretInput) (eventstore.CommitResult, error) {
	return r.commitWithSecrets(ctx, previous, decision, inputs)
}

func (r *Repository) commitWithSecrets(ctx context.Context, previous State, decision Decision, inputs []SecretInput) (eventstore.CommitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for index := range inputs {
		defer zeroSecretInput(&inputs[index])
	}
	if r == nil || r.Store == nil {
		return eventstore.CommitResult{}, errors.New("endpoint: repository unavailable")
	}
	if err := validateDecisionEffects(decision); err != nil {
		return eventstore.CommitResult{}, err
	}
	if decision.Replay || len(decision.Events) == 0 {
		return eventstore.CommitResult{Idempotent: true, Deduplicated: true}, nil
	}
	clock := r.Clock
	if clock == nil {
		clock = eventstore.SystemClock{}
	}
	producer := r.Producer
	if producer == "" {
		producer = "endpoint"
	}
	streamID := previous.EndpointID
	if streamID == "" && len(decision.Events) > 0 {
		streamID = decision.Events[0].EndpointID
	}
	if !streamID.Valid() {
		return eventstore.CommitResult{}, fmt.Errorf("%w: invalid stream endpoint", ErrInvalidState)
	}
	if err := validateDecisionEffects(decision); err != nil {
		return eventstore.CommitResult{}, err
	}
	if _, err := ApplyDecision(previous, decision); err != nil {
		return eventstore.CommitResult{}, err
	}
	operationScope := decision.IdempotencyScope
	if operationScope == "" {
		operationScope = EndpointAggregateType
	}
	operationKey := decision.IdempotencyKey
	if operationKey == "" {
		operationKey = ""
	}
	operationDigest := append([]byte(nil), decision.RequestDigest...)
	appendEvents := make([]eventstore.NewEvent, 0, len(decision.Events))
	operations := make([]eventstore.OperationUpdate, 0, len(decision.Events))
	for index, event := range decision.Events {
		if err := validateDecisionEvent(previous, streamID, event, index); err != nil {
			return eventstore.CommitResult{}, err
		}
		payload, err := json.Marshal(event)
		if err != nil {
			return eventstore.CommitResult{}, err
		}
		occurred := clock.Now().UTC()
		newEvent, err := (eventstore.EventFactory{Clock: clock}).NewEvent(string(event.Type), 1, payload, eventstore.Metadata{
			EventID: event.ID, CommandID: event.CommandID, CorrelationID: event.CorrelationID,
			PrincipalID: decision.PrincipalID, Producer: producer, OccurredAt: occurred,
		})
		if err != nil {
			return eventstore.CommitResult{}, err
		}
		appendEvents = append(appendEvents, newEvent)
		if event.Type == EventEndpointIdentityObserved || event.Type == EventLegacyMetadataRestored {
			continue
		}
		status := string(event.OperationState)
		if status == string(OperationStateIdle) {
			status = "succeeded"
		}
		nextOperationVersion := uint64(1)
		expectedOperationVersion := uint64(0)
		if operationsRepo, ok := r.Store.(eventstore.OperationRepository); ok {
			view, lookupErr := operationsRepo.GetOperation(ctx, event.OperationID)
			if lookupErr == nil {
				if view.Version >= ^uint64(0)>>1 {
					return eventstore.CommitResult{}, eventstore.ErrVersionExhausted
				}
				expectedOperationVersion = view.Version
				nextOperationVersion = view.Version + 1
			} else if !errors.Is(lookupErr, eventstore.ErrNotFound) {
				return eventstore.CommitResult{}, lookupErr
			}
		}
		requestID := decision.RequestID
		if requestID == "" {
			requestID = event.CommandID
		}
		idempotencyKey := operationKey
		if idempotencyKey == "" {
			idempotencyKey = event.CommandID
		}
		requestDigest := operationDigest
		if len(requestDigest) == 0 {
			requestDigest = []byte(event.CommandDigest)
		}
		operations = append(operations, eventstore.OperationUpdate{
			OperationID: event.OperationID, ExpectedVersion: expectedOperationVersion, Version: nextOperationVersion,
			Kind: string(event.Type), Status: status, PrincipalID: decision.PrincipalID,
			ResourceID: string(event.EndpointID),
			RequestID:  requestID, CorrelationID: event.CorrelationID,
			IdempotencyScope: operationScope, IdempotencyKey: idempotencyKey,
			RequestDigest: requestDigest, ResultCode: string(event.Type),
			CreatedAt: occurred, UpdatedAt: occurred,
		})
	}
	// Lifecycle intent is durable in the endpoint events and recovered by
	// Supervisor reconciliation. The outbox is only for adapter outbound effects.
	work := eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: endpointStream(streamID), ExpectedVersion: previous.Version, Events: appendEvents}}, Operations: operations}
	for index := range inputs {
		input := &inputs[index]
		if input.Ref == "" || input.Version == 0 || len(input.Plaintext) == 0 || len(input.Plaintext) > eventstore.MaxSecretBytes {
			return eventstore.CommitResult{}, fmt.Errorf("%w: invalid transient secret input", ErrInvalidState)
		}
		if r.EffectCodec == nil {
			return eventstore.CommitResult{}, eventstore.ErrEncryptionUnavailable
		}
		matched := false
		adapterID := ""
		for _, event := range decision.Events {
			if adapterID == "" {
				adapterID = string(event.AdapterKey)
			}
			for _, ref := range event.Config.SecretRefs {
				if ref.Ref == input.Ref && ref.Version == input.Version {
					matched = true
				}
			}
		}
		if !matched || adapterID == "" {
			return eventstore.CommitResult{}, fmt.Errorf("%w: transient secret reference is not part of endpoint config", ErrInvalidState)
		}
		plaintext := append([]byte(nil), input.Plaintext...)
		ciphertext, nonce, keyID, err := r.EffectCodec.EncryptBound(ctx, "adapter-secret/v1", input.Ref, string(streamID)+"/"+adapterID, input.Version, plaintext)
		for clearIndex := range plaintext {
			plaintext[clearIndex] = 0
		}
		if err != nil {
			return eventstore.CommitResult{}, eventstore.ErrEncryptionUnavailable
		}
		work.SecretUpdates = append(work.SecretUpdates, eventstore.SecretUpdate{
			SecretRef: input.Ref, ExpectedVersion: input.ExpectedVersion,
			EndpointID: string(streamID), AdapterID: adapterID, SecretVersion: input.Version,
			Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID,
		})
	}
	return r.Store.Commit(ctx, work)
}
func (r *Repository) Save(ctx context.Context, previous State, decision Decision) (eventstore.CommitResult, error) {
	return r.Commit(ctx, previous, decision)
}
func (r *Repository) LoadEndpoint(ctx context.Context, id adapterapi.EndpointID) (State, error) {
	return r.Load(ctx, id)
}
func (r *Repository) CommitDecision(ctx context.Context, previous State, decision Decision) (eventstore.CommitResult, error) {
	return r.Commit(ctx, previous, decision)
}

// ApplyDecision is a convenience for callers that need the post-command state
// after a successful commit; it still performs the pure fold before returning.
func ApplyDecision(previous State, decision Decision) (State, error) {
	next := previous
	var err error
	for _, event := range decision.Events {
		next, err = Apply(next, event)
		if err != nil {
			return State{}, err
		}
	}
	return next, nil
}
