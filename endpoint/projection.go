package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
	"gorm.io/gorm"
)

const (
	EndpointProjectionName  = "endpoint"
	OperationProjectionName = "endpoint-operation"
	EndpointProjectionVersion = "v1"
)

// EndpointView is the public endpoint read model. It intentionally contains
// validated non-secret config and references only; runtime, private context,
// resolved credentials and artifacts have no representation here.
type EndpointView struct {
	EndpointID     adapterapi.EndpointID       `json:"endpointId"`
	AdapterKey     adapterapi.AdapterKey       `json:"adapterKey"`
	Config         adapterapi.ValidatedConfig  `json:"config"`
	DesiredState   DesiredState                `json:"desiredState"`
	ObservedState  adapterapi.ObservedState    `json:"observedState"`
	OperationState OperationState               `json:"operationState"`
	DesiredVersion uint64                      `json:"desiredVersion"`
	Generation     uint64                      `json:"generation"`
	OperationID    string                      `json:"operationId"`
	CorrelationID  string                      `json:"correlationId"`
	Version        uint64                      `json:"version"`
}
type EndpointProjection = EndpointView

// OperationProjection is a safe operation API view. It mirrors only durable
// operation metadata; private ciphertext and artifact contents are absent.
type OperationProjection struct {
	OperationID   string `json:"operationId"`
	EndpointID    adapterapi.EndpointID `json:"endpointId"`
	Kind          string `json:"kind"`
	Status        OperationState `json:"status"`
	ResultCode    string `json:"resultCode,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
	EffectID      string `json:"effectId,omitempty"`
	DesiredVersion uint64 `json:"desiredVersion"`
	Generation    uint64 `json:"generation"`
	Version       uint64 `json:"version"`
}

func EndpointProjectionDescriptor() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: EndpointProjectionName, Version: EndpointProjectionVersion, Apply: ApplyEndpointProjection}
}
func OperationProjectionDescriptor() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: OperationProjectionName, Version: EndpointProjectionVersion, Apply: ApplyOperationProjection}
}
func EndpointProjections() []eventstore.ProjectionDescriptor {
	return []eventstore.ProjectionDescriptor{EndpointProjectionDescriptor(), OperationProjectionDescriptor()}
}
func RegisterEndpointProjections(store *eventstore.GORMStore) error {
	if store == nil { return errors.New("endpoint: nil eventstore") }
	for _, descriptor := range EndpointProjections() {
		if err := store.RegisterProjection(descriptor); err != nil && !errors.Is(err, eventstore.ErrDuplicateProjector) { return err }
	}
	return nil
}

func decodeProjectionEvent(envelope eventstore.Envelope) (Event, error) {
	if envelope.Stream.AggregateType != EndpointAggregateType {
		return Event{}, fmt.Errorf("endpoint: projection stream mismatch: %w", ErrInvalidState)
	}
	streamEndpointID := adapterapi.EndpointID(envelope.Stream.AggregateID)
	eventType := EventType(envelope.EventType)
	if !streamEndpointID.Valid() || !eventType.Valid() || envelope.EventID == "" || envelope.StreamVersion == 0 || envelope.SchemaVersion != 1 {
		return Event{}, fmt.Errorf("endpoint: invalid projection envelope identity: %w", ErrInvalidState)
	}
	var event Event
	if err := json.Unmarshal(envelope.Payload, &event); err != nil { return Event{}, fmt.Errorf("endpoint: projection decode: %w", err) }
	if event.ID == "" || event.EventID == "" || event.Type == "" || event.Kind == "" || event.Sequence == 0 || event.AggregateVersion == 0 || event.EndpointID == "" {
		return Event{}, fmt.Errorf("endpoint: incomplete projection identity: %w", ErrInvalidState)
	}
	if event.ID != "" && event.ID != envelope.EventID || event.EventID != "" && event.EventID != envelope.EventID {
		return Event{}, fmt.Errorf("%w: projection event id mismatch", ErrInvalidState)
	}
	if event.Type != "" && string(event.Type) != envelope.EventType || event.Kind != "" && string(event.Kind) != envelope.EventType {
		return Event{}, fmt.Errorf("%w: projection event type mismatch", ErrInvalidState)
	}
	if event.Sequence != 0 && event.Sequence != envelope.StreamVersion || event.AggregateVersion != 0 && event.AggregateVersion != envelope.StreamVersion {
		return Event{}, fmt.Errorf("%w: projection event version mismatch", ErrInvalidState)
	}
	if event.ID == "" { event.ID = envelope.EventID }
	if event.EventID == "" { event.EventID = envelope.EventID }
	if event.EndpointID == "" { event.EndpointID = streamEndpointID }
	if event.Sequence == 0 || event.AggregateVersion == 0 || event.OperationID == "" || event.CorrelationID == "" || event.CommandID == "" || event.DesiredVersion == 0 || !event.DesiredState.Valid() || !event.ObservedState.Valid() || !event.OperationState.Valid() {
		return Event{}, fmt.Errorf("endpoint: incomplete projection event: %w", ErrInvalidState)
	}
	if event.EndpointID != streamEndpointID || !event.EndpointID.Valid() {
		return Event{}, fmt.Errorf("endpoint: projection endpoint mismatch: %w", ErrInvalidState)
	}
	if !event.ConfigSet { event.Config = adapterapi.ValidatedConfig{} }
	return event, nil
}

func ApplyEndpointProjection(_ context.Context, tx *gorm.DB, envelopes []eventstore.Envelope) error {
	for _, envelope := range envelopes {
		if envelope.Stream.AggregateType != EndpointAggregateType { continue }
		event, err := decodeProjectionEvent(envelope)
		if err != nil { return err }
		view := EndpointView{EndpointID: event.EndpointID, AdapterKey: event.AdapterKey, Config: event.Config.Clone(), DesiredState: event.DesiredState, ObservedState: event.ObservedState, OperationState: event.OperationState, DesiredVersion: event.DesiredVersion, Generation: event.Generation, OperationID: event.OperationID, CorrelationID: event.CorrelationID, Version: event.Sequence}
		if !event.ConfigSet {
			var previous EndpointView
			rowErr := readProjection(tx, EndpointProjectionName, string(event.EndpointID), &previous)
			if rowErr == nil {
				view.Config = previous.Config.Clone()
				if view.AdapterKey == "" { view.AdapterKey = previous.AdapterKey }
			} else if !errors.Is(rowErr, gorm.ErrRecordNotFound) {
				return rowErr
			}
		}
		payload, err := json.Marshal(view)
		if err != nil { return err }
		if err := eventstore.UpsertProjectionRow(tx, EndpointProjectionName, string(event.EndpointID), payload); err != nil { return err }
	}
	return nil
}
func ApplyOperationProjection(_ context.Context, tx *gorm.DB, envelopes []eventstore.Envelope) error {
	for _, envelope := range envelopes {
		if envelope.Stream.AggregateType != EndpointAggregateType { continue }
		event, err := decodeProjectionEvent(envelope)
		if err != nil { return err }
		status := event.OperationState
		if status == OperationStateIdle { status = OperationStateSucceeded }
		view := OperationProjection{OperationID: event.OperationID, EndpointID: event.EndpointID, Kind: string(event.Type), Status: status, EffectID: event.EffectID, DesiredVersion: event.DesiredVersion, Generation: event.Generation, Version: event.Sequence, ResultCode: string(event.Type)}
		payload, err := json.Marshal(view)
		if err != nil { return err }
		if err := eventstore.UpsertProjectionRow(tx, OperationProjectionName, event.OperationID, payload); err != nil { return err }
	}
	return nil
}

func readProjection(tx *gorm.DB, name, key string, target any) error {
	if tx == nil { return errors.New("endpoint: nil projection transaction") }
	row, err := tx.Raw("SELECT payload FROM projection_read_models WHERE projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), name, key).Rows()
	if err != nil { return err }
	defer row.Close()
	if !row.Next() { return gorm.ErrRecordNotFound }
	var payload []byte
	if err := row.Scan(&payload); err != nil { return err }
	return json.Unmarshal(payload, target)
}

// ProjectEndpoint is retained as a short callback name for store registration.
func ProjectEndpoint(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error { return ApplyEndpointProjection(ctx, tx, events) }
func ProjectOperation(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error { return ApplyOperationProjection(ctx, tx, events) }
