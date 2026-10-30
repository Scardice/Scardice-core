package extensionstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"Scardice-core/eventstore"

	"gorm.io/gorm"
)

const ExtensionProjectionName = "extension-state"
const ExtensionProjectionVersion = "v1"

type projectionRow struct {
	ProjectionGeneration string `gorm:"column:projection_generation;primaryKey"`
	ProjectionName       string `gorm:"column:projection_name;primaryKey"`
	RowKey               string `gorm:"column:row_key;primaryKey"`
	Payload              []byte `gorm:"column:payload"`
}

func (projectionRow) TableName() string { return "projection_read_models" }
func ExtensionProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: ExtensionProjectionName, Version: ExtensionProjectionVersion, Apply: applyExtensionProjection}
}
func Projection() eventstore.ProjectionDescriptor { return ExtensionProjection() }
func applyExtensionProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, envelope := range events {
		if envelope.Stream.AggregateType != ExtensionAggregateType {
			continue
		}
		if envelope.SchemaVersion != ExtensionEventSchemaVersion {
			return ErrInvalidEvent
		}
		state := State{}
		var row projectionRow
		query := tx.WithContext(ctx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), ExtensionProjectionName, envelope.Stream.AggregateID).First(&row)
		if query.Error == nil {
			var err error
			state, err = decodeProjectionState(row.Payload)
			if err != nil {
				return err
			}
			if ExtensionStream(state.DiceID).AggregateID != envelope.Stream.AggregateID {
				return ErrInvalidState
			}
		} else if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return query.Error
		}
		var err error
		state, err = ApplyEnvelope(state, envelope)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(state.Clone())
		if err != nil {
			return err
		}
		if err := eventstore.UpsertProjectionRow(tx, ExtensionProjectionName, envelope.Stream.AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}
func decodeProjectionState(payload []byte) (State, error) {
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return State{}, ErrInvalidState
	}
	if _, ok := raw.(map[string]any); !ok || containsNull(raw) {
		return State{}, ErrInvalidState
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, ErrInvalidState
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return State{}, ErrInvalidState
	}
	if state.Version == 0 || ValidateState(state) != nil {
		return State{}, ErrInvalidState
	}
	return state, nil
}

type projectionReader interface {
	ReadProjectionRow(ctx context.Context, projectionName, rowKey string) (eventstore.ProjectionRow, error)
}

func ReadProjected(ctx context.Context, store any, diceID string) (State, error) {
	if err := validateIdentity(diceID); err != nil {
		return State{}, err
	}
	reader, ok := store.(projectionReader)
	if !ok || reader == nil {
		return State{}, ErrRepositoryUnavailable
	}
	stream := ExtensionStream(diceID)
	row, err := reader.ReadProjectionRow(ctx, ExtensionProjectionName, stream.AggregateID)
	if err != nil {
		if !errors.Is(err, eventstore.ErrNotFound) {
			return State{}, err
		}
		eventStore, ok := store.(eventstore.Store)
		if !ok {
			return State{}, err
		}
		state, loadErr := NewRepository(eventStore).Load(ctx, diceID)
		if loadErr != nil {
			return State{}, loadErr
		}
		if state.Version == 0 {
			return state, nil
		}
		row, err = reader.ReadProjectionRow(ctx, ExtensionProjectionName, stream.AggregateID)
		if err != nil {
			return State{}, err
		}
	}
	state, err := decodeProjectionState(row.Payload)
	if err != nil {
		return State{}, err
	}
	if ExtensionStream(state.DiceID).AggregateID != stream.AggregateID {
		return State{}, ErrInvalidState
	}
	return state.Clone(), nil
}
