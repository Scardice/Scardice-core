package configstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"Scardice-core/eventstore"
	"gorm.io/gorm"
)

type projectionRow struct {
	ProjectionGeneration string `gorm:"column:projection_generation;primaryKey"`
	ProjectionName       string `gorm:"column:projection_name;primaryKey"`
	RowKey               string `gorm:"column:row_key;primaryKey"`
	Payload              []byte `gorm:"column:payload"`
}

func (projectionRow) TableName() string { return "projection_read_models" }
func ConfigProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: ConfigProjectionName, Version: ConfigProjectionVersion, Apply: applyConfigProjection}
}
func applyConfigProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	state := State{}
	for _, e := range events {
		if e.Stream.AggregateType != ConfigAggregateType {
			continue
		}
		if e.SchemaVersion != ConfigEventSchemaVersion {
			return ErrUnsupportedSchema
		}
		var row projectionRow
		q := tx.WithContext(ctx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), ConfigProjectionName, e.Stream.AggregateID).First(&row)
		if q.Error == nil {
			var err error
			state, err = decodeProjectionState(row.Payload)
			if err != nil {
				return err
			}
		} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
			return q.Error
		}
		next, err := ApplyEnvelope(state, e)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(next.Clone())
		if err != nil {
			return err
		}
		if err := eventstore.UpsertProjectionRow(tx, ConfigProjectionName, e.Stream.AggregateID, payload); err != nil {
			return err
		}
		state = next
	}
	if err := ValidateState(state); err != nil {
		return err
	}
	return nil
}
func decodeProjectionState(payload []byte) (State, error) {
	var value any
	if json.Unmarshal(payload, &value) != nil {
		return State{}, ErrInvalidState
	}
	if _, ok := value.(map[string]any); !ok || containsJSONNull(value) {
		return State{}, ErrInvalidState
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var state State
	if err := dec.Decode(&state); err != nil {
		return State{}, ErrInvalidState
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return State{}, ErrInvalidState
	}
	if err := validateStateIdentity(state); err != nil {
		return State{}, err
	}
	return state, nil
}

type projectionReader interface {
	ReadProjectionRow(context.Context, string, string) (eventstore.ProjectionRow, error)
}

func ReadProjected(ctx context.Context, store any, diceID string) (State, error) {
	stream := ConfigStream(diceID)
	if stream.AggregateID == "" {
		return State{}, ErrInvalidIdentity
	}
	reader, ok := store.(projectionReader)
	if !ok || reader == nil {
		return State{}, ErrRepositoryUnavailable
	}
	row, err := reader.ReadProjectionRow(ctx, ConfigProjectionName, stream.AggregateID)
	if err != nil {
		return State{}, err
	}
	state, err := decodeProjectionState(row.Payload)
	if err != nil {
		return State{}, err
	}
	if err := ValidateState(state); err != nil {
		return State{}, err
	}
	if ConfigStream(state.DiceID) != stream {
		return State{}, ErrInvalidState
	}
	return state.Clone(), nil
}

var DiceConfigProjection = ConfigProjection

func ReadProjectedConfig(ctx context.Context, store any, diceID string) (State, error) {
	return ReadProjected(ctx, store, diceID)
}
