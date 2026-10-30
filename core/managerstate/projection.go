package managerstate

import (
	"context"
	"encoding/json"
	"errors"

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

func Projection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: ProjectionName, Version: ProjectionVersion, Apply: applyProjection}
}

func applyProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, envelope := range events {
		if envelope.Stream.AggregateType != AggregateType {
			continue
		}
		if envelope.Stream != Stream() || envelope.SchemaVersion != EventSchemaVersion ||
			(envelope.EventType != EventBaselineImported && envelope.EventType != EventSnapshotReplaced) {
			return ErrInvalidEvent
		}
		state := State{}
		var existing projectionRow
		query := tx.WithContext(ctx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), ProjectionName, AggregateID).First(&existing)
		if query.Error == nil {
			if err := json.Unmarshal(existing.Payload, &state); err != nil || ValidateState(state) != nil {
				return ErrInvalidState
			}
		} else if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return query.Error
		}
		if state.Version == 0 && (envelope.EventType != EventBaselineImported || envelope.StreamVersion != 1) ||
			state.Version != 0 && (envelope.EventType != EventSnapshotReplaced || envelope.StreamVersion != state.Version+1) {
			return ErrInvalidEvent
		}
		event, err := DecodeSnapshotV1(envelope.Payload)
		if err != nil {
			return err
		}
		state, err = Apply(state, event)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if err = eventstore.UpsertProjectionRow(tx, ProjectionName, AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}

type projectionReader interface {
	ReadProjectionRow(ctx context.Context, projectionName, rowKey string) (eventstore.ProjectionRow, error)
}

func ReadProjected(ctx context.Context, store any) (State, error) {
	reader, ok := store.(projectionReader)
	if !ok || reader == nil {
		return State{}, ErrRepositoryUnavailable
	}
	row, err := reader.ReadProjectionRow(ctx, ProjectionName, AggregateID)
	if err != nil {
		return State{}, err
	}
	var state State
	if err = json.Unmarshal(row.Payload, &state); err != nil || ValidateState(state) != nil {
		return State{}, ErrInvalidState
	}
	return state, nil
}
