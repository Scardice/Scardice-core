package groupstate

import (
	"context"
	"encoding/json"
	"errors"

	"Scardice-core/eventstore"
	"gorm.io/gorm"
)

const GroupProjectionName = "group-record"
const GroupProjectionVersion = "v1"

type projectionRow struct {
	ProjectionGeneration string `gorm:"column:projection_generation;primaryKey"`
	ProjectionName string `gorm:"column:projection_name;primaryKey"`
	RowKey string `gorm:"column:row_key;primaryKey"`
	Payload []byte `gorm:"column:payload"`
}
func (projectionRow) TableName() string { return "projection_read_models" }

func GroupProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: GroupProjectionName, Version: GroupProjectionVersion, Apply: applyGroupProjection}
}

func applyGroupProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, envelope := range events {
		if envelope.Stream.AggregateType != GroupAggregateType { continue }
		if envelope.SchemaVersion != GroupEventSchemaVersion { return ErrUnsupportedSchema }
		state := State{}
		var row projectionRow
		query := tx.WithContext(ctx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), GroupProjectionName, envelope.Stream.AggregateID).First(&row)
		if query.Error == nil {
			if err := json.Unmarshal(row.Payload, &state); err != nil { return ErrInvalidState }
		} else if !errors.Is(query.Error, gorm.ErrRecordNotFound) { return query.Error }
		state, err := ApplyEnvelope(state, envelope)
		if err != nil { return err }
		payload, err := json.Marshal(state.Clone()); if err != nil { return err }
		if err := eventstore.UpsertProjectionRow(tx, GroupProjectionName, envelope.Stream.AggregateID, payload); err != nil { return err }
	}
	return nil
}

type projectionReader interface { ReadProjectionRow(context.Context, string, string) (eventstore.ProjectionRow, error) }

// ReadProjected returns a value copy from the active immutable projection. It
// never returns a pointer to store-owned or cached mutable state.
func ReadProjected(ctx context.Context, store any, diceID, groupID string) (State, error) {
	if err := ValidateIdentity(diceID, groupID); err != nil { return State{}, err }
	reader, ok := store.(projectionReader); if !ok || reader == nil { return State{}, ErrRepositoryUnavailable }
	stream := GroupStream(diceID, groupID)
	row, err := reader.ReadProjectionRow(ctx, GroupProjectionName, stream.AggregateID)
	if err != nil { return State{}, err }
	var object map[string]json.RawMessage
	if err := json.Unmarshal(row.Payload, &object); err != nil || object == nil { return State{}, ErrInvalidState }
	var state State
	if err := json.Unmarshal(row.Payload, &state); err != nil { return State{}, ErrInvalidState }
	if err := ValidateState(state); err != nil { return State{}, err }
	if canonicalAggregateID(state.DiceID, state.GroupID) != stream.AggregateID { return State{}, ErrInvalidState }
	return state.Clone(), nil
}
