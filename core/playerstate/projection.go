package playerstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"Scardice-core/eventstore"

	"gorm.io/gorm"
)

const (
	PlayerProjectionName            = "player"
	PlayerProjectionVersion         = "v1"
	GroupUserAttrsProjectionName    = "group-user-attrs"
	GroupUserAttrsProjectionVersion = "v1"
	CharacterProjectionName         = "character"
	CharacterProjectionVersion      = "v1"
	ModerationProjectionName        = "moderation"
	ModerationProjectionVersion     = "v1"
)

type projectionRow struct {
	ProjectionGeneration string `gorm:"column:projection_generation;primaryKey"`
	ProjectionName       string `gorm:"column:projection_name;primaryKey"`
	RowKey               string `gorm:"column:row_key;primaryKey"`
	Payload              []byte `gorm:"column:payload"`
}

func (projectionRow) TableName() string { return "projection_read_models" }

type projectionReader interface {
	ReadProjectionRow(ctx context.Context, projectionName, rowKey string) (eventstore.ProjectionRow, error)
}
type projectionFragmentLister interface {
	ListProjectionRowsByRowKeyFragments(ctx context.Context, projectionName string, fragments []string) ([]eventstore.ProjectionRow, error)
}

func PlayerProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: PlayerProjectionName, Version: PlayerProjectionVersion, Apply: applyPlayerProjection}
}
func GroupUserAttrsProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: GroupUserAttrsProjectionName, Version: GroupUserAttrsProjectionVersion, Apply: applyAttrsProjection}
}
func CharacterProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: CharacterProjectionName, Version: CharacterProjectionVersion, Apply: applyCharacterProjection}
}
func ModerationProjection() eventstore.ProjectionDescriptor {
	return eventstore.ProjectionDescriptor{Name: ModerationProjectionName, Version: ModerationProjectionVersion, Apply: applyModerationProjection}
}
func projectionState(tx *gorm.DB, ctx context.Context, name, rowKey string, payload []byte, out any) error {
	var row projectionRow
	q := tx.WithContext(ctx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), name, rowKey).First(&row)
	if q.Error == nil {
		if err := decodeProjection(row.Payload, out); err != nil {
			return err
		}
	} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return q.Error
	}
	return nil
}
func applyPlayerProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, e := range events {
		if e.Stream.AggregateType != PlayerAggregateType {
			continue
		}
		if e.SchemaVersion != EventSchemaVersion {
			return ErrUnsupportedSchema
		}
		state := PlayerState{}
		if err := projectionState(tx, ctx, PlayerProjectionName, e.Stream.AggregateID, e.Payload, &state); err != nil {
			return err
		}
		next, err := ApplyPlayerEnvelope(state, e, e.Stream)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(next.Clone())
		if err != nil {
			return err
		}
		if err := eventstore.UpsertProjectionRow(tx, PlayerProjectionName, e.Stream.AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}
func applyAttrsProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, e := range events {
		if e.Stream.AggregateType != GroupUserAttrsAggregateType {
			continue
		}
		if e.SchemaVersion != EventSchemaVersion {
			return ErrUnsupportedSchema
		}
		state := GroupUserAttrsState{}
		if err := projectionState(tx, ctx, GroupUserAttrsProjectionName, e.Stream.AggregateID, e.Payload, &state); err != nil {
			return err
		}
		next, err := ApplyGroupUserAttrsEnvelope(state, e, e.Stream)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(next.Clone())
		if err != nil {
			return err
		}
		if err := eventstore.UpsertProjectionRow(tx, GroupUserAttrsProjectionName, e.Stream.AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}
func applyCharacterProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, e := range events {
		if e.Stream.AggregateType != CharacterAggregateType {
			continue
		}
		if e.SchemaVersion != EventSchemaVersion {
			return ErrUnsupportedSchema
		}
		state := CharacterState{}
		if err := projectionState(tx, ctx, CharacterProjectionName, e.Stream.AggregateID, e.Payload, &state); err != nil {
			return err
		}
		next, err := ApplyCharacterEnvelope(state, e, e.Stream)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(next.Clone())
		if err != nil {
			return err
		}
		if err := eventstore.UpsertProjectionRow(tx, CharacterProjectionName, e.Stream.AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}
func applyModerationProjection(ctx context.Context, tx *gorm.DB, events []eventstore.Envelope) error {
	for _, e := range events {
		if e.Stream.AggregateType != ModerationAggregateType {
			continue
		}
		if e.SchemaVersion != EventSchemaVersion {
			return ErrUnsupportedSchema
		}
		state := ModerationState{}
		if err := projectionState(tx, ctx, ModerationProjectionName, e.Stream.AggregateID, e.Payload, &state); err != nil {
			return err
		}
		next, err := ApplyModerationEnvelope(state, e, e.Stream)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(next.Clone())
		if err != nil {
			return err
		}
		if err := eventstore.UpsertProjectionRow(tx, ModerationProjectionName, e.Stream.AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}
func decodeProjection(payload []byte, out any) error {
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return ErrInvalidState
	}
	if _, ok := value.(map[string]any); !ok || containsNull(value) {
		return ErrInvalidState
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return ErrInvalidState
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidState
	}
	return nil
}
func readProjected(ctx context.Context, store any, name string, stream eventstore.StreamID, out any) error {
	reader, ok := store.(projectionReader)
	if !ok || reader == nil {
		return ErrRepositoryUnavailable
	}
	row, err := reader.ReadProjectionRow(ctx, name, stream.AggregateID)
	if err != nil {
		return err
	}
	if err := decodeProjection(row.Payload, out); err != nil {
		return err
	}
	return nil
}
func ReadProjectedPlayer(ctx context.Context, store any, diceID, groupID, userID string) (PlayerState, error) {
	stream := PlayerStream(diceID, groupID, userID)
	var s PlayerState
	if stream.AggregateID == "" {
		return s, ErrInvalidIdentity
	}
	if err := readProjected(ctx, store, PlayerProjectionName, stream, &s); err != nil {
		return PlayerState{}, err
	}
	if s.Version == 0 || PlayerStream(s.DiceID, s.GroupID, s.UserID) != stream {
		return PlayerState{}, ErrInvalidState
	}
	return s.Clone(), nil
}

// CountProjectedGroupProfiles returns the number of distinct, non-deleted
// group/user profiles in the selected groups across all Dice owners.
func CountProjectedGroupProfiles(ctx context.Context, store any, groupIDs []string) (map[string]int64, error) {
	counts := make(map[string]int64, len(groupIDs))
	wanted := make(map[string]struct{}, len(groupIDs))
	for _, groupID := range groupIDs {
		if groupID == "" {
			return nil, ErrInvalidIdentity
		}
		counts[groupID] = 0
		wanted[groupID] = struct{}{}
	}
	if len(wanted) == 0 {
		return counts, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lister, ok := store.(projectionFragmentLister)
	if !ok || lister == nil {
		return nil, ErrRepositoryUnavailable
	}
	fragments := make([]string, 0, len(wanted))
	for groupID := range wanted {
		fragments = append(fragments, canonical(groupID))
	}
	// Group IDs are canonical length-prefixed segments. The reader narrows the
	// candidate set; validate the complete stream and group identity below.
	rows, err := lister.ListProjectionRowsByRowKeyFragments(ctx, PlayerProjectionName, fragments)
	if err != nil {
		return nil, err
	}

	usersByGroup := make(map[string]map[string]struct{}, len(wanted))
	for _, row := range rows {
		var state PlayerState
		if row.ProjectionName != PlayerProjectionName || decodeProjection(row.Payload, &state) != nil {
			return nil, ErrInvalidState
		}
		stream := PlayerStream(state.DiceID, state.GroupID, state.UserID)
		if state.Version == 0 || stream.AggregateID == "" || stream.AggregateID != row.RowKey {
			return nil, ErrInvalidState
		}
		if state.Deleted {
			continue
		}
		if _, wantedGroup := wanted[state.GroupID]; !wantedGroup {
			continue
		}
		users := usersByGroup[state.GroupID]
		if users == nil {
			users = make(map[string]struct{})
			usersByGroup[state.GroupID] = users
		}
		if _, exists := users[state.UserID]; exists {
			continue
		}
		users[state.UserID] = struct{}{}
		counts[state.GroupID]++
	}
	return counts, nil
}

func ReadProjectedGroupUserAttrs(ctx context.Context, store any, diceID, groupID, userID string) (GroupUserAttrsState, error) {
	stream := GroupUserAttrsStream(diceID, groupID, userID)
	var s GroupUserAttrsState
	if stream.AggregateID == "" {
		return s, ErrInvalidIdentity
	}
	if err := readProjected(ctx, store, GroupUserAttrsProjectionName, stream, &s); err != nil {
		return GroupUserAttrsState{}, err
	}
	if s.Version == 0 || GroupUserAttrsStream(s.DiceID, s.GroupID, s.UserID) != stream {
		return GroupUserAttrsState{}, ErrInvalidState
	}
	return s.Clone(), nil
}
func ReadProjectedCharacter(ctx context.Context, store any, diceID, userID, characterID string) (CharacterState, error) {
	stream := CharacterStream(diceID, userID, characterID)
	var s CharacterState
	if stream.AggregateID == "" {
		return s, ErrInvalidIdentity
	}
	if err := readProjected(ctx, store, CharacterProjectionName, stream, &s); err != nil {
		return CharacterState{}, err
	}
	if s.Version == 0 || CharacterStream(s.DiceID, s.UserID, s.CharacterID) != stream {
		return CharacterState{}, ErrInvalidState
	}
	return s.Clone(), nil
}
func ReadProjectedModeration(ctx context.Context, store any, diceID, groupID, subjectID string) (ModerationState, error) {
	stream := ModerationStream(diceID, groupID, subjectID)
	var s ModerationState
	if stream.AggregateID == "" {
		return s, ErrInvalidIdentity
	}
	if err := readProjected(ctx, store, ModerationProjectionName, stream, &s); err != nil {
		return ModerationState{}, err
	}
	if s.Version == 0 || ModerationStream(s.DiceID, s.GroupID, s.SubjectID) != stream {
		return ModerationState{}, ErrInvalidState
	}
	return s.Clone(), nil
}
