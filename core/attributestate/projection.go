package attributestate

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

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
		if envelope.SchemaVersion != EventSchemaVersion ||
			(envelope.EventType != EventBaselineImported && envelope.EventType != EventSnapshotReplaced) {
			return ErrInvalidEvent
		}
		state := State{}
		var existing projectionRow
		query := tx.WithContext(ctx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", eventstore.ProjectionGeneration(tx), ProjectionName, envelope.Stream.AggregateID).First(&existing)
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
		event, err := DecodeBaselineImportedV1(envelope.Payload)
		if err != nil || Stream(event.DiceID, event.ID) != envelope.Stream {
			return ErrInvalidEvent
		}
		state, err = Apply(state, event)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if err = eventstore.UpsertProjectionRow(tx, ProjectionName, envelope.Stream.AggregateID, payload); err != nil {
			return err
		}
	}
	return nil
}

type projectionReader interface {
	ReadProjectionRow(ctx context.Context, projectionName, rowKey string) (eventstore.ProjectionRow, error)
}

type projectionPageLister interface {
	ListProjectionRowsPage(ctx context.Context, request eventstore.ProjectionPageRequest) (eventstore.ProjectionPage, error)
}

// ProjectedPageRequest selects one bounded page for exactly one Dice.
// ExpectedSnapshot should be the value returned by ValidateProjected during
// startup, or the Snapshot returned by the first page for ordinary scoped
// reads. AfterRowKey is the prior page's NextRowKey.
type ProjectedPageRequest struct {
	DiceID           string
	AfterRowKey      string
	Limit            int
	ExpectedSnapshot *eventstore.ProjectionSnapshot
}

// ProjectedPage is detached from the event-store transaction. Done is true
// only on an empty terminal source page; callers must advance NextRowKey until
// Done even when exact scope filtering leaves States empty.
type ProjectedPage struct {
	Snapshot   eventstore.ProjectionSnapshot
	States     []State
	NextRowKey string
	Done       bool
}

func ReadProjected(ctx context.Context, store any, diceID, id string) (State, error) {
	stream := Stream(diceID, id)
	reader, ok := store.(projectionReader)
	if !ok || reader == nil || stream.AggregateID == "" {
		return State{}, ErrRepositoryUnavailable
	}
	row, err := reader.ReadProjectionRow(ctx, ProjectionName, stream.AggregateID)
	if err != nil {
		return State{}, err
	}
	return decodeProjectedState(row.Payload, stream)
}

func projectedDiceRowRange(diceID string) (prefix, start, end string, ok bool) {
	if !validPart(diceID) {
		return "", "", "", false
	}
	prefix = strconv.Itoa(len(diceID)) + ":" + diceID
	// A valid following length is decimal and starts between '1' and '9'.
	// The half-open 0..: suffix range therefore contains every encoded
	// attribute stream for this exact length-prefixed Dice identity.
	return prefix, prefix + "0", prefix + ":", true
}

func validateProjectionPageContract(page eventstore.ProjectionPage, afterRowKey string, limit int, expected *eventstore.ProjectionSnapshot) error {
	if page.Snapshot.Generation == "" ||
		len(page.Rows) > limit ||
		page.Done != (len(page.Rows) == 0) {
		return ErrInvalidState
	}
	if expected != nil && page.Snapshot != *expected {
		return eventstore.ErrParticipantConflict
	}
	if len(page.Rows) == 0 {
		if page.NextRowKey != afterRowKey {
			return ErrInvalidState
		}
		return nil
	}
	if page.NextRowKey != page.Rows[len(page.Rows)-1].RowKey || page.NextRowKey == afterRowKey {
		return ErrInvalidState
	}
	for _, row := range page.Rows {
		if row.ProjectionGeneration != page.Snapshot.Generation ||
			row.ProjectionName != ProjectionName ||
			row.RowKey == "" {
			return ErrInvalidState
		}
	}
	return nil
}

// ListProjectedPage reads only the exact length-prefixed Dice row-key range.
// It does not validate unrelated Dice rows; startup callers must first call
// ValidateProjected and carry the returned snapshot through every page.
func ListProjectedPage(ctx context.Context, store any, request ProjectedPageRequest) (ProjectedPage, error) {
	lister, ok := store.(projectionPageLister)
	prefix, start, end, validDice := projectedDiceRowRange(request.DiceID)
	if !ok || lister == nil || !validDice {
		return ProjectedPage{}, ErrRepositoryUnavailable
	}
	if request.Limit <= 0 || request.Limit > eventstore.MaxProjectionReadPageRows {
		return ProjectedPage{}, eventstore.ErrProjectionInvariant
	}
	page, err := lister.ListProjectionRowsPage(ctx, eventstore.ProjectionPageRequest{
		ProjectionName:   ProjectionName,
		RowKeyPrefix:     prefix,
		RowKeyStart:      start,
		RowKeyEnd:        end,
		AfterRowKey:      request.AfterRowKey,
		Limit:            request.Limit,
		ExpectedSnapshot: request.ExpectedSnapshot,
	})
	if err != nil {
		return ProjectedPage{}, err
	}
	if err = validateProjectionPageContract(page, request.AfterRowKey, request.Limit, request.ExpectedSnapshot); err != nil {
		return ProjectedPage{}, err
	}

	result := ProjectedPage{
		Snapshot:   page.Snapshot,
		States:     make([]State, 0, len(page.Rows)),
		NextRowKey: page.NextRowKey,
		Done:       page.Done,
	}
	for _, row := range page.Rows {
		// SQL collations may broaden a textual range (for example by folding
		// case). Keep the public scope byte-exact without decoding another
		// Dice's payload; the global validation pass still checks every row.
		if !strings.HasPrefix(row.RowKey, prefix) ||
			len(row.RowKey) == len(prefix) ||
			row.RowKey[len(prefix)] < '0' || row.RowKey[len(prefix)] > '9' {
			continue
		}
		state, decodeErr := decodeProjectedRow(row)
		if decodeErr != nil || state.DiceID != request.DiceID {
			return ProjectedPage{}, ErrInvalidState
		}
		result.States = append(result.States, state)
	}
	return result, nil
}

// ValidateProjected performs the global corruption gate in bounded pages and
// returns the snapshot token that scoped startup reads must use. Any malformed
// row or publication change returns a zero token and no partial success.
func ValidateProjected(ctx context.Context, store any) (eventstore.ProjectionSnapshot, error) {
	lister, ok := store.(projectionPageLister)
	if !ok || lister == nil {
		return eventstore.ProjectionSnapshot{}, ErrRepositoryUnavailable
	}
	var (
		snapshot eventstore.ProjectionSnapshot
		expected *eventstore.ProjectionSnapshot
		cursor   string
	)
	for {
		page, err := lister.ListProjectionRowsPage(ctx, eventstore.ProjectionPageRequest{
			ProjectionName:   ProjectionName,
			AfterRowKey:      cursor,
			Limit:            eventstore.MaxProjectionReadPageRows,
			ExpectedSnapshot: expected,
		})
		if err != nil {
			return eventstore.ProjectionSnapshot{}, err
		}
		if err = validateProjectionPageContract(page, cursor, eventstore.MaxProjectionReadPageRows, expected); err != nil {
			return eventstore.ProjectionSnapshot{}, err
		}
		if expected == nil {
			snapshot = page.Snapshot
			expected = &snapshot
		}
		for _, row := range page.Rows {
			if _, err = decodeProjectedRow(row); err != nil {
				return eventstore.ProjectionSnapshot{}, ErrInvalidState
			}
		}
		if page.Done {
			return snapshot, nil
		}
		cursor = page.NextRowKey
	}
}

type projectionPrefixLister interface {
	ListProjectionRowsByRowKeyPrefix(ctx context.Context, projectionName, prefix string) ([]eventstore.ProjectionRow, error)
}

// ListProjected returns metadata for one Dice in one consistent transaction.
// Streaming startup validation uses the separate fenced page API so unrelated
// live commits do not introduce new errors into ordinary character lists.
func ListProjected(ctx context.Context, store any, diceID string) ([]State, error) {
	lister, ok := store.(projectionPrefixLister)
	prefix, _, _, validDice := projectedDiceRowRange(diceID)
	if !ok || lister == nil || !validDice {
		return nil, ErrRepositoryUnavailable
	}
	rows, err := lister.ListProjectionRowsByRowKeyPrefix(ctx, ProjectionName, prefix)
	if err != nil {
		return nil, err
	}
	states := make([]State, 0, len(rows))
	for _, row := range rows {
		if !strings.HasPrefix(row.RowKey, prefix) ||
			len(row.RowKey) == len(prefix) ||
			row.RowKey[len(prefix)] < '0' || row.RowKey[len(prefix)] > '9' {
			continue
		}
		state, decodeErr := decodeProjectedRow(row)
		if decodeErr != nil || state.DiceID != diceID {
			return nil, ErrInvalidState
		}
		states = append(states, state)
	}
	return states, nil
}

func decodeProjectedRow(row eventstore.ProjectionRow) (State, error) {
	state, err := decodeProjectedPayload(row.Payload)
	if err != nil || Stream(state.DiceID, state.ID).AggregateID != row.RowKey {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func decodeProjectedPayload(payload []byte) (State, error) {
	var state State
	if err := json.Unmarshal(payload, &state); err != nil || ValidateState(state) != nil {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func decodeProjectedState(payload []byte, stream eventstore.StreamID) (State, error) {
	state, err := decodeProjectedPayload(payload)
	if err != nil || Stream(state.DiceID, state.ID) != stream {
		return State{}, ErrInvalidState
	}
	return state, nil
}
