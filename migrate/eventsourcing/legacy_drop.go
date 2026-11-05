package eventsourcing

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// legacyGroupTable is the legacy table name written into drop records.
const legacyGroupTable = "group_info"

// Reasons a legacy group_info row is dropped instead of aborting the import.
// The first four follow the v150 group_info cleanup (data NULL, created_at or
// updated_at present but not positive); the rest are rows whose content cannot
// be interpreted, which the importer used to answer with ErrValidation.
const (
	legacyGroupDropInvalidID   = "invalid-id"
	legacyGroupDropDataNull    = "data-null"
	legacyGroupDropDataEmpty   = "data-empty"
	legacyGroupDropCreatedAt   = "created-at-not-positive"
	legacyGroupDropUpdatedAt   = "updated-at-not-positive"
	legacyGroupDropInvalidData = "invalid-data"
	legacyGroupDropUndecidable = "undecidable-state"
	// legacyGroupDropStoryLog drops only the row's story-log state; the group
	// itself was imported.
	legacyGroupDropStoryLog = "invalid-story-log-state"
)

// legacyGroupRowDrop explains why one group_info row cannot be imported.
type legacyGroupRowDrop struct {
	reason string
	cause  error
}

// abortError is the error used when no drop recorder is bound. Without a
// record file a drop would be silent data loss, so the row keeps aborting the
// import.
func (d legacyGroupRowDrop) abortError(row legacyGroupRow) error {
	if d.cause != nil {
		return fmt.Errorf("legacy group %q: %w", row.ID, d.cause)
	}
	return fmt.Errorf("legacy group %q: %s: %w", row.ID, d.reason, ErrValidation)
}

// legacyGroupDropDetail is the detail object of a legacy-import group drop
// record. It carries everything needed to inspect or re-create the row by
// hand: the raw row id, both timestamp columns (null when absent) and the full
// original data. Values that are not valid UTF-8 are kept losslessly as base64.
type legacyGroupDropDetail struct {
	Table       string `json:"table"`
	DiceID      string `json:"diceId"`
	RowID       string `json:"rowId"`
	RowIDBase64 string `json:"rowIdBase64,omitempty"`
	RowIDNull   bool   `json:"rowIdNull,omitempty"`
	CreatedAt   *int64 `json:"createdAt"`
	UpdatedAt   *int64 `json:"updatedAt"`
	DataNull    bool   `json:"dataNull,omitempty"`
	Data        string `json:"data,omitempty"`
	DataBase64  string `json:"dataBase64,omitempty"`
	Error       string `json:"error,omitempty"`
	// GroupImported is true when only the story-log state of the row was
	// dropped and the group itself was imported.
	GroupImported bool `json:"groupImported,omitempty"`
	// StoryLog repeats the story-log fields behind a story-log drop.
	StoryLog *legacyStoryLogDropDetail `json:"storyLog,omitempty"`
}

type legacyStoryLogDropDetail struct {
	LogOn      bool   `json:"logOn"`
	LogCurName string `json:"logCurName"`
}

func newLegacyGroupDropDetail(diceID string, row legacyGroupRow, drop legacyGroupRowDrop) legacyGroupDropDetail {
	detail := legacyGroupDropDetail{
		Table: legacyGroupTable, DiceID: diceID,
		RowID: strings.ToValidUTF8(row.ID, "\uFFFD"), RowIDNull: row.IDNull, DataNull: row.DataNull,
	}
	if !utf8.ValidString(row.ID) {
		detail.RowIDBase64 = base64.StdEncoding.EncodeToString([]byte(row.ID))
	}
	if row.CreatedAt.Valid {
		detail.CreatedAt = &row.CreatedAt.Int64
	}
	if row.UpdatedAt.Valid {
		detail.UpdatedAt = &row.UpdatedAt.Int64
	}
	if !row.DataNull {
		if utf8.Valid(row.Data) {
			detail.Data = string(row.Data)
		} else {
			detail.DataBase64 = base64.StdEncoding.EncodeToString(row.Data)
		}
	}
	if drop.cause != nil {
		detail.Error = drop.cause.Error()
	}
	return detail
}

// legacyGroupRowRecords converts one group_info row. A row that cannot be
// decided (ErrValidation, or a v150-style bad row) yields a drop instead of an
// error; every other failure is returned and still aborts the import.
func legacyGroupRowRecords(diceID string, row legacyGroupRow) ([]SourceRecord, *legacyGroupRowDrop, error) {
	switch {
	case row.IDNull || !utf8.ValidString(row.ID):
		return nil, &legacyGroupRowDrop{reason: legacyGroupDropInvalidID}, nil
	case row.DataNull:
		return nil, &legacyGroupRowDrop{reason: legacyGroupDropDataNull}, nil
	case row.CreatedAt.Valid && row.CreatedAt.Int64 <= 0:
		return nil, &legacyGroupRowDrop{reason: legacyGroupDropCreatedAt}, nil
	case row.UpdatedAt.Valid && row.UpdatedAt.Int64 <= 0:
		return nil, &legacyGroupRowDrop{reason: legacyGroupDropUpdatedAt}, nil
	case len(row.Data) == 0:
		return nil, &legacyGroupRowDrop{reason: legacyGroupDropDataEmpty}, nil
	}
	group, err := decodeLegacyGroupSnapshot(row.Data)
	if err != nil {
		if errors.Is(err, ErrValidation) {
			return nil, &legacyGroupRowDrop{reason: legacyGroupDropInvalidData, cause: err}, nil
		}
		return nil, nil, fmt.Errorf("legacy group %q: %w", row.ID, err)
	}
	// The historical loader assigned the row id to GroupID after decoding
	// (loadGroups: groupInfo.GroupID = id), so a divergent embedded value
	// never had any effect; the embedded value is only a fallback for an
	// empty row id.
	if row.ID != "" {
		group.GroupID = row.ID
	}
	records, err := legacyGroupRecords(diceID, group, row.CreatedAt.Int64)
	if err != nil {
		if errors.Is(err, ErrValidation) {
			return nil, &legacyGroupRowDrop{reason: legacyGroupDropUndecidable, cause: err}, nil
		}
		return nil, nil, fmt.Errorf("legacy group %q: %w", row.ID, err)
	}
	return records, nil, nil
}

// legacyTableHasColumn reports whether a legacy SQLite table carries a column.
func legacyTableHasColumn(ctx context.Context, database *sql.DB, table, column string) (bool, error) {
	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&count)
	return count > 0, err
}

// Table names and reasons for the v151 precedent (ban_info and attrs rows
// whose data is NULL or empty carry nothing to import; v151 deleted them from
// live databases) and for the other rows the importer cannot place.
const (
	legacyBanTable           = "ban_info"
	legacyAttrsTable         = "attrs"
	legacyPlayerTable        = "group_player_info"
	legacyDropDataNullOrZero = "data-empty"
	legacyDropAttrsNoID      = "attrs-missing-id"
	legacyDropBanInvalidData = "invalid-data"
	legacyDropPlayerNoID     = "player-missing-identity"
	legacyDropStoryNoSession = "story-log-session-missing"
)

// recordLegacyRowDrop writes the drop record of a row of a legacy table other
// than group_info. data is the row's original data column (omitted when
// empty; kept as base64 when not valid UTF-8) and columns holds the row's
// other column values.
func recordLegacyRowDrop(drops *dropRecorder, table, diceID, rowID, reason string, data []byte, columns map[string]any) error {
	detail := map[string]any{"table": table, "diceId": diceID, "rowId": strings.ToValidUTF8(rowID, "\uFFFD")}
	if !utf8.ValidString(rowID) {
		detail["rowIdBase64"] = base64.StdEncoding.EncodeToString([]byte(rowID))
	}
	if len(data) != 0 {
		if utf8.Valid(data) {
			detail["data"] = string(data)
		} else {
			detail["dataBase64"] = base64.StdEncoding.EncodeToString(data)
		}
	}
	for name, value := range columns {
		detail[name] = value
	}
	return drops.Add(table, strings.ToValidUTF8(rowID, "\uFFFD"), reason, detail)
}

// recordLegacyEmptyDataDrop writes the drop record of a ban_info/attrs row with
// NULL or empty data.
func recordLegacyEmptyDataDrop(drops *dropRecorder, table, diceID, rowID string, columns map[string]any) error {
	merged := map[string]any{"dataEmpty": true}
	for name, value := range columns {
		merged[name] = value
	}
	return recordLegacyRowDrop(drops, table, diceID, rowID, legacyDropDataNullOrZero, nil, merged)
}

// queryLegacyGroupRows selects every group_info row with the columns the v150
// bad-row rule needs. NULL timestamps and NULL data stay distinguishable from
// zero/empty, and a table without updated_at simply has no row that column
// could mark bad.
func queryLegacyGroupRows(ctx context.Context, database *sql.DB) (*sql.Rows, error) {
	hasUpdatedAt, err := legacyTableHasColumn(ctx, database, legacyGroupTable, "updated_at")
	if err != nil {
		return nil, err
	}
	updatedAt := "NULL"
	if hasUpdatedAt {
		updatedAt = "CAST(updated_at AS INTEGER)"
	}
	return database.QueryContext(ctx, "SELECT id IS NULL, COALESCE(id, ''), CAST(created_at AS INTEGER), "+updatedAt+", data IS NULL, data FROM group_info ORDER BY id")
}

func scanLegacyGroupRow(rows *sql.Rows) (legacyGroupRow, error) {
	var row legacyGroupRow
	err := rows.Scan(&row.IDNull, &row.ID, &row.CreatedAt, &row.UpdatedAt, &row.DataNull, &row.Data)
	return row, err
}

// recordLegacyGroupDrop writes the drop record of one group_info row.
func recordLegacyGroupDrop(drops *dropRecorder, diceID string, row legacyGroupRow, drop legacyGroupRowDrop, groupImported bool) error {
	detail := newLegacyGroupDropDetail(diceID, row, drop)
	detail.GroupImported = groupImported
	if err := drops.Add(legacyGroupTable, strings.ToValidUTF8(row.ID, "\uFFFD"), drop.reason, detail); err != nil {
		return fmt.Errorf("record dropped legacy group %q: %w", row.ID, err)
	}
	return nil
}

// recordLegacyStoryLogSessionDrop records that a group's current story-log
// state has no matching session. The group itself was imported; only that
// state is left out, i.e. the log is imported as closed.
func recordLegacyStoryLogSessionDrop(drops *dropRecorder, diceID string, row legacyGroupRow, group legacyStoryLogGroupSnapshot, cause error) error {
	detail := newLegacyGroupDropDetail(diceID, row, legacyGroupRowDrop{reason: legacyDropStoryNoSession, cause: cause})
	detail.GroupImported = true
	detail.StoryLog = &legacyStoryLogDropDetail{LogOn: group.LogOn, LogCurName: group.LogName}
	if err := drops.Add(legacyGroupTable, strings.ToValidUTF8(row.ID, "\uFFFD"), legacyDropStoryNoSession, detail); err != nil {
		return fmt.Errorf("record dropped legacy group %q: %w", row.ID, err)
	}
	return nil
}

// Errors the stream classifies as droppable rows. The identity ones keep
// ErrValidation in their chain so an unrecorded stream still aborts as before.
var (
	errLegacyAttrsNoIdentity   = fmt.Errorf("%w: attrs row has no identity", ErrValidation)
	errLegacyPlayerNoIdentity  = fmt.Errorf("%w: player row has no user or group", ErrValidation)
	errLegacyStoryLogNoSession = fmt.Errorf("%w: legacy group log state has no session", ErrValidation)
	errLegacyBanInvalidData    = errors.New("ban data is not valid JSON for a ban entry")
)
