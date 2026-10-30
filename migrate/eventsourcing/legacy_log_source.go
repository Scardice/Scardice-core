package eventsourcing

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"Scardice-core/dice"
	"Scardice-core/eventstore"
)

const (
	legacyLogImportSession = "session"
	legacyLogImportEntry   = "entry"
	legacyLogImportState   = "state"
	legacyLogRecordDomain  = "story-log-archive"
)

// legacyStoryLogImportPayload is the encrypted migration payload. Its explicit
// JSON fields include values intentionally hidden by the public StoryLog JSON
// views, such as DiceID, upload metadata, Removed, and ParentID.
type legacyStoryLogImportPayload struct {
	SourceID        string                        `json:"sourceId"`
	Kind            string                        `json:"kind"`
	DiceID          string                        `json:"diceId"`
	GroupID         string                        `json:"groupId"`
	SessionSourceID string                        `json:"sessionSourceId,omitempty"`
	Session         *legacyStoryLogSessionPayload `json:"session,omitempty"`
	Entry           *legacyStoryLogEntryPayload   `json:"entry,omitempty"`
	State           *legacyStoryLogStatePayload   `json:"state,omitempty"`
}

type legacyStoryLogSessionPayload struct {
	ID         uint64  `json:"id"`
	DiceID     string  `json:"diceId"`
	GroupID    string  `json:"groupId"`
	Name       string  `json:"name"`
	CreatedAt  int64   `json:"createdAt"`
	UpdatedAt  int64   `json:"updatedAt"`
	Extra      *string `json:"extra"`
	UploadURL  string  `json:"uploadUrl"`
	UploadTime int64   `json:"uploadTime"`
}

type legacyStoryLogEntryPayload struct {
	ID          uint64          `json:"id"`
	LogID       uint64          `json:"logId"`
	DiceID      string          `json:"diceId"`
	GroupID     string          `json:"groupId"`
	LogName     string          `json:"logName"`
	Nickname    string          `json:"nickname"`
	IMUserID    string          `json:"IMUserId"`
	Time        int64           `json:"time"`
	Message     string          `json:"message"`
	IsDice      bool            `json:"isDice"`
	CommandID   int64           `json:"commandId"`
	CommandInfo json.RawMessage `json:"commandInfo,omitempty"`
	RawMsgID    string          `json:"rawMsgId,omitempty"`
	UniformID   string          `json:"uniformId"`
	Seq         *int64          `json:"seq,omitempty"`
	Removed     *int            `json:"removed"`
	ParentID    *int            `json:"parentId"`
}

type legacyStoryLogStatePayload struct {
	DiceID    string `json:"diceId"`
	GroupID   string `json:"groupId"`
	SessionID uint64 `json:"sessionId"`
	Name      string `json:"name"`
	On        bool   `json:"on"`
}

func legacyStoryLogSourceID(sourceIdentity, diceID, groupID, kind string, legacyID uint64) string {
	scopeDigest := sha256.Sum256([]byte(diceID + "\x00" + groupID))
	return fmt.Sprintf("legacy-story-log/v1/%s/%s/%s/%d", sourceIdentity, hex.EncodeToString(scopeDigest[:]), kind, legacyID)
}
func legacyStoryLogSourcePrefix(sourceID string) (string, bool) {
	parts := strings.Split(sourceID, "/")
	if len(parts) != 6 || parts[0] != "legacy-story-log" || parts[1] != "v1" ||
		parts[2] == "" || parts[4] == "" || parts[5] == "" {
		return "", false
	}
	scopeDigest, err := hex.DecodeString(parts[3])
	if err != nil || len(scopeDigest) != sha256.Size {
		return "", false
	}
	if _, ok := legacyStoryLogImportKindRank(parts[4]); !ok {
		return "", false
	}
	if _, err := strconv.ParseUint(parts[5], 10, 64); err != nil {
		return "", false
	}
	return strings.Join(parts[:3], "/") + "/", true
}

func legacyStoryLogSourceRecord(payload legacyStoryLogImportPayload) (SourceRecord, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return SourceRecord{}, err
	}
	return SourceRecord{
		RecordType: RecordTypeLogArchive, Domain: legacyLogRecordDomain, Identity: payload.SourceID,
		Kind: payload.Kind, SchemaVersion: 1, Version: 1, Sensitive: true,
		Payload: encoded, Size: uint64(len(encoded)),
	}, nil
}

func streamLegacyStoryLogRecords(ctx context.Context, root *legacySourceRoot, dataDB *sql.DB, logPath, diceID, sourceIdentity string, yield func([]SourceRecord) error) (streamErr error) {
	if yield == nil {
		return ErrValidation
	}
	batcher := sourceRecordBatcher{yield: yield}
	var logDB *sql.DB
	info, err := root.Lstat(logPath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return ErrSourceMutation
		}
		var cleanup func() error
		logDB, cleanup, err = openLegacySQLiteSnapshotReader(ctx, root, logPath)
		if err != nil {
			return err
		}
		defer func() { streamErr = errors.Join(streamErr, cleanup()) }()
		logColumns, itemColumns, schemaErr := validateLegacyStoryLogSchema(ctx, logDB)
		if schemaErr != nil {
			return fmt.Errorf("validate legacy story-log schema: %w", schemaErr)
		}
		if err = validateLegacyStoryLogRows(ctx, logDB); err != nil {
			return fmt.Errorf("validate legacy story-log row constraints: %w", err)
		}
		if err = streamLegacyStoryLogSessions(ctx, logDB, logColumns, diceID, sourceIdentity, &batcher); err != nil {
			return fmt.Errorf("stream legacy logs rows: %w", err)
		}
		if err = streamLegacyStoryLogEntries(ctx, logDB, itemColumns, diceID, sourceIdentity, &batcher); err != nil {
			return fmt.Errorf("stream legacy log_items rows: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, sidecarErr := root.Lstat(logPath + suffix); sidecarErr == nil {
				return ErrSourceMutation
			} else if !errors.Is(sidecarErr, os.ErrNotExist) {
				return sidecarErr
			}
		}
	}
	if err = streamLegacyStoryLogStates(ctx, dataDB, logDB, diceID, sourceIdentity, &batcher); err != nil {
		return fmt.Errorf("stream legacy group story-log state: %w", err)
	}
	return batcher.flush()
}

func legacySQLiteTableColumns(ctx context.Context, database *sql.DB, table string) (columns map[string]struct{}, resultErr error) {
	rows, err := database.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
	columns = make(map[string]struct{})
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		columns[name] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, &UnsupportedPreflightError{Feature: "legacy log SQLite schema missing table " + table}
	}
	return columns, nil
}

func validateLegacyStoryLogSchema(ctx context.Context, database *sql.DB) (map[string]struct{}, map[string]struct{}, error) {
	logs, err := legacySQLiteTableColumns(ctx, database, "logs")
	if err != nil {
		return nil, nil, err
	}
	items, err := legacySQLiteTableColumns(ctx, database, "log_items")
	if err != nil {
		return nil, nil, err
	}
	required := map[string][]string{
		"logs":      {"id", "name", "group_id", "created_at", "updated_at"},
		"log_items": {"id", "log_id", "group_id", "nickname", "im_userid", "time", "message", "is_dice", "command_id"},
	}
	missing := make([]string, 0)
	for table, columns := range required {
		actual := logs
		if table == "log_items" {
			actual = items
		}
		for _, column := range columns {
			if _, ok := actual[column]; !ok {
				missing = append(missing, table+"."+column)
			}
		}
	}
	if len(missing) != 0 {
		return nil, nil, &UnsupportedPreflightError{Feature: "legacy log SQLite schema missing " + strings.Join(missing, ", ")}
	}
	return logs, items, nil
}

func validateLegacyStoryLogRows(ctx context.Context, database *sql.DB) error {
	for _, query := range []string{
		"SELECT id FROM logs WHERE id IS NULL OR id <= 0 LIMIT 1",
		"SELECT id FROM logs GROUP BY id HAVING COUNT(1) > 1 LIMIT 1",
		"SELECT id FROM logs GROUP BY group_id, name HAVING COUNT(1) > 1 LIMIT 1",
		"SELECT id FROM log_items WHERE id IS NULL OR id <= 0 LIMIT 1",
		"SELECT id FROM log_items GROUP BY id HAVING COUNT(1) > 1 LIMIT 1",
	} {
		var id sql.NullInt64
		err := database.QueryRowContext(ctx, query).Scan(&id)
		if err == nil {
			return fmt.Errorf("%w: duplicate or invalid legacy log identifier", ErrValidation)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}

func legacyLogColumn(columns map[string]struct{}, alias, name, fallback string) string {
	if _, ok := columns[name]; !ok {
		return fallback
	}
	return `"` + alias + `"."` + name + `"`
}

func streamLegacyStoryLogSessions(ctx context.Context, database *sql.DB, columns map[string]struct{}, diceID, sourceIdentity string, batcher *sourceRecordBatcher) (streamErr error) {
	// #nosec G202 -- Identifiers and fallback expressions below are fixed literals, never source-provided SQL.
	query := `SELECT id, name, group_id, COALESCE(created_at, 0), COALESCE(updated_at, 0), ` +
		legacyLogColumn(columns, "logs", "extra", "NULL") + `, ` +
		legacyLogColumn(columns, "logs", "upload_url", `''`) + `, ` +
		legacyLogColumn(columns, "logs", "upload_time", "0") + ` FROM logs ORDER BY id`
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var id int64
		var name, groupID, extra, uploadURL sql.NullString
		var createdAt, updatedAt int64
		var uploadTime sql.NullInt64
		if err = rows.Scan(&id, &name, &groupID, &createdAt, &updatedAt, &extra, &uploadURL, &uploadTime); err != nil {
			return err
		}
		if id <= 0 || !name.Valid || strings.TrimSpace(name.String) == "" ||
			!groupID.Valid || strings.TrimSpace(groupID.String) == "" ||
			!utf8.ValidString(name.String) || !utf8.ValidString(groupID.String) ||
			(extra.Valid && !utf8.ValidString(extra.String)) || (uploadURL.Valid && !utf8.ValidString(uploadURL.String)) {
			return fmt.Errorf("%w: invalid legacy logs row id=%d", ErrValidation, id)
		}
		var extraValue *string
		if extra.Valid {
			value := extra.String
			extraValue = &value
		}
		uploadTimeValue := int64(0)
		if uploadTime.Valid {
			uploadTimeValue = uploadTime.Int64
		}
		payload := legacyStoryLogImportPayload{
			SourceID: legacyStoryLogSourceID(sourceIdentity, diceID, groupID.String, legacyLogImportSession, uint64(id)),
			Kind:     legacyLogImportSession, DiceID: diceID, GroupID: groupID.String,
			Session: &legacyStoryLogSessionPayload{
				DiceID: diceID, GroupID: groupID.String, Name: name.String,
				CreatedAt: createdAt, UpdatedAt: updatedAt, Extra: extraValue,
				UploadURL: uploadURL.String, UploadTime: uploadTimeValue,
			},
		}
		record, recordErr := legacyStoryLogSourceRecord(payload)
		if recordErr != nil {
			return recordErr
		}
		if err = batcher.add(record); err != nil {
			return err
		}
	}
	return rows.Err()
}

func streamLegacyStoryLogEntries(ctx context.Context, database *sql.DB, items map[string]struct{}, diceID, sourceIdentity string, batcher *sourceRecordBatcher) (streamErr error) {
	// #nosec G202 -- Optional columns select only the fixed identifiers and fallback expressions listed below.
	query := `SELECT l.id, l.name, l.group_id, i.id, i.log_id, i.group_id, COALESCE(i.nickname, ''), COALESCE(i.im_userid, ''), COALESCE(i.time, 0), COALESCE(i.message, ''), COALESCE(i.is_dice, 0), COALESCE(i.command_id, 0), ` +
		legacyLogColumn(items, "i", "command_info", "NULL") + `, ` +
		legacyLogColumn(items, "i", "raw_msg_id", "NULL") + `, ` +
		legacyLogColumn(items, "i", "user_uniform_id", "NULL") + `, ` +
		legacyLogColumn(items, "i", "removed", "NULL") + `, ` +
		legacyLogColumn(items, "i", "parent_id", "NULL") + `, ` +
		legacyLogColumn(items, "i", "seq", "NULL") +
		` FROM log_items i LEFT JOIN logs l ON l.id = i.log_id ORDER BY i.id`
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var sessionID, id, logID sql.NullInt64
		var sessionName, sessionGroup, groupID, nickname, imUserID, message sql.NullString
		var timestamp, isDice, commandID sql.NullInt64
		var commandInfo, rawMsgID, uniformID sql.NullString
		var removed, parentID, sequence sql.NullInt64
		if err = rows.Scan(&sessionID, &sessionName, &sessionGroup, &id, &logID, &groupID, &nickname, &imUserID, &timestamp, &message, &isDice, &commandID,
			&commandInfo, &rawMsgID, &uniformID, &removed, &parentID, &sequence); err != nil {
			return err
		}
		if !sessionID.Valid || sessionID.Int64 <= 0 || !id.Valid || id.Int64 <= 0 || !logID.Valid || logID.Int64 != sessionID.Int64 ||
			!sessionName.Valid || strings.TrimSpace(sessionName.String) == "" || !sessionGroup.Valid ||
			!groupID.Valid || groupID.String != sessionGroup.String || !nickname.Valid || !imUserID.Valid ||
			!timestamp.Valid || !message.Valid || !isDice.Valid || !commandID.Valid {
			return fmt.Errorf("%w: orphan or invalid legacy log_items row id=%d", ErrValidation, id.Int64)
		}
		if !utf8.ValidString(sessionName.String) || !utf8.ValidString(sessionGroup.String) ||
			!utf8.ValidString(groupID.String) || !utf8.ValidString(nickname.String) ||
			!utf8.ValidString(imUserID.String) || !utf8.ValidString(message.String) ||
			(rawMsgID.Valid && !utf8.ValidString(rawMsgID.String)) ||
			(uniformID.Valid && !utf8.ValidString(uniformID.String)) ||
			(isDice.Int64 != 0 && isDice.Int64 != 1) {
			return fmt.Errorf("%w: invalid text or dice flag in legacy log_items row id=%d", ErrValidation, id.Int64)
		}
		var commandJSON json.RawMessage
		if commandInfo.Valid && commandInfo.String != "" {
			if !utf8.ValidString(commandInfo.String) || !json.Valid([]byte(commandInfo.String)) {
				return fmt.Errorf("%w: invalid legacy log command info", ErrValidation)
			}
			commandJSON = append(json.RawMessage(nil), commandInfo.String...)
		}
		removedValue, err := legacyNullableInt(removed)
		if err != nil {
			return err
		}
		parentValue, err := legacyNullableInt(parentID)
		if err != nil {
			return err
		}
		var sequenceValue *int64
		if sequence.Valid {
			value := sequence.Int64
			sequenceValue = &value
		}
		payload := legacyStoryLogImportPayload{
			SourceID: legacyStoryLogSourceID(sourceIdentity, diceID, groupID.String, legacyLogImportEntry, uint64(id.Int64)),
			Kind:     legacyLogImportEntry, DiceID: diceID, GroupID: groupID.String,
			SessionSourceID: legacyStoryLogSourceID(sourceIdentity, diceID, sessionGroup.String, legacyLogImportSession, uint64(sessionID.Int64)),
			Entry: &legacyStoryLogEntryPayload{
				DiceID: diceID, GroupID: groupID.String, LogName: sessionName.String,
				Nickname: nickname.String, IMUserID: imUserID.String, Time: timestamp.Int64,
				Message: message.String, IsDice: isDice.Int64 != 0, CommandID: commandID.Int64,
				CommandInfo: commandJSON, RawMsgID: rawMsgID.String, UniformID: uniformID.String,
				Seq: sequenceValue, Removed: removedValue, ParentID: parentValue,
			},
		}
		record, recordErr := legacyStoryLogSourceRecord(payload)
		if recordErr != nil {
			return recordErr
		}
		if err = batcher.add(record); err != nil {
			return fmt.Errorf("legacy log_items row id=%d: %w", id.Int64, err)
		}
	}
	return rows.Err()
}

//nolint:nilnil // SQL NULL must remain absent rather than being changed to zero or an error.
func legacyNullableInt(value sql.NullInt64) (*int, error) {
	if !value.Valid {
		return nil, nil
	}
	converted := int(value.Int64)
	if int64(converted) != value.Int64 {
		return nil, ErrValidation
	}
	return &converted, nil
}

func streamLegacyStoryLogStates(ctx context.Context, dataDB, logDB *sql.DB, diceID, sourceIdentity string, batcher *sourceRecordBatcher) (streamErr error) {
	if dataDB == nil || batcher == nil {
		return ErrValidation
	}
	rows, err := dataDB.QueryContext(ctx, "SELECT id, data FROM group_info ORDER BY id")
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var rowID string
		var data []byte
		if err = rows.Scan(&rowID, &data); err != nil {
			return err
		}
		var group dice.GroupInfo
		if !utf8.Valid(data) || !utf8.ValidString(rowID) {
			return fmt.Errorf("%w: invalid text in legacy group_info row %q", ErrValidation, rowID)
		}
		if err = json.Unmarshal(data, &group); err != nil {
			return fmt.Errorf("legacy group %q: %w", rowID, err)
		}
		if group.GroupID == "" {
			group.GroupID = rowID
		} else if rowID != "" && group.GroupID != rowID {
			return fmt.Errorf("%w: legacy group row identity mismatch", ErrValidation)
		}
		if !utf8.ValidString(group.GroupID) {
			return fmt.Errorf("%w: invalid group identity in legacy group_info row %q", ErrValidation, rowID)
		}
		state := group.GetLogState()
		if !utf8.ValidString(state.Name) {
			return fmt.Errorf("%w: invalid story-log name in legacy group_info row %q", ErrValidation, rowID)
		}
		if state.Name == "" && !state.On {
			continue
		}
		if strings.TrimSpace(group.GroupID) == "" || strings.TrimSpace(state.Name) == "" || logDB == nil {
			return fmt.Errorf("%w: legacy group log state has no session", ErrValidation)
		}
		sessionID, lookupErr := legacyStoryLogSessionID(ctx, logDB, group.GroupID, state.Name)
		if lookupErr != nil {
			return lookupErr
		}
		payload := legacyStoryLogImportPayload{
			SourceID: legacyStoryLogSourceID(sourceIdentity, diceID, group.GroupID, legacyLogImportState, 0),
			Kind:     legacyLogImportState, DiceID: diceID, GroupID: group.GroupID,
			SessionSourceID: legacyStoryLogSourceID(sourceIdentity, diceID, group.GroupID, legacyLogImportSession, sessionID),
			State:           &legacyStoryLogStatePayload{DiceID: diceID, GroupID: group.GroupID, Name: state.Name, On: state.On},
		}
		record, recordErr := legacyStoryLogSourceRecord(payload)
		if recordErr != nil {
			return recordErr
		}
		if err = batcher.add(record); err != nil {
			return err
		}
	}
	return rows.Err()
}

func legacyStoryLogSessionID(ctx context.Context, database *sql.DB, groupID, name string) (uint64, error) {
	rows, err := database.QueryContext(ctx, "SELECT id FROM logs WHERE group_id = ? AND name = ? ORDER BY id LIMIT 2", groupID, name)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var found uint64
	count := 0
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return 0, err
		}
		if id <= 0 {
			return 0, ErrValidation
		}
		found = uint64(id)
		count++
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}
	if count != 1 {
		return 0, fmt.Errorf("%w: legacy group log state has %d matching sessions", ErrValidation, count)
	}
	return found, nil
}
func validateLegacyLogArchiveSourceRecord(record SourceRecord) error {
	if record.Domain != legacyLogRecordDomain || !record.Sensitive || record.Version != 1 || record.SchemaVersion != 1 {
		return ErrValidation
	}
	var payload legacyStoryLogImportPayload
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		return ErrValidation
	}
	if payload.SourceID == "" || payload.SourceID != record.Identity || payload.Kind != record.Kind ||
		payload.DiceID == "" || payload.GroupID == "" {
		return ErrValidation
	}
	switch payload.Kind {
	case legacyLogImportSession:
		if payload.Session == nil || payload.Entry != nil || payload.State != nil || payload.SessionSourceID != "" ||
			payload.Session.DiceID != payload.DiceID || payload.Session.GroupID != payload.GroupID ||
			strings.TrimSpace(payload.Session.Name) == "" || payload.Session.ID != 0 {
			return ErrValidation
		}
	case legacyLogImportEntry:
		if payload.Entry == nil || payload.Session != nil || payload.State != nil || payload.SessionSourceID == "" ||
			payload.Entry.DiceID != payload.DiceID || payload.Entry.GroupID != payload.GroupID ||
			strings.TrimSpace(payload.Entry.LogName) == "" || payload.Entry.ID != 0 || payload.Entry.LogID != 0 {
			return ErrValidation
		}
	case legacyLogImportState:
		if payload.State == nil || payload.Session != nil || payload.Entry != nil || payload.SessionSourceID == "" ||
			payload.State.DiceID != payload.DiceID || payload.State.GroupID != payload.GroupID ||
			strings.TrimSpace(payload.State.Name) == "" || payload.State.SessionID != 0 {
			return ErrValidation
		}
	default:
		return ErrValidation
	}
	return nil
}

func legacyStoryLogImportKindRank(kind string) (int, bool) {
	switch kind {
	case legacyLogImportSession:
		return 0, true
	case legacyLogImportEntry:
		return 1, true
	case legacyLogImportState:
		return 2, true
	default:
		return 0, false
	}
}
func decodeLegacyStoryLogImport(record SourceRecord) (eventstore.StoryLogImportRecord, error) {
	if err := validateLegacyLogArchiveSourceRecord(record); err != nil {
		return eventstore.StoryLogImportRecord{}, err
	}
	var payload legacyStoryLogImportPayload
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		return eventstore.StoryLogImportRecord{}, ErrValidation
	}
	importRecord := eventstore.StoryLogImportRecord{
		SourceID: payload.SourceID, Kind: eventstore.StoryLogImportKind(payload.Kind),
		DiceID: payload.DiceID, GroupID: payload.GroupID, SessionSourceID: payload.SessionSourceID,
	}
	switch payload.Kind {
	case legacyLogImportSession:
		session := payload.Session
		importRecord.Session = &eventstore.StoryLogSession{
			DiceID: session.DiceID, GroupID: session.GroupID, Name: session.Name,
			CreatedAt: session.CreatedAt, UpdatedAt: session.UpdatedAt,
			Extra: session.Extra, UploadURL: session.UploadURL, UploadTime: session.UploadTime,
		}
	case legacyLogImportEntry:
		entry := payload.Entry
		importRecord.Entry = &eventstore.StoryLogEntry{
			DiceID: entry.DiceID, GroupID: entry.GroupID, LogName: entry.LogName,
			Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: entry.Time,
			Message: entry.Message, IsDice: entry.IsDice, CommandID: entry.CommandID,
			CommandInfo: entry.CommandInfo, RawMsgID: entry.RawMsgID, UniformID: entry.UniformID,
			Seq: entry.Seq, Removed: entry.Removed, ParentID: entry.ParentID,
		}
	case legacyLogImportState:
		state := payload.State
		importRecord.State = &eventstore.StoryLogState{
			DiceID: state.DiceID, GroupID: state.GroupID, Name: state.Name, On: state.On,
		}
	}
	return importRecord, nil
}

func clearLegacyStoryLogImport(record *eventstore.StoryLogImportRecord) {
	if record == nil {
		return
	}
	record.SourceID = ""
	record.SessionSourceID = ""
	if record.Session != nil {
		record.Session.DiceID = ""
		record.Session.GroupID = ""
		record.Session.Name = ""
		record.Session.UploadURL = ""
		if record.Session.Extra != nil {
			*record.Session.Extra = ""
			record.Session.Extra = nil
		}
		record.Session = nil
	}
	if record.Entry != nil {
		record.Entry.DiceID = ""
		record.Entry.GroupID = ""
		record.Entry.LogName = ""
		record.Entry.Nickname = ""
		record.Entry.IMUserID = ""
		record.Entry.Message = ""
		record.Entry.RawMsgID = ""
		record.Entry.UniformID = ""
		clear(record.Entry.CommandInfo)
		record.Entry.CommandInfo = nil
		record.Entry = nil
	}
	if record.State != nil {
		record.State.DiceID = ""
		record.State.GroupID = ""
		record.State.Name = ""
		record.State = nil
	}
}
