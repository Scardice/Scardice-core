package eventstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"gorm.io/gorm"
)

const (
	logUpdateCreateSession LogUpdateKind = "session-create"
	logUpdateSetState      LogUpdateKind = "state-set"
	logUpdateAppendEntry   LogUpdateKind = "entry-append"
	logUpdateAppendOnce    LogUpdateKind = "entry-append-once"
	logUpdateEditEntry     LogUpdateKind = "entry-edit"
	logUpdateDeleteEntry   LogUpdateKind = "entry-delete"
	logUpdateDeleteSession LogUpdateKind = "session-delete"
	logUpdatePutIntent     LogUpdateKind = "intent-put"
	logUpdateFinishIntent  LogUpdateKind = "intent-finish"
	logUpdateSetUploadInfo LogUpdateKind = "session-upload-info"
)

// LogUpdateKind identifies a typed, transactionally applied archive mutation.
type LogUpdateKind string

// StoryLogEntry is the plaintext contract returned by the archive.
type StoryLogEntry struct {
	ID          uint64          `json:"id"`
	LogID       uint64          `json:"logId"`
	DiceID      string          `json:"-"`
	GroupID     string          `json:"groupId,omitempty"`
	LogName     string          `json:"logName,omitempty"`
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
	Removed     *int            `json:"-"`
	ParentID    *int            `json:"-"`
}

// StoryLogSession is an archive session summary used by commands and Story API.
type StoryLogSession struct {
	ID         uint64  `json:"id"`
	DiceID     string  `json:"-"`
	GroupID    string  `json:"groupId"`
	Name       string  `json:"name"`
	CreatedAt  int64   `json:"createdAt"`
	UpdatedAt  int64   `json:"updatedAt"`
	UploadURL  string  `json:"-"`
	UploadTime int64   `json:"-"`
	Extra      *string `json:"-"`
}

// StoryLogState persists the group's explicit current-session selection.
type StoryLogState struct {
	DiceID    string `json:"-"`
	GroupID   string `json:"-"`
	SessionID uint64 `json:"sessionId"`
	Name      string `json:"name"`
	On        bool   `json:"on"`
	// BaselineSeq is the provider sequence number of the message that last
	// switched this log on. Messages up to it were not meant for the log, so a
	// gap is never measured from before it. Zero when unknown.
	BaselineSeq int64 `json:"baselineSeq,omitempty"`
}

// StoryLogIntent carries a successful outbound message until the terminal
// effect transition commits it into the archive.
type StoryLogIntent struct {
	EffectID string        `json:"effectId"`
	Entry    StoryLogEntry `json:"entry"`
}

// LogUpdate is copied into the same Store.Commit unit as inbox/effect state.
type LogUpdate struct {
	Kind              LogUpdateKind
	DiceID            string
	GroupID           string
	Name              string
	Entry             StoryLogEntry
	State             StoryLogState
	RawMsgID          string
	Intent            StoryLogIntent
	EffectID          string
	ProviderMessageID string
	Successful        bool
	UploadURL         string
	UploadTime        int64
}

func (u LogUpdate) IsStoryLogStateUpdate() bool { return u.Kind == logUpdateSetState }

// DeletesStoryLogSession reports whether the update removes a Story session.
func (u LogUpdate) DeletesStoryLogSession() bool { return u.Kind == logUpdateDeleteSession }

func NewStoryLogStateUpdate(state StoryLogState) LogUpdate {
	return LogUpdate{Kind: logUpdateSetState, DiceID: state.DiceID, GroupID: state.GroupID, State: state, Name: state.Name}
}

// NewStoryLogCreateSessionUpdate creates the named Story session inside the
// unit that carries it; creating an existing session is a no-op.
func NewStoryLogCreateSessionUpdate(diceID, groupID, name string) LogUpdate {
	return LogUpdate{Kind: logUpdateCreateSession, DiceID: diceID, GroupID: groupID, Name: name}
}

func NewStoryLogAppendUpdate(entry StoryLogEntry) LogUpdate {
	return LogUpdate{Kind: logUpdateAppendEntry, DiceID: entry.DiceID, GroupID: entry.GroupID, Name: entry.LogName, Entry: entry}
}

// NewStoryLogAppendOnceUpdate appends the entry unless its session already
// holds an entry with the same RawMsgID. The check and the append are one step
// of the unit that carries them, so the provider's report of a message and
// Core's own archive of it, committed in either order or concurrently, leave one
// entry. RawMsgID is required.
func NewStoryLogAppendOnceUpdate(entry StoryLogEntry) LogUpdate {
	return LogUpdate{Kind: logUpdateAppendOnce, DiceID: entry.DiceID, GroupID: entry.GroupID, Name: entry.LogName, Entry: entry}
}

func NewStoryLogEditUpdate(diceID, groupID, rawMsgID, message string) LogUpdate {
	return LogUpdate{Kind: logUpdateEditEntry, DiceID: diceID, GroupID: groupID, RawMsgID: rawMsgID, Entry: StoryLogEntry{Message: message}}
}

func NewStoryLogDeleteEntryUpdate(diceID, groupID, rawMsgID string) LogUpdate {
	return LogUpdate{Kind: logUpdateDeleteEntry, DiceID: diceID, GroupID: groupID, RawMsgID: rawMsgID}
}
func NewStoryLogDeleteSessionUpdate(diceID, groupID, name string) LogUpdate {
	return LogUpdate{Kind: logUpdateDeleteSession, DiceID: diceID, GroupID: groupID, Name: name}
}

func NewStoryLogIntentPutUpdate(intent StoryLogIntent) LogUpdate {
	return LogUpdate{Kind: logUpdatePutIntent, Intent: intent}
}
func NewStoryLogFinishIntentUpdate(effectID, providerMessageID string, successful bool) LogUpdate {
	return LogUpdate{Kind: logUpdateFinishIntent, EffectID: effectID, ProviderMessageID: providerMessageID, Successful: successful}
}
func NewStoryLogUploadInfoUpdate(diceID, groupID, name, uploadURL string, uploadTime int64) LogUpdate {
	return LogUpdate{Kind: logUpdateSetUploadInfo, DiceID: diceID, GroupID: groupID, Name: name, UploadURL: uploadURL, UploadTime: uploadTime}
}

// LogRepository is the narrow archive contract shared by EventStore and the
// legacy SQL adapter. UOW-backed producers should attach LogUpdate values to
// their existing transaction instead of issuing direct repository writes.
type LogRepository interface {
	CreateStoryLog(ctx context.Context, diceID, groupID, name string) (StoryLogSession, error)
	ListStoryLogs(ctx context.Context, diceID, groupID string) ([]StoryLogSession, error)
	ListStoryLogsForDice(ctx context.Context, diceID string) ([]StoryLogSession, error)
	GetStoryLogState(ctx context.Context, diceID, groupID string) (StoryLogState, error)
	SetStoryLogState(ctx context.Context, state StoryLogState) error
	AppendStoryLogEntry(ctx context.Context, entry StoryLogEntry) error
	GetStoryLogEntries(ctx context.Context, diceID, groupID, name string) ([]StoryLogEntry, error)
	DeleteStoryLogEntryByRawID(ctx context.Context, diceID, groupID, rawID string) error
	EditStoryLogEntryByRawID(ctx context.Context, diceID, groupID, rawID, message string) error
	DeleteStoryLog(ctx context.Context, diceID, groupID, name string) error
	StoryLogStats(ctx context.Context, diceID, groupID, name string) (int64, error)
	SetStoryLogUploadInfo(ctx context.Context, diceID, groupID, name, uploadURL string, uploadTime int64) error
}

var _ LogRepository = (*GORMStore)(nil)

type storyLogEntryData struct {
	DiceID      string          `json:"diceId"`
	GroupID     string          `json:"groupId"`
	LogName     string          `json:"logName"`
	Nickname    string          `json:"nickname"`
	IMUserID    string          `json:"imUserId"`
	Time        int64           `json:"time"`
	Message     string          `json:"message"`
	IsDice      bool            `json:"isDice"`
	CommandID   int64           `json:"commandId"`
	CommandInfo json.RawMessage `json:"commandInfo,omitempty"`
	RawMsgID    string          `json:"rawMsgId,omitempty"`
	UniformID   string          `json:"uniformId"`
	Seq         *int64          `json:"seq,omitempty"`
	Removed     *int            `json:"removed,omitempty"`
	ParentID    *int            `json:"parentId,omitempty"`
}

type storyLogSessionRow struct {
	ID           uint64 `gorm:"primaryKey;autoIncrement;index:ix_story_log_sessions_updated,priority:2"`
	DiceID       string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	DiceLookup   []byte `gorm:"size:32;not null;index:ix_story_log_sessions_dice"`
	GroupID      string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Scope        string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	ScopeLookup  []byte `gorm:"size:32;not null;index:ix_story_log_sessions_scope"`
	LookupDigest []byte `gorm:"size:32;not null;index:ix_story_log_session_lookup"`
	Name         string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	UploadURL    string
	UploadTime   int64
	Extra        *string
	Version      uint64 `gorm:"not null"`
	CreatedAt    int64  `gorm:"not null;autoCreateTime:false"`
	UpdatedAt    int64  `gorm:"not null;autoUpdateTime:false;index:ix_story_log_sessions_updated,priority:1,sort:desc"`
}

func (*storyLogSessionRow) TableName() string { return tableStoryLogSessions }

type storyLogStateRow struct {
	ID          uint64 `gorm:"primaryKey;autoIncrement"`
	Scope       string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	ScopeLookup []byte `gorm:"size:32;not null;index:ix_story_log_state_scope"`
	DiceID      string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	GroupID     string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	SessionID   uint64
	Name        string `gorm:"type:bytes;size:16777217;serializer:raw_string"`
	On          bool
	BaselineSeq int64
	Version     uint64 `gorm:"not null"`
}

func (*storyLogStateRow) TableName() string { return tableStoryLogStates }

type logArchiveEntryRow struct {
	ID           uint64 `gorm:"primaryKey;autoIncrement"`
	DiceID       string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	GroupID      string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Scope        string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	ScopeLookup  []byte `gorm:"size:32;not null;index:ix_story_log_entries_scope_session,priority:1;index:ix_story_log_entries_raw,priority:1"`
	SessionID    uint64 `gorm:"not null;index:ix_story_log_entries_scope_session,priority:2;index:ix_story_log_entries_raw,priority:2"`
	RawMsgID     string `gorm:"type:bytes;size:16777217;serializer:raw_string"`
	RawMsgLookup []byte `gorm:"size:32;not null;index:ix_story_log_entries_raw,priority:3"`
	Payload      []byte
	Version      uint64 `gorm:"not null"`
}

func (*logArchiveEntryRow) TableName() string { return tableStoryLogEntries }

type logArchiveIntentRow struct {
	EffectID    string `gorm:"type:varchar(255);primaryKey;uniqueIndex:ux_story_log_intent_effect"`
	DiceID      string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	GroupID     string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Scope       string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	ScopeLookup []byte `gorm:"size:32;not null;index:ix_story_log_intent_scope_session,priority:1"`
	SessionID   uint64 `gorm:"not null;index:ix_story_log_intent_scope_session,priority:2"`
	Payload     []byte
}

func (*logArchiveIntentRow) TableName() string { return tableStoryLogIntents }

func sameStoryLogIntentRow(left, right logArchiveIntentRow) bool {
	return left.EffectID == right.EffectID && left.SessionID == right.SessionID &&
		left.Scope == right.Scope && left.DiceID == right.DiceID && left.GroupID == right.GroupID &&
		bytes.Equal(left.Payload, right.Payload)
}

func storyLogScope(diceID, groupID string) (string, error) {
	if strings.TrimSpace(diceID) == "" || strings.TrimSpace(groupID) == "" {
		return "", ErrInvalidMetadata
	}
	return privacyCanonical(diceID, groupID), nil
}

func entryData(entry StoryLogEntry) storyLogEntryData {
	return storyLogEntryData{
		DiceID: entry.DiceID, GroupID: entry.GroupID, LogName: entry.LogName,
		Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: entry.Time, Message: entry.Message,
		IsDice: entry.IsDice, CommandID: entry.CommandID, CommandInfo: entry.CommandInfo,
		RawMsgID: entry.RawMsgID, UniformID: entry.UniformID, Seq: entry.Seq,
		Removed: entry.Removed, ParentID: entry.ParentID,
	}
}

func (s *GORMStore) applyStoryLogUpdates(ctx context.Context, tx *gorm.DB, work UnitOfWork) error {
	ctx = withStoryLogRevisionPlan(ctx, work)
	for _, update := range work.LogUpdates {
		if err := s.applyStoryLogUpdate(ctx, tx, update); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) applyStoryLogUpdate(ctx context.Context, tx *gorm.DB, u LogUpdate) error {
	var intent *logArchiveIntentRow
	var scope string
	if u.Kind == logUpdateFinishIntent {
		var row logArchiveIntentRow
		if err := tx.Where("effect_id = ?", u.EffectID).Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return ErrParticipantFailure
		}
		intent, scope = &row, row.Scope
	} else {
		var err error
		scope, _, err = s.storyLogScopeForUpdate(ctx, tx, u)
		if err != nil {
			return err
		}
	}
	if !storyLogRevisionGuarded(ctx, scope) {
		if err := s.advanceStoryLogScopeRevisionTx(tx, scope); err != nil {
			return err
		}
		ctx = withStoryLogRevisionAdvanced(ctx, scope)
	}
	if intent != nil {
		var current logArchiveIntentRow
		if err := locked(tx).Where("effect_id = ?", intent.EffectID).Take(&current).Error; err != nil {
			return ErrParticipantConflict
		}
		if !sameStoryLogIntentRow(*intent, current) {
			return ErrParticipantConflict
		}
		if !u.Successful {
			return tx.Delete(&current).Error
		}
		var session storyLogSessionRow
		err := storyScopeQuery(locked(tx), scope).Where("id = ?", current.SessionID).Take(&session).Error
		// Session IDs bind intents to the original session, never a replacement
		// created under the same name after deletion.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Delete(&current).Error
		}
		if err != nil {
			return ErrParticipantFailure
		}
		entry, err := storyLogEntryFromData(current.Payload)
		if err != nil {
			return err
		}
		if entry.DiceID != current.DiceID || entry.GroupID != current.GroupID || entry.LogName != session.Name {
			return ErrInvalidMetadata
		}
		if u.ProviderMessageID != "" {
			entry.RawMsgID = u.ProviderMessageID
		}
		var existing logArchiveEntryRow
		found := false
		if u.ProviderMessageID != "" {
			existing, found, err = s.storyLogEntryRowByRawTx(ctx, tx, scope, session.ID, entry.RawMsgID)
			if err != nil {
				return err
			}
		}
		if found {
			err = s.replaceStoryLogEntryRowTx(ctx, tx, existing, entry)
		} else {
			err = s.appendStoryLogEntryToSessionTx(ctx, tx, session, entry)
		}
		if err != nil {
			return err
		}
		return tx.Delete(&current).Error
	}
	if u.Kind == logUpdatePutIntent {
		return s.putStoryLogIntent(ctx, tx, u.Intent)
	}
	switch u.Kind {
	case logUpdateCreateSession:
		var row storyLogSessionRow
		err := storySessionQuery(tx, scope, u.Name).Take(&row).Error
		if err == nil {
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		now := s.task5Now().Unix()
		return tx.Create(&storyLogSessionRow{Scope: scope, DiceID: u.DiceID, GroupID: u.GroupID, Name: u.Name, Version: 1, CreatedAt: now, UpdatedAt: now}).Error
	case logUpdateSetState:
		state := u.State
		if state.Name != "" || state.SessionID != 0 {
			var session storyLogSessionRow
			query := storyScopeQuery(tx, scope)
			if state.SessionID != 0 {
				query = query.Where("id = ?", state.SessionID)
			} else {
				query = storySessionQuery(tx, scope, state.Name)
			}
			if err := query.Take(&session).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrNotFound
				}
				return ErrParticipantFailure
			}
			if state.Name != session.Name {
				return ErrInvalidMetadata
			}
			state.SessionID = session.ID
		} else if state.On {
			return ErrInvalidMetadata
		}
		var old storyLogStateRow
		version := uint64(1)
		if err := storyScopeQuery(tx, scope).Take(&old).Error; err == nil {
			var err error
			version, err = nextVersion(old.Version)
			if err != nil {
				return err
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		return tx.Save(&storyLogStateRow{ID: old.ID, Scope: scope, ScopeLookup: old.ScopeLookup, DiceID: u.DiceID, GroupID: u.GroupID, SessionID: state.SessionID, Name: state.Name, On: state.On, BaselineSeq: state.BaselineSeq, Version: version}).Error
	case logUpdateAppendEntry:
		return s.appendStoryLogEntryTx(ctx, tx, u.Entry)
	case logUpdateAppendOnce:
		if u.Entry.RawMsgID == "" {
			return ErrInvalidMetadata
		}
		var session storyLogSessionRow
		if err := storySessionQuery(locked(tx), scope, u.Entry.LogName).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return ErrParticipantFailure
		}
		if _, found, err := s.storyLogEntryRowByRawTx(ctx, tx, scope, session.ID, u.Entry.RawMsgID); err != nil || found {
			return err
		}
		return s.appendStoryLogEntryToSessionTx(ctx, tx, session, u.Entry)
	case logUpdateEditEntry, logUpdateDeleteEntry:
		return s.mutateStoryLogEntryTx(ctx, tx, scope, u.RawMsgID, u.Entry.Message, u.Kind == logUpdateDeleteEntry)
	case logUpdateDeleteSession:
		var session storyLogSessionRow
		if err := storySessionQuery(locked(tx), scope, u.Name).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return ErrParticipantFailure
		}
		if err := storyScopeQuery(tx, scope).Where("session_id = ?", session.ID).Delete(&logArchiveIntentRow{}).Error; err != nil {
			return ErrParticipantFailure
		}
		if err := storyScopeQuery(tx, scope).Where("session_id = ?", session.ID).Delete(&logArchiveEntryRow{}).Error; err != nil {
			return ErrParticipantFailure
		}
		if err := storyScopeQuery(tx, scope).Where("session_id = ?", session.ID).Delete(&storyLogStateRow{}).Error; err != nil {
			return ErrParticipantFailure
		}
		return tx.Delete(&session).Error
	case logUpdateSetUploadInfo:
		if u.UploadURL == "" || u.UploadTime <= 0 {
			return ErrInvalidMetadata
		}
		var session storyLogSessionRow
		if err := storySessionQuery(locked(tx), scope, u.Name).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return ErrParticipantFailure
		}
		version, err := nextVersion(session.Version)
		if err != nil {
			return err
		}
		return tx.Model(&session).Updates(map[string]any{"upload_url": u.UploadURL, "upload_time": u.UploadTime, "version": version}).Error
	default:
		return ErrInvalidMetadata
	}
}

func (s *GORMStore) putStoryLogIntent(ctx context.Context, tx *gorm.DB, intent StoryLogIntent) error {
	scope, err := storyLogScope(intent.Entry.DiceID, intent.Entry.GroupID)
	if err != nil || intent.EffectID == "" || intent.Entry.LogName == "" {
		return ErrInvalidMetadata
	}
	var session storyLogSessionRow
	if err := storySessionQuery(locked(tx), scope, intent.Entry.LogName).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return ErrParticipantFailure
	}
	payload, err := json.Marshal(entryData(intent.Entry))
	if err != nil {
		return ErrInvalidMetadata
	}
	return tx.Create(&logArchiveIntentRow{EffectID: intent.EffectID, Scope: scope, DiceID: intent.Entry.DiceID, GroupID: intent.Entry.GroupID, SessionID: session.ID, Payload: payload}).Error
}

func (s *GORMStore) appendStoryLogEntryTx(ctx context.Context, tx *gorm.DB, entry StoryLogEntry) error {
	scope, err := storyLogScope(entry.DiceID, entry.GroupID)
	if err != nil {
		return err
	}
	var session storyLogSessionRow
	err = storySessionQuery(tx, scope, entry.LogName).Take(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := s.applyStoryLogUpdate(ctx, tx, NewStoryLogCreateSessionUpdate(entry.DiceID, entry.GroupID, entry.LogName)); err != nil {
			return err
		}
		err = storySessionQuery(tx, scope, entry.LogName).Take(&session).Error
	}
	if err != nil {
		return ErrParticipantFailure
	}
	return s.appendStoryLogEntryToSessionTx(ctx, tx, session, entry)
}

func (s *GORMStore) storyLogEntryRowByRawTx(_ context.Context, tx *gorm.DB, scope string, sessionID uint64, rawID string) (logArchiveEntryRow, bool, error) {
	var row logArchiveEntryRow
	err := rawStringQuery(storyScopeQuery(tx, scope).Where("session_id = ? AND raw_msg_lookup = ?", sessionID, Digest("story-raw-lookup/v1", rawID)), "raw_msg_id", rawID).Order("id ASC").Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return logArchiveEntryRow{}, false, nil
	}
	if err != nil {
		return logArchiveEntryRow{}, false, ErrParticipantFailure
	}
	return row, true, nil
}

func (s *GORMStore) replaceStoryLogEntryRowTx(ctx context.Context, tx *gorm.DB, row logArchiveEntryRow, entry StoryLogEntry) error {
	if entry.Time == 0 {
		entry.Time = s.task5Now().Unix()
	}
	payload, err := json.Marshal(entryData(entry))
	if err != nil {
		return ErrInvalidMetadata
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return err
	}
	if err := tx.Model(&row).Updates(map[string]any{"payload": payload, "raw_msg_id": []byte(entry.RawMsgID), "raw_msg_lookup": Digest("story-raw-lookup/v1", entry.RawMsgID), "version": version}).Error; err != nil {
		return ErrParticipantFailure
	}
	return s.touchStoryLogSessionTx(ctx, tx, row.Scope, row.SessionID)
}

func (s *GORMStore) appendStoryLogEntryToSessionTx(ctx context.Context, tx *gorm.DB, session storyLogSessionRow, entry StoryLogEntry) error {
	if entry.Time == 0 {
		entry.Time = s.task5Now().Unix()
	}
	payload, err := json.Marshal(entryData(entry))
	if err != nil {
		return ErrInvalidMetadata
	}
	row := logArchiveEntryRow{Scope: session.Scope, DiceID: entry.DiceID, GroupID: entry.GroupID, SessionID: session.ID, RawMsgID: entry.RawMsgID, Payload: payload, Version: 1}
	if err := tx.Create(&row).Error; err != nil {
		return ErrParticipantFailure
	}
	return s.touchStoryLogSessionTx(ctx, tx, session.Scope, session.ID)
}

func (s *GORMStore) touchStoryLogSessionTx(_ context.Context, tx *gorm.DB, scope string, sessionID uint64) error {
	var session storyLogSessionRow
	if err := storyScopeQuery(locked(tx), scope).Where("id = ?", sessionID).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return ErrParticipantFailure
	}
	version, err := nextVersion(session.Version)
	if err != nil {
		return err
	}
	return tx.Model(&session).Updates(map[string]any{"updated_at": s.task5Now().Unix(), "upload_url": "", "upload_time": int64(0), "version": version}).Error
}

func (s *GORMStore) mutateStoryLogEntryTx(ctx context.Context, tx *gorm.DB, scope, rawID, message string, remove bool) error {
	var row logArchiveEntryRow
	if err := rawStringQuery(storyScopeQuery(tx, scope).Where("raw_msg_lookup = ?", Digest("story-raw-lookup/v1", rawID)), "raw_msg_id", rawID).Order("id DESC").Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return ErrParticipantFailure
	}
	if remove {
		if err := tx.Delete(&row).Error; err != nil {
			return ErrParticipantFailure
		}
		return s.touchStoryLogSessionTx(ctx, tx, scope, row.SessionID)
	}
	entry, err := s.storyLogEntry(ctx, row)
	if err != nil {
		return err
	}
	if entry.Message == message {
		return nil
	}
	entry.Message = message
	return s.replaceStoryLogEntryRowTx(ctx, tx, row, entry)
}

func (s *GORMStore) storyLogSession(_ context.Context, row storyLogSessionRow) (StoryLogSession, error) {
	return StoryLogSession{ID: row.ID, DiceID: row.DiceID, GroupID: row.GroupID, Name: row.Name, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, UploadURL: row.UploadURL, UploadTime: row.UploadTime, Extra: cloneString(row.Extra)}, nil
}

func storyLogEntryFromData(payload []byte) (StoryLogEntry, error) {
	var p storyLogEntryData
	if json.Unmarshal(payload, &p) != nil {
		return StoryLogEntry{}, ErrInvalidMetadata
	}
	return StoryLogEntry{DiceID: p.DiceID, GroupID: p.GroupID, LogName: p.LogName, Nickname: p.Nickname, IMUserID: p.IMUserID, Time: p.Time, Message: p.Message, IsDice: p.IsDice, CommandID: p.CommandID, CommandInfo: p.CommandInfo, RawMsgID: p.RawMsgID, UniformID: p.UniformID, Seq: p.Seq, Removed: p.Removed, ParentID: p.ParentID}, nil
}

func (s *GORMStore) storyLogEntry(_ context.Context, row logArchiveEntryRow) (StoryLogEntry, error) {
	entry, err := storyLogEntryFromData(row.Payload)
	if err != nil {
		return StoryLogEntry{}, err
	}
	if entry.DiceID != row.DiceID || entry.GroupID != row.GroupID || entry.RawMsgID != row.RawMsgID {
		return StoryLogEntry{}, ErrInvalidMetadata
	}
	entry.ID, entry.LogID = row.ID, row.SessionID
	return entry, nil
}

func (s *GORMStore) CreateStoryLog(ctx context.Context, diceID, groupID, name string) (StoryLogSession, error) {
	if strings.TrimSpace(name) == "" {
		return StoryLogSession{}, ErrInvalidMetadata
	}
	if err := s.commitLogUpdate(ctx, NewStoryLogCreateSessionUpdate(diceID, groupID, name)); err != nil {
		return StoryLogSession{}, err
	}
	scope, err := storyLogScope(diceID, groupID)
	if err != nil {
		return StoryLogSession{}, err
	}
	var row storyLogSessionRow
	if err := storySessionQuery(s.db.ReadGORM().WithContext(ctx), scope, name).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return StoryLogSession{}, ErrParticipantConflict
		}
		return StoryLogSession{}, ErrParticipantFailure
	}
	return s.storyLogSession(ctx, row)
}

func (s *GORMStore) ListStoryLogs(ctx context.Context, diceID, groupID string) ([]StoryLogSession, error) {
	scope, err := storyLogScope(diceID, groupID)
	if err != nil {
		return nil, err
	}
	return s.listStoryLogSessions(ctx, storyScopeQuery(s.db.ReadGORM(), scope))
}

func (s *GORMStore) ListStoryLogsForDice(ctx context.Context, diceID string) ([]StoryLogSession, error) {
	if strings.TrimSpace(diceID) == "" {
		return nil, ErrInvalidMetadata
	}
	return s.listStoryLogSessions(ctx, storyDiceQuery(s.db.ReadGORM(), diceID))
}

func (s *GORMStore) listStoryLogSessions(ctx context.Context, query *gorm.DB) ([]StoryLogSession, error) {
	if err := s.requireReady(ctx); err != nil {
		return nil, err
	}
	var rows []storyLogSessionRow
	if err := query.WithContext(ctx).Order("updated_at DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	out := make([]StoryLogSession, 0, len(rows))
	for _, row := range rows {
		value, _ := s.storyLogSession(ctx, row)
		out = append(out, value)
	}
	return out, nil
}

func (s *GORMStore) GetStoryLogState(ctx context.Context, diceID, groupID string) (StoryLogState, error) {
	state, _, err := s.getStoryLogStateSnapshot(ctx, diceID, groupID)
	return state, err
}
func (s *GORMStore) SetStoryLogState(ctx context.Context, state StoryLogState) error {
	return s.commitLogUpdate(ctx, NewStoryLogStateUpdate(state))
}
func (s *GORMStore) AppendStoryLogEntry(ctx context.Context, entry StoryLogEntry) error {
	return s.commitLogUpdate(ctx, NewStoryLogAppendUpdate(entry))
}
func (s *GORMStore) DeleteStoryLogEntryByRawID(ctx context.Context, diceID, groupID, rawID string) error {
	return s.commitLogUpdate(ctx, NewStoryLogDeleteEntryUpdate(diceID, groupID, rawID))
}
func (s *GORMStore) EditStoryLogEntryByRawID(ctx context.Context, diceID, groupID, rawID, message string) error {
	return s.commitLogUpdate(ctx, NewStoryLogEditUpdate(diceID, groupID, rawID, message))
}
func (s *GORMStore) DeleteStoryLog(ctx context.Context, diceID, groupID, name string) error {
	return s.commitLogUpdate(ctx, NewStoryLogDeleteSessionUpdate(diceID, groupID, name))
}
func (s *GORMStore) SetStoryLogUploadInfo(ctx context.Context, diceID, groupID, name, uploadURL string, uploadTime int64) error {
	if uploadURL == "" {
		return nil
	}
	return s.commitLogUpdate(ctx, NewStoryLogUploadInfoUpdate(diceID, groupID, name, uploadURL, uploadTime))
}
func (s *GORMStore) commitLogUpdate(ctx context.Context, update LogUpdate) error {
	_, err := s.Commit(ctx, UnitOfWork{LogUpdates: []LogUpdate{update}})
	return err
}
func (s *GORMStore) GetStoryLogEntries(ctx context.Context, diceID, groupID, name string) ([]StoryLogEntry, error) {
	if err := s.requireReady(ctx); err != nil {
		return nil, err
	}
	scope, err := storyLogScope(diceID, groupID)
	if err != nil {
		return nil, err
	}
	out := make([]StoryLogEntry, 0)
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		var session storyLogSessionRow
		if err := storySessionQuery(tx, scope, name).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return ErrParticipantFailure
		}
		var rows []logArchiveEntryRow
		if err := storyScopeQuery(tx, scope).Where("session_id = ?", session.ID).Order("id ASC").Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		for _, row := range rows {
			entry, err := s.storyLogEntry(ctx, row)
			if err != nil {
				return err
			}
			out = append(out, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return orderStoryLogEntries(out), nil
}

// orderStoryLogEntries puts entries, given in the order they were stored, into
// reading order: by time, then by the message's place in the group's sequence,
// then by storage order.
//
// Stored order only says when an entry was written. A message recovered after
// an outage is written after everything that arrived live, so within the same
// second it would read after messages it preceded. Sequence numbers say where
// a message really sits, so they decide ties. An entry without one takes the
// place of what explains it: a reply is anchored to the message that triggered
// it (same command), anything else to the latest sequence stored before it.
// Every entry gets its own key, so the result is a total order; entries without
// any sequence all share anchor 0 and read by time and storage order as before.
func orderStoryLogEntries(entries []StoryLogEntry) []StoryLogEntry {
	triggers := make(map[int64]int64)
	for _, entry := range entries {
		if entry.Seq != nil && !entry.IsDice && entry.CommandID != 0 {
			triggers[entry.CommandID] = *entry.Seq
		}
	}
	type keyed struct {
		entry  StoryLogEntry
		anchor int64
	}
	keys := make([]keyed, len(entries))
	var latest int64
	for i, entry := range entries {
		anchor := latest
		switch trigger, found := triggers[entry.CommandID]; {
		case entry.Seq != nil:
			anchor, latest = *entry.Seq, max(latest, *entry.Seq)
		case entry.IsDice && entry.CommandID != 0 && found:
			anchor = trigger
		}
		keys[i] = keyed{entry: entry, anchor: anchor}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.entry.Time != b.entry.Time {
			return a.entry.Time < b.entry.Time
		}
		if a.anchor != b.anchor {
			return a.anchor < b.anchor
		}
		return a.entry.ID < b.entry.ID
	})
	ordered := make([]StoryLogEntry, len(keys))
	for i, key := range keys {
		ordered[i] = key.entry
	}
	return ordered
}

func (s *GORMStore) QueueStoryLogIntent(ctx context.Context, intent StoryLogIntent) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdatePutIntent, Intent: intent})
}
func (s *GORMStore) CompleteStoryLogIntent(ctx context.Context, effectID string, success bool) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdateFinishIntent, EffectID: effectID, Successful: success})
}

// StoryLogPage returns a deterministic time-ascending slice and count.
func (s *GORMStore) StoryLogPage(ctx context.Context, diceID, groupID, name string, page, pageSize int) (int, []StoryLogEntry, error) {
	items, err := s.GetStoryLogEntries(ctx, diceID, groupID, name)
	if err != nil {
		return 0, nil, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return len(items), []StoryLogEntry{}, nil
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return len(items), items[start:end], nil
}

func (s *GORMStore) StoryLogStats(ctx context.Context, diceID, groupID, name string) (int64, error) {
	scope, err := storyLogScope(diceID, groupID)
	if err != nil {
		return 0, err
	}
	var session storyLogSessionRow
	if err := storySessionQuery(s.db.ReadGORM().WithContext(ctx), scope, name).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrNotFound
		}
		return 0, ErrParticipantFailure
	}
	items, err := s.GetStoryLogEntries(ctx, diceID, groupID, name)
	if err != nil {
		return 0, err
	}
	var count int64
	for _, item := range items {
		if item.Removed == nil {
			count++
		}
	}
	return count, nil
}

func validateStoryLogUpdates(updates []LogUpdate) error {
	if len(updates) > 128 {
		return &OversizeError{Bound: "story log updates", Limit: 128, Actual: len(updates)}
	}
	for _, update := range updates {
		switch update.Kind {
		case logUpdateFinishIntent:
			if strings.TrimSpace(update.EffectID) == "" {
				return ErrInvalidMetadata
			}
			continue
		case logUpdatePutIntent:
			if strings.TrimSpace(update.Intent.EffectID) == "" ||
				strings.TrimSpace(update.Intent.Entry.DiceID) == "" ||
				strings.TrimSpace(update.Intent.Entry.GroupID) == "" ||
				strings.TrimSpace(update.Intent.Entry.LogName) == "" {
				return ErrInvalidMetadata
			}
			continue
		case logUpdateCreateSession, logUpdateSetState, logUpdateAppendEntry, logUpdateAppendOnce,
			logUpdateEditEntry, logUpdateDeleteEntry, logUpdateDeleteSession, logUpdateSetUploadInfo:
		default:
			return ErrInvalidMetadata
		}
		if strings.TrimSpace(update.DiceID) == "" || strings.TrimSpace(update.GroupID) == "" {
			return ErrInvalidMetadata
		}
		switch update.Kind {
		case logUpdateCreateSession, logUpdateDeleteSession, logUpdateSetUploadInfo:
			if strings.TrimSpace(update.Name) == "" {
				return ErrInvalidMetadata
			}
			if update.Kind == logUpdateSetUploadInfo && (update.UploadURL == "" || update.UploadTime <= 0) {
				return ErrInvalidMetadata
			}
		case logUpdateSetState:
			if update.State.SessionID == 0 && update.State.Name == "" && update.State.On {
				return ErrInvalidMetadata
			}
		case logUpdateAppendEntry, logUpdateAppendOnce:
			if strings.TrimSpace(update.Entry.DiceID) == "" ||
				strings.TrimSpace(update.Entry.GroupID) == "" ||
				strings.TrimSpace(update.Entry.LogName) == "" {
				return ErrInvalidMetadata
			}
		case logUpdateEditEntry, logUpdateDeleteEntry:
			if update.RawMsgID == "" {
				return ErrInvalidMetadata
			}
		case logUpdatePutIntent, logUpdateFinishIntent:
			// Validated and continued by the preceding switch.
		}
	}
	return nil
}
