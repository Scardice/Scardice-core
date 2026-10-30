package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	logUpdateCreateSession LogUpdateKind = "session-create"
	logUpdateSetState      LogUpdateKind = "state-set"
	logUpdateAppendEntry   LogUpdateKind = "entry-append"
	logUpdateEditEntry     LogUpdateKind = "entry-edit"
	logUpdateDeleteEntry   LogUpdateKind = "entry-delete"
	logUpdateDeleteSession LogUpdateKind = "session-delete"
	logUpdatePutIntent     LogUpdateKind = "intent-put"
	logUpdateFinishIntent  LogUpdateKind = "intent-finish"
	logUpdateSetUploadInfo LogUpdateKind = "session-upload-info"
)

// LogUpdateKind identifies a typed, transactionally applied archive mutation.
type LogUpdateKind string

// StoryLogEntry is the plaintext contract returned by the archive. Session
// identities and user-authored fields are encrypted; database rows also expose
// surrogate IDs, keyed HMAC indexes, and indexed session timestamps.
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

func NewStoryLogStateUpdate(state StoryLogState) LogUpdate {
	return LogUpdate{Kind: logUpdateSetState, DiceID: state.DiceID, GroupID: state.GroupID, State: state, Name: state.Name}
}

func NewStoryLogAppendUpdate(entry StoryLogEntry) LogUpdate {
	return LogUpdate{Kind: logUpdateAppendEntry, DiceID: entry.DiceID, GroupID: entry.GroupID, Name: entry.LogName, Entry: entry}
}

func NewStoryLogEditUpdate(diceID, groupID, rawMsgID, message string) LogUpdate {
	return LogUpdate{Kind: logUpdateEditEntry, DiceID: diceID, GroupID: groupID, RawMsgID: rawMsgID, Entry: StoryLogEntry{Message: message}}
}

func NewStoryLogDeleteEntryUpdate(diceID, groupID, rawMsgID string) LogUpdate {
	return LogUpdate{Kind: logUpdateDeleteEntry, DiceID: diceID, GroupID: groupID, RawMsgID: rawMsgID}
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

type storyLogSessionPrivate struct {
	DiceID     string  `json:"diceId"`
	GroupID    string  `json:"groupId"`
	Name       string  `json:"name"`
	UploadURL  string  `json:"uploadUrl,omitempty"`
	UploadTime int64   `json:"uploadTime,omitempty"`
	Extra      *string `json:"extra,omitempty"`
}

type storyLogStatePrivate struct {
	DiceID      string `json:"diceId"`
	GroupID     string `json:"groupId"`
	SessionID   uint64 `json:"sessionId"`
	Name        string `json:"name"`
	On          bool   `json:"on"`
	BaselineSeq int64  `json:"baselineSeq,omitempty"`
}

type storyLogEntryPrivate struct {
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

type storyLogIntentPrivate struct {
	SessionID uint64               `json:"sessionId"`
	Entry     storyLogEntryPrivate `json:"entry"`
}

type storyLogSessionRow struct {
	ID              uint64 `gorm:"primaryKey;autoIncrement;index:ix_story_log_sessions_updated,priority:2"`
	DiceHMAC        []byte `gorm:"size:32;not null;index:ix_story_log_sessions_dice"`
	ScopeHMAC       []byte `gorm:"size:32;not null;uniqueIndex:ux_story_log_session_scope_name,priority:1;index:ix_story_log_session_owner,priority:2"`
	OwnerHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_session_owner,priority:1"`
	NameHMAC        []byte `gorm:"size:32;not null;uniqueIndex:ux_story_log_session_scope_name,priority:2"`
	Payload         []byte `gorm:"not null"`
	Nonce           []byte `gorm:"not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	Version         uint64 `gorm:"not null"`
	CreatedAt       int64  `gorm:"not null;autoCreateTime:false"`
	UpdatedAt       int64  `gorm:"not null;autoUpdateTime:false;index:ix_story_log_sessions_updated,priority:1,sort:desc"`
}

func (storyLogSessionRow) TableName() string { return "story_log_sessions" }

type storyLogStateRow struct {
	ScopeHMAC       []byte `gorm:"size:32;primaryKey;uniqueIndex:ux_story_log_state_scope"`
	OwnerHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_state_owner"`
	Payload         []byte `gorm:"not null"`
	Nonce           []byte `gorm:"not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	Version         uint64 `gorm:"not null"`
}

func (storyLogStateRow) TableName() string { return "story_log_states" }

type logArchiveEntryRow struct {
	ID              uint64 `gorm:"primaryKey;autoIncrement"`
	ScopeHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_entries_scope_session,priority:1;index:ix_story_log_entries_raw,priority:1"`
	OwnerHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_entries_owner"`
	SessionID       uint64 `gorm:"not null;index:ix_story_log_entries_scope_session,priority:2;index:ix_story_log_entries_raw,priority:2"`
	RawMsgHMAC      []byte `gorm:"size:32;index:ix_story_log_entries_raw,priority:3"`
	Payload         []byte `gorm:"not null"`
	Nonce           []byte `gorm:"not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	Version         uint64 `gorm:"not null"`
}

func (logArchiveEntryRow) TableName() string { return "story_log_entries" }

type logArchiveIntentRow struct {
	EffectID        string `gorm:"type:varchar(255);primaryKey;uniqueIndex:ux_story_log_intent_effect"`
	ScopeHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_intent_owner,priority:2;index:ix_story_log_intent_scope_session,priority:1"`
	OwnerHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_intent_owner,priority:1"`
	SessionID       uint64 `gorm:"not null;index:ix_story_log_intent_scope_session,priority:2"`
	Payload         []byte `gorm:"not null"`
	Nonce           []byte `gorm:"not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	Version         uint64 `gorm:"not null"`
}

func (logArchiveIntentRow) TableName() string { return "story_log_outbound_intents" }

func (s *GORMStore) storyLogKeys(ctx context.Context, diceID, groupID, name string) (scope, owner, nameKey []byte, err error) {
	if strings.TrimSpace(diceID) == "" || strings.TrimSpace(groupID) == "" {
		return nil, nil, nil, ErrInvalidMetadata
	}
	scope, err = s.privacyHMAC(ctx, "story-log-scope/v1", privacyCanonical(diceID, groupID))
	if err != nil {
		return nil, nil, nil, err
	}
	owner, err = privacySubjectKey(ctx, s, groupID)
	if err != nil {
		return nil, nil, nil, err
	}
	if name != "" {
		nameKey, err = s.privacyHMAC(ctx, "story-log-name/v1", privacyCanonical(diceID, groupID, name))
	}
	return scope, owner, nameKey, err
}
func (s *GORMStore) storyLogDiceHMAC(ctx context.Context, diceID string) ([]byte, error) {
	if strings.TrimSpace(diceID) == "" {
		return nil, ErrInvalidMetadata
	}
	return s.privacyHMAC(ctx, "story-log-dice/v1", diceID)
}

func logAADIdentity(scope []byte, rowID uint64) string {
	return fmt.Sprintf("%x/%d", scope, rowID)
}
func logOwner(owner []byte) string { return "hmac:" + hex.EncodeToString(owner) }
func logIntentAADID(effectID string) uint64 {
	sum := sha256.Sum256([]byte(effectID))
	return binary.BigEndian.Uint64(sum[:8])
}

func storyLogRawIdentity(scope []byte, rawID string) string {
	return privacyCanonical(hex.EncodeToString(scope), rawID)
}
func (s *GORMStore) storyLogRawHMAC(ctx context.Context, scope []byte, rawID string) ([]byte, error) {
	return s.privacyHMAC(ctx, "story-log-raw-id/v1", storyLogRawIdentity(scope, rawID))
}

func (s *GORMStore) sealStoryLog(tx *gorm.DB, ctx context.Context, domain string, scope, owner []byte, id, version uint64, plain []byte) ([]byte, []byte, string, error) {
	if s == nil || s.keySource == nil {
		return nil, nil, "", ErrKeySourceUnavailable
	}
	return s.sealBoundPayloadInMutation(ctx, tx, domain, logAADIdentity(scope, id), logOwner(owner), version, plain)
}
func (s *GORMStore) openStoryLog(ctx context.Context, domain string, scope, owner []byte, id, version uint64, keyID string, cipherText, nonce []byte) ([]byte, error) {
	if s == nil || s.keySource == nil {
		return nil, ErrKeySourceUnavailable
	}
	return a6Open(ctx, s.keySource, domain, logAADIdentity(scope, id), logOwner(owner), version, keyID, cipherText, nonce)
}

func (s *GORMStore) applyStoryLogUpdates(ctx context.Context, tx *gorm.DB, work UnitOfWork) error {
	for _, update := range work.LogUpdates {
		if err := s.applyStoryLogUpdate(ctx, tx, update); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) applyStoryLogUpdate(ctx context.Context, tx *gorm.DB, u LogUpdate) error {
	if u.Kind == logUpdateFinishIntent {
		var intent logArchiveIntentRow
		if err := tx.Where("effect_id = ?", u.EffectID).Take(&intent).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return ErrParticipantFailure
		}
		if !u.Successful {
			return tx.Delete(&intent).Error
		}
		if intent.Version == 1 {
			entry, err := s.storyLogIntentPayload(ctx, intent)
			if err != nil {
				return ErrAuthenticationFailed
			}
			scope, owner, _, err := s.storyLogKeys(ctx, entry.DiceID, entry.GroupID, entry.LogName)
			if err != nil || !bytes.Equal(scope, intent.ScopeHMAC) || !bytes.Equal(owner, intent.OwnerHMAC) {
				return ErrAuthenticationFailed
			}
			// Version 1 intents lack a session identity. Retire authenticated old
			// intents at terminal completion rather than risk recreating a deleted
			// session or attaching a reply to a same-named replacement.
			return tx.Delete(&intent).Error
		}
		if intent.Version != 2 {
			return ErrAuthenticationFailed
		}
		plain, err := s.openStoryLog(ctx, "story-log-intent/v2", intent.ScopeHMAC, intent.OwnerHMAC, logIntentAADID(u.EffectID), intent.Version, intent.EncryptionKeyID, intent.Payload, intent.Nonce)
		if err != nil {
			return ErrAuthenticationFailed
		}
		var private storyLogIntentPrivate
		if json.Unmarshal(plain, &private) != nil || private.SessionID == 0 || private.SessionID != intent.SessionID {
			return ErrAuthenticationFailed
		}
		entry := private.Entry
		scope, owner, nameKey, err := s.storyLogKeys(ctx, entry.DiceID, entry.GroupID, entry.LogName)
		if err != nil || !bytes.Equal(scope, intent.ScopeHMAC) || !bytes.Equal(owner, intent.OwnerHMAC) {
			return ErrAuthenticationFailed
		}
		if err := privacyCheckSubjectFence(ctx, tx, owner); err != nil {
			return err
		}
		var session storyLogSessionRow
		err = locked(tx).Where("id = ? AND scope_hmac = ? AND name_hmac = ?", private.SessionID, scope, nameKey).Take(&session).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Delete(&intent).Error
		}
		if err != nil {
			return ErrParticipantFailure
		}
		if !bytes.Equal(session.OwnerHMAC, owner) {
			return ErrAuthenticationFailed
		}
		sessionPrivate, err := s.storyLogSession(ctx, session)
		if err != nil || sessionPrivate.DiceID != entry.DiceID || sessionPrivate.GroupID != entry.GroupID || sessionPrivate.Name != entry.LogName {
			return ErrAuthenticationFailed
		}
		rawMsgID := entry.RawMsgID
		if u.ProviderMessageID != "" {
			rawMsgID = u.ProviderMessageID
		}
		entryRecord := StoryLogEntry{
			DiceID: entry.DiceID, GroupID: entry.GroupID, LogName: entry.LogName,
			Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: entry.Time, Message: entry.Message,
			IsDice: entry.IsDice, CommandID: entry.CommandID, CommandInfo: entry.CommandInfo,
			RawMsgID: rawMsgID, UniformID: entry.UniformID, Seq: entry.Seq, Removed: entry.Removed, ParentID: entry.ParentID,
		}
		if err := s.appendStoryLogEntryToSessionTx(ctx, tx, scope, owner, session, entryRecord); err != nil {
			return err
		}
		return tx.Delete(&intent).Error
	}
	if u.Kind == logUpdatePutIntent {
		return s.putStoryLogIntent(ctx, tx, u.Intent)
	}
	scope, owner, nameKey, err := s.storyLogKeys(ctx, u.DiceID, u.GroupID, u.Name)
	if err != nil {
		return err
	}
	if err := privacyCheckSubjectFence(ctx, tx, owner); err != nil {
		return err
	}
	switch u.Kind {
	case logUpdateCreateSession:
		var row storyLogSessionRow
		err := tx.Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&row).Error
		if err == nil {
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		now := time.Now().UTC().Unix()
		private := storyLogSessionPrivate{DiceID: u.DiceID, GroupID: u.GroupID, Name: u.Name}
		payload, err := json.Marshal(private)
		if err != nil {
			return ErrInvalidMetadata
		}
		diceKey, err := s.storyLogDiceHMAC(ctx, u.DiceID)
		if err != nil {
			return err
		}
		row = storyLogSessionRow{DiceHMAC: diceKey, ScopeHMAC: scope, OwnerHMAC: owner, NameHMAC: nameKey, Payload: []byte{0}, Nonce: []byte{0}, EncryptionKeyID: "pending", Version: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&row).Error; err != nil {
			return ErrParticipantFailure
		}
		cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-session/v1", scope, owner, row.ID, row.Version, payload)
		if err != nil {
			return err
		}
		return tx.Model(&storyLogSessionRow{}).Where("id = ?", row.ID).UpdateColumns(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID}).Error
	case logUpdateSetState:
		state := u.State
		if state.SessionID != 0 {
			var session storyLogSessionRow
			if err := tx.Where("id = ? AND scope_hmac = ?", state.SessionID, scope).Take(&session).Error; err != nil {
				return ErrNotFound
			}
			sessionPlain, err := s.openStoryLog(ctx, "story-log-session/v1", scope, owner, session.ID, session.Version, session.EncryptionKeyID, session.Payload, session.Nonce)
			if err != nil {
				return ErrAuthenticationFailed
			}
			var sessionPrivate storyLogSessionPrivate
			if json.Unmarshal(sessionPlain, &sessionPrivate) != nil || state.Name != sessionPrivate.Name {
				return ErrInvalidMetadata
			}
		} else if state.Name != "" || state.On {
			return ErrInvalidMetadata
		}
		var row storyLogStateRow
		queryErr := tx.Where("scope_hmac = ?", scope).Take(&row).Error
		version := uint64(1)
		if queryErr == nil {
			version = row.Version + 1
		} else if !errors.Is(queryErr, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		private := storyLogStatePrivate{DiceID: u.DiceID, GroupID: u.GroupID, SessionID: state.SessionID, Name: state.Name, On: state.On, BaselineSeq: state.BaselineSeq}
		payload, err := json.Marshal(private)
		if err != nil {
			return ErrInvalidMetadata
		}
		cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-state/v1", scope, owner, 0, version, payload)
		if err != nil {
			return err
		}
		row = storyLogStateRow{ScopeHMAC: scope, OwnerHMAC: owner, Payload: cipherText, Nonce: nonce, EncryptionKeyID: keyID, Version: version}
		return tx.Save(&row).Error
	case logUpdateAppendEntry:
		return s.appendStoryLogEntryTx(ctx, tx, u.Entry)
	case logUpdateEditEntry, logUpdateDeleteEntry:
		return s.mutateStoryLogEntryTx(ctx, tx, scope, owner, u.RawMsgID, u.Entry.Message, u.Kind == logUpdateDeleteEntry)
	case logUpdateDeleteSession:
		var session storyLogSessionRow
		if err := locked(tx).Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return ErrParticipantFailure
		}
		if err := s.deleteStoryLogIntentsForSessionTx(ctx, tx, scope, owner, session); err != nil {
			return err
		}
		if err := tx.Where("session_id = ? AND scope_hmac = ?", session.ID, scope).Delete(&logArchiveEntryRow{}).Error; err != nil {
			return ErrParticipantFailure
		}
		var state storyLogStateRow
		stateErr := tx.Where("scope_hmac = ?", scope).Take(&state).Error
		if stateErr == nil {
			plain, err := s.openStoryLog(ctx, "story-log-state/v1", scope, owner, 0, state.Version, state.EncryptionKeyID, state.Payload, state.Nonce)
			if err != nil {
				return ErrAuthenticationFailed
			}
			var private storyLogStatePrivate
			if json.Unmarshal(plain, &private) != nil {
				return ErrAuthenticationFailed
			}
			if private.SessionID == session.ID {
				if err := tx.Delete(&state).Error; err != nil {
					return ErrParticipantFailure
				}
			}
		} else if !errors.Is(stateErr, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		return tx.Delete(&session).Error
	case logUpdateSetUploadInfo:
		if u.UploadURL == "" || u.UploadTime <= 0 {
			return ErrInvalidMetadata
		}
		var session storyLogSessionRow
		if err := tx.Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return ErrParticipantFailure
		}
		plain, err := s.openStoryLog(ctx, "story-log-session/v1", scope, owner, session.ID, session.Version, session.EncryptionKeyID, session.Payload, session.Nonce)
		if err != nil {
			return ErrAuthenticationFailed
		}
		var private storyLogSessionPrivate
		if json.Unmarshal(plain, &private) != nil {
			return ErrAuthenticationFailed
		}
		private.UploadURL, private.UploadTime = u.UploadURL, u.UploadTime
		payload, err := json.Marshal(private)
		if err != nil {
			return ErrInvalidMetadata
		}
		version := session.Version + 1
		cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-session/v1", scope, owner, session.ID, version, payload)
		if err != nil {
			return err
		}
		result := tx.Model(&storyLogSessionRow{}).Where("id = ? AND version = ?", session.ID, session.Version).
			UpdateColumns(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID, "version": version})
		if result.Error != nil {
			return ErrParticipantFailure
		}
		if result.RowsAffected != 1 {
			return ErrParticipantConflict
		}
		return nil
	default:
		return ErrInvalidMetadata
	}
}
func (s *GORMStore) putStoryLogIntent(ctx context.Context, tx *gorm.DB, intent StoryLogIntent) error {
	if strings.TrimSpace(intent.EffectID) == "" || strings.TrimSpace(intent.Entry.LogName) == "" {
		return ErrInvalidMetadata
	}
	entry := intent.Entry
	scope, owner, nameKey, err := s.storyLogKeys(ctx, entry.DiceID, entry.GroupID, entry.LogName)
	if err != nil {
		return err
	}
	if err := privacyCheckSubjectFence(ctx, tx, owner); err != nil {
		return err
	}
	var session storyLogSessionRow
	if err := locked(tx).Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return ErrParticipantFailure
	}
	if !bytes.Equal(session.OwnerHMAC, owner) {
		return ErrAuthenticationFailed
	}
	sessionPrivate, err := s.storyLogSession(ctx, session)
	if err != nil || sessionPrivate.DiceID != entry.DiceID || sessionPrivate.GroupID != entry.GroupID || sessionPrivate.Name != entry.LogName {
		return ErrAuthenticationFailed
	}
	private := storyLogIntentPrivate{
		SessionID: session.ID,
		Entry: storyLogEntryPrivate{
			DiceID: entry.DiceID, GroupID: entry.GroupID, LogName: entry.LogName,
			Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: entry.Time,
			Message: entry.Message, IsDice: entry.IsDice, CommandID: entry.CommandID,
			CommandInfo: entry.CommandInfo, RawMsgID: entry.RawMsgID, UniformID: entry.UniformID,
			Seq: entry.Seq, Removed: entry.Removed, ParentID: entry.ParentID,
		},
	}
	payload, err := json.Marshal(private)
	if err != nil {
		return ErrInvalidMetadata
	}
	cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-intent/v2", scope, owner, logIntentAADID(intent.EffectID), 2, payload)
	if err != nil {
		return err
	}
	if err := tx.Create(&logArchiveIntentRow{
		EffectID: intent.EffectID, ScopeHMAC: scope, OwnerHMAC: owner, SessionID: session.ID,
		Payload: cipherText, Nonce: nonce, EncryptionKeyID: keyID, Version: 2,
	}).Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}

func (s *GORMStore) deleteStoryLogIntentsForSessionTx(ctx context.Context, tx *gorm.DB, scope, owner []byte, session storyLogSessionRow) error {
	if err := tx.Where("scope_hmac = ? AND session_id = ?", scope, session.ID).Delete(&logArchiveIntentRow{}).Error; err != nil {
		return ErrParticipantFailure
	}
	var unbound []logArchiveIntentRow
	if err := tx.Where("scope_hmac = ? AND session_id = 0", scope).Find(&unbound).Error; err != nil {
		return ErrParticipantFailure
	}
	if len(unbound) == 0 {
		return nil
	}
	target, err := s.storyLogSession(ctx, session)
	if err != nil {
		return err
	}
	for _, intent := range unbound {
		if intent.Version != 1 {
			return ErrAuthenticationFailed
		}
		entry, err := s.storyLogIntentPayload(ctx, intent)
		if err != nil {
			return ErrAuthenticationFailed
		}
		intentScope, intentOwner, _, err := s.storyLogKeys(ctx, entry.DiceID, entry.GroupID, entry.LogName)
		if err != nil || !bytes.Equal(intentScope, scope) || !bytes.Equal(intentOwner, owner) || !bytes.Equal(intentOwner, intent.OwnerHMAC) {
			return ErrAuthenticationFailed
		}
		if entry.DiceID != target.DiceID || entry.GroupID != target.GroupID || entry.LogName != target.Name {
			continue
		}
		if err := tx.Delete(&intent).Error; err != nil {
			return ErrParticipantFailure
		}
	}
	return nil
}

func (s *GORMStore) appendStoryLogEntryTx(ctx context.Context, tx *gorm.DB, entry StoryLogEntry) error {
	scope, owner, nameKey, err := s.storyLogKeys(ctx, entry.DiceID, entry.GroupID, entry.LogName)
	if err != nil {
		return err
	}
	if err := privacyCheckSubjectFence(ctx, tx, owner); err != nil {
		return err
	}
	var session storyLogSessionRow
	if err := tx.Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrParticipantFailure
		}
		if err := s.applyStoryLogUpdate(ctx, tx, LogUpdate{Kind: logUpdateCreateSession, DiceID: entry.DiceID, GroupID: entry.GroupID, Name: entry.LogName}); err != nil {
			return err
		}
		if err := tx.Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
			return ErrParticipantFailure
		}
	}
	return s.appendStoryLogEntryToSessionTx(ctx, tx, scope, owner, session, entry)
}

func (s *GORMStore) appendStoryLogEntryToSessionTx(ctx context.Context, tx *gorm.DB, scope, owner []byte, session storyLogSessionRow, entry StoryLogEntry) error {
	timestamp := entry.Time
	if timestamp == 0 {
		timestamp = time.Now().UTC().Unix()
	}
	private := storyLogEntryPrivate{
		DiceID: entry.DiceID, GroupID: entry.GroupID, LogName: entry.LogName,
		Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: timestamp, Message: entry.Message,
		IsDice: entry.IsDice, CommandID: entry.CommandID, CommandInfo: entry.CommandInfo,
		RawMsgID: entry.RawMsgID, UniformID: entry.UniformID, Seq: entry.Seq,
		Removed: entry.Removed, ParentID: entry.ParentID,
	}
	payload, err := json.Marshal(private)
	if err != nil {
		return ErrInvalidMetadata
	}
	cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-entry/v1", scope, owner, 0, 1, payload)
	if err != nil {
		return err
	}
	var rawHMAC []byte
	if entry.RawMsgID != "" {
		rawHMAC, err = s.storyLogRawHMAC(ctx, scope, entry.RawMsgID)
		if err != nil {
			return err
		}
	}
	row := logArchiveEntryRow{ScopeHMAC: scope, OwnerHMAC: owner, SessionID: session.ID, RawMsgHMAC: rawHMAC, Payload: cipherText, Nonce: nonce, EncryptionKeyID: keyID, Version: 1}
	if err := tx.Create(&row).Error; err != nil {
		return ErrParticipantFailure
	}
	cipherText, nonce, keyID, err = s.sealStoryLog(tx, ctx, "story-log-entry/v1", scope, owner, row.ID, row.Version, payload)
	if err != nil {
		return err
	}
	if err := tx.Model(&logArchiveEntryRow{}).Where("id = ?", row.ID).Updates(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID}).Error; err != nil {
		return ErrParticipantFailure
	}
	return s.touchStoryLogSessionTx(ctx, tx, scope, owner, session.ID)
}

func (s *GORMStore) touchStoryLogSessionTx(ctx context.Context, tx *gorm.DB, scope, owner []byte, sessionID uint64) error {
	var session storyLogSessionRow
	if err := locked(tx).Where("id = ? AND scope_hmac = ?", sessionID, scope).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return ErrParticipantFailure
	}
	if !bytes.Equal(session.OwnerHMAC, owner) {
		return ErrAuthenticationFailed
	}
	plain, err := s.openStoryLog(ctx, "story-log-session/v1", scope, owner, session.ID, session.Version, session.EncryptionKeyID, session.Payload, session.Nonce)
	if err != nil {
		return ErrAuthenticationFailed
	}
	var private storyLogSessionPrivate
	if json.Unmarshal(plain, &private) != nil {
		return ErrAuthenticationFailed
	}
	now := time.Now().UTC().Unix()
	if private.UploadURL == "" && private.UploadTime == 0 {
		if err := tx.Model(&storyLogSessionRow{}).
			Where("id = ? AND scope_hmac = ?", session.ID, scope).
			Update("updated_at", now).Error; err != nil {
			return ErrParticipantFailure
		}
		return nil
	}
	private.UploadURL, private.UploadTime = "", 0
	payload, err := json.Marshal(private)
	if err != nil {
		return ErrInvalidMetadata
	}
	version := session.Version + 1
	cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-session/v1", scope, owner, session.ID, version, payload)
	if err != nil {
		return err
	}
	result := tx.Model(&storyLogSessionRow{}).
		Where("id = ? AND scope_hmac = ? AND version = ?", session.ID, scope, session.Version).
		Updates(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID, "version": version, "updated_at": now})
	if result.Error != nil {
		return ErrParticipantFailure
	}
	if result.RowsAffected != 1 {
		return ErrParticipantConflict
	}
	return nil
}

func (s *GORMStore) mutateStoryLogEntryTx(ctx context.Context, tx *gorm.DB, scope, owner []byte, rawID, message string, remove bool) error {
	if rawID == "" {
		return nil
	}
	rawKey, err := s.storyLogRawHMAC(ctx, scope, rawID)
	if err != nil {
		return err
	}
	var rows []logArchiveEntryRow
	if err := tx.Where("scope_hmac = ? AND raw_msg_hmac = ?", scope, rawKey).Order("id DESC").Find(&rows).Error; err != nil {
		return ErrParticipantFailure
	}
	for _, row := range rows {
		plain, err := s.openStoryLog(ctx, "story-log-entry/v1", scope, owner, row.ID, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
		if err != nil {
			return ErrAuthenticationFailed
		}
		var entry storyLogEntryPrivate
		if json.Unmarshal(plain, &entry) != nil {
			return ErrAuthenticationFailed
		}
		if entry.RawMsgID != rawID {
			continue
		}
		if remove {
			if err := tx.Delete(&row).Error; err != nil {
				return ErrParticipantFailure
			}
			return s.touchStoryLogSessionTx(ctx, tx, scope, owner, row.SessionID)
		}
		if entry.Message == message {
			return nil
		}
		entry.Message = message
		payload, err := json.Marshal(entry)
		if err != nil {
			return ErrInvalidMetadata
		}
		version := row.Version + 1
		cipherText, nonce, keyID, err := s.sealStoryLog(tx, ctx, "story-log-entry/v1", scope, owner, row.ID, version, payload)
		if err != nil {
			return err
		}
		if err := tx.Model(&logArchiveEntryRow{}).Where("id = ?", row.ID).Updates(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID, "version": version}).Error; err != nil {
			return ErrParticipantFailure
		}
		return s.touchStoryLogSessionTx(ctx, tx, scope, owner, row.SessionID)
	}
	return nil
}

func (s *GORMStore) storyLogSession(ctx context.Context, row storyLogSessionRow) (StoryLogSession, error) {
	plain, err := s.openStoryLog(ctx, "story-log-session/v1", row.ScopeHMAC, row.OwnerHMAC, row.ID, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
	if err != nil {
		return StoryLogSession{}, err
	}
	var private storyLogSessionPrivate
	if json.Unmarshal(plain, &private) != nil {
		return StoryLogSession{}, ErrAuthenticationFailed
	}
	return StoryLogSession{ID: row.ID, DiceID: private.DiceID, GroupID: private.GroupID, Name: private.Name, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, UploadURL: private.UploadURL, UploadTime: private.UploadTime, Extra: cloneString(private.Extra)}, nil
}

func (s *GORMStore) CreateStoryLog(ctx context.Context, diceID, groupID, name string) (StoryLogSession, error) {
	if strings.TrimSpace(name) == "" {
		return StoryLogSession{}, ErrInvalidMetadata
	}
	if _, _, _, err := s.storyLogKeys(ctx, diceID, groupID, name); err != nil {
		return StoryLogSession{}, err
	}
	if _, err := s.Commit(ctx, UnitOfWork{LogUpdates: []LogUpdate{{Kind: logUpdateCreateSession, DiceID: diceID, GroupID: groupID, Name: name}}}); err != nil {
		return StoryLogSession{}, err
	}
	items, err := s.ListStoryLogs(ctx, diceID, groupID)
	if err != nil {
		return StoryLogSession{}, err
	}
	for _, item := range items {
		if item.Name == name {
			return item, nil
		}
	}
	return StoryLogSession{}, ErrParticipantFailure
}

func (s *GORMStore) ListStoryLogs(ctx context.Context, diceID, groupID string) ([]StoryLogSession, error) {
	scope, _, _, err := s.storyLogKeys(ctx, diceID, groupID, "")
	if err != nil {
		return nil, err
	}
	var rows []storyLogSessionRow
	if err := s.db.GORM().WithContext(ctx).Where("scope_hmac = ?", scope).Order("updated_at DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	out := make([]StoryLogSession, 0, len(rows))
	for _, row := range rows {
		value, err := s.storyLogSession(ctx, row)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}
func (s *GORMStore) ListStoryLogsForDice(ctx context.Context, diceID string) ([]StoryLogSession, error) {
	diceKey, err := s.storyLogDiceHMAC(ctx, diceID)
	if err != nil {
		return nil, err
	}
	var rows []storyLogSessionRow
	if err := s.db.GORM().WithContext(ctx).Where("dice_hmac = ?", diceKey).Order("updated_at DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	out := make([]StoryLogSession, 0, len(rows))
	for _, row := range rows {
		value, err := s.storyLogSession(ctx, row)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

func (s *GORMStore) GetStoryLogState(ctx context.Context, diceID, groupID string) (StoryLogState, error) {
	scope, owner, _, err := s.storyLogKeys(ctx, diceID, groupID, "")
	if err != nil {
		return StoryLogState{}, err
	}
	var row storyLogStateRow
	if err := s.db.GORM().WithContext(ctx).Where("scope_hmac = ?", scope).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return StoryLogState{DiceID: diceID, GroupID: groupID}, nil
		}
		return StoryLogState{}, ErrParticipantFailure
	}
	plain, err := s.openStoryLog(ctx, "story-log-state/v1", scope, owner, 0, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
	if err != nil {
		return StoryLogState{}, err
	}
	var private storyLogStatePrivate
	if json.Unmarshal(plain, &private) != nil {
		return StoryLogState{}, ErrAuthenticationFailed
	}
	return StoryLogState(private), nil
}

func (s *GORMStore) SetStoryLogState(ctx context.Context, state StoryLogState) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdateSetState, DiceID: state.DiceID, GroupID: state.GroupID, Name: state.Name, State: state})
}
func (s *GORMStore) AppendStoryLogEntry(ctx context.Context, entry StoryLogEntry) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdateAppendEntry, DiceID: entry.DiceID, GroupID: entry.GroupID, Name: entry.LogName, Entry: entry})
}
func (s *GORMStore) DeleteStoryLogEntryByRawID(ctx context.Context, diceID, groupID, rawID string) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdateDeleteEntry, DiceID: diceID, GroupID: groupID, RawMsgID: rawID})
}
func (s *GORMStore) EditStoryLogEntryByRawID(ctx context.Context, diceID, groupID, rawID, message string) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdateEditEntry, DiceID: diceID, GroupID: groupID, RawMsgID: rawID, Entry: StoryLogEntry{Message: message}})
}
func (s *GORMStore) DeleteStoryLog(ctx context.Context, diceID, groupID, name string) error {
	return s.commitLogUpdate(ctx, LogUpdate{Kind: logUpdateDeleteSession, DiceID: diceID, GroupID: groupID, Name: name})
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
	scope, owner, nameKey, err := s.storyLogKeys(ctx, diceID, groupID, name)
	if err != nil {
		return nil, err
	}
	var session storyLogSessionRow
	if err := s.db.GORM().WithContext(ctx).Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return []StoryLogEntry{}, nil
		}
		return nil, ErrParticipantFailure
	}
	var rows []logArchiveEntryRow
	if err := s.db.GORM().WithContext(ctx).Where("scope_hmac = ? AND session_id = ?", scope, session.ID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	out := make([]StoryLogEntry, 0, len(rows))
	for _, row := range rows {
		plain, err := s.openStoryLog(ctx, "story-log-entry/v1", scope, owner, row.ID, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
		if err != nil {
			return nil, err
		}
		var p storyLogEntryPrivate
		if json.Unmarshal(plain, &p) != nil {
			return nil, ErrAuthenticationFailed
		}
		out = append(out, StoryLogEntry{ID: row.ID, LogID: session.ID, DiceID: p.DiceID, GroupID: p.GroupID, LogName: p.LogName, Nickname: p.Nickname, IMUserID: p.IMUserID, Time: p.Time, Message: p.Message, IsDice: p.IsDice, CommandID: p.CommandID, CommandInfo: p.CommandInfo, RawMsgID: p.RawMsgID, UniformID: p.UniformID, Seq: p.Seq, Removed: p.Removed, ParentID: p.ParentID})
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
	scope, _, nameKey, err := s.storyLogKeys(ctx, diceID, groupID, name)
	if err != nil {
		return 0, err
	}
	var session storyLogSessionRow
	if err := s.db.GORM().WithContext(ctx).Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&session).Error; err != nil {
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

func (s *GORMStore) storyLogIntentPayload(ctx context.Context, row logArchiveIntentRow) (storyLogEntryPrivate, error) {
	plain, err := s.openStoryLog(ctx, "story-log-intent/v1", row.ScopeHMAC, row.OwnerHMAC, 0, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
	if err != nil {
		return storyLogEntryPrivate{}, err
	}
	var out storyLogEntryPrivate
	if json.Unmarshal(plain, &out) != nil {
		return storyLogEntryPrivate{}, ErrAuthenticationFailed
	}
	return out, nil
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
		case logUpdateCreateSession, logUpdateSetState, logUpdateAppendEntry,
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
			if update.State.SessionID == 0 && (update.State.Name != "" || update.State.On) {
				return ErrInvalidMetadata
			}
		case logUpdateAppendEntry:
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
