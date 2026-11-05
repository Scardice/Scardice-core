package eventstore

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"gorm.io/gorm"
)

type StoryLogImportKind string

const (
	StoryLogImportSession StoryLogImportKind = "session"
	StoryLogImportEntry   StoryLogImportKind = "entry"
	StoryLogImportState   StoryLogImportKind = "state"
)

// StoryLogImportRecord links source records without depending on allocated target IDs.
type StoryLogImportRecord struct {
	SourceID        string
	Kind            StoryLogImportKind
	DiceID          string
	GroupID         string
	Session         *StoryLogSession
	Entry           *StoryLogEntry
	State           *StoryLogState
	SessionSourceID string
}

type StoryLogImportReceipt struct {
	SourceID       string
	Kind           StoryLogImportKind
	SemanticDigest []byte
	ResourceID     uint64
}

type LogImportRepository interface {
	StoryLogImportSemanticDigest(ctx context.Context, record StoryLogImportRecord) ([]byte, error)
	ImportStoryLogBatch(ctx context.Context, records []StoryLogImportRecord) ([]StoryLogImportReceipt, error)
	ListStoryLogImports(ctx context.Context, sourcePrefix, diceID string) ([]StoryLogImportReceipt, error)
}

type storyLogImportRow struct {
	ID              uint64 `gorm:"primaryKey;autoIncrement;index:ix_story_log_import_dice_identity,priority:2"`
	Identity        string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	IdentityLookup  []byte `gorm:"size:32;not null;index:ix_story_log_import_identity"`
	DiceID          string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	DiceLookup      []byte `gorm:"size:32;not null;index:ix_story_log_import_dice_identity,priority:1"`
	GroupID         string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Scope           string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	ScopeLookup     []byte `gorm:"size:32;not null;index:ix_story_log_import_owner"`
	Kind            string `gorm:"type:varchar(32);not null"`
	ResourceID      uint64 `gorm:"not null"`
	SessionSourceID string `gorm:"type:bytes;size:16777217;serializer:raw_string"`
	SemanticDigest  []byte `gorm:"size:32;not null"`
}

func (*storyLogImportRow) TableName() string { return tableStoryLogImports }

type storyLogImportCanonical struct {
	SourceID        string                    `json:"sourceId"`
	Kind            StoryLogImportKind        `json:"kind"`
	DiceID          string                    `json:"diceId"`
	GroupID         string                    `json:"groupId"`
	SessionSourceID string                    `json:"sessionSourceId,omitempty"`
	Session         *storyLogSessionCanonical `json:"session,omitempty"`
	Entry           *storyLogEntryData        `json:"entry,omitempty"`
	State           *storyLogStateCanonical   `json:"state,omitempty"`
}
type storyLogSessionCanonical struct {
	Name       string  `json:"name"`
	CreatedAt  int64   `json:"createdAt"`
	UpdatedAt  int64   `json:"updatedAt"`
	UploadURL  string  `json:"uploadUrl"`
	UploadTime int64   `json:"uploadTime"`
	Extra      *string `json:"extra"`
}
type storyLogStateCanonical struct {
	Name        string `json:"name"`
	On          bool   `json:"on"`
	BaselineSeq int64  `json:"baselineSeq"`
}

func normalizeStoryLogImport(record StoryLogImportRecord) (storyLogImportCanonical, error) {
	if strings.TrimSpace(record.SourceID) == "" || strings.TrimSpace(record.DiceID) == "" || strings.TrimSpace(record.GroupID) == "" {
		return storyLogImportCanonical{}, ErrInvalidMetadata
	}
	canonical := storyLogImportCanonical{SourceID: record.SourceID, Kind: record.Kind, DiceID: record.DiceID, GroupID: record.GroupID, SessionSourceID: record.SessionSourceID}
	switch record.Kind {
	case StoryLogImportSession:
		if record.Session == nil || record.Entry != nil || record.State != nil || record.Session.DiceID != record.DiceID || record.Session.GroupID != record.GroupID || strings.TrimSpace(record.Session.Name) == "" || record.SessionSourceID != "" {
			return storyLogImportCanonical{}, ErrInvalidMetadata
		}
		v := record.Session
		canonical.Session = &storyLogSessionCanonical{Name: v.Name, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, UploadURL: v.UploadURL, UploadTime: v.UploadTime, Extra: cloneString(v.Extra)}
	case StoryLogImportEntry:
		if record.Entry == nil || record.Session != nil || record.State != nil || record.Entry.DiceID != record.DiceID || record.Entry.GroupID != record.GroupID || strings.TrimSpace(record.Entry.LogName) == "" || strings.TrimSpace(record.SessionSourceID) == "" {
			return storyLogImportCanonical{}, ErrInvalidMetadata
		}
		data := entryData(*record.Entry)
		canonical.Entry = &data
	case StoryLogImportState:
		if record.State == nil || record.Session != nil || record.Entry != nil || record.State.DiceID != record.DiceID || record.State.GroupID != record.GroupID || (record.State.Name == "") != (record.SessionSourceID == "") || record.State.On && record.State.Name == "" {
			return storyLogImportCanonical{}, ErrInvalidMetadata
		}
		canonical.State = &storyLogStateCanonical{Name: record.State.Name, On: record.State.On, BaselineSeq: record.State.BaselineSeq}
	default:
		return storyLogImportCanonical{}, ErrInvalidMetadata
	}
	return canonical, nil
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func storyLogImportSemanticDigest(record StoryLogImportRecord) ([]byte, error) {
	canonical, err := normalizeStoryLogImport(record)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, ErrInvalidMetadata
	}
	return Digest("story-log-import-semantic/v2", string(encoded)), nil
}
func (s *GORMStore) StoryLogImportSemanticDigest(_ context.Context, record StoryLogImportRecord) ([]byte, error) {
	return storyLogImportSemanticDigest(record)
}
func (s *GORMStore) StoryLogImportSemanticDigests(_ context.Context, records []StoryLogImportRecord) ([][]byte, error) {
	out := make([][]byte, len(records))
	for i, record := range records {
		digest, err := storyLogImportSemanticDigest(record)
		if err != nil {
			return nil, err
		}
		out[i] = digest
	}
	return out, nil
}
func validateStoryLogImports(records []StoryLogImportRecord) error {
	if len(records) > MaxUnitOfWorkEvents {
		return &OversizeError{Bound: "story log import records", Limit: MaxUnitOfWorkEvents, Actual: len(records)}
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if _, err := normalizeStoryLogImport(record); err != nil {
			return err
		}
		if _, ok := seen[record.SourceID]; ok {
			return ErrDuplicateParticipant
		}
		seen[record.SourceID] = struct{}{}
	}
	return nil
}

func (s *GORMStore) applyStoryLogImports(ctx context.Context, tx *gorm.DB, work UnitOfWork) error {
	if len(work.LogImports) == 0 {
		return nil
	}
	ctx = withStoryLogRevisionPlan(ctx, work)
	revisionGuard, _ := ctx.Value(storyLogRevisionGuardContextKey{}).(*storyLogRevisionGuard)
	sources := make([]string, 0, len(work.LogImports)*2)
	seen := make(map[string]bool)
	for _, record := range work.LogImports {
		for _, id := range []string{record.SourceID, record.SessionSourceID} {
			if id != "" && !seen[id] {
				seen[id] = true
				sources = append(sources, id)
			}
		}
	}
	prior := make(map[string]storyLogImportRow, len(sources))
	for start := 0; start < len(sources); start += 500 {
		var rows []storyLogImportRow
		if err := storyImportsByIdentities(tx, sources[start:min(start+500, len(sources))]).Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		for _, row := range rows {
			prior[row.Identity] = row
		}
	}
	oldRows := make([]storyLogImportRow, 0, len(work.LogImports))
	for _, record := range work.LogImports {
		if row, ok := prior[record.SourceID]; ok {
			oldRows = append(oldRows, row)
		}
	}
	actual, err := s.storyLogImportRecordsFromRows(ctx, tx, oldRows)
	if err != nil {
		return err
	}
	actualByID := make(map[string]StoryLogImportRecord, len(actual))
	for _, record := range actual {
		actualByID[record.SourceID] = record
	}
	sessions := make(map[string]storyLogSessionRow)
	resolveSession := func(record StoryLogImportRecord) (storyLogSessionRow, error) {
		if row, ok := sessions[record.SessionSourceID]; ok {
			return row, nil
		}
		imported, ok := prior[record.SessionSourceID]
		if !ok || imported.Kind != string(StoryLogImportSession) || imported.DiceID != record.DiceID || imported.GroupID != record.GroupID {
			return storyLogSessionRow{}, ErrParticipantConflict
		}
		var row storyLogSessionRow
		if err := storyScopeQuery(tx, imported.Scope).Where("id = ?", imported.ResourceID).Take(&row).Error; err != nil {
			return storyLogSessionRow{}, ErrNotFound
		}
		sessions[record.SessionSourceID] = row
		return row, nil
	}
	pendingEntries := make([]logArchiveEntryRow, 0)
	pendingImports := make([]storyLogImportRow, 0, len(work.LogImports))
	entryImportIndexes := make([]int, 0)
	// Sessions precede all dependent records regardless of their order in the unit.
	ordered := make([]StoryLogImportRecord, 0, len(work.LogImports))
	for _, record := range work.LogImports {
		if record.Kind == StoryLogImportSession {
			ordered = append(ordered, record)
		}
	}
	for _, record := range work.LogImports {
		if record.Kind != StoryLogImportSession {
			ordered = append(ordered, record)
		}
	}
	for _, record := range ordered {
		digest, err := storyLogImportSemanticDigest(record)
		if err != nil {
			return err
		}
		if previous, ok := prior[record.SourceID]; ok {
			persisted, ok := actualByID[record.SourceID]
			if !ok {
				return ErrParticipantConflict
			}
			actualDigest, err := storyLogImportSemanticDigest(persisted)
			if err != nil || previous.DiceID != record.DiceID || previous.GroupID != record.GroupID || !bytes.Equal(digest, previous.SemanticDigest) || !bytes.Equal(actualDigest, digest) {
				return ErrParticipantConflict
			}
			continue
		}
		scope, err := storyLogScope(record.DiceID, record.GroupID)
		if err != nil {
			return err
		}
		if !storyLogRevisionGuarded(ctx, scope) {
			if err := s.advanceStoryLogScopeRevisionTx(tx, scope); err != nil {
				return err
			}
			revisionGuard.advanced[scope] = struct{}{}
		}
		row := storyLogImportRow{Identity: record.SourceID, DiceID: record.DiceID, GroupID: record.GroupID, Scope: scope, Kind: string(record.Kind), SessionSourceID: record.SessionSourceID, SemanticDigest: digest}
		switch record.Kind {
		case StoryLogImportSession:
			var exists int64
			if err := storySessionQuery(tx.Model(&storyLogSessionRow{}), scope, record.Session.Name).Count(&exists).Error; err != nil {
				return ErrParticipantFailure
			}
			if exists != 0 {
				return ErrParticipantConflict
			}
			v := record.Session
			target := storyLogSessionRow{DiceID: record.DiceID, GroupID: record.GroupID, Scope: scope, Name: v.Name, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, UploadURL: v.UploadURL, UploadTime: v.UploadTime, Extra: cloneString(v.Extra), Version: 1}
			if err := tx.Create(&target).Error; err != nil {
				return ErrParticipantFailure
			}
			row.ResourceID = target.ID
			sessions[record.SourceID] = target
		case StoryLogImportEntry:
			session, err := resolveSession(record)
			if err != nil {
				return err
			}
			if session.Name != record.Entry.LogName {
				return ErrParticipantConflict
			}
			payload, err := json.Marshal(entryData(*record.Entry))
			if err != nil {
				return ErrInvalidMetadata
			}
			pendingEntries = append(pendingEntries, logArchiveEntryRow{DiceID: record.DiceID, GroupID: record.GroupID, Scope: scope, SessionID: session.ID, RawMsgID: record.Entry.RawMsgID, Payload: payload, Version: 1})
			entryImportIndexes = append(entryImportIndexes, len(pendingImports))
		case StoryLogImportState:
			sessionID := uint64(0)
			if record.SessionSourceID != "" {
				session, err := resolveSession(record)
				if err != nil {
					return err
				}
				if session.Name != record.State.Name {
					return ErrParticipantConflict
				}
				sessionID = session.ID
			}
			var count int64
			if err := storyScopeQuery(tx.Model(&storyLogStateRow{}), scope).Count(&count).Error; err != nil {
				return ErrParticipantFailure
			}
			if count != 0 {
				return ErrParticipantConflict
			}
			if err := tx.Create(&storyLogStateRow{Scope: scope, DiceID: record.DiceID, GroupID: record.GroupID, SessionID: sessionID, Name: record.State.Name, On: record.State.On, BaselineSeq: record.State.BaselineSeq, Version: 1}).Error; err != nil {
				return ErrParticipantFailure
			}
		default:
			return ErrInvalidMetadata
		}
		pendingImports = append(pendingImports, row)
		prior[row.Identity] = row
	}
	if len(pendingEntries) > 0 {
		if err := tx.CreateInBatches(&pendingEntries, 100).Error; err != nil {
			return ErrParticipantFailure
		}
		for i, row := range pendingEntries {
			if row.ID == 0 {
				return ErrParticipantFailure
			}
			pendingImports[entryImportIndexes[i]].ResourceID = row.ID
		}
	}
	if len(pendingImports) > 0 {
		if err := tx.CreateInBatches(&pendingImports, 100).Error; err != nil {
			return ErrParticipantFailure
		}
	}
	return nil
}

// Read back actual resource rows rather than trusting stored import digests.
func (s *GORMStore) storyLogImportRecordsFromRows(ctx context.Context, tx *gorm.DB, rows []storyLogImportRow) ([]StoryLogImportRecord, error) {
	sessions := make(map[uint64]storyLogSessionRow)
	entries := make(map[uint64]logArchiveEntryRow)
	states := make(map[string]storyLogStateRow)
	ids := make([]uint64, 0, len(rows))
	entryIDs := make([]uint64, 0, len(rows))
	scopes := make([]string, 0, len(rows))
	sessionSources := make(map[string]storyLogImportRow)
	sources := make([]string, 0, len(rows))
	for _, row := range rows {
		switch StoryLogImportKind(row.Kind) {
		case StoryLogImportSession:
			ids = append(ids, row.ResourceID)
		case StoryLogImportEntry:
			entryIDs = append(entryIDs, row.ResourceID)
		case StoryLogImportState:
			scopes = append(scopes, row.Scope)
		default:
			return nil, ErrInvalidMetadata
		}
		if row.SessionSourceID != "" {
			sources = append(sources, row.SessionSourceID)
		}
	}
	for start := 0; start < len(sources); start += 500 {
		var found []storyLogImportRow
		if err := storyImportsByIdentities(tx, sources[start:min(start+500, len(sources))]).Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			sessionSources[row.Identity] = row
		}
	}
	for start := 0; start < len(ids); start += 500 {
		var found []storyLogSessionRow
		if err := tx.Where("id IN ?", ids[start:min(start+500, len(ids))]).Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			sessions[row.ID] = row
		}
	}
	for start := 0; start < len(entryIDs); start += 500 {
		var found []logArchiveEntryRow
		if err := tx.Where("id IN ?", entryIDs[start:min(start+500, len(entryIDs))]).Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			entries[row.ID] = row
		}
	}
	for start := 0; start < len(scopes); start += 500 {
		var found []storyLogStateRow
		if err := tx.Where("scope IN ?", rawStrings(scopes[start:min(start+500, len(scopes))])).Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			states[row.Scope] = row
		}
	}
	out := make([]StoryLogImportRecord, 0, len(rows))
	for _, row := range rows {
		record := StoryLogImportRecord{SourceID: row.Identity, Kind: StoryLogImportKind(row.Kind), DiceID: row.DiceID, GroupID: row.GroupID, SessionSourceID: row.SessionSourceID}
		var sessionID uint64
		switch record.Kind {
		case StoryLogImportSession:
			value, ok := sessions[row.ResourceID]
			if !ok || value.Scope != row.Scope || value.DiceID != row.DiceID || value.GroupID != row.GroupID {
				return nil, ErrNotFound
			}
			session, _ := s.storyLogSession(ctx, value)
			record.Session = &session
		case StoryLogImportEntry:
			value, ok := entries[row.ResourceID]
			if !ok || value.Scope != row.Scope {
				return nil, ErrNotFound
			}
			entry, err := s.storyLogEntry(ctx, value)
			if err != nil {
				return nil, err
			}
			record.Entry = &entry
			sessionID = value.SessionID
		case StoryLogImportState:
			value, ok := states[row.Scope]
			if !ok || value.DiceID != row.DiceID || value.GroupID != row.GroupID {
				return nil, ErrNotFound
			}
			record.State = &StoryLogState{DiceID: value.DiceID, GroupID: value.GroupID, Name: value.Name, On: value.On, SessionID: value.SessionID, BaselineSeq: value.BaselineSeq}
			sessionID = value.SessionID
		}
		if row.SessionSourceID != "" {
			source, ok := sessionSources[row.SessionSourceID]
			if !ok || source.Kind != string(StoryLogImportSession) || source.ResourceID != sessionID || source.Scope != row.Scope {
				return nil, ErrInvalidMetadata
			}
		} else if sessionID != 0 {
			return nil, ErrInvalidMetadata
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *GORMStore) ImportStoryLogBatch(ctx context.Context, records []StoryLogImportRecord) ([]StoryLogImportReceipt, error) {
	if err := validateStoryLogImports(records); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return []StoryLogImportReceipt{}, nil
	}
	if _, err := s.Commit(ctx, UnitOfWork{LogImports: records}); err != nil {
		return nil, err
	}
	ids := make([]string, len(records))
	for i, record := range records {
		ids[i] = record.SourceID
	}
	byID := make(map[string]StoryLogImportReceipt, len(records))
	err := s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		for start := 0; start < len(ids); start += 500 {
			var rows []storyLogImportRow
			if err := storyImportsByIdentities(tx, ids[start:min(start+500, len(ids))]).Find(&rows).Error; err != nil {
				return ErrParticipantFailure
			}
			if err := s.visitStoryLogImportRows(ctx, tx, rows, func(receipt StoryLogImportReceipt) error {
				receipt.SemanticDigest = bytes.Clone(receipt.SemanticDigest)
				byID[receipt.SourceID] = receipt
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]StoryLogImportReceipt, len(records))
	for i, record := range records {
		receipt, ok := byID[record.SourceID]
		if !ok {
			return nil, ErrNotFound
		}
		out[i] = receipt
	}
	return out, nil
}
func (s *GORMStore) visitStoryLogImportRows(ctx context.Context, tx *gorm.DB, rows []storyLogImportRow, visit func(StoryLogImportReceipt) error) error {
	actual, err := s.storyLogImportRecordsFromRows(ctx, tx, rows)
	if err != nil {
		return err
	}
	for i, record := range actual {
		digest, err := storyLogImportSemanticDigest(record)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest, rows[i].SemanticDigest) {
			return ErrChecksumMismatch
		}
		if err := visit(StoryLogImportReceipt{SourceID: record.SourceID, Kind: record.Kind, SemanticDigest: digest, ResourceID: rows[i].ResourceID}); err != nil {
			return err
		}
	}
	return nil
}
func (s *GORMStore) ListStoryLogImports(ctx context.Context, sourcePrefix, diceID string) ([]StoryLogImportReceipt, error) {
	out := make([]StoryLogImportReceipt, 0)
	err := s.VisitStoryLogImports(ctx, sourcePrefix, diceID, func(receipt StoryLogImportReceipt) error {
		receipt.SemanticDigest = bytes.Clone(receipt.SemanticDigest)
		out = append(out, receipt)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *GORMStore) VisitStoryLogImports(ctx context.Context, sourcePrefix, diceID string, visit func(StoryLogImportReceipt) error) error {
	if visit == nil {
		return ErrInvalidMetadata
	}
	if err := s.requireReady(ctx); err != nil {
		return err
	}
	return s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		var cursor uint64
		for {
			query := tx.Order("id ASC").Limit(MaxUnitOfWorkEvents).Where("id > ?", cursor)
			if diceID != "" {
				query = storyDiceQuery(query, diceID)
			}
			var rows []storyLogImportRow
			if err := query.Find(&rows).Error; err != nil {
				return ErrParticipantFailure
			}
			selected := rows
			if sourcePrefix != "" {
				selected = make([]storyLogImportRow, 0, len(rows))
				for _, row := range rows {
					if strings.HasPrefix(row.Identity, sourcePrefix) {
						selected = append(selected, row)
					}
				}
			}
			if err := s.visitStoryLogImportRows(ctx, tx, selected, visit); err != nil {
				return err
			}
			if len(rows) < MaxUnitOfWorkEvents {
				return nil
			}
			cursor = rows[len(rows)-1].ID
		}
	})
}
