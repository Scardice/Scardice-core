package eventstore

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"sort"
	"strconv"
	"strings"

	"gorm.io/gorm"
)

const privacyLogArchiveCursorPrefix = "story-log-privacy/v1:"

const (
	privacyLogSessionsTable = iota
	privacyLogStatesTable
	privacyLogEntriesTable
	privacyLogIntentsTable
	privacyLogImportsTable
	privacyLogArchiveDone
)

type privacyLogArchiveCursor struct {
	Table int    `json:"t"`
	Key   string `json:"k,omitempty"`
}

type privacyLogArchiveSelection struct {
	ownerHMAC   []byte
	scopeHMACs  [][]byte
	diceByScope map[string][]byte
}

func privacyHasLogScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "logs" {
			return true
		}
	}
	return false
}

func encodePrivacyLogArchiveCursor(cursor privacyLogArchiveCursor) string {
	encoded, _ := json.Marshal(cursor)
	return privacyLogArchiveCursorPrefix + base64.RawURLEncoding.EncodeToString(encoded)
}

func decodePrivacyLogArchiveCursor(value string) (privacyLogArchiveCursor, bool, error) {
	if !strings.HasPrefix(value, privacyLogArchiveCursorPrefix) {
		return privacyLogArchiveCursor{}, false, nil
	}
	encoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, privacyLogArchiveCursorPrefix))
	if err != nil {
		return privacyLogArchiveCursor{}, true, ErrInvalidMetadata
	}
	var cursor privacyLogArchiveCursor
	if err := json.Unmarshal(encoded, &cursor); err != nil || cursor.Table < privacyLogSessionsTable || cursor.Table > privacyLogArchiveDone {
		return privacyLogArchiveCursor{}, true, ErrInvalidMetadata
	}
	if cursor.Table == privacyLogArchiveDone && cursor.Key != "" {
		return privacyLogArchiveCursor{}, true, ErrInvalidMetadata
	}
	if cursor.Key != "" {
		switch cursor.Table {
		case privacyLogSessionsTable, privacyLogEntriesTable:
			id, err := strconv.ParseUint(cursor.Key, 10, 64)
			if err != nil || id == 0 {
				return privacyLogArchiveCursor{}, true, ErrInvalidMetadata
			}
		case privacyLogStatesTable, privacyLogImportsTable:
			key, err := hex.DecodeString(cursor.Key)
			if err != nil || len(key) == 0 {
				return privacyLogArchiveCursor{}, true, ErrInvalidMetadata
			}
		}
	}
	return cursor, true, nil
}

func (s *GORMStore) privacyLogArchiveSelection(ctx context.Context, groupID string, diceIDs []string) (privacyLogArchiveSelection, error) {
	if len(diceIDs) == 0 {
		return privacyLogArchiveSelection{}, ErrInvalidMetadata
	}
	dice := append([]string(nil), diceIDs...)
	sort.Strings(dice)
	selection := privacyLogArchiveSelection{diceByScope: make(map[string][]byte, len(dice))}
	for i, diceID := range dice {
		if i > 0 && diceID == dice[i-1] {
			continue
		}
		scope, owner, _, err := s.storyLogKeys(ctx, diceID, groupID, "")
		if err != nil {
			return privacyLogArchiveSelection{}, err
		}
		diceKey, err := s.storyLogDiceHMAC(ctx, diceID)
		if err != nil {
			return privacyLogArchiveSelection{}, err
		}
		if selection.ownerHMAC == nil {
			selection.ownerHMAC = append([]byte(nil), owner...)
		} else if !hmac.Equal(selection.ownerHMAC, owner) {
			return privacyLogArchiveSelection{}, ErrInvalidMetadata
		}
		scopeID := string(scope)
		if priorDiceKey, ok := selection.diceByScope[scopeID]; ok {
			if !hmac.Equal(priorDiceKey, diceKey) {
				return privacyLogArchiveSelection{}, ErrInvalidMetadata
			}
			continue
		}
		selection.scopeHMACs = append(selection.scopeHMACs, append([]byte(nil), scope...))
		selection.diceByScope[scopeID] = append([]byte(nil), diceKey...)
	}
	if len(selection.scopeHMACs) == 0 || len(selection.ownerHMAC) == 0 {
		return privacyLogArchiveSelection{}, ErrInvalidMetadata
	}
	return selection, nil
}

func (selection privacyLogArchiveSelection) validate(scopeHMAC, ownerHMAC, diceHMAC []byte) error {
	if !hmac.Equal(ownerHMAC, selection.ownerHMAC) {
		return ErrInvalidMetadata
	}
	diceKey, ok := selection.diceByScope[string(scopeHMAC)]
	if !ok || (diceHMAC != nil && !hmac.Equal(diceHMAC, diceKey)) {
		return ErrInvalidMetadata
	}
	return nil
}

type privacyLogArchiveMetadata struct {
	ID           uint64 `gorm:"column:id"`
	ScopeHMAC    []byte `gorm:"column:scope_hmac"`
	OwnerHMAC    []byte `gorm:"column:owner_hmac"`
	DiceHMAC     []byte `gorm:"column:dice_hmac"`
	EffectID     string `gorm:"column:effect_id"`
	IdentityHMAC []byte `gorm:"column:identity_hmac"`
	PayloadBytes int64  `gorm:"column:payload_bytes"`
}

func privacyLogArchiveMetadataColumns(table string) (string, bool) {
	switch table {
	case "story_log_sessions":
		return "id, dice_hmac, scope_hmac, owner_hmac", true
	case "story_log_states":
		return "scope_hmac, owner_hmac", true
	case "story_log_entries":
		return "id, scope_hmac, owner_hmac", true
	case "story_log_outbound_intents":
		return "effect_id, scope_hmac, owner_hmac", true
	case "story_log_imports":
		return "identity_hmac, dice_hmac, scope_hmac, owner_hmac", true
	default:
		return "", false
	}
}

func privacyPayloadLengthExpression(db *gorm.DB) (string, bool) {
	switch db.Name() {
	case "sqlite", "mysql":
		return "LENGTH(payload)", true
	case "postgres":
		return "OCTET_LENGTH(payload)", true
	default:
		return "", false
	}
}

func privacyFetchLogMetadata(ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, table, keyColumn string, after any, limit int) ([]privacyLogArchiveMetadata, error) {
	columns, ok := privacyLogArchiveMetadataColumns(table)
	if !ok || limit < 1 {
		return nil, ErrInvalidMetadata
	}
	payloadLength, ok := privacyPayloadLengthExpression(db)
	if !ok {
		return nil, ErrParticipantFailure
	}
	query := db.WithContext(ctx).Table(table).Select(columns+", "+payloadLength+" AS payload_bytes").Where("owner_hmac = ? AND scope_hmac IN ?", selection.ownerHMAC, selection.scopeHMACs)
	if after != nil {
		query = query.Where(keyColumn+" > ?", after)
	}
	var rows []privacyLogArchiveMetadata
	if err := query.Order(keyColumn + " ASC").Limit(limit).Scan(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	return rows, nil
}

func privacyBoundedLogMetadata(rows []privacyLogArchiveMetadata, limit int) ([]privacyLogArchiveMetadata, error) {
	selected, totalBytes := 0, int64(0)
	for _, row := range rows {
		if selected == limit {
			break
		}
		if row.PayloadBytes < 0 {
			return nil, ErrInvalidMetadata
		}
		if selected > 0 && row.PayloadBytes > int64(PrivacyBatchBytes)-totalBytes {
			break
		}
		selected++
		totalBytes += row.PayloadBytes
	}
	return rows[:selected], nil
}

func privacyLogMetadataKeys(rows []privacyLogArchiveMetadata, keyColumn string) (any, any, error) {
	switch keyColumn {
	case "id":
		keys := make([]uint64, len(rows))
		for i, row := range rows {
			keys[i] = row.ID
		}
		return keys, rows[len(rows)-1].ID, nil
	case "scope_hmac":
		keys := make([][]byte, len(rows))
		for i, row := range rows {
			keys[i] = row.ScopeHMAC
		}
		return keys, rows[len(rows)-1].ScopeHMAC, nil
	case "effect_id":
		keys := make([]string, len(rows))
		for i, row := range rows {
			keys[i] = row.EffectID
		}
		return keys, rows[len(rows)-1].EffectID, nil
	case "identity_hmac":
		keys := make([][]byte, len(rows))
		for i, row := range rows {
			keys[i] = row.IdentityHMAC
		}
		return keys, rows[len(rows)-1].IdentityHMAC, nil
	default:
		return nil, nil, ErrInvalidMetadata
	}
}

func privacyFetchLogRowsByKeys[T any](ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, table, keyColumn string, keys any, omitPayload bool) ([]T, error) {
	query := db.WithContext(ctx).Table(table).Where("owner_hmac = ? AND scope_hmac IN ?", selection.ownerHMAC, selection.scopeHMACs).Where(keyColumn+" IN ?", keys)
	if omitPayload {
		query = query.Omit("Payload")
	}
	var rows []T
	if err := query.Order(keyColumn + " ASC").Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	return rows, nil
}

type privacyDigestPayloadInfo struct {
	Stream bool
	Key    any
	Bytes  int64
}

type privacyDigestPayloadPage[T any] struct {
	Rows    []T
	Next    any
	More    bool
	Payload privacyDigestPayloadInfo
}

const privacyLogPayloadChunkBytes = 1024 * 1024

func privacyPayloadChunkExpression(db *gorm.DB) (string, bool) {
	switch db.Name() {
	case "sqlite", "mysql":
		return "SUBSTR(payload, ?, ?)", true
	case "postgres":
		return "SUBSTRING(payload FROM ? FOR ?)", true
	default:
		return "", false
	}
}

func privacyWriteLogPayloadChunks(ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, table, keyColumn string, key any, payloadBytes int64, digest hash.Hash) error {
	expression, ok := privacyPayloadChunkExpression(db)
	if !ok || payloadBytes <= 0 {
		return ErrParticipantFailure
	}
	var header [10]byte
	header[0] = 'b'
	header[1] = 1
	binary.BigEndian.PutUint64(header[2:], uint64(payloadBytes))
	_, _ = digest.Write(header[:])
	for offset := int64(0); offset < payloadBytes; {
		chunkSize := int64(privacyLogPayloadChunkBytes)
		if remaining := payloadBytes - offset; remaining < chunkSize {
			chunkSize = remaining
		}
		var chunkRows []struct {
			Payload []byte `gorm:"column:payload"`
		}
		result := db.WithContext(ctx).Table(table).Select(expression+" AS payload", offset+1, chunkSize).
			Where("owner_hmac = ? AND scope_hmac IN ?", selection.ownerHMAC, selection.scopeHMACs).
			Where(keyColumn+" = ?", key).Limit(1).Find(&chunkRows)
		if result.Error != nil {
			return ErrParticipantFailure
		}
		if len(chunkRows) != 1 || len(chunkRows[0].Payload) != int(chunkSize) {
			return ErrParticipantConflict
		}
		_, _ = digest.Write(chunkRows[0].Payload)
		offset += int64(len(chunkRows[0].Payload))
	}
	return nil
}

func privacyWriteLogArchivePayload(ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, table, keyColumn string, info privacyDigestPayloadInfo, payload []byte, digest hash.Hash) error {
	if info.Stream {
		return privacyWriteLogPayloadChunks(ctx, db, selection, table, keyColumn, info.Key, info.Bytes, digest)
	}
	writeCanonicalBytes(digest, payload, payload == nil)
	return nil
}

func privacyFetchBoundedLogPayloadRows[T any](ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, table, keyColumn string, after any) (privacyDigestPayloadPage[T], error) {
	page := privacyDigestPayloadPage[T]{}
	metadata, err := privacyFetchLogMetadata(ctx, db, selection, table, keyColumn, after, PrivacyBatchRecords)
	if err != nil {
		return page, err
	}
	selected, err := privacyBoundedLogMetadata(metadata, PrivacyBatchRecords)
	if err != nil {
		return page, err
	}
	if len(selected) == 0 {
		return page, nil
	}
	keys, next, err := privacyLogMetadataKeys(selected, keyColumn)
	if err != nil {
		return page, err
	}
	page.Next = next
	page.More = len(selected) < len(metadata) || len(metadata) == PrivacyBatchRecords
	omitPayload := len(selected) == 1 && selected[0].PayloadBytes > int64(PrivacyBatchBytes)
	rows, err := privacyFetchLogRowsByKeys[T](ctx, db, selection, table, keyColumn, keys, omitPayload)
	if err != nil {
		return page, err
	}
	if len(rows) != len(selected) {
		return page, ErrParticipantConflict
	}
	page.Rows = rows
	if omitPayload {
		page.Payload = privacyDigestPayloadInfo{Stream: true, Key: next, Bytes: selected[0].PayloadBytes}
	}
	return page, nil
}

func privacyFetchBoundedLogMetadata(ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, table, keyColumn string, after any, limit int) ([]privacyLogArchiveMetadata, bool, error) {
	rows, err := privacyFetchLogMetadata(ctx, db, selection, table, keyColumn, after, limit+1)
	if err != nil {
		return nil, false, err
	}
	selected, err := privacyBoundedLogMetadata(rows, limit)
	if err != nil {
		return nil, false, err
	}
	return selected, len(selected) < len(rows), nil
}

func privacyWriteStoryLogArchiveDigest(ctx context.Context, db *gorm.DB, selection privacyLogArchiveSelection, digest hash.Hash, counts *PrivacyCounts) error {
	for after := any(nil); ; {
		page, err := privacyFetchBoundedLogPayloadRows[storyLogSessionRow](ctx, db, selection, "story_log_sessions", "id", after)
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, row.DiceHMAC); err != nil {
				return err
			}
			writeCanonicalString(digest, "story_log_sessions")
			writeCanonicalUint64(digest, row.ID)
			writeCanonicalBytes(digest, row.DiceHMAC, row.DiceHMAC == nil)
			writeCanonicalBytes(digest, row.ScopeHMAC, row.ScopeHMAC == nil)
			writeCanonicalBytes(digest, row.OwnerHMAC, row.OwnerHMAC == nil)
			writeCanonicalBytes(digest, row.NameHMAC, row.NameHMAC == nil)
			if err := privacyWriteLogArchivePayload(ctx, db, selection, "story_log_sessions", "id", page.Payload, row.Payload, digest); err != nil {
				return err
			}
			writeCanonicalBytes(digest, row.Nonce, row.Nonce == nil)
			writeCanonicalString(digest, row.EncryptionKeyID)
			writeCanonicalUint64(digest, row.Version)
			writeCanonicalUint64(digest, uint64(row.CreatedAt))
			writeCanonicalUint64(digest, uint64(row.UpdatedAt))
			counts.LogSessions++
		}
		if !page.More {
			break
		}
		after = page.Next
	}

	for after := any(nil); ; {
		page, err := privacyFetchBoundedLogPayloadRows[storyLogStateRow](ctx, db, selection, "story_log_states", "scope_hmac", after)
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, nil); err != nil {
				return err
			}
			writeCanonicalString(digest, "story_log_states")
			writeCanonicalBytes(digest, row.ScopeHMAC, row.ScopeHMAC == nil)
			writeCanonicalBytes(digest, row.OwnerHMAC, row.OwnerHMAC == nil)
			if err := privacyWriteLogArchivePayload(ctx, db, selection, "story_log_states", "scope_hmac", page.Payload, row.Payload, digest); err != nil {
				return err
			}
			writeCanonicalBytes(digest, row.Nonce, row.Nonce == nil)
			writeCanonicalString(digest, row.EncryptionKeyID)
			writeCanonicalUint64(digest, row.Version)
			counts.LogStates++
		}
		if !page.More {
			break
		}
		after = page.Next
	}

	for after := any(nil); ; {
		page, err := privacyFetchBoundedLogPayloadRows[logArchiveEntryRow](ctx, db, selection, "story_log_entries", "id", after)
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, nil); err != nil {
				return err
			}
			writeCanonicalString(digest, "story_log_entries")
			writeCanonicalUint64(digest, row.ID)
			writeCanonicalBytes(digest, row.ScopeHMAC, row.ScopeHMAC == nil)
			writeCanonicalBytes(digest, row.OwnerHMAC, row.OwnerHMAC == nil)
			writeCanonicalUint64(digest, row.SessionID)
			writeCanonicalBytes(digest, row.RawMsgHMAC, row.RawMsgHMAC == nil)
			if err := privacyWriteLogArchivePayload(ctx, db, selection, "story_log_entries", "id", page.Payload, row.Payload, digest); err != nil {
				return err
			}
			writeCanonicalBytes(digest, row.Nonce, row.Nonce == nil)
			writeCanonicalString(digest, row.EncryptionKeyID)
			writeCanonicalUint64(digest, row.Version)
			counts.LogEntries++
		}
		if !page.More {
			break
		}
		after = page.Next
	}

	for after := any(nil); ; {
		page, err := privacyFetchBoundedLogPayloadRows[logArchiveIntentRow](ctx, db, selection, "story_log_outbound_intents", "effect_id", after)
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, nil); err != nil {
				return err
			}
			writeCanonicalString(digest, "story_log_outbound_intents")
			writeCanonicalString(digest, row.EffectID)
			writeCanonicalBytes(digest, row.ScopeHMAC, row.ScopeHMAC == nil)
			writeCanonicalBytes(digest, row.OwnerHMAC, row.OwnerHMAC == nil)
			if err := privacyWriteLogArchivePayload(ctx, db, selection, "story_log_outbound_intents", "effect_id", page.Payload, row.Payload, digest); err != nil {
				return err
			}
			writeCanonicalBytes(digest, row.Nonce, row.Nonce == nil)
			writeCanonicalString(digest, row.EncryptionKeyID)
			writeCanonicalUint64(digest, row.Version)
			counts.LogIntents++
		}
		if !page.More {
			break
		}
		after = page.Next
	}

	for after := any(nil); ; {
		page, err := privacyFetchBoundedLogPayloadRows[storyLogImportRow](ctx, db, selection, "story_log_imports", "identity_hmac", after)
		if err != nil {
			return err
		}
		for _, row := range page.Rows {
			if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, row.DiceHMAC); err != nil {
				return err
			}
			writeCanonicalString(digest, "story_log_imports")
			writeCanonicalBytes(digest, row.IdentityHMAC, row.IdentityHMAC == nil)
			writeCanonicalBytes(digest, row.ScopeHMAC, row.ScopeHMAC == nil)
			writeCanonicalBytes(digest, row.OwnerHMAC, row.OwnerHMAC == nil)
			writeCanonicalBytes(digest, row.DiceHMAC, row.DiceHMAC == nil)
			writeCanonicalString(digest, row.Kind)
			writeCanonicalUint64(digest, row.ResourceID)
			writeCanonicalBytes(digest, row.SemanticHMAC, row.SemanticHMAC == nil)
			if err := privacyWriteLogArchivePayload(ctx, db, selection, "story_log_imports", "identity_hmac", page.Payload, row.Payload, digest); err != nil {
				return err
			}
			writeCanonicalBytes(digest, row.Nonce, row.Nonce == nil)
			writeCanonicalString(digest, row.EncryptionKeyID)
			writeCanonicalUint64(digest, row.Version)
			counts.LogImports++
		}
		if !page.More {
			break
		}
		after = page.Next
	}
	return nil
}

//nolint:nilnil // An empty cursor represents the first page, with no lower bound.
func privacyDecodeCursorNumber(value string) (any, error) {
	if value == "" {
		return nil, nil
	}
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || id == 0 {
		return nil, ErrInvalidMetadata
	}
	return id, nil
}

//nolint:nilnil // An empty cursor represents the first page, with no lower bound.
func privacyDecodeCursorHMAC(value string) (any, error) {
	if value == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) == 0 {
		return nil, ErrInvalidMetadata
	}
	return key, nil
}

func privacyDeleteStoryLogSessions(ctx context.Context, tx *gorm.DB, selection privacyLogArchiveSelection, cursorKey string, limit int) (int64, string, bool, error) {
	after, err := privacyDecodeCursorNumber(cursorKey)
	if err != nil {
		return 0, "", false, err
	}
	selected, more, err := privacyFetchBoundedLogMetadata(ctx, tx, selection, "story_log_sessions", "id", after, limit)
	if err != nil {
		return 0, "", false, err
	}
	if len(selected) == 0 {
		return 0, "", false, nil
	}
	ids := make([]uint64, len(selected))
	for i, row := range selected {
		if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, row.DiceHMAC); err != nil {
			return 0, "", false, err
		}
		ids[i] = row.ID
	}
	deleted := tx.WithContext(ctx).Where("owner_hmac = ? AND scope_hmac IN ? AND id IN ?", selection.ownerHMAC, selection.scopeHMACs, ids).Delete(&storyLogSessionRow{})
	if deleted.Error != nil {
		return 0, "", false, ErrParticipantFailure
	}
	if deleted.RowsAffected != int64(len(selected)) {
		return 0, "", false, ErrParticipantConflict
	}
	return int64(len(selected)), strconv.FormatUint(selected[len(selected)-1].ID, 10), more, nil
}

func privacyDeleteStoryLogStates(ctx context.Context, tx *gorm.DB, selection privacyLogArchiveSelection, cursorKey string, limit int) (int64, string, bool, error) {
	after, err := privacyDecodeCursorHMAC(cursorKey)
	if err != nil {
		return 0, "", false, err
	}
	selected, more, err := privacyFetchBoundedLogMetadata(ctx, tx, selection, "story_log_states", "scope_hmac", after, limit)
	if err != nil {
		return 0, "", false, err
	}
	if len(selected) == 0 {
		return 0, "", false, nil
	}
	scopes := make([][]byte, len(selected))
	for i, row := range selected {
		if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, nil); err != nil {
			return 0, "", false, err
		}
		scopes[i] = row.ScopeHMAC
	}
	deleted := tx.WithContext(ctx).Where("owner_hmac = ? AND scope_hmac IN ?", selection.ownerHMAC, scopes).Delete(&storyLogStateRow{})
	if deleted.Error != nil {
		return 0, "", false, ErrParticipantFailure
	}
	if deleted.RowsAffected != int64(len(selected)) {
		return 0, "", false, ErrParticipantConflict
	}
	return int64(len(selected)), hex.EncodeToString(selected[len(selected)-1].ScopeHMAC), more, nil
}

func privacyDeleteStoryLogEntries(ctx context.Context, tx *gorm.DB, selection privacyLogArchiveSelection, cursorKey string, limit int) (int64, string, bool, error) {
	after, err := privacyDecodeCursorNumber(cursorKey)
	if err != nil {
		return 0, "", false, err
	}
	selected, more, err := privacyFetchBoundedLogMetadata(ctx, tx, selection, "story_log_entries", "id", after, limit)
	if err != nil {
		return 0, "", false, err
	}
	if len(selected) == 0 {
		return 0, "", false, nil
	}
	ids := make([]uint64, len(selected))
	for i, row := range selected {
		if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, nil); err != nil {
			return 0, "", false, err
		}
		ids[i] = row.ID
	}
	deleted := tx.WithContext(ctx).Where("owner_hmac = ? AND scope_hmac IN ? AND id IN ?", selection.ownerHMAC, selection.scopeHMACs, ids).Delete(&logArchiveEntryRow{})
	if deleted.Error != nil {
		return 0, "", false, ErrParticipantFailure
	}
	if deleted.RowsAffected != int64(len(selected)) {
		return 0, "", false, ErrParticipantConflict
	}
	return int64(len(selected)), strconv.FormatUint(selected[len(selected)-1].ID, 10), more, nil
}

func privacyDeleteStoryLogIntents(ctx context.Context, tx *gorm.DB, selection privacyLogArchiveSelection, cursorKey string, limit int) (int64, string, bool, error) {
	var after any
	if cursorKey != "" {
		after = cursorKey
	}
	selected, more, err := privacyFetchBoundedLogMetadata(ctx, tx, selection, "story_log_outbound_intents", "effect_id", after, limit)
	if err != nil {
		return 0, "", false, err
	}
	if len(selected) == 0 {
		return 0, "", false, nil
	}
	ids := make([]string, len(selected))
	for i, row := range selected {
		if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, nil); err != nil {
			return 0, "", false, err
		}
		ids[i] = row.EffectID
	}
	deleted := tx.WithContext(ctx).Where("owner_hmac = ? AND scope_hmac IN ? AND effect_id IN ?", selection.ownerHMAC, selection.scopeHMACs, ids).Delete(&logArchiveIntentRow{})
	if deleted.Error != nil {
		return 0, "", false, ErrParticipantFailure
	}
	if deleted.RowsAffected != int64(len(selected)) {
		return 0, "", false, ErrParticipantConflict
	}
	return int64(len(selected)), selected[len(selected)-1].EffectID, more, nil
}

func privacyDeleteStoryLogImports(ctx context.Context, tx *gorm.DB, selection privacyLogArchiveSelection, cursorKey string, limit int) (int64, string, bool, error) {
	after, err := privacyDecodeCursorHMAC(cursorKey)
	if err != nil {
		return 0, "", false, err
	}
	selected, more, err := privacyFetchBoundedLogMetadata(ctx, tx, selection, "story_log_imports", "identity_hmac", after, limit)
	if err != nil {
		return 0, "", false, err
	}
	if len(selected) == 0 {
		return 0, "", false, nil
	}
	ids := make([][]byte, len(selected))
	for i, row := range selected {
		if err := selection.validate(row.ScopeHMAC, row.OwnerHMAC, row.DiceHMAC); err != nil {
			return 0, "", false, err
		}
		ids[i] = row.IdentityHMAC
	}
	deleted := tx.WithContext(ctx).Where("owner_hmac = ? AND scope_hmac IN ? AND identity_hmac IN ?", selection.ownerHMAC, selection.scopeHMACs, ids).Delete(&storyLogImportRow{})
	if deleted.Error != nil {
		return 0, "", false, ErrParticipantFailure
	}
	if deleted.RowsAffected != int64(len(selected)) {
		return 0, "", false, ErrParticipantConflict
	}
	return int64(len(selected)), hex.EncodeToString(selected[len(selected)-1].IdentityHMAC), more, nil
}

func privacyDeleteLogArchiveBatch(ctx context.Context, tx *gorm.DB, selection privacyLogArchiveSelection, cursor privacyLogArchiveCursor, limit int) (PrivacyCounts, string, bool, error) {
	counts := PrivacyCounts{}
	if cursor.Table == privacyLogArchiveDone {
		return counts, encodePrivacyLogArchiveCursor(cursor), true, nil
	}
	for cursor.Table < privacyLogArchiveDone {
		var count int64
		var nextKey string
		var more bool
		var err error
		switch cursor.Table {
		case privacyLogSessionsTable:
			count, nextKey, more, err = privacyDeleteStoryLogSessions(ctx, tx, selection, cursor.Key, limit)
			counts.LogSessions = count
		case privacyLogStatesTable:
			count, nextKey, more, err = privacyDeleteStoryLogStates(ctx, tx, selection, cursor.Key, limit)
			counts.LogStates = count
		case privacyLogEntriesTable:
			count, nextKey, more, err = privacyDeleteStoryLogEntries(ctx, tx, selection, cursor.Key, limit)
			counts.LogEntries = count
		case privacyLogIntentsTable:
			count, nextKey, more, err = privacyDeleteStoryLogIntents(ctx, tx, selection, cursor.Key, limit)
			counts.LogIntents = count
		case privacyLogImportsTable:
			count, nextKey, more, err = privacyDeleteStoryLogImports(ctx, tx, selection, cursor.Key, limit)
			counts.LogImports = count
		default:
			return PrivacyCounts{}, "", false, ErrInvalidMetadata
		}
		if err != nil {
			return PrivacyCounts{}, "", false, err
		}
		if count == 0 {
			cursor.Table++
			cursor.Key = ""
			continue
		}
		if more {
			cursor.Key = nextKey
			return counts, encodePrivacyLogArchiveCursor(cursor), false, nil
		}
		cursor.Table++
		cursor.Key = ""
		return counts, encodePrivacyLogArchiveCursor(cursor), cursor.Table == privacyLogArchiveDone, nil
	}
	return counts, encodePrivacyLogArchiveCursor(cursor), true, nil
}

func (s *GORMStore) privacyDeleteLogArchiveBatch(ctx context.Context, req PrivacyBatchRequest, subjectKey []byte, fenceVersion uint64, opView OperationView, private PrivacyOperationContext, selection privacyLogArchiveSelection, cursor privacyLogArchiveCursor, limit int) (PrivacyBatchResult, error) {
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return PrivacyBatchResult{}, err
	}
	var liveFence subjectFenceRow
	if err := tx.Where("subject_key = ? AND scope = ? AND purge_operation_id = ?", subjectKey, privacyFenceScope, req.OperationID).First(&liveFence).Error; err != nil {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	if liveFence.Version != fenceVersion {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	var liveOperation operationRow
	if err := tx.Where("operation_id = ? AND status IN ?", req.OperationID, []string{"pending", "running", "resumable-failure"}).First(&liveOperation).Error; err != nil {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	if liveOperation.Version != opView.Version || liveOperation.PrincipalID != logOwner(subjectKey) {
		return PrivacyBatchResult{}, ErrAuthenticationFailed
	}
	lockedPlain, err := a6Open(ctx, s.keySource, "operation-private/v1", req.OperationID, liveOperation.PrincipalID, liveOperation.Version, liveOperation.PrivateKeyID, liveOperation.PrivateContext, liveOperation.PrivateNonce)
	if err != nil {
		return PrivacyBatchResult{}, err
	}
	lockedPrivate, err := unmarshalPrivacyContext(lockedPlain)
	if err != nil {
		return PrivacyBatchResult{}, err
	}
	if lockedPrivate.Phase != "delete" || lockedPrivate.GroupID != req.GroupID || lockedPrivate.Cursor != req.Cursor || strings.Join(lockedPrivate.DiceIDs, "\x00") != strings.Join(private.DiceIDs, "\x00") || strings.Join(lockedPrivate.Scopes, "\x00") != strings.Join(private.Scopes, "\x00") {
		return PrivacyBatchResult{}, ErrParticipantConflict
	}
	deleted, nextCursor, done, err := privacyDeleteLogArchiveBatch(ctx, tx, selection, cursor, limit)
	if err != nil {
		return PrivacyBatchResult{}, err
	}
	if err := tx.Commit().Error; err != nil {
		return PrivacyBatchResult{}, ErrParticipantFailure
	}
	return PrivacyBatchResult{NextCursor: nextCursor, Deleted: deleted, Done: done}, nil
}
