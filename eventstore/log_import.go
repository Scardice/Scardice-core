package eventstore

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type StoryLogImportKind string

const (
	StoryLogImportSession StoryLogImportKind = "session"
	StoryLogImportEntry   StoryLogImportKind = "entry"
	StoryLogImportState   StoryLogImportKind = "state"
)

// StoryLogImportRecord is a typed legacy archive record. SourceID is a stable,
// source-scoped record identity; SessionSourceID links entries and current
// state to the imported session without relying on target surrogate IDs.
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

// StoryLogImportReceipt is an integrity-checked import manifest item. ResourceID
// is the target session or entry surrogate, and zero for state records.
type StoryLogImportReceipt struct {
	SourceID       string
	Kind           StoryLogImportKind
	SemanticDigest []byte
	ResourceID     uint64
}

type LogImportRepository interface {
	StoryLogImportSemanticDigest(ctx context.Context, record StoryLogImportRecord) ([]byte, error)
	ImportStoryLogBatch(ctx context.Context, records []StoryLogImportRecord) ([]StoryLogImportReceipt, error)
	ListStoryLogImports(ctx context.Context, diceID, groupID string) ([]StoryLogImportReceipt, error)
}

type storyLogImportRow struct {
	IdentityHMAC    []byte `gorm:"column:identity_hmac;size:32;primaryKey;index:ix_story_log_import_dice_identity,priority:2"`
	ScopeHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_import_owner,priority:2"`
	OwnerHMAC       []byte `gorm:"size:32;not null;index:ix_story_log_import_owner,priority:1"`
	DiceHMAC        []byte `gorm:"size:32;not null;index:ix_story_log_import_dice_identity,priority:1"`
	Kind            string `gorm:"type:varchar(32);not null"`
	ResourceID      uint64 `gorm:"not null"`
	SemanticHMAC    []byte `gorm:"size:32;not null"`
	Payload         []byte `gorm:"not null"`
	Nonce           []byte `gorm:"not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	Version         uint64 `gorm:"not null"`
	ImportRowID     int64  `gorm:"column:import_rowid;->;-:migration"`
}

func (storyLogImportRow) TableName() string { return tableStoryLogImports }

type storyLogImportPrivate struct {
	SourceID        string `json:"sourceId"`
	SessionSourceID string `json:"sessionSourceId,omitempty"`
}

type storyLogImportCanonical struct {
	SourceID        string                    `json:"sourceId"`
	Kind            StoryLogImportKind        `json:"kind"`
	DiceID          string                    `json:"diceId"`
	GroupID         string                    `json:"groupId"`
	SessionSourceID string                    `json:"sessionSourceId,omitempty"`
	Session         *storyLogSessionCanonical `json:"session,omitempty"`
	Entry           *storyLogEntryCanonical   `json:"entry,omitempty"`
	State           *storyLogStateCanonical   `json:"state,omitempty"`
}

type storyLogSessionCanonical struct {
	CreatedAt  int64   `json:"createdAt"`
	UpdatedAt  int64   `json:"updatedAt"`
	UploadURL  string  `json:"uploadUrl"`
	UploadTime int64   `json:"uploadTime"`
	Extra      *string `json:"extra"`
}

type storyLogEntryCanonical struct {
	LogName     string          `json:"logName"`
	Nickname    string          `json:"nickname"`
	IMUserID    string          `json:"imUserId"`
	Time        int64           `json:"time"`
	Message     string          `json:"message"`
	IsDice      bool            `json:"isDice"`
	CommandID   int64           `json:"commandId"`
	CommandInfo json.RawMessage `json:"commandInfo"`
	RawMsgID    string          `json:"rawMsgId"`
	UniformID   string          `json:"uniformId"`
	Seq         *int64          `json:"seq"`
	Removed     *int            `json:"removed"`
	ParentID    *int            `json:"parentId"`
}

type storyLogStateCanonical struct {
	Name string `json:"name"`
	On   bool   `json:"on"`
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
		canonical.Session = &storyLogSessionCanonical{CreatedAt: record.Session.CreatedAt, UpdatedAt: record.Session.UpdatedAt, UploadURL: record.Session.UploadURL, UploadTime: record.Session.UploadTime, Extra: cloneString(record.Session.Extra)}
	case StoryLogImportEntry:
		if record.Entry == nil || record.Session != nil || record.State != nil || record.Entry.DiceID != record.DiceID || record.Entry.GroupID != record.GroupID || strings.TrimSpace(record.Entry.LogName) == "" || strings.TrimSpace(record.SessionSourceID) == "" {
			return storyLogImportCanonical{}, ErrInvalidMetadata
		}
		canonical.Entry = &storyLogEntryCanonical{LogName: record.Entry.LogName, Nickname: record.Entry.Nickname, IMUserID: record.Entry.IMUserID, Time: record.Entry.Time, Message: record.Entry.Message, IsDice: record.Entry.IsDice, CommandID: record.Entry.CommandID, CommandInfo: cloneRawMessage(record.Entry.CommandInfo), RawMsgID: record.Entry.RawMsgID, UniformID: record.Entry.UniformID, Seq: cloneInt64(record.Entry.Seq), Removed: cloneInt(record.Entry.Removed), ParentID: cloneInt(record.Entry.ParentID)}
	case StoryLogImportState:
		if record.State == nil || record.Session != nil || record.Entry != nil || record.State.DiceID != record.DiceID || record.State.GroupID != record.GroupID || record.State.Name == "" && record.SessionSourceID != "" || record.State.Name != "" && record.SessionSourceID == "" {
			return storyLogImportCanonical{}, ErrInvalidMetadata
		}
		canonical.State = &storyLogStateCanonical{Name: record.State.Name, On: record.State.On}
	default:
		return storyLogImportCanonical{}, ErrInvalidMetadata
	}
	return canonical, nil
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
func cloneRawMessage(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}

// StoryLogImportSemanticDigest computes the key-backed canonical digest used by
// source manifests, idempotent writes, and reopened-target verification. Target
// surrogate IDs are deliberately excluded; SourceID and SessionSourceID carry
// the stable source relationship instead.
func storyLogImportSemanticDigestWithMaterial(material []byte, record StoryLogImportRecord) ([]byte, error) {
	canonical, err := normalizeStoryLogImport(record)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, ErrInvalidMetadata
	}
	return privacyHMACWithMaterial(material, "story-log-import-semantic/v1", string(encoded))
}

func (s *GORMStore) StoryLogImportSemanticDigest(ctx context.Context, record StoryLogImportRecord) ([]byte, error) {
	_, material, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return nil, err
	}
	return storyLogImportSemanticDigestWithMaterial(material, record)
}

// StoryLogImportSemanticDigests computes one batch with a single index-key
// load. Large offline imports use this to avoid rereading key material for
// every archive row.
func (s *GORMStore) StoryLogImportSemanticDigests(ctx context.Context, records []StoryLogImportRecord) ([][]byte, error) {
	_, material, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return nil, err
	}
	digests := make([][]byte, len(records))
	for index, record := range records {
		digests[index], err = storyLogImportSemanticDigestWithMaterial(material, record)
		if err != nil {
			for prior := range index {
				clear(digests[prior])
			}
			return nil, err
		}
	}
	return digests, nil
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

func storyLogImportAAD(identity []byte) string {
	return fmt.Sprintf("story-log-import/v1/%x", identity)
}

func storyLogImportIdentityWithMaterial(material []byte, sourceID string) ([]byte, error) {
	if strings.TrimSpace(sourceID) == "" {
		return nil, ErrInvalidMetadata
	}
	return privacyHMACWithMaterial(material, "story-log-import-identity/v1", sourceID)
}

func (s *GORMStore) openStoryLogImport(ctx context.Context, identity, owner []byte, row storyLogImportRow) ([]byte, error) {
	if s == nil || s.keySource == nil {
		return nil, ErrKeySourceUnavailable
	}
	return a6Open(ctx, s.keySource, "story-log-import/v1", storyLogImportAAD(identity), logOwner(owner), row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
}

type storyLogImportScopeKey struct {
	diceID  string
	groupID string
}

type storyLogImportScopeMaterial struct {
	scope []byte
	owner []byte
}

type storyLogImportedSession struct {
	importRow storyLogImportRow
	session   StoryLogSession
}

type storyLogImportNonceSequence struct {
	prefix      [10]byte
	next        uint32
	initialized bool
}

func (sequence *storyLogImportNonceSequence) nonce(size int) ([]byte, error) {
	if sequence == nil || size != 12 || sequence.next >= 1<<16 {
		return nil, ErrEncryptionUnavailable
	}
	if !sequence.initialized {
		if _, err := rand.Read(sequence.prefix[:]); err != nil {
			return nil, ErrEncryptionUnavailable
		}
		sequence.initialized = true
	}
	nonce := make([]byte, size)
	copy(nonce, sequence.prefix[:])
	binary.BigEndian.PutUint16(nonce[len(sequence.prefix):], uint16(sequence.next))
	sequence.next++
	return nonce, nil
}

type storyLogImportApplyCache struct {
	identities     map[string][]byte
	prior          map[string]storyLogImportRow
	scopes         map[storyLogImportScopeKey]storyLogImportScopeMaterial
	diceKeys       map[string][]byte
	fences         map[string]struct{}
	sessions       map[string]storyLogImportedSession
	indexMaterial  []byte
	encryptionRoot EncryptionRoot
	aeads          map[string]cipher.AEAD
	nonces         map[string]*storyLogImportNonceSequence
}

func (cache *storyLogImportApplyCache) seal(domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	if cache == nil {
		return nil, nil, "", ErrEncryptionUnavailable
	}
	aead := cache.aeads[domain]
	if aead == nil {
		var err error
		aead, err = newA6AEAD(cache.encryptionRoot.Material, domain)
		if err != nil {
			return nil, nil, "", err
		}
		cache.aeads[domain] = aead
	}
	sequence := cache.nonces[domain]
	if sequence == nil {
		sequence = &storyLogImportNonceSequence{}
		cache.nonces[domain] = sequence
	}
	nonce, err := sequence.nonce(aead.NonceSize())
	if err != nil {
		return nil, nil, "", err
	}
	cipherText := aead.Seal(nil, nonce, plaintext, a6AAD(domain, identity, owner, version, cache.encryptionRoot.ID))
	return cipherText, nonce, cache.encryptionRoot.ID, nil
}

func (s *GORMStore) prepareStoryLogImportApplyCache(ctx context.Context, tx *gorm.DB, records []StoryLogImportRecord) (*storyLogImportApplyCache, error) {
	_, indexMaterial, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return nil, err
	}
	encryptionRoot, err := s.admittedCurrentRoot(ctx, tx)
	if err != nil {
		return nil, err
	}
	cache := &storyLogImportApplyCache{
		identities:     make(map[string][]byte, len(records)),
		prior:          make(map[string]storyLogImportRow),
		scopes:         make(map[storyLogImportScopeKey]storyLogImportScopeMaterial),
		diceKeys:       make(map[string][]byte),
		fences:         make(map[string]struct{}),
		sessions:       make(map[string]storyLogImportedSession),
		indexMaterial:  append([]byte(nil), indexMaterial...),
		encryptionRoot: EncryptionRoot{ID: encryptionRoot.ID, Material: append([]byte(nil), encryptionRoot.Material...)},
		aeads:          make(map[string]cipher.AEAD, 3),
		nonces:         make(map[string]*storyLogImportNonceSequence, 3),
	}
	identities := make([][]byte, 0, len(records)*2)
	addIdentity := func(sourceID string) error {
		if sourceID == "" {
			return nil
		}
		if _, exists := cache.identities[sourceID]; exists {
			return nil
		}
		identity, err := storyLogImportIdentityWithMaterial(cache.indexMaterial, sourceID)
		if err != nil {
			return err
		}
		cache.identities[sourceID] = identity
		identities = append(identities, identity)
		return nil
	}
	for _, record := range records {
		if err := addIdentity(record.SourceID); err != nil {
			return nil, err
		}
		if err := addIdentity(record.SessionSourceID); err != nil {
			return nil, err
		}
	}
	const identityQueryBatch = 500
	for start := 0; start < len(identities); start += identityQueryBatch {
		end := min(start+identityQueryBatch, len(identities))
		var rows []storyLogImportRow
		if err := tx.WithContext(ctx).Where("identity_hmac IN ?", identities[start:end]).Find(&rows).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range rows {
			cache.prior[string(row.IdentityHMAC)] = row
		}
	}
	return cache, nil
}

func (s *GORMStore) applyStoryLogImports(ctx context.Context, tx *gorm.DB, work UnitOfWork) error {
	if len(work.LogImports) == 0 {
		return nil
	}
	cache, err := s.prepareStoryLogImportApplyCache(ctx, tx, work.LogImports)
	if err != nil {
		return err
	}
	defer func() {
		clear(cache.indexMaterial)
		clear(cache.encryptionRoot.Material)
	}()
	// Materialize sessions first so entries and current-state rows can resolve
	// a session imported in the same unit of work.
	for _, record := range work.LogImports {
		if record.Kind == StoryLogImportSession {
			if err := s.applyStoryLogImport(ctx, tx, record, cache); err != nil {
				return err
			}
		}
	}
	for _, record := range work.LogImports {
		if record.Kind != StoryLogImportSession && record.Kind != StoryLogImportEntry {
			if err := s.applyStoryLogImport(ctx, tx, record, cache); err != nil {
				return err
			}
		}
	}
	return s.applyStoryLogEntryImports(ctx, tx, work.LogImports, cache)
}

type preparedStoryLogImport struct {
	identity []byte
	scope    []byte
	owner    []byte
	digest   []byte
}

func (s *GORMStore) prepareStoryLogImport(
	ctx context.Context,
	tx *gorm.DB,
	record StoryLogImportRecord,
	cache *storyLogImportApplyCache,
) (preparedStoryLogImport, error) {
	if _, err := normalizeStoryLogImport(record); err != nil {
		return preparedStoryLogImport{}, err
	}
	scopeKey := storyLogImportScopeKey{diceID: record.DiceID, groupID: record.GroupID}
	material, ok := cache.scopes[scopeKey]
	if !ok {
		if strings.TrimSpace(record.DiceID) == "" || strings.TrimSpace(record.GroupID) == "" {
			return preparedStoryLogImport{}, ErrInvalidMetadata
		}
		scope, err := privacyHMACWithMaterial(cache.indexMaterial, "story-log-scope/v1", privacyCanonical(record.DiceID, record.GroupID))
		if err != nil {
			return preparedStoryLogImport{}, err
		}
		owner, err := privacyHMACWithMaterial(cache.indexMaterial, "privacy-subject/v1", record.GroupID)
		if err != nil {
			return preparedStoryLogImport{}, err
		}
		material = storyLogImportScopeMaterial{scope: scope, owner: owner}
		cache.scopes[scopeKey] = material
	}
	if _, checked := cache.fences[string(material.owner)]; !checked {
		if err := privacyCheckSubjectFence(ctx, tx, material.owner); err != nil {
			return preparedStoryLogImport{}, err
		}
		cache.fences[string(material.owner)] = struct{}{}
	}
	identity, ok := cache.identities[record.SourceID]
	if !ok {
		return preparedStoryLogImport{}, ErrInvalidMetadata
	}
	digest, err := storyLogImportSemanticDigestWithMaterial(cache.indexMaterial, record)
	if err != nil {
		return preparedStoryLogImport{}, err
	}
	return preparedStoryLogImport{
		identity: identity, scope: material.scope, owner: material.owner, digest: digest,
	}, nil
}

func storyLogImportDiceKey(record StoryLogImportRecord, cache *storyLogImportApplyCache) ([]byte, error) {
	if diceKey, ok := cache.diceKeys[record.DiceID]; ok {
		return diceKey, nil
	}
	diceKey, err := privacyHMACWithMaterial(cache.indexMaterial, "story-log-dice/v1", record.DiceID)
	if err != nil {
		return nil, err
	}
	cache.diceKeys[record.DiceID] = diceKey
	return diceKey, nil
}

func (s *GORMStore) applyStoryLogImport(ctx context.Context, tx *gorm.DB, record StoryLogImportRecord, cache *storyLogImportApplyCache) error {
	prepared, err := s.prepareStoryLogImport(ctx, tx, record, cache)
	if err != nil {
		return err
	}
	if prior, exists := cache.prior[string(prepared.identity)]; exists {
		if !hmac.Equal(prior.ScopeHMAC, prepared.scope) || !hmac.Equal(prior.OwnerHMAC, prepared.owner) || prior.Kind != string(record.Kind) {
			return ErrParticipantConflict
		}
		actual, err := s.storyLogImportRecordFromRow(ctx, tx, prior)
		if err != nil {
			return err
		}
		actualDigest, err := storyLogImportSemanticDigestWithMaterial(cache.indexMaterial, actual)
		if err != nil {
			return err
		}
		if !hmac.Equal(actualDigest, prior.SemanticHMAC) || !hmac.Equal(actualDigest, prepared.digest) {
			return ErrParticipantConflict
		}
		return nil
	}
	diceKey, err := storyLogImportDiceKey(record, cache)
	if err != nil {
		return err
	}
	resourceID, err := s.writeStoryLogImportResource(ctx, tx, record, prepared.scope, prepared.owner, diceKey, cache)
	if err != nil {
		return err
	}
	private, err := json.Marshal(storyLogImportPrivate{SourceID: record.SourceID, SessionSourceID: record.SessionSourceID})
	if err != nil {
		return ErrInvalidMetadata
	}
	cipherText, nonce, keyID, err := cache.seal("story-log-import/v1", storyLogImportAAD(prepared.identity), logOwner(prepared.owner), 1, private)
	if err != nil {
		return err
	}
	row := storyLogImportRow{
		IdentityHMAC: prepared.identity, ScopeHMAC: prepared.scope, OwnerHMAC: prepared.owner, DiceHMAC: diceKey,
		Kind: string(record.Kind), ResourceID: resourceID, SemanticHMAC: prepared.digest,
		Payload: cipherText, Nonce: nonce, EncryptionKeyID: keyID, Version: 1,
	}
	if err := tx.Create(&row).Error; err != nil {
		return ErrParticipantFailure
	}
	cache.prior[string(prepared.identity)] = row
	if session, exists := cache.sessions[record.SourceID]; exists {
		session.importRow = row
		cache.sessions[record.SourceID] = session
	}
	return nil
}

func reserveSQLiteStoryLogEntryIDs(tx *gorm.DB, rows []logArchiveEntryRow) (bool, error) {
	if tx == nil || tx.Dialector == nil || tx.Name() != "sqlite" {
		return false, nil
	}
	if len(rows) == 0 {
		return true, nil
	}
	lock := tx.Exec(
		"UPDATE store_readiness SET singleton_id = singleton_id WHERE singleton_id = ?",
		"default",
	)
	if lock.Error != nil || lock.RowsAffected != 1 {
		return false, ErrParticipantFailure
	}
	var maxID int64
	if err := tx.Raw("SELECT COALESCE(MAX(id), 0) FROM story_log_entries").Scan(&maxID).Error; err != nil || maxID < 0 {
		return false, ErrParticipantFailure
	}
	const maxSQLiteRowID = uint64(1<<63 - 1)
	base := uint64(maxID)
	if uint64(len(rows)) > maxSQLiteRowID-base {
		return false, ErrVersionExhausted
	}
	for index := range rows {
		rows[index].ID = base + uint64(index) + 1
	}
	return true, nil
}

func insertSQLiteStoryLogEntryRows(tx *gorm.DB, rows []logArchiveEntryRow) error {
	if tx == nil || len(rows) == 0 {
		return ErrParticipantFailure
	}
	var query strings.Builder
	query.Grow(len(rows) * 512)
	query.WriteString("INSERT INTO story_log_entries (id,scope_hmac,owner_hmac,session_id,raw_msg_hmac,payload,nonce,encryption_key_id,version) VALUES ")
	for index, row := range rows {
		if index != 0 {
			query.WriteByte(',')
		}
		query.WriteByte('(')
		writeSQLiteUint(&query, row.ID)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.ScopeHMAC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.OwnerHMAC)
		query.WriteByte(',')
		writeSQLiteUint(&query, row.SessionID)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.RawMsgHMAC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.Payload)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.Nonce)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.EncryptionKeyID)
		query.WriteByte(',')
		writeSQLiteUint(&query, row.Version)
		query.WriteByte(')')
	}
	result := tx.Exec(query.String())
	if result.Error != nil || result.RowsAffected != int64(len(rows)) {
		return ErrParticipantFailure
	}
	return nil
}

func insertSQLiteStoryLogImportRows(tx *gorm.DB, rows []storyLogImportRow) error {
	if tx == nil || len(rows) == 0 {
		return ErrParticipantFailure
	}
	var query strings.Builder
	query.Grow(len(rows) * 512)
	query.WriteString("INSERT INTO story_log_imports (identity_hmac,scope_hmac,owner_hmac,dice_hmac,kind,resource_id,semantic_hmac,payload,nonce,encryption_key_id,version) VALUES ")
	for index, row := range rows {
		if index != 0 {
			query.WriteByte(',')
		}
		query.WriteByte('(')
		writeSQLiteBlobLiteral(&query, row.IdentityHMAC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.ScopeHMAC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.OwnerHMAC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.DiceHMAC)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.Kind)
		query.WriteByte(',')
		writeSQLiteUint(&query, row.ResourceID)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.SemanticHMAC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.Payload)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.Nonce)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.EncryptionKeyID)
		query.WriteByte(',')
		writeSQLiteUint(&query, row.Version)
		query.WriteByte(')')
	}
	result := tx.Exec(query.String())
	if result.Error != nil || result.RowsAffected != int64(len(rows)) {
		return ErrParticipantFailure
	}
	return nil
}

func updateStoryLogEntryPayloads(tx *gorm.DB, rows []logArchiveEntryRow) error {
	if tx == nil {
		return ErrParticipantFailure
	}
	if len(rows) == 0 {
		return nil
	}
	const columnCount = 3
	columnNames := [columnCount]string{"payload", "nonce", "encryption_key_id"}
	var query strings.Builder
	query.Grow(len(rows) * 96)
	query.WriteString("UPDATE story_log_entries SET ")
	args := make([]any, 0, len(rows)*(columnCount*2+1))
	for columnIndex, columnName := range columnNames {
		if columnIndex != 0 {
			query.WriteString(", ")
		}
		query.WriteString(columnName)
		query.WriteString(" = CASE id ")
		for rowIndex := range rows {
			query.WriteString("WHEN ? THEN ? ")
			args = append(args, rows[rowIndex].ID)
			switch columnIndex {
			case 0:
				args = append(args, rows[rowIndex].Payload)
			case 1:
				args = append(args, rows[rowIndex].Nonce)
			default:
				args = append(args, rows[rowIndex].EncryptionKeyID)
			}
		}
		query.WriteString("ELSE ")
		query.WriteString(columnName)
		query.WriteString(" END")
	}
	query.WriteString(" WHERE id IN (")
	for index := range rows {
		if index != 0 {
			query.WriteByte(',')
		}
		query.WriteByte('?')
		args = append(args, rows[index].ID)
	}
	query.WriteByte(')')
	result := tx.Exec(query.String(), args...)
	if result.Error != nil || result.RowsAffected != int64(len(rows)) {
		return ErrParticipantFailure
	}
	return nil
}

type pendingStoryLogEntryImport struct {
	record      StoryLogImportRecord
	prepared    preparedStoryLogImport
	diceKey     []byte
	private     []byte
	resourceRow int
}

func (s *GORMStore) applyStoryLogEntryImports(
	ctx context.Context,
	tx *gorm.DB,
	records []StoryLogImportRecord,
	cache *storyLogImportApplyCache,
) error {
	pending := make([]pendingStoryLogEntryImport, 0, len(records))
	resourceRows := make([]logArchiveEntryRow, 0, len(records))
	for _, record := range records {
		if record.Kind != StoryLogImportEntry {
			continue
		}
		identity, ok := cache.identities[record.SourceID]
		if !ok {
			return ErrInvalidMetadata
		}
		if _, exists := cache.prior[string(identity)]; exists {
			if err := s.applyStoryLogImport(ctx, tx, record, cache); err != nil {
				return err
			}
			continue
		}
		prepared, err := s.prepareStoryLogImport(ctx, tx, record, cache)
		if err != nil {
			return err
		}
		diceKey, err := storyLogImportDiceKey(record, cache)
		if err != nil {
			return err
		}
		_, session, err := s.importedSessionBySourceCached(ctx, tx, record.SessionSourceID, prepared.scope, prepared.owner, cache)
		if err != nil {
			return err
		}
		entry := *record.Entry
		if entry.LogName != session.Name {
			return ErrInvalidMetadata
		}
		entry.DiceID, entry.GroupID = record.DiceID, record.GroupID
		private, err := json.Marshal(storyLogEntryPrivate{
			DiceID: entry.DiceID, GroupID: entry.GroupID, LogName: entry.LogName,
			Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: entry.Time,
			Message: entry.Message, IsDice: entry.IsDice, CommandID: entry.CommandID,
			CommandInfo: cloneRawMessage(entry.CommandInfo), RawMsgID: entry.RawMsgID,
			UniformID: entry.UniformID, Seq: cloneInt64(entry.Seq), Removed: cloneInt(entry.Removed),
			ParentID: cloneInt(entry.ParentID),
		})
		if err != nil {
			return ErrInvalidMetadata
		}
		rawHMAC := []byte(nil)
		if entry.RawMsgID != "" {
			rawHMAC, err = privacyHMACWithMaterial(cache.indexMaterial, "story-log-raw-id/v1", storyLogRawIdentity(prepared.scope, entry.RawMsgID))
			if err != nil {
				return err
			}
		}
		resourceRows = append(resourceRows, logArchiveEntryRow{
			ScopeHMAC: prepared.scope, OwnerHMAC: prepared.owner, SessionID: session.ID, RawMsgHMAC: rawHMAC,
			Payload: []byte{0}, Nonce: []byte{0}, EncryptionKeyID: "pending", Version: 1,
		})
		pending = append(pending, pendingStoryLogEntryImport{
			record: record, prepared: prepared, diceKey: diceKey, private: private,
			resourceRow: len(resourceRows) - 1,
		})
	}
	if len(pending) == 0 {
		return nil
	}
	reservedSQLiteIDs, err := reserveSQLiteStoryLogEntryIDs(tx, resourceRows)
	if err != nil {
		return err
	}
	if !reservedSQLiteIDs {
		if err := tx.CreateInBatches(&resourceRows, len(resourceRows)).Error; err != nil {
			return ErrParticipantFailure
		}
	}
	for index := range pending {
		item := &pending[index]
		row := &resourceRows[item.resourceRow]
		if row.ID == 0 {
			return ErrParticipantFailure
		}
		cipherText, nonce, keyID, err := cache.seal(
			"story-log-entry/v1", logAADIdentity(item.prepared.scope, row.ID),
			logOwner(item.prepared.owner), row.Version, item.private,
		)
		if err != nil {
			return err
		}
		row.Payload, row.Nonce, row.EncryptionKeyID = cipherText, nonce, keyID
		clear(item.private)
		item.private = nil
	}
	if reservedSQLiteIDs {
		if err := insertSQLiteStoryLogEntryRows(tx, resourceRows); err != nil {
			return err
		}
	} else if err := updateStoryLogEntryPayloads(tx, resourceRows); err != nil {
		return err
	}
	importRows := make([]storyLogImportRow, len(pending))
	for index := range pending {
		item := &pending[index]
		resourceID := resourceRows[item.resourceRow].ID
		private, err := json.Marshal(storyLogImportPrivate{
			SourceID: item.record.SourceID, SessionSourceID: item.record.SessionSourceID,
		})
		if err != nil {
			return ErrInvalidMetadata
		}
		cipherText, nonce, keyID, err := cache.seal(
			"story-log-import/v1", storyLogImportAAD(item.prepared.identity),
			logOwner(item.prepared.owner), 1, private,
		)
		if err != nil {
			return err
		}
		importRows[index] = storyLogImportRow{
			IdentityHMAC: item.prepared.identity, ScopeHMAC: item.prepared.scope,
			OwnerHMAC: item.prepared.owner, DiceHMAC: item.diceKey,
			Kind: string(StoryLogImportEntry), ResourceID: resourceID,
			SemanticHMAC: item.prepared.digest, Payload: cipherText, Nonce: nonce,
			EncryptionKeyID: keyID, Version: 1,
		}
	}
	if reservedSQLiteIDs {
		if err := insertSQLiteStoryLogImportRows(tx, importRows); err != nil {
			return err
		}
	} else if err := tx.CreateInBatches(&importRows, len(importRows)).Error; err != nil {
		return ErrParticipantFailure
	}
	for index, row := range importRows {
		cache.prior[string(pending[index].prepared.identity)] = row
	}
	return nil
}

func (s *GORMStore) writeStoryLogImportResource(
	ctx context.Context,
	tx *gorm.DB,
	record StoryLogImportRecord,
	scope, owner, diceKey []byte,
	cache *storyLogImportApplyCache,
) (uint64, error) {
	switch record.Kind {
	case StoryLogImportSession:
		resourceID, err := s.writeImportedSession(tx, record, scope, owner, diceKey, cache)
		if err != nil {
			return 0, err
		}
		session := *record.Session
		session.ID, session.DiceID, session.GroupID = resourceID, record.DiceID, record.GroupID
		cache.sessions[record.SourceID] = storyLogImportedSession{
			importRow: storyLogImportRow{
				ScopeHMAC: scope, OwnerHMAC: owner, Kind: string(StoryLogImportSession), ResourceID: resourceID,
			},
			session: session,
		}
		return resourceID, nil
	case StoryLogImportEntry:
		return s.writeImportedEntry(ctx, tx, record, scope, owner, cache)
	case StoryLogImportState:
		state := *record.State
		state.DiceID, state.GroupID = record.DiceID, record.GroupID
		if record.SessionSourceID != "" {
			sessionImport, session, err := s.importedSessionBySourceCached(ctx, tx, record.SessionSourceID, scope, owner, cache)
			if err != nil {
				return 0, err
			}
			if session.Name != state.Name {
				return 0, ErrInvalidMetadata
			}
			state.SessionID = sessionImport.ResourceID
		} else {
			state.SessionID = 0
		}
		if err := s.applyStoryLogUpdate(ctx, tx, LogUpdate{Kind: logUpdateSetState, DiceID: record.DiceID, GroupID: record.GroupID, Name: state.Name, State: state}); err != nil {
			return 0, err
		}
		return 0, nil
	default:
		return 0, ErrInvalidMetadata
	}
}

func (s *GORMStore) writeImportedSession(
	tx *gorm.DB,
	record StoryLogImportRecord,
	scope, owner, diceKey []byte,
	cache *storyLogImportApplyCache,
) (uint64, error) {
	input := *record.Session
	nameKey, err := privacyHMACWithMaterial(cache.indexMaterial, "story-log-name/v1", privacyCanonical(record.DiceID, record.GroupID, input.Name))
	if err != nil {
		return 0, err
	}
	var existing storyLogSessionRow
	if err := tx.Where("scope_hmac = ? AND name_hmac = ?", scope, nameKey).Take(&existing).Error; err == nil {
		return 0, ErrParticipantConflict
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, ErrParticipantFailure
	}
	private := storyLogSessionPrivate{DiceID: record.DiceID, GroupID: record.GroupID, Name: input.Name, UploadURL: input.UploadURL, UploadTime: input.UploadTime, Extra: cloneString(input.Extra)}
	plain, err := json.Marshal(private)
	if err != nil {
		return 0, ErrInvalidMetadata
	}
	row := storyLogSessionRow{DiceHMAC: diceKey, ScopeHMAC: scope, OwnerHMAC: owner, NameHMAC: nameKey, Payload: []byte{0}, Nonce: []byte{0}, EncryptionKeyID: "pending", Version: 1, CreatedAt: input.CreatedAt, UpdatedAt: input.UpdatedAt}
	if err := tx.Create(&row).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	cipherText, nonce, keyID, err := cache.seal("story-log-session/v1", logAADIdentity(scope, row.ID), logOwner(owner), row.Version, plain)
	if err != nil {
		return 0, err
	}
	if err := tx.Model(&storyLogSessionRow{}).Where("id = ?", row.ID).UpdateColumns(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID}).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	return row.ID, nil
}

func (s *GORMStore) importedSessionBySourceCached(
	ctx context.Context,
	tx *gorm.DB,
	sourceID string,
	scope, owner []byte,
	cache *storyLogImportApplyCache,
) (storyLogImportRow, StoryLogSession, error) {
	if cached, ok := cache.sessions[sourceID]; ok {
		if cached.importRow.Kind != string(StoryLogImportSession) ||
			!hmac.Equal(cached.importRow.ScopeHMAC, scope) || !hmac.Equal(cached.importRow.OwnerHMAC, owner) {
			return storyLogImportRow{}, StoryLogSession{}, ErrInvalidMetadata
		}
		return cached.importRow, cached.session, nil
	}
	identity, ok := cache.identities[sourceID]
	if !ok {
		return storyLogImportRow{}, StoryLogSession{}, ErrInvalidMetadata
	}
	sessionImport, ok := cache.prior[string(identity)]
	if !ok {
		return storyLogImportRow{}, StoryLogSession{}, ErrNotFound
	}
	if sessionImport.Kind != string(StoryLogImportSession) ||
		!hmac.Equal(sessionImport.ScopeHMAC, scope) || !hmac.Equal(sessionImport.OwnerHMAC, owner) {
		return storyLogImportRow{}, StoryLogSession{}, ErrInvalidMetadata
	}
	var sessionRow storyLogSessionRow
	if err := tx.Where("id = ? AND scope_hmac = ?", sessionImport.ResourceID, scope).Take(&sessionRow).Error; err != nil {
		return storyLogImportRow{}, StoryLogSession{}, ErrParticipantFailure
	}
	session, err := s.storyLogSession(ctx, sessionRow)
	if err != nil {
		return storyLogImportRow{}, StoryLogSession{}, err
	}
	cache.sessions[sourceID] = storyLogImportedSession{importRow: sessionImport, session: session}
	return sessionImport, session, nil
}

func (s *GORMStore) writeImportedEntry(
	ctx context.Context,
	tx *gorm.DB,
	record StoryLogImportRecord,
	scope, owner []byte,
	cache *storyLogImportApplyCache,
) (uint64, error) {
	_, session, err := s.importedSessionBySourceCached(ctx, tx, record.SessionSourceID, scope, owner, cache)
	if err != nil {
		return 0, err
	}
	entry := record.Entry
	if entry.LogName != session.Name {
		return 0, ErrInvalidMetadata
	}
	private := storyLogEntryPrivate{DiceID: record.DiceID, GroupID: record.GroupID, LogName: entry.LogName, Nickname: entry.Nickname, IMUserID: entry.IMUserID, Time: entry.Time, Message: entry.Message, IsDice: entry.IsDice, CommandID: entry.CommandID, CommandInfo: cloneRawMessage(entry.CommandInfo), RawMsgID: entry.RawMsgID, UniformID: entry.UniformID, Seq: cloneInt64(entry.Seq), Removed: cloneInt(entry.Removed), ParentID: cloneInt(entry.ParentID)}
	plain, err := json.Marshal(private)
	if err != nil {
		return 0, ErrInvalidMetadata
	}
	rawHMAC := []byte(nil)
	if entry.RawMsgID != "" {
		rawHMAC, err = privacyHMACWithMaterial(cache.indexMaterial, "story-log-raw-id/v1", storyLogRawIdentity(scope, entry.RawMsgID))
		if err != nil {
			return 0, err
		}
	}
	row := logArchiveEntryRow{
		ScopeHMAC: scope, OwnerHMAC: owner, SessionID: session.ID, RawMsgHMAC: rawHMAC,
		Payload: []byte{0}, Nonce: []byte{0}, EncryptionKeyID: "pending", Version: 1,
	}
	if err := tx.Create(&row).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	cipherText, nonce, keyID, err := cache.seal("story-log-entry/v1", logAADIdentity(scope, row.ID), logOwner(owner), row.Version, plain)
	if err != nil {
		return 0, err
	}
	if err := tx.Model(&logArchiveEntryRow{}).Where("id = ?", row.ID).Updates(map[string]any{"payload": cipherText, "nonce": nonce, "encryption_key_id": keyID}).Error; err != nil {
		return 0, ErrParticipantFailure
	}
	return row.ID, nil
}

func (s *GORMStore) storyLogImportRecordFromRow(ctx context.Context, tx *gorm.DB, row storyLogImportRow) (StoryLogImportRecord, error) {
	plain, err := s.openStoryLogImport(ctx, row.IdentityHMAC, row.OwnerHMAC, row)
	if err != nil {
		return StoryLogImportRecord{}, err
	}
	var identity storyLogImportPrivate
	if json.Unmarshal(plain, &identity) != nil || identity.SourceID == "" {
		return StoryLogImportRecord{}, ErrAuthenticationFailed
	}
	record := StoryLogImportRecord{SourceID: identity.SourceID, Kind: StoryLogImportKind(row.Kind)}
	switch record.Kind {
	case StoryLogImportSession:
		var sessionRow storyLogSessionRow
		if err := tx.Where("id = ? AND scope_hmac = ?", row.ResourceID, row.ScopeHMAC).Take(&sessionRow).Error; err != nil {
			return StoryLogImportRecord{}, ErrNotFound
		}
		session, err := s.storyLogSession(ctx, sessionRow)
		if err != nil {
			return StoryLogImportRecord{}, err
		}
		record.DiceID, record.GroupID = session.DiceID, session.GroupID
		record.Session = &session
	case StoryLogImportEntry:
		var entryRow logArchiveEntryRow
		if err := tx.Where("id = ? AND scope_hmac = ?", row.ResourceID, row.ScopeHMAC).Take(&entryRow).Error; err != nil {
			return StoryLogImportRecord{}, ErrNotFound
		}
		entry, err := s.storyLogEntry(ctx, entryRow)
		if err != nil {
			return StoryLogImportRecord{}, err
		}
		record.DiceID, record.GroupID, record.Entry = entry.DiceID, entry.GroupID, &entry
		var sessionImport storyLogImportRow
		if err := tx.Where("scope_hmac = ? AND kind = ? AND resource_id = ?", row.ScopeHMAC, string(StoryLogImportSession), entry.LogID).Take(&sessionImport).Error; err != nil {
			return StoryLogImportRecord{}, ErrNotFound
		}
		sessionPrivate, err := s.openStoryLogImport(ctx, sessionImport.IdentityHMAC, sessionImport.OwnerHMAC, sessionImport)
		if err != nil {
			return StoryLogImportRecord{}, err
		}
		var sessionIdentity storyLogImportPrivate
		if json.Unmarshal(sessionPrivate, &sessionIdentity) != nil || sessionIdentity.SourceID == "" {
			return StoryLogImportRecord{}, ErrAuthenticationFailed
		}
		record.SessionSourceID = sessionIdentity.SourceID
	case StoryLogImportState:
		var stateRow storyLogStateRow
		if err := tx.Where("scope_hmac = ?", row.ScopeHMAC).Take(&stateRow).Error; err != nil {
			return StoryLogImportRecord{}, ErrNotFound
		}
		private, err := s.openStoryLog(ctx, "story-log-state/v1", row.ScopeHMAC, row.OwnerHMAC, 0, stateRow.Version, stateRow.EncryptionKeyID, stateRow.Payload, stateRow.Nonce)
		if err != nil {
			return StoryLogImportRecord{}, err
		}
		var state storyLogStatePrivate
		if json.Unmarshal(private, &state) != nil {
			return StoryLogImportRecord{}, ErrAuthenticationFailed
		}
		record.DiceID, record.GroupID = state.DiceID, state.GroupID
		publicState := StoryLogState(state)
		record.State = &publicState
		if state.SessionID != 0 {
			var sessionImport storyLogImportRow
			if err := tx.Where("scope_hmac = ? AND kind = ? AND resource_id = ?", row.ScopeHMAC, string(StoryLogImportSession), state.SessionID).Take(&sessionImport).Error; err != nil {
				return StoryLogImportRecord{}, ErrNotFound
			}
			sessionPrivate, err := s.openStoryLogImport(ctx, sessionImport.IdentityHMAC, sessionImport.OwnerHMAC, sessionImport)
			if err != nil {
				return StoryLogImportRecord{}, err
			}
			var sessionIdentity storyLogImportPrivate
			if json.Unmarshal(sessionPrivate, &sessionIdentity) != nil || sessionIdentity.SourceID == "" {
				return StoryLogImportRecord{}, ErrAuthenticationFailed
			}
			record.SessionSourceID = sessionIdentity.SourceID
		}
	default:
		return StoryLogImportRecord{}, ErrAuthenticationFailed
	}
	if identity.SessionSourceID != record.SessionSourceID {
		return StoryLogImportRecord{}, ErrAuthenticationFailed
	}
	return record, nil
}

func (s *GORMStore) storyLogEntry(ctx context.Context, row logArchiveEntryRow) (StoryLogEntry, error) {
	plain, err := s.openStoryLog(ctx, "story-log-entry/v1", row.ScopeHMAC, row.OwnerHMAC, row.ID, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce)
	if err != nil {
		return StoryLogEntry{}, err
	}
	var private storyLogEntryPrivate
	if json.Unmarshal(plain, &private) != nil {
		return StoryLogEntry{}, ErrAuthenticationFailed
	}
	return StoryLogEntry{ID: row.ID, LogID: row.SessionID, DiceID: private.DiceID, GroupID: private.GroupID, LogName: private.LogName, Nickname: private.Nickname, IMUserID: private.IMUserID, Time: private.Time, Message: private.Message, IsDice: private.IsDice, CommandID: private.CommandID, CommandInfo: cloneRawMessage(private.CommandInfo), RawMsgID: private.RawMsgID, UniformID: private.UniformID, Seq: cloneInt64(private.Seq), Removed: cloneInt(private.Removed), ParentID: cloneInt(private.ParentID)}, nil
}

type storyLogImportSessionReference struct {
	scope      string
	resourceID uint64
}

type decodedStoryLogImport struct {
	identity storyLogImportPrivate
	record   StoryLogImportRecord
}

type storyLogImportRootCache struct {
	roots map[string][]byte
	aeads map[string]cipher.AEAD
}

func newStoryLogImportRootCache() *storyLogImportRootCache {
	return &storyLogImportRootCache{
		roots: make(map[string][]byte),
		aeads: make(map[string]cipher.AEAD),
	}
}

func (cache *storyLogImportRootCache) clear() {
	if cache == nil {
		return
	}
	for keyID, material := range cache.roots {
		clear(material)
		delete(cache.roots, keyID)
	}
	clear(cache.aeads)
}

func (s *GORMStore) openA6WithRootCache(
	ctx context.Context,
	cache *storyLogImportRootCache,
	domain, identity, owner string,
	version uint64,
	keyID string,
	ciphertext, nonce []byte,
) ([]byte, error) {
	if s == nil || s.keySource == nil || cache == nil {
		return nil, ErrKeySourceUnavailable
	}
	cacheKey := keyID + "\x00" + domain
	aead := cache.aeads[cacheKey]
	if aead == nil {
		root, ok := cache.roots[keyID]
		if !ok {
			material, err := keySourceRoot(ctx, s.keySource, keyID)
			if err != nil {
				return nil, err
			}
			root = append([]byte(nil), material...)
			cache.roots[keyID] = root
		}
		var err error
		aead, err = newA6AEAD(root, domain)
		if err != nil {
			return nil, err
		}
		cache.aeads[cacheKey] = aead
	}
	return a6OpenWithAEAD(aead, domain, identity, owner, version, keyID, ciphertext, nonce)
}

func (s *GORMStore) openStoryLogImportWithRootCache(
	ctx context.Context,
	cache *storyLogImportRootCache,
	identity, owner []byte,
	row storyLogImportRow,
) ([]byte, error) {
	return s.openA6WithRootCache(
		ctx, cache, "story-log-import/v1", storyLogImportAAD(identity), logOwner(owner),
		row.Version, row.EncryptionKeyID, row.Payload, row.Nonce,
	)
}

func (s *GORMStore) openStoryLogWithRootCache(
	ctx context.Context,
	cache *storyLogImportRootCache,
	domain string,
	scope, owner []byte,
	id, version uint64,
	keyID string,
	ciphertext, nonce []byte,
) ([]byte, error) {
	return s.openA6WithRootCache(
		ctx, cache, domain, logAADIdentity(scope, id), logOwner(owner),
		version, keyID, ciphertext, nonce,
	)
}

func (s *GORMStore) storyLogSessionWithRootCache(
	ctx context.Context,
	cache *storyLogImportRootCache,
	row storyLogSessionRow,
) (StoryLogSession, error) {
	plain, err := s.openStoryLogWithRootCache(
		ctx, cache, "story-log-session/v1", row.ScopeHMAC, row.OwnerHMAC,
		row.ID, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce,
	)
	if err != nil {
		return StoryLogSession{}, err
	}
	var private storyLogSessionPrivate
	if json.Unmarshal(plain, &private) != nil {
		return StoryLogSession{}, ErrAuthenticationFailed
	}
	return StoryLogSession{
		ID: row.ID, DiceID: private.DiceID, GroupID: private.GroupID, Name: private.Name,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, UploadURL: private.UploadURL,
		UploadTime: private.UploadTime, Extra: cloneString(private.Extra),
	}, nil
}

func (s *GORMStore) storyLogEntryWithRootCache(
	ctx context.Context,
	cache *storyLogImportRootCache,
	row logArchiveEntryRow,
) (StoryLogEntry, error) {
	plain, err := s.openStoryLogWithRootCache(
		ctx, cache, "story-log-entry/v1", row.ScopeHMAC, row.OwnerHMAC,
		row.ID, row.Version, row.EncryptionKeyID, row.Payload, row.Nonce,
	)
	if err != nil {
		return StoryLogEntry{}, err
	}
	var private storyLogEntryPrivate
	if json.Unmarshal(plain, &private) != nil {
		return StoryLogEntry{}, ErrAuthenticationFailed
	}
	return StoryLogEntry{
		ID: row.ID, LogID: row.SessionID, DiceID: private.DiceID, GroupID: private.GroupID,
		LogName: private.LogName, Nickname: private.Nickname, IMUserID: private.IMUserID,
		Time: private.Time, Message: private.Message, IsDice: private.IsDice, CommandID: private.CommandID,
		CommandInfo: cloneRawMessage(private.CommandInfo), RawMsgID: private.RawMsgID,
		UniformID: private.UniformID, Seq: cloneInt64(private.Seq), Removed: cloneInt(private.Removed),
		ParentID: cloneInt(private.ParentID),
	}, nil
}

func (s *GORMStore) storyLogImportSessionSources(
	ctx context.Context,
	tx *gorm.DB,
	diceKey []byte,
	roots *storyLogImportRootCache,
) (map[storyLogImportSessionReference]string, error) {
	query := tx.WithContext(ctx).Where("kind = ?", string(StoryLogImportSession))
	if len(diceKey) != 0 {
		query = query.Where("dice_hmac = ?", diceKey)
	}
	var imports []storyLogImportRow
	if err := query.Find(&imports).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	sessionSources := make(map[storyLogImportSessionReference]string, len(imports))
	for _, row := range imports {
		key := storyLogImportSessionReference{scope: string(row.ScopeHMAC), resourceID: row.ResourceID}
		if _, exists := sessionSources[key]; exists {
			return nil, ErrAuthenticationFailed
		}
		private, err := s.openStoryLogImportWithRootCache(ctx, roots, row.IdentityHMAC, row.OwnerHMAC, row)
		if err != nil {
			return nil, err
		}
		var identity storyLogImportPrivate
		if json.Unmarshal(private, &identity) != nil || identity.SourceID == "" || identity.SessionSourceID != "" {
			return nil, ErrAuthenticationFailed
		}
		sessionSources[key] = identity.SourceID
	}
	return sessionSources, nil
}

func contiguousUint64Range(values []uint64) (uint64, uint64, bool) {
	if len(values) == 0 {
		return 0, 0, false
	}
	first, last := values[0], values[0]
	for _, value := range values[1:] {
		if value < first {
			first = value
		}
		if value > last {
			last = value
		}
	}
	return first, last, last-first == uint64(len(values)-1)
}

func (s *GORMStore) storyLogImportRecordsFromRows(
	ctx context.Context,
	tx *gorm.DB,
	rows []storyLogImportRow,
	roots *storyLogImportRootCache,
	sessionSources map[storyLogImportSessionReference]string,
) ([]StoryLogImportRecord, error) {
	decoded := make([]decodedStoryLogImport, len(rows))
	sessionIDs := make([]uint64, 0, len(rows))
	entryIDs := make([]uint64, 0, len(rows))
	stateScopes := make([][]byte, 0, len(rows))
	sessionIDSet := make(map[uint64]struct{})
	entryIDSet := make(map[uint64]struct{})
	stateScopeSet := make(map[string]struct{})
	for index, row := range rows {
		plain, err := s.openStoryLogImportWithRootCache(ctx, roots, row.IdentityHMAC, row.OwnerHMAC, row)
		if err != nil {
			return nil, err
		}
		var identity storyLogImportPrivate
		if json.Unmarshal(plain, &identity) != nil || identity.SourceID == "" {
			return nil, ErrAuthenticationFailed
		}
		record := StoryLogImportRecord{SourceID: identity.SourceID, Kind: StoryLogImportKind(row.Kind)}
		switch record.Kind {
		case StoryLogImportSession:
			if _, exists := sessionIDSet[row.ResourceID]; !exists {
				sessionIDSet[row.ResourceID] = struct{}{}
				sessionIDs = append(sessionIDs, row.ResourceID)
			}
		case StoryLogImportEntry:
			if _, exists := entryIDSet[row.ResourceID]; !exists {
				entryIDSet[row.ResourceID] = struct{}{}
				entryIDs = append(entryIDs, row.ResourceID)
			}
		case StoryLogImportState:
			scopeKey := string(row.ScopeHMAC)
			if _, exists := stateScopeSet[scopeKey]; !exists {
				stateScopeSet[scopeKey] = struct{}{}
				stateScopes = append(stateScopes, row.ScopeHMAC)
			}
		default:
			return nil, ErrAuthenticationFailed
		}
		decoded[index] = decodedStoryLogImport{identity: identity, record: record}
	}

	sessions := make(map[uint64]storyLogSessionRow, len(sessionIDs))
	if len(sessionIDs) != 0 {
		var found []storyLogSessionRow
		query := tx.WithContext(ctx)
		if first, last, contiguous := contiguousUint64Range(sessionIDs); contiguous {
			query = query.Where("id BETWEEN ? AND ?", first, last)
		} else {
			query = query.Where("id IN ?", sessionIDs)
		}
		if err := query.Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			if _, exists := sessions[row.ID]; exists {
				return nil, ErrAuthenticationFailed
			}
			sessions[row.ID] = row
		}
	}
	entries := make(map[uint64]logArchiveEntryRow, len(entryIDs))
	if len(entryIDs) != 0 {
		var found []logArchiveEntryRow
		query := tx.WithContext(ctx)
		if first, last, contiguous := contiguousUint64Range(entryIDs); contiguous {
			query = query.Where("id BETWEEN ? AND ?", first, last)
		} else {
			query = query.Where("id IN ?", entryIDs)
		}
		if err := query.Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			if _, exists := entries[row.ID]; exists {
				return nil, ErrAuthenticationFailed
			}
			entries[row.ID] = row
		}
	}
	states := make(map[string]storyLogStateRow, len(stateScopes))
	if len(stateScopes) != 0 {
		var found []storyLogStateRow
		if err := tx.WithContext(ctx).Where("scope_hmac IN ?", stateScopes).Find(&found).Error; err != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range found {
			key := string(row.ScopeHMAC)
			if _, exists := states[key]; exists {
				return nil, ErrAuthenticationFailed
			}
			states[key] = row
		}
	}

	sessionReferences := make([]storyLogImportSessionReference, len(rows))
	hasSessionReference := make([]bool, len(rows))
	for index, row := range rows {
		record := &decoded[index].record
		switch record.Kind {
		case StoryLogImportSession:
			sessionRow, ok := sessions[row.ResourceID]
			if !ok || !hmac.Equal(sessionRow.ScopeHMAC, row.ScopeHMAC) {
				return nil, ErrNotFound
			}
			session, err := s.storyLogSessionWithRootCache(ctx, roots, sessionRow)
			if err != nil {
				return nil, err
			}
			record.DiceID, record.GroupID, record.Session = session.DiceID, session.GroupID, &session
		case StoryLogImportEntry:
			entryRow, ok := entries[row.ResourceID]
			if !ok || !hmac.Equal(entryRow.ScopeHMAC, row.ScopeHMAC) {
				return nil, ErrNotFound
			}
			entry, err := s.storyLogEntryWithRootCache(ctx, roots, entryRow)
			if err != nil {
				return nil, err
			}
			record.DiceID, record.GroupID, record.Entry = entry.DiceID, entry.GroupID, &entry
			sessionReferences[index] = storyLogImportSessionReference{scope: string(row.ScopeHMAC), resourceID: entry.LogID}
			hasSessionReference[index] = true
		case StoryLogImportState:
			stateRow, ok := states[string(row.ScopeHMAC)]
			if !ok {
				return nil, ErrNotFound
			}
			private, err := s.openStoryLogWithRootCache(ctx, roots, "story-log-state/v1", row.ScopeHMAC, row.OwnerHMAC, 0, stateRow.Version, stateRow.EncryptionKeyID, stateRow.Payload, stateRow.Nonce)
			if err != nil {
				return nil, err
			}
			var state storyLogStatePrivate
			if json.Unmarshal(private, &state) != nil {
				return nil, ErrAuthenticationFailed
			}
			record.DiceID, record.GroupID = state.DiceID, state.GroupID
			record.State = &StoryLogState{DiceID: state.DiceID, GroupID: state.GroupID, SessionID: state.SessionID, Name: state.Name, On: state.On}
			if state.SessionID != 0 {
				sessionReferences[index] = storyLogImportSessionReference{scope: string(row.ScopeHMAC), resourceID: state.SessionID}
				hasSessionReference[index] = true
			}
		}
	}

	records := make([]StoryLogImportRecord, len(rows))
	for index := range decoded {
		record := decoded[index].record
		if hasSessionReference[index] {
			sourceID, ok := sessionSources[sessionReferences[index]]
			if !ok {
				return nil, ErrNotFound
			}
			record.SessionSourceID = sourceID
		}
		if decoded[index].identity.SessionSourceID != record.SessionSourceID {
			return nil, ErrAuthenticationFailed
		}
		records[index] = record
	}
	return records, nil
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

	_, material, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return nil, err
	}
	indexMaterial := append([]byte(nil), material...)
	defer clear(indexMaterial)
	identities := make([][]byte, len(records))
	for index, record := range records {
		identities[index], err = storyLogImportIdentityWithMaterial(indexMaterial, record.SourceID)
		if err != nil {
			return nil, err
		}
	}
	var found []storyLogImportRow
	tx := s.db.GORM().WithContext(ctx)
	if err = tx.Where("identity_hmac IN ?", identities).Find(&found).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	if len(found) != len(records) {
		return nil, ErrNotFound
	}
	foundByIdentity := make(map[string]storyLogImportRow, len(found))
	for _, row := range found {
		key := string(row.IdentityHMAC)
		if _, exists := foundByIdentity[key]; exists {
			return nil, ErrAuthenticationFailed
		}
		foundByIdentity[key] = row
	}
	rows := make([]storyLogImportRow, len(records))
	for index, identity := range identities {
		row, ok := foundByIdentity[string(identity)]
		if !ok {
			return nil, ErrNotFound
		}
		rows[index] = row
	}

	roots := newStoryLogImportRootCache()
	defer roots.clear()
	sessionSources, err := s.storyLogImportSessionSources(ctx, tx, nil, roots)
	if err != nil {
		return nil, err
	}
	actualRecords, err := s.storyLogImportRecordsFromRows(ctx, tx, rows, roots, sessionSources)
	if err != nil {
		return nil, err
	}
	if len(actualRecords) != len(records) {
		return nil, ErrAuthenticationFailed
	}
	receipts := make([]StoryLogImportReceipt, 0, len(records))
	for index, actual := range actualRecords {
		// #nosec G602 -- Both slices have equal lengths, checked immediately above.
		if actual.SourceID != records[index].SourceID {
			return nil, ErrAuthenticationFailed
		}
		digest, digestErr := storyLogImportSemanticDigestWithMaterial(indexMaterial, actual)
		if digestErr != nil {
			return nil, digestErr
		}
		row := rows[index]
		if !hmac.Equal(digest, row.SemanticHMAC) {
			clear(digest)
			return nil, ErrAuthenticationFailed
		}
		receipts = append(receipts, StoryLogImportReceipt{
			SourceID: actual.SourceID, Kind: StoryLogImportKind(row.Kind),
			SemanticDigest: digest, ResourceID: row.ResourceID,
		})
	}
	return receipts, nil
}

func (s *GORMStore) ListStoryLogImports(ctx context.Context, sourcePrefix, diceID string) ([]StoryLogImportReceipt, error) {
	out := make([]StoryLogImportReceipt, 0)
	err := s.VisitStoryLogImports(ctx, sourcePrefix, diceID, func(receipt StoryLogImportReceipt) error {
		receipt.SemanticDigest = append([]byte(nil), receipt.SemanticDigest...)
		out = append(out, receipt)
		return nil
	})
	if err != nil {
		for index := range out {
			clear(out[index].SemanticDigest)
		}
		return nil, err
	}
	return out, nil
}

// VisitStoryLogImports authenticates imported archive rows in bounded pages.
// The receipt digest is valid only for the duration of the callback.
func (s *GORMStore) VisitStoryLogImports(ctx context.Context, sourcePrefix, diceID string, visit func(StoryLogImportReceipt) error) error {
	if visit == nil {
		return ErrInvalidMetadata
	}
	_, material, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return err
	}
	indexMaterial := append([]byte(nil), material...)
	defer clear(indexMaterial)
	var diceKey []byte
	if diceID != "" {
		diceKey, err = privacyHMACWithMaterial(indexMaterial, "story-log-dice/v1", diceID)
		if err != nil {
			return err
		}
	}
	roots := newStoryLogImportRootCache()
	defer roots.clear()
	sessionSources, err := s.storyLogImportSessionSources(ctx, s.db.GORM(), diceKey, roots)
	if err != nil {
		return fmt.Errorf("load story log import sessions: %w", err)
	}
	const readbackBatchSize = MaxUnitOfWorkEvents
	sqliteRows := s.db.GORM().Name() == "sqlite"
	var identityCursor []byte
	var sqliteRowCursor int64
	for {
		var rows []storyLogImportRow
		if sqliteRows {
			var query *gorm.DB
			if len(diceKey) == 0 {
				query = s.db.GORM().WithContext(ctx).Raw(
					"SELECT _rowid_ AS import_rowid, * FROM story_log_imports NOT INDEXED WHERE _rowid_ > ? ORDER BY _rowid_ ASC LIMIT ?",
					sqliteRowCursor, readbackBatchSize,
				)
			} else {
				query = s.db.GORM().WithContext(ctx).Raw(
					"SELECT _rowid_ AS import_rowid, * FROM story_log_imports NOT INDEXED WHERE _rowid_ > ? AND dice_hmac = ? ORDER BY _rowid_ ASC LIMIT ?",
					sqliteRowCursor, diceKey, readbackBatchSize,
				)
			}
			if err = query.Scan(&rows).Error; err != nil {
				return fmt.Errorf("read SQLite story log import page: %w", ErrParticipantFailure)
			}
			if len(rows) != 0 {
				sqliteRowCursor = rows[len(rows)-1].ImportRowID
			}
		} else {
			page := s.db.GORM().WithContext(ctx).Model(&storyLogImportRow{})
			if len(diceKey) != 0 {
				page = page.Where("dice_hmac = ?", diceKey)
			}
			if len(identityCursor) != 0 {
				page = page.Where("identity_hmac > ?", identityCursor)
			}
			if err = page.Order("identity_hmac ASC").Limit(readbackBatchSize).Find(&rows).Error; err != nil {
				return fmt.Errorf("read story log import page: %w", ErrParticipantFailure)
			}
		}
		if len(rows) == 0 {
			break
		}
		actualRecords, decodeErr := s.storyLogImportRecordsFromRows(ctx, s.db.GORM(), rows, roots, sessionSources)
		if decodeErr != nil {
			return fmt.Errorf("decode story log import readback batch: %w", decodeErr)
		}
		for index, actual := range actualRecords {
			if sourcePrefix != "" && !strings.HasPrefix(actual.SourceID, sourcePrefix) {
				continue
			}
			digest, digestErr := storyLogImportSemanticDigestWithMaterial(indexMaterial, actual)
			if digestErr != nil {
				return digestErr
			}
			row := rows[index]
			if !hmac.Equal(digest, row.SemanticHMAC) {
				clear(digest)
				return fmt.Errorf("story log import semantic digest mismatch for kind %q: %w", row.Kind, ErrAuthenticationFailed)
			}
			receipt := StoryLogImportReceipt{
				SourceID: actual.SourceID, Kind: StoryLogImportKind(row.Kind),
				SemanticDigest: digest, ResourceID: row.ResourceID,
			}
			visitErr := visit(receipt)
			clear(digest)
			if visitErr != nil {
				return visitErr
			}
		}
		if !sqliteRows {
			identityCursor = append(identityCursor[:0], rows[len(rows)-1].IdentityHMAC...)
		}
		if len(rows) < readbackBatchSize {
			break
		}
	}
	return nil
}
