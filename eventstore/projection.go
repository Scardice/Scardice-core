package eventstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	projectionPageSize          = 1000
	projectionGenerationKey     = "eventstore.projection_generation"
	supportedEventSchemaVersion = uint16(1)

	// MaxProjectionReadPageRows is the hard upper bound for one keyset page.
	MaxProjectionReadPageRows = 5000
)

// ProjectionRow is the generation-aware read shape exposed by the narrow
// projection reader. Generation is selected once when the read transaction
// starts and is never changed for that transaction.
type ProjectionRow struct {
	ProjectionGeneration string
	ProjectionName       string
	RowKey               string

	Payload   []byte
	UpdatedAt time.Time
}

// ProjectionSnapshot identifies one published logical projection state.
// Generation changes on rebuild publication, TerminalPosition changes on
// live projection writes, and HistoryRevision changes on privacy deletion.
// A paged reader must carry the complete value into every subsequent page.
type ProjectionSnapshot struct {
	Generation       string
	TerminalPosition uint64
	HistoryRevision  uint64
}

// ProjectionPageRequest selects an optional row-key prefix or half-open
// database row-key range and an exclusive keyset cursor. Limit must be between
// 1 and MaxProjectionReadPageRows. RowKeyStart and RowKeyEnd must either both
// be empty or both be set. When Prefix and bounds are both supplied, SQLite
// uses the binary bounds while other dialects use anchored Prefix matching to
// avoid locale-collation omissions. ExpectedSnapshot is nil only for the first
// page of an unvalidated scan. Callers needing byte-exact identity scope must
// validate returned keys because database collations vary.
type ProjectionPageRequest struct {
	ProjectionName   string
	RowKeyPrefix     string
	RowKeyStart      string
	RowKeyEnd        string
	AfterRowKey      string
	Limit            int
	ExpectedSnapshot *ProjectionSnapshot
}

// ProjectionPage contains at most the requested number of rows. Done is true
// only for an empty terminal page, so consumers can process the preceding page
// outside the database transaction and then perform one final snapshot check.
type ProjectionPage struct {
	Snapshot   ProjectionSnapshot
	Rows       []ProjectionRow
	NextRowKey string
	Done       bool
}

func copyProjectionBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte{}, value...)
}

func ProjectionGeneration(tx *gorm.DB) string {
	if tx == nil {
		return ""
	}
	value, ok := tx.Get(projectionGenerationKey)
	if !ok {
		return ""
	}
	generation, _ := value.(string)
	return generation
}

// withProjectionGeneration attaches the generation projectors write to. Set
// alone returns a handle whose statement keeps every condition added to it, so
// the handle is turned into a session: each query made from it, here or inside
// a projector, starts clean.
func withProjectionGeneration(tx *gorm.DB, generation string) *gorm.DB {
	return tx.Set(projectionGenerationKey, generation).Session(&gorm.Session{})
}

func CurrentProjectionGeneration(tx *gorm.DB) string { return ProjectionGeneration(tx) }

// UpsertProjectionRow writes to the generation selected by the surrounding
// live or rebuild transaction. Projectors should use this helper rather than
// choosing a generation themselves.
func UpsertProjectionRow(tx *gorm.DB, projectionName, rowKey string, payload []byte) error {
	generation := ProjectionGeneration(tx)
	if tx == nil || generation == "" || projectionName == "" || rowKey == "" {
		return ErrProjectionInvariant
	}
	row := projectionReadModelRow{
		ProjectionGeneration: generation,
		ProjectionName:       projectionName,
		RowKey:               rowKey,
		Payload:              copyProjectionBytes(payload),
		PayloadPresent:       payload != nil,
		UpdatedAt:            time.Now().UTC(),
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "projection_generation"}, {Name: "projection_name"}, {Name: "row_key"}},
		DoUpdates: clause.AssignmentColumns([]string{"payload", "payload_present", "updated_at"}),
	}).Create(&row).Error
}

func PutProjectionRow(tx *gorm.DB, projectionName, rowKey string, payload []byte) error {
	return UpsertProjectionRow(tx, projectionName, rowKey, payload)
}

func stableProjectors(projectors []ProjectionDescriptor) []ProjectionDescriptor {
	stable := make([]ProjectionDescriptor, 0, len(projectors))
	for _, projector := range projectors {
		if !projector.Legacy {
			stable = append(stable, projector)
		}
	}
	return stable
}

func projectorSetVersion(projectors []ProjectionDescriptor) string {
	ordered := append([]ProjectionDescriptor(nil), projectors...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	var builder strings.Builder
	builder.WriteString("eventstore.projector-set.v1;")
	for _, projector := range ordered {
		builder.WriteString(strconv.Itoa(len(projector.Name)))
		builder.WriteByte(':')
		builder.WriteString(projector.Name)
		builder.WriteString(strconv.Itoa(len(projector.Version)))
		builder.WriteByte(':')
		builder.WriteString(projector.Version)
	}
	encoded := builder.String()
	if len(encoded) <= 255 {
		return encoded
	}
	sum := sha256.Sum256([]byte(encoded))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sameProjectors(a, b []ProjectionDescriptor) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Version != b[i].Version || a[i].Legacy != b[i].Legacy {
			return false
		}
	}
	return true
}

func (s *GORMStore) projectorSnapshot() ([]ProjectionDescriptor, string, error) {
	if s == nil {
		return nil, "", errors.New("eventstore: store unavailable")
	}
	s.projectorMu.RLock()
	defer s.projectorMu.RUnlock()
	for _, projector := range s.projectors {
		if projector.Legacy {
			return nil, "", ErrLegacyProjector
		}
	}
	projectors := append([]ProjectionDescriptor(nil), s.projectors...)
	if len(projectors) == 0 {
		return nil, "", ErrInvalidProjector
	}
	return projectors, projectorSetVersion(projectors), nil
}
func projectorRequestVersion(projectors []ProjectionDescriptor, requested, canonical string) bool {
	if requested == canonical {
		return true
	}
	if len(projectors) == 0 {
		return false
	}
	for _, projector := range projectors {
		if projector.Version != requested {
			return false
		}
	}
	return true
}

func (s *GORMStore) Rebuild(ctx context.Context, request RebuildRequest) (RebuildResult, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return RebuildResult{}, errors.New("eventstore: store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return RebuildResult{}, err
	}
	projectors, setVersion, projectionErr := s.projectorSnapshot()
	if projectionErr != nil {
		return RebuildResult{}, projectionErr
	}
	if request.ProjectorVersion == "" || !projectorRequestVersion(projectors, request.ProjectorVersion, setVersion) {
		return RebuildResult{}, ErrProjectorVersionConflict
	}
	base := s.db.GORM().WithContext(ctx)
	var control projectionControlRow
	if err := base.Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: read projection control failed")
	}
	highWater, projectionErr := s.highWater(ctx)
	if projectionErr != nil {
		return RebuildResult{}, projectionErr
	}
	generation, projectionErr := (UUIDGenerator{}).NewID()
	if projectionErr != nil {
		return RebuildResult{}, errors.New("eventstore: allocate projection generation failed")
	}
	cursor := uint64(0)
	for cursor < highWater {
		rows, err := loadProjectionEventPage(base, cursor, highWater)
		if err != nil {
			return RebuildResult{}, err
		}
		next, err := validateProjectionPage(base, rows, cursor, highWater)
		if err != nil {
			return RebuildResult{}, err
		}
		if err := s.applyProjectionPage(ctx, generation, &control, rows, projectors); err != nil {
			return RebuildResult{}, err
		}
		cursor = next
	}

	// Catch up outside the publication fence. Once the observed lag is one
	// page or less, the final transaction takes the fence before re-reading it.
	for {
		latest, err := s.highWater(ctx)
		if err != nil {
			return RebuildResult{}, err
		}
		if latest <= cursor || latest-cursor <= projectionPageSize {
			break
		}
		rows, err := loadProjectionEventPage(base, cursor, latest)
		if err != nil {
			return RebuildResult{}, err
		}
		next, err := validateProjectionPage(base, rows, cursor, latest)
		if err != nil {
			return RebuildResult{}, err
		}
		if err := s.applyProjectionPage(ctx, generation, &control, rows, projectors); err != nil {
			return RebuildResult{}, err
		}
		cursor = next
	}
	return s.publishProjection(ctx, generation, &control, cursor, projectors, setVersion)
}

func (s *GORMStore) highWater(ctx context.Context) (uint64, error) {
	var sequence eventGlobalSequenceRow
	if err := s.db.GORM().WithContext(ctx).Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
		return 0, errors.New("eventstore: read event sequence failed")
	}
	if sequence.NextPosition == 0 {
		return 0, nil
	}
	return sequence.NextPosition - 1, nil
}

func validateProjectionPage(db *gorm.DB, rows []domainEventRow, cursor, highWater uint64) (uint64, error) {
	if cursor > highWater {
		return 0, ErrProjectionInvariant
	}
	for _, row := range rows {
		if row.GlobalPosition <= cursor || row.GlobalPosition > highWater {
			return 0, ErrProjectionInvariant
		}
		if err := validateProjectionGap(db, cursor, row.GlobalPosition-1); err != nil {
			return 0, err
		}
		cursor = row.GlobalPosition
	}
	if len(rows) == 0 {
		if err := validateProjectionGap(db, cursor, highWater); err != nil {
			return 0, err
		}
		cursor = highWater
	}
	return cursor, nil
}

func validateProjectionGap(db *gorm.DB, after, through uint64) error {
	if through <= after {
		return nil
	}
	var count int64
	if err := db.Model(&eventTombstoneRow{}).Where("global_position > ? AND global_position <= ?", after, through).Count(&count).Error; err != nil {
		return ErrParticipantFailure
	}
	if count < 0 || uint64(count) != through-after {
		return ErrProjectionInvariant
	}
	return nil
}

func loadProjectionEventPage(db *gorm.DB, cursor, highWater uint64) ([]domainEventRow, error) {
	var rows []domainEventRow
	query := db.Where("global_position > ? AND global_position <= ?", cursor, highWater).
		Order("global_position ASC").Limit(projectionPageSize).Find(&rows)
	if query.Error != nil {
		return nil, errors.New("eventstore: scan projection events failed")
	}
	return rows, nil
}

func projectionEnvelope(row domainEventRow) (Envelope, error) {
	if row.AggregateType == "" || row.AggregateID == "" || row.AggregateVersion == 0 ||
		row.GlobalPosition == 0 || row.EventID == "" || row.EventType == "" ||
		row.CommandID == "" || row.CorrelationID == "" ||
		row.SchemaVersion == 0 || len(row.Payload) > MaxEventPayloadBytes {
		return Envelope{}, ErrInvalidEvent
	}
	if row.SchemaVersion != supportedEventSchemaVersion {
		return Envelope{}, ErrUnsupportedEventSchema
	}
	var checksum EventChecksum
	if len(row.Checksum) != len(checksum) {
		return Envelope{}, ErrChecksumMismatch
	}
	copy(checksum[:], row.Checksum)
	envelope := Envelope{
		Stream:         StreamID{AggregateType: row.AggregateType, AggregateID: row.AggregateID},
		StreamVersion:  row.AggregateVersion,
		GlobalPosition: row.GlobalPosition,
		EventID:        row.EventID,
		EventType:      row.EventType,
		SchemaVersion:  row.SchemaVersion,
		Payload:        copyProjectionBytes(row.Payload),
		Metadata: Metadata{
			EventID:               row.EventID,
			CommandID:             row.CommandID,
			CorrelationID:         row.CorrelationID,
			CausationID:           row.CausationID,
			PrincipalID:           row.PrincipalID,
			Producer:              row.Producer,
			OccurredAtUnixNanoUTC: row.OccurredAtUnixNanoUTC,
			OccurredAtUnixNanoSet: true,
		},
		Checksum: checksum,
	}
	return verifyEnvelopeChecksum(envelope)
}

func (s *GORMStore) applyProjectionPage(ctx context.Context, generation string, source *projectionControlRow, rows []domainEventRow, projectors []ProjectionDescriptor) error {
	if len(rows) == 0 {
		return nil
	}
	envelopes := make([]Envelope, len(rows))
	for i, row := range rows {
		envelope, err := projectionEnvelope(row)
		if err != nil {
			return err
		}
		envelopes[i] = envelope
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return errors.New("eventstore: begin projection transaction failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	if err := validateProjectionSource(tx, source); err != nil {
		return err
	}
	tx = withProjectionGeneration(tx, generation)
	for _, projector := range projectors {
		if err := projector.Apply(ctx, tx, envelopes); err != nil {
			return errors.Join(ErrProjectorFailure, err)
		}
	}
	if err := tx.Commit().Error; err != nil {
		return errors.New("eventstore: commit projection transaction failed")
	}
	committed = true
	return nil
}

func validateProjectionSource(tx *gorm.DB, source *projectionControlRow) error {
	var current projectionControlRow
	if err := tx.Where("singleton_id = ?", "default").First(&current).Error; err != nil {
		return ErrParticipantFailure
	}
	// Publication can remove an in-flight shadow generation even when no
	// additional events were erased. Fence both changes, not just the high-water mark.
	if current.ActiveGeneration != source.ActiveGeneration || current.HistoryRevision != source.HistoryRevision {
		return ErrParticipantConflict
	}
	return nil
}

func (s *GORMStore) publishProjection(ctx context.Context, generation string, source *projectionControlRow, cursor uint64, projectors []ProjectionDescriptor, setVersion string) (RebuildResult, error) {
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return RebuildResult{}, errors.New("eventstore: begin projection publication failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()
	var readiness storeReadinessRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&readiness).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: lock readiness failed")
	}
	s.observeLock(tableStoreReadiness)
	var control projectionControlRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: lock projection control failed")
	}
	s.observeLock(tableProjectionControl)
	if control.ActiveGeneration != source.ActiveGeneration || control.HistoryRevision != source.HistoryRevision {
		return RebuildResult{}, ErrParticipantConflict
	}
	var sequence eventGlobalSequenceRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: lock event sequence failed")
	}
	latest := uint64(0)
	if sequence.NextPosition > 0 {
		latest = sequence.NextPosition - 1
	}
	if latest < cursor {
		return RebuildResult{}, errors.New("eventstore: projection terminal regressed")
	}
	for cursor < latest {
		rows, err := loadProjectionEventPage(tx, cursor, latest)
		if err != nil {
			return RebuildResult{}, err
		}
		next, err := validateProjectionPage(tx, rows, cursor, latest)
		if err != nil {
			return RebuildResult{}, err
		}
		cursor = next
		if len(rows) == 0 {
			continue
		}
		envelopes := make([]Envelope, len(rows))
		for i, row := range rows {
			envelope, err := projectionEnvelope(row)
			if err != nil {
				return RebuildResult{}, err
			}
			envelopes[i] = envelope
		}
		projectionTx := withProjectionGeneration(tx, generation)
		for _, projector := range projectors {
			if err := projector.Apply(ctx, projectionTx, envelopes); err != nil {
				return RebuildResult{}, errors.Join(ErrProjectorFailure, err)
			}
		}
	}
	s.projectorMu.RLock()
	defer s.projectorMu.RUnlock()
	currentAll := append([]ProjectionDescriptor(nil), s.projectors...)
	if !sameProjectors(currentAll, projectors) {
		return RebuildResult{}, ErrProjectorRegistryChanged
	}
	current := stableProjectors(currentAll)
	if setVersion != projectorSetVersion(current) {
		return RebuildResult{}, ErrProjectorRegistryChanged
	}
	if err := validateProjectionRows(tx, generation); err != nil {
		return RebuildResult{}, err
	}
	digest, err := digestProjectionRows(tx, generation)
	if err != nil {
		return RebuildResult{}, errors.New("eventstore: compute projection digest failed")
	}
	if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
		"active_generation":     generation,
		"terminal_position":     cursor,
		"projector_set_version": setVersion,
		"publication_state":     "published",
		"updated_at":            time.Now().UTC(),
	}).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: publish projection generation failed")
	}
	if readiness.Mode == "import" {
		if err := tx.Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
			"terminal_global_position":     latest,
			"terminal_projection_position": cursor,
		}).Error; err != nil {
			return RebuildResult{}, errors.New("eventstore: publish readiness terminal failed")
		}
	}
	if s.keySource != nil {
		if err := s.validateReadinessOnDB(ctx, tx, false); err != nil {
			return RebuildResult{}, err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: commit projection publication failed")
	}
	committed = true
	return RebuildResult{GenerationID: generation, TerminalPosition: cursor, Digest: digest}, nil
}

func validateProjectionRows(tx *gorm.DB, generation string) error {
	var rows []projectionReadModelRow
	if err := tx.Where("projection_generation = ?", generation).Find(&rows).Error; err != nil {
		return ErrProjectionInvariant
	}
	for _, row := range rows {
		if row.ProjectionGeneration != generation || row.ProjectionName == "" || row.RowKey == "" {
			return ErrProjectionInvariant
		}
	}
	return nil
}

func digestProjectionRows(tx *gorm.DB, generation string) (EventChecksum, error) {
	var rows []projectionReadModelRow
	if err := tx.Where("projection_generation = ?", generation).Find(&rows).Error; err != nil {
		return EventChecksum{}, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ProjectionName != rows[j].ProjectionName {
			return rows[i].ProjectionName < rows[j].ProjectionName
		}
		return rows[i].RowKey < rows[j].RowKey
	})
	hash := sha256.New()
	writeCanonicalString(hash, "eventstore.projection.digest.v1")
	for _, row := range rows {
		writeCanonicalString(hash, "row")
		writeCanonicalString(hash, "projection_name")
		writeCanonicalString(hash, row.ProjectionName)
		writeCanonicalString(hash, "row_key")
		writeCanonicalString(hash, row.RowKey)
		writeCanonicalString(hash, "payload")
		payload := projectionPayload(row)
		writeCanonicalBytes(hash, payload, payload == nil)
	}
	var digest EventChecksum
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (s *GORMStore) DigestProjection(ctx context.Context, generation string) (EventChecksum, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return EventChecksum{}, errors.New("eventstore: store unavailable")
	}
	if err := s.requireReady(ctx); err != nil {
		return EventChecksum{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	digest, err := digestProjectionRows(s.db.GORM().WithContext(ctx), generation)
	if err != nil {
		return EventChecksum{}, errors.New("eventstore: compute projection digest failed")
	}
	return digest, nil
}

func (s *GORMStore) ReadProjectionRow(ctx context.Context, projectionName, rowKey string) (ProjectionRow, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ProjectionRow{}, errors.New("eventstore: store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return ProjectionRow{}, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ProjectionRow{}, errors.New("eventstore: begin projection read failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return ProjectionRow{}, err
	}
	var control projectionControlRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return ProjectionRow{}, ErrParticipantFailure
	}
	var row projectionReadModelRow
	queryErr := locked(tx).Where("projection_generation = ? AND projection_name = ? AND row_key = ?", control.ActiveGeneration, projectionName, rowKey).First(&row).Error
	if errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return ProjectionRow{}, ErrNotFound
	}
	if queryErr != nil {
		return ProjectionRow{}, ErrParticipantFailure
	}
	if err := tx.Commit().Error; err != nil {
		return ProjectionRow{}, errors.New("eventstore: commit projection read failed")
	}
	committed = true
	return ProjectionRow{ProjectionGeneration: row.ProjectionGeneration, ProjectionName: row.ProjectionName, RowKey: row.RowKey, Payload: projectionPayload(row), UpdatedAt: row.UpdatedAt}, nil
}

func projectionSnapshot(control projectionControlRow) ProjectionSnapshot {
	return ProjectionSnapshot{
		Generation:       control.ActiveGeneration,
		TerminalPosition: control.TerminalPosition,
		HistoryRevision:  control.HistoryRevision,
	}
}

func validateProjectionPageRequest(request ProjectionPageRequest) error {
	if strings.TrimSpace(request.ProjectionName) == "" ||
		request.Limit <= 0 || request.Limit > MaxProjectionReadPageRows ||
		(request.RowKeyStart == "") != (request.RowKeyEnd == "") ||
		(request.RowKeyStart != "" && request.RowKeyStart >= request.RowKeyEnd) {
		return ErrProjectionInvariant
	}
	if request.ExpectedSnapshot != nil && request.ExpectedSnapshot.Generation == "" {
		return ErrProjectionInvariant
	}
	if request.AfterRowKey != "" && request.ExpectedSnapshot == nil {
		return ErrProjectionInvariant
	}
	return nil
}

func projectionPageQuery(db *gorm.DB, snapshot ProjectionSnapshot, request ProjectionPageRequest) *gorm.DB {
	query := locked(db).Where(
		"projection_generation = ? AND projection_name = ?",
		snapshot.Generation,
		request.ProjectionName,
	)
	if request.RowKeyPrefix != "" {
		query = query.Where("row_key LIKE ? ESCAPE ?", privacyLikePrefix(request.RowKeyPrefix), `\`)
	}
	if request.RowKeyStart != "" && (request.RowKeyPrefix == "" || db.Name() == "sqlite") {
		query = query.Where("row_key >= ? AND row_key < ?", request.RowKeyStart, request.RowKeyEnd)
	}
	if request.AfterRowKey != "" {
		query = query.Where("row_key > ?", request.AfterRowKey)
	}
	return query.Order("row_key ASC").Limit(request.Limit)
}

// ListProjectionRowsPage reads one bounded keyset page from a published
// projection snapshot. The transaction and publication lock are released
// before the page is returned, so callers may safely open another transaction
// while processing it. Every later page must supply the returned Snapshot;
// generation, live terminal, or privacy revision changes fail closed with
// ErrParticipantConflict instead of mixing logical snapshots.
func (s *GORMStore) ListProjectionRowsPage(ctx context.Context, request ProjectionPageRequest) (ProjectionPage, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ProjectionPage{}, errors.New("eventstore: store unavailable")
	}
	if err := validateProjectionPageRequest(request); err != nil {
		return ProjectionPage{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return ProjectionPage{}, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ProjectionPage{}, errors.New("eventstore: begin projection page read failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return ProjectionPage{}, err
	}
	var control projectionControlRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return ProjectionPage{}, ErrParticipantFailure
	}
	snapshot := projectionSnapshot(control)
	if snapshot.Generation == "" {
		return ProjectionPage{}, ErrProjectionInvariant
	}
	if request.ExpectedSnapshot != nil && snapshot != *request.ExpectedSnapshot {
		return ProjectionPage{}, ErrParticipantConflict
	}

	query := projectionPageQuery(tx, snapshot, request)
	var rows []projectionReadModelRow
	if err := query.Find(&rows).Error; err != nil {
		return ProjectionPage{}, ErrParticipantFailure
	}
	for _, row := range rows {
		if row.ProjectionGeneration != snapshot.Generation ||
			row.ProjectionName != request.ProjectionName ||
			row.RowKey == "" {
			return ProjectionPage{}, ErrProjectionInvariant
		}
	}
	if err := tx.Commit().Error; err != nil {
		return ProjectionPage{}, errors.New("eventstore: commit projection page read failed")
	}
	committed = true

	result := ProjectionPage{
		Snapshot:   snapshot,
		Rows:       make([]ProjectionRow, 0, len(rows)),
		NextRowKey: request.AfterRowKey,
		Done:       len(rows) == 0,
	}
	for _, row := range rows {
		result.Rows = append(result.Rows, ProjectionRow{
			ProjectionGeneration: row.ProjectionGeneration,
			ProjectionName:       row.ProjectionName,
			RowKey:               row.RowKey,
			Payload:              projectionPayload(row),
			UpdatedAt:            row.UpdatedAt,
		})
	}
	if len(rows) != 0 {
		result.NextRowKey = rows[len(rows)-1].RowKey
	}
	return result, nil
}

// ListProjectionRows returns the active generation rows for one projection.
// It is a read-only startup source; it never constructs a runtime or invokes
// a projector.
func (s *GORMStore) ListProjectionRows(ctx context.Context, projectionName string) ([]ProjectionRow, error) {
	return s.listProjectionRows(ctx, projectionName, nil, "")
}

// ListProjectionRowsByRowKeyPrefix keeps metadata lists in one transaction:
// unrelated live commits cannot turn a list request into a paging conflict.
func (s *GORMStore) ListProjectionRowsByRowKeyPrefix(ctx context.Context, projectionName, prefix string) ([]ProjectionRow, error) {
	if prefix == "" {
		return nil, ErrProjectionInvariant
	}
	return s.listProjectionRows(ctx, projectionName, nil, prefix)
}

// ListProjectionRowsByRowKeyFragments returns active-generation rows whose
// row key contains one of the supplied literal fragments. Callers must still
// validate the complete identity when a fragment is not a full row key.
func (s *GORMStore) ListProjectionRowsByRowKeyFragments(ctx context.Context, projectionName string, fragments []string) ([]ProjectionRow, error) {
	if len(fragments) == 0 {
		return []ProjectionRow{}, nil
	}
	for _, fragment := range fragments {
		if fragment == "" {
			return nil, ErrProjectionInvariant
		}
	}
	return s.listProjectionRows(ctx, projectionName, fragments, "")
}

func (s *GORMStore) listProjectionRows(ctx context.Context, projectionName string, keyFragments []string, rowKeyPrefix string) ([]ProjectionRow, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, errors.New("eventstore: store unavailable")
	}
	if strings.TrimSpace(projectionName) == "" {
		return nil, ErrProjectionInvariant
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return nil, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, errors.New("eventstore: begin projection read failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return nil, err
	}
	var control projectionControlRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	query := locked(tx).Where("projection_generation = ? AND projection_name = ?", control.ActiveGeneration, projectionName)
	if rowKeyPrefix != "" {
		query = query.Where("row_key LIKE ? ESCAPE ?", privacyLikePrefix(rowKeyPrefix), `\`)
	}
	if keyFragments != nil {
		clauses := make([]string, len(keyFragments))
		args := make([]any, len(keyFragments))
		for i, fragment := range keyFragments {
			clauses[i] = "row_key LIKE ? ESCAPE '\\'"
			args[i] = "%" + privacyLikePrefix(fragment)
		}
		query = query.Where("("+strings.Join(clauses, " OR ")+")", args...)
	}
	var rows []projectionReadModelRow
	if err := query.Order("row_key ASC").Find(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	if err := tx.Commit().Error; err != nil {
		return nil, errors.New("eventstore: commit projection read failed")
	}
	committed = true
	result := make([]ProjectionRow, 0, len(rows))
	for _, row := range rows {
		result = append(result, ProjectionRow{ProjectionGeneration: row.ProjectionGeneration, ProjectionName: row.ProjectionName, RowKey: row.RowKey, Payload: projectionPayload(row), UpdatedAt: row.UpdatedAt})
	}
	return result, nil
}

// ListStreamHeads returns the latest event version for each stream of one
// aggregate type. Callers can compare projection rows with the durable stream
// set before accepting a startup snapshot.
func (s *GORMStore) ListStreamHeads(ctx context.Context, aggregateType string) ([]StreamHead, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, errors.New("eventstore: store unavailable")
	}
	if strings.TrimSpace(aggregateType) == "" {
		return nil, errors.New("eventstore: aggregate type required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return nil, err
	}
	type headRow struct {
		AggregateID string
		Version     uint64
	}
	var rows []headRow
	if err := s.db.GORM().WithContext(ctx).Model(&domainEventRow{}).
		Select("aggregate_id, MAX(aggregate_version) AS version").
		Where("aggregate_type = ?", aggregateType).
		Group("aggregate_id").
		Order("aggregate_id ASC").
		Scan(&rows).Error; err != nil {
		return nil, errors.New("eventstore: list stream heads failed")
	}
	heads := make([]StreamHead, 0, len(rows))
	for _, row := range rows {
		heads = append(heads, StreamHead{
			Stream:  StreamID{AggregateType: aggregateType, AggregateID: row.AggregateID},
			Version: row.Version,
		})
	}
	return heads, nil
}

func projectionPayload(row projectionReadModelRow) []byte {
	if !row.PayloadPresent {
		return nil
	}
	if row.Payload == nil {
		return []byte{}
	}
	return copyProjectionBytes(row.Payload)
}
