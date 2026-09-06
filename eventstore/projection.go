package eventstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	projectionPageSize         = 1000
	projectionGenerationKey    = "eventstore.projection_generation"
	supportedEventSchemaVersion = uint16(1)
)

// ProjectionRow is the generation-aware read shape exposed by the narrow
// projection reader. Generation is selected once when the read transaction
// starts and is never changed for that transaction.
type ProjectionRow struct {
	ProjectionGeneration string
	ProjectionName       string
	RowKey               string
	Payload              []byte
	UpdatedAt            time.Time
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
		Payload:              append([]byte(nil), payload...),
		UpdatedAt:            time.Now().UTC(),
	}
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "projection_generation"}, {Name: "projection_name"}, {Name: "row_key"}},
		DoUpdates: clause.AssignmentColumns([]string{"payload", "updated_at"}),
	}).Create(&row).Error
}

func PutProjectionRow(tx *gorm.DB, projectionName, rowKey string, payload []byte) error {
	return UpsertProjectionRow(tx, projectionName, rowKey, payload)
}

func projectorSetVersion(projectors []ProjectionDescriptor) string {
	if len(projectors) == 0 {
		return "initial"
	}
	ordered := append([]ProjectionDescriptor(nil), projectors...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	version := ordered[0].Version
	allSame := true
	for _, projector := range ordered[1:] {
		if projector.Version != version {
			allSame = false
			break
		}
	}
	if allSame {
		return version
	}
	parts := make([]string, len(ordered))
	for i, projector := range ordered {
		parts[i] = projector.Name + "=" + projector.Version
	}
	return strings.Join(parts, "|")
}

func (s *GORMStore) projectorSnapshot() ([]ProjectionDescriptor, string, error) {
	if s == nil {
		return nil, "", errors.New("eventstore: store unavailable")
	}
	s.mu.RLock()
	projectors := append([]ProjectionDescriptor(nil), s.projectors...)
	s.mu.RUnlock()
	if len(projectors) == 0 {
		return nil, "", ErrInvalidProjector
	}
	return projectors, projectorSetVersion(projectors), nil
}

func (s *GORMStore) Rebuild(ctx context.Context, request RebuildRequest) (RebuildResult, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return RebuildResult{}, errors.New("eventstore: store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	projectors, setVersion, err := s.projectorSnapshot()
	if err != nil {
		return RebuildResult{}, err
	}
	if request.ProjectorVersion == "" || request.ProjectorVersion != setVersion {
		return RebuildResult{}, ErrProjectorVersionConflict
	}
	base := s.db.GORM().WithContext(ctx)
	var control projectionControlRow
	if err := base.Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: read projection control failed")
	}
	highWater, err := s.highWater(ctx)
	if err != nil {
		return RebuildResult{}, err
	}
	generation, err := (UUIDGenerator{}).NewID()
	if err != nil {
		return RebuildResult{}, errors.New("eventstore: allocate projection generation failed")
	}
	cursor := uint64(0)
	for cursor < highWater {
		rows, err := loadProjectionEventPage(base, cursor, highWater)
		if err != nil {
			return RebuildResult{}, err
		}
		if len(rows) == 0 {
			return RebuildResult{}, errors.New("eventstore: projection event scan stalled")
		}
		if err := s.applyProjectionPage(ctx, generation, rows, projectors); err != nil {
			return RebuildResult{}, err
		}
		cursor = rows[len(rows)-1].GlobalPosition
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
		if len(rows) == 0 {
			return RebuildResult{}, errors.New("eventstore: projection catch-up stalled")
		}
		if err := s.applyProjectionPage(ctx, generation, rows, projectors); err != nil {
			return RebuildResult{}, err
		}
		cursor = rows[len(rows)-1].GlobalPosition
	}
	return s.publishProjection(ctx, generation, cursor, projectors, setVersion)
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
		Payload:        append([]byte(nil), row.Payload...),
		Metadata: Metadata{
			EventID:                   row.EventID,
			CommandID:                row.CommandID,
			CorrelationID:            row.CorrelationID,
			CausationID:              row.CausationID,
			PrincipalID:              row.PrincipalID,
			Producer:                 row.Producer,
			OccurredAtUnixNanoUTC:    row.OccurredAtUnixNanoUTC,
			OccurredAtUnixNanoSet:    true,
		},
		Checksum: checksum,
	}
	if ComputeEventChecksum(envelope) != checksum {
		return Envelope{}, ErrChecksumMismatch
	}
	return envelope, nil
}

func (s *GORMStore) applyProjectionPage(ctx context.Context, generation string, rows []domainEventRow, projectors []ProjectionDescriptor) error {
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
	tx = tx.Set(projectionGenerationKey, generation)
	for _, projector := range projectors {
		if err := projector.Apply(ctx, tx, envelopes); err != nil {
			return ErrProjectorFailure
		}
	}
	if err := tx.Commit().Error; err != nil {
		return errors.New("eventstore: commit projection transaction failed")
	}
	committed = true
	return nil
}

func (s *GORMStore) publishProjection(ctx context.Context, generation string, cursor uint64, projectors []ProjectionDescriptor, setVersion string) (RebuildResult, error) {
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
	var control projectionControlRow
	if err := locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: lock projection control failed")
	}
	s.observeLock(tableProjectionControl)
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
		if len(rows) == 0 {
			return RebuildResult{}, errors.New("eventstore: projection final scan stalled")
		}
		envelopes := make([]Envelope, len(rows))
		for i, row := range rows {
			envelope, err := projectionEnvelope(row)
			if err != nil {
				return RebuildResult{}, err
			}
			envelopes[i] = envelope
		}
		tx = tx.Set(projectionGenerationKey, generation)
		for _, projector := range projectors {
			if err := projector.Apply(ctx, tx, envelopes); err != nil {
				return RebuildResult{}, ErrProjectorFailure
			}
		}
		cursor = rows[len(rows)-1].GlobalPosition
	}
	if err := validateProjectionRows(tx, generation); err != nil {
		return RebuildResult{}, err
	}
	digest, err := digestProjectionRows(tx, generation)
	if err != nil {
		return RebuildResult{}, errors.New("eventstore: compute projection digest failed")
	}
	if err := tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
		"active_generation": generation,
		"terminal_position": cursor,
		"projector_set_version": setVersion,
		"publication_state": "published",
		"updated_at": time.Now().UTC(),
	}).Error; err != nil {
		return RebuildResult{}, errors.New("eventstore: publish projection generation failed")
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
	if err := tx.Where("projection_generation = ?", generation).
		Order("projection_name ASC, row_key ASC").Find(&rows).Error; err != nil {
		return EventChecksum{}, err
	}
	hash := sha256.New()
	writeCanonicalString(hash, "eventstore.projection.digest.v1")
	for _, row := range rows {
		writeCanonicalString(hash, "row")
		writeCanonicalString(hash, "projection_name")
		writeCanonicalString(hash, row.ProjectionName)
		writeCanonicalString(hash, "row_key")
		writeCanonicalString(hash, row.RowKey)
		writeCanonicalString(hash, "payload")
		writeCanonicalBytes(hash, row.Payload, row.Payload == nil)
	}
	var digest EventChecksum
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (s *GORMStore) DigestProjection(ctx context.Context, generation string) (EventChecksum, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return EventChecksum{}, errors.New("eventstore: store unavailable")
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
	var control projectionControlRow
	if err := tx.Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return ProjectionRow{}, errors.New("eventstore: read projection control failed")
	}
	var row projectionReadModelRow
	if err := tx.Where("projection_generation = ? AND projection_name = ? AND row_key = ?", control.ActiveGeneration, projectionName, rowKey).First(&row).Error; err != nil {
		return ProjectionRow{}, err
	}
	if err := tx.Commit().Error; err != nil {
		return ProjectionRow{}, errors.New("eventstore: commit projection read failed")
	}
	committed = true
	return ProjectionRow{ProjectionGeneration: row.ProjectionGeneration, ProjectionName: row.ProjectionName, RowKey: row.RowKey, Payload: append([]byte(nil), row.Payload...), UpdatedAt: row.UpdatedAt}, nil
}
