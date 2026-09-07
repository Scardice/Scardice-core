package eventstore

import (
	"context"
	"errors"
	"sort"
	"sync"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrChecksumMismatch          = errors.New("eventstore: checksum mismatch")
	ErrParticipantConflict       = errors.New("eventstore: participant conflict")
	ErrParticipantFailure        = errors.New("eventstore: participant failure")
	ErrProjectorFailure         = errors.New("eventstore: projector failure")
	ErrInvalidProjector          = errors.New("eventstore: invalid projector")
	ErrDuplicateProjector       = errors.New("eventstore: duplicate projector")
	ErrProjectorVersionConflict = errors.New("eventstore: projector version conflict")
	ErrProjectorRegistryChanged = errors.New("eventstore: projector registry changed")
	ErrLegacyProjector           = errors.New("eventstore: legacy projector requires A2 live compatibility")
	ErrProjectionInvariant      = errors.New("eventstore: projection invariant failed")
	ErrVersionExhausted         = errors.New("eventstore: version exhausted")
	ErrUnsupportedEventSchema   = ErrUnsupportedSchema
)

type ParticipantConflict struct {
	Table           string
	Key             string
	ExpectedVersion uint64
	CurrentVersion  uint64
}

type ParticipantConflictError struct { Conflicts []ParticipantConflict }
func (e *ParticipantConflictError) Error() string { return ErrParticipantConflict.Error() }
func (e *ParticipantConflictError) Unwrap() error { return ErrParticipantConflict }

type Projector func(context.Context, *gorm.DB, []Envelope) error

// ProjectionDescriptor is a stable, store-local projector registration.
// Name and Version are persisted as the projector set identity during publish.
type ProjectionDescriptor struct {
	Name                string
	Version             string
	SchemaVersion       string
	ProjectorSetVersion string
	ProjectorVersion    string
	Apply               Projector
	Legacy              bool
}

type ProjectorDescriptor = ProjectionDescriptor
type ProjectorRegistration = ProjectionDescriptor
type ProjectorSpec = ProjectionDescriptor

type ParticipantHook func(context.Context, *gorm.DB, UnitOfWork) error
type StoreOption func(*GORMStore)
func WithProjector(projector any) StoreOption {
	return func(s *GORMStore) {
		if err := s.RegisterProjector(projector); err != nil {
			s.recordInitError(err)
		}
	}
}
func WithProjection(descriptor ProjectionDescriptor) StoreOption {
	return func(s *GORMStore) {
		if err := s.RegisterProjection(descriptor); err != nil {
			s.recordInitError(err)
		}
	}
}
func WithParticipant(hook ParticipantHook) StoreOption { return func(s *GORMStore) { s.RegisterParticipant(hook) } }
func WithLockObserver(observer func(string)) StoreOption { return func(s *GORMStore) { s.SetLockObserver(observer) } }
func WithClock(clock Clock) StoreOption {
	return func(s *GORMStore) { if clock != nil { s.clock = clock } }
}
func WithIDGenerator(generator IDGenerator) StoreOption {
	return func(s *GORMStore) { if generator != nil { s.ids = generator } }
}
func WithPayloadCodec(codec any) StoreOption {
	return func(s *GORMStore) {
		if s.keySource == nil {
			s.codec = codec
		}
	}
}
func WithKeySource(source KeySource) StoreOption {
	return func(s *GORMStore) {
		if source == nil {
			return
		}
		s.keySource = source
		s.codec = &a6PayloadCodec{source: source}
	}
}

type GORMStore struct {
	db *Database
	mu sync.RWMutex
	projectorMu sync.RWMutex
	initErr error
	projectors []ProjectionDescriptor
	participants []ParticipantHook
	lockObserver func(string)
	clock Clock
	ids IDGenerator
	codec any
	keySource KeySource
}
func NewStore(database *Database, options ...StoreOption) *GORMStore {
	s := &GORMStore{db: database, clock: SystemClock{}, ids: UUIDGenerator{}}
	if database != nil && database.keySource != nil {
		s.keySource = database.keySource
		s.codec = &a6PayloadCodec{source: database.keySource}
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	if s.keySource != nil {
		s.recordInitError(s.initializeA6Readiness(context.Background()))
	}
	return s
}
func descriptorVersion(descriptor ProjectionDescriptor) (string, error) {
	values := []string{
		strings.TrimSpace(descriptor.Version),
		strings.TrimSpace(descriptor.SchemaVersion),
		strings.TrimSpace(descriptor.ProjectorSetVersion),
		strings.TrimSpace(descriptor.ProjectorVersion),
	}
	version := ""
	for _, value := range values {
		if value == "" {
			continue
		}
		if version != "" && version != value {
			return "", ErrProjectorVersionConflict
		}
		version = value
	}
	if version == "" {
		return "", ErrInvalidProjector
	}
	return version, nil
}

func (s *GORMStore) recordInitError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	if s.initErr == nil {
		s.initErr = err
	}
	s.mu.Unlock()
}
func (s *GORMStore) clearInitializationError() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.initErr = nil
	s.mu.Unlock()
}


func (s *GORMStore) initializationError() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	err := s.initErr
	s.mu.RUnlock()
	return err
}

func (s *GORMStore) RegisterProjection(descriptor ProjectionDescriptor) error {
	version, err := descriptorVersion(descriptor)
	descriptor.Name = strings.TrimSpace(descriptor.Name)
	descriptor.Version = version
	if s == nil || err != nil || descriptor.Apply == nil || descriptor.Name == "" {
		if err != nil {
			return err
		}
		return ErrInvalidProjector
	}
	s.projectorMu.Lock()
	defer s.projectorMu.Unlock()
	for _, existing := range s.projectors {
		if existing.Legacy {
			continue
		}
		if existing.Version != descriptor.Version {
			return ErrProjectorVersionConflict
		}
		if existing.Name == descriptor.Name {
			return ErrDuplicateProjector
		}
	}
	s.projectors = append(s.projectors, descriptor)
	sort.Slice(s.projectors, func(i, j int) bool { return s.projectors[i].Name < s.projectors[j].Name })
	return nil
}

// RegisterProjector preserves the A2 callback form while accepting stable descriptors for A3 callers.
func (s *GORMStore) RegisterProjector(projector any) error {
	switch value := projector.(type) {
	case ProjectionDescriptor:
		return s.RegisterProjection(value)
	case Projector:
		if value == nil {
			return ErrInvalidProjector
		}
		s.projectorMu.Lock()
		name := "legacy"
		for i := range s.projectors {
			if s.projectors[i].Name == name {
				name = "legacy-" + string(rune('0'+i+1))
			}
		}
		s.projectors = append(s.projectors, ProjectionDescriptor{Name: name, Version: "legacy", Apply: value, Legacy: true})
		sort.Slice(s.projectors, func(i, j int) bool { return s.projectors[i].Name < s.projectors[j].Name })
		s.projectorMu.Unlock()
		return nil
	case func(context.Context, *gorm.DB, []Envelope) error:
		return s.RegisterProjector(Projector(value))
	default:
		return ErrInvalidProjector
	}
}

func (s *GORMStore) SetProjector(projector any) error { return s.RegisterProjector(projector) }
func (s *GORMStore) RegisterParticipant(hook ParticipantHook) {
	if s == nil || hook == nil { return }
	s.mu.Lock(); defer s.mu.Unlock(); s.participants = append(s.participants, hook)
}
func (s *GORMStore) SetParticipant(hook ParticipantHook) { s.RegisterParticipant(hook) }
func (s *GORMStore) SetLockObserver(observer func(string)) {
	if s == nil { return }
	s.mu.Lock(); defer s.mu.Unlock(); s.lockObserver = observer
}

func (s *GORMStore) observeLock(name string) {
	s.mu.RLock(); observer := s.lockObserver; s.mu.RUnlock()
	if observer != nil { observer(name) }
}


func locked(db *gorm.DB) *gorm.DB {
	if db != nil && db.Dialector.Name() != "sqlite" {
		return db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return db
}

func (s *GORMStore) Commit(ctx context.Context, work UnitOfWork) (result CommitResult, err error) {
	if ctx == nil { ctx = context.Background() }
	if err = ValidateUnitOfWork(work); err != nil { return CommitResult{}, err }
	if initErr := s.requireReady(ctx); initErr != nil { return CommitResult{}, initErr }
	base := (*gorm.DB)(nil)
	if s.db != nil { base = s.db.GORM() }
	if base == nil { return CommitResult{}, errors.New("eventstore: store unavailable") }
	if ctx == nil { ctx = context.Background() }
	tx := base.WithContext(ctx).Begin()
	if tx.Error != nil { return CommitResult{}, errors.New("eventstore: begin transaction failed") }
	committed := false
	defer func() {
		if !committed { _ = tx.Rollback().Error }
	}()

	var readiness storeReadinessRow
	if err = locked(tx).Where("singleton_id = ?", "default").First(&readiness).Error; err != nil { return CommitResult{}, errors.New("eventstore: lock readiness failed") }
	var control projectionControlRow
	if err = locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil { return CommitResult{}, errors.New("eventstore: lock projection control failed") }
	if control.PublicationState != "published" {
		return CommitResult{}, ErrReadinessQuarantined
	}
	if s.keySource != nil {
		if err = s.validateReadinessOnDB(ctx, tx, false); err != nil { return CommitResult{}, err }
	}
	if err = s.validateA6UnitOfWorkWithDB(ctx, tx, work); err != nil { return CommitResult{}, err }
	s.observeLock(tableProjectionControl)

	type headState struct { stream StreamID; current uint64 }
	headOrder := make([]StreamID, 0, len(work.Streams))
	for _, item := range work.Streams { headOrder = append(headOrder, item.Stream) }
	sort.Slice(headOrder, func(i, j int) bool { return streamLess(headOrder[i], headOrder[j]) })
	headStates := make(map[StreamID]headState, len(headOrder))
	for _, stream := range headOrder {
		var head aggregateHeadRow
		q := locked(tx).Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).First(&head)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			head = aggregateHeadRow{AggregateType: stream.AggregateType, AggregateID: stream.AggregateID, UpdatedAt: time.Now().UTC()}
			if q = tx.Create(&head); q.Error != nil { return CommitResult{}, errors.New("eventstore: materialize aggregate head failed") }
		} else if q.Error != nil { return CommitResult{}, errors.New("eventstore: lock aggregate head failed") }
		headStates[stream] = headState{stream: stream, current: head.CurrentVersion}
		s.observeLock(tableAggregateHeads)
	}

	conflicts := make([]StreamConflict, 0)
	for _, item := range work.Streams {
		current := headStates[item.Stream].current
		if current != item.ExpectedVersion {
			conflicts = append(conflicts, StreamConflict{Stream: item.Stream, ExpectedVersion: item.ExpectedVersion, CurrentVersion: current})
		}
	}
	if len(conflicts) != 0 { return CommitResult{}, &ConflictError{Conflicts: conflicts} }

	totalEvents := 0
	for _, item := range work.Streams { totalEvents += len(item.Events) }
	for _, item := range work.Streams {
		if uint64(len(item.Events)) > maxUint64-headStates[item.Stream].current { return CommitResult{}, ErrVersionExhausted }
	}
	var sequence eventGlobalSequenceRow
	if totalEvents > 0 {
		if err = locked(tx).Where("singleton_id = ?", "default").First(&sequence).Error; err != nil { return CommitResult{}, errors.New("eventstore: lock event sequence failed") }
		s.observeLock(tableEventGlobalSequence)
		if uint64(totalEvents) > maxUint64-sequence.NextPosition { return CommitResult{}, ErrVersionExhausted }
	}

	result.StreamVersions = make(map[StreamID]uint64, len(work.Streams))
	if totalEvents > 0 {
		result.Events = make([]Envelope, 0, totalEvents)
		position := sequence.NextPosition
		for _, item := range work.Streams {
			version := headStates[item.Stream].current
			for _, event := range item.Events {
				version, err = nextVersion(version)
				if err != nil { return CommitResult{}, err }
				envelope, envelopeErr := (EventFactory{}).Envelope(item.Stream, version, position, event)
				if envelopeErr != nil { return CommitResult{}, envelopeErr }
				row := domainEventRow{EventID: envelope.EventID, AggregateType: envelope.Stream.AggregateType, AggregateID: envelope.Stream.AggregateID, AggregateVersion: envelope.StreamVersion, GlobalPosition: envelope.GlobalPosition, EventType: envelope.EventType, SchemaVersion: envelope.SchemaVersion, Payload: envelope.Payload, CommandID: envelope.Metadata.CommandID, CorrelationID: envelope.Metadata.CorrelationID, CausationID: envelope.Metadata.CausationID, PrincipalID: envelope.Metadata.PrincipalID, Producer: envelope.Metadata.Producer, OccurredAtUnixNanoUTC: metadataUnixNano(envelope.Metadata), Checksum: append([]byte(nil), envelope.Checksum[:]...), CreatedAt: time.Now().UTC()}
				if err = tx.Create(&row).Error; err != nil { return CommitResult{}, errors.New("eventstore: insert domain event failed") }
				result.Events = append(result.Events, envelope)
				position, err = nextVersion(position)
				if err != nil { return CommitResult{}, err }
			}
			result.StreamVersions[item.Stream] = version
		}
		sequence.NextPosition = position
		sequence.UpdatedAt = time.Now().UTC()
		if err = tx.Model(&eventGlobalSequenceRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{"next_position": sequence.NextPosition, "updated_at": sequence.UpdatedAt}).Error; err != nil { return CommitResult{}, errors.New("eventstore: advance event sequence failed") }
	} else {
		for _, item := range work.Streams { result.StreamVersions[item.Stream] = headStates[item.Stream].current }
	}
	for _, item := range work.Streams {
		if len(item.Events) == 0 { continue }
		if err = tx.Model(&aggregateHeadRow{}).Where("aggregate_type = ? AND aggregate_id = ?", item.Stream.AggregateType, item.Stream.AggregateID).Updates(map[string]any{"current_version": result.StreamVersions[item.Stream], "updated_at": time.Now().UTC()}).Error; err != nil { return CommitResult{}, errors.New("eventstore: advance aggregate head failed") }
	}

	if err = s.applyParticipants(ctx, tx, work, &result); err != nil {
		var expiredArtifact *task5ExpiredArtifactError
		if errors.As(err, &expiredArtifact) {
			_ = tx.Rollback().Error
			compCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			scrubErr := s.task5PersistExpiredArtifacts(compCtx, work, expiredArtifact)
			cancel()
			if scrubErr != nil {
				return CommitResult{}, scrubErr
			}
			return CommitResult{}, ErrArtifactGone
		}
		var expired *task5ExpiredPayloadError
		if errors.As(err, &expired) {
			_ = tx.Rollback().Error
			compCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			scrubErr := s.task5PersistExpiredPayloads(compCtx, work, expired)
			cancel()
			if scrubErr != nil {
				return CommitResult{}, scrubErr
			}
			return CommitResult{}, ErrPayloadExpired
		}
		return CommitResult{}, err
	}
	s.projectorMu.RLock()
	projectors := append([]ProjectionDescriptor(nil), s.projectors...)
	s.projectorMu.RUnlock()
	s.mu.RLock()
	participants := append([]ParticipantHook(nil), s.participants...)
	s.mu.RUnlock()
	stable := stableProjectors(projectors)
	controlUpdates := map[string]any{"updated_at": time.Now().UTC()}
	if len(result.Events) > 0 {
		control.TerminalPosition = result.Events[len(result.Events)-1].GlobalPosition
		controlUpdates["terminal_position"] = control.TerminalPosition
	}
	if len(stable) > 0 {
		control.ProjectorSetVersion = projectorSetVersion(stable)
		controlUpdates["projector_set_version"] = control.ProjectorSetVersion
	}
	if len(controlUpdates) > 1 {
		if err = tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(controlUpdates).Error; err != nil {
			return CommitResult{}, errors.New("eventstore: update projection control failed")
		}
	}
	for _, hook := range participants {
		if hookErr := hook(ctx, tx, work); hookErr != nil { return CommitResult{}, ErrParticipantFailure }
	}
	if len(projectors) > 0 {
		tx = tx.Set(projectionGenerationKey, control.ActiveGeneration)
	}
	for _, descriptor := range projectors {
		if hookErr := descriptor.Apply(ctx, tx, result.Events); hookErr != nil { return CommitResult{}, ErrProjectorFailure }
	}
	s.projectorMu.RLock()
	currentProjectors := append([]ProjectionDescriptor(nil), s.projectors...)
	if !sameProjectors(currentProjectors, projectors) {
		s.projectorMu.RUnlock()
		return CommitResult{}, ErrProjectorRegistryChanged
	}
	commitErr := tx.Commit().Error
	s.projectorMu.RUnlock()
	if err = commitErr; err != nil { return CommitResult{}, errors.New("eventstore: commit transaction failed") }
	return result, nil
}

func streamLess(a, b StreamID) bool {
	if a.AggregateType != b.AggregateType { return a.AggregateType < b.AggregateType }
	return a.AggregateID < b.AggregateID
}

func (s *GORMStore) Load(ctx context.Context, stream StreamID, fromVersion uint64) ([]Envelope, error) {
	if s == nil { return nil, errors.New("eventstore: store unavailable") }
	base := (*gorm.DB)(nil)
	if s.db != nil { base = s.db.GORM() }
	if base == nil { return nil, errors.New("eventstore: store unavailable") }
	if ctx == nil { ctx = context.Background() }
	if err := s.requireReady(ctx); err != nil { return nil, err }
	var rows []domainEventRow
	q := base.WithContext(ctx).Where("aggregate_type = ? AND aggregate_id = ? AND aggregate_version >= ?", stream.AggregateType, stream.AggregateID, fromVersion).Order("aggregate_version ASC").Find(&rows)
	if q.Error != nil { return nil, errors.New("eventstore: load events failed") }
	envelopes := make([]Envelope, 0, len(rows))
	for _, row := range rows {
		var checksum EventChecksum
		if len(row.Checksum) != len(checksum) { return nil, ErrChecksumMismatch }
		copy(checksum[:], row.Checksum)
		envelope := Envelope{Stream: stream, StreamVersion: row.AggregateVersion, GlobalPosition: row.GlobalPosition, EventID: row.EventID, EventType: row.EventType, SchemaVersion: row.SchemaVersion, Payload: copyProjectionBytes(row.Payload), Metadata: Metadata{EventID: row.EventID, CommandID: row.CommandID, CorrelationID: row.CorrelationID, CausationID: row.CausationID, PrincipalID: row.PrincipalID, Producer: row.Producer, OccurredAtUnixNanoUTC: row.OccurredAtUnixNanoUTC, OccurredAtUnixNanoSet: true}, Checksum: checksum}
		if ComputeEventChecksum(envelope) != checksum { return nil, ErrChecksumMismatch }
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
}
func operationStatusTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "succeeded", "failed", "completed", "cancelled", "canceled", "expired":
		return true
	default:
		return false
	}
}

func (s *GORMStore) GetOperation(ctx context.Context, operationID string) (OperationView, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return OperationView{}, ErrParticipantFailure
	}
	if err := s.requireReady(ctx); err != nil {
		return OperationView{}, err
	}
	if strings.TrimSpace(operationID) == "" {
		return OperationView{}, ErrNotFound
	}
	var row operationRow
	if err := s.db.GORM().WithContext(ctx).Where("operation_id = ?", operationID).First(&row).Error; err != nil {
		return OperationView{}, ErrNotFound
	}
	return OperationView{
		OperationID: row.OperationID, Version: row.Version, Kind: row.Kind, Status: row.Status,
		ResultCode: row.ResultCode, ErrorCode: row.ErrorCode, ArtifactID: row.ArtifactRef,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ExpiresAt: valueTime(row.ExpiresAt),
	}, nil
}

func (s *GORMStore) Purge(ctx context.Context, req PrivacyPurgeRequest) (PrivacyPurgeResult, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return PrivacyPurgeResult{}, ErrParticipantFailure
	}
	if err := s.requireReady(ctx); err != nil {
		return PrivacyPurgeResult{}, err
	}
	if strings.TrimSpace(req.OperationID) == "" {
		return PrivacyPurgeResult{}, ErrInvalidMetadata
	}
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope == "" {
		scope = "private"
	}
	if scope != "private" && scope != "artifacts" && scope != "all" {
		return PrivacyPurgeResult{}, ErrInvalidMetadata
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return PrivacyPurgeResult{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return PrivacyPurgeResult{}, err
	}
	var row operationRow
	if err := locked(tx).Where("operation_id = ?", req.OperationID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return PrivacyPurgeResult{}, ErrNotFound
		}
		return PrivacyPurgeResult{}, ErrParticipantFailure
	}
	if !req.AllowActive && !operationStatusTerminal(row.Status) {
		return PrivacyPurgeResult{}, ErrInvalidTransition
	}
	var deleted int64
	if scope == "private" || scope == "all" {
		if len(row.PrivateContext) > 0 || len(row.PrivateNonce) > 0 || row.PrivateKeyID != "" {
			if err := tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?", row.OperationID, row.Version).Updates(map[string]any{"private_context": nil, "private_nonce": nil, "private_key_id": "", "updated_at": s.task5Now()}).Error; err != nil {
				return PrivacyPurgeResult{}, ErrParticipantFailure
			}
			deleted++
		}
	}
	if scope == "artifacts" || scope == "all" {
		q := tx.Where("operation_id = ?", req.OperationID).Delete(&operationArtifactRow{})
		if q.Error != nil {
			return PrivacyPurgeResult{}, ErrParticipantFailure
		}
		deleted += q.RowsAffected
	}
	if err := tx.Commit().Error; err != nil {
		return PrivacyPurgeResult{}, ErrParticipantFailure
	}
	return PrivacyPurgeResult{OperationID: req.OperationID, Deleted: deleted}, nil
}


func (s *GORMStore) Close() error { if s == nil || s.db == nil { return nil }; return s.db.Close() }
const maxUint64 = ^uint64(0)

func nextVersion(current uint64) (uint64, error) {
	if current == maxUint64 { return 0, ErrVersionExhausted }
	return current + 1, nil
}


func participantVersion(expected, current, supplied uint64, table, key string) error {
	if expected != current { return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: key, ExpectedVersion: expected, CurrentVersion: current}}} }
	if supplied != 0 {
		if current == maxUint64 { return ErrVersionExhausted }
		if supplied != current+1 { return ErrParticipantConflict }
	}
	return nil
}

func participantCAS(table, key string, expected, current uint64, q *gorm.DB) error {
	if q.Error != nil { return ErrParticipantFailure }
	if current != 0 && q.RowsAffected != 1 {
		return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: key, ExpectedVersion: expected, CurrentVersion: current}}}
	}
	return nil
}
func (s *GORMStore) applyParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	applyOps := func() error { ops := append([]OperationUpdate(nil), work.Operations...); sort.Slice(ops, func(i,j int) bool{return ops[i].OperationID < ops[j].OperationID})
	for _, update := range ops {
		if update.OperationID == "" { return ErrParticipantFailure }
		var row operationRow
		q := tx.Where("operation_id = ?", update.OperationID).First(&row)
		current := uint64(0)
		if q.Error == nil { current = row.Version } else if !errors.Is(q.Error, gorm.ErrRecordNotFound) { return ErrParticipantFailure }
		if err := participantVersion(update.ExpectedVersion, current, update.Version, tableOperations, "<redacted>"); err != nil { return err }
		version, err := nextVersion(current); if err != nil { return err }; now := chooseTime(update.UpdatedAt, time.Now().UTC())
		if current > 0 && update.PrincipalID != "" && update.PrincipalID != row.PrincipalID && (len(update.PrivateContextCiphertext) == 0 || len(update.PrivateContextNonce) == 0 || update.EncryptionKeyID == "") {
			return ErrInvalidTransition
		}
		if current == 0 { row = operationRow{OperationID:update.OperationID, Version:version, Kind:nonempty(update.Kind,"unknown"), Status:nonempty(update.Status,"pending"), PrincipalID:nonempty(update.PrincipalID,update.OperationID), ResourceType:nonempty(update.ResourceID,"unknown"), ResourceID:update.ResourceID, IdempotencyScope:nonempty(update.IdempotencyScope,"operation"), IdempotencyKey:nonempty(update.IdempotencyKey,update.OperationID), RequestID:update.RequestID, RequestDigest:update.RequestDigest, CorrelationID:update.CorrelationID, ResultCode:update.ResultCode, ErrorCode:update.ErrorCode, ArtifactRef:update.ArtifactID, PrivatePayloadVersion:1, PrivateContext:update.PrivateContextCiphertext, PrivateNonce:update.PrivateContextNonce, PrivateKeyID:update.EncryptionKeyID, CreatedAt:chooseTime(update.CreatedAt,now), UpdatedAt:now, ExpiresAt:timePtr(update.ExpiresAt)}; q=tx.Create(&row)
		} else {
			if update.Kind != "" { row.Kind = update.Kind }; if update.Status != "" { row.Status = update.Status }; if update.PrincipalID != "" { row.PrincipalID = update.PrincipalID }; if update.ResourceID != "" { row.ResourceID = update.ResourceID }; if update.IdempotencyScope != "" { row.IdempotencyScope = update.IdempotencyScope }; if update.IdempotencyKey != "" { row.IdempotencyKey = update.IdempotencyKey }; if update.RequestID != "" { row.RequestID = update.RequestID }; if len(update.RequestDigest) > 0 { row.RequestDigest = update.RequestDigest }; if update.CorrelationID != "" { row.CorrelationID = update.CorrelationID }; if update.ResultCode != "" { row.ResultCode = update.ResultCode }; if update.ErrorCode != "" { row.ErrorCode = update.ErrorCode }; if update.ArtifactID != "" { row.ArtifactRef = update.ArtifactID }; if len(update.PrivateContextCiphertext) > 0 { row.PrivateContext = update.PrivateContextCiphertext }; if len(update.PrivateContextNonce) > 0 { row.PrivateNonce = update.PrivateContextNonce }; if update.EncryptionKeyID != "" { row.PrivateKeyID = update.EncryptionKeyID }; if !update.ExpiresAt.IsZero() { row.ExpiresAt = timePtr(update.ExpiresAt) }; row.Version = version; row.UpdatedAt = now
			q=tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?",update.OperationID,current).Updates(map[string]any{"version":row.Version,"kind":row.Kind,"status":row.Status,"principal_id":row.PrincipalID,"resource_type":row.ResourceType,"resource_id":row.ResourceID,"idempotency_scope":row.IdempotencyScope,"idempotency_key":row.IdempotencyKey,"request_id":row.RequestID,"request_digest":row.RequestDigest,"correlation_id":row.CorrelationID,"result_code":row.ResultCode,"error_code":row.ErrorCode,"artifact_id":row.ArtifactRef,"private_context":row.PrivateContext,"private_nonce":row.PrivateNonce,"private_key_id":row.PrivateKeyID,"updated_at":row.UpdatedAt,"expires_at":row.ExpiresAt})
		}
		if err := participantCAS(tableOperations, "<redacted>", update.ExpectedVersion, current, q); err != nil { return err }; result.OperationIDs=append(result.OperationIDs,update.OperationID)
	}
	return nil
}
	applyArts := func() error { return s.applyTask5ArtifactParticipants(tx, work, result) }
	applySecrets := func() error {
		secrets := append([]SecretUpdate(nil), work.SecretUpdates...)
		sort.Slice(secrets, func(i, j int) bool { return secrets[i].SecretRef < secrets[j].SecretRef })
		for _, update := range secrets {
			if update.SecretRef == "" {
				return ErrParticipantFailure
			}
			var latest adapterSecretRow
			q := tx.Where("secret_ref = ?", update.SecretRef).Order("row_version DESC").First(&latest)
			current := uint64(0)
			if q.Error == nil {
				current = latest.RowVersion
			} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
				return ErrParticipantFailure
			}
			if err := participantVersion(update.ExpectedVersion, current, update.Version, tableAdapterSecrets, "<redacted>"); err != nil {
				return err
			}
			version, err := nextVersion(current)
			if err != nil {
				return err
			}
			secretVersion := update.SecretVersion
			if secretVersion == 0 {
				secretVersion = 1
				if current > 0 {
					if latest.SecretVersion == maxUint64 {
						return ErrVersionExhausted
					}
					secretVersion = latest.SecretVersion + 1
				}
			}
			if current > 0 && secretVersion <= latest.SecretVersion {
				return ErrParticipantConflict
			}
			allCipher := len(update.Ciphertext) > 0 && len(update.Nonce) > 0 && (update.EncryptionKeyID != "" || s.keySource == nil)
			anyCipher := len(update.Ciphertext) > 0 || len(update.Nonce) > 0 || update.EncryptionKeyID != ""
			if s.keySource != nil && anyCipher && !allCipher {
				return ErrInvalidMetadata
			}
			if current == 0 && s.keySource != nil && !allCipher {
				return ErrInvalidMetadata
			}
			row := latest
			row.SecretRef = update.SecretRef
			row.SecretVersion = secretVersion
			row.RowVersion = version
			if current == 0 {
				row.EndpointID = update.EndpointID
				row.AdapterID = update.AdapterID
				row.AdapterType = "opaque"
				row.Ciphertext = append([]byte(nil), update.Ciphertext...)
				row.Nonce = append([]byte(nil), update.Nonce...)
				row.EncryptionKeyID = update.EncryptionKeyID
				if s.keySource == nil {
					row.Ciphertext = nonemptyBytes(row.Ciphertext)
					row.Nonce = nonemptyBytes(row.Nonce)
					row.EncryptionKeyID = nonempty(row.EncryptionKeyID, "opaque")
				}
				row.CreatedAt = time.Now().UTC()
			} else {
				if update.EndpointID != "" {
					row.EndpointID = update.EndpointID
				}
				if update.AdapterID != "" {
					row.AdapterID = update.AdapterID
				}
				if allCipher {
					row.Ciphertext = append([]byte(nil), update.Ciphertext...)
					row.Nonce = append([]byte(nil), update.Nonce...)
					if update.EncryptionKeyID != "" {
						row.EncryptionKeyID = update.EncryptionKeyID
					}
				} else if s.keySource != nil {
					plain, openErr := a6Open(ctx, s.keySource, "adapter-secret/v1", latest.SecretRef, latest.EndpointID+"/"+latest.AdapterID, latest.SecretVersion, latest.EncryptionKeyID, latest.Ciphertext, latest.Nonce)
					if openErr != nil {
						return ErrAuthenticationFailed
					}
					ciphertext, nonce, keyID, sealErr := a6Seal(ctx, s.keySource, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, plain)
					if sealErr != nil {
						return ErrEncryptionUnavailable
					}
					row.Ciphertext, row.Nonce, row.EncryptionKeyID = ciphertext, nonce, keyID
				}
			}
			row.UpdatedAt = chooseTime(update.UpdatedAt, time.Now().UTC())
			if len(row.Ciphertext) == 0 || len(row.Nonce) == 0 || row.EncryptionKeyID == "" {
				return ErrInvalidMetadata
			}
			q = tx.Create(&row)
			if q.Error != nil {
				return ErrParticipantFailure
			}
			result.SecretRefs = append(result.SecretRefs, update.SecretRef)
		}
		return nil
	}
	applyPlugins := func() error {
		plugins := append([]PluginKVUpdate(nil), work.PluginKVUpdates...)
		sort.Slice(plugins, func(i, j int) bool {
			if plugins[i].ExtensionID != plugins[j].ExtensionID {
				return plugins[i].ExtensionID < plugins[j].ExtensionID
			}
			return string(plugins[i].KeyHMAC) < string(plugins[j].KeyHMAC)
		})
		if len(plugins) == 0 {
			return nil
		}
		if err := lockPluginQuota(tx); err != nil {
			return err
		}
		type quota struct{ count, usage int64 }
		quotas := make(map[string]quota)
		loadQuota := func(extension string) (quota, error) {
			if q, ok := quotas[extension]; ok {
				return q, nil
			}
			var rows []pluginKVRow
			if err := tx.Where("extension_id = ?", extension).Order("key_hmac ASC").Limit(MaxPluginScan + 1).Find(&rows).Error; err != nil {
				return quota{}, ErrParticipantFailure
			}
			if len(rows) > MaxPluginScan {
				return quota{}, ErrOversizeInput
			}
			q := quota{count: int64(len(rows))}
			for _, row := range rows {
				if row.ValueSize < 0 || row.ValueSize > MaxPluginValueBytes {
					return quota{}, ErrInvalidMetadata
				}
				if s.keySource != nil {
					item, decodeErr := s.decodePluginKVRow(ctx, row)
					if decodeErr != nil {
						return quota{}, decodeErr
					}
					if int64(len(item.Value)) != row.ValueSize {
						return quota{}, ErrInvalidMetadata
					}
				}
				q.usage += row.ValueSize
			}
			if q.usage > MaxPluginBytes {
				return quota{}, ErrOversizeInput
			}
			quotas[extension] = q
			return q, nil
		}
		for _, update := range plugins {
			if update.ExtensionID == "" || len(update.KeyHMAC) == 0 || s.keySource != nil && len(update.KeyHMAC) != 32 {
				return ErrParticipantFailure
			}
			if update.ValueSize < 0 || update.ValueSize > MaxPluginValueBytes {
				return ErrOversizeInput
			}
			if update.Deleted {
				currentQuota, err := loadQuota(update.ExtensionID)
				if err != nil {
					return err
				}
				var row pluginKVRow
				q := locked(tx).Where("extension_id = ? AND key_hmac = ?", update.ExtensionID, update.KeyHMAC).First(&row)
				if errors.Is(q.Error, gorm.ErrRecordNotFound) {
					return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: tablePluginKV, Key: "<redacted>", ExpectedVersion: update.ExpectedVersion, CurrentVersion: 0}}}
				}
				if q.Error != nil {
					return ErrParticipantFailure
				}
				if err := participantVersion(update.ExpectedVersion, row.RowVersion, update.Version, tablePluginKV, "<redacted>"); err != nil {
					return err
				}
				if s.keySource != nil {
					if _, err := s.decodePluginKVRow(ctx, row); err != nil {
						return err
					}
				}
				q = tx.Where("extension_id = ? AND key_hmac = ? AND row_version = ?", update.ExtensionID, update.KeyHMAC, row.RowVersion).Delete(&pluginKVRow{})
				if err := participantCAS(tablePluginKV, "<redacted>", update.ExpectedVersion, row.RowVersion, q); err != nil {
					return err
				}
				currentQuota.count--
				currentQuota.usage -= row.ValueSize
				quotas[update.ExtensionID] = currentQuota
				result.PluginKVIndexes = append(result.PluginKVIndexes, append([]byte(nil), update.KeyHMAC...))
				continue
			}
			keyLen := len(update.KeyCiphertext)
			valueLen := len(update.ValueCiphertext)
			if s.keySource == nil && (keyLen > MaxPluginKeyBytes+16 || valueLen > MaxPluginValueBytes+16) {
				return ErrOversizeInput
			}
			var row pluginKVRow
			q := tx.Where("extension_id = ? AND key_hmac = ?", update.ExtensionID, update.KeyHMAC).First(&row)
			current := uint64(0)
			if q.Error == nil {
				current = row.RowVersion
			} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
				return ErrParticipantFailure
			}
			if err := participantVersion(update.ExpectedVersion, current, update.Version, tablePluginKV, "<redacted>"); err != nil {
				return err
			}
			if current == 0 && s.keySource != nil && (len(update.KeyCiphertext) == 0 || len(update.KeyNonce) == 0 || len(update.ValueCiphertext) == 0 || len(update.ValueNonce) == 0 || update.EncryptionKeyID == "") {
				return ErrInvalidMetadata
			}
			currentQuota, err := loadQuota(update.ExtensionID)
			if err != nil {
				return err
			}
			oldSize := int64(0)
			if current > 0 {
				oldSize = row.ValueSize
			} else if currentQuota.count >= MaxPluginKeys {
				return ErrOversizeInput
			}
			version, err := nextVersion(current)
			if err != nil {
				return err
			}
			if current == 0 {
				row = pluginKVRow{ExtensionID: update.ExtensionID, KeyHMAC: append([]byte(nil), update.KeyHMAC...), EncryptedKey: append([]byte(nil), update.KeyCiphertext...), KeyNonce: append([]byte(nil), update.KeyNonce...), EncryptedValue: append([]byte(nil), update.ValueCiphertext...), ValueNonce: append([]byte(nil), update.ValueNonce...), ValueSize: update.ValueSize, RowVersion: version, EncryptionKeyID: update.EncryptionKeyID, CreatedAt: chooseTime(update.UpdatedAt, time.Now().UTC()), UpdatedAt: chooseTime(update.UpdatedAt, time.Now().UTC())}
				if s.keySource == nil {
					row.EncryptedKey = nonemptyBytes(row.EncryptedKey)
					row.KeyNonce = nonemptyBytes(row.KeyNonce)
					row.EncryptedValue = nonemptyBytes(row.EncryptedValue)
					row.ValueNonce = nonemptyBytes(row.ValueNonce)
					row.EncryptionKeyID = nonempty(row.EncryptionKeyID, "opaque")
				}
				q = tx.Create(&row)
			} else {
				if len(update.KeyCiphertext) > 0 {
					row.EncryptedKey = append([]byte(nil), update.KeyCiphertext...)
				}
				if len(update.KeyNonce) > 0 {
					row.KeyNonce = append([]byte(nil), update.KeyNonce...)
				}
				if len(update.ValueCiphertext) > 0 {
					row.EncryptedValue = append([]byte(nil), update.ValueCiphertext...)
					row.ValueSize = update.ValueSize
				}
				if len(update.ValueNonce) > 0 {
					row.ValueNonce = append([]byte(nil), update.ValueNonce...)
				}
				if update.EncryptionKeyID != "" {
					row.EncryptionKeyID = update.EncryptionKeyID
				}
				row.RowVersion = version
				row.UpdatedAt = chooseTime(update.UpdatedAt, time.Now().UTC())
				q = tx.Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ?", update.ExtensionID, update.KeyHMAC, current).Updates(map[string]any{"encrypted_key": row.EncryptedKey, "key_nonce": row.KeyNonce, "encrypted_value": row.EncryptedValue, "value_nonce": row.ValueNonce, "value_size": row.ValueSize, "row_version": row.RowVersion, "encryption_key_id": row.EncryptionKeyID, "updated_at": row.UpdatedAt})
			}
			if err := participantCAS(tablePluginKV, "<redacted>", update.ExpectedVersion, current, q); err != nil {
				return err
			}
			currentQuota.usage -= oldSize
			currentQuota.usage += row.ValueSize
			if current == 0 {
				currentQuota.count++
			}
			if currentQuota.usage > MaxPluginBytes {
				return ErrOversizeInput
			}
			quotas[update.ExtensionID] = currentQuota
			result.PluginKVIndexes = append(result.PluginKVIndexes, append([]byte(nil), update.KeyHMAC...))
		}
		return nil
	}
	applyInbox := func() error { return s.applyTask5InboxParticipants(ctx, tx, work, result) }
	applyEffects := func() error { return s.applyTask5EffectParticipants(ctx, tx, work, result) }
	applyFences := func() error { fences := append([]SubjectFenceUpdate(nil), work.FenceUpdates...); sort.Slice(fences,func(i,j int)bool{if string(fences[i].SubjectKey)!=string(fences[j].SubjectKey){return string(fences[i].SubjectKey)<string(fences[j].SubjectKey)};return fences[i].Scope<fences[j].Scope})
	for _, update := range fences {
		if len(update.SubjectKey)==0 || update.Scope=="" {return ErrParticipantFailure}
		var row subjectFenceRow
		q:=tx.Where("subject_key = ? AND scope = ?",update.SubjectKey,update.Scope).First(&row); current:=uint64(0); if q.Error==nil{current=row.Version}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure}
		if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableSubjectFences,"<redacted>");err!=nil{return err}
		if update.Deleted { if current==0{return &ParticipantConflictError{Conflicts:[]ParticipantConflict{{Table:tableSubjectFences,Key:"<redacted>",ExpectedVersion:update.ExpectedVersion,CurrentVersion:current}}}}; q=tx.Where("subject_key = ? AND scope = ? AND version = ?",update.SubjectKey,update.Scope,current).Delete(&subjectFenceRow{}); if err:=participantCAS(tableSubjectFences,"<redacted>",update.ExpectedVersion,current,q);err!=nil{return err}; result.FenceKeys=append(result.FenceKeys,append([]byte(nil),update.SubjectKey...)); continue }
		version, err := nextVersion(current); if err != nil { return err }
		if current==0 { if update.PurgeOperationID=="" {return ErrParticipantFailure}; row=subjectFenceRow{SubjectKey:update.SubjectKey,Scope:update.Scope,Version:version,PurgeOperationID:update.PurgeOperationID,CreatedAt:chooseTime(update.CreatedAt,time.Now().UTC()),ExpiresAt:timePtr(update.ExpiresAt)}; q=tx.Create(&row) } else { if update.PurgeOperationID!="" {row.PurgeOperationID=update.PurgeOperationID}; if !update.CreatedAt.IsZero(){row.CreatedAt=update.CreatedAt}; if !update.ExpiresAt.IsZero(){row.ExpiresAt=timePtr(update.ExpiresAt)}; row.Version=version; q=tx.Model(&subjectFenceRow{}).Where("subject_key = ? AND scope = ? AND version = ?",update.SubjectKey,update.Scope,current).Updates(map[string]any{"version":row.Version,"purge_operation_id":row.PurgeOperationID,"created_at":row.CreatedAt,"expires_at":row.ExpiresAt}) }
		if err := participantCAS(tableSubjectFences, "<redacted>", update.ExpectedVersion, current, q); err != nil { return err };result.FenceKeys=append(result.FenceKeys,append([]byte(nil),update.SubjectKey...))
	}
	return nil
}
	if err := applyOps(); err != nil { return err }
	if err := applyInbox(); err != nil { return err }
	if err := applyEffects(); err != nil { return err }
	if err := applyArts(); err != nil { return err }
	if err := applySecrets(); err != nil { return err }
	if err := applyPlugins(); err != nil { return err }
	if err := applyFences(); err != nil { return err }
	return nil
}
func nonempty(v, fallback string) string { if v=="" {return fallback};return v }
func nonemptyBytes(v []byte) []byte { if len(v)==0{return []byte{0}};return v }
func chooseTime(v, fallback time.Time) time.Time {if v.IsZero(){return fallback};return v}
func timePtr(v time.Time) *time.Time {if v.IsZero(){return nil};return &v}
func chooseUint(v, fallback uint64) uint64 {if v==0{return fallback};return v}

var _ Store = (*GORMStore)(nil)
