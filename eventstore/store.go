package eventstore

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrChecksumMismatch         = errors.New("eventstore: checksum mismatch")
	ErrParticipantConflict      = errors.New("eventstore: participant conflict")
	ErrParticipantFailure       = errors.New("eventstore: participant failure")
	ErrProjectorFailure         = errors.New("eventstore: projector failure")
	ErrInvalidProjector         = errors.New("eventstore: invalid projector")
	ErrDuplicateProjector       = errors.New("eventstore: duplicate projector")
	ErrProjectorVersionConflict = errors.New("eventstore: projector version conflict")
	ErrProjectorRegistryChanged = errors.New("eventstore: projector registry changed")
	ErrProjectionInvariant      = errors.New("eventstore: projection invariant failed")
	ErrVersionExhausted         = errors.New("eventstore: version exhausted")
	ErrUnsupportedEventSchema   = ErrUnsupportedSchema
)

const storeWorkSignalCapacity = 4

type ParticipantConflict struct {
	Table           string
	Key             string
	ExpectedVersion uint64
	CurrentVersion  uint64
}

type ParticipantConflictError struct{ Conflicts []ParticipantConflict }

func (e *ParticipantConflictError) Error() string { return ErrParticipantConflict.Error() }
func (e *ParticipantConflictError) Unwrap() error { return ErrParticipantConflict }

type Projector func(context.Context, *gorm.DB, []Envelope) error

// ProjectionDescriptor is a stable, store-local projector registration.
// Name and Version are persisted as the projector set identity during publish.
type ProjectionDescriptor struct {
	Name    string
	Version string
	Apply   Projector
}

type ParticipantHook func(context.Context, *gorm.DB, UnitOfWork) error
type StoreOption func(*GORMStore)

func WithProjection(descriptor ProjectionDescriptor) StoreOption {
	return func(s *GORMStore) {
		if err := s.RegisterProjection(descriptor); err != nil {
			s.recordInitError(err)
		}
	}
}
func WithParticipant(hook ParticipantHook) StoreOption {
	return func(s *GORMStore) { s.RegisterParticipant(hook) }
}
func WithLockObserver(observer func(string)) StoreOption {
	return func(s *GORMStore) { s.SetLockObserver(observer) }
}
func WithClock(clock Clock) StoreOption {
	return func(s *GORMStore) {
		if clock != nil {
			s.clock = clock
		}
	}
}
func WithIDGenerator(generator IDGenerator) StoreOption {
	return func(s *GORMStore) {
		if generator != nil {
			s.ids = generator
		}
	}
}

type GORMStore struct {
	db           *Database
	mu           sync.RWMutex
	projectorMu  sync.RWMutex
	workMu       sync.Mutex
	initErr      error
	readinessErr error
	projectors   []ProjectionDescriptor
	participants []ParticipantHook
	lockObserver func(string)
	clock        Clock
	ids          IDGenerator
	inboxWork    chan struct{}
	outboxWork   chan struct{}
}

func NewStore(database *Database, options ...StoreOption) *GORMStore {
	s := &GORMStore{
		db: database, clock: SystemClock{}, ids: UUIDGenerator{},
		inboxWork: make(chan struct{}, storeWorkSignalCapacity), outboxWork: make(chan struct{}, storeWorkSignalCapacity),
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	s.participants = append(s.participants, s.applyStoryLogUpdates, s.applyStoryLogImports)
	_, err := s.GetReadiness(context.Background())
	s.recordReadinessError(err)
	return s
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
func (s *GORMStore) recordReadinessError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	if s.readinessErr == nil {
		s.readinessErr = err
	}
	s.mu.Unlock()
}
func (s *GORMStore) clearReadinessError() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.readinessErr = nil
	s.mu.Unlock()
}
func (s *GORMStore) initializationError() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	initErr, readinessErr := s.initErr, s.readinessErr
	s.mu.RUnlock()
	if initErr != nil {
		return initErr
	}
	return readinessErr
}

func (s *GORMStore) RegisterProjection(descriptor ProjectionDescriptor) error {
	descriptor.Name = strings.TrimSpace(descriptor.Name)
	descriptor.Version = strings.TrimSpace(descriptor.Version)
	if s == nil || descriptor.Apply == nil || descriptor.Name == "" || descriptor.Version == "" {
		return ErrInvalidProjector
	}
	s.projectorMu.Lock()
	defer s.projectorMu.Unlock()
	for _, existing := range s.projectors {
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

func (s *GORMStore) RegisterParticipant(hook ParticipantHook) {
	if s == nil || hook == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.participants = append(s.participants, hook)
}
func (s *GORMStore) SetParticipant(hook ParticipantHook) { s.RegisterParticipant(hook) }
func (s *GORMStore) SetLockObserver(observer func(string)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockObserver = observer
}

func (s *GORMStore) observeLock(name string) {
	s.mu.RLock()
	observer := s.lockObserver
	s.mu.RUnlock()
	if observer != nil {
		observer(name)
	}
}

// InboxWorkSignal receives whenever committed inbox work may be claimable.
// Fetch it before a claim attempt so a concurrent commit cannot be missed.
func (s *GORMStore) InboxWorkSignal() <-chan struct{} {
	if s == nil {
		return nil
	}
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.inboxWork == nil {
		s.inboxWork = make(chan struct{}, storeWorkSignalCapacity)
	}
	return s.inboxWork
}

// OutboxWorkSignal receives whenever committed outbox work may be claimable.
// Fetch it before a claim attempt so a concurrent commit cannot be missed.
func (s *GORMStore) OutboxWorkSignal() <-chan struct{} {
	if s == nil {
		return nil
	}
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.outboxWork == nil {
		s.outboxWork = make(chan struct{}, storeWorkSignalCapacity)
	}
	return s.outboxWork
}

func (s *GORMStore) signalInboxWork() {
	if s != nil {
		s.signalWork(&s.inboxWork)
	}
}

func (s *GORMStore) signalOutboxWork() {
	if s != nil {
		s.signalWork(&s.outboxWork)
	}
}

func (s *GORMStore) signalWork(signal *chan struct{}) {
	s.workMu.Lock()
	if *signal == nil {
		*signal = make(chan struct{}, storeWorkSignalCapacity)
	}
	work := *signal
	s.workMu.Unlock()
	for range cap(work) {
		select {
		case work <- struct{}{}:
		default:
			return
		}
	}
}

func locked(db *gorm.DB) *gorm.DB {
	if db != nil && db.Name() != "sqlite" {
		return db.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return db
}

func insertDomainEventRows(tx *gorm.DB, rows []domainEventRow) error {
	if tx == nil || len(rows) == 0 {
		return ErrParticipantFailure
	}
	if tx.Dialector == nil || tx.Name() != "sqlite" {
		const eventInsertBatchSize = 500
		if err := tx.CreateInBatches(&rows, eventInsertBatchSize).Error; err != nil {
			return ErrParticipantFailure
		}
		return nil
	}
	var query strings.Builder
	query.Grow(len(rows) * 1024)
	query.WriteString("INSERT INTO domain_events (event_id,aggregate_type,aggregate_id,aggregate_version,global_position,event_type,schema_version,payload,command_id,correlation_id,causation_id,principal_id,producer,occurred_at_unix_nano_utc,checksum,created_at) VALUES ")
	for index, row := range rows {
		if index != 0 {
			query.WriteByte(',')
		}
		query.WriteByte('(')
		writeSQLiteTextLiteral(&query, row.EventID)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.AggregateType)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.AggregateID)
		query.WriteByte(',')
		writeSQLiteUint(&query, row.AggregateVersion)
		query.WriteByte(',')
		writeSQLiteUint(&query, row.GlobalPosition)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.EventType)
		query.WriteByte(',')
		writeSQLiteUint(&query, uint64(row.SchemaVersion))
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.Payload)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.CommandID)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.CorrelationID)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.CausationID)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.PrincipalID)
		query.WriteByte(',')
		writeSQLiteTextLiteral(&query, row.Producer)
		query.WriteByte(',')
		writeSQLiteInt(&query, row.OccurredAtUnixNanoUTC)
		query.WriteByte(',')
		writeSQLiteBlobLiteral(&query, row.Checksum)
		query.WriteString(",CURRENT_TIMESTAMP)")
	}
	result := tx.Exec(query.String())
	if result.Error != nil || result.RowsAffected != int64(len(rows)) {
		return ErrParticipantFailure
	}
	return nil
}

func (s *GORMStore) Commit(ctx context.Context, work UnitOfWork) (result CommitResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err = ValidateUnitOfWork(work); err != nil {
		return CommitResult{}, err
	}
	if initErr := s.requireReady(ctx); initErr != nil {
		return CommitResult{}, initErr
	}
	base := (*gorm.DB)(nil)
	if s.db != nil {
		base = s.db.GORM()
	}
	if base == nil {
		return CommitResult{}, errors.New("eventstore: store unavailable")
	}
	streamPlan, err := buildStreamPlan(work)
	if err != nil {
		return CommitResult{}, err
	}
	revisionPlan, err := s.prepareRevisionPlan(ctx, work)
	if err != nil {
		return CommitResult{}, err
	}
	var executionCommit *preparedExecutionCommit
	if work.Execution != nil {
		executionCommit, err = s.prepareExecutionCommit(ctx, work.Execution)
		if err != nil {
			return CommitResult{}, err
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx := base.WithContext(ctx).Begin()
	if tx.Error != nil {
		return CommitResult{}, errors.New("eventstore: begin transaction failed")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()

	if len(work.PluginKVUpdates) > 0 {
		if err = lockPluginQuota(tx); err != nil {
			return CommitResult{}, err
		}
	}
	var readiness storeReadinessRow
	if err = locked(tx).Where("singleton_id = ?", "default").First(&readiness).Error; err != nil {
		return CommitResult{}, errors.New("eventstore: lock readiness failed")
	}
	var control projectionControlRow
	if err = locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return CommitResult{}, errors.New("eventstore: lock projection control failed")
	}
	if control.PublicationState != "published" {
		return CommitResult{}, ErrReadinessQuarantined
	}
	if err = validateProjectionReads(control, work.ProjectionReads); err != nil {
		return CommitResult{}, err
	}
	s.observeLock(tableProjectionControl)

	headStates, err := lockStreamPlan(tx, streamPlan, s.task5Now())
	if err != nil {
		return CommitResult{}, err
	}
	for range streamPlan {
		s.observeLock(tableAggregateHeads)
	}
	revisionStates, err := lockRevisionPlan(tx, revisionPlan)
	if err != nil {
		return CommitResult{}, err
	}
	if len(revisionPlan) > 0 {
		s.observeLock(tableRevisionHeads)
	}
	executionRow, err := lockExecutionCommit(tx, executionCommit, s.task5Now())
	if err != nil {
		return CommitResult{}, err
	}
	if executionCommit != nil {
		s.observeLock(tableExecutionReceipts)
	}

	totalEvents := 0
	for _, item := range work.Streams {
		totalEvents += len(item.Events)
	}
	for _, item := range work.Streams {
		if uint64(len(item.Events)) > maxUint64-headStates[item.Stream] {
			return CommitResult{}, ErrVersionExhausted
		}
	}
	var sequence eventGlobalSequenceRow
	if totalEvents > 0 {
		if err = locked(tx).Where("singleton_id = ?", "default").First(&sequence).Error; err != nil {
			return CommitResult{}, errors.New("eventstore: lock event sequence failed")
		}
		s.observeLock(tableEventGlobalSequence)
		if uint64(totalEvents) > maxUint64-sequence.NextPosition {
			return CommitResult{}, ErrVersionExhausted
		}
	}
	if err = advanceRevisionPlan(tx, revisionPlan, revisionStates, s.task5Now()); err != nil {
		return CommitResult{}, err
	}

	result.StreamVersions = make(map[StreamID]uint64, len(work.Streams))
	if totalEvents > 0 {
		result.Events = make([]Envelope, 0, totalEvents)
		rows := make([]domainEventRow, 0, totalEvents)
		position := sequence.NextPosition
		for _, item := range work.Streams {
			version := headStates[item.Stream]
			for _, event := range item.Events {
				version, err = nextVersion(version)
				if err != nil {
					return CommitResult{}, err
				}
				envelope, envelopeErr := (EventFactory{}).Envelope(item.Stream, version, position, event)
				if envelopeErr != nil {
					return CommitResult{}, envelopeErr
				}
				rows = append(rows, domainEventRow{
					EventID: envelope.EventID, AggregateType: envelope.Stream.AggregateType, AggregateID: envelope.Stream.AggregateID,
					AggregateVersion: envelope.StreamVersion, GlobalPosition: envelope.GlobalPosition,
					EventType: envelope.EventType, SchemaVersion: envelope.SchemaVersion,
					Payload: envelope.Payload, CommandID: envelope.Metadata.CommandID,
					CorrelationID: envelope.Metadata.CorrelationID, CausationID: envelope.Metadata.CausationID,
					PrincipalID: envelope.Metadata.PrincipalID, Producer: envelope.Metadata.Producer,
					OccurredAtUnixNanoUTC: metadataUnixNano(envelope.Metadata),
					Checksum:              append([]byte(nil), envelope.Checksum[:]...), CreatedAt: time.Now().UTC(),
				})
				result.Events = append(result.Events, envelope)
				position, err = nextVersion(position)
				if err != nil {
					return CommitResult{}, err
				}
			}
			result.StreamVersions[item.Stream] = version
		}
		if err = insertDomainEventRows(tx, rows); err != nil {
			return CommitResult{}, errors.New("eventstore: insert domain events failed")
		}
		sequence.NextPosition = position
		sequence.UpdatedAt = time.Now().UTC()
		if err = tx.Model(&eventGlobalSequenceRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{"next_position": sequence.NextPosition, "updated_at": sequence.UpdatedAt}).Error; err != nil {
			return CommitResult{}, errors.New("eventstore: advance event sequence failed")
		}
	} else {
		for _, item := range work.Streams {
			result.StreamVersions[item.Stream] = headStates[item.Stream]
		}
	}
	for _, item := range work.Streams {
		if len(item.Events) == 0 {
			continue
		}
		if err = tx.Model(&aggregateHeadRow{}).Where("aggregate_type = ? AND aggregate_id = ?", item.Stream.AggregateType, item.Stream.AggregateID).Updates(map[string]any{"current_version": result.StreamVersions[item.Stream], "updated_at": time.Now().UTC()}).Error; err != nil {
			return CommitResult{}, errors.New("eventstore: advance aggregate head failed")
		}
	}

	if err = s.applyParticipants(ctx, tx, work, &result); err != nil {
		return CommitResult{}, err
	}
	if len(work.InboxUpdates) > 0 || len(work.Effects) > 0 {
		if err = s.refreshQueueScheduling(ctx, tx, work); err != nil {
			return CommitResult{}, err
		}
	}
	s.projectorMu.RLock()
	projectors := append([]ProjectionDescriptor(nil), s.projectors...)
	s.projectorMu.RUnlock()
	s.mu.RLock()
	participants := append([]ParticipantHook(nil), s.participants...)
	s.mu.RUnlock()
	controlUpdates := map[string]any{"updated_at": time.Now().UTC()}
	if len(result.Events) > 0 {
		control.TerminalPosition = result.Events[len(result.Events)-1].GlobalPosition
		controlUpdates["terminal_position"] = control.TerminalPosition
	}
	if len(projectors) > 0 {
		control.ProjectorSetVersion = projectorSetVersion(projectors)
		controlUpdates["projector_set_version"] = control.ProjectorSetVersion
	}
	if len(controlUpdates) > 1 {
		if err = tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(controlUpdates).Error; err != nil {
			return CommitResult{}, errors.New("eventstore: update projection control failed")
		}
	}
	for _, hook := range participants {
		if hookErr := hook(ctx, tx, work); hookErr != nil {
			return CommitResult{}, ErrParticipantFailure
		}
	}
	if len(projectors) > 0 {
		tx = withProjectionGeneration(tx, control.ActiveGeneration)
	}
	for _, descriptor := range projectors {
		if hookErr := descriptor.Apply(ctx, tx, result.Events); hookErr != nil {
			return CommitResult{}, errors.Join(ErrProjectorFailure, hookErr)
		}
	}
	s.projectorMu.RLock()
	if !sameProjectors(s.projectors, projectors) {
		s.projectorMu.RUnlock()
		return CommitResult{}, ErrProjectorRegistryChanged
	}
	if err = applyExecutionCommit(tx, executionCommit, executionRow, s.task5Now()); err != nil {
		s.projectorMu.RUnlock()
		return CommitResult{}, err
	}
	commitErr := tx.Commit().Error
	s.projectorMu.RUnlock()
	if err = commitErr; err != nil {
		return CommitResult{}, errors.New("eventstore: commit transaction failed")
	}
	if len(work.InboxUpdates) > 0 {
		s.signalInboxWork()
	}
	if len(work.Effects) > 0 {
		s.signalOutboxWork()
	}
	return result, nil
}

func streamLess(a, b StreamID) bool {
	if a.AggregateType != b.AggregateType {
		return a.AggregateType < b.AggregateType
	}
	return a.AggregateID < b.AggregateID
}

func (s *GORMStore) Load(ctx context.Context, stream StreamID, fromVersion uint64) ([]Envelope, error) {
	if s == nil {
		return nil, errors.New("eventstore: store unavailable")
	}
	base := (*gorm.DB)(nil)
	if s.db != nil {
		base = s.db.GORM()
	}
	if base == nil {
		return nil, errors.New("eventstore: store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return nil, err
	}
	var rows []domainEventRow
	q := base.WithContext(ctx).Where("aggregate_type = ? AND aggregate_id = ? AND aggregate_version >= ?", stream.AggregateType, stream.AggregateID, fromVersion).Order("aggregate_version ASC").Find(&rows)
	if q.Error != nil {
		return nil, errors.New("eventstore: load events failed")
	}
	envelopes := make([]Envelope, 0, len(rows))
	for _, row := range rows {
		var checksum EventChecksum
		if len(row.Checksum) != len(checksum) {
			return nil, ErrChecksumMismatch
		}
		copy(checksum[:], row.Checksum)
		envelope := Envelope{Stream: stream, StreamVersion: row.AggregateVersion, GlobalPosition: row.GlobalPosition, EventID: row.EventID, EventType: row.EventType, SchemaVersion: row.SchemaVersion, Payload: copyProjectionBytes(row.Payload), Metadata: Metadata{EventID: row.EventID, CommandID: row.CommandID, CorrelationID: row.CorrelationID, CausationID: row.CausationID, PrincipalID: row.PrincipalID, Producer: row.Producer, OccurredAtUnixNanoUTC: row.OccurredAtUnixNanoUTC, OccurredAtUnixNanoSet: true}, Checksum: checksum}
		envelope, err := verifyEnvelopeChecksum(envelope)
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
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
	queryErr := s.db.GORM().WithContext(ctx).Select(
		"operation_id", "version", "kind", "status", "principal_id", "resource_id",
		"idempotency_scope", "idempotency_key", "request_id", "request_digest",
		"correlation_id", "result_code", "error_code", "artifact_id",
		"created_at", "updated_at", "expires_at",
	).Where("operation_id = ?", operationID).First(&row).Error
	if errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return OperationView{}, ErrNotFound
	}
	if queryErr != nil {
		return OperationView{}, ErrParticipantFailure
	}
	return OperationView{
		OperationID: row.OperationID, Version: row.Version, Kind: row.Kind,
		Status: row.Status, PrincipalID: row.PrincipalID, ResourceID: row.ResourceID,
		IdempotencyScope: row.IdempotencyScope, IdempotencyKey: row.IdempotencyKey,
		RequestID: row.RequestID, RequestDigest: append([]byte(nil), row.RequestDigest...),
		CorrelationID: row.CorrelationID, ResultCode: row.ResultCode,
		ErrorCode: row.ErrorCode, ArtifactID: row.ArtifactRef,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ExpiresAt: valueTime(row.ExpiresAt),
	}, nil
}

func (s *GORMStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

const maxUint64 = ^uint64(0)
const maxPersistedVersion = ^uint64(0) >> 1

func nextVersion(current uint64) (uint64, error) {
	if current >= maxPersistedVersion {
		return 0, ErrVersionExhausted
	}
	return current + 1, nil
}

func participantVersion(expected, current, supplied uint64, table, key string) error {
	if expected != current {
		return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: key, ExpectedVersion: expected, CurrentVersion: current}}}
	}
	if supplied != 0 {
		if current >= maxPersistedVersion {
			return ErrVersionExhausted
		}
		if supplied != current+1 {
			return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: key, ExpectedVersion: supplied, CurrentVersion: current}}}
		}
	}
	return nil
}

func participantCAS(table, key string, expected, current uint64, q *gorm.DB) error {
	if q.Error != nil {
		return ErrParticipantFailure
	}
	if current != 0 && q.RowsAffected != 1 {
		return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: key, ExpectedVersion: expected, CurrentVersion: current}}}
	}
	return nil
}
func (s *GORMStore) applyParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	applyOps := func() error {
		ops := append([]OperationUpdate(nil), work.Operations...)
		sort.Slice(ops, func(i, j int) bool { return ops[i].OperationID < ops[j].OperationID })
		for _, update := range ops {
			if update.OperationID == "" {
				return ErrParticipantFailure
			}
			var row operationRow
			q := tx.Where("operation_id = ?", update.OperationID).First(&row)
			current := uint64(0)
			if q.Error == nil {
				current = row.Version
			} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
				return ErrParticipantFailure
			}
			if err := participantVersion(update.ExpectedVersion, current, update.Version, tableOperations, "<redacted>"); err != nil {
				return err
			}
			version, err := nextVersion(current)
			if err != nil {
				return err
			}
			now := chooseTime(update.UpdatedAt, s.task5Now())
			if current == 0 {
				row = operationRow{OperationID: update.OperationID, Version: version, Kind: nonempty(update.Kind, "unknown"), Status: nonempty(update.Status, "pending"), PrincipalID: nonempty(update.PrincipalID, update.OperationID), ResourceType: nonempty(update.ResourceID, "unknown"), ResourceID: update.ResourceID, IdempotencyScope: nonempty(update.IdempotencyScope, "operation"), IdempotencyKey: nonempty(update.IdempotencyKey, update.OperationID), RequestID: update.RequestID, RequestDigest: update.RequestDigest, CorrelationID: update.CorrelationID, ResultCode: update.ResultCode, ErrorCode: update.ErrorCode, ArtifactRef: update.ArtifactID, PrivateContext: update.PrivateContext, CreatedAt: chooseTime(update.CreatedAt, now), UpdatedAt: now, ExpiresAt: timePtr(update.ExpiresAt)}
				q = tx.Create(&row)
			} else {
				if update.Kind != "" {
					row.Kind = update.Kind
				}
				if update.Status != "" {
					row.Status = update.Status
				}
				if update.PrincipalID != "" {
					row.PrincipalID = update.PrincipalID
				}
				if update.ResourceID != "" {
					row.ResourceID = update.ResourceID
				}
				if update.IdempotencyScope != "" {
					row.IdempotencyScope = update.IdempotencyScope
				}
				if update.IdempotencyKey != "" {
					row.IdempotencyKey = update.IdempotencyKey
				}
				if update.RequestID != "" {
					row.RequestID = update.RequestID
				}
				if len(update.RequestDigest) > 0 {
					row.RequestDigest = update.RequestDigest
				}
				if update.CorrelationID != "" {
					row.CorrelationID = update.CorrelationID
				}
				if update.ResultCode != "" {
					row.ResultCode = update.ResultCode
				}
				if update.ErrorCode != "" {
					row.ErrorCode = update.ErrorCode
				}
				if update.ArtifactID != "" {
					row.ArtifactRef = update.ArtifactID
				}
				if update.PrivateContext != nil {
					row.PrivateContext = update.PrivateContext
				}
				if !update.ExpiresAt.IsZero() {
					row.ExpiresAt = timePtr(update.ExpiresAt)
				}
				row.Version = version
				row.UpdatedAt = now
				q = tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?", update.OperationID, current).Updates(map[string]any{"version": row.Version, "kind": row.Kind, "status": row.Status, "principal_id": row.PrincipalID, "resource_type": row.ResourceType, "resource_id": row.ResourceID, "idempotency_scope": row.IdempotencyScope, "idempotency_key": row.IdempotencyKey, "request_id": row.RequestID, "request_digest": row.RequestDigest, "correlation_id": row.CorrelationID, "result_code": row.ResultCode, "error_code": row.ErrorCode, "artifact_id": row.ArtifactRef, "private_context": row.PrivateContext, "updated_at": row.UpdatedAt, "expires_at": row.ExpiresAt})
			}
			if err := participantCAS(tableOperations, "<redacted>", update.ExpectedVersion, current, q); err != nil {
				return err
			}
			result.OperationIDs = append(result.OperationIDs, update.OperationID)
		}
		return nil
	}
	applyArts := func() error { return s.applyTask5ArtifactParticipants(ctx, tx, work, result) }
	applySecrets := func() error {
		secrets := append([]SecretUpdate(nil), work.SecretUpdates...)
		sort.Slice(secrets, func(i, j int) bool { return secrets[i].SecretRef < secrets[j].SecretRef })
		for _, update := range secrets {
			if update.SecretRef == "" || len(update.SecretRef) > MaxSecretRefBytes {
				return ErrParticipantFailure
			}
			var latest adapterSecretRow
			q := rawStringQuery(tx, "secret_ref", update.SecretRef).Order("row_version DESC").First(&latest)
			current := uint64(0)
			if q.Error == nil {
				current = latest.RowVersion
			} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
				return ErrParticipantFailure
			}
			if current >= maxPersistedVersion || (current > 0 && latest.SecretVersion >= maxPersistedVersion) {
				return ErrVersionExhausted
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
					if latest.SecretVersion >= maxPersistedVersion {
						return ErrVersionExhausted
					}
					secretVersion = latest.SecretVersion + 1
				}
			}
			if secretVersion >= maxPersistedVersion {
				return ErrVersionExhausted
			}
			if current > 0 && secretVersion <= latest.SecretVersion {
				return ErrParticipantConflict
			}
			row := latest
			row.SecretRef = update.SecretRef
			row.SecretVersion = secretVersion
			row.RowVersion = version
			if current == 0 {
				row.EndpointID = update.EndpointID
				row.AdapterID = update.AdapterID
				row.AdapterType = "opaque"
				row.CreatedAt = time.Now().UTC()
			} else {
				if update.EndpointID != "" {
					row.EndpointID = update.EndpointID
				}
				if update.AdapterID != "" {
					row.AdapterID = update.AdapterID
				}
			}
			if update.ValueSet || update.Value != nil {
				row.Value = bytes.Clone(update.Value)
			} else if current == 0 {
				return ErrInvalidMetadata
			}
			row.UpdatedAt = chooseTime(update.UpdatedAt, time.Now().UTC())
			if len(row.Value) > MaxSecretBytes {
				return ErrOversizeInput
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
			return plugins[i].Key < plugins[j].Key
		})
		for _, update := range plugins {
			if update.ExtensionID == "" {
				return ErrInvalidMetadata
			}
			if len(update.Value) > MaxPluginValueBytes {
				return &OversizeError{Bound: "plugin value bytes", Limit: MaxPluginValueBytes, Actual: len(update.Value)}
			}
			var row pluginKVRow
			q := pluginQuery(tx, update.ExtensionID, update.Key).First(&row)
			current := uint64(0)
			if q.Error == nil {
				current = row.RowVersion
			} else if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
				return ErrParticipantFailure
			}
			if err := participantVersion(update.ExpectedVersion, current, update.Version, tablePluginKV, "<redacted>"); err != nil {
				return err
			}
			if update.Deleted {
				if current == 0 {
					return ErrNotFound
				}
				q = pluginQuery(tx, update.ExtensionID, update.Key).Where("row_version = ?", current).Delete(&pluginKVRow{})
				if err := participantCAS(tablePluginKV, "<redacted>", update.ExpectedVersion, current, q); err != nil {
					return err
				}
				result.PluginKVIndexes = append(result.PluginKVIndexes, []byte(update.Key))
				continue
			}
			version, err := nextVersion(current)
			if err != nil {
				return err
			}
			if current == 0 {
				row = pluginKVRow{ExtensionID: update.ExtensionID, Key: update.Key, Value: bytes.Clone(update.Value), RowVersion: version, CreatedAt: chooseTime(update.UpdatedAt, time.Now().UTC()), UpdatedAt: chooseTime(update.UpdatedAt, time.Now().UTC())}
				q = tx.Create(&row)
			} else {
				row.Value = bytes.Clone(update.Value)
				row.RowVersion = version
				row.UpdatedAt = chooseTime(update.UpdatedAt, time.Now().UTC())
				q = pluginQuery(tx.Model(&pluginKVRow{}), update.ExtensionID, update.Key).Where("row_version = ?", current).Updates(map[string]any{"value": row.Value, "row_version": row.RowVersion, "updated_at": row.UpdatedAt})
			}
			if err := participantCAS(tablePluginKV, "<redacted>", update.ExpectedVersion, current, q); err != nil {
				return err
			}
			result.PluginKVIndexes = append(result.PluginKVIndexes, []byte(update.Key))
		}
		for index := range plugins {
			if index > 0 && plugins[index].ExtensionID == plugins[index-1].ExtensionID {
				continue
			}
			if err := validatePluginQuota(tx, plugins[index].ExtensionID); err != nil {
				return err
			}
		}
		return nil
	}
	applyInbox := func() error { return s.applyTask5InboxParticipants(ctx, tx, work, result) }
	applyEffects := func() error { return s.applyTask5EffectParticipants(ctx, tx, work, result) }
	if err := applyOps(); err != nil {
		return err
	}
	if err := applyInbox(); err != nil {
		return err
	}
	if err := applyEffects(); err != nil {
		return err
	}
	if err := applyArts(); err != nil {
		return err
	}
	if err := applySecrets(); err != nil {
		return err
	}
	if err := applyPlugins(); err != nil {
		return err
	}
	return nil
}
func nonempty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
func chooseTime(v, fallback time.Time) time.Time {
	if v.IsZero() {
		return fallback
	}
	return v
}
func timePtr(v time.Time) *time.Time {
	if v.IsZero() {
		return nil
	}
	return &v
}

var _ Store = (*GORMStore)(nil)
