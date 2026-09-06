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
	return func(s *GORMStore) { s.codec = codec }
}
func WithArtifactCodec(codec any) StoreOption { return WithPayloadCodec(codec) }

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
}
func NewStore(database *Database, options ...StoreOption) *GORMStore {
	s := &GORMStore{db: database, clock: SystemClock{}, ids: UUIDGenerator{}}
	for _, option := range options { if option != nil { option(s) } }
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
	if err = ValidateUnitOfWork(work); err != nil { return CommitResult{}, err }
	if initErr := s.initializationError(); initErr != nil { return CommitResult{}, initErr }
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

	var control projectionControlRow
	if err = locked(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil { return CommitResult{}, errors.New("eventstore: lock projection control failed") }
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
		if current == 0 { row = operationRow{OperationID:update.OperationID, Version:version, Kind:nonempty(update.Kind,"unknown"), Status:nonempty(update.Status,"pending"), PrincipalID:nonempty(update.PrincipalID,update.OperationID), ResourceType:nonempty(update.ResourceID,"unknown"), ResourceID:update.ResourceID, IdempotencyScope:nonempty(update.IdempotencyScope,"operation"), IdempotencyKey:nonempty(update.IdempotencyKey,update.OperationID), RequestID:update.RequestID, RequestDigest:update.RequestDigest, CorrelationID:update.CorrelationID, ResultCode:update.ResultCode, ErrorCode:update.ErrorCode, ArtifactRef:update.ArtifactID, PrivateContext:update.PrivateContextCiphertext, PrivateNonce:update.PrivateContextNonce, PrivateKeyID:update.EncryptionKeyID, CreatedAt:chooseTime(update.CreatedAt,now), UpdatedAt:now, ExpiresAt:timePtr(update.ExpiresAt)}; q=tx.Create(&row)
		} else {
			if update.Kind != "" { row.Kind = update.Kind }; if update.Status != "" { row.Status = update.Status }; if update.PrincipalID != "" { row.PrincipalID = update.PrincipalID }; if update.ResourceID != "" { row.ResourceID = update.ResourceID }; if update.IdempotencyScope != "" { row.IdempotencyScope = update.IdempotencyScope }; if update.IdempotencyKey != "" { row.IdempotencyKey = update.IdempotencyKey }; if update.RequestID != "" { row.RequestID = update.RequestID }; if len(update.RequestDigest) > 0 { row.RequestDigest = update.RequestDigest }; if update.CorrelationID != "" { row.CorrelationID = update.CorrelationID }; if update.ResultCode != "" { row.ResultCode = update.ResultCode }; if update.ErrorCode != "" { row.ErrorCode = update.ErrorCode }; if update.ArtifactID != "" { row.ArtifactRef = update.ArtifactID }; if len(update.PrivateContextCiphertext) > 0 { row.PrivateContext = update.PrivateContextCiphertext }; if len(update.PrivateContextNonce) > 0 { row.PrivateNonce = update.PrivateContextNonce }; if update.EncryptionKeyID != "" { row.PrivateKeyID = update.EncryptionKeyID }; if !update.ExpiresAt.IsZero() { row.ExpiresAt = timePtr(update.ExpiresAt) }; row.Version = version; row.UpdatedAt = now
			q=tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?",update.OperationID,current).Updates(map[string]any{"version":row.Version,"kind":row.Kind,"status":row.Status,"principal_id":row.PrincipalID,"resource_type":row.ResourceType,"resource_id":row.ResourceID,"idempotency_scope":row.IdempotencyScope,"idempotency_key":row.IdempotencyKey,"request_id":row.RequestID,"request_digest":row.RequestDigest,"correlation_id":row.CorrelationID,"result_code":row.ResultCode,"error_code":row.ErrorCode,"artifact_id":row.ArtifactRef,"private_context":row.PrivateContext,"private_nonce":row.PrivateNonce,"private_key_id":row.PrivateKeyID,"updated_at":row.UpdatedAt,"expires_at":row.ExpiresAt})
		}
		if err := participantCAS(tableOperations, "<redacted>", update.ExpectedVersion, current, q); err != nil { return err }; result.OperationIDs=append(result.OperationIDs,update.OperationID)
	}
	return nil
}
	applyArts := func() error { return s.applyTask5ArtifactParticipants(tx, work, result) }
	applySecrets := func() error { secrets := append([]SecretUpdate(nil), work.SecretUpdates...); sort.Slice(secrets, func(i,j int) bool{return secrets[i].SecretRef < secrets[j].SecretRef})
	for _, update := range secrets {
		if update.SecretRef=="" { return ErrParticipantFailure }
		var latest adapterSecretRow
		q:=tx.Where("secret_ref = ?",update.SecretRef).Order("row_version DESC").First(&latest); current:=uint64(0)
		if q.Error==nil { current=latest.RowVersion } else if !errors.Is(q.Error,gorm.ErrRecordNotFound) { return ErrParticipantFailure }
		if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableAdapterSecrets,"<redacted>");err!=nil{return err}
		version, err := nextVersion(current); if err != nil { return err }; secretVersion:=update.SecretVersion; if secretVersion==0 {if current>0 {if latest.SecretVersion==maxUint64{return ErrVersionExhausted};secretVersion=latest.SecretVersion+1} else {secretVersion=1}}; if current>0 && secretVersion<=latest.SecretVersion{return ErrParticipantConflict}
		row:=latest; row.SecretRef=update.SecretRef; row.SecretVersion=secretVersion; row.RowVersion=version; if current==0 { row.EndpointID=nonempty(update.EndpointID,"unknown"); row.AdapterID=nonempty(update.AdapterID,"unknown"); row.AdapterType="opaque"; row.Ciphertext=nonemptyBytes(update.Ciphertext); row.Nonce=nonemptyBytes(update.Nonce); row.EncryptionKeyID=nonempty(update.EncryptionKeyID,"opaque"); row.CreatedAt=time.Now().UTC() }; if update.EndpointID!="" {row.EndpointID=update.EndpointID}; if update.AdapterID!="" {row.AdapterID=update.AdapterID}; if len(update.Ciphertext)>0 {row.Ciphertext=update.Ciphertext}; if len(update.Nonce)>0 {row.Nonce=update.Nonce}; if update.EncryptionKeyID!="" {row.EncryptionKeyID=update.EncryptionKeyID}; row.UpdatedAt=chooseTime(update.UpdatedAt,time.Now().UTC())
		q=tx.Create(&row); if q.Error!=nil{return ErrParticipantFailure}; result.SecretRefs=append(result.SecretRefs,update.SecretRef)
	}
	return nil
}
	applyPlugins := func() error { plugins := append([]PluginKVUpdate(nil), work.PluginKVUpdates...);sort.Slice(plugins,func(i,j int)bool{if plugins[i].ExtensionID!=plugins[j].ExtensionID{return plugins[i].ExtensionID<plugins[j].ExtensionID};return string(plugins[i].KeyHMAC)<string(plugins[j].KeyHMAC)})
	for _, update := range plugins {
		if update.ExtensionID=="" || len(update.KeyHMAC)==0 {return ErrParticipantFailure}
		var row pluginKVRow; q:=tx.Where("extension_id = ? AND key_hmac = ?",update.ExtensionID,update.KeyHMAC).First(&row); current:=uint64(0)
		if q.Error==nil {current=row.RowVersion} else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure}
		if err:=participantVersion(update.ExpectedVersion,current,update.Version,tablePluginKV,"<redacted>");err!=nil{return err}
		if update.Deleted { if current==0{return &ParticipantConflictError{Conflicts:[]ParticipantConflict{{Table:tablePluginKV,Key:"<redacted>",ExpectedVersion:update.ExpectedVersion,CurrentVersion:current}}}}; q=tx.Where("extension_id = ? AND key_hmac = ? AND row_version = ?",update.ExtensionID,update.KeyHMAC,current).Delete(&pluginKVRow{}); if err:=participantCAS(tablePluginKV,"<redacted>",update.ExpectedVersion,current,q);err!=nil{return err}; result.PluginKVIndexes=append(result.PluginKVIndexes,append([]byte(nil),update.KeyHMAC...)); continue }
		version, err := nextVersion(current); if err != nil { return err }; if current == 0 {row=pluginKVRow{ExtensionID:update.ExtensionID,KeyHMAC:update.KeyHMAC,EncryptedKey:nonemptyBytes(update.KeyCiphertext),KeyNonce:nonemptyBytes(update.KeyNonce),EncryptedValue:nonemptyBytes(update.ValueCiphertext),ValueNonce:nonemptyBytes(update.ValueNonce),ValueSize:update.ValueSize,RowVersion:version,EncryptionKeyID:nonempty(update.EncryptionKeyID,"opaque"),CreatedAt:time.Now().UTC(),UpdatedAt:chooseTime(update.UpdatedAt,time.Now().UTC())}} else {if len(update.KeyCiphertext)>0{row.EncryptedKey=update.KeyCiphertext};if len(update.KeyNonce)>0{row.KeyNonce=update.KeyNonce};if len(update.ValueCiphertext)>0{row.EncryptedValue=update.ValueCiphertext};if len(update.ValueNonce)>0{row.ValueNonce=update.ValueNonce};if update.ValueSize!=0{row.ValueSize=update.ValueSize};if update.EncryptionKeyID!=""{row.EncryptionKeyID=update.EncryptionKeyID};row.RowVersion=version;row.UpdatedAt=chooseTime(update.UpdatedAt,time.Now().UTC());q=tx.Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ?",update.ExtensionID,update.KeyHMAC,current).Updates(map[string]any{"encrypted_key":row.EncryptedKey,"key_nonce":row.KeyNonce,"encrypted_value":row.EncryptedValue,"value_nonce":row.ValueNonce,"value_size":row.ValueSize,"row_version":version,"updated_at":row.UpdatedAt,"encryption_key_id":row.EncryptionKeyID});if err:=participantCAS(tablePluginKV,"<redacted>",update.ExpectedVersion,current,q);err!=nil{return err};result.PluginKVIndexes=append(result.PluginKVIndexes,append([]byte(nil),update.KeyHMAC...));continue}
		if q=tx.Create(&row);q.Error!=nil{return ErrParticipantFailure}; result.PluginKVIndexes=append(result.PluginKVIndexes,append([]byte(nil),update.KeyHMAC...))
	}
	return nil
}
	applyInbox := func() error { return s.applyTask5InboxParticipants(tx, work, result) }
	applyEffects := func() error { return s.applyTask5EffectParticipants(tx, work, result) }
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
