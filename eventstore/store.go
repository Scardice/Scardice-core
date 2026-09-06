package eventstore

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"
)

var (
	ErrChecksumMismatch   = errors.New("eventstore: checksum mismatch")
	ErrParticipantConflict = errors.New("eventstore: participant conflict")
	ErrParticipantFailure  = errors.New("eventstore: participant failure")
	ErrProjectorFailure    = errors.New("eventstore: projector failure")
)

type ParticipantConflict struct {
	Table           string
	Key             string
	ExpectedVersion uint64
	CurrentVersion  uint64
}

type ParticipantConflictError struct { Conflicts []ParticipantConflict }
func (e *ParticipantConflictError) Error() string { return ErrParticipantConflict.Error() }
type Projector func(context.Context, []Envelope) error
type ParticipantHook func(context.Context, UnitOfWork) error
type TransactionProjector func(context.Context, *gorm.DB, []Envelope) error
type TransactionParticipant func(context.Context, *gorm.DB, UnitOfWork) error
type StoreOption func(*GORMStore)
func WithProjector(projector Projector) StoreOption { return func(s *GORMStore) { s.RegisterProjector(projector) } }
func WithParticipant(hook any) StoreOption { return func(s *GORMStore) { s.RegisterParticipant(hook) } }
func WithTransactionProjector(projector TransactionProjector) StoreOption { return func(s *GORMStore) { s.RegisterProjectorTx(projector) } }
func WithTransactionParticipant(hook TransactionParticipant) StoreOption { return func(s *GORMStore) { s.RegisterParticipantTx(hook) } }
func WithLockObserver(observer func(string)) StoreOption { return func(s *GORMStore) { s.SetLockObserver(observer) } }

type GORMStore struct {
	db *Database
	rawDB *gorm.DB
	mu sync.RWMutex
	projectors []Projector
	txProjectors []TransactionProjector
	participants []ParticipantHook
	txParticipants []TransactionParticipant
	lockObserver func(string)
}

// NewStore wires a store to one explicitly owned Database. A *gorm.DB is also
// accepted for tests that already own the database handle; Close is then a no-op.
func NewStore(database any, options ...StoreOption) *GORMStore {
	s := &GORMStore{}
	switch value := database.(type) {
	case *Database:
		s.db = value
	case *gorm.DB:
		s.rawDB = value
	}
	for _, option := range options { if option != nil { option(s) } }
	return s
}
func NewGORMStore(database any, options ...StoreOption) *GORMStore { return NewStore(database, options...) }
func NewEventStore(database any, options ...StoreOption) *GORMStore { return NewStore(database, options...) }

func (s *GORMStore) RegisterProjector(projector any) {
	if s == nil || projector == nil { return }
	s.mu.Lock(); defer s.mu.Unlock()
	switch hook := projector.(type) {
	case Projector: s.projectors = append(s.projectors, hook)
	case func(context.Context, []Envelope) error: s.projectors = append(s.projectors, Projector(hook))
	case TransactionProjector: s.txProjectors = append(s.txProjectors, hook)
	case func(context.Context, *gorm.DB, []Envelope) error: s.txProjectors = append(s.txProjectors, TransactionProjector(hook))
	}
}
func (s *GORMStore) RegisterProjectorTx(projector TransactionProjector) {
	if s == nil || projector == nil { return }; s.mu.Lock(); defer s.mu.Unlock(); s.txProjectors = append(s.txProjectors, projector)
}
func (s *GORMStore) RegisterParticipant(hook any) {
	if s == nil || hook == nil { return }
	s.mu.Lock(); defer s.mu.Unlock()
	switch value := hook.(type) {
	case ParticipantHook: s.participants = append(s.participants, value)
	case func(context.Context, UnitOfWork) error: s.participants = append(s.participants, ParticipantHook(value))
	case TransactionParticipant: s.txParticipants = append(s.txParticipants, value)
	case func(context.Context, *gorm.DB, UnitOfWork) error: s.txParticipants = append(s.txParticipants, TransactionParticipant(value))
	}
}
func (s *GORMStore) RegisterParticipantTx(hook TransactionParticipant) {
	if s == nil || hook == nil { return }; s.mu.Lock(); defer s.mu.Unlock(); s.txParticipants = append(s.txParticipants, hook)
}
func (s *GORMStore) SetProjector(projector any) { s.RegisterProjector(projector) }
func (s *GORMStore) SetParticipant(hook any) { s.RegisterParticipant(hook) }
func (s *GORMStore) SetLockObserver(observer func(string)) {
	if s == nil { return }
	s.mu.Lock(); defer s.mu.Unlock(); s.lockObserver = observer
}

func (s *GORMStore) observeLock(name string) {
	s.mu.RLock(); observer := s.lockObserver; s.mu.RUnlock()
	if observer != nil { observer(name) }
}

func (s *GORMStore) Commit(ctx context.Context, work UnitOfWork) (result CommitResult, err error) {
	if err = ValidateUnitOfWork(work); err != nil { return CommitResult{}, err }
	if s == nil { return CommitResult{}, errors.New("eventstore: store unavailable") }
	base := s.rawDB
	if s.db != nil { base = s.db.GORM() }
	if base == nil { return CommitResult{}, errors.New("eventstore: store unavailable") }
	if ctx == nil { ctx = context.Background() }
	tx := base.WithContext(ctx).Begin()
	if tx.Error != nil { return CommitResult{}, errors.New("eventstore: begin transaction failed") }
	committed := false
	defer func() {
		if !committed { _ = tx.Rollback().Error }
	}()

	// A2 lock order: projection control, aggregate heads, global sequence.
	var control projectionControlRow
	if err = tx.Where("singleton_id = ?", "default").First(&control).Error; err != nil { return CommitResult{}, errors.New("eventstore: lock projection control failed") }
	s.observeLock(tableProjectionControl)

	type headState struct { stream StreamID; current uint64 }
	headOrder := make([]StreamID, 0, len(work.Streams))
	for _, item := range work.Streams { headOrder = append(headOrder, item.Stream) }
	sort.Slice(headOrder, func(i, j int) bool { return streamLess(headOrder[i], headOrder[j]) })
	headStates := make(map[StreamID]headState, len(headOrder))
	for _, stream := range headOrder {
		var head aggregateHeadRow
		q := tx.Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).First(&head)
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
	var sequence eventGlobalSequenceRow
	if totalEvents > 0 {
		if err = tx.Where("singleton_id = ?", "default").First(&sequence).Error; err != nil { return CommitResult{}, errors.New("eventstore: lock event sequence failed") }
		s.observeLock(tableEventGlobalSequence)
	}

	result.StreamVersions = make(map[StreamID]uint64, len(work.Streams))
	if totalEvents > 0 {
		result.Events = make([]Envelope, 0, totalEvents)
		position := sequence.NextPosition
		for _, item := range work.Streams {
			version := headStates[item.Stream].current
			for _, event := range item.Events {
				version++
				envelope, envelopeErr := (EventFactory{}).Envelope(item.Stream, version, position, event)
				if envelopeErr != nil { return CommitResult{}, envelopeErr }
				if ComputeEventChecksum(envelope) != envelope.Checksum { return CommitResult{}, ErrChecksumMismatch }
				row := domainEventRow{EventID: envelope.EventID, AggregateType: envelope.Stream.AggregateType, AggregateID: envelope.Stream.AggregateID, AggregateVersion: envelope.StreamVersion, GlobalPosition: envelope.GlobalPosition, EventType: envelope.EventType, SchemaVersion: envelope.SchemaVersion, Payload: envelope.Payload, CommandID: envelope.Metadata.CommandID, CorrelationID: envelope.Metadata.CorrelationID, CausationID: envelope.Metadata.CausationID, PrincipalID: envelope.Metadata.PrincipalID, Producer: envelope.Metadata.Producer, OccurredAtUnixNanoUTC: metadataUnixNano(envelope.Metadata), Checksum: append([]byte(nil), envelope.Checksum[:]...), CreatedAt: time.Now().UTC()}
				if err = tx.Create(&row).Error; err != nil { return CommitResult{}, errors.New("eventstore: insert domain event failed") }
				result.Events = append(result.Events, envelope)
				position++
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

	if err = s.applyParticipants(ctx, tx, work, &result); err != nil { return CommitResult{}, err }
	s.mu.RLock(); projectors := append([]Projector(nil), s.projectors...); txProjectors := append([]TransactionProjector(nil), s.txProjectors...); participants := append([]ParticipantHook(nil), s.participants...); txParticipants := append([]TransactionParticipant(nil), s.txParticipants...); s.mu.RUnlock()
	for _, hook := range txParticipants {
		if hookErr := hook(ctx, tx, work); hookErr != nil { return CommitResult{}, ErrParticipantFailure }
	}
	for _, hook := range participants {
		if hookErr := hook(ctx, work); hookErr != nil { return CommitResult{}, ErrParticipantFailure }
	}
	for _, projector := range txProjectors {
		if hookErr := projector(ctx, tx, result.Events); hookErr != nil { return CommitResult{}, ErrProjectorFailure }
	}
	for _, projector := range projectors {
		if hookErr := projector(ctx, result.Events); hookErr != nil { return CommitResult{}, ErrProjectorFailure }
	}
	if err = tx.Commit().Error; err != nil { return CommitResult{}, errors.New("eventstore: commit transaction failed") }
	committed = true
	return result, nil
}

func streamLess(a, b StreamID) bool {
	if a.AggregateType != b.AggregateType { return a.AggregateType < b.AggregateType }
	return a.AggregateID < b.AggregateID
}

func (s *GORMStore) Load(ctx context.Context, stream StreamID, fromVersion uint64) ([]Envelope, error) {
	if s == nil { return nil, errors.New("eventstore: store unavailable") }
	base := s.rawDB
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
		envelope := Envelope{Stream: stream, StreamVersion: row.AggregateVersion, GlobalPosition: row.GlobalPosition, EventID: row.EventID, EventType: row.EventType, SchemaVersion: row.SchemaVersion, Payload: append([]byte(nil), row.Payload...), Metadata: Metadata{EventID: row.EventID, CommandID: row.CommandID, CorrelationID: row.CorrelationID, CausationID: row.CausationID, PrincipalID: row.PrincipalID, Producer: row.Producer, OccurredAtUnixNanoUTC: row.OccurredAtUnixNanoUTC, OccurredAtUnixNanoSet: true}, Checksum: checksum}
		if ComputeEventChecksum(envelope) != checksum { return nil, ErrChecksumMismatch }
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
}

func (s *GORMStore) Close() error { if s == nil || s.db == nil { return nil }; return s.db.Close() }

func participantVersion(expected, current, supplied uint64, table, key string) error {
	if expected != current { return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: key, ExpectedVersion: expected, CurrentVersion: current}}} }
	if supplied != 0 && supplied != current+1 { return ErrParticipantConflict }
	return nil
}

func (s *GORMStore) applyParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	// Fixed participant order is intentional; each group is sorted by its stable key.
	ops := append([]OperationUpdate(nil), work.Operations...); sort.Slice(ops, func(i,j int) bool{return ops[i].OperationID < ops[j].OperationID})
	for _, update := range ops {
		if update.OperationID == "" { return ErrParticipantFailure }
		var row operationRow; q := tx.Where("operation_id = ?", update.OperationID).First(&row); current := uint64(0)
		version := current+1; now := update.UpdatedAt; if now.IsZero(){now=time.Now().UTC()}
		if current == 0 { row = operationRow{OperationID:update.OperationID, Version:version, Kind:nonempty(update.Kind,"unknown"), Status:nonempty(update.Status,"pending"), PrincipalID:nonempty(update.PrincipalID,update.OperationID), ResourceType:nonempty(update.ResourceID,"unknown"), ResourceID:update.ResourceID, IdempotencyScope:nonempty(update.IdempotencyScope,"operation"), IdempotencyKey:nonempty(update.IdempotencyKey,update.OperationID), RequestID:update.RequestID, RequestDigest:update.RequestDigest, CorrelationID:update.CorrelationID, ResultCode:update.ResultCode, ErrorCode:update.ErrorCode, ArtifactRef:update.ArtifactID, PrivateContext:update.PrivateContextCiphertext, PrivateNonce:update.PrivateContextNonce, PrivateKeyID:update.EncryptionKeyID, CreatedAt:chooseTime(update.CreatedAt,now), UpdatedAt:now, ExpiresAt:timePtr(update.ExpiresAt)}; q=tx.Create(&row)
		} else { q=tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?",update.OperationID,current).Updates(map[string]any{"version":version,"status":update.Status,"result_code":update.ResultCode,"error_code":update.ErrorCode,"artifact_id":update.ArtifactID,"updated_at":now}) }
		if q.Error != nil || q.RowsAffected == 0 && current != 0 { return ErrParticipantFailure }; result.OperationIDs=append(result.OperationIDs,update.OperationID)
	}
	arts := append([]ArtifactUpdate(nil), work.ArtifactUpdates...); sort.Slice(arts, func(i,j int) bool{return arts[i].ArtifactID < arts[j].ArtifactID})
	for _, update := range arts {
		var row operationArtifactRow; q:=tx.Where("artifact_id = ?",update.ArtifactID).First(&row); current:=uint64(0); if q.Error==nil{current=row.Version}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure}; if update.ArtifactID==""{return ErrParticipantFailure}; if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableOperationArtifacts,update.ArtifactID);err!=nil{return err}; version:=current+1; row=operationArtifactRow{ArtifactID:update.ArtifactID,Version:version,OperationID:update.OperationID,OwnerPrincipalID:nonempty(update.OwnerPrincipalID,"unknown"),MediaType:nonempty(update.MediaType,"application/octet-stream"),SafeFilename:update.SafeFilename,Size:update.Size,Status:nonempty(update.Status,"ready"),Ciphertext:update.Ciphertext,Nonce:update.Nonce,EncryptionKeyID:update.EncryptionKeyID,ExpiresAt:chooseTime(update.ExpiresAt,time.Now().UTC())}; if current==0{q=tx.Create(&row)}else{q=tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?",update.ArtifactID,current).Updates(map[string]any{"version":version,"status":row.Status,"ciphertext":row.Ciphertext,"nonce":row.Nonce})}; if q.Error!=nil{return ErrParticipantFailure}; result.ArtifactIDs=append(result.ArtifactIDs,update.ArtifactID)
	}
	secrets := append([]SecretUpdate(nil), work.SecretUpdates...); sort.Slice(secrets, func(i,j int) bool{return secrets[i].SecretRef < secrets[j].SecretRef})
	for _, update := range secrets { if update.SecretRef==""{return ErrParticipantFailure}; var row adapterSecretRow; q:=tx.Where("secret_ref = ?",update.SecretRef).Order("secret_version DESC").First(&row); current:=uint64(0);if q.Error==nil{current=row.RowVersion}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure};if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableAdapterSecrets,update.SecretRef);err!=nil{return err};version:=current+1;row=adapterSecretRow{SecretRef:update.SecretRef,SecretVersion:chooseUint(update.SecretVersion,version),EndpointID:nonempty(update.EndpointID,"unknown"),AdapterID:nonempty(update.AdapterID,"unknown"),AdapterType:"opaque",Ciphertext:nonemptyBytes(update.Ciphertext),Nonce:nonemptyBytes(update.Nonce),EncryptionKeyID:nonempty(update.EncryptionKeyID,"opaque"),RowVersion:version,CreatedAt:time.Now().UTC(),UpdatedAt:chooseTime(update.UpdatedAt,time.Now().UTC())};if current==0{q=tx.Create(&row)}else{q=tx.Model(&adapterSecretRow{}).Where("secret_ref = ? AND row_version = ?",update.SecretRef,current).Updates(map[string]any{"secret_version":row.SecretVersion,"ciphertext":row.Ciphertext,"nonce":row.Nonce,"row_version":version,"updated_at":row.UpdatedAt})};if q.Error!=nil{return ErrParticipantFailure};result.SecretRefs=append(result.SecretRefs,update.SecretRef)}
	plugins := append([]PluginKVUpdate(nil), work.PluginKVUpdates...);sort.Slice(plugins,func(i,j int)bool{if plugins[i].ExtensionID!=plugins[j].ExtensionID{return plugins[i].ExtensionID<plugins[j].ExtensionID};return string(plugins[i].KeyHMAC)<string(plugins[j].KeyHMAC)})
	for _, update := range plugins {var row pluginKVRow;q:=tx.Where("extension_id = ? AND key_hmac = ?",update.ExtensionID,update.KeyHMAC).First(&row);current:=uint64(0);if q.Error==nil{current=row.RowVersion}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure};if update.ExtensionID==""||len(update.KeyHMAC)==0{return ErrParticipantFailure};if err:=participantVersion(update.ExpectedVersion,current,update.Version,tablePluginKV,"<redacted>");err!=nil{return err};version:=current+1;row=pluginKVRow{ExtensionID:update.ExtensionID,KeyHMAC:update.KeyHMAC,EncryptedKey:nonemptyBytes(update.KeyCiphertext),KeyNonce:nonemptyBytes(update.KeyNonce),EncryptedValue:nonemptyBytes(update.ValueCiphertext),ValueNonce:nonemptyBytes(update.ValueNonce),ValueSize:update.ValueSize,RowVersion:version,EncryptionKeyID:nonempty(update.EncryptionKeyID,"opaque"),CreatedAt:time.Now().UTC(),UpdatedAt:chooseTime(update.UpdatedAt,time.Now().UTC())};if current==0{q=tx.Create(&row)}else{q=tx.Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ? AND row_version = ?",update.ExtensionID,update.KeyHMAC,current).Updates(map[string]any{"encrypted_key":row.EncryptedKey,"key_nonce":row.KeyNonce,"encrypted_value":row.EncryptedValue,"value_nonce":row.ValueNonce,"value_size":row.ValueSize,"row_version":version,"updated_at":row.UpdatedAt})};if q.Error!=nil{return ErrParticipantFailure};result.PluginKVIndexes=append(result.PluginKVIndexes,append([]byte(nil),update.KeyHMAC...))}
	inbox := append([]InboxUpdate(nil), work.InboxUpdates...); sort.Slice(inbox, func(i,j int)bool{return inbox[i].InboxID<inbox[j].InboxID})
	for _, update := range inbox {
		if update.InboxID=="" { return ErrParticipantFailure }
		var row inboxMessageRow
		q:=tx.Where("inbox_id = ?",update.InboxID).First(&row); current:=uint64(0)
		if q.Error==nil { current=row.Version } else if !errors.Is(q.Error,gorm.ErrRecordNotFound) { return ErrParticipantFailure }
		if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableInboxMessages,update.InboxID);err!=nil{return err}
		version:=current+1; now:=time.Now().UTC()
		row=inboxMessageRow{InboxID:update.InboxID,EndpointID:nonempty(update.EndpointID,"unknown"),ProviderEventKey:nonempty(update.ProviderEventKey,update.InboxID),LaneHMAC:nonemptyBytes(update.LaneHMAC),OrderingSequence:update.OrderingSequence,Status:nonempty(update.Status,"pending"),Version:version,LeaseOwner:update.LeaseOwner,LeaseEpoch:update.LeaseEpoch,LeaseExpiry:timePtr(update.LeaseExpiresAt),AttemptID:update.AttemptID,CallbackStartedAt:timePtr(update.CallbackStartedAt),CompletedAt:timePtr(update.CompletedAt),PayloadCiphertext:update.PayloadCiphertext,PayloadNonce:update.PayloadNonce,EncryptionKeyID:nonempty(update.DigestKeyID,"opaque"),ContentDigest:update.ContentDigest,ContentDigestKeyID:update.DigestKeyID,PayloadExpiresAt:timePtr(update.PayloadExpiresAt),WorkflowID:update.WorkflowID}
		if current==0 { q=tx.Create(&row) } else { q=tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?",update.InboxID,current).Updates(map[string]any{"version":version,"status":row.Status,"lease_owner":row.LeaseOwner,"lease_epoch":row.LeaseEpoch,"lease_expiry":row.LeaseExpiry,"attempt_id":row.AttemptID,"completed_at":row.CompletedAt}) }
		if q.Error!=nil{return ErrParticipantFailure}; result.InboxIDs=append(result.InboxIDs,update.InboxID); _=now
	}
	effects := append([]NewEffect(nil), work.Effects...); sort.Slice(effects, func(i,j int)bool{return effects[i].EffectID<effects[j].EffectID})
	for _, update := range effects {
		if update.EffectID=="" { return ErrParticipantFailure }
		var row outboxEffectRow
		q:=tx.Where("effect_id = ?",update.EffectID).First(&row); current:=uint64(0)
		if q.Error==nil {current=row.Version} else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure}
		if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableOutboxEffects,update.EffectID);err!=nil{return err}
		version:=current+1; now:=time.Now().UTC()
		row=outboxEffectRow{EffectID:update.EffectID,Version:version,EndpointID:nonempty(update.EndpointID,"unknown"),LaneHMAC:nonemptyBytes(update.LaneHMAC),OrderingSequence:update.OrderingSequence,EffectClass:nonempty(update.EffectType,"unknown"),RiskClass:nonempty(update.RiskClass,"normal"),Status:nonempty(update.Status,"pending"),AttemptID:update.AttemptID,LeaseOwner:update.LeaseOwner,LeaseEpoch:update.LeaseEpoch,LeaseExpiry:timePtr(update.LeaseExpiresAt),DeadlineAt:timePtr(update.DeadlineAt),NextAttemptAt:timePtr(update.NextAttemptAt),DispatchedAt:timePtr(update.DispatchedAt),PayloadCiphertext:update.PayloadCiphertext,PayloadNonce:update.PayloadNonce,EncryptionKeyID:nonempty(update.DigestKeyID,"opaque"),ContentDigest:update.ContentDigest,ContentDigestKeyID:update.DigestKeyID,ResultCode:update.ResultCode,ErrorCode:update.ErrorCode,ProviderMessageID:update.ProviderMessageID,CompletedAt:timePtr(update.CompletedAt),PayloadExpiresAt:timePtr(update.PayloadExpiresAt),CreatedAt:now}
		if current==0 {q=tx.Create(&row)} else {q=tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?",update.EffectID,current).Updates(map[string]any{"version":version,"status":row.Status,"lease_owner":row.LeaseOwner,"lease_epoch":row.LeaseEpoch,"lease_expiry":row.LeaseExpiry,"attempt_id":row.AttemptID,"result_code":row.ResultCode,"error_code":row.ErrorCode})}
		if q.Error!=nil{return ErrParticipantFailure}; result.EffectIDs=append(result.EffectIDs,update.EffectID)
	}
	fences := append([]SubjectFenceUpdate(nil), work.FenceUpdates...); sort.Slice(fences,func(i,j int)bool{if string(fences[i].SubjectKey)!=string(fences[j].SubjectKey){return string(fences[i].SubjectKey)<string(fences[j].SubjectKey)};return fences[i].Scope<fences[j].Scope})
	for _, update := range fences {
		if len(update.SubjectKey)==0 || update.Scope=="" {return ErrParticipantFailure}
		var row subjectFenceRow
		q:=tx.Where("subject_key = ? AND scope = ?",update.SubjectKey,update.Scope).First(&row); current:=uint64(0)
		if q.Error==nil{current=row.Version}else if !errors.Is(q.Error,gorm.ErrRecordNotFound){return ErrParticipantFailure}
		if err:=participantVersion(update.ExpectedVersion,current,update.Version,tableSubjectFences,"<redacted>");err!=nil{return err}
		version:=current+1; row=subjectFenceRow{SubjectKey:update.SubjectKey,Scope:update.Scope,Version:version,PurgeOperationID:update.PurgeOperationID,CreatedAt:chooseTime(update.CreatedAt,time.Now().UTC()),ExpiresAt:timePtr(update.ExpiresAt)}
		if current==0{q=tx.Create(&row)}else{q=tx.Model(&subjectFenceRow{}).Where("subject_key = ? AND scope = ? AND version = ?",update.SubjectKey,update.Scope,current).Updates(map[string]any{"version":version,"purge_operation_id":row.PurgeOperationID,"expires_at":row.ExpiresAt})}
		if q.Error!=nil{return ErrParticipantFailure};result.FenceKeys=append(result.FenceKeys,append([]byte(nil),update.SubjectKey...))
	}
	return nil
}
func nonempty(v, fallback string) string { if v=="" {return fallback};return v }
func nonemptyBytes(v []byte) []byte { if len(v)==0{return []byte{0}};return v }
func chooseTime(v, fallback time.Time) time.Time {if v.IsZero(){return fallback};return v}
func timePtr(v time.Time) *time.Time {if v.IsZero(){return nil};return &v}
func chooseUint(v, fallback uint64) uint64 {if v==0{return fallback};return v}

var _ Store = (*GORMStore)(nil)
