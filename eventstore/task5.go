package eventstore

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	inboxLaneKind        = "inbox"
	outboxLaneKind       = "outbox"
	defaultLeaseDuration = time.Minute
)

func (s *GORMStore) task5Base(ctx context.Context) (*gorm.DB, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, errors.New("eventstore: store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.db.GORM().WithContext(ctx), nil
}

func (s *GORMStore) task5Now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *GORMStore) task5ID() (string, error) {
	if s != nil && s.ids != nil {
		return s.ids.NewID()
	}
	return "", ErrEncryptionUnavailable
}

func task5Ptr(v time.Time) *time.Time {
	if v.IsZero() {
		return nil
	}
	v = v.UTC()
	return &v
}

func task5Copy(v []byte) []byte {
	if v == nil {
		return nil
	}
	return append([]byte(nil), v...)
}

func task5LeaseDuration(v time.Duration) time.Duration {
	if v <= 0 {
		return defaultLeaseDuration
	}
	return v
}

func task5Begin(base *gorm.DB) (*gorm.DB, error) {
	tx := base.Begin()
	if tx.Error != nil {
		return nil, errors.New("eventstore: begin transaction failed")
	}
	return tx, nil
}

func task5Commit(tx *gorm.DB) error {
	if err := tx.Commit().Error; err != nil {
		return errors.New("eventstore: commit transaction failed")
	}
	return nil
}

func task5Rollback(tx *gorm.DB) {
	if tx != nil {
		_ = tx.Rollback().Error
	}
}

func task5Lane(tx *gorm.DB, kind string, lane []byte, now time.Time) (laneHeadRow, error) {
	var head laneHeadRow
	q := locked(tx).Where("kind = ? AND lane_hmac = ?", kind, lane).First(&head)
	if q.Error == nil {
		return head, nil
	}
	if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return laneHeadRow{}, errors.New("eventstore: lock lane head failed")
	}
	head = laneHeadRow{Kind: kind, LaneHMAC: task5Copy(lane), NextSequence: 1, UpdatedAt: now}
	if err := tx.Create(&head).Error; err != nil {
		return laneHeadRow{}, errors.New("eventstore: materialize lane head failed")
	}
	return head, nil
}

func task5AllocateLane(tx *gorm.DB, kind string, lane []byte, now time.Time) (uint64, error) {
	head, err := task5Lane(tx, kind, lane, now)
	if err != nil {
		return 0, err
	}
	sequence := head.NextSequence
	if sequence == 0 || sequence == maxUint64 {
		return 0, ErrVersionExhausted
	}
	head.NextSequence++
	head.UpdatedAt = now
	if err := tx.Model(&laneHeadRow{}).Where("kind = ? AND lane_hmac = ?", kind, lane).Updates(map[string]any{"next_sequence": head.NextSequence, "updated_at": head.UpdatedAt}).Error; err != nil {
		return 0, errors.New("eventstore: advance lane head failed")
	}
	return sequence, nil
}

func validInboxStatus(v string) bool {
	switch v {
	case InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous, InboxStatusConfirmedConsumed, InboxStatusFailed, InboxStatusSkipped:
		return true
	}
	return false
}
func validOutboxStatus(v string) bool {
	switch v {
	case OutboxStatusPending, OutboxStatusLeased, OutboxStatusDispatched, OutboxStatusSucceeded, OutboxStatusFailed, OutboxStatusAmbiguous:
		return true
	}
	return false
}
func validRisk(v string) bool {
	switch v {
	case RiskPreDispatchRetryable, RiskProviderIdempotent, RiskNonIdempotentAfterDispatch:
		return true
	}
	return false
}
func inboxUnresolved(v string) bool {
	switch v {
	case InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous:
		return true
	}
	return false
}
func outboxUnresolved(v string) bool {
	switch v {
	case OutboxStatusPending, OutboxStatusLeased, OutboxStatusDispatched, OutboxStatusAmbiguous:
		return true
	}
	return false
}

func inboxTransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case InboxStatusPending:
		return to == InboxStatusLeased || to == InboxStatusFailed
	case InboxStatusLeased:
		return to == InboxStatusCallbackStarted || to == InboxStatusFailed || to == InboxStatusPending
	case InboxStatusCallbackStarted:
		return to == InboxStatusAmbiguous
	case InboxStatusAmbiguous:
		return false
	}
	return false
}
func outboxTransitionAllowed(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case OutboxStatusPending:
		return to == OutboxStatusLeased || to == OutboxStatusFailed
	case OutboxStatusLeased:
		return to == OutboxStatusDispatched || to == OutboxStatusPending || to == OutboxStatusAmbiguous
	case OutboxStatusDispatched:
		return to == OutboxStatusSucceeded || to == OutboxStatusFailed || to == OutboxStatusAmbiguous
	case OutboxStatusAmbiguous:
		return false
	}
	return false
}

func (s *GORMStore) AcceptInbox(ctx context.Context, update InboxUpdate) (result CommitResult, err error) {
	if update.InboxID == "" {
		update.InboxID, err = s.task5ID()
		if err != nil {
			return CommitResult{}, err
		}
	}
	if update.EndpointID == "" || update.ProviderEventKey == "" || len(update.LaneHMAC) == 0 || len(update.PayloadCiphertext) == 0 || len(update.PayloadNonce) == 0 {
		return CommitResult{}, ErrParticipantFailure
	}
	if update.Status == "" {
		update.Status = InboxStatusPending
	}
	if update.Status != InboxStatusPending {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.PayloadExpiresAt.IsZero() {
		update.PayloadExpiresAt = s.task5Now().Add(InboxPayloadTTL)
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var existing inboxMessageRow
	q := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&existing)
	if q.Error == nil {
		result = CommitResult{InboxIDs: []string{existing.InboxID}, OrderingSequence: existing.OrderingSequence, Version: existing.Version, Deduplicated: true, Idempotent: true}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return result, nil
	}
	if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, errors.New("eventstore: dedupe lookup failed")
	}
	now := s.task5Now()
	sequence, err := task5AllocateLane(tx, inboxLaneKind, update.LaneHMAC, now)
	if err != nil {
		return CommitResult{}, err
	}
	row := inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, Status: InboxStatusPending, Version: 1, PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), EncryptionKeyID: update.DigestKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: update.DigestKeyID, PayloadExpiresAt: task5Ptr(update.PayloadExpiresAt), WorkflowID: update.WorkflowID}
	if err = tx.Create(&row).Error; err != nil {
		return CommitResult{}, errors.New("eventstore: insert inbox failed")
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, OrderingSequence: sequence, Version: 1}, nil
}

func (s *GORMStore) ClaimInbox(ctx context.Context, req InboxClaimRequest) (lease InboxLease, err error) {
	if strings.TrimSpace(req.WorkerID) == "" {
		return InboxLease{}, ErrParticipantFailure
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return InboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return InboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	var row inboxMessageRow
	q := locked(tx).Where("(status = ? OR (status = ? AND (lease_expiry IS NULL OR lease_expiry <= ?)))", InboxStatusPending, InboxStatusLeased, now).Where("NOT EXISTS (SELECT 1 FROM inbox_messages p WHERE p.lane_hmac = inbox_messages.lane_hmac AND p.ordering_sequence < inbox_messages.ordering_sequence AND p.status IN ?)", []string{InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous}).Order("ordering_sequence ASC").First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return InboxLease{}, ErrNotFound
	}
	if q.Error != nil {
		return InboxLease{}, errors.New("eventstore: claim inbox query failed")
	}
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubInbox(tx, &row, now, true); err != nil {
			return InboxLease{}, err
		}
		if err = task5Commit(tx); err != nil {
			return InboxLease{}, err
		}
		return InboxLease{}, ErrPayloadExpired
	}
	if row.LeaseEpoch == maxUint64 {
		return InboxLease{}, ErrVersionExhausted
	}
	attempt, idErr := s.task5ID()
	if idErr != nil {
		return InboxLease{}, idErr
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	version, vErr := nextVersion(row.Version)
	if vErr != nil {
		return InboxLease{}, vErr
	}
	updates := map[string]any{"status": InboxStatusLeased, "version": version, "lease_owner": req.WorkerID, "lease_epoch": row.LeaseEpoch + 1, "lease_expiry": expires, "attempt_id": attempt}
	q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, row.Version).Updates(updates)
	if q.Error != nil {
		return InboxLease{}, errors.New("eventstore: claim inbox failed")
	}
	if q.RowsAffected != 1 {
		return InboxLease{}, ErrStaleLease
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID = InboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt
	lease.Update = inboxUpdateFromRow(row)
	if err = task5Commit(tx); err != nil {
		return InboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) UpdateInbox(ctx context.Context, update InboxUpdate) (result CommitResult, err error) {
	if update.InboxID == "" || !validInboxStatus(update.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Resolution != "" {
		return s.resolveInboxTx(ctx, InboxResolutionRequest{InboxID: update.InboxID, ExpectedVersion: update.ExpectedVersion, Resolution: update.Resolution, PrincipalID: update.PrincipalID, Reason: update.Reason}, update.ResolutionAt)
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row inboxMessageRow
	q := locked(tx).Where("inbox_id = ?", update.InboxID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, ErrNotFound
	}
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: load inbox failed")
	}
	if update.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if !inboxTransitionAllowed(row.Status, update.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Status == InboxStatusLeased || row.Status == InboxStatusLeased || row.Status == InboxStatusCallbackStarted {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) {
			return CommitResult{}, ErrStaleLease
		}
	}
	now := s.task5Now()
	if update.Status == InboxStatusPending && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubInbox(tx, &row, now, false); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{}, ErrPayloadExpired
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return CommitResult{}, err
	}
	if update.Status == InboxStatusCallbackStarted && row.CallbackStartedAt == nil {
		row.CallbackStartedAt = task5Ptr(now)
	}
	row.Status = update.Status
	row.Version = version
	if update.LeaseOwner != "" {
		row.LeaseOwner = update.LeaseOwner
	}
	if update.LeaseEpoch != 0 {
		row.LeaseEpoch = update.LeaseEpoch
	}
	if update.AttemptID != "" {
		row.AttemptID = update.AttemptID
	}
	if !update.LeaseExpiresAt.IsZero() {
		row.LeaseExpiry = task5Ptr(update.LeaseExpiresAt)
	}
	if update.PrincipalID != "" {
		row.ResolutionPrincipal = update.PrincipalID
	}
	if update.Reason != "" {
		row.ResolutionReason = update.Reason
	}
	if !update.ResolutionAt.IsZero() {
		row.ResolutionAt = task5Ptr(update.ResolutionAt)
	}
	if update.Status == InboxStatusFailed || update.Status == InboxStatusConfirmedConsumed || update.Status == InboxStatusSkipped {
		row.LeaseExpiry = nil
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ResolutionAt = task5Ptr(now)
	}
	q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, update.ExpectedVersion).Updates(inboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: update inbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, Version: row.Version}, nil
}

func (s *GORMStore) ResolveInbox(ctx context.Context, req InboxResolutionRequest) (CommitResult, error) {
	if req.Resolution != InboxResolutionConfirmedConsumed && req.Resolution != InboxResolutionRetry && req.Resolution != InboxResolutionSkip {
		return CommitResult{}, ErrInvalidTransition
	}
	return s.resolveInboxTx(ctx, req, time.Time{})
}

func (s *GORMStore) resolveInboxTx(ctx context.Context, req InboxResolutionRequest, resolutionAt time.Time) (result CommitResult, err error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row inboxMessageRow
	q := locked(tx).Where("inbox_id = ?", req.InboxID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, ErrNotFound
	}
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: load inbox failed")
	}
	if req.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if !inboxUnresolved(row.Status) {
		if req.Resolution == InboxResolutionConfirmedConsumed && row.Status == InboxStatusConfirmedConsumed {
			return CommitResult{InboxIDs: []string{row.InboxID}, Version: row.Version, Idempotent: true}, task5Commit(tx)
		}
		return CommitResult{}, ErrInvalidTransition
	}
	now := s.task5Now()
	if resolutionAt.IsZero() {
		resolutionAt = now
	}
	if req.Resolution == InboxResolutionRetry {
		if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
			if e := task5ScrubInbox(tx, &row, now, false); e != nil {
				return CommitResult{}, e
			}
			if e := task5Commit(tx); e != nil {
				return CommitResult{}, e
			}
			return CommitResult{}, ErrPayloadExpired
		}
		row.Status = InboxStatusPending
	} else if req.Resolution == InboxResolutionConfirmedConsumed {
		row.Status = InboxStatusConfirmedConsumed
	} else {
		row.Status = InboxStatusSkipped
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return CommitResult{}, e
	}
	row.Version = version
	row.ResolutionPrincipal = req.PrincipalID
	row.ResolutionReason = req.Reason
	row.ResolutionAt = task5Ptr(resolutionAt)
	row.LeaseExpiry = nil
	if row.Status != InboxStatusPending {
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.CompletedAt = task5Ptr(now)
	}
	q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, req.ExpectedVersion).Updates(inboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: resolve inbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, Version: row.Version}, nil
}

func (s *GORMStore) AcceptOutbox(ctx context.Context, effect NewEffect) (result CommitResult, err error) {
	if effect.EffectID == "" {
		effect.EffectID, err = s.task5ID()
		if err != nil {
			return CommitResult{}, err
		}
	}
	if effect.EndpointID == "" || len(effect.LaneHMAC) == 0 || effect.EffectType == "" || len(effect.PayloadCiphertext) == 0 || len(effect.PayloadNonce) == 0 {
		return CommitResult{}, ErrParticipantFailure
	}
	if !validRisk(effect.RiskClass) {
		return CommitResult{}, ErrInvalidRiskClass
	}
	if effect.Status == "" {
		effect.Status = OutboxStatusPending
	}
	if effect.Status != OutboxStatusPending {
		return CommitResult{}, ErrInvalidTransition
	}
	if effect.PayloadExpiresAt.IsZero() {
		effect.PayloadExpiresAt = s.task5Now().Add(InboxPayloadTTL)
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	seq, err := task5AllocateLane(tx, outboxLaneKind, effect.LaneHMAC, now)
	if err != nil {
		return CommitResult{}, err
	}
	row := outboxEffectRow{EffectID: effect.EffectID, Version: 1, EndpointID: effect.EndpointID, LaneHMAC: task5Copy(effect.LaneHMAC), OrderingSequence: seq, EffectClass: effect.EffectType, RiskClass: effect.RiskClass, Status: OutboxStatusPending, PayloadCiphertext: task5Copy(effect.PayloadCiphertext), PayloadNonce: task5Copy(effect.PayloadNonce), EncryptionKeyID: effect.DigestKeyID, ContentDigest: task5Copy(effect.ContentDigest), ContentDigestKeyID: effect.DigestKeyID, DeadlineAt: task5Ptr(effect.DeadlineAt), NextAttemptAt: task5Ptr(effect.NextAttemptAt), PayloadExpiresAt: task5Ptr(effect.PayloadExpiresAt), CreatedAt: now}
	if err = tx.Create(&row).Error; err != nil {
		return CommitResult{}, errors.New("eventstore: insert outbox failed")
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, OrderingSequence: seq, Version: 1}, nil
}

func (s *GORMStore) ClaimOutbox(ctx context.Context, req OutboxClaimRequest) (lease OutboxLease, err error) {
	if strings.TrimSpace(req.WorkerID) == "" {
		return OutboxLease{}, ErrParticipantFailure
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	var row outboxEffectRow
	q := locked(tx).Where("((status = ? AND (next_attempt_at IS NULL OR next_attempt_at <= ?)) OR (status = ? AND (lease_expiry IS NULL OR lease_expiry <= ?)) OR (status = ? AND lease_expiry IS NOT NULL AND lease_expiry <= ?))", OutboxStatusPending, now, OutboxStatusLeased, now, OutboxStatusDispatched, now).Where("NOT EXISTS (SELECT 1 FROM outbox_effects p WHERE p.lane_hmac = outbox_effects.lane_hmac AND p.ordering_sequence < outbox_effects.ordering_sequence AND p.status IN ?)", []string{OutboxStatusPending, OutboxStatusLeased, OutboxStatusDispatched, OutboxStatusAmbiguous}).Order("ordering_sequence ASC").First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return OutboxLease{}, ErrNotFound
	}
	if q.Error != nil {
		return OutboxLease{}, errors.New("eventstore: claim outbox query failed")
	}
	if (row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched) && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now) && row.DispatchedAt != nil && row.RiskClass != RiskProviderIdempotent {
		version, vErr := nextVersion(row.Version)
		if vErr != nil {
			return OutboxLease{}, vErr
		}
		row.Status, row.Version, row.ResolutionReason, row.ResolutionAt, row.LeaseExpiry = OutboxStatusAmbiguous, version, "expired-after-dispatch", task5Ptr(now), nil
		q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, version-1).Updates(outboxMap(row))
		if q.Error != nil || q.RowsAffected != 1 {
			return OutboxLease{}, ErrStaleLease
		}
		if err = task5Commit(tx); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrNotFound
	}
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5Commit(tx); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrPayloadExpired
	}
	if row.LeaseEpoch == maxUint64 {
		return OutboxLease{}, ErrVersionExhausted
	}
	attempt, idErr := s.task5ID()
	if idErr != nil {
		return OutboxLease{}, idErr
	}
	version, vErr := nextVersion(row.Version)
	if vErr != nil {
		return OutboxLease{}, vErr
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	retry := row.RetryCount
	if row.Status == OutboxStatusLeased && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now) {
		if retry < math.MaxUint32 {
			retry++
		}
	}
	updates := map[string]any{"status": OutboxStatusLeased, "version": version, "lease_owner": req.WorkerID, "lease_epoch": row.LeaseEpoch + 1, "lease_expiry": expires, "attempt_id": attempt, "retry_count": retry}
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, row.Version).Updates(updates)
	if q.Error != nil {
		return OutboxLease{}, errors.New("eventstore: claim outbox failed")
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, ErrStaleLease
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID, row.RetryCount = OutboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt, retry
	lease.Effect = effectFromRow(row)
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) UpdateOutbox(ctx context.Context, effect NewEffect) (result CommitResult, err error) {
	if effect.EffectID == "" || !validOutboxStatus(effect.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row outboxEffectRow
	q := locked(tx).Where("effect_id = ?", effect.EffectID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, ErrNotFound
	}
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: load outbox failed")
	}
	if effect.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableOutboxEffects)
	}
	if !outboxTransitionAllowed(row.Status, effect.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if effect.RiskClass != "" && !validRisk(effect.RiskClass) {
		return CommitResult{}, ErrInvalidRiskClass
	}
	if row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, effect.LeaseOwner, effect.LeaseEpoch, effect.AttemptID) {
			return CommitResult{}, ErrStaleLease
		}
	}
	now := s.task5Now()
	version, err := nextVersion(row.Version)
	if err != nil {
		return CommitResult{}, err
	}
	row.Status = effect.Status
	row.Version = version
	if effect.ResultCode != "" {
		row.ResultCode = effect.ResultCode
	}
	if effect.ErrorCode != "" {
		row.ErrorCode = effect.ErrorCode
	}
	if effect.ProviderMessageID != "" {
		row.ProviderMessageID = effect.ProviderMessageID
	}
	if effect.RiskClass != "" {
		row.RiskClass = effect.RiskClass
	}
	if effect.Status == OutboxStatusDispatched && row.DispatchedAt == nil {
		row.DispatchedAt = task5Ptr(now)
	}
	if effect.Status == OutboxStatusFailed || effect.Status == OutboxStatusSucceeded {
		row.CompletedAt = task5Ptr(now)
		row.LeaseExpiry = nil
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ScrubbedAt = task5Ptr(now)
	}
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, effect.ExpectedVersion).Updates(outboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: update outbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func (s *GORMStore) RenewOutbox(ctx context.Context, req OutboxRenewRequest) (OutboxLease, error) {
	return s.renewOutbox(ctx, req)
}
func (s *GORMStore) RenewOutboxLease(ctx context.Context, req OutboxRenewRequest) (OutboxLease, error) {
	return s.RenewOutbox(ctx, req)
}
func (s *GORMStore) renewOutbox(ctx context.Context, req OutboxRenewRequest) (lease OutboxLease, err error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row outboxEffectRow
	q := locked(tx).Where("effect_id = ?", req.EffectID).First(&row)
	if q.Error != nil {
		return OutboxLease{}, ErrStaleLease
	}
	if row.Status != OutboxStatusLeased || !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) {
		return OutboxLease{}, ErrStaleLease
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return OutboxLease{}, e
	}
	expires := s.task5Now().Add(task5LeaseDuration(req.LeaseDuration))
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ?", req.EffectID, row.Version, req.WorkerID, req.LeaseEpoch, req.AttemptID).Updates(map[string]any{"version": version, "lease_expiry": expires})
	if q.Error != nil {
		return OutboxLease{}, errors.New("eventstore: renew outbox failed")
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, ErrStaleLease
	}
	row.Version, row.LeaseExpiry = version, &expires
	lease.Effect = effectFromRow(row)
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) MarkOutboxDispatched(ctx context.Context, req OutboxDispatchRequest) (lease OutboxLease, err error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row outboxEffectRow
	q := locked(tx).Where("effect_id = ?", req.EffectID).First(&row)
	if q.Error != nil {
		return OutboxLease{}, ErrStaleLease
	}
	if row.Status != OutboxStatusLeased || !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) {
		return OutboxLease{}, ErrStaleLease
	}
	newAttempt, idErr := s.task5ID()
	if idErr != nil {
		return OutboxLease{}, idErr
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return OutboxLease{}, e
	}
	now := s.task5Now()
	row.Status, row.Version, row.AttemptID, row.DispatchedAt = OutboxStatusDispatched, version, newAttempt, &now
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ?", req.EffectID, reqVersion(row.Version), req.WorkerID, req.LeaseEpoch, req.AttemptID).Updates(map[string]any{"status": row.Status, "version": row.Version, "attempt_id": row.AttemptID, "dispatched_at": row.DispatchedAt})
	if q.Error != nil {
		return OutboxLease{}, errors.New("eventstore: dispatch marker failed")
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, ErrStaleLease
	}
	lease.Effect = effectFromRow(row)
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func reqVersion(v uint64) uint64 {
	if v == 0 {
		return 0
	}
	return v - 1
}

func (s *GORMStore) CompleteOutbox(ctx context.Context, req OutboxCompletionRequest) (result CommitResult, err error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row outboxEffectRow
	q := locked(tx).Where("effect_id = ?", req.EffectID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, ErrNotFound
	}
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: load outbox failed")
	}
	if !validOutboxStatus(req.Status) || req.Status == OutboxStatusPending || req.Status == OutboxStatusLeased || req.Status == OutboxStatusDispatched || req.Status == OutboxStatusAmbiguous {
		return CommitResult{}, ErrInvalidTransition
	}
	if row.Status == req.Status && row.ResultCode == req.ResultCode && row.ErrorCode == req.ErrorCode && row.ProviderMessageID == req.ProviderMessageID {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) {
			return CommitResult{}, ErrStaleLease
		}
		return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version, Idempotent: true}, task5Commit(tx)
	}
	if row.Status != OutboxStatusLeased && row.Status != OutboxStatusDispatched {
		return CommitResult{}, ErrStaleLease
	}
	if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) {
		return CommitResult{}, ErrStaleLease
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return CommitResult{}, e
	}
	now := s.task5Now()
	row.Status, row.Version, row.ResultCode, row.ErrorCode, row.ProviderMessageID, row.CompletedAt, row.LeaseExpiry = req.Status, version, req.ResultCode, req.ErrorCode, req.ProviderMessageID, &now, nil
	row.PayloadCiphertext = nil
	row.ScrubbedAt = task5Ptr(now)
	row.PayloadNonce = nil
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ?", row.EffectID, reqVersion(row.Version), req.WorkerID, req.LeaseEpoch, req.AttemptID).Updates(outboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: complete outbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}
func (s *GORMStore) DispatchOutbox(ctx context.Context, req OutboxDispatchRequest) (OutboxLease, error) {
	return s.MarkOutboxDispatched(ctx, req)
}

func (s *GORMStore) ResolveOutbox(ctx context.Context, req OutboxResolutionRequest) (result CommitResult, err error) {
	if req.Resolution != OutboxResolutionRetry && req.Resolution != OutboxResolutionSucceeded && req.Resolution != OutboxResolutionFailed {
		return CommitResult{}, ErrInvalidTransition
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row outboxEffectRow
	q := locked(tx).Where("effect_id = ?", req.EffectID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, ErrNotFound
	}
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: load outbox failed")
	}
	if req.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableOutboxEffects)
	}
	if !outboxUnresolved(row.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	now := s.task5Now()
	if req.Resolution == OutboxResolutionRetry {
		if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
			if e := task5ScrubOutbox(tx, &row, now); e != nil {
				return CommitResult{}, e
			}
			if e := task5Commit(tx); e != nil {
				return CommitResult{}, e
			}
			return CommitResult{}, ErrPayloadExpired
		}
		row.Status = OutboxStatusPending
	} else if req.Resolution == OutboxResolutionSucceeded {
		row.Status = OutboxStatusSucceeded
	} else {
		row.Status = OutboxStatusFailed
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return CommitResult{}, e
	}
	row.Version = version
	row.ResolutionPrincipal = req.PrincipalID
	row.ResolutionReason = req.Reason
	row.ResolutionAt = task5Ptr(now)
	row.LeaseExpiry = nil
	if row.Status != OutboxStatusPending {
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ScrubbedAt = task5Ptr(now)
		row.CompletedAt = task5Ptr(now)
	}
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, req.ExpectedVersion).Updates(outboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: resolve outbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func task5LeaseMatches(owner string, epoch uint64, attempt, wantOwner string, wantEpoch uint64, wantAttempt string) bool {
	return owner != "" && attempt != "" && owner == wantOwner && epoch == wantEpoch && attempt == wantAttempt
}
func participantConflict(table string) error {
	return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: "<redacted>"}}}
}

func task5ScrubInbox(tx *gorm.DB, row *inboxMessageRow, now time.Time, terminal bool) error {
	row.PayloadCiphertext = nil
	row.PayloadNonce = nil
	if terminal {
		row.ResolutionReason = "payload-expired"
		row.ResolutionAt = task5Ptr(now)
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return e
	}
	row.Version = version
	q := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, version-1).Updates(inboxMap(*row))
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrStaleLease
	}
	return nil
}
func task5ScrubOutbox(tx *gorm.DB, row *outboxEffectRow, now time.Time) error {
	row.PayloadCiphertext = nil
	row.PayloadNonce = nil
	row.ScrubbedAt = task5Ptr(now)
	row.ResolutionReason = "payload-expired"
	row.ResolutionAt = task5Ptr(now)
	version, e := nextVersion(row.Version)
	if e != nil {
		return e
	}
	row.Version = version
	q := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, version-1).Updates(outboxMap(*row))
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrStaleLease
	}
	return nil
}

func inboxMap(row inboxMessageRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "attempt_id": row.AttemptID, "callback_started_at": row.CallbackStartedAt, "completed_at": row.CompletedAt, "payload_ciphertext": row.PayloadCiphertext, "payload_nonce": row.PayloadNonce, "encryption_key_id": row.EncryptionKeyID, "content_digest": row.ContentDigest, "content_digest_key_id": row.ContentDigestKeyID, "payload_expires_at": row.PayloadExpiresAt, "workflow_id": row.WorkflowID, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}
func outboxMap(row outboxEffectRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "attempt_id": row.AttemptID, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "dispatched_at": row.DispatchedAt, "deadline_at": row.DeadlineAt, "next_attempt_at": row.NextAttemptAt, "payload_ciphertext": row.PayloadCiphertext, "payload_nonce": row.PayloadNonce, "encryption_key_id": row.EncryptionKeyID, "content_digest": row.ContentDigest, "content_digest_key_id": row.ContentDigestKeyID, "result_code": row.ResultCode, "error_code": row.ErrorCode, "provider_message_id": row.ProviderMessageID, "completed_at": row.CompletedAt, "payload_expires_at": row.PayloadExpiresAt, "retry_count": row.RetryCount, "scrubbed_at": row.ScrubbedAt, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}

func inboxUpdateFromRow(row inboxMessageRow) InboxUpdate {
	return InboxUpdate{InboxID: row.InboxID, ExpectedVersion: row.Version, Version: row.Version, EndpointID: row.EndpointID, ProviderEventKey: row.ProviderEventKey, LaneHMAC: task5Copy(row.LaneHMAC), OrderingSequence: row.OrderingSequence, Status: row.Status, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch, LeaseExpiresAt: valueTime(row.LeaseExpiry), AttemptID: row.AttemptID, PayloadCiphertext: task5Copy(row.PayloadCiphertext), PayloadNonce: task5Copy(row.PayloadNonce), ContentDigest: task5Copy(row.ContentDigest), DigestKeyID: row.ContentDigestKeyID, WorkflowID: row.WorkflowID, CallbackStartedAt: valueTime(row.CallbackStartedAt), CompletedAt: valueTime(row.CompletedAt), PayloadExpiresAt: valueTime(row.PayloadExpiresAt), PrincipalID: row.ResolutionPrincipal, Reason: row.ResolutionReason, ResolutionAt: valueTime(row.ResolutionAt)}
}
func effectFromRow(row outboxEffectRow) NewEffect {
	return NewEffect{EffectID: row.EffectID, ExpectedVersion: row.Version, Version: row.Version, EndpointID: row.EndpointID, LaneHMAC: task5Copy(row.LaneHMAC), OrderingSequence: row.OrderingSequence, EffectType: row.EffectClass, RiskClass: row.RiskClass, Status: row.Status, AttemptID: row.AttemptID, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch, LeaseExpiresAt: valueTime(row.LeaseExpiry), DeadlineAt: valueTime(row.DeadlineAt), NextAttemptAt: valueTime(row.NextAttemptAt), DispatchedAt: valueTime(row.DispatchedAt), PayloadCiphertext: task5Copy(row.PayloadCiphertext), PayloadNonce: task5Copy(row.PayloadNonce), ContentDigest: task5Copy(row.ContentDigest), DigestKeyID: row.ContentDigestKeyID, ProviderMessageID: row.ProviderMessageID, ResultCode: row.ResultCode, ErrorCode: row.ErrorCode, CompletedAt: valueTime(row.CompletedAt), PayloadExpiresAt: valueTime(row.PayloadExpiresAt), RetryCount: row.RetryCount, PrincipalID: row.ResolutionPrincipal, Reason: row.ResolutionReason, ResolutionAt: valueTime(row.ResolutionAt)}
}
func valueTime(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.UTC()
}

func sealPayload(ctx context.Context, codec any, plaintext []byte) ([]byte, []byte, string, error) {
	if codec == nil {
		return nil, nil, "", ErrEncryptionUnavailable
	}
	if c, ok := codec.(PayloadCodec); ok {
		return c.Encrypt(ctx, plaintext)
	}
	if c, ok := codec.(interface {
		Seal(context.Context, []byte) ([]byte, []byte, string, error)
	}); ok {
		return c.Seal(ctx, plaintext)
	}
	if c, ok := codec.(interface {
		Encrypt([]byte) ([]byte, []byte, string, error)
	}); ok {
		return c.Encrypt(plaintext)
	}
	if c, ok := codec.(interface {
		Seal([]byte) ([]byte, []byte, string, error)
	}); ok {
		return c.Seal(plaintext)
	}
	return nil, nil, "", ErrEncryptionUnavailable
}
func openPayload(ctx context.Context, codec any, ciphertext, nonce []byte, keyID string) ([]byte, error) {
	if codec == nil {
		return nil, ErrEncryptionUnavailable
	}
	if c, ok := codec.(PayloadCodec); ok {
		return c.Decrypt(ctx, ciphertext, nonce, keyID)
	}
	if c, ok := codec.(interface {
		Open(context.Context, []byte, []byte, string) ([]byte, error)
	}); ok {
		return c.Open(ctx, ciphertext, nonce, keyID)
	}
	if c, ok := codec.(interface {
		Decrypt([]byte, []byte, string) ([]byte, error)
	}); ok {
		return c.Decrypt(ciphertext, nonce, keyID)
	}
	if c, ok := codec.(interface {
		Open([]byte, []byte, string) ([]byte, error)
	}); ok {
		return c.Open(ciphertext, nonce, keyID)
	}
	return nil, ErrEncryptionUnavailable
}
func (s *GORMStore) PutArtifact(ctx context.Context, req ArtifactPutRequest) (result ArtifactPutResult, err error) {
	if len(req.Plaintext) > MaxArtifactBytes {
		return ArtifactPutResult{}, &OversizeError{Bound: "artifact bytes", Limit: MaxArtifactBytes, Actual: len(req.Plaintext)}
	}
	if req.OperationID == "" {
		return ArtifactPutResult{}, ErrParticipantFailure
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultArtifactTTL
	}
	if ttl < 0 || ttl > MaxArtifactTTL {
		return ArtifactPutResult{}, ErrInvalidTTL
	}
	ciphertext, nonce, keyID, err := sealPayload(ctx, s.codec, req.Plaintext)
	if err != nil {
		return ArtifactPutResult{}, ErrEncryptionUnavailable
	}
	if len(ciphertext) == 0 || len(nonce) == 0 || keyID == "" {
		return ArtifactPutResult{}, ErrEncryptionUnavailable
	}
	if req.ArtifactID == "" {
		req.ArtifactID, err = s.task5ID()
		if err != nil {
			return ArtifactPutResult{}, err
		}
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactPutResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactPutResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	expires := now.Add(ttl)
	row := operationArtifactRow{ArtifactID: req.ArtifactID, Version: 1, OperationID: req.OperationID, OwnerPrincipalID: req.OwnerPrincipalID, MediaType: req.MediaType, SafeFilename: req.SafeFilename, Size: int64(len(req.Plaintext)), Status: "available", Ciphertext: task5Copy(ciphertext), Nonce: task5Copy(nonce), EncryptionKeyID: keyID, ExpiresAt: expires}
	if row.OwnerPrincipalID == "" {
		row.OwnerPrincipalID = "unknown"
	}
	if row.MediaType == "" {
		row.MediaType = "application/octet-stream"
	}
	if err = tx.Create(&row).Error; err != nil {
		return ArtifactPutResult{}, errors.New("eventstore: insert artifact failed")
	}
	if err = task5Commit(tx); err != nil {
		return ArtifactPutResult{}, err
	}
	return ArtifactPutResult{ArtifactID: row.ArtifactID, Version: 1, Size: row.Size, ExpiresAt: expires}, nil
}

func (s *GORMStore) ConsumeArtifact(ctx context.Context, req ArtifactConsumeRequest) (result ArtifactResult, err error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row operationArtifactRow
	q := locked(tx).Where("artifact_id = ?", req.ArtifactID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return ArtifactResult{}, ErrArtifactGone
	}
	if q.Error != nil {
		return ArtifactResult{}, errors.New("eventstore: load artifact failed")
	}
	now := s.task5Now()
	if row.Status != "available" || !row.ExpiresAt.After(now) || len(row.Ciphertext) == 0 || len(row.Nonce) == 0 {
		row.Status = "expired"
		if row.ExpiresAt.After(now) && len(row.Ciphertext) > 0 && len(row.Nonce) > 0 {
			row.Status = "consumed"
		}
		row.Ciphertext = nil
		row.Nonce = nil
		row.ConsumedAt = task5Ptr(now)
		version, e := nextVersion(row.Version)
		if e != nil {
			return ArtifactResult{}, e
		}
		row.Version = version
		q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, version-1).Updates(map[string]any{"version": row.Version, "status": row.Status, "ciphertext": nil, "nonce": nil, "consumed_at": row.ConsumedAt})
		if q.Error != nil || q.RowsAffected != 1 {
			return ArtifactResult{}, ErrStaleLease
		}
		if err = task5Commit(tx); err != nil {
			return ArtifactResult{}, err
		}
		return ArtifactResult{}, ErrArtifactGone
	}
	plaintext, openErr := openPayload(ctx, s.codec, row.Ciphertext, row.Nonce, row.EncryptionKeyID)
	if openErr != nil {
		return ArtifactResult{}, ErrEncryptionUnavailable
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return ArtifactResult{}, e
	}
	row.Status = "consumed"
	row.Version = version
	row.ConsumedAt = task5Ptr(now)
	row.Ciphertext = nil
	row.Nonce = nil
	q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, version-1).Updates(map[string]any{"version": row.Version, "status": row.Status, "ciphertext": nil, "nonce": nil, "consumed_at": row.ConsumedAt})
	if q.Error != nil || q.RowsAffected != 1 {
		return ArtifactResult{}, ErrStaleLease
	}
	result = ArtifactResult{ArtifactID: row.ArtifactID, OperationID: row.OperationID, OwnerPrincipalID: row.OwnerPrincipalID, MediaType: row.MediaType, SafeFilename: row.SafeFilename, Size: row.Size, Plaintext: task5Copy(plaintext), ExpiresAt: row.ExpiresAt, ConsumedAt: now}
	if err = task5Commit(tx); err != nil {
		return ArtifactResult{}, err
	}
	return result, nil
}

var _ InboxRepository = (*GORMStore)(nil)
var _ OutboxRepository = (*GORMStore)(nil)
var _ ArtifactRepository = (*GORMStore)(nil)
