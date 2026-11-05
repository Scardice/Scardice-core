package eventstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	sealdicelogger "Scardice-core/logger"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type task5QueueFailure struct {
	queue     string
	itemID    string
	status    string
	reason    string
	errorCode string
	version   uint64
}

func task5LogQueueFailures(failures []task5QueueFailure) {
	for _, failure := range failures {
		if failure.itemID == "" {
			continue
		}
		sealdicelogger.QueueFailures().Warnw(
			"queue item isolated",
			"queue", failure.queue,
			"item_id", failure.itemID,
			"status", failure.status,
			"reason", failure.reason,
			"error_code", failure.errorCode,
			"version", failure.version,
		)
	}
}

const (
	inboxLaneKind               = "inbox"
	outboxLaneKind              = "outbox"
	defaultLeaseDuration        = time.Minute
	task5PayloadLimit           = 2 * 1024 * 1024
	task5InboxRecoveryBatchSize = 128
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
	return "", ErrParticipantFailure
}

func task5Ptr(v time.Time) *time.Time {
	if v.IsZero() {
		return nil
	}
	v = v.UTC()
	return &v
}

func task5InboxDuplicate(row inboxMessageRow, update InboxUpdate) bool {
	if row.EndpointID != update.EndpointID || row.ProviderEventKey != update.ProviderEventKey || row.Lane != update.Lane || row.Subject != update.Subject {
		return false
	}
	if len(update.ContentDigest) > 0 {
		return bytes.Equal(row.ContentDigest, update.ContentDigest)
	}
	return bytes.Equal(row.Payload, update.Payload)
}
func task5EffectDuplicate(row outboxEffectRow, update NewEffect) bool {
	return row.EndpointID == update.EndpointID && row.Lane == update.Lane && row.Subject == update.Subject && row.EffectClass == update.EffectType && row.RiskClass == update.RiskClass && bytes.Equal(row.Payload, update.Payload)
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

func task5CommitQueueFailures(tx *gorm.DB, failures []task5QueueFailure) error {
	if err := task5Commit(tx); err != nil {
		return err
	}
	task5LogQueueFailures(failures)
	return nil
}

func task5Rollback(tx *gorm.DB) {
	if tx != nil {
		_ = tx.Rollback().Error
	}
}

func task5RejectQueueCandidate(tx *gorm.DB, kind, lane string, now time.Time, failures []task5QueueFailure, _ bool) error {
	if err := refreshQueueLane(tx, kind, lane, now); err != nil {
		return err
	}
	if err := task5CommitQueueFailures(tx, failures); err != nil {
		return err
	}
	return ErrNotFound
}

func task5Lane(tx *gorm.DB, kind, lane string, now time.Time) (laneHeadRow, error) {
	var head laneHeadRow
	err := laneQuery(locked(tx), kind, lane).Take(&head).Error
	if err == nil {
		return head, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return laneHeadRow{}, ErrParticipantFailure
	}
	// A raw lane can exceed every backend's btree key bound. Serialize creation
	// with the existing publication singleton, then compare raw identities again.
	if err := lockPublication(tx); err != nil {
		return laneHeadRow{}, err
	}
	err = laneQuery(locked(tx), kind, lane).Take(&head).Error
	if err == nil {
		return head, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return laneHeadRow{}, ErrParticipantFailure
	}
	head = laneHeadRow{Kind: kind, Lane: lane, NextSequence: 1, SchedulingVersion: queueSchedulingVersion, UpdatedAt: now}
	if err := tx.Create(&head).Error; err != nil {
		return laneHeadRow{}, ErrParticipantFailure
	}
	return head, nil
}

func task5AllocateLane(tx *gorm.DB, kind, lane string, now time.Time) (uint64, uint64, error) {
	head, err := task5Lane(tx, kind, lane, now)
	if err != nil {
		return 0, 0, err
	}
	sequence := head.NextSequence
	if sequence == 0 || sequence >= maxPersistedVersion {
		return 0, 0, ErrVersionExhausted
	}
	nextSequence, err := nextVersion(sequence)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Model(&laneHeadRow{}).Where("id = ?", head.ID).Updates(map[string]any{"next_sequence": nextSequence, "updated_at": now}).Error; err != nil {
		return 0, 0, ErrParticipantFailure
	}
	return sequence, head.ID, nil
}

func validInboxStatus(v string) bool {
	switch v {
	case InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous, InboxStatusConfirmedConsumed, InboxStatusFailed, InboxStatusSkipped:
		return true
	}
	return false
}
func validInboxWorkflowID(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 255 || strings.Contains(value, "$t") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
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
		return to == InboxStatusAmbiguous || to == InboxStatusConfirmedConsumed
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
	if err = s.requireReady(ctx); err != nil {
		return CommitResult{}, err
	}
	defer func() {
		if err == nil && len(result.InboxIDs) > 0 {
			s.signalInboxWork()
		}
	}()
	if update.InboxID == "" {
		update.InboxID, err = s.task5ID()
		if err != nil {
			return CommitResult{}, err
		}
	}
	if update.ExpectedVersion != 0 || update.Version != 0 {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.EndpointID == "" || update.ProviderEventKey == "" || update.Lane == "" || len(update.Payload) > task5PayloadLimit {
		return CommitResult{}, ErrInvalidMetadata
	}
	if update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() || update.WorkflowID != "" {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Status == "" {
		update.Status = InboxStatusPending
	}
	if update.Status != InboxStatusPending {
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
	if err = s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var existing inboxMessageRow
	query := inboxProviderQuery(locked(tx), update.EndpointID, update.ProviderEventKey).First(&existing)
	if query.Error == nil {
		if !task5InboxDuplicate(existing, update) {
			return CommitResult{}, ErrConflict
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{InboxIDs: []string{existing.InboxID}, OrderingSequence: existing.OrderingSequence, Version: existing.Version, Deduplicated: true, Idempotent: true}, nil
	}
	if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, errors.New("eventstore: dedupe lookup failed")
	}
	now := s.task5Now()
	sequence, laneID, err := task5AllocateLane(tx, inboxLaneKind, update.Lane, now)
	if err != nil {
		return CommitResult{}, err
	}
	row := inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, Lane: update.Lane, LaneID: laneID, Subject: update.Subject, OrderingSequence: sequence, Status: InboxStatusPending, Version: 1, Payload: bytes.Clone(update.Payload), ContentDigest: bytes.Clone(update.ContentDigest)}
	if err = tx.Create(&row).Error; err != nil {
		return CommitResult{}, ErrParticipantConflict
	}
	if err = refreshQueueLane(tx, inboxLaneKind, row.Lane, now); err != nil {
		return CommitResult{}, err
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	result = CommitResult{InboxIDs: []string{row.InboxID}, OrderingSequence: sequence, Version: row.Version}
	return result, nil
}

func task5RecoverExpiredInboxCallbacks(tx *gorm.DB, now time.Time) ([]task5QueueFailure, error) {
	var candidates []struct {
		InboxID string `gorm:"column:inbox_id"`
	}
	if err := tx.Model(&laneHeadRow{}).Select("active_id AS inbox_id").
		Where("kind = ? AND ready_action = ? AND ready_at IS NOT NULL AND ready_at <= ?", inboxLaneKind, queueReadyActionRecover, now).
		Order("ready_at ASC").Order("active_since ASC").Order("id ASC").
		Limit(task5InboxRecoveryBatchSize).Scan(&candidates).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	var failures []task5QueueFailure
	for _, candidate := range candidates {
		var row inboxMessageRow
		query := locked(tx).Select("inbox_id", "lane", "version", "status", "lease_expiry").Where("inbox_id = ?", candidate.InboxID).Take(&row)
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if query.Error != nil {
			return nil, ErrParticipantFailure
		}
		if row.Status != InboxStatusCallbackStarted || row.LeaseExpiry == nil || row.LeaseExpiry.After(now) {
			continue
		}
		version, err := nextVersion(row.Version)
		if err != nil {
			return nil, err
		}
		query = tx.Model(&inboxMessageRow{}).
			Where("inbox_id = ? AND version = ? AND status = ? AND lease_expiry IS NOT NULL AND lease_expiry <= ?", row.InboxID, row.Version, InboxStatusCallbackStarted, now).
			Updates(map[string]any{
				"status": InboxStatusAmbiguous, "version": version, "lease_expiry": nil,
				"completed_at": now, "resolution_at": now, "resolution_reason": "callback-lease-expired",
			})
		if query.Error != nil {
			return nil, ErrParticipantFailure
		}
		if query.RowsAffected != 1 {
			return nil, ErrStaleLease
		}
		if err := refreshQueueLane(tx, inboxLaneKind, row.Lane, now); err != nil {
			return nil, err
		}
		failures = append(failures, task5QueueFailure{
			queue: inboxLaneKind, itemID: row.InboxID, status: InboxStatusAmbiguous,
			reason: "callback-lease-expired", version: version,
		})
	}
	return failures, nil
}

func (s *GORMStore) ClaimInbox(ctx context.Context, req InboxClaimRequest) (InboxLease, error) {
	return s.claimInbox(ctx, req, true)
}

func (s *GORMStore) claimInbox(ctx context.Context, req InboxClaimRequest, retryAfterMaintenance bool) (lease InboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return InboxLease{}, readyErr
	}
	if strings.TrimSpace(req.WorkerID) == "" {
		return InboxLease{}, ErrParticipantFailure
	}
	now := s.task5Now()
	base, err := s.task5Base(ctx)
	if err != nil {
		return InboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return InboxLease{}, err
	}
	if err = s.lockParticipantPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return InboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	if retryAfterMaintenance {
		failures, recoveryErr := task5RecoverExpiredInboxCallbacks(tx, now)
		if recoveryErr != nil {
			return InboxLease{}, recoveryErr
		}
		if len(failures) > 0 {
			if err = task5CommitQueueFailures(tx, failures); err != nil {
				return InboxLease{}, err
			}
			s.signalInboxWork()
			return s.claimInbox(ctx, req, false)
		}
	}
	var candidate struct {
		InboxID string `gorm:"column:inbox_id"`
	}
	q := scanInboxClaimable(tx, now, &candidate)
	if q.Error != nil {
		return InboxLease{}, errors.New("eventstore: claim inbox query failed")
	}
	if q.RowsAffected == 0 {
		return InboxLease{}, ErrNotFound
	}
	var row inboxMessageRow
	if err = locked(tx).Where("inbox_id = ?", candidate.InboxID).First(&row).Error; err != nil {
		return InboxLease{}, ErrNotFound
	}
	if row.Status != InboxStatusPending && row.Status != InboxStatusLeased {
		return InboxLease{}, task5RejectQueueCandidate(tx, inboxLaneKind, row.Lane, now, nil, retryAfterMaintenance)
	}
	if row.Status == InboxStatusLeased && row.LeaseExpiry != nil && row.LeaseExpiry.After(now) {
		return InboxLease{}, ErrStaleLease
	}
	if row.LeaseEpoch >= maxPersistedVersion {
		return InboxLease{}, ErrVersionExhausted
	}
	attempt, err := s.task5ID()
	if err != nil {
		return InboxLease{}, err
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	version, err := nextVersion(row.Version)
	if err != nil {
		return InboxLease{}, err
	}
	query := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ? AND status = ?", row.InboxID, row.Version, row.Status)
	if row.Status == InboxStatusLeased {
		query = query.Where("lease_expiry IS NULL OR lease_expiry <= ?", now)
	}
	result, err := query.Updates(map[string]any{"status": InboxStatusLeased, "version": version, "lease_owner": req.WorkerID, "lease_epoch": row.LeaseEpoch + 1, "lease_expiry": expires, "attempt_id": attempt}).RowsAffected, query.Error
	if err != nil {
		return InboxLease{}, ErrParticipantFailure
	}
	if result != 1 {
		return InboxLease{}, ErrStaleLease
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID = InboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt
	lease.Update = inboxUpdateFromRow(row)
	if err = refreshQueueLane(tx, inboxLaneKind, row.Lane, now); err != nil {
		return InboxLease{}, err
	}
	if err = task5Commit(tx); err != nil {
		return InboxLease{}, err
	}
	return lease, nil
}
func (s *GORMStore) RenewInbox(ctx context.Context, req InboxRenewRequest) (lease InboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return InboxLease{}, readyErr
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return InboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return InboxLease{}, err
	}
	if lockErr := s.lockParticipantPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return InboxLease{}, lockErr
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row inboxMessageRow
	q := locked(tx).Where("inbox_id = ?", req.InboxID).First(&row)
	if q.Error != nil {
		return InboxLease{}, ErrStaleLease
	}
	now := s.task5Now()
	if (row.Status != InboxStatusLeased && row.Status != InboxStatusCallbackStarted) ||
		!task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) ||
		!task5LeaseActive(row.LeaseExpiry, now) {
		return InboxLease{}, ErrStaleLease
	}
	version, versionErr := nextVersion(row.Version)
	if versionErr != nil {
		return InboxLease{}, versionErr
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	q = tx.Model(&inboxMessageRow{}).
		Where("inbox_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ? AND lease_expiry > ?", req.InboxID, row.Version, req.WorkerID, req.LeaseEpoch, req.AttemptID, now).
		Updates(map[string]any{"version": version, "lease_expiry": expires})
	if q.Error != nil {
		return InboxLease{}, errors.New("eventstore: renew inbox failed")
	}
	if q.RowsAffected != 1 {
		return InboxLease{}, ErrStaleLease
	}
	row.Version, row.LeaseExpiry = version, &expires
	lease.Update = inboxUpdateFromRow(row)
	if err = refreshQueueLane(tx, inboxLaneKind, row.Lane, now); err != nil {
		return InboxLease{}, err
	}
	if err = task5Commit(tx); err != nil {
		return InboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) UpdateInbox(ctx context.Context, update InboxUpdate) (result CommitResult, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return CommitResult{}, readyErr
	}
	if update.InboxID == "" || !validInboxStatus(update.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Resolution != "" {
		if strings.TrimSpace(update.PrincipalID) == "" || strings.TrimSpace(update.Reason) == "" {
			return CommitResult{}, ErrInvalidMetadata
		}
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
	if lockErr := s.lockParticipantPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return CommitResult{}, lockErr
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
	now := s.task5Now()
	if update.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if update.Version != 0 && update.Version != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if row.Status == InboxStatusFailed || row.Status == InboxStatusConfirmedConsumed || row.Status == InboxStatusSkipped {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.EndpointID != "" || update.ProviderEventKey != "" || update.Lane != "" || update.OrderingSequence != 0 || len(update.Payload) > 0 || update.WorkflowID != "" || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || !update.ResolutionAt.IsZero() {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Status != InboxStatusLeased && update.Status != InboxStatusCallbackStarted && row.Status != InboxStatusLeased && row.Status != InboxStatusCallbackStarted && (update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero()) {
		return CommitResult{}, ErrStaleLease
	}
	allowsExpiredAmbiguous := task5AllowsExpiredAmbiguous(row, update)
	if update.Status != InboxStatusPending || row.Status != InboxStatusPending {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || (!task5LeaseActive(row.LeaseExpiry, now) && !allowsExpiredAmbiguous) {
			return CommitResult{}, ErrStaleLease
		}
	}
	if !inboxTransitionAllowed(row.Status, update.Status) {
		return CommitResult{}, ErrInvalidTransition
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
	if update.Status == InboxStatusFailed || update.Status == InboxStatusConfirmedConsumed || update.Status == InboxStatusSkipped || update.Status == InboxStatusAmbiguous {
		row.LeaseExpiry = nil
		row.CompletedAt = task5Ptr(now)
		row.ResolutionAt = task5Ptr(now)
	}
	updateQuery := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, update.ExpectedVersion)
	if !allowsExpiredAmbiguous {
		updateQuery = updateQuery.Where("(lease_expiry IS NULL OR lease_expiry > ?)", now)
	}
	q = updateQuery.Updates(inboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: update inbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = refreshQueueLane(tx, inboxLaneKind, row.Lane, now); err != nil {
		return CommitResult{}, err
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, Version: row.Version}, nil
}

func (s *GORMStore) ResolveInbox(ctx context.Context, req InboxResolutionRequest) (CommitResult, error) {
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
	}
	if req.Resolution != InboxResolutionConfirmedConsumed && req.Resolution != InboxResolutionRetry && req.Resolution != InboxResolutionSkip {
		return CommitResult{}, ErrInvalidTransition
	}
	if strings.TrimSpace(req.PrincipalID) == "" || strings.TrimSpace(req.Reason) == "" {
		return CommitResult{}, ErrInvalidMetadata
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
	if lockErr := s.lockParticipantPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return CommitResult{}, lockErr
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
	now := s.task5Now()
	if req.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if !inboxUnresolved(row.Status) {
		if req.Resolution == InboxResolutionConfirmedConsumed && row.Status == InboxStatusConfirmedConsumed {
			if err = task5Commit(tx); err != nil {
				return CommitResult{}, err
			}
			return CommitResult{InboxIDs: []string{row.InboxID}, Version: row.Version, Idempotent: true}, nil
		}
		return CommitResult{}, ErrInvalidTransition
	}
	if resolutionAt.IsZero() {
		resolutionAt = now
	}
	switch req.Resolution {
	case InboxResolutionRetry:
		row.Status = InboxStatusPending
	case InboxResolutionConfirmedConsumed:
		row.Status = InboxStatusConfirmedConsumed
	default:
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
	row.CompletedAt = task5Ptr(now)
	q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, req.ExpectedVersion).Updates(inboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: resolve inbox failed")
	}
	if err = refreshQueueLane(tx, inboxLaneKind, row.Lane, now); err != nil {
		return CommitResult{}, err
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, Version: row.Version}, nil
}

func (s *GORMStore) AcceptOutbox(ctx context.Context, effect NewEffect) (result CommitResult, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return CommitResult{}, readyErr
	}
	if effect.EffectID == "" {
		effect.EffectID, err = s.task5ID()
		if err != nil {
			return CommitResult{}, err
		}
	}
	if effect.ExpectedVersion != 0 || effect.Version != 0 {
		return CommitResult{}, ErrInvalidTransition
	}
	if effect.EndpointID == "" || effect.Lane == "" || effect.EffectType == "" || len(effect.Payload) > task5PayloadLimit {
		return CommitResult{}, ErrInvalidMetadata
	}
	if effect.LeaseOwner != "" || effect.LeaseEpoch != 0 || effect.AttemptID != "" || !effect.LeaseExpiresAt.IsZero() || !effect.DispatchedAt.IsZero() || !effect.CompletedAt.IsZero() || effect.ProviderMessageID != "" || effect.ResultCode != "" || effect.ErrorCode != "" || effect.RetryCount != 0 || effect.PrincipalID != "" || effect.Reason != "" || effect.Resolution != "" || !effect.ResolutionAt.IsZero() {
		return CommitResult{}, ErrInvalidTransition
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
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	if err = s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var existing outboxEffectRow
	query := locked(tx).Where("effect_id = ?", effect.EffectID).First(&existing)
	if query.Error == nil {
		if !task5EffectDuplicate(existing, effect) {
			return CommitResult{}, ErrConflict
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{EffectIDs: []string{existing.EffectID}, OrderingSequence: existing.OrderingSequence, Version: existing.Version, Deduplicated: true, Idempotent: true}, nil
	}
	if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, errors.New("eventstore: lookup outbox failed")
	}
	seq, laneID, err := task5AllocateLane(tx, outboxLaneKind, effect.Lane, s.task5Now())
	if err != nil {
		return CommitResult{}, err
	}
	now := s.task5Now()
	row := outboxEffectRow{EffectID: effect.EffectID, Version: 1, EndpointID: effect.EndpointID, Lane: effect.Lane, LaneID: laneID, Subject: effect.Subject, OrderingSequence: seq, EffectClass: effect.EffectType, RiskClass: effect.RiskClass, Status: OutboxStatusPending, Payload: bytes.Clone(effect.Payload), ContentDigest: bytes.Clone(effect.ContentDigest), DeadlineAt: task5Ptr(effect.DeadlineAt), NextAttemptAt: task5Ptr(effect.NextAttemptAt), CreatedAt: now, SchedulingVersion: queueSchedulingVersion}
	if err = tx.Create(&row).Error; err != nil {
		return CommitResult{}, ErrParticipantConflict
	}
	if err = refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
		return CommitResult{}, err
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	result = CommitResult{EffectIDs: []string{row.EffectID}, OrderingSequence: seq, Version: row.Version}
	s.signalOutboxWork()
	return result, nil
}

func (s *GORMStore) ClaimOutbox(ctx context.Context, req OutboxClaimRequest) (OutboxLease, error) {
	return s.claimOutbox(ctx, req, true)
}

func (s *GORMStore) claimOutbox(ctx context.Context, req OutboxClaimRequest, retryAfterMaintenance bool) (lease OutboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return OutboxLease{}, readyErr
	}
	if strings.TrimSpace(req.WorkerID) == "" {
		return OutboxLease{}, ErrParticipantFailure
	}
	now := s.task5Now()
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	if err = s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return OutboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var candidate struct {
		EffectID string `gorm:"column:effect_id"`
	}
	q := scanOutboxClaimable(tx, now, &candidate)
	if q.Error != nil {
		return OutboxLease{}, ErrParticipantFailure
	}
	if q.RowsAffected == 0 {
		return OutboxLease{}, ErrNotFound
	}
	var row outboxEffectRow
	if err = locked(tx).Where("effect_id = ?", candidate.EffectID).First(&row).Error; err != nil {
		return OutboxLease{}, ErrNotFound
	}
	if row.Status != OutboxStatusPending && row.Status != OutboxStatusLeased && row.Status != OutboxStatusDispatched {
		return OutboxLease{}, task5RejectQueueCandidate(tx, outboxLaneKind, row.Lane, now, nil, retryAfterMaintenance)
	}
	if row.Status == OutboxStatusPending && row.NextAttemptAt != nil && row.NextAttemptAt.After(now) {
		return OutboxLease{}, task5RejectQueueCandidate(tx, outboxLaneKind, row.Lane, now, nil, retryAfterMaintenance)
	}
	if row.DispatchedAt != nil && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now) && row.RiskClass != RiskProviderIdempotent {
		failure, isolateErr := s.task5IsolateOutbox(ctx, tx, &row, now, OutboxStatusAmbiguous, "dispatch-lease-expired", "expired-after-dispatch")
		if isolateErr != nil {
			return OutboxLease{}, isolateErr
		}
		if err = refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
			return OutboxLease{}, err
		}
		failures := [...]task5QueueFailure{failure}
		if err = task5CommitQueueFailures(tx, failures[:]); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrNotFound
	}
	if row.Status == OutboxStatusDispatched && row.RiskClass != RiskProviderIdempotent {
		return OutboxLease{}, ErrNotFound
	}
	if row.LeaseEpoch >= maxPersistedVersion {
		return OutboxLease{}, ErrVersionExhausted
	}
	attempt, err := s.task5ID()
	if err != nil {
		return OutboxLease{}, err
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return OutboxLease{}, err
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	retry := row.RetryCount
	if retry < math.MaxUint32 && (row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched) {
		retry++
	}
	updates := map[string]any{"status": OutboxStatusLeased, "version": version, "lease_owner": req.WorkerID, "lease_epoch": row.LeaseEpoch + 1, "lease_expiry": expires, "attempt_id": attempt, "retry_count": retry}
	query := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND status = ?", row.EffectID, row.Version, row.Status)
	if row.Status == OutboxStatusPending && row.NextAttemptAt != nil {
		query = query.Where("next_attempt_at <= ?", now)
	}
	if row.Status == OutboxStatusLeased {
		query = query.Where("lease_expiry IS NULL OR lease_expiry <= ?", now)
	}
	if row.Status == OutboxStatusDispatched {
		query = query.Where("risk_class = ? AND lease_expiry IS NOT NULL AND lease_expiry <= ?", RiskProviderIdempotent, now)
	}
	result, err := query.Updates(updates).RowsAffected, query.Error
	if err != nil {
		return OutboxLease{}, ErrParticipantFailure
	}
	if result != 1 {
		return OutboxLease{}, ErrStaleLease
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID, row.RetryCount = OutboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt, retry
	lease.Effect = effectFromRow(row)
	if err = refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
		return OutboxLease{}, err
	}
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) UpdateOutbox(ctx context.Context, effect NewEffect) (result CommitResult, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return CommitResult{}, readyErr
	}
	if effect.EffectID == "" || !validOutboxStatus(effect.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if effect.Status == OutboxStatusDispatched || effect.Resolution != "" {
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return CommitResult{}, lockErr
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
	now := s.task5Now()
	if effect.EndpointID != "" || effect.Lane != "" || effect.OrderingSequence != 0 || effect.EffectType != "" || len(effect.Payload) > 0 || len(effect.ContentDigest) > 0 || !effect.DispatchedAt.IsZero() || !effect.CompletedAt.IsZero() || effect.ResultCode != "" || effect.ErrorCode != "" || effect.ProviderMessageID != "" || effect.PrincipalID != "" || effect.Reason != "" || !effect.ResolutionAt.IsZero() {
		return CommitResult{}, ErrInvalidTransition
	}
	if row.Status == OutboxStatusSucceeded || row.Status == OutboxStatusFailed || row.Status == OutboxStatusAmbiguous {
		return CommitResult{}, ErrInvalidTransition
	}
	if row.Status == OutboxStatusDispatched && (effect.Status == OutboxStatusSucceeded || effect.Status == OutboxStatusFailed) {
		return CommitResult{}, ErrInvalidTransition
	}
	if effect.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableOutboxEffects)
	}
	if effect.Version != 0 && effect.Version != row.Version {
		return CommitResult{}, participantConflict(tableOutboxEffects)
	}
	if !outboxTransitionAllowed(row.Status, effect.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if effect.RiskClass != "" && !validRisk(effect.RiskClass) {
		return CommitResult{}, ErrInvalidRiskClass
	}
	if effect.RiskClass != "" && effect.RiskClass != row.RiskClass {
		return CommitResult{}, ErrInvalidTransition
	}
	leaseState := row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched
	leaseFields := effect.LeaseOwner != "" || effect.LeaseEpoch != 0 || effect.AttemptID != "" || !effect.LeaseExpiresAt.IsZero()
	if !leaseState && (effect.Status != OutboxStatusPending || leaseFields) {
		return CommitResult{}, ErrStaleLease
	}
	if leaseState || effect.Status == OutboxStatusLeased || effect.Status == OutboxStatusDispatched {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, effect.LeaseOwner, effect.LeaseEpoch, effect.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
			return CommitResult{}, ErrStaleLease
		}
	}
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
	if effect.RetryCount != 0 {
		row.RetryCount = effect.RetryCount
	}
	if !effect.NextAttemptAt.IsZero() {
		row.NextAttemptAt = task5Ptr(effect.NextAttemptAt)
	}
	if !effect.DeadlineAt.IsZero() {
		row.DeadlineAt = task5Ptr(effect.DeadlineAt)
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
	}
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND (lease_expiry IS NULL OR lease_expiry > ?)", row.EffectID, effect.ExpectedVersion, now).Updates(outboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: update outbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = task5CommitOutboxStatus(tx, row, now, "status-transition"); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func (s *GORMStore) RenewOutbox(ctx context.Context, req OutboxRenewRequest) (OutboxLease, error) {
	return s.renewOutbox(ctx, req)
}
func (s *GORMStore) RenewOutboxLease(ctx context.Context, req OutboxRenewRequest) (OutboxLease, error) {
	if err := s.requireReady(ctx); err != nil {
		return OutboxLease{}, err
	}
	return s.RenewOutbox(ctx, req)
}
func (s *GORMStore) renewOutbox(ctx context.Context, req OutboxRenewRequest) (lease OutboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return OutboxLease{}, readyErr
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return OutboxLease{}, lockErr
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
	now := s.task5Now()
	if row.Status != OutboxStatusLeased || !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
		return OutboxLease{}, ErrStaleLease
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return OutboxLease{}, e
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ? AND lease_expiry > ?", req.EffectID, row.Version, req.WorkerID, req.LeaseEpoch, req.AttemptID, now).Updates(map[string]any{"version": version, "lease_expiry": expires})
	if q.Error != nil {
		return OutboxLease{}, errors.New("eventstore: renew outbox failed")
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, ErrStaleLease
	}
	row.Version, row.LeaseExpiry = version, &expires
	lease.Effect = effectFromRow(row)
	if err = refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
		return OutboxLease{}, err
	}
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) MarkOutboxDispatched(ctx context.Context, req OutboxDispatchRequest) (lease OutboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return OutboxLease{}, readyErr
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return OutboxLease{}, lockErr
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
	now := s.task5Now()
	if row.Status != OutboxStatusLeased || !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
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
	row.Status, row.Version, row.AttemptID, row.DispatchedAt = OutboxStatusDispatched, version, newAttempt, &now
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ? AND lease_expiry > ?", req.EffectID, reqVersion(row.Version), req.WorkerID, req.LeaseEpoch, req.AttemptID, now).Updates(map[string]any{"status": row.Status, "version": row.Version, "attempt_id": row.AttemptID, "dispatched_at": row.DispatchedAt})
	if q.Error != nil {
		return OutboxLease{}, errors.New("eventstore: dispatch marker failed")
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, ErrStaleLease
	}
	lease.Effect = effectFromRow(row)
	if err = refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
		return OutboxLease{}, err
	}
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
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return CommitResult{}, readyErr
	}
	if !validOutboxStatus(req.Status) || req.Status == OutboxStatusPending || req.Status == OutboxStatusLeased || req.Status == OutboxStatusDispatched || req.Status == OutboxStatusAmbiguous {
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return CommitResult{}, lockErr
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
	now := s.task5Now()
	if row.Status == req.Status && row.ResultCode == req.ResultCode && row.ErrorCode == req.ErrorCode && row.ProviderMessageID == req.ProviderMessageID {
		if row.CompletedAt != nil {
			if row.LeaseOwner != req.WorkerID || row.LeaseEpoch != req.LeaseEpoch || row.AttemptID != req.AttemptID {
				return CommitResult{}, ErrStaleLease
			}
		} else if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
			return CommitResult{}, ErrStaleLease
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version, Idempotent: true}, nil
	}
	if row.Status != OutboxStatusDispatched || row.DispatchedAt == nil {
		return CommitResult{}, ErrInvalidTransition
	}
	if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
		return CommitResult{}, ErrStaleLease
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return CommitResult{}, e
	}
	row.Status, row.Version, row.ResultCode, row.ErrorCode, row.ProviderMessageID, row.CompletedAt, row.LeaseExpiry = req.Status, version, req.ResultCode, req.ErrorCode, req.ProviderMessageID, &now, nil
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ? AND lease_expiry > ?", row.EffectID, reqVersion(row.Version), req.WorkerID, req.LeaseEpoch, req.AttemptID, now).Updates(outboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: complete outbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = s.applyStoryLogUpdate(ctx, tx, NewStoryLogFinishIntentUpdate(row.EffectID, row.ProviderMessageID, row.Status == OutboxStatusSucceeded)); err != nil {
		return CommitResult{}, err
	}
	if err = task5CommitOutboxStatus(tx, row, now, "provider-terminal-outcome"); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}
func (s *GORMStore) RequeuePreDispatch(ctx context.Context, req OutboxPreDispatchRequeueRequest) (result CommitResult, err error) {
	if err = s.requireReady(ctx); err != nil {
		return result, err
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return result, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return result, err
	}
	if err = s.lockParticipantPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return result, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var row outboxEffectRow
	if q := locked(tx).Where("effect_id = ?", req.EffectID).First(&row); q.Error != nil {
		return result, ErrStaleLease
	}
	now := s.task5Now()
	if row.Status != OutboxStatusDispatched || !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
		return result, ErrStaleLease
	}
	version, e := nextVersion(row.Version)
	if e != nil {
		return result, e
	}
	row.Status = OutboxStatusPending
	row.Version = version
	row.RetryCount = req.RetryCount
	row.NextAttemptAt = &req.NextAttemptAt
	row.LeaseOwner = ""
	row.LeaseEpoch = 0
	row.AttemptID = ""
	row.LeaseExpiry = nil
	row.DispatchedAt = nil
	q := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND lease_owner = ? AND lease_epoch = ? AND attempt_id = ? AND lease_expiry > ?", req.EffectID, reqVersion(row.Version), req.WorkerID, req.LeaseEpoch, req.AttemptID, now).Updates(outboxMap(row))
	if q.Error != nil || q.RowsAffected != 1 {
		return result, ErrStaleLease
	}
	if err = refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
		return result, err
	}
	if err = task5Commit(tx); err != nil {
		return result, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}
func (s *GORMStore) DispatchOutbox(ctx context.Context, req OutboxDispatchRequest) (OutboxLease, error) {
	return s.MarkOutboxDispatched(ctx, req)
}
func task5QuarantineLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return fallback
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return fallback
		}
	}
	return value
}

func task5OutboxFailureRecord(row outboxEffectRow, reason string) task5QueueFailure {
	if row.Status != OutboxStatusFailed && row.Status != OutboxStatusAmbiguous {
		return task5QueueFailure{}
	}
	errorCode := ""
	if row.ErrorCode != "" {
		errorCode = task5QuarantineLabel(row.ErrorCode, "redacted-error-code")
	}
	return task5QueueFailure{
		queue: "outbox", itemID: row.EffectID, status: row.Status,
		reason: task5QuarantineLabel(reason, "queue-failure"), errorCode: errorCode, version: row.Version,
	}
}

func task5CommitOutboxStatus(tx *gorm.DB, row outboxEffectRow, now time.Time, reason string) error {
	if err := refreshQueueLane(tx, outboxLaneKind, row.Lane, now); err != nil {
		return err
	}
	failure := task5OutboxFailureRecord(row, reason)
	if failure.itemID == "" {
		return task5Commit(tx)
	}
	failures := [...]task5QueueFailure{failure}
	return task5CommitQueueFailures(tx, failures[:])
}

func (s *GORMStore) QuarantineOutbox(ctx context.Context, req OutboxQuarantineRequest) (result CommitResult, err error) {
	result.StreamVersions = make(map[StreamID]uint64, 1)
	if err = s.requireReady(ctx); err != nil {
		return result, err
	}
	if req.EffectID == "" || req.WorkerID == "" || req.LeaseEpoch == 0 || req.AttemptID == "" || req.ExpectedVersion == 0 {
		return result, ErrStaleLease
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return result, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	if err = s.lockMutationPublication(ctx, tx); err != nil {
		return result, err
	}
	var row outboxEffectRow
	q := locked(tx).Where("effect_id = ?", req.EffectID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return result, ErrNotFound
	}
	if q.Error != nil {
		return result, errors.New("eventstore: load outbox failed")
	}
	now := s.task5Now()
	if (row.Status != OutboxStatusLeased && row.Status != OutboxStatusDispatched) ||
		!task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, req.WorkerID, req.LeaseEpoch, req.AttemptID) ||
		!task5LeaseActive(row.LeaseExpiry, now) || row.Version != req.ExpectedVersion {
		return result, ErrStaleLease
	}
	status := OutboxStatusFailed
	if row.Status == OutboxStatusDispatched {
		status = OutboxStatusAmbiguous
	}
	errorCode := task5QuarantineLabel(req.ErrorCode, "dispatcher-quarantine")
	reason := task5QuarantineLabel(req.Reason, "dispatcher-quarantine")
	if err = s.task5SettleOutboxOutcome(ctx, tx, &row, now, task5OutboxSettlement{
		status: status, errorCode: errorCode, reason: reason, lease: &req,
	}, &result); err != nil {
		return result, err
	}
	if err = task5CommitOutboxStatus(tx, row, now, row.ResolutionReason); err != nil {
		return result, err
	}
	return result, nil
}

type task5OutboxSettlement struct {
	status                  string
	errorCode               string
	reason                  string
	resolutionPrincipal     string
	producer                string
	preserveOutcome         bool
	expectedOperationStatus string
	lease                   *OutboxQuarantineRequest
}

func (s *GORMStore) task5SettleOutboxOutcome(
	ctx context.Context,
	tx *gorm.DB,
	row *outboxEffectRow,
	now time.Time,
	settlement task5OutboxSettlement,
	result *CommitResult,
) error {
	status, errorCode, reason := settlement.status, settlement.errorCode, settlement.reason
	if status != OutboxStatusSucceeded && status != OutboxStatusFailed && status != OutboxStatusAmbiguous {
		return ErrInvalidTransition
	}
	var readiness storeReadinessRow
	if q := locked(tx).Where("singleton_id = ?", "default").First(&readiness); q.Error != nil {
		return errors.New("eventstore: lock readiness failed")
	}
	var control projectionControlRow
	if q := locked(tx).Where("singleton_id = ?", "default").First(&control); q.Error != nil {
		return errors.New("eventstore: lock projection control failed")
	}
	if control.PublicationState != "published" {
		return ErrReadinessQuarantined
	}

	var source domainEventRow
	sourceFound := false
	sourceQuery := locked(tx).Where("aggregate_type = ? AND aggregate_id = ? AND aggregate_version = ?", "outbound-effect", row.EffectID, 1).First(&source)
	if sourceQuery.Error == nil {
		sourceFound = true
	} else if !errors.Is(sourceQuery.Error, gorm.ErrRecordNotFound) {
		return errors.New("eventstore: load source event for outbox settlement failed")
	}
	var sourceIdentity struct {
		EffectID    string `json:"effectId"`
		OperationID string `json:"operationId"`
		EndpointID  string `json:"endpointId"`
	}
	operationID := ""
	if sourceFound && json.Unmarshal(source.Payload, &sourceIdentity) == nil &&
		sourceIdentity.EffectID == row.EffectID && sourceIdentity.EndpointID == row.EndpointID {
		operationID = sourceIdentity.OperationID
	}

	operationStatus := "failed"
	eventType := "OutboundEffectFailedV1"
	switch status {
	case OutboxStatusSucceeded:
		operationStatus = "succeeded"
		eventType = "OutboundEffectSucceededV1"
	case OutboxStatusAmbiguous:
		operationStatus = "ambiguous"
		eventType = "OutboundEffectAmbiguousV1"
	}
	var operation operationRow
	operationFound := false
	if operationID != "" {
		operationQuery := locked(tx).Where("operation_id = ?", operationID).First(&operation)
		if operationQuery.Error == nil {
			operationFound = true
		} else if !errors.Is(operationQuery.Error, gorm.ErrRecordNotFound) {
			return errors.New("eventstore: load operation for outbox settlement failed")
		}
	}
	if settlement.expectedOperationStatus != "" && operationID != "" &&
		(!operationFound || operation.Status != settlement.expectedOperationStatus) {
		return participantConflict(tableOperations)
	}
	resultCode := ""
	providerMessageID := ""
	if settlement.preserveOutcome {
		resultCode = row.ResultCode
		providerMessageID = row.ProviderMessageID
		if errorCode == "" {
			errorCode = row.ErrorCode
		}
	}
	var q *gorm.DB
	if operationFound {
		version, versionErr := nextVersion(operation.Version)
		if versionErr != nil {
			return versionErr
		}
		operation.Version = version
		operation.Status = operationStatus
		operation.ResultCode = resultCode
		operation.ErrorCode = errorCode
		operation.UpdatedAt = now
		q = tx.Model(&operationRow{}).Where("operation_id = ? AND version = ?", operation.OperationID, version-1).Updates(map[string]any{
			"version": operation.Version, "status": operation.Status, "result_code": operation.ResultCode,
			"error_code": operation.ErrorCode, "updated_at": operation.UpdatedAt,
		})
		if q.Error != nil || q.RowsAffected != 1 {
			return ErrStaleLease
		}
		result.OperationIDs = append(result.OperationIDs, operation.OperationID)
	}

	previousVersion := row.Version
	rowVersion, versionErr := nextVersion(previousVersion)
	if versionErr != nil {
		return versionErr
	}
	row.Version = rowVersion
	row.Status = status
	row.ErrorCode = errorCode
	row.ResultCode = resultCode
	row.ProviderMessageID = providerMessageID
	row.CompletedAt = task5Ptr(now)
	row.LeaseExpiry = nil
	row.ResolutionPrincipal = settlement.resolutionPrincipal
	if row.ResolutionPrincipal == "" {
		row.ResolutionPrincipal = "endpoint-dispatcher"
		if operationFound && operation.PrincipalID != "" {
			row.ResolutionPrincipal = operation.PrincipalID
		}
	}
	row.ResolutionReason = reason
	row.ResolutionAt = task5Ptr(now)
	updateQuery := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, previousVersion)
	if settlement.lease != nil {
		updateQuery = updateQuery.Where(
			"lease_owner = ? AND lease_epoch = ? AND attempt_id = ? AND lease_expiry > ?",
			settlement.lease.WorkerID, settlement.lease.LeaseEpoch, settlement.lease.AttemptID, now,
		)
	}
	q = updateQuery.Updates(outboxMap(*row))
	if q.Error != nil {
		return errors.New("eventstore: settle outbox failed")
	}
	if q.RowsAffected != 1 {
		return ErrStaleLease
	}
	if row.Status == OutboxStatusSucceeded || row.Status == OutboxStatusFailed {
		if err := s.applyStoryLogUpdate(ctx, tx, NewStoryLogFinishIntentUpdate(
			row.EffectID, row.ProviderMessageID, row.Status == OutboxStatusSucceeded,
		)); err != nil {
			return err
		}
	}

	s.projectorMu.RLock()
	projectors := append([]ProjectionDescriptor(nil), s.projectors...)
	s.projectorMu.RUnlock()
	if len(projectors) > 0 {
		tx = withProjectionGeneration(tx, control.ActiveGeneration)
	}
	if sourceFound {
		stream := StreamID{AggregateType: "outbound-effect", AggregateID: row.EffectID}
		var head aggregateHeadRow
		headQuery := locked(tx).Where("aggregate_type = ? AND aggregate_id = ?", stream.AggregateType, stream.AggregateID).First(&head)
		if errors.Is(headQuery.Error, gorm.ErrRecordNotFound) {
			return errors.New("eventstore: source event head missing during outbox settlement")
		}
		if headQuery.Error != nil {
			return errors.New("eventstore: load source event head failed")
		}
		if head.CurrentVersion >= maxPersistedVersion {
			return ErrVersionExhausted
		}
		causationID := source.EventID
		if head.CurrentVersion != source.AggregateVersion {
			var predecessor domainEventRow
			predecessorQuery := locked(tx).
				Select("event_id").
				Where("aggregate_type = ? AND aggregate_id = ? AND aggregate_version = ?", stream.AggregateType, stream.AggregateID, head.CurrentVersion).
				First(&predecessor)
			if predecessorQuery.Error != nil {
				return errors.New("eventstore: load outbox settlement predecessor failed")
			}
			causationID = predecessor.EventID
		}
		var sequence eventGlobalSequenceRow
		if q = locked(tx).Where("singleton_id = ?", "default").First(&sequence); q.Error != nil {
			return errors.New("eventstore: lock event sequence failed")
		}
		eventID, idErr := s.task5ID()
		if idErr != nil {
			return idErr
		}
		commandID, idErr := s.task5ID()
		if idErr != nil {
			return idErr
		}
		correlationID := source.CorrelationID
		if correlationID == "" {
			correlationID, idErr = s.task5ID()
			if idErr != nil {
				return idErr
			}
		}
		principalID := settlement.resolutionPrincipal
		if principalID == "" {
			principalID = source.PrincipalID
			if principalID == "" && operationFound {
				principalID = operation.PrincipalID
			}
			if principalID == "" {
				principalID = "endpoint-dispatcher"
			}
		}
		producer := settlement.producer
		if producer == "" {
			producer = "endpoint-dispatcher"
		}
		eventPayload, marshalErr := json.Marshal(struct {
			EffectID          string `json:"effectId"`
			OperationID       string `json:"operationId,omitempty"`
			EndpointID        string `json:"endpointId"`
			Status            string `json:"status"`
			ResultCode        string `json:"resultCode,omitempty"`
			ErrorCode         string `json:"errorCode,omitempty"`
			ProviderMessageID string `json:"providerId,omitempty"`
			Reason            string `json:"reason"`
		}{row.EffectID, operationID, row.EndpointID, status, resultCode, errorCode, providerMessageID, reason})
		if marshalErr != nil {
			return errors.New("eventstore: outbox settlement event build failed")
		}
		event := NewEvent{EventType: eventType, SchemaVersion: 1, Payload: eventPayload, Metadata: Metadata{
			EventID: eventID, CommandID: commandID, CorrelationID: correlationID, CausationID: causationID,
			PrincipalID: principalID, Producer: producer, OccurredAt: now,
		}}
		position := sequence.NextPosition
		envelope, envelopeErr := (EventFactory{}).Envelope(stream, head.CurrentVersion+1, position, event)
		if envelopeErr != nil {
			return envelopeErr
		}
		eventRow := domainEventRow{EventID: envelope.EventID, AggregateType: stream.AggregateType, AggregateID: stream.AggregateID, AggregateVersion: envelope.StreamVersion, GlobalPosition: envelope.GlobalPosition, EventType: envelope.EventType, SchemaVersion: envelope.SchemaVersion, Payload: envelope.Payload, CommandID: envelope.Metadata.CommandID, CorrelationID: envelope.Metadata.CorrelationID, CausationID: envelope.Metadata.CausationID, PrincipalID: envelope.Metadata.PrincipalID, Producer: envelope.Metadata.Producer, OccurredAtUnixNanoUTC: metadataUnixNano(envelope.Metadata), Checksum: append([]byte(nil), envelope.Checksum[:]...), CreatedAt: now}
		if q = tx.Create(&eventRow); q.Error != nil {
			return errors.New("eventstore: insert outbox settlement event failed")
		}
		if q = tx.Model(&aggregateHeadRow{}).Where("aggregate_type = ? AND aggregate_id = ? AND current_version = ?", stream.AggregateType, stream.AggregateID, head.CurrentVersion).Update("current_version", head.CurrentVersion+1); q.Error != nil || q.RowsAffected != 1 {
			return ErrStaleLease
		}
		nextPosition, positionErr := nextVersion(position)
		if positionErr != nil {
			return positionErr
		}
		if q = tx.Model(&eventGlobalSequenceRow{}).Where("singleton_id = ? AND next_position = ?", "default", position).Update("next_position", nextPosition); q.Error != nil || q.RowsAffected != 1 {
			return ErrStaleLease
		}
		if q = tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Update("terminal_position", position); q.Error != nil || q.RowsAffected != 1 {
			return errors.New("eventstore: update projection control failed")
		}
		result.Events = append(result.Events, envelope)
		if result.StreamVersions == nil {
			result.StreamVersions = make(map[StreamID]uint64, 1)
		}
		result.StreamVersions[stream] = envelope.StreamVersion
	}
	if len(result.Events) > 0 {
		if len(projectors) > 0 {
			if q = tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
				"projector_set_version": projectorSetVersion(projectors),
				"updated_at":            now,
			}); q.Error != nil || q.RowsAffected != 1 {
				return errors.New("eventstore: update projector control failed")
			}
		}
		for _, projector := range projectors {
			if applyErr := projector.Apply(ctx, tx, result.Events); applyErr != nil {
				return errors.Join(ErrProjectorFailure, applyErr)
			}
		}
		s.projectorMu.RLock()
		if !sameProjectors(s.projectors, projectors) {
			s.projectorMu.RUnlock()
			return ErrProjectorRegistryChanged
		}
		s.projectorMu.RUnlock()
	}
	result.EffectIDs = []string{row.EffectID}
	result.Version = row.Version
	return nil
}

func (s *GORMStore) task5IsolateOutbox(
	ctx context.Context,
	tx *gorm.DB,
	row *outboxEffectRow,
	now time.Time,
	status string,
	errorCode string,
	reason string,
) (task5QueueFailure, error) {
	result := CommitResult{}
	if err := s.task5SettleOutboxOutcome(ctx, tx, row, now, task5OutboxSettlement{
		status: status, errorCode: errorCode, reason: reason,
	}, &result); err != nil {
		return task5QueueFailure{}, err
	}
	return task5OutboxFailureRecord(*row, row.ResolutionReason), nil
}

func (s *GORMStore) ResolveOutbox(ctx context.Context, req OutboxResolutionRequest) (result CommitResult, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return CommitResult{}, readyErr
	}
	if req.Resolution != OutboxResolutionRetry && req.Resolution != OutboxResolutionSucceeded && req.Resolution != OutboxResolutionFailed {
		return CommitResult{}, ErrInvalidTransition
	}
	if strings.TrimSpace(req.PrincipalID) == "" || strings.TrimSpace(req.Reason) == "" {
		return CommitResult{}, ErrInvalidMetadata
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return CommitResult{}, lockErr
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
	now := s.task5Now()
	if req.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableOutboxEffects)
	}
	if req.Resolution == OutboxResolutionRetry && row.DispatchedAt != nil && row.RiskClass != RiskProviderIdempotent {
		return CommitResult{}, ErrInvalidTransition
	}
	if !outboxUnresolved(row.Status) {
		return CommitResult{}, ErrInvalidTransition
	}
	if row.Status == OutboxStatusAmbiguous && req.Resolution != OutboxResolutionRetry {
		status := OutboxStatusFailed
		if req.Resolution == OutboxResolutionSucceeded {
			status = OutboxStatusSucceeded
		}
		if err = s.task5SettleOutboxOutcome(ctx, tx, &row, now, task5OutboxSettlement{
			status: status, errorCode: row.ErrorCode, reason: req.Reason,
			resolutionPrincipal: req.PrincipalID, producer: "operator-resolution",
			preserveOutcome: true, expectedOperationStatus: "ambiguous",
		}, &result); err != nil {
			return CommitResult{}, err
		}
		if err = task5CommitOutboxStatus(tx, row, now, "operator-resolution"); err != nil {
			return CommitResult{}, err
		}
		return result, nil
	}
	switch req.Resolution {
	case OutboxResolutionRetry:
		row.Status = OutboxStatusPending
		if row.RetryCount < math.MaxUint32 {
			row.RetryCount++
		}
		row.NextAttemptAt = task5Ptr(now)
	case OutboxResolutionSucceeded:
		row.Status = OutboxStatusSucceeded
	default:
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
		row.CompletedAt = task5Ptr(now)
	}
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, req.ExpectedVersion).Updates(outboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: resolve outbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if row.Status == OutboxStatusSucceeded || row.Status == OutboxStatusFailed {
		if err = s.applyStoryLogUpdate(ctx, tx, NewStoryLogFinishIntentUpdate(row.EffectID, row.ProviderMessageID, row.Status == OutboxStatusSucceeded)); err != nil {
			return CommitResult{}, err
		}
	}
	if err = task5CommitOutboxStatus(tx, row, now, "operator-resolution"); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}

func task5LeaseMatches(owner string, epoch uint64, attempt, wantOwner string, wantEpoch uint64, wantAttempt string) bool {
	return owner != "" && attempt != "" && owner == wantOwner && epoch == wantEpoch && attempt == wantAttempt
}
func task5LeaseActive(expiry *time.Time, now time.Time) bool {
	return expiry != nil && expiry.After(now)
}
func task5AllowsExpiredAmbiguous(row inboxMessageRow, update InboxUpdate) bool {
	return row.Status == InboxStatusCallbackStarted &&
		update.Status == InboxStatusAmbiguous &&
		update.ExpectedVersion == row.Version &&
		task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID)
}

func participantConflict(table string) error {
	return &ParticipantConflictError{Conflicts: []ParticipantConflict{{Table: table, Key: "<redacted>"}}}
}

func inboxMap(row inboxMessageRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "attempt_id": row.AttemptID, "callback_started_at": row.CallbackStartedAt, "completed_at": row.CompletedAt, "payload": row.Payload, "scheduling_version": queueSchedulingVersion, "workflow_id": row.WorkflowID, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}
func outboxMap(row outboxEffectRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "attempt_id": row.AttemptID, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "dispatched_at": row.DispatchedAt, "deadline_at": row.DeadlineAt, "next_attempt_at": row.NextAttemptAt, "payload": row.Payload, "scheduling_version": queueSchedulingVersion, "result_code": row.ResultCode, "error_code": row.ErrorCode, "provider_message_id": row.ProviderMessageID, "completed_at": row.CompletedAt, "retry_count": row.RetryCount, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}

func inboxUpdateFromRow(row inboxMessageRow) InboxUpdate {
	return InboxUpdate{InboxID: row.InboxID, ExpectedVersion: row.Version, Version: row.Version, EndpointID: row.EndpointID, ProviderEventKey: row.ProviderEventKey, Lane: row.Lane, Subject: row.Subject, OrderingSequence: row.OrderingSequence, Status: row.Status, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch, LeaseExpiresAt: valueTime(row.LeaseExpiry), AttemptID: row.AttemptID, Payload: bytes.Clone(row.Payload), ContentDigest: bytes.Clone(row.ContentDigest), WorkflowID: row.WorkflowID, CallbackStartedAt: valueTime(row.CallbackStartedAt), CompletedAt: valueTime(row.CompletedAt), Resolution: row.ResolutionReason, PrincipalID: row.ResolutionPrincipal, Reason: row.ResolutionReason, ResolutionAt: valueTime(row.ResolutionAt)}
}

func effectFromRow(row outboxEffectRow) NewEffect {
	return NewEffect{EffectID: row.EffectID, ExpectedVersion: row.Version, Version: row.Version, EndpointID: row.EndpointID, Lane: row.Lane, Subject: row.Subject, OrderingSequence: row.OrderingSequence, EffectType: row.EffectClass, RiskClass: row.RiskClass, Status: row.Status, AttemptID: row.AttemptID, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch, LeaseExpiresAt: valueTime(row.LeaseExpiry), DeadlineAt: valueTime(row.DeadlineAt), NextAttemptAt: valueTime(row.NextAttemptAt), DispatchedAt: valueTime(row.DispatchedAt), Payload: bytes.Clone(row.Payload), ContentDigest: bytes.Clone(row.ContentDigest), ProviderMessageID: row.ProviderMessageID, ResultCode: row.ResultCode, ErrorCode: row.ErrorCode, CompletedAt: valueTime(row.CompletedAt), RetryCount: row.RetryCount, Resolution: row.ResolutionReason, PrincipalID: row.ResolutionPrincipal, Reason: row.ResolutionReason, ResolutionAt: valueTime(row.ResolutionAt)}
}

func valueTime(v *time.Time) time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.UTC()
}
func (s *GORMStore) PutArtifact(ctx context.Context, req ArtifactPutRequest) (result ArtifactPutResult, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return ArtifactPutResult{}, readyErr
	}
	if ctx == nil {
		ctx = context.Background()
	}
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
	if req.ArtifactID == "" {
		req.ArtifactID, err = s.task5ID()
		if err != nil {
			return ArtifactPutResult{}, err
		}
	}
	var preparedOperation operationRow
	operationQuery := s.db.GORM().WithContext(ctx).Select("operation_id", "principal_id").Where("operation_id = ?", req.OperationID).First(&preparedOperation)
	if errors.Is(operationQuery.Error, gorm.ErrRecordNotFound) {
		return ArtifactPutResult{}, ErrNotFound
	}
	if operationQuery.Error != nil {
		return ArtifactPutResult{}, errors.New("eventstore: load artifact owner failed")
	}
	if req.OwnerPrincipalID == "" {
		req.OwnerPrincipalID = preparedOperation.PrincipalID
	}
	if req.OwnerPrincipalID != preparedOperation.PrincipalID {
		return ArtifactPutResult{}, ErrInvalidMetadata
	}
	data := bytes.Clone(req.Plaintext)
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactPutResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactPutResult{}, err
	}
	if lockErr := s.lockParticipantPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return ArtifactPutResult{}, lockErr
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var operation operationRow
	operationQuery = locked(tx).Select("operation_id", "principal_id").Where("operation_id = ?", req.OperationID).First(&operation)
	if errors.Is(operationQuery.Error, gorm.ErrRecordNotFound) {
		return ArtifactPutResult{}, ErrNotFound
	}
	if operationQuery.Error != nil {
		return ArtifactPutResult{}, errors.New("eventstore: load artifact owner failed")
	}
	if req.OwnerPrincipalID == "" {
		req.OwnerPrincipalID = operation.PrincipalID
	}
	if req.OwnerPrincipalID != operation.PrincipalID {
		return ArtifactPutResult{}, ErrInvalidMetadata
	}
	now := s.task5Now()
	expires := now.Add(ttl)
	row := operationArtifactRow{ArtifactID: req.ArtifactID, Version: 1, OperationID: req.OperationID, OwnerPrincipalID: req.OwnerPrincipalID, MediaType: req.MediaType, SafeFilename: req.SafeFilename, Size: int64(len(data)), Status: "available", Data: data, ExpiresAt: expires}
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
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return ArtifactResult{}, readyErr
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var preparedArtifact operationArtifactRow
	preparedQuery := s.db.GORM().WithContext(ctx).Where("artifact_id = ?", req.ArtifactID).First(&preparedArtifact)
	if errors.Is(preparedQuery.Error, gorm.ErrRecordNotFound) {
		return ArtifactResult{}, ErrArtifactGone
	}
	if preparedQuery.Error != nil {
		return ArtifactResult{}, errors.New("eventstore: load artifact failed")
	}
	if req.OwnerPrincipalID != "" && req.OwnerPrincipalID != preparedArtifact.OwnerPrincipalID {
		return ArtifactResult{}, ErrArtifactOwner
	}
	if preparedArtifact.Status != "available" && preparedArtifact.Status != "ready" {
		return ArtifactResult{}, ErrArtifactGone
	}
	plaintext := bytes.Clone(preparedArtifact.Data)
	if len(plaintext) > MaxArtifactBytes || int64(len(plaintext)) != preparedArtifact.Size {
		return ArtifactResult{}, ErrInvalidMetadata
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactResult{}, err
	}
	if lockErr := s.lockParticipantPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return ArtifactResult{}, lockErr
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
		return ArtifactResult{}, ErrParticipantFailure
	}
	now := s.task5Now()
	if req.OwnerPrincipalID != "" && req.OwnerPrincipalID != row.OwnerPrincipalID {
		return ArtifactResult{}, ErrArtifactOwner
	}
	if row.Status != "available" && row.Status != "ready" {
		return ArtifactResult{}, ErrArtifactGone
	}
	if !row.ExpiresAt.After(now) {
		return ArtifactResult{}, ErrArtifactGone
	}
	if row.Version != preparedArtifact.Version || row.OwnerPrincipalID != preparedArtifact.OwnerPrincipalID || row.Size != preparedArtifact.Size || !bytes.Equal(row.Data, preparedArtifact.Data) {
		return ArtifactResult{}, ErrStaleLease
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return ArtifactResult{}, err
	}
	q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, row.Version).Updates(map[string]any{"version": version, "status": "consumed", "consumed_at": now})
	if q.Error != nil || q.RowsAffected != 1 {
		return ArtifactResult{}, ErrStaleLease
	}
	consumed := ArtifactResult{ArtifactID: row.ArtifactID, OperationID: row.OperationID, OwnerPrincipalID: row.OwnerPrincipalID, MediaType: row.MediaType, SafeFilename: row.SafeFilename, Size: row.Size, Plaintext: plaintext, ExpiresAt: row.ExpiresAt, ConsumedAt: now}
	if err = task5Commit(tx); err != nil {
		clear(plaintext)
		return ArtifactResult{}, err
	}
	return consumed, nil
}

const (
	task5MessageWorkflowAggregateType       = "message-workflow"
	task5MessageWorkflowTerminatedEventType = "message-workflow.terminated"
)

func task5WorkflowEventContainsOverlay(event NewEvent) bool {
	if strings.Contains(event.EventType, "$t") ||
		strings.Contains(event.Metadata.EventID, "$t") ||
		strings.Contains(event.Metadata.CommandID, "$t") ||
		strings.Contains(event.Metadata.CorrelationID, "$t") ||
		strings.Contains(event.Metadata.CausationID, "$t") ||
		strings.Contains(event.Metadata.PrincipalID, "$t") ||
		strings.Contains(event.Metadata.Producer, "$t") {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	contains, err := task5ScanWorkflowJSON(decoder)
	if err != nil {
		return true
	}
	if _, err := decoder.Token(); err != io.EOF {
		return true
	}
	return contains
}

func task5ScanWorkflowJSON(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if text, ok := token.(string); ok && strings.Contains(text, "$t") {
		return true, nil
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			contains := false
			seen := make(map[string]struct{})
			for decoder.More() {
				key, keyErr := decoder.Token()
				if keyErr != nil {
					return false, keyErr
				}
				keyText, keyOK := key.(string)
				if !keyOK {
					return false, errors.New("eventstore: invalid workflow JSON object key")
				}
				if _, exists := seen[keyText]; exists {
					return false, errors.New("eventstore: duplicate workflow JSON object key")
				}
				seen[keyText] = struct{}{}
				if strings.Contains(keyText, "$t") {
					contains = true
				}
				child, childErr := task5ScanWorkflowJSON(decoder)
				if childErr != nil {
					return false, childErr
				}
				contains = contains || child
			}
			if _, err := decoder.Token(); err != nil {
				return false, err
			}
			return contains, nil
		case '[':
			contains := false
			for decoder.More() {
				child, childErr := task5ScanWorkflowJSON(decoder)
				if childErr != nil {
					return false, childErr
				}
				contains = contains || child
			}
			if _, err := decoder.Token(); err != nil {
				return false, err
			}
			return contains, nil
		default:
			return false, errors.New("eventstore: invalid workflow JSON delimiter")
		}
	}
	return false, nil
}

func task5WorkflowEventValidation(event NewEvent) error {
	if task5WorkflowEventContainsOverlay(event) {
		return ErrInvalidEvent
	}
	return nil
}

func task5WorkflowStreamCount(work UnitOfWork) int {
	count := 0
	for _, streamAppend := range work.Streams {
		if streamAppend.Stream.AggregateType == task5MessageWorkflowAggregateType {
			count++
		}
	}
	return count
}

func (s *GORMStore) validateTask5WorkflowLink(ctx context.Context, tx *gorm.DB, work UnitOfWork) error {
	workflowStreams := make([]StreamAppend, 0, 1)
	for _, streamAppend := range work.Streams {
		if streamAppend.Stream.AggregateType == task5MessageWorkflowAggregateType {
			workflowStreams = append(workflowStreams, streamAppend)
		}
	}
	if len(workflowStreams) == 0 {
		return nil
	}
	workflowLinks := make([]InboxUpdate, 0, 1)
	for _, update := range work.InboxUpdates {
		if update.WorkflowID != "" {
			workflowLinks = append(workflowLinks, update)
		}
	}
	if len(workflowStreams) != 1 || len(workflowLinks) != 1 {
		return ErrInvalidTransition
	}
	workflow := workflowStreams[0]
	link := workflowLinks[0]
	if !validInboxWorkflowID(link.WorkflowID) {
		return ErrInvalidMetadata
	}
	if workflow.Stream.AggregateID != link.WorkflowID || len(workflow.Events) != 1 || workflow.Events[0].EventType != task5MessageWorkflowTerminatedEventType {
		return ErrInvalidTransition
	}
	if err := task5WorkflowEventValidation(workflow.Events[0]); err != nil {
		return err
	}
	var head aggregateHeadRow
	query := locked(tx).WithContext(ctx).Where("aggregate_type = ? AND aggregate_id = ?", workflow.Stream.AggregateType, workflow.Stream.AggregateID).First(&head)
	if errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return participantConflict(tableAggregateHeads)
	}
	if query.Error != nil {
		return ErrParticipantFailure
	}
	expectedHeadVersion := workflow.ExpectedVersion + uint64(len(workflow.Events))
	if head.CurrentVersion != expectedHeadVersion {
		return participantConflict(tableAggregateHeads)
	}
	return nil
}

func (s *GORMStore) applyTask5InboxParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	workflowStreamCount := task5WorkflowStreamCount(work)
	if err := s.validateTask5WorkflowLink(ctx, tx, work); err != nil {
		return err
	}
	updates := append([]InboxUpdate(nil), work.InboxUpdates...)
	sort.Slice(updates, func(i, j int) bool {
		if updates[i].Lane != updates[j].Lane {
			return updates[i].Lane < updates[j].Lane
		}
		return updates[i].InboxID < updates[j].InboxID
	})
	for _, update := range updates {
		if update.InboxID == "" {
			return ErrInvalidMetadata
		}
		var row inboxMessageRow
		query := tx.Where("inbox_id = ?", update.InboxID).First(&row)
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			if err := s.createTask5InboxParticipant(tx, update, result); err != nil {
				return err
			}
			continue
		}
		if query.Error != nil {
			return ErrParticipantFailure
		}
		if err := s.updateTask5InboxParticipant(tx, update, row, workflowStreamCount, result); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) createTask5InboxParticipant(tx *gorm.DB, update InboxUpdate, result *CommitResult) error {
	if update.EndpointID == "" || update.ProviderEventKey == "" || update.Lane == "" || len(update.Payload) > task5PayloadLimit {
		return ErrInvalidMetadata
	}
	if update.WorkflowID != "" {
		return ErrInvalidTransition
	}
	if err := participantVersion(update.ExpectedVersion, 0, update.Version, tableInboxMessages, "<redacted>"); err != nil {
		return err
	}
	if update.Status == "" {
		update.Status = InboxStatusPending
	}
	if update.Status != InboxStatusPending || update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	var existing inboxMessageRow
	dedupe := inboxProviderQuery(locked(tx), update.EndpointID, update.ProviderEventKey).First(&existing)
	if dedupe.Error == nil {
		if task5InboxDuplicate(existing, update) {
			result.InboxIDs = append(result.InboxIDs, existing.InboxID)
			result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, existing.OrderingSequence, existing.Version
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(dedupe.Error, gorm.ErrRecordNotFound) {
		return ErrParticipantFailure
	}
	sequence, laneID, err := task5AllocateLane(tx, inboxLaneKind, update.Lane, s.task5Now())
	if err != nil {
		return err
	}
	row := inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, Lane: update.Lane, LaneID: laneID, Subject: update.Subject, OrderingSequence: sequence, Status: update.Status, Version: 1, Payload: bytes.Clone(update.Payload), ContentDigest: bytes.Clone(update.ContentDigest)}
	query := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if query.Error != nil {
		return ErrParticipantFailure
	}
	if query.RowsAffected == 0 {
		return ErrConflict
	}
	result.OrderingSequence, result.Version = sequence, row.Version
	result.InboxIDs = append(result.InboxIDs, update.InboxID)
	return nil
}

func (s *GORMStore) updateTask5InboxParticipant(tx *gorm.DB, update InboxUpdate, row inboxMessageRow, workflowStreamCount int, result *CommitResult) error {
	if len(update.Payload) > task5PayloadLimit {
		return &OversizeError{Bound: "inbox payload", Limit: task5PayloadLimit, Actual: len(update.Payload)}
	}
	if task5InboxDuplicate(row, update) && update.ExpectedVersion == 0 &&
		(update.Version == 0 || update.Version == 1) && (update.Status == "" || update.Status == InboxStatusPending) &&
		update.LeaseOwner == "" && update.LeaseEpoch == 0 && update.AttemptID == "" && update.LeaseExpiresAt.IsZero() &&
		update.CallbackStartedAt.IsZero() && update.CompletedAt.IsZero() && update.PrincipalID == "" && update.Reason == "" &&
		update.Resolution == "" && update.ResolutionAt.IsZero() && update.WorkflowID == "" {
		result.InboxIDs = append(result.InboxIDs, row.InboxID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, row.OrderingSequence, row.Version
		return nil
	}
	if update.EndpointID != "" || update.ProviderEventKey != "" || update.Lane != "" || update.Subject != "" || update.OrderingSequence != 0 || len(update.Payload) != 0 || !update.CallbackStartedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	if update.WorkflowID != "" && (!validInboxWorkflowID(update.WorkflowID) || update.Status != InboxStatusConfirmedConsumed || workflowStreamCount == 0) {
		return ErrInvalidTransition
	}
	if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableInboxMessages, "<redacted>"); err != nil {
		return err
	}
	if row.Status == InboxStatusFailed || row.Status == InboxStatusConfirmedConsumed || row.Status == InboxStatusSkipped {
		return ErrInvalidTransition
	}
	terminalStatus := update.Status == InboxStatusFailed || update.Status == InboxStatusConfirmedConsumed || update.Status == InboxStatusSkipped || update.Status == InboxStatusAmbiguous
	if !update.CompletedAt.IsZero() && !terminalStatus {
		return ErrInvalidTransition
	}
	if update.Resolution != "" {
		return ErrInvalidTransition
	}
	if update.Status != "" && (!validInboxStatus(update.Status) || !inboxTransitionAllowed(row.Status, update.Status)) {
		return ErrInvalidTransition
	}
	if update.Status != InboxStatusPending || row.Status != InboxStatusPending {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) ||
			(!task5LeaseActive(row.LeaseExpiry, s.task5Now()) && !task5AllowsExpiredAmbiguous(row, update)) {
			return ErrStaleLease
		}
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return err
	}
	if update.Status != "" {
		row.Status = update.Status
	}
	if row.Status == InboxStatusCallbackStarted && row.CallbackStartedAt == nil {
		row.CallbackStartedAt = task5Ptr(s.task5Now())
	}
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
	if update.WorkflowID != "" {
		row.WorkflowID = update.WorkflowID
	}
	if terminalStatus {
		row.LeaseExpiry = nil
		if !update.CompletedAt.IsZero() {
			row.CompletedAt = task5Ptr(update.CompletedAt)
		} else {
			row.CompletedAt = task5Ptr(s.task5Now())
		}
	}
	row.Version = version
	query := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, update.ExpectedVersion).Updates(inboxMap(row))
	if query.Error != nil || query.RowsAffected != 1 {
		return ErrStaleLease
	}
	result.InboxIDs = append(result.InboxIDs, row.InboxID)
	return nil
}

func (s *GORMStore) applyTask5EffectParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	updates := append([]NewEffect(nil), work.Effects...)
	sort.SliceStable(updates, func(i, j int) bool {
		return updates[i].Lane < updates[j].Lane
	})
	for _, update := range updates {
		if update.EffectID == "" {
			return ErrInvalidMetadata
		}
		var row outboxEffectRow
		query := tx.Where("effect_id = ?", update.EffectID).First(&row)
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			if err := s.createTask5EffectParticipant(tx, update, result); err != nil {
				return err
			}
			continue
		}
		if query.Error != nil {
			return ErrParticipantFailure
		}
		if err := s.updateTask5EffectParticipant(ctx, tx, update, row, result); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) createTask5EffectParticipant(tx *gorm.DB, update NewEffect, result *CommitResult) error {
	if err := participantVersion(update.ExpectedVersion, 0, update.Version, tableOutboxEffects, "<redacted>"); err != nil {
		return err
	}
	if update.EndpointID == "" || update.Lane == "" || update.EffectType == "" || len(update.Payload) > task5PayloadLimit {
		return ErrInvalidMetadata
	}
	if update.Status != "" && update.Status != OutboxStatusPending {
		return ErrInvalidTransition
	}
	if !validRisk(update.RiskClass) {
		return ErrInvalidRiskClass
	}
	if update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.DispatchedAt.IsZero() || !update.CompletedAt.IsZero() || update.ProviderMessageID != "" || update.ResultCode != "" || update.ErrorCode != "" || update.RetryCount != 0 || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	var existing outboxEffectRow
	query := tx.Where("effect_id = ?", update.EffectID).First(&existing)
	if query.Error == nil {
		if task5EffectDuplicate(existing, update) {
			result.EffectIDs = append(result.EffectIDs, existing.EffectID)
			result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, existing.OrderingSequence, existing.Version
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return ErrParticipantFailure
	}
	sequence, laneID, err := task5AllocateLane(tx, outboxLaneKind, update.Lane, s.task5Now())
	if err != nil {
		return err
	}
	status := update.Status
	if status == "" {
		status = OutboxStatusPending
	}
	row := outboxEffectRow{EffectID: update.EffectID, Version: 1, EndpointID: update.EndpointID, Lane: update.Lane, LaneID: laneID, Subject: update.Subject, OrderingSequence: sequence, EffectClass: update.EffectType, RiskClass: update.RiskClass, Status: status, DeadlineAt: task5Ptr(update.DeadlineAt), NextAttemptAt: task5Ptr(update.NextAttemptAt), Payload: bytes.Clone(update.Payload), ContentDigest: bytes.Clone(update.ContentDigest), CreatedAt: chooseTime(update.ResolutionAt, s.task5Now()), SchedulingVersion: queueSchedulingVersion}
	if err := tx.Create(&row).Error; err != nil {
		return ErrParticipantFailure
	}
	result.OrderingSequence, result.Version = sequence, row.Version
	result.EffectIDs = append(result.EffectIDs, row.EffectID)
	return nil
}

func (s *GORMStore) updateTask5EffectParticipant(ctx context.Context, tx *gorm.DB, update NewEffect, row outboxEffectRow, result *CommitResult) error {
	if len(update.Payload) > task5PayloadLimit {
		return &OversizeError{Bound: "outbox payload", Limit: task5PayloadLimit, Actual: len(update.Payload)}
	}
	if task5EffectDuplicate(row, update) && bytes.Equal(row.ContentDigest, update.ContentDigest) &&
		row.Status == OutboxStatusPending && row.Version == 1 && update.ExpectedVersion == 0 &&
		(update.Version == 0 || update.Version == 1) && (update.Status == "" || update.Status == OutboxStatusPending) &&
		update.LeaseOwner == "" && update.LeaseEpoch == 0 && update.AttemptID == "" && update.LeaseExpiresAt.IsZero() &&
		update.DispatchedAt.IsZero() && update.CompletedAt.IsZero() && update.ProviderMessageID == "" &&
		update.ResultCode == "" && update.ErrorCode == "" && update.RetryCount == 0 && update.PrincipalID == "" &&
		update.Reason == "" && update.Resolution == "" && update.ResolutionAt.IsZero() {
		result.EffectIDs = append(result.EffectIDs, row.EffectID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, row.OrderingSequence, row.Version
		return nil
	}
	if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableOutboxEffects, "<redacted>"); err != nil {
		return err
	}
	if row.Status == OutboxStatusSucceeded || row.Status == OutboxStatusFailed || row.Status == OutboxStatusAmbiguous {
		return ErrInvalidTransition
	}
	if update.Status == OutboxStatusDispatched {
		return ErrInvalidTransition
	}
	terminal := update.Status == OutboxStatusSucceeded || update.Status == OutboxStatusFailed || update.Status == OutboxStatusAmbiguous
	if update.EndpointID != "" || update.Lane != "" || update.OrderingSequence != 0 || update.EffectType != "" || len(update.Payload) > 0 || len(update.ContentDigest) > 0 || !update.DispatchedAt.IsZero() {
		return ErrInvalidTransition
	}
	leaseState := row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched
	requiresLease := update.Status != "" && update.Status != OutboxStatusPending
	if requiresLease && !leaseState {
		return ErrStaleLease
	}
	if leaseState || requiresLease {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || !task5LeaseActive(row.LeaseExpiry, s.task5Now()) {
			return ErrStaleLease
		}
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return err
	}
	if update.Status != "" {
		if !validOutboxStatus(update.Status) || !outboxTransitionAllowed(row.Status, update.Status) {
			return ErrInvalidTransition
		}
		row.Status = update.Status
	}
	if update.ResultCode != "" {
		row.ResultCode = update.ResultCode
	}
	if update.ErrorCode != "" {
		row.ErrorCode = update.ErrorCode
	}
	if update.ProviderMessageID != "" {
		row.ProviderMessageID = update.ProviderMessageID
	}
	if update.RetryCount != 0 {
		row.RetryCount = update.RetryCount
	}
	if !update.NextAttemptAt.IsZero() {
		row.NextAttemptAt = task5Ptr(update.NextAttemptAt)
	}
	if !update.DeadlineAt.IsZero() {
		row.DeadlineAt = task5Ptr(update.DeadlineAt)
	}
	if update.RiskClass != "" && update.RiskClass != row.RiskClass {
		return ErrInvalidTransition
	}
	if terminal {
		row.CompletedAt = task5Ptr(s.task5Now())
		row.LeaseExpiry = nil
	}
	row.Version = version
	query := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, update.ExpectedVersion).Updates(outboxMap(row))
	if query.Error != nil || query.RowsAffected != 1 {
		return ErrStaleLease
	}
	if terminal {
		if err := s.applyStoryLogUpdate(ctx, tx, NewStoryLogFinishIntentUpdate(row.EffectID, row.ProviderMessageID, row.Status == OutboxStatusSucceeded)); err != nil {
			return err
		}
	}
	result.EffectIDs = append(result.EffectIDs, row.EffectID)
	return nil
}

func (s *GORMStore) applyTask5ArtifactParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	updates := append([]ArtifactUpdate(nil), work.ArtifactUpdates...)
	sort.Slice(updates, func(i, j int) bool { return updates[i].ArtifactID < updates[j].ArtifactID })
	for _, update := range updates {
		if update.ArtifactID == "" || len(update.Data) > MaxArtifactBytes {
			return ErrInvalidMetadata
		}
		if update.Size < 0 || update.Size > MaxArtifactBytes {
			return &OversizeError{Bound: "artifact bytes", Limit: MaxArtifactBytes, Actual: int(update.Size)}
		}
		if update.Status != "" && update.Status != "ready" && update.Status != "available" {
			return ErrInvalidTransition
		}
		now := s.task5Now()
		var row operationArtifactRow
		query := tx.Where("artifact_id = ?", update.ArtifactID).First(&row)
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			if err := s.createTask5ArtifactParticipant(ctx, tx, update, now, result); err != nil {
				return err
			}
			continue
		}
		if query.Error != nil {
			return ErrParticipantFailure
		}
		if err := s.updateTask5ArtifactParticipant(tx, update, row, now, result); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) createTask5ArtifactParticipant(_ context.Context, tx *gorm.DB, update ArtifactUpdate, now time.Time, result *CommitResult) error {
	if err := participantVersion(update.ExpectedVersion, 0, update.Version, tableOperationArtifacts, "<redacted>"); err != nil {
		return err
	}
	if update.OperationID == "" || !update.ConsumedAt.IsZero() {
		return ErrInvalidTransition
	}
	var operation operationRow
	query := locked(tx).Select("operation_id", "principal_id").Where("operation_id = ?", update.OperationID).First(&operation)
	if errors.Is(query.Error, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if query.Error != nil {
		return ErrParticipantFailure
	}
	owner := update.OwnerPrincipalID
	if owner == "" {
		owner = operation.PrincipalID
	}
	if owner == "" || owner != operation.PrincipalID {
		return ErrInvalidMetadata
	}
	expires := update.ExpiresAt
	if expires.IsZero() {
		expires = now.Add(DefaultArtifactTTL)
	} else {
		expires = expires.UTC()
		if !expires.After(now) || expires.After(now.Add(MaxArtifactTTL)) {
			return ErrInvalidTTL
		}
	}
	size := int64(len(update.Data))
	if update.Size != 0 && update.Size != size {
		return ErrInvalidMetadata
	}
	row := operationArtifactRow{ArtifactID: update.ArtifactID, Version: 1, OperationID: update.OperationID, OwnerPrincipalID: owner, MediaType: nonempty(update.MediaType, "application/octet-stream"), SafeFilename: update.SafeFilename, Size: size, Status: nonempty(update.Status, "available"), Data: bytes.Clone(update.Data), ExpiresAt: expires}
	if err := tx.Create(&row).Error; err != nil {
		return ErrParticipantFailure
	}
	result.ArtifactIDs = append(result.ArtifactIDs, row.ArtifactID)
	return nil
}

func (s *GORMStore) updateTask5ArtifactParticipant(tx *gorm.DB, update ArtifactUpdate, row operationArtifactRow, now time.Time, result *CommitResult) error {
	if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableOperationArtifacts, "<redacted>"); err != nil {
		return err
	}
	if !row.ExpiresAt.After(now) {
		return ErrArtifactGone
	}
	if row.Status != "available" && row.Status != "ready" {
		return ErrArtifactGone
	}
	if update.OwnerPrincipalID != "" && update.OwnerPrincipalID != row.OwnerPrincipalID {
		return ErrInvalidMetadata
	}
	if update.OperationID != "" || update.MediaType != "" || update.SafeFilename != "" || !update.ConsumedAt.IsZero() || len(update.Data) > 0 || update.Size != 0 {
		return ErrInvalidTransition
	}
	if update.Status != "" && update.Status != row.Status && (row.Status != "ready" || update.Status != "available") {
		return ErrInvalidTransition
	}
	version, err := nextVersion(row.Version)
	if err != nil {
		return err
	}
	if update.Status != "" {
		row.Status = update.Status
	}
	row.Version = version
	query := tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, update.ExpectedVersion).Updates(map[string]any{"version": row.Version, "owner_principal_id": row.OwnerPrincipalID, "status": row.Status, "data": row.Data, "expires_at": row.ExpiresAt, "consumed_at": row.ConsumedAt})
	if query.Error != nil || query.RowsAffected != 1 {
		return ErrStaleLease
	}
	result.ArtifactIDs = append(result.ArtifactIDs, row.ArtifactID)
	return nil
}

var _ InboxRepository = (*GORMStore)(nil)
var _ OutboxRepository = (*GORMStore)(nil)
var _ ArtifactRepository = (*GORMStore)(nil)
var _ OperationRepository = (*GORMStore)(nil)
