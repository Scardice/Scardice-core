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

type task5ExpiredPayloadError struct {
	table string
	id    string
	now   time.Time
}

func (e *task5ExpiredPayloadError) Error() string { return ErrPayloadExpired.Error() }
func (e *task5ExpiredPayloadError) Unwrap() error { return ErrPayloadExpired }

type task5ExpiredArtifactError struct {
	id  string
	now time.Time
}

func (e *task5ExpiredArtifactError) Error() string { return ErrArtifactGone.Error() }
func (e *task5ExpiredArtifactError) Unwrap() error { return ErrArtifactGone }

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
	inboxLaneKind              = "inbox"
	outboxLaneKind             = "outbox"
	defaultLeaseDuration       = time.Minute
	task5PayloadLimit          = 2 * 1024 * 1024
	task5NonceLimit            = 12
	task5PayloadScrubBatchSize = 128
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
func validateTask5OpaquePayload(ciphertext, nonce []byte, keyID string) error {
	if len(ciphertext) > task5PayloadLimit {
		return &OversizeError{Bound: "encrypted payload", Limit: task5PayloadLimit, Actual: len(ciphertext)}
	}
	if len(ciphertext) == 0 || len(nonce) == 0 || len(nonce) > task5NonceLimit || strings.TrimSpace(keyID) == "" {
		return ErrInvalidMetadata
	}
	return nil
}
func validateTask5ArtifactOpaquePayload(ciphertext, nonce []byte, keyID string) error {
	if len(ciphertext) > MaxArtifactBytes+16 {
		return &OversizeError{Bound: "encrypted artifact bytes", Limit: MaxArtifactBytes + 16, Actual: len(ciphertext)}
	}
	if len(ciphertext) == 0 || len(nonce) == 0 || len(nonce) > task5NonceLimit || strings.TrimSpace(keyID) == "" {
		return ErrInvalidMetadata
	}
	return nil
}
func task5PayloadKeyID(update InboxUpdate) string {
	if update.PayloadEncryptionKeyID != "" {
		return update.PayloadEncryptionKeyID
	}
	return update.DigestKeyID
}
func task5EffectPayloadKeyID(effect NewEffect) string {
	if effect.PayloadEncryptionKeyID != "" {
		return effect.PayloadEncryptionKeyID
	}
	return effect.DigestKeyID
}
func task5ValidateKeyFields(source KeySource, legacy, payload string) error {
	if source != nil && legacy != "" {
		return ErrInvalidMetadata
	}
	if source != nil && payload == "" {
		return ErrInvalidMetadata
	}
	return nil
}
func task5ContentDigestKeyID(updateKey, explicit string) string {
	if explicit != "" {
		return explicit
	}
	return updateKey
}
func task5PayloadVersion(version uint64) uint64 {
	if version == 0 {
		return 1
	}
	return version
}
func (s *GORMStore) task5CanonicalDigestKeyID(ctx context.Context, explicit string) (string, error) {
	if s.keySource == nil {
		return explicit, nil
	}
	indexID, _, err := keySourceIndex(ctx, s.keySource)
	if err != nil {
		return "", err
	}
	if explicit != "" && explicit != indexID {
		return "", ErrAuthenticationFailed
	}
	return indexID, nil
}
func (s *GORMStore) task5ValidatePayload(ctx context.Context, db *gorm.DB, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string, artifact bool) error {
	if len(ciphertext) == 0 && len(nonce) == 0 {
		if s.keySource != nil {
			return ErrAuthenticationFailed
		}
		return nil
	}
	limitErr := validateTask5OpaquePayload(ciphertext, nonce, keyID)
	if artifact {
		limitErr = validateTask5ArtifactOpaquePayload(ciphertext, nonce, keyID)
	}
	if limitErr != nil {
		return limitErr
	}
	if s.keySource == nil {
		return nil
	}
	if err := s.requireA6BoundCodec(); err != nil {
		return err
	}
	if err := s.validateA6KeyID(ctx, db, keyID); err != nil {
		return err
	}
	if _, err := openBoundPayload(ctx, s.codec, domain, identity, owner, version, ciphertext, nonce, keyID); err != nil {
		return err
	}
	return nil
}
func task5StableDigestEqual(storedDigest []byte, storedKey string, digest []byte, key string) bool {
	if storedKey != key || len(storedDigest) == 0 || len(digest) == 0 {
		return false
	}
	return bytes.Equal(storedDigest, digest)
}

func hasBoundPayloadCodec(codec any) bool {
	_, encryptOK := codec.(interface {
		EncryptBound(ctx context.Context, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error)
	})
	_, decryptOK := codec.(interface {
		DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error)
	})
	return encryptOK && decryptOK
}

func (s *GORMStore) requireA6BoundCodec() error {
	if s == nil || s.keySource == nil {
		return nil
	}
	if !hasBoundPayloadCodec(s.codec) {
		return ErrEncryptionUnavailable
	}
	return nil
}

func task5InboxDuplicate(row inboxMessageRow, update InboxUpdate) bool {
	if row.EndpointID != update.EndpointID || row.ProviderEventKey != update.ProviderEventKey || !bytes.Equal(row.LaneHMAC, update.LaneHMAC) {
		return false
	}
	payloadKeyID := task5PayloadKeyID(update)
	digestKeyID := task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID)
	if len(row.ContentDigest) == 0 || len(update.ContentDigest) == 0 {
		return len(row.ContentDigest) == 0 && len(update.ContentDigest) == 0 &&
			len(row.PayloadCiphertext) > 0 && bytes.Equal(row.PayloadCiphertext, update.PayloadCiphertext) &&
			len(row.PayloadNonce) > 0 && bytes.Equal(row.PayloadNonce, update.PayloadNonce) &&
			row.EncryptionKeyID == payloadKeyID
	}
	storedKey := row.ContentDigestKeyID
	if storedKey == "" {
		storedKey = row.EncryptionKeyID
	}
	return task5StableDigestEqual(row.ContentDigest, storedKey, update.ContentDigest, digestKeyID)
}

func task5EffectDuplicate(row outboxEffectRow, update NewEffect) bool {
	if row.EndpointID != update.EndpointID || !bytes.Equal(row.LaneHMAC, update.LaneHMAC) || row.EffectClass != update.EffectType || row.RiskClass != update.RiskClass {
		return false
	}
	payloadKeyID := task5EffectPayloadKeyID(update)
	digestKeyID := task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID)
	if len(row.ContentDigest) == 0 || len(update.ContentDigest) == 0 {
		return len(row.ContentDigest) == 0 && len(update.ContentDigest) == 0 &&
			len(row.PayloadCiphertext) > 0 && bytes.Equal(row.PayloadCiphertext, update.PayloadCiphertext) &&
			len(row.PayloadNonce) > 0 && bytes.Equal(row.PayloadNonce, update.PayloadNonce) &&
			row.EncryptionKeyID == payloadKeyID
	}
	storedKey := row.ContentDigestKeyID
	if storedKey == "" {
		storedKey = row.EncryptionKeyID
	}
	return task5StableDigestEqual(row.ContentDigest, storedKey, update.ContentDigest, digestKeyID)
}

func task5ReleaseLane(tx *gorm.DB, kind string, lane []byte, sequence uint64) error {
	if sequence == 0 || sequence == maxUint64 {
		return errors.New("eventstore: invalid lane sequence")
	}
	q := tx.Model(&laneHeadRow{}).Where("kind = ? AND lane_hmac = ? AND next_sequence = ?", kind, lane, sequence+1).Update("next_sequence", sequence)
	if q.Error != nil || q.RowsAffected != 1 {
		return errors.New("eventstore: release lane sequence failed")
	}
	return nil
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
	if err := markFreshInitializedTx(tx); err != nil {
		return err
	}
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

func task5RejectQueueCandidate(tx *gorm.DB, kind string, lane []byte, now time.Time, failures []task5QueueFailure, expiredObserved bool) error {
	if err := refreshQueueLane(tx, kind, lane, now); err != nil {
		return err
	}
	if err := task5CommitQueueFailures(tx, failures); err != nil {
		return err
	}
	if expiredObserved {
		return ErrPayloadExpired
	}
	return ErrNotFound
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
	head = laneHeadRow{Kind: kind, LaneHMAC: task5Copy(lane), NextSequence: 1, SchedulingVersion: queueSchedulingVersion, UpdatedAt: now}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&head).Error; err != nil {
		return laneHeadRow{}, errors.New("eventstore: materialize lane head failed")
	}
	if err := locked(tx).Where("kind = ? AND lane_hmac = ?", kind, lane).First(&head).Error; err != nil {
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
	if sequence == 0 || sequence >= maxPersistedVersion {
		return 0, ErrVersionExhausted
	}
	nextSequence, nextErr := nextVersion(sequence)
	if nextErr != nil {
		return 0, nextErr
	}
	head.NextSequence = nextSequence
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
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return CommitResult{}, readyErr
	}
	defer func() {
		if err == nil && len(result.InboxIDs) > 0 {
			s.signalInboxWork()
		}
	}()
	if len(update.SubjectKey) != 0 && len(update.SubjectKey) != 32 {
		return CommitResult{}, ErrInvalidMetadata
	}
	if update.InboxID == "" {
		update.InboxID, err = s.task5ID()
		if err != nil {
			return CommitResult{}, err
		}
	}
	if update.ExpectedVersion != 0 || update.Version != 0 {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.EndpointID == "" || update.ProviderEventKey == "" || len(update.LaneHMAC) == 0 {
		return CommitResult{}, ErrParticipantFailure
	}
	if keyErr := task5ValidateKeyFields(s.keySource, update.DigestKeyID, update.PayloadEncryptionKeyID); keyErr != nil {
		return CommitResult{}, keyErr
	}
	payloadKeyID := task5PayloadKeyID(update)
	digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, update.ContentDigestKeyID)
	if digestErr != nil {
		return CommitResult{}, digestErr
	}
	update.ContentDigestKeyID = digestKeyID
	if payloadErr := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); payloadErr != nil {
		return CommitResult{}, payloadErr
	}
	if update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() ||
		!update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" ||
		update.Resolution != "" || !update.ResolutionAt.IsZero() {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Status == "" {
		update.Status = InboxStatusPending
	}
	if update.Status != InboxStatusPending {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.WorkflowID != "" {
		return CommitResult{}, ErrInvalidTransition
	}
	now := s.task5Now()
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
	var fencedSubject int64
	if len(update.SubjectKey) > 0 {
		if queryErr := tx.Model(&subjectFenceRow{}).Where("subject_key = ? AND scope = ?", update.SubjectKey, "group").Count(&fencedSubject).Error; queryErr != nil {
			task5Rollback(tx)
			return CommitResult{}, ErrParticipantFailure
		}
	} else {
		if queryErr := tx.Model(&subjectFenceRow{}).Where("scope = ?", "group").Count(&fencedSubject).Error; queryErr != nil {
			task5Rollback(tx)
			return CommitResult{}, ErrParticipantFailure
		}
	}
	if fencedSubject > 0 {
		task5Rollback(tx)
		return CommitResult{}, ErrInvalidTransition
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	queueRefs := make([]queueLaneRef, 0, 2)
	validatePayload := func() error {
		if payloadErr := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); payloadErr != nil {
			return payloadErr
		}
		if s.keySource == nil {
			return nil
		}
		if codecErr := s.requireA6BoundCodec(); codecErr != nil {
			return codecErr
		}
		if keyErr := s.validateA6KeyID(ctx, tx, payloadKeyID); keyErr != nil {
			return keyErr
		}
		if _, decryptErr := openBoundPayload(ctx, s.codec, "inbox/v1", update.InboxID, update.EndpointID, task5PayloadVersion(update.PayloadVersion), update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); decryptErr != nil {
			return ErrAuthenticationFailed
		}
		return nil
	}
	var existing inboxMessageRow
	q := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&existing)
	if q.Error != nil {
		if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
			return CommitResult{}, errors.New("eventstore: dedupe lookup failed")
		}
		goto insertExpiredReplacement
	}
	if existing.PayloadExpiresAt == nil || existing.PayloadExpiresAt.After(now) {
		if !update.PayloadExpiresAt.IsZero() {
			if !update.PayloadExpiresAt.After(now) {
				return CommitResult{}, ErrPayloadExpired
			}
			if update.PayloadExpiresAt.After(now.Add(InboxPayloadTTL)) {
				return CommitResult{}, ErrInvalidTTL
			}
		}
		if err = validatePayload(); err != nil {
			return CommitResult{}, err
		}
		if !task5InboxDuplicate(existing, update) {
			return CommitResult{}, ErrConflict
		}
		result = CommitResult{InboxIDs: []string{existing.InboxID}, OrderingSequence: existing.OrderingSequence, Version: existing.Version, Deduplicated: true, Idempotent: true}
		if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return result, nil
	}
	if existing.Status == InboxStatusCallbackStarted || existing.Status == InboxStatusAmbiguous {
		return CommitResult{}, ErrPayloadExpired
	}
	if update.AllowExpiredDedupe {
		deleteResult := tx.Where("inbox_id = ? AND version = ?", existing.InboxID, existing.Version).Delete(&inboxMessageRow{})
		if deleteResult.Error != nil {
			return CommitResult{}, deleteResult.Error
		}
		if deleteResult.RowsAffected != 1 {
			return CommitResult{}, ErrConflict
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: existing.LaneHMAC})
		goto insertExpiredReplacement
	}
	if inboxUnresolved(existing.Status) {
		original := existing
		if err = task5ScrubInbox(tx, &existing, now, false); err != nil {
			return CommitResult{}, err
		}
		if err = refreshQueueLaneRefs(tx, append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: existing.LaneHMAC}), now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		if !task5InboxDuplicate(original, update) {
			return CommitResult{}, ErrConflict
		}
	}
	return CommitResult{}, ErrPayloadExpired
insertExpiredReplacement:
	if update.PayloadExpiresAt.IsZero() {
		update.PayloadExpiresAt = now.Add(InboxPayloadTTL)
	} else if !update.PayloadExpiresAt.After(now) {
		return CommitResult{}, ErrPayloadExpired
	} else if update.PayloadExpiresAt.After(now.Add(InboxPayloadTTL)) {
		return CommitResult{}, ErrInvalidTTL
	}
	if err = validatePayload(); err != nil {
		return CommitResult{}, err
	}
	sequence, err := task5AllocateLane(tx, inboxLaneKind, update.LaneHMAC, now)
	if err != nil {
		return CommitResult{}, err
	}
	row := inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, Status: InboxStatusPending, Version: 1, PayloadVersion: task5PayloadVersion(update.PayloadVersion), PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), PayloadPresent: true, SchedulingVersion: queueSchedulingVersion, EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID), PayloadExpiresAt: task5Ptr(update.PayloadExpiresAt), WorkflowID: update.WorkflowID}
	row.SubjectKey = task5Copy(update.SubjectKey)
	if q = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row); q.Error != nil {
		return CommitResult{}, errors.New("eventstore: insert inbox failed")
	}
	if q.RowsAffected == 0 {
		var duplicate inboxMessageRow
		if lookup := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&duplicate); lookup.Error == nil {
			if !task5InboxDuplicate(duplicate, update) {
				return CommitResult{}, ErrConflict
			}
			if err = task5ReleaseLane(tx, inboxLaneKind, update.LaneHMAC, sequence); err != nil {
				return CommitResult{}, err
			}
			result = CommitResult{InboxIDs: []string{duplicate.InboxID}, OrderingSequence: duplicate.OrderingSequence, Version: duplicate.Version, Deduplicated: true, Idempotent: true}
			if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
				return CommitResult{}, err
			}
			if err = task5Commit(tx); err != nil {
				return CommitResult{}, err
			}
			return result, nil
		}
		return CommitResult{}, ErrConflict
	}
	queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: row.LaneHMAC})
	if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
		return CommitResult{}, err
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, OrderingSequence: sequence, Version: 1}, nil
}

func (s *GORMStore) ClaimInbox(ctx context.Context, req InboxClaimRequest) (lease InboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return InboxLease{}, readyErr
	}
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return InboxLease{}, lockErr
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	var failures []task5QueueFailure
	queueRefs := make([]queueLaneRef, 0, task5PayloadScrubBatchSize)
	if req.RecoverExpiredCallbackStarted {
		var recoveredRows []inboxMessageRow
		recoveredQuery := locked(tx).Where("status = ? AND lease_expiry IS NOT NULL AND lease_expiry <= ?", InboxStatusCallbackStarted, now).Order("lease_expiry ASC, inbox_id ASC").Limit(task5PayloadScrubBatchSize).Find(&recoveredRows)
		if recoveredQuery.Error != nil {
			return InboxLease{}, errors.New("eventstore: recover callback-started query failed")
		}
		for i := range recoveredRows {
			if err = task5RecoverExpiredCallbackStarted(tx, &recoveredRows[i], now); err != nil {
				return InboxLease{}, err
			}
			failures = append(failures, task5QueueFailure{
				queue: "inbox", itemID: recoveredRows[i].InboxID, status: recoveredRows[i].Status,
				reason: recoveredRows[i].ResolutionReason, version: recoveredRows[i].Version,
			})
			queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: recoveredRows[i].LaneHMAC})
		}
	}
	var expiredCandidates []task5ExpiredPayloadCandidate
	expiredQuery := inboxExpiredPayloadCandidates(tx, now, task5PayloadScrubBatchSize).Scan(&expiredCandidates)
	if expiredQuery.Error != nil {
		return InboxLease{}, errors.New("eventstore: scrub inbox query failed")
	}
	expiredRows, loadExpiredErr := loadLockedInboxPayloadCandidates(tx, expiredCandidates)
	if loadExpiredErr != nil {
		return InboxLease{}, errors.New("eventstore: lock scrub inbox candidates failed")
	}
	expiredObserved := len(expiredRows) > 0
	for i := range expiredRows {
		if req.TerminalizeExpired {
			wasIsolated := expiredRows[i].Status == InboxStatusAmbiguous
			if err = task5TerminalizeExpiredInbox(tx, &expiredRows[i], now); err != nil {
				return InboxLease{}, err
			}
			if !wasIsolated {
				failures = append(failures, task5QueueFailure{
					queue: "inbox", itemID: expiredRows[i].InboxID, status: expiredRows[i].Status,
					reason: expiredRows[i].ResolutionReason, version: expiredRows[i].Version,
				})
			}
		} else if err = task5ScrubInbox(tx, &expiredRows[i], now, true); err != nil {
			return InboxLease{}, err
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: expiredRows[i].LaneHMAC})
	}
	if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
		return InboxLease{}, err
	}
	commitObservedScrub := func(candidateErr error) error {
		if !expiredObserved && len(failures) == 0 {
			return candidateErr
		}
		if refreshErr := refreshQueueLaneRefs(tx, queueRefs, now); refreshErr != nil {
			return refreshErr
		}
		if commitErr := task5CommitQueueFailures(tx, failures); commitErr != nil {
			return commitErr
		}
		return candidateErr
	}
	var candidate struct {
		InboxID string `gorm:"column:inbox_id"`
	}
	q := scanInboxClaimable(tx, now, &candidate)
	if q.Error != nil {
		return InboxLease{}, commitObservedScrub(errors.New("eventstore: claim inbox query failed"))
	}
	if q.RowsAffected == 0 {
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return InboxLease{}, err
		}
		if expiredObserved {
			return InboxLease{}, ErrPayloadExpired
		}
		return InboxLease{}, ErrNotFound
	}
	var row inboxMessageRow
	q = locked(tx).Where("inbox_id = ?", candidate.InboxID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return InboxLease{}, err
		}
		if expiredObserved {
			return InboxLease{}, ErrPayloadExpired
		}
		return InboxLease{}, ErrNotFound
	}
	if q.Error != nil {
		return InboxLease{}, commitObservedScrub(errors.New("eventstore: claim inbox query failed"))
	}
	if row.Status != InboxStatusPending && row.Status != InboxStatusLeased {
		return InboxLease{}, task5RejectQueueCandidate(tx, inboxLaneKind, row.LaneHMAC, now, failures, expiredObserved)
	}
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if req.TerminalizeExpired {
			if err = task5TerminalizeExpiredInbox(tx, &row, now); err != nil {
				return InboxLease{}, err
			}
			failures = append(failures, task5QueueFailure{
				queue: "inbox", itemID: row.InboxID, status: row.Status,
				reason: row.ResolutionReason, version: row.Version,
			})
		} else if len(row.PayloadCiphertext) > 0 || len(row.PayloadNonce) > 0 {
			if err = task5ScrubInbox(tx, &row, now, true); err != nil {
				return InboxLease{}, err
			}
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: row.LaneHMAC})
		if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
			return InboxLease{}, err
		}
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return InboxLease{}, err
		}
		return InboxLease{}, ErrPayloadExpired
	}
	if row.Status == InboxStatusLeased && row.LeaseExpiry != nil && row.LeaseExpiry.After(now) {
		return InboxLease{}, task5RejectQueueCandidate(tx, inboxLaneKind, row.LaneHMAC, now, failures, expiredObserved)
	}
	if err = s.task5ValidatePayload(ctx, tx, "inbox/v1", row.InboxID, row.EndpointID, task5PayloadVersion(row.PayloadVersion), row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID, false); err != nil {
		if req.QuarantinePayloadErrors && errors.Is(err, ErrAuthenticationFailed) {
			if quarantineErr := task5QuarantineInboxPayload(tx, &row, now, "payload-authentication-failed"); quarantineErr != nil {
				return InboxLease{}, quarantineErr
			}
			failure := task5QueueFailure{
				queue: "inbox", itemID: row.InboxID, status: row.Status,
				reason: row.ResolutionReason, version: row.Version,
			}
			queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: row.LaneHMAC})
			if refreshErr := refreshQueueLaneRefs(tx, queueRefs, now); refreshErr != nil {
				return InboxLease{}, refreshErr
			}
			if commitErr := task5CommitQueueFailures(tx, append(failures, failure)); commitErr != nil {
				return InboxLease{}, commitErr
			}
			return InboxLease{}, err
		}
		return InboxLease{}, commitObservedScrub(err)
	}
	if row.LeaseEpoch >= maxPersistedVersion {
		return InboxLease{}, commitObservedScrub(ErrVersionExhausted)
	}
	attempt, idErr := s.task5ID()
	if idErr != nil {
		return InboxLease{}, commitObservedScrub(idErr)
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	version, vErr := nextVersion(row.Version)
	if vErr != nil {
		return InboxLease{}, commitObservedScrub(vErr)
	}
	updates := map[string]any{"status": InboxStatusLeased, "version": version, "lease_owner": req.WorkerID, "lease_epoch": row.LeaseEpoch + 1, "lease_expiry": expires, "attempt_id": attempt}
	claimQuery := tx.Model(&inboxMessageRow{}).
		Where("inbox_id = ? AND version = ? AND status = ?", row.InboxID, row.Version, row.Status)
	if row.Status == InboxStatusLeased {
		if row.LeaseExpiry == nil {
			claimQuery = claimQuery.Where("lease_expiry IS NULL")
		} else {
			claimQuery = claimQuery.Where("lease_expiry <= ?", now)
		}
	}
	q = claimQuery.Updates(updates)
	if q.Error != nil {
		return InboxLease{}, commitObservedScrub(errors.New("eventstore: claim inbox failed"))
	}
	if q.RowsAffected != 1 {
		return InboxLease{}, commitObservedScrub(ErrStaleLease)
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID = InboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt
	lease.Update = inboxUpdateFromRow(row)
	queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: row.LaneHMAC})
	if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
		return InboxLease{}, err
	}
	if err = task5CommitQueueFailures(tx, failures); err != nil {
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
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
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubInbox(tx, &row, now, true); err != nil {
			return InboxLease{}, err
		}
		if err = refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); err != nil {
			return InboxLease{}, err
		}
		if err = task5Commit(tx); err != nil {
			return InboxLease{}, err
		}
		return InboxLease{}, ErrPayloadExpired
	}
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
	if err = refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); err != nil {
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
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
	allowExpiredAmbiguous := task5AllowsExpiredAmbiguous(row, update)
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) && !allowExpiredAmbiguous {
		if err = task5ScrubInbox(tx, &row, now, false); err != nil {
			return CommitResult{}, err
		}
		if err = refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{}, ErrPayloadExpired
	}
	if update.ExpectedVersion != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if update.Version != 0 && update.Version != row.Version {
		return CommitResult{}, participantConflict(tableInboxMessages)
	}
	if row.Status == InboxStatusFailed || row.Status == InboxStatusConfirmedConsumed || row.Status == InboxStatusSkipped {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.EndpointID != "" || update.ProviderEventKey != "" || len(update.LaneHMAC) > 0 || update.OrderingSequence != 0 ||
		len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.DigestKeyID != "" ||
		update.PayloadVersion != 0 || update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || !update.PayloadExpiresAt.IsZero() ||
		update.WorkflowID != "" || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || !update.ResolutionAt.IsZero() {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Status != InboxStatusLeased && update.Status != InboxStatusCallbackStarted && row.Status != InboxStatusLeased && row.Status != InboxStatusCallbackStarted && (update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero()) {
		return CommitResult{}, ErrStaleLease
	}
	if update.Status != InboxStatusPending || row.Status != InboxStatusPending {
		if !allowExpiredAmbiguous && (!task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now)) {
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
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ResolutionAt = task5Ptr(now)
	}
	updateQuery := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, update.ExpectedVersion)
	if !allowExpiredAmbiguous {
		updateQuery = updateQuery.Where("(lease_expiry IS NULL OR lease_expiry > ?)", now)
	}
	q = updateQuery.Updates(inboxMap(row))
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: update inbox failed")
	}
	if q.RowsAffected != 1 {
		return CommitResult{}, ErrStaleLease
	}
	if err = refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); err != nil {
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
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
	if (row.Status == InboxStatusPending || row.Status == InboxStatusLeased) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubInbox(tx, &row, now, false); err != nil {
			return CommitResult{}, err
		}
		if err = refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{}, ErrPayloadExpired
	}
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
		if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
			if e := task5ScrubInbox(tx, &row, now, false); e != nil {
				return CommitResult{}, e
			}
			if e := refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); e != nil {
				return CommitResult{}, e
			}
			if e := task5Commit(tx); e != nil {
				return CommitResult{}, e
			}
			return CommitResult{}, ErrPayloadExpired
		}
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
	if err = refreshQueueLane(tx, inboxLaneKind, row.LaneHMAC, now); err != nil {
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
	if len(effect.SubjectKey) != 0 && len(effect.SubjectKey) != 32 {
		return CommitResult{}, ErrInvalidMetadata
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
	if effect.EndpointID == "" || len(effect.LaneHMAC) == 0 || effect.EffectType == "" {
		return CommitResult{}, ErrParticipantFailure
	}
	if keyErr := task5ValidateKeyFields(s.keySource, effect.DigestKeyID, effect.PayloadEncryptionKeyID); keyErr != nil {
		return CommitResult{}, keyErr
	}
	payloadKeyID := task5EffectPayloadKeyID(effect)
	digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, effect.ContentDigestKeyID)
	if digestErr != nil {
		return CommitResult{}, digestErr
	}
	effect.ContentDigestKeyID = digestKeyID
	if effect.LeaseOwner != "" || effect.LeaseEpoch != 0 || effect.AttemptID != "" || !effect.LeaseExpiresAt.IsZero() ||
		!effect.DispatchedAt.IsZero() || !effect.CompletedAt.IsZero() || effect.ProviderMessageID != "" ||
		effect.ResultCode != "" || effect.ErrorCode != "" || effect.RetryCount != 0 || effect.PrincipalID != "" ||
		effect.Reason != "" || effect.Resolution != "" || !effect.ResolutionAt.IsZero() {
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
	payloadVersion := task5PayloadVersion(effect.PayloadVersion)
	now := s.task5Now()
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
	var fencedSubject int64
	if len(effect.SubjectKey) > 0 {
		if queryErr := tx.Model(&subjectFenceRow{}).Where("subject_key = ? AND scope = ?", effect.SubjectKey, "group").Count(&fencedSubject).Error; queryErr != nil {
			task5Rollback(tx)
			return CommitResult{}, ErrParticipantFailure
		}
	} else {
		if queryErr := tx.Model(&subjectFenceRow{}).Where("scope = ?", "group").Count(&fencedSubject).Error; queryErr != nil {
			task5Rollback(tx)
			return CommitResult{}, ErrParticipantFailure
		}
	}
	if fencedSubject > 0 {
		task5Rollback(tx)
		return CommitResult{}, ErrInvalidTransition
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	validatePayload := func() error {
		if payloadErr := validateTask5OpaquePayload(effect.PayloadCiphertext, effect.PayloadNonce, payloadKeyID); payloadErr != nil {
			return payloadErr
		}
		if s.keySource == nil {
			return nil
		}
		if codecErr := s.requireA6BoundCodec(); codecErr != nil {
			return codecErr
		}
		if keyErr := s.validateA6KeyID(ctx, tx, payloadKeyID); keyErr != nil {
			return keyErr
		}
		if _, decryptErr := openBoundPayload(ctx, s.codec, "outbox/v1", effect.EffectID, effect.EndpointID, payloadVersion, effect.PayloadCiphertext, effect.PayloadNonce, payloadKeyID); decryptErr != nil {
			return ErrAuthenticationFailed
		}
		return nil
	}
	var existing outboxEffectRow
	lookup := locked(tx).Where("effect_id = ?", effect.EffectID).First(&existing)
	if lookup.Error == nil {
		if outboxUnresolved(existing.Status) && existing.PayloadExpiresAt != nil && !existing.PayloadExpiresAt.After(now) {
			original := existing
			failure, expireErr := s.task5ExpireOutbox(ctx, tx, &existing, now)
			if expireErr != nil {
				return CommitResult{}, expireErr
			}
			if err = refreshQueueLane(tx, outboxLaneKind, existing.LaneHMAC, now); err != nil {
				return CommitResult{}, err
			}
			if err = task5CommitQueueFailures(tx, []task5QueueFailure{failure}); err != nil {
				return CommitResult{}, err
			}
			if !task5EffectDuplicate(original, effect) {
				return CommitResult{}, ErrConflict
			}
			return CommitResult{}, ErrPayloadExpired
		}
		if !effect.PayloadExpiresAt.IsZero() {
			if !effect.PayloadExpiresAt.After(now) {
				return CommitResult{}, ErrPayloadExpired
			}
			if effect.PayloadExpiresAt.After(now.Add(InboxPayloadTTL)) {
				return CommitResult{}, ErrInvalidTTL
			}
		}
		if err = validatePayload(); err != nil {
			return CommitResult{}, err
		}
		if !task5EffectDuplicate(existing, effect) {
			return CommitResult{}, ErrConflict
		}
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{EffectIDs: []string{existing.EffectID}, OrderingSequence: existing.OrderingSequence, Version: existing.Version, Deduplicated: true, Idempotent: true}, nil
	}
	if !errors.Is(lookup.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, errors.New("eventstore: lookup outbox failed")
	}
	if effect.PayloadExpiresAt.IsZero() {
		effect.PayloadExpiresAt = now.Add(InboxPayloadTTL)
	} else if !effect.PayloadExpiresAt.After(now) {
		return CommitResult{}, ErrPayloadExpired
	} else if effect.PayloadExpiresAt.After(now.Add(InboxPayloadTTL)) {
		return CommitResult{}, ErrInvalidTTL
	}
	if err = validatePayload(); err != nil {
		return CommitResult{}, err
	}
	seq, err := task5AllocateLane(tx, outboxLaneKind, effect.LaneHMAC, now)
	if err != nil {
		return CommitResult{}, err
	}
	row := outboxEffectRow{EffectID: effect.EffectID, Version: 1, PayloadVersion: payloadVersion, EndpointID: effect.EndpointID, LaneHMAC: task5Copy(effect.LaneHMAC), OrderingSequence: seq, EffectClass: effect.EffectType, RiskClass: effect.RiskClass, Status: OutboxStatusPending, PayloadCiphertext: task5Copy(effect.PayloadCiphertext), PayloadNonce: task5Copy(effect.PayloadNonce), PayloadPresent: true, SchedulingVersion: queueSchedulingVersion, EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(effect.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(effect.DigestKeyID, effect.ContentDigestKeyID), DeadlineAt: task5Ptr(effect.DeadlineAt), NextAttemptAt: task5Ptr(effect.NextAttemptAt), PayloadExpiresAt: task5Ptr(effect.PayloadExpiresAt), CreatedAt: now}
	row.SubjectKey = task5Copy(effect.SubjectKey)
	q := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if q.Error != nil {
		return CommitResult{}, errors.New("eventstore: insert outbox failed")
	}
	if q.RowsAffected == 0 {
		var duplicate outboxEffectRow
		if lookup := locked(tx).Where("effect_id = ?", effect.EffectID).First(&duplicate); lookup.Error == nil {
			if !task5EffectDuplicate(duplicate, effect) {
				return CommitResult{}, ErrConflict
			}
			if err = task5ReleaseLane(tx, outboxLaneKind, effect.LaneHMAC, seq); err != nil {
				return CommitResult{}, err
			}
			result = CommitResult{EffectIDs: []string{duplicate.EffectID}, OrderingSequence: duplicate.OrderingSequence, Version: duplicate.Version, Deduplicated: true, Idempotent: true}
			if err = task5Commit(tx); err != nil {
				return CommitResult{}, err
			}
			return result, nil
		}
		return CommitResult{}, ErrConflict
	}
	if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
		return CommitResult{}, err
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, OrderingSequence: seq, Version: 1}, nil
}

func (s *GORMStore) ClaimOutbox(ctx context.Context, req OutboxClaimRequest) (lease OutboxLease, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return OutboxLease{}, readyErr
	}
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
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return OutboxLease{}, lockErr
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	var expiredCandidates []task5ExpiredPayloadCandidate
	expiredQuery := outboxExpiredPayloadCandidates(tx, now, task5PayloadScrubBatchSize).Scan(&expiredCandidates)
	if expiredQuery.Error != nil {
		return OutboxLease{}, errors.New("eventstore: scrub outbox query failed")
	}
	expiredRows, loadExpiredErr := loadLockedOutboxPayloadCandidates(tx, expiredCandidates)
	if loadExpiredErr != nil {
		return OutboxLease{}, errors.New("eventstore: lock scrub outbox candidates failed")
	}
	expiredObserved := len(expiredRows) > 0
	var failures []task5QueueFailure
	queueRefs := make([]queueLaneRef, 0, len(expiredRows)+1)
	for i := range expiredRows {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &expiredRows[i], now)
		if expireErr != nil {
			return OutboxLease{}, expireErr
		}
		if failure.itemID != "" {
			failures = append(failures, failure)
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: outboxLaneKind, lane: expiredRows[i].LaneHMAC})
	}
	if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
		return OutboxLease{}, err
	}
	commitObservedScrub := func(candidateErr error) error {
		if !expiredObserved {
			return candidateErr
		}
		if refreshErr := refreshQueueLaneRefs(tx, queueRefs, now); refreshErr != nil {
			return refreshErr
		}
		if commitErr := task5CommitQueueFailures(tx, failures); commitErr != nil {
			return commitErr
		}
		return candidateErr
	}
	var candidate struct {
		EffectID string `gorm:"column:effect_id"`
	}
	q := scanOutboxClaimable(tx, now, &candidate)
	if q.Error != nil {
		return OutboxLease{}, commitObservedScrub(errors.New("eventstore: claim outbox query failed"))
	}
	if q.RowsAffected == 0 {
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return OutboxLease{}, err
		}
		if expiredObserved {
			return OutboxLease{}, ErrPayloadExpired
		}
		return OutboxLease{}, ErrNotFound
	}
	var row outboxEffectRow
	q = locked(tx).Where("effect_id = ?", candidate.EffectID).First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return OutboxLease{}, err
		}
		if expiredObserved {
			return OutboxLease{}, ErrPayloadExpired
		}
		return OutboxLease{}, ErrNotFound
	}
	if q.Error != nil {
		return OutboxLease{}, commitObservedScrub(errors.New("eventstore: claim outbox query failed"))
	}
	if row.Status != OutboxStatusPending && row.Status != OutboxStatusLeased && row.Status != OutboxStatusDispatched {
		return OutboxLease{}, task5RejectQueueCandidate(tx, outboxLaneKind, row.LaneHMAC, now, failures, expiredObserved)
	}
	if (row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched) && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now) && row.DispatchedAt != nil && row.RiskClass != RiskProviderIdempotent {
		failure, isolateErr := s.task5IsolateOutbox(ctx, tx, &row, now, OutboxStatusAmbiguous, "dispatch-lease-expired", "expired-after-dispatch")
		if isolateErr != nil {
			return OutboxLease{}, commitObservedScrub(isolateErr)
		}
		failures = append(failures, failure)
		queueRefs = append(queueRefs, queueLaneRef{kind: outboxLaneKind, lane: row.LaneHMAC})
		if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrNotFound
	}
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			return OutboxLease{}, expireErr
		}
		if failure.itemID != "" {
			failures = append(failures, failure)
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: outboxLaneKind, lane: row.LaneHMAC})
		if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5CommitQueueFailures(tx, failures); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrPayloadExpired
	}
	claimReady := false
	switch row.Status {
	case OutboxStatusPending:
		claimReady = row.NextAttemptAt == nil || !row.NextAttemptAt.After(now)
	case OutboxStatusLeased:
		claimReady = row.LeaseExpiry == nil || !row.LeaseExpiry.After(now)
	case OutboxStatusDispatched:
		claimReady = row.DispatchedAt != nil && row.RiskClass == RiskProviderIdempotent &&
			row.LeaseExpiry != nil && !row.LeaseExpiry.After(now)
	}
	if !claimReady {
		return OutboxLease{}, task5RejectQueueCandidate(tx, outboxLaneKind, row.LaneHMAC, now, failures, expiredObserved)
	}
	if err = s.task5ValidatePayload(ctx, tx, "outbox/v1", row.EffectID, row.EndpointID, task5PayloadVersion(row.PayloadVersion), row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID, false); err != nil {
		var oversized *OversizeError
		if !errors.Is(err, ErrAuthenticationFailed) && !errors.Is(err, ErrInvalidMetadata) && !errors.As(err, &oversized) {
			return OutboxLease{}, commitObservedScrub(err)
		}
		payloadErr := err
		status := OutboxStatusFailed
		if row.DispatchedAt != nil {
			status = OutboxStatusAmbiguous
		}
		failure, isolateErr := s.task5IsolateOutbox(ctx, tx, &row, now, status, "payload-invalid", "payload-validation-failed")
		if isolateErr != nil {
			return OutboxLease{}, isolateErr
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: outboxLaneKind, lane: row.LaneHMAC})
		if refreshErr := refreshQueueLaneRefs(tx, queueRefs, now); refreshErr != nil {
			return OutboxLease{}, refreshErr
		}
		if commitErr := task5CommitQueueFailures(tx, append(failures, failure)); commitErr != nil {
			return OutboxLease{}, commitErr
		}
		return OutboxLease{}, payloadErr
	}
	if row.LeaseEpoch >= maxPersistedVersion {
		return OutboxLease{}, commitObservedScrub(ErrVersionExhausted)
	}
	attempt, idErr := s.task5ID()
	if idErr != nil {
		return OutboxLease{}, commitObservedScrub(idErr)
	}
	version, vErr := nextVersion(row.Version)
	if vErr != nil {
		return OutboxLease{}, commitObservedScrub(vErr)
	}
	expires := now.Add(task5LeaseDuration(req.LeaseDuration))
	retry := row.RetryCount
	if (row.Status == OutboxStatusLeased && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now)) ||
		(row.Status == OutboxStatusDispatched && row.DispatchedAt != nil && row.RiskClass == RiskProviderIdempotent && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now)) {
		if retry < math.MaxUint32 {
			retry++
		}
	}
	updates := map[string]any{"status": OutboxStatusLeased, "version": version, "lease_owner": req.WorkerID, "lease_epoch": row.LeaseEpoch + 1, "lease_expiry": expires, "attempt_id": attempt, "retry_count": retry}
	claimQuery := tx.Model(&outboxEffectRow{}).
		Where("effect_id = ? AND version = ? AND status = ?", row.EffectID, row.Version, row.Status)
	switch row.Status {
	case OutboxStatusPending:
		if row.NextAttemptAt == nil {
			claimQuery = claimQuery.Where("next_attempt_at IS NULL")
		} else {
			claimQuery = claimQuery.Where("next_attempt_at <= ?", now)
		}
	case OutboxStatusLeased:
		if row.LeaseExpiry == nil {
			claimQuery = claimQuery.Where("lease_expiry IS NULL")
		} else {
			claimQuery = claimQuery.Where("lease_expiry <= ?", now)
		}
	case OutboxStatusDispatched:
		claimQuery = claimQuery.Where(
			"dispatched_at IS NOT NULL AND risk_class = ? AND lease_expiry IS NOT NULL AND lease_expiry <= ?",
			RiskProviderIdempotent, now,
		)
	}
	q = claimQuery.Updates(updates)
	if q.Error != nil {
		return OutboxLease{}, commitObservedScrub(errors.New("eventstore: claim outbox failed"))
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, commitObservedScrub(ErrStaleLease)
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID, row.RetryCount = OutboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt, retry
	lease.Effect = effectFromRow(row)
	queueRefs = append(queueRefs, queueLaneRef{kind: outboxLaneKind, lane: row.LaneHMAC})
	if err = refreshQueueLaneRefs(tx, queueRefs, now); err != nil {
		return OutboxLease{}, err
	}
	if err = task5CommitQueueFailures(tx, failures); err != nil {
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
	if outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			return CommitResult{}, expireErr
		}
		if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5CommitQueueFailures(tx, []task5QueueFailure{failure}); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{}, ErrPayloadExpired
	}
	if effect.EndpointID != "" || len(effect.LaneHMAC) > 0 || effect.OrderingSequence != 0 ||
		effect.EffectType != "" || len(effect.PayloadCiphertext) > 0 || len(effect.PayloadNonce) > 0 ||
		len(effect.ContentDigest) > 0 || effect.DigestKeyID != "" || effect.PayloadEncryptionKeyID != "" || effect.ContentDigestKeyID != "" || !effect.PayloadExpiresAt.IsZero() ||
		!effect.DispatchedAt.IsZero() || !effect.CompletedAt.IsZero() || effect.ResultCode != "" || effect.ErrorCode != "" ||
		effect.ProviderMessageID != "" || effect.PrincipalID != "" || effect.Reason != "" || !effect.ResolutionAt.IsZero() {
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
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ScrubbedAt = task5Ptr(now)
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
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			return OutboxLease{}, expireErr
		}
		if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5CommitQueueFailures(tx, []task5QueueFailure{failure}); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrPayloadExpired
	}
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
	if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
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
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			return OutboxLease{}, expireErr
		}
		if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5CommitQueueFailures(tx, []task5QueueFailure{failure}); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrPayloadExpired
	}
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
	if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
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
	if !validOutboxStatus(req.Status) || req.Status == OutboxStatusPending || req.Status == OutboxStatusLeased || req.Status == OutboxStatusDispatched || req.Status == OutboxStatusAmbiguous {
		return CommitResult{}, ErrInvalidTransition
	}
	now := s.task5Now()
	if row.Status != OutboxStatusAmbiguous && outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			return CommitResult{}, expireErr
		}
		if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5CommitQueueFailures(tx, []task5QueueFailure{failure}); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{}, ErrPayloadExpired
	}
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
	row.PayloadCiphertext = nil
	row.ScrubbedAt = task5Ptr(now)
	row.PayloadNonce = nil
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
	if err = s.lockMutationPublication(ctx, tx); err != nil {
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
	if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
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
	if err := refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
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
	row.PayloadCiphertext = nil
	row.PayloadNonce = nil
	row.ScrubbedAt = task5Ptr(now)
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
	stable := stableProjectors(projectors)
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
		if readiness.Mode == "import" {
			if q = tx.Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
				"terminal_global_position":     position,
				"terminal_projection_position": position,
			}); q.Error != nil || q.RowsAffected != 1 {
				return errors.New("eventstore: advance readiness terminals failed")
			}
		}
		result.Events = append(result.Events, envelope)
		if result.StreamVersions == nil {
			result.StreamVersions = make(map[StreamID]uint64, 1)
		}
		result.StreamVersions[stream] = envelope.StreamVersion
	}
	if len(result.Events) > 0 {
		if len(stable) > 0 {
			if q = tx.Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
				"projector_set_version": projectorSetVersion(stable),
				"updated_at":            now,
			}); q.Error != nil || q.RowsAffected != 1 {
				return errors.New("eventstore: update projector control failed")
			}
		}
		for _, projector := range projectors {
			if projector.Apply == nil {
				continue
			}
			if applyErr := projector.Apply(ctx, tx, result.Events); applyErr != nil {
				return errors.Join(ErrProjectorFailure, applyErr)
			}
		}
		s.projectorMu.RLock()
		currentProjectors := append([]ProjectionDescriptor(nil), s.projectors...)
		if !sameProjectors(currentProjectors, projectors) {
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

func (s *GORMStore) task5ExpireOutbox(ctx context.Context, tx *gorm.DB, row *outboxEffectRow, now time.Time) (task5QueueFailure, error) {
	if !outboxUnresolved(row.Status) {
		return task5QueueFailure{}, nil
	}
	if row.Status == OutboxStatusAmbiguous {
		if err := task5ScrubOutbox(tx, row, now); err != nil {
			return task5QueueFailure{}, err
		}
		// The ambiguity was logged when it was isolated. Privacy scrubbing is
		// maintenance, not a second queue failure.
		return task5QueueFailure{}, nil
	}
	status := OutboxStatusFailed
	reason := "payload-expired"
	if row.DispatchedAt != nil {
		status = OutboxStatusAmbiguous
		reason = "expired-after-dispatch"
	}
	return s.task5IsolateOutbox(ctx, tx, row, now, status, "payload-expired", reason)
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
	if row.Status != OutboxStatusAmbiguous && outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			return CommitResult{}, expireErr
		}
		if err = refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5CommitQueueFailures(tx, []task5QueueFailure{failure}); err != nil {
			return CommitResult{}, err
		}
		return CommitResult{}, ErrPayloadExpired
	}
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
		if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
			failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
			if expireErr != nil {
				return CommitResult{}, expireErr
			}
			if refreshErr := refreshQueueLane(tx, outboxLaneKind, row.LaneHMAC, now); refreshErr != nil {
				return CommitResult{}, refreshErr
			}
			if commitErr := task5CommitQueueFailures(tx, []task5QueueFailure{failure}); commitErr != nil {
				return CommitResult{}, commitErr
			}
			return CommitResult{}, ErrPayloadExpired
		}
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

func task5ScrubInbox(tx *gorm.DB, row *inboxMessageRow, now time.Time, terminal bool) error {
	if len(row.PayloadCiphertext) == 0 && len(row.PayloadNonce) == 0 {
		return nil
	}
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
func task5FinalizeInboxPayload(tx *gorm.DB, row *inboxMessageRow, now time.Time, status, reason string) error {
	row.Status = status
	row.LeaseOwner = ""
	row.LeaseEpoch = 0
	row.LeaseExpiry = nil
	row.AttemptID = ""
	row.PayloadCiphertext = nil
	row.PayloadNonce = nil
	row.CompletedAt = task5Ptr(now)
	row.ResolutionReason = reason
	row.ResolutionAt = task5Ptr(now)
	version, err := nextVersion(row.Version)
	if err != nil {
		return err
	}
	row.Version = version
	q := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, version-1).Updates(inboxMap(*row))
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrStaleLease
	}
	return nil
}
func task5RecoverExpiredCallbackStarted(tx *gorm.DB, row *inboxMessageRow, now time.Time) error {
	if row.Status != InboxStatusCallbackStarted || row.LeaseExpiry == nil || row.LeaseExpiry.After(now) {
		return nil
	}
	return task5FinalizeInboxPayload(tx, row, now, InboxStatusAmbiguous, "callback-lease-expired")
}

func task5QuarantineInboxPayload(tx *gorm.DB, row *inboxMessageRow, now time.Time, reason string) error {
	return task5FinalizeInboxPayload(tx, row, now, InboxStatusFailed, reason)
}

func task5TerminalizeExpiredInbox(tx *gorm.DB, row *inboxMessageRow, now time.Time) error {
	status := InboxStatusAmbiguous
	if row.Status == InboxStatusPending || row.Status == InboxStatusLeased {
		status = InboxStatusFailed
	}
	return task5FinalizeInboxPayload(tx, row, now, status, "payload-expired")
}

func task5ScrubOutbox(tx *gorm.DB, row *outboxEffectRow, now time.Time) error {
	if len(row.PayloadCiphertext) == 0 && len(row.PayloadNonce) == 0 {
		return nil
	}
	row.PayloadCiphertext = nil
	row.PayloadNonce = nil
	row.ScrubbedAt = task5Ptr(now)
	if row.ResolutionReason == "" {
		row.ResolutionReason = "payload-expired"
		row.ResolutionAt = task5Ptr(now)
	}
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

func task5PayloadPresent(ciphertext, nonce []byte) bool {
	return len(ciphertext) != 0 || len(nonce) != 0
}

func inboxMap(row inboxMessageRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "attempt_id": row.AttemptID, "callback_started_at": row.CallbackStartedAt, "completed_at": row.CompletedAt, "payload_ciphertext": row.PayloadCiphertext, "payload_nonce": row.PayloadNonce, "payload_present": task5PayloadPresent(row.PayloadCiphertext, row.PayloadNonce), "scheduling_version": queueSchedulingVersion, "encryption_key_id": row.EncryptionKeyID, "content_digest": row.ContentDigest, "content_digest_key_id": row.ContentDigestKeyID, "payload_expires_at": row.PayloadExpiresAt, "workflow_id": row.WorkflowID, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}
func outboxMap(row outboxEffectRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "attempt_id": row.AttemptID, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "dispatched_at": row.DispatchedAt, "deadline_at": row.DeadlineAt, "next_attempt_at": row.NextAttemptAt, "payload_ciphertext": row.PayloadCiphertext, "payload_nonce": row.PayloadNonce, "payload_present": task5PayloadPresent(row.PayloadCiphertext, row.PayloadNonce), "scheduling_version": queueSchedulingVersion, "encryption_key_id": row.EncryptionKeyID, "content_digest": row.ContentDigest, "content_digest_key_id": row.ContentDigestKeyID, "result_code": row.ResultCode, "error_code": row.ErrorCode, "provider_message_id": row.ProviderMessageID, "completed_at": row.CompletedAt, "payload_expires_at": row.PayloadExpiresAt, "retry_count": row.RetryCount, "scrubbed_at": row.ScrubbedAt, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}
func (s *GORMStore) task5PersistExpiredArtifacts(ctx context.Context, work UnitOfWork, first *task5ExpiredArtifactError) error {
	base, publicationErr := s.task5Base(ctx)
	if publicationErr != nil {
		return publicationErr
	}
	tx, publicationErr := task5Begin(base)
	if publicationErr != nil {
		return publicationErr
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return err
	}
	defer func() {
		if publicationErr != nil {
			task5Rollback(tx)
		}
	}()
	ids := make([]string, 0, len(work.ArtifactUpdates))
	seen := make(map[string]struct{}, len(work.ArtifactUpdates))
	for _, update := range work.ArtifactUpdates {
		if update.ArtifactID != "" {
			if _, ok := seen[update.ArtifactID]; !ok {
				seen[update.ArtifactID] = struct{}{}
				ids = append(ids, update.ArtifactID)
			}
		}
	}
	if _, ok := seen[first.id]; !ok {
		ids = append(ids, first.id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var row operationArtifactRow
		q := locked(tx).Where("artifact_id = ?", id).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if row.Status != "available" && row.Status != "ready" {
			continue
		}
		if row.ExpiresAt.After(first.now) || (len(row.Ciphertext) == 0 && len(row.Nonce) == 0) {
			continue
		}
		version, versionErr := nextVersion(row.Version)
		if versionErr != nil {
			return versionErr
		}
		row.Status = "expired"
		row.Version = version
		row.Ciphertext = nil
		row.Nonce = nil
		row.ConsumedAt = task5Ptr(first.now)
		q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, version-1).Updates(map[string]any{
			"version": row.Version, "status": row.Status, "ciphertext": nil, "nonce": nil, "consumed_at": row.ConsumedAt,
		})
		if q.Error != nil || q.RowsAffected != 1 {
			return ErrStaleLease
		}
	}
	return task5Commit(tx)
}
func (s *GORMStore) task5PersistExpiredPayloads(ctx context.Context, work UnitOfWork, first *task5ExpiredPayloadError) error {
	base, publicationErr := s.task5Base(ctx)
	if publicationErr != nil {
		return publicationErr
	}
	tx, publicationErr := task5Begin(base)
	if publicationErr != nil {
		return publicationErr
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return err
	}
	defer func() {
		if publicationErr != nil {
			task5Rollback(tx)
		}
	}()
	seenInbox := map[string]bool{}
	seenOutbox := map[string]bool{}
	var failures []task5QueueFailure
	queueRefs := make([]queueLaneRef, 0, len(work.InboxUpdates)+len(work.Effects)+1)
	scrubInbox := func(id string, now time.Time) error {
		if id == "" || seenInbox[id] {
			return nil
		}
		var row inboxMessageRow
		if q := locked(tx).Where("inbox_id = ?", id).First(&row); q.Error != nil {
			return ErrParticipantFailure
		}
		mutated := false
		if row.Status == InboxStatusCallbackStarted {
			if publicationErr = task5FinalizeInboxPayload(tx, &row, now, InboxStatusAmbiguous, "payload-expired"); publicationErr != nil {
				return publicationErr
			}
			failures = append(failures, task5QueueFailure{
				queue: "inbox", itemID: row.InboxID, status: row.Status,
				reason: row.ResolutionReason, version: row.Version,
			})
			mutated = true
		} else if len(row.PayloadCiphertext) != 0 || len(row.PayloadNonce) != 0 {
			if publicationErr = task5ScrubInbox(tx, &row, now, false); publicationErr != nil {
				return publicationErr
			}
			mutated = true
		}
		if mutated {
			queueRefs = append(queueRefs, queueLaneRef{kind: inboxLaneKind, lane: row.LaneHMAC})
		}
		seenInbox[id] = true
		return nil
	}
	scrubOutbox := func(id string, now time.Time) error {
		if id == "" || seenOutbox[id] {
			return nil
		}
		var row outboxEffectRow
		if q := locked(tx).Where("effect_id = ?", id).First(&row); q.Error != nil {
			return ErrParticipantFailure
		}
		if !outboxUnresolved(row.Status) {
			seenOutbox[id] = true
			return nil
		}
		failure, expireErr := s.task5ExpireOutbox(ctx, tx, &row, now)
		if expireErr != nil {
			publicationErr = expireErr
			return publicationErr
		}
		if failure.itemID != "" {
			failures = append(failures, failure)
		}
		queueRefs = append(queueRefs, queueLaneRef{kind: outboxLaneKind, lane: row.LaneHMAC})
		seenOutbox[id] = true
		return nil
	}
	seenArtifacts := map[string]bool{}
	scrubArtifact := func(id string, now time.Time) error {
		if id == "" || seenArtifacts[id] {
			return nil
		}
		var row operationArtifactRow
		q := locked(tx).Where("artifact_id = ?", id).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			seenArtifacts[id] = true
			return nil
		}
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if (row.Status != "available" && row.Status != "ready") || row.ExpiresAt.After(now) || (len(row.Ciphertext) == 0 && len(row.Nonce) == 0) {
			seenArtifacts[id] = true
			return nil
		}
		version, versionErr := nextVersion(row.Version)
		if versionErr != nil {
			return versionErr
		}
		q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, row.Version).Updates(map[string]any{
			"version": version, "status": "expired", "ciphertext": nil, "nonce": nil, "consumed_at": now,
		})
		if q.Error != nil || q.RowsAffected != 1 {
			return ErrStaleLease
		}
		seenArtifacts[id] = true
		return nil
	}
	switch first.table {
	case tableInboxMessages:
		if publicationErr = scrubInbox(first.id, first.now); publicationErr != nil {
			return publicationErr
		}
	case tableOutboxEffects:
		if publicationErr = scrubOutbox(first.id, first.now); publicationErr != nil {
			return publicationErr
		}
	}
	inboxIDs := make([]string, 0, len(work.InboxUpdates)+1)
	if first.table == tableInboxMessages {
		inboxIDs = append(inboxIDs, first.id)
	} else if first.table != tableOutboxEffects {
		return ErrParticipantFailure
	}
	for _, update := range work.InboxUpdates {
		inboxIDs = append(inboxIDs, update.InboxID)
	}
	for _, update := range work.InboxUpdates {
		if update.EndpointID == "" || update.ProviderEventKey == "" {
			continue
		}
		var dedupe inboxMessageRow
		q := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&dedupe)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return ErrParticipantFailure
		}
		inboxIDs = append(inboxIDs, dedupe.InboxID)
	}
	sort.Strings(inboxIDs)
	for _, id := range inboxIDs {
		var row inboxMessageRow
		q := locked(tx).Where("inbox_id = ?", id).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if inboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(first.now) {
			if publicationErr = scrubInbox(row.InboxID, first.now); publicationErr != nil {
				return publicationErr
			}
		}
	}
	effectIDs := make([]string, 0, len(work.Effects)+1)
	if first.table == tableOutboxEffects {
		effectIDs = append(effectIDs, first.id)
	}
	for _, update := range work.Effects {
		effectIDs = append(effectIDs, update.EffectID)
	}
	sort.Strings(effectIDs)
	for _, id := range effectIDs {
		var row outboxEffectRow
		q := locked(tx).Where("effect_id = ?", id).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(first.now) {
			if publicationErr = scrubOutbox(row.EffectID, first.now); publicationErr != nil {
				return publicationErr
			}
		}
	}
	artifactIDs := make([]string, 0, len(work.ArtifactUpdates))
	for _, update := range work.ArtifactUpdates {
		if update.ArtifactID != "" {
			artifactIDs = append(artifactIDs, update.ArtifactID)
		}
	}
	sort.Strings(artifactIDs)
	for _, id := range artifactIDs {
		var row operationArtifactRow
		q := locked(tx).Where("artifact_id = ?", id).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return ErrParticipantFailure
		}
		if (row.Status == "available" || row.Status == "ready") && !row.ExpiresAt.After(first.now) {
			if publicationErr = scrubArtifact(row.ArtifactID, first.now); publicationErr != nil {
				return publicationErr
			}
		}
	}
	if publicationErr = refreshQueueLaneRefs(tx, queueRefs, first.now); publicationErr != nil {
		return publicationErr
	}
	publicationErr = task5CommitQueueFailures(tx, failures)
	return publicationErr
}

func inboxUpdateFromRow(row inboxMessageRow) InboxUpdate {
	return InboxUpdate{
		InboxID: row.InboxID, ExpectedVersion: row.Version, Version: row.Version,
		EndpointID: row.EndpointID, ProviderEventKey: row.ProviderEventKey, LaneHMAC: task5Copy(row.LaneHMAC),
		SubjectKey:       task5Copy(row.SubjectKey),
		OrderingSequence: row.OrderingSequence, Status: row.Status, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch,
		LeaseExpiresAt: valueTime(row.LeaseExpiry), AttemptID: row.AttemptID, PayloadCiphertext: task5Copy(row.PayloadCiphertext),
		PayloadNonce: task5Copy(row.PayloadNonce), PayloadVersion: task5PayloadVersion(row.PayloadVersion), ContentDigest: task5Copy(row.ContentDigest), DigestKeyID: row.ContentDigestKeyID,
		PayloadEncryptionKeyID: row.EncryptionKeyID, ContentDigestKeyID: row.ContentDigestKeyID,
		WorkflowID: row.WorkflowID, CallbackStartedAt: valueTime(row.CallbackStartedAt), CompletedAt: valueTime(row.CompletedAt),
		PayloadExpiresAt: valueTime(row.PayloadExpiresAt), PrincipalID: row.ResolutionPrincipal, Reason: row.ResolutionReason,
		ResolutionAt: valueTime(row.ResolutionAt),
	}
}

func effectFromRow(row outboxEffectRow) NewEffect {
	return NewEffect{
		EffectID: row.EffectID, ExpectedVersion: row.Version, Version: row.Version, EndpointID: row.EndpointID,
		LaneHMAC: task5Copy(row.LaneHMAC), OrderingSequence: row.OrderingSequence, EffectType: row.EffectClass,
		SubjectKey: task5Copy(row.SubjectKey),
		RiskClass:  row.RiskClass, Status: row.Status, AttemptID: row.AttemptID, LeaseOwner: row.LeaseOwner,
		LeaseEpoch: row.LeaseEpoch, LeaseExpiresAt: valueTime(row.LeaseExpiry), DeadlineAt: valueTime(row.DeadlineAt),
		NextAttemptAt: valueTime(row.NextAttemptAt), DispatchedAt: valueTime(row.DispatchedAt),
		PayloadCiphertext: task5Copy(row.PayloadCiphertext), PayloadNonce: task5Copy(row.PayloadNonce), PayloadVersion: row.PayloadVersion,
		ContentDigest: task5Copy(row.ContentDigest), DigestKeyID: row.ContentDigestKeyID,
		PayloadEncryptionKeyID: row.EncryptionKeyID, ContentDigestKeyID: row.ContentDigestKeyID,
		ProviderMessageID: row.ProviderMessageID, ResultCode: row.ResultCode, ErrorCode: row.ErrorCode,
		CompletedAt: valueTime(row.CompletedAt), PayloadExpiresAt: valueTime(row.PayloadExpiresAt), RetryCount: row.RetryCount,
		PrincipalID: row.ResolutionPrincipal, Reason: row.ResolutionReason, ResolutionAt: valueTime(row.ResolutionAt),
	}
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
		Seal(ctx context.Context, plaintext []byte) ([]byte, []byte, string, error)
	}); ok {
		return c.Seal(ctx, plaintext)
	}
	if c, ok := codec.(interface {
		Encrypt(plaintext []byte) ([]byte, []byte, string, error)
	}); ok {
		return c.Encrypt(plaintext)
	}
	if c, ok := codec.(interface {
		Seal(plaintext []byte) ([]byte, []byte, string, error)
	}); ok {
		return c.Seal(plaintext)
	}
	return nil, nil, "", ErrEncryptionUnavailable
}

// EncryptBound seals a payload with the store's admitted key source and the
// complete AAD binding. It is intentionally narrow so callers cannot access
// key material or bypass the readiness/admission checks.
func (s *GORMStore) EncryptBound(ctx context.Context, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, nil, "", ErrEncryptionUnavailable
	}
	if err := s.requireReady(ctx); err != nil {
		return nil, nil, "", err
	}
	var ciphertext, nonce []byte
	var keyID string
	err := s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.lockMutationPublication(ctx, tx); err != nil {
			return err
		}
		var err error
		ciphertext, nonce, keyID, err = s.sealBoundPayloadInMutation(ctx, tx, domain, identity, owner, version, plaintext)
		return err
	})
	return ciphertext, nonce, keyID, err
}

func (s *GORMStore) DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, ErrEncryptionUnavailable
	}
	if err := s.requireReady(ctx); err != nil {
		return nil, err
	}
	if s.keySource == nil {
		return openBoundPayload(ctx, s.codec, domain, identity, owner, version, ciphertext, nonce, keyID)
	}
	var plaintext []byte
	err := s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.lockMutationPublication(ctx, tx); err != nil {
			return err
		}
		if err := s.validateA6KeyID(ctx, tx, keyID); err != nil {
			return err
		}
		var err error
		plaintext, err = a6Open(ctx, s.keySource, domain, identity, owner, version, keyID, ciphertext, nonce)
		return err
	})
	return plaintext, err
}
func sealBoundPayload(ctx context.Context, codec any, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	if bound, ok := codec.(interface {
		EncryptBound(ctx context.Context, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error)
	}); ok {
		return bound.EncryptBound(ctx, domain, identity, owner, version, plaintext)
	}
	return sealPayload(ctx, codec, plaintext)
}
func (s *GORMStore) sealBoundPayloadInMutation(ctx context.Context, tx *gorm.DB, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	if s.keySource != nil {
		if _, ok := s.codec.(*a6PayloadCodec); ok {
			root, err := s.admittedCurrentRoot(ctx, tx)
			if err != nil {
				return nil, nil, "", err
			}
			return a6SealWithRoot(root, domain, identity, owner, version, plaintext)
		}
	}
	return sealBoundPayload(ctx, s.codec, domain, identity, owner, version, plaintext)
}

func openBoundPayload(ctx context.Context, codec any, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error) {
	if bound, ok := codec.(interface {
		DecryptBound(ctx context.Context, domain, identity, owner string, version uint64, ciphertext, nonce []byte, keyID string) ([]byte, error)
	}); ok {
		return bound.DecryptBound(ctx, domain, identity, owner, version, ciphertext, nonce, keyID)
	}
	return openPayload(ctx, codec, ciphertext, nonce, keyID)
}
func openPayload(ctx context.Context, codec any, ciphertext, nonce []byte, keyID string) ([]byte, error) {
	if codec == nil {
		return nil, ErrEncryptionUnavailable
	}
	if c, ok := codec.(PayloadCodec); ok {
		return c.Decrypt(ctx, ciphertext, nonce, keyID)
	}
	if c, ok := codec.(interface {
		Open(ctx context.Context, ciphertext, nonce []byte, keyID string) ([]byte, error)
	}); ok {
		return c.Open(ctx, ciphertext, nonce, keyID)
	}
	if c, ok := codec.(interface {
		Decrypt(ciphertext, nonce []byte, keyID string) ([]byte, error)
	}); ok {
		return c.Decrypt(ciphertext, nonce, keyID)
	}
	if c, ok := codec.(interface {
		Open(ciphertext, nonce []byte, keyID string) ([]byte, error)
	}); ok {
		return c.Open(ciphertext, nonce, keyID)
	}
	return nil, ErrEncryptionUnavailable
}
func (s *GORMStore) PutArtifact(ctx context.Context, req ArtifactPutRequest) (result ArtifactPutResult, err error) {
	if readyErr := s.requireReady(ctx); readyErr != nil {
		return ArtifactPutResult{}, readyErr
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
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactPutResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactPutResult{}, err
	}
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
		task5Rollback(tx)
		return ArtifactPutResult{}, lockErr
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	var operation operationRow
	operationQuery := locked(tx).Select("operation_id", "principal_id").Where("operation_id = ?", req.OperationID).First(&operation)
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
	if err = s.requireA6BoundCodec(); err != nil {
		return ArtifactPutResult{}, err
	}
	ciphertext, nonce, keyID, err := s.sealBoundPayloadInMutation(ctx, tx, "artifact/v1", req.ArtifactID, req.OwnerPrincipalID, 1, req.Plaintext)
	if err != nil {
		if errors.Is(err, ErrReadinessQuarantined) {
			return ArtifactPutResult{}, err
		}
		return ArtifactPutResult{}, ErrEncryptionUnavailable
	}
	if opaqueErr := validateTask5ArtifactOpaquePayload(ciphertext, nonce, keyID); opaqueErr != nil {
		return ArtifactPutResult{}, opaqueErr
	}
	now := s.task5Now()
	expires := now.Add(ttl)
	row := operationArtifactRow{ArtifactID: req.ArtifactID, Version: 1, PayloadVersion: 1, OperationID: req.OperationID, OwnerPrincipalID: req.OwnerPrincipalID, MediaType: req.MediaType, SafeFilename: req.SafeFilename, Size: int64(len(req.Plaintext)), Status: "available", Ciphertext: task5Copy(ciphertext), Nonce: task5Copy(nonce), EncryptionKeyID: keyID, ExpiresAt: expires}
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
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactResult{}, err
	}
	if lockErr := s.lockMutationPublication(ctx, tx); lockErr != nil {
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
		return ArtifactResult{}, errors.New("eventstore: load artifact failed")
	}
	if req.OwnerPrincipalID != "" && req.OwnerPrincipalID != row.OwnerPrincipalID {
		return ArtifactResult{}, ErrArtifactOwner
	}
	now := s.task5Now()
	if row.Status != "available" && row.Status != "ready" {
		return ArtifactResult{}, ErrArtifactGone
	}
	if !row.ExpiresAt.After(now) {
		row.Status = "expired"
		row.Ciphertext = nil
		row.Nonce = nil
		version, e := nextVersion(row.Version)
		if e != nil {
			return ArtifactResult{}, e
		}
		row.Version = version
		row.ConsumedAt = task5Ptr(now)
		q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, version-1).Updates(map[string]any{"version": row.Version, "status": row.Status, "ciphertext": nil, "nonce": nil, "consumed_at": row.ConsumedAt})
		if q.Error != nil || q.RowsAffected != 1 {
			return ArtifactResult{}, ErrStaleLease
		}
		if err = task5Commit(tx); err != nil {
			return ArtifactResult{}, err
		}
		return ArtifactResult{}, ErrArtifactGone
	}
	if row.Size < 0 || row.Size > MaxArtifactBytes {
		return ArtifactResult{}, &OversizeError{Bound: "artifact bytes", Limit: MaxArtifactBytes, Actual: int(row.Size)}
	}
	if err = s.requireA6BoundCodec(); err != nil {
		return ArtifactResult{}, err
	}
	if err = validateTask5ArtifactOpaquePayload(row.Ciphertext, row.Nonce, row.EncryptionKeyID); err != nil {
		return ArtifactResult{}, err
	}
	if err = s.validateA6KeyID(ctx, tx, row.EncryptionKeyID); err != nil {
		return ArtifactResult{}, err
	}
	plaintext, openErr := openBoundPayload(ctx, s.codec, "artifact/v1", row.ArtifactID, row.OwnerPrincipalID, task5PayloadVersion(row.PayloadVersion), row.Ciphertext, row.Nonce, row.EncryptionKeyID)
	if openErr != nil {
		if errors.Is(openErr, ErrEncryptionUnavailable) || errors.Is(openErr, ErrKeyUnavailable) || errors.Is(openErr, ErrKeySourceUnavailable) {
			return ArtifactResult{}, ErrEncryptionUnavailable
		}
		return ArtifactResult{}, ErrAuthenticationFailed
	}
	if int64(len(plaintext)) != row.Size || len(plaintext) > MaxArtifactBytes {
		return ArtifactResult{}, ErrInvalidMetadata
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
	consumed := ArtifactResult{ArtifactID: row.ArtifactID, OperationID: row.OperationID, OwnerPrincipalID: row.OwnerPrincipalID, MediaType: row.MediaType, SafeFilename: row.SafeFilename, Size: row.Size, Plaintext: task5Copy(plaintext), ExpiresAt: row.ExpiresAt, ConsumedAt: now}
	if err = task5Commit(tx); err != nil {
		return ArtifactResult{}, err
	}
	return consumed, nil
}

func task5ParticipantExpiry(expiry time.Time, now time.Time, maxTTL time.Duration) (time.Time, error) {
	if expiry.IsZero() {
		return now.Add(maxTTL), nil
	}
	expiry = expiry.UTC()
	if !expiry.After(now) {
		return time.Time{}, ErrPayloadExpired
	}
	if expiry.After(now.Add(maxTTL)) {
		return time.Time{}, ErrInvalidTTL
	}
	return expiry, nil
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
		if laneCompare := bytes.Compare(updates[i].LaneHMAC, updates[j].LaneHMAC); laneCompare != 0 {
			return laneCompare < 0
		}
		return updates[i].InboxID < updates[j].InboxID
	})
	for _, update := range updates {
		payloadBearing := len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || update.DigestKeyID != ""
		payloadKeyID := task5PayloadKeyID(update)
		if payloadBearing {
			if err := task5ValidateKeyFields(s.keySource, update.DigestKeyID, update.PayloadEncryptionKeyID); err != nil {
				return err
			}
			digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, update.ContentDigestKeyID)
			if digestErr != nil {
				return digestErr
			}
			update.ContentDigestKeyID = digestKeyID
		}
		if update.InboxID == "" {
			return ErrParticipantFailure
		}
		var row inboxMessageRow
		q := tx.Where("inbox_id = ?", update.InboxID).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			if err := s.createTask5InboxParticipant(tx, update, payloadKeyID, result); err != nil {
				return err
			}
		} else if q.Error != nil {
			return ErrParticipantFailure
		} else {
			if err := s.updateTask5InboxParticipant(tx, update, row, payloadKeyID, workflowStreamCount, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *GORMStore) createTask5InboxParticipant(tx *gorm.DB, update InboxUpdate, payloadKeyID string, result *CommitResult) error {
	var row inboxMessageRow
	if update.WorkflowID != "" {
		return ErrInvalidTransition
	}
	if err := participantVersion(update.ExpectedVersion, 0, update.Version, tableInboxMessages, "<redacted>"); err != nil {
		return err
	}
	if update.Status == "" {
		update.Status = InboxStatusPending
	}
	if err := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); err != nil {
		return err
	}
	if update.EndpointID == "" || update.ProviderEventKey == "" || len(update.LaneHMAC) == 0 {
		return ErrParticipantFailure
	}
	if update.Status != InboxStatusPending || update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	if len(update.PayloadCiphertext) == 0 || len(update.PayloadNonce) == 0 || payloadKeyID == "" || len(update.PayloadCiphertext) > task5PayloadLimit {
		return ErrParticipantFailure
	}
	now := s.task5Now()
	var existing inboxMessageRow
	dedupe := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&existing)
	if dedupe.Error == nil {
		if inboxUnresolved(existing.Status) && existing.PayloadExpiresAt != nil && !existing.PayloadExpiresAt.After(now) {
			return &task5ExpiredPayloadError{table: tableInboxMessages, id: existing.InboxID, now: now}
		}
		if !task5InboxDuplicate(existing, update) {
			return ErrConflict
		}
		result.InboxIDs = append(result.InboxIDs, existing.InboxID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, existing.OrderingSequence, existing.Version
		return nil
	}
	if !errors.Is(dedupe.Error, gorm.ErrRecordNotFound) {
		return ErrParticipantFailure
	}
	expiry, expiryErr := task5ParticipantExpiry(update.PayloadExpiresAt, now, InboxPayloadTTL)
	if expiryErr != nil {
		return expiryErr
	}
	sequence, sequenceErr := task5AllocateLane(tx, inboxLaneKind, update.LaneHMAC, now)
	if sequenceErr != nil {
		return sequenceErr
	}
	status := update.Status
	if status == "" {
		status = InboxStatusPending
	}
	row = inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, Status: status, Version: 1, PayloadVersion: task5PayloadVersion(update.PayloadVersion), LeaseOwner: update.LeaseOwner, LeaseEpoch: update.LeaseEpoch, LeaseExpiry: task5Ptr(update.LeaseExpiresAt), AttemptID: update.AttemptID, CallbackStartedAt: task5Ptr(update.CallbackStartedAt), CompletedAt: task5Ptr(update.CompletedAt), PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), PayloadPresent: true, SchedulingVersion: queueSchedulingVersion, EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID), PayloadExpiresAt: task5Ptr(expiry), WorkflowID: update.WorkflowID, ResolutionPrincipal: update.PrincipalID, ResolutionReason: update.Reason, ResolutionAt: task5Ptr(update.ResolutionAt)}
	row.SubjectKey = task5Copy(update.SubjectKey)
	q := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if q.Error != nil {
		return ErrParticipantFailure
	}
	if q.RowsAffected == 0 {
		var duplicate inboxMessageRow
		lookup := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&duplicate)
		if lookup.Error != nil {
			return ErrParticipantFailure
		}
		if inboxUnresolved(duplicate.Status) && duplicate.PayloadExpiresAt != nil && !duplicate.PayloadExpiresAt.After(now) {
			return &task5ExpiredPayloadError{table: tableInboxMessages, id: duplicate.InboxID, now: now}
		}
		if !task5InboxDuplicate(duplicate, update) {
			return ErrConflict
		}
		if err := task5ReleaseLane(tx, inboxLaneKind, update.LaneHMAC, sequence); err != nil {
			return err
		}
		result.InboxIDs = append(result.InboxIDs, duplicate.InboxID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, duplicate.OrderingSequence, duplicate.Version
		return nil
	}
	result.OrderingSequence, result.Version = sequence, row.Version
	result.InboxIDs = append(result.InboxIDs, update.InboxID)
	return nil
}

func (s *GORMStore) updateTask5InboxParticipant(tx *gorm.DB, update InboxUpdate, row inboxMessageRow, payloadKeyID string, workflowStreamCount int, result *CommitResult) error {
	now := s.task5Now()
	allowExpiredAmbiguous := task5AllowsExpiredAmbiguous(row, update)
	if inboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) && !allowExpiredAmbiguous {
		return &task5ExpiredPayloadError{table: tableInboxMessages, id: row.InboxID, now: now}
	}
	hasOpaqueReplay := len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0
	if hasOpaqueReplay {
		if update.WorkflowID != "" {
			return ErrInvalidTransition
		}
		if err := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); err != nil {
			return err
		}
		if !task5InboxDuplicate(row, update) {
			return ErrConflict
		}
		if update.ExpectedVersion != 0 && update.ExpectedVersion != row.Version {
			return participantConflict(tableInboxMessages)
		}
		if update.Version != 0 && update.Version != row.Version {
			return ErrParticipantConflict
		}
		if (update.Status != "" && update.Status != InboxStatusPending) || update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
			return ErrInvalidTransition
		}
		result.InboxIDs = append(result.InboxIDs, row.InboxID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, row.OrderingSequence, row.Version
		return nil
	}
	if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableInboxMessages, "<redacted>"); err != nil {
		return err
	}
	if row.Status == InboxStatusFailed || row.Status == InboxStatusConfirmedConsumed || row.Status == InboxStatusSkipped {
		return ErrInvalidTransition
	}
	if row.WorkflowID != "" && update.Status == InboxStatusConfirmedConsumed && update.WorkflowID == "" {
		return ErrInvalidTransition
	}
	if update.EndpointID != "" || update.ProviderEventKey != "" || len(update.LaneHMAC) > 0 || update.OrderingSequence != 0 ||
		len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.DigestKeyID != "" ||
		update.PayloadVersion != 0 || update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || !update.PayloadExpiresAt.IsZero() {
		return ErrInvalidTransition
	}
	if update.WorkflowID != "" {
		if !validInboxWorkflowID(update.WorkflowID) || update.Status != InboxStatusConfirmedConsumed {
			return ErrInvalidMetadata
		}
		if workflowStreamCount == 0 {
			return ErrInvalidTransition
		}
		if row.WorkflowID != "" && row.WorkflowID != update.WorkflowID {
			return ErrInvalidTransition
		}
		if row.WorkflowID == "" && row.Status != InboxStatusCallbackStarted {
			return ErrInvalidTransition
		}
	}
	if update.Status != InboxStatusLeased && update.Status != InboxStatusCallbackStarted && row.Status != InboxStatusLeased && row.Status != InboxStatusCallbackStarted && (update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero()) {
		return ErrStaleLease
	}
	if update.Status != "" {
		if !validInboxStatus(update.Status) || !inboxTransitionAllowed(row.Status, update.Status) {
			return ErrInvalidTransition
		}
	}
	if update.Resolution != "" || update.PrincipalID != "" || update.Reason != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	if update.Status != InboxStatusPending || row.Status != InboxStatusPending {
		if !allowExpiredAmbiguous && (!task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now)) {
			return ErrStaleLease
		}
	}
	if (!update.CallbackStartedAt.IsZero() && update.Status != InboxStatusCallbackStarted) || (!update.CompletedAt.IsZero() && update.Status != InboxStatusFailed && update.Status != InboxStatusConfirmedConsumed && update.Status != InboxStatusSkipped) {
		return ErrInvalidTransition
	}
	if update.Resolution != "" || update.PrincipalID != "" || update.Reason != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	if update.ExpectedVersion != row.Version {
		return participantConflict(tableInboxMessages)
	}
	version, versionErr := nextVersion(row.Version)
	if versionErr != nil {
		return versionErr
	}
	if update.Status != "" {
		row.Status = update.Status
	}
	if update.Status == InboxStatusCallbackStarted && row.CallbackStartedAt == nil {
		row.CallbackStartedAt = task5Ptr(now)
	}
	if update.LeaseOwner != "" {
		row.LeaseOwner = update.LeaseOwner
	}
	if update.WorkflowID != "" {
		row.WorkflowID = update.WorkflowID
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
	if !update.CallbackStartedAt.IsZero() {
		row.CallbackStartedAt = task5Ptr(update.CallbackStartedAt)
	}
	if !update.CompletedAt.IsZero() {
		row.CompletedAt = task5Ptr(update.CompletedAt)
	}
	if len(update.PayloadCiphertext) > 0 {
		row.PayloadCiphertext = task5Copy(update.PayloadCiphertext)
	}
	if len(update.PayloadNonce) > 0 {
		row.PayloadNonce = task5Copy(update.PayloadNonce)
	}
	if len(update.ContentDigest) > 0 {
		row.ContentDigest = task5Copy(update.ContentDigest)
	}
	if !update.PayloadExpiresAt.IsZero() {
		expiry, expiryErr := task5ParticipantExpiry(update.PayloadExpiresAt, s.task5Now(), InboxPayloadTTL)
		if expiryErr != nil {
			return expiryErr
		}
		row.PayloadExpiresAt = task5Ptr(expiry)
	}
	if update.Status == InboxStatusFailed || update.Status == InboxStatusConfirmedConsumed || update.Status == InboxStatusSkipped || update.Status == InboxStatusAmbiguous {
		row.LeaseExpiry = nil
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ResolutionAt = task5Ptr(now)
	}
	row.Version = version
	updateQuery := tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, update.ExpectedVersion)
	if !allowExpiredAmbiguous {
		updateQuery = updateQuery.Where("(lease_expiry IS NULL OR lease_expiry > ?)", now)
	}
	q := updateQuery.Updates(inboxParticipantMap(row))
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrStaleLease
	}
	result.InboxIDs = append(result.InboxIDs, update.InboxID)
	return nil
}

func inboxParticipantMap(row inboxMessageRow) map[string]any {
	values := inboxMap(row)
	values["endpoint_id"] = row.EndpointID
	values["provider_event_id"] = row.ProviderEventKey
	values["lane_hmac"] = row.LaneHMAC
	values["ordering_sequence"] = row.OrderingSequence
	return values
}

func (s *GORMStore) applyTask5EffectParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	updates := append([]NewEffect(nil), work.Effects...)
	// Lock lanes deterministically without reordering emissions within a lane.
	sort.SliceStable(updates, func(i, j int) bool {
		return bytes.Compare(updates[i].LaneHMAC, updates[j].LaneHMAC) < 0
	})
	for _, update := range updates {
		payloadBearing := len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || update.DigestKeyID != ""
		payloadKeyID := task5EffectPayloadKeyID(update)
		if payloadBearing {
			if err := task5ValidateKeyFields(s.keySource, update.DigestKeyID, update.PayloadEncryptionKeyID); err != nil {
				return err
			}
			digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, update.ContentDigestKeyID)
			if digestErr != nil {
				return digestErr
			}
			update.ContentDigestKeyID = digestKeyID
		}
		if update.EffectID == "" {
			return ErrParticipantFailure
		}
		var row outboxEffectRow
		q := tx.Where("effect_id = ?", update.EffectID).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			if err := s.createTask5EffectParticipant(tx, update, payloadKeyID, result); err != nil {
				return err
			}
		} else if q.Error != nil {
			return ErrParticipantFailure
		} else {
			if err := s.updateTask5EffectParticipant(ctx, tx, update, row, payloadKeyID, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *GORMStore) createTask5EffectParticipant(tx *gorm.DB, update NewEffect, payloadKeyID string, result *CommitResult) error {
	var row outboxEffectRow
	if err := participantVersion(update.ExpectedVersion, 0, update.Version, tableOutboxEffects, "<redacted>"); err != nil {
		return err
	}
	if err := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); err != nil {
		return err
	}
	if update.EffectType == "" || !validRisk(update.RiskClass) || (update.Status != "" && update.Status != OutboxStatusPending) || update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || len(update.PayloadCiphertext) == 0 || len(update.PayloadNonce) == 0 || payloadKeyID == "" || len(update.PayloadCiphertext) > task5PayloadLimit {
		if update.Status != "" && update.Status != OutboxStatusPending {
			return ErrInvalidTransition
		}
		if !validRisk(update.RiskClass) {
			return ErrInvalidRiskClass
		}
		return ErrParticipantFailure
	}
	if !update.DispatchedAt.IsZero() || !update.CompletedAt.IsZero() || update.ResultCode != "" || update.ErrorCode != "" || update.ProviderMessageID != "" || update.RetryCount != 0 || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
		return ErrInvalidTransition
	}
	now := s.task5Now()
	var existing outboxEffectRow
	if tx.Where("effect_id = ?", update.EffectID).First(&existing).Error == nil {
		if outboxUnresolved(existing.Status) && existing.PayloadExpiresAt != nil && !existing.PayloadExpiresAt.After(now) {
			return &task5ExpiredPayloadError{table: tableOutboxEffects, id: existing.EffectID, now: now}
		}
		if !task5EffectDuplicate(existing, update) {
			return ErrConflict
		}
		result.EffectIDs = append(result.EffectIDs, existing.EffectID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, existing.OrderingSequence, existing.Version
		return nil
	}
	expiry, expiryErr := task5ParticipantExpiry(update.PayloadExpiresAt, now, InboxPayloadTTL)
	if expiryErr != nil {
		return expiryErr
	}
	sequence, sequenceErr := task5AllocateLane(tx, outboxLaneKind, update.LaneHMAC, now)
	if sequenceErr != nil {
		return sequenceErr
	}
	status := update.Status
	if status == "" {
		status = OutboxStatusPending
	}
	risk := update.RiskClass
	if risk == "" {
		risk = RiskPreDispatchRetryable
	}
	row = outboxEffectRow{EffectID: update.EffectID, Version: 1, PayloadVersion: task5PayloadVersion(update.PayloadVersion), EndpointID: update.EndpointID, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, EffectClass: update.EffectType, RiskClass: risk, Status: status, AttemptID: update.AttemptID, LeaseOwner: update.LeaseOwner, LeaseEpoch: update.LeaseEpoch, LeaseExpiry: task5Ptr(update.LeaseExpiresAt), DispatchedAt: task5Ptr(update.DispatchedAt), DeadlineAt: task5Ptr(update.DeadlineAt), NextAttemptAt: task5Ptr(update.NextAttemptAt), PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), PayloadPresent: true, SchedulingVersion: queueSchedulingVersion, EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID), ResultCode: update.ResultCode, ErrorCode: update.ErrorCode, ProviderMessageID: update.ProviderMessageID, CompletedAt: task5Ptr(update.CompletedAt), PayloadExpiresAt: task5Ptr(expiry), CreatedAt: now, RetryCount: update.RetryCount}
	row.SubjectKey = task5Copy(update.SubjectKey)
	q := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if q.Error != nil {
		return ErrParticipantFailure
	}
	if q.RowsAffected == 0 {
		var duplicate outboxEffectRow
		lookup := locked(tx).Where("effect_id = ?", update.EffectID).First(&duplicate)
		if lookup.Error != nil {
			return ErrParticipantFailure
		}
		if outboxUnresolved(duplicate.Status) && duplicate.PayloadExpiresAt != nil && !duplicate.PayloadExpiresAt.After(now) {
			return &task5ExpiredPayloadError{table: tableOutboxEffects, id: duplicate.EffectID, now: now}
		}
		if !task5EffectDuplicate(duplicate, update) {
			return ErrConflict
		}
		if err := task5ReleaseLane(tx, outboxLaneKind, update.LaneHMAC, sequence); err != nil {
			return err
		}
		result.EffectIDs = append(result.EffectIDs, duplicate.EffectID)
		result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, duplicate.OrderingSequence, duplicate.Version
		return nil
	}
	result.OrderingSequence, result.Version = sequence, row.Version
	result.EffectIDs = append(result.EffectIDs, update.EffectID)
	return nil
}

func (s *GORMStore) updateTask5EffectParticipant(ctx context.Context, tx *gorm.DB, update NewEffect, row outboxEffectRow, payloadKeyID string, result *CommitResult) error {
	now := s.task5Now()
	if outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		return &task5ExpiredPayloadError{table: tableOutboxEffects, id: row.EffectID, now: now}
	}
	hasOpaqueReplay := len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0
	if hasOpaqueReplay {
		if err := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); err != nil {
			return err
		}
		if !task5EffectDuplicate(row, update) {
			return ErrConflict
		}
		if update.ExpectedVersion != 0 && update.ExpectedVersion != row.Version {
			return participantConflict(tableOutboxEffects)
		}
		if update.Version != 0 && update.Version != row.Version {
			return ErrParticipantConflict
		}
		if (update.Status != "" && update.Status != OutboxStatusPending) || update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.DispatchedAt.IsZero() || (!update.CompletedAt.IsZero() && update.Status != OutboxStatusSucceeded && update.Status != OutboxStatusFailed) || update.ProviderMessageID != "" || update.ResultCode != "" || update.ErrorCode != "" || update.RetryCount != 0 || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
			return ErrInvalidTransition
		}
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
	if update.EndpointID != "" || len(update.LaneHMAC) > 0 || update.OrderingSequence != 0 || update.EffectType != "" ||
		len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.DigestKeyID != "" ||
		update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || !update.PayloadExpiresAt.IsZero() || !update.DispatchedAt.IsZero() || (!terminal && (update.ResultCode != "" || update.ErrorCode != "" || update.ProviderMessageID != "")) {
		return ErrInvalidTransition
	}
	leaseState := row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched
	requiresLease := update.Status != "" && update.Status != OutboxStatusPending
	if requiresLease && !leaseState {
		return ErrStaleLease
	}
	if leaseState || requiresLease {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
			return ErrStaleLease
		}
	} else if update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() {
		return ErrStaleLease
	}
	if update.Status != "" {
		allowed := validOutboxStatus(update.Status) && outboxTransitionAllowed(row.Status, update.Status)
		if row.Status == OutboxStatusDispatched && update.Status == OutboxStatusPending && (row.RiskClass == RiskProviderIdempotent || row.RiskClass == RiskPreDispatchRetryable) {
			allowed = true
		}
		if !allowed {
			return ErrInvalidTransition
		}
	}
	if update.RiskClass != "" && !validRisk(update.RiskClass) {
		return ErrInvalidRiskClass
	}
	if update.RiskClass != "" && update.RiskClass != row.RiskClass {
		return ErrInvalidTransition
	}
	if update.ExpectedVersion != row.Version {
		return participantConflict(tableOutboxEffects)
	}
	version, versionErr := nextVersion(row.Version)
	if versionErr != nil {
		return versionErr
	}
	if update.Status != "" {
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
	if terminal {
		row.CompletedAt = task5Ptr(now)
		row.LeaseExpiry = nil
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ScrubbedAt = task5Ptr(now)
	}
	if update.Status == OutboxStatusPending {
		row.LeaseOwner, row.LeaseEpoch, row.AttemptID, row.LeaseExpiry = "", 0, "", nil
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
	if !update.DispatchedAt.IsZero() {
		row.DispatchedAt = task5Ptr(update.DispatchedAt)
	}
	row.Version = version
	q := tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND (lease_expiry IS NULL OR lease_expiry > ?)", row.EffectID, update.ExpectedVersion, now).Updates(outboxMap(row))
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrStaleLease
	}
	if terminal {
		if err := s.applyStoryLogUpdate(ctx, tx, NewStoryLogFinishIntentUpdate(row.EffectID, row.ProviderMessageID, row.Status == OutboxStatusSucceeded)); err != nil {
			return err
		}
	}
	result.EffectIDs = append(result.EffectIDs, update.EffectID)
	return nil
}

func (s *GORMStore) applyTask5ArtifactParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	updates := append([]ArtifactUpdate(nil), work.ArtifactUpdates...)
	sort.Slice(updates, func(i, j int) bool { return updates[i].ArtifactID < updates[j].ArtifactID })
	for _, update := range updates {
		if update.PlaintextSet && update.OwnerPrincipalID == "" && update.OperationID != "" {
			var owner operationRow
			q := locked(tx).Select("operation_id", "principal_id").Where("operation_id = ?", update.OperationID).First(&owner)
			if q.Error != nil {
				if errors.Is(q.Error, gorm.ErrRecordNotFound) {
					return ErrNotFound
				}
				return ErrParticipantFailure
			}
			update.OwnerPrincipalID = owner.PrincipalID
		}
		if update.PlaintextSet {
			ciphertext, nonce, keyID, err := s.sealBoundPayloadInMutation(ctx, tx, "artifact/v1", update.ArtifactID, update.OwnerPrincipalID, 1, update.Plaintext)
			if err != nil {
				return err
			}
			update.Ciphertext, update.Nonce, update.EncryptionKeyID = ciphertext, nonce, keyID
			if update.Size == 0 {
				update.Size = int64(len(update.Plaintext))
			}
		}
		if update.ArtifactID == "" {
			return ErrParticipantFailure
		}
		if update.Size < 0 || update.Size > MaxArtifactBytes {
			return &OversizeError{Bound: "artifact bytes", Limit: MaxArtifactBytes, Actual: int(update.Size)}
		}
		if len(update.Ciphertext) > MaxArtifactBytes+16 {
			return &OversizeError{Bound: "encrypted artifact bytes", Limit: MaxArtifactBytes + 16, Actual: len(update.Ciphertext)}
		}
		if update.Status != "" && update.Status != "ready" && update.Status != "available" {
			return ErrInvalidTransition
		}
		now := s.task5Now()
		var row operationArtifactRow
		q := tx.Where("artifact_id = ?", update.ArtifactID).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			if err := s.createTask5ArtifactParticipant(ctx, tx, update, now, result); err != nil {
				return err
			}
		} else if q.Error != nil {
			return ErrParticipantFailure
		} else {
			if err := s.updateTask5ArtifactParticipant(tx, update, row, now, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *GORMStore) createTask5ArtifactParticipant(ctx context.Context, tx *gorm.DB, update ArtifactUpdate, now time.Time, result *CommitResult) error {
	var row operationArtifactRow
	if err := participantVersion(update.ExpectedVersion, 0, update.Version, tableOperationArtifacts, "<redacted>"); err != nil {
		return err
	}
	if update.OperationID == "" || len(update.Ciphertext) == 0 || len(update.Nonce) == 0 || update.EncryptionKeyID == "" || !update.ConsumedAt.IsZero() {
		return ErrInvalidTransition
	}
	var operation operationRow
	operationQuery := locked(tx).Select("operation_id", "principal_id").Where("operation_id = ?", update.OperationID).First(&operation)
	if errors.Is(operationQuery.Error, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if operationQuery.Error != nil {
		return ErrParticipantFailure
	}
	owner := update.OwnerPrincipalID
	if owner == "" {
		owner = operation.PrincipalID
	}
	if owner == "" || owner != operation.PrincipalID {
		return ErrInvalidMetadata
	}
	if err := validateTask5ArtifactOpaquePayload(update.Ciphertext, update.Nonce, update.EncryptionKeyID); err != nil {
		return err
	}
	if s.codec == nil {
		return ErrEncryptionUnavailable
	}
	plaintext, decryptErr := openBoundPayload(ctx, s.codec, "artifact/v1", update.ArtifactID, owner, 1, update.Ciphertext, update.Nonce, update.EncryptionKeyID)
	if errors.Is(decryptErr, ErrEncryptionUnavailable) {
		return ErrEncryptionUnavailable
	}
	if decryptErr != nil || int64(len(plaintext)) != update.Size {
		return ErrInvalidMetadata
	}
	var expiry time.Time
	if update.ExpiresAt.IsZero() {
		expiry = now.Add(DefaultArtifactTTL)
	} else {
		var expiryErr error
		expiry, expiryErr = task5ParticipantExpiry(update.ExpiresAt, now, MaxArtifactTTL)
		if expiryErr != nil {
			return expiryErr
		}
	}
	row = operationArtifactRow{ArtifactID: update.ArtifactID, Version: 1, PayloadVersion: 1, OperationID: update.OperationID, OwnerPrincipalID: owner, MediaType: nonempty(update.MediaType, "application/octet-stream"), SafeFilename: update.SafeFilename, Size: update.Size, Status: "available", Ciphertext: task5Copy(update.Ciphertext), Nonce: task5Copy(update.Nonce), EncryptionKeyID: update.EncryptionKeyID, ExpiresAt: expiry}
	q := tx.Create(&row)
	if q.Error != nil {
		return ErrParticipantFailure
	}
	result.ArtifactIDs = append(result.ArtifactIDs, update.ArtifactID)
	return nil
}

func (s *GORMStore) updateTask5ArtifactParticipant(tx *gorm.DB, update ArtifactUpdate, row operationArtifactRow, now time.Time, result *CommitResult) error {
	if (row.Status == "available" || row.Status == "ready") && !row.ExpiresAt.After(now) {
		return &task5ExpiredArtifactError{id: row.ArtifactID, now: now}
	}
	if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableOperationArtifacts, "<redacted>"); err != nil {
		return err
	}
	if row.Status != "ready" && row.Status != "available" {
		return ErrArtifactGone
	}
	if update.Status != "" && update.Status != row.Status && (row.Status != "ready" || update.Status != "available") {
		return ErrInvalidTransition
	}
	if update.OwnerPrincipalID != "" && update.OwnerPrincipalID != row.OwnerPrincipalID {
		return ErrInvalidMetadata
	}
	if update.OperationID != "" || update.MediaType != "" || update.SafeFilename != "" || !update.ConsumedAt.IsZero() ||
		len(update.Ciphertext) > 0 || len(update.Nonce) > 0 || update.Size != 0 || update.EncryptionKeyID != "" {
		return ErrInvalidTransition
	}
	if !update.ExpiresAt.IsZero() {
		return ErrInvalidTransition
	}
	if update.ExpectedVersion != row.Version {
		return participantConflict(tableOperationArtifacts)
	}
	version, versionErr := nextVersion(row.Version)
	if versionErr != nil {
		return versionErr
	}
	if update.Status != "" {
		row.Status = update.Status
	}
	if len(update.Ciphertext) > 0 {
		row.Ciphertext = task5Copy(update.Ciphertext)
	}
	if len(update.Nonce) > 0 {
		row.Nonce = task5Copy(update.Nonce)
	}
	row.Version = version
	q := tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, update.ExpectedVersion).Updates(map[string]any{"version": row.Version, "operation_id": row.OperationID, "owner_principal_id": row.OwnerPrincipalID, "media_type": row.MediaType, "safe_filename": row.SafeFilename, "size": row.Size, "status": row.Status, "ciphertext": row.Ciphertext, "nonce": row.Nonce, "encryption_key_id": row.EncryptionKeyID, "expires_at": row.ExpiresAt, "consumed_at": row.ConsumedAt})
	if q.Error != nil || q.RowsAffected != 1 {
		return ErrStaleLease
	}
	result.ArtifactIDs = append(result.ArtifactIDs, update.ArtifactID)
	return nil
}

var _ InboxRepository = (*GORMStore)(nil)
var _ OutboxRepository = (*GORMStore)(nil)
var _ ArtifactRepository = (*GORMStore)(nil)
var _ OperationRepository = (*GORMStore)(nil)
var _ PrivacyPurger = (*GORMStore)(nil)
