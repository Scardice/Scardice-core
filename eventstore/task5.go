package eventstore

import (
	"context"
	"bytes"
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"math"
	"sort"
	"strings"
	"time"
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

const (
	inboxLaneKind        = "inbox"
	outboxLaneKind       = "outbox"
	defaultLeaseDuration = time.Minute
	task5PayloadLimit = 2 * 1024 * 1024
	task5NonceLimit      = 12
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
		return ErrAuthenticationFailed
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
		EncryptBound(context.Context, string, string, string, uint64, []byte) ([]byte, []byte, string, error)
	})
	_, decryptOK := codec.(interface {
		DecryptBound(context.Context, string, string, string, uint64, []byte, []byte, string) ([]byte, error)
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
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
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
	if err := task5ValidateKeyFields(s.keySource, update.DigestKeyID, update.PayloadEncryptionKeyID); err != nil {
		return CommitResult{}, err
	}
	payloadKeyID := task5PayloadKeyID(update)
	digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, update.ContentDigestKeyID)
	if digestErr != nil {
		return CommitResult{}, digestErr
	}
	update.ContentDigestKeyID = digestKeyID
	if err := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); err != nil {
		return CommitResult{}, err
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
	now := s.task5Now()
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	validatePayload := func() error {
		if err := validateTask5OpaquePayload(update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); err != nil {
			return err
		}
		if s.keySource == nil {
			return nil
		}
		if err := s.requireA6BoundCodec(); err != nil {
			return err
		}
		if err := s.validateA6KeyID(ctx, tx, payloadKeyID); err != nil {
			return err
		}
		if _, decryptErr := openBoundPayload(ctx, s.codec, "inbox/v1", update.InboxID, update.EndpointID, 1, update.PayloadCiphertext, update.PayloadNonce, payloadKeyID); decryptErr != nil {
			return ErrAuthenticationFailed
		}
		return nil
	}
	var existing inboxMessageRow
	q := locked(tx).Where("endpoint_id = ? AND provider_event_id = ?", update.EndpointID, update.ProviderEventKey).First(&existing)
	if q.Error == nil {
		if inboxUnresolved(existing.Status) && existing.PayloadExpiresAt != nil && !existing.PayloadExpiresAt.After(now) {
			original := existing
			if err = task5ScrubInbox(tx, &existing, now, false); err != nil {
				return CommitResult{}, err
			}
			if err = task5Commit(tx); err != nil {
				return CommitResult{}, err
			}
			if !task5InboxDuplicate(original, update) {
				return CommitResult{}, ErrConflict
			}
			return CommitResult{}, ErrPayloadExpired
		}
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
		if err = task5Commit(tx); err != nil {
			return CommitResult{}, err
		}
		return result, nil
	}
	if !errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return CommitResult{}, errors.New("eventstore: dedupe lookup failed")
	}
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
	row := inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID), PayloadExpiresAt: task5Ptr(update.PayloadExpiresAt), WorkflowID: update.WorkflowID}
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
			if err = task5Commit(tx); err != nil {
				return CommitResult{}, err
			}
			return result, nil
		}
		return CommitResult{}, ErrConflict
	}
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{InboxIDs: []string{row.InboxID}, OrderingSequence: sequence, Version: 1}, nil
}

func (s *GORMStore) ClaimInbox(ctx context.Context, req InboxClaimRequest) (lease InboxLease, err error) {
	if err := s.requireReady(ctx); err != nil {
		return InboxLease{}, err
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return InboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	var expiredRows []inboxMessageRow
	expiredQuery := locked(tx).Where("status IN ? AND payload_expires_at IS NOT NULL AND payload_expires_at <= ? AND (payload_ciphertext IS NOT NULL OR payload_nonce IS NOT NULL)", []string{InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous}, now).Find(&expiredRows)
	if expiredQuery.Error != nil {
		return InboxLease{}, errors.New("eventstore: scrub inbox query failed")
	}
	expiredObserved := len(expiredRows) > 0
	for i := range expiredRows {
		if err = task5ScrubInbox(tx, &expiredRows[i], now, true); err != nil {
			return InboxLease{}, err
		}
	}
	commitObservedScrub := func(candidateErr error) error {
		if !expiredObserved {
			return candidateErr
		}
		if commitErr := task5Commit(tx); commitErr != nil {
			return commitErr
		}
		return candidateErr
	}
	var row inboxMessageRow
	q := locked(tx).Where("(status = ? OR (status = ? AND (lease_expiry IS NULL OR lease_expiry <= ?)))", InboxStatusPending, InboxStatusLeased, now).Where("NOT EXISTS (SELECT 1 FROM inbox_messages p WHERE p.lane_hmac = inbox_messages.lane_hmac AND p.ordering_sequence < inbox_messages.ordering_sequence AND p.status IN ?)", []string{InboxStatusPending, InboxStatusLeased, InboxStatusCallbackStarted, InboxStatusAmbiguous}).Order("ordering_sequence ASC").First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		if err = task5Commit(tx); err != nil {
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
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if len(row.PayloadCiphertext) > 0 || len(row.PayloadNonce) > 0 {
			if err = task5ScrubInbox(tx, &row, now, true); err != nil {
				return InboxLease{}, err
			}
		}
		if err = task5Commit(tx); err != nil {
			return InboxLease{}, err
		}
		return InboxLease{}, ErrPayloadExpired
	}
	if err = s.task5ValidatePayload(ctx, tx, "inbox/v1", row.InboxID, row.EndpointID, task5PayloadVersion(row.PayloadVersion), row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID, false); err != nil {
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
	q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ?", row.InboxID, row.Version).Updates(updates)
	if q.Error != nil {
		return InboxLease{}, commitObservedScrub(errors.New("eventstore: claim inbox failed"))
	}
	if q.RowsAffected != 1 {
		return InboxLease{}, commitObservedScrub(ErrStaleLease)
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID = InboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt
	lease.Update = inboxUpdateFromRow(row)
	if err = task5Commit(tx); err != nil {
		return InboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) UpdateInbox(ctx context.Context, update InboxUpdate) (result CommitResult, err error) {
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubInbox(tx, &row, now, false); err != nil {
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
		update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || !update.PayloadExpiresAt.IsZero() ||
		update.WorkflowID != "" || !update.CallbackStartedAt.IsZero() || !update.CompletedAt.IsZero() ||
		update.PrincipalID != "" || update.Reason != "" || !update.ResolutionAt.IsZero() {
		return CommitResult{}, ErrInvalidTransition
	}
	if update.Status != InboxStatusLeased && update.Status != InboxStatusCallbackStarted && row.Status != InboxStatusLeased && row.Status != InboxStatusCallbackStarted && (update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero()) {
		return CommitResult{}, ErrStaleLease
	}
	if update.Status != InboxStatusPending || row.Status != InboxStatusPending {
		if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
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
	if update.Status == InboxStatusFailed || update.Status == InboxStatusConfirmedConsumed || update.Status == InboxStatusSkipped {
		row.LeaseExpiry = nil
		row.PayloadCiphertext = nil
		row.PayloadNonce = nil
		row.ResolutionAt = task5Ptr(now)
	}
	q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ? AND (lease_expiry IS NULL OR lease_expiry > ?)", row.InboxID, update.ExpectedVersion, now).Updates(inboxMap(row))
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if (row.Status == InboxStatusPending || row.Status == InboxStatusLeased) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubInbox(tx, &row, now, false); err != nil {
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
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
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
	if err := task5ValidateKeyFields(s.keySource, effect.DigestKeyID, effect.PayloadEncryptionKeyID); err != nil {
		return CommitResult{}, err
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
	now := s.task5Now()
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return CommitResult{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	validatePayload := func() error {
		if err := validateTask5OpaquePayload(effect.PayloadCiphertext, effect.PayloadNonce, payloadKeyID); err != nil {
			return err
		}
		if s.keySource == nil {
			return nil
		}
		if err := s.requireA6BoundCodec(); err != nil {
			return err
		}
		if err := s.validateA6KeyID(ctx, tx, payloadKeyID); err != nil {
			return err
		}
		if _, decryptErr := openBoundPayload(ctx, s.codec, "outbox/v1", effect.EffectID, effect.EndpointID, 1, effect.PayloadCiphertext, effect.PayloadNonce, payloadKeyID); decryptErr != nil {
			return ErrAuthenticationFailed
		}
		return nil
	}
	var existing outboxEffectRow
	lookup := locked(tx).Where("effect_id = ?", effect.EffectID).First(&existing)
	if lookup.Error == nil {
		if outboxUnresolved(existing.Status) && existing.PayloadExpiresAt != nil && !existing.PayloadExpiresAt.After(now) {
			original := existing
			if err = task5ScrubOutbox(tx, &existing, now); err != nil {
				return CommitResult{}, err
			}
			if err = task5Commit(tx); err != nil {
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
	row := outboxEffectRow{EffectID: effect.EffectID, Version: 1, PayloadVersion: 1, EndpointID: effect.EndpointID, LaneHMAC: task5Copy(effect.LaneHMAC), OrderingSequence: seq, EffectClass: effect.EffectType, RiskClass: effect.RiskClass, Status: OutboxStatusPending, PayloadCiphertext: task5Copy(effect.PayloadCiphertext), PayloadNonce: task5Copy(effect.PayloadNonce), EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(effect.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(effect.DigestKeyID, effect.ContentDigestKeyID), DeadlineAt: task5Ptr(effect.DeadlineAt), NextAttemptAt: task5Ptr(effect.NextAttemptAt), PayloadExpiresAt: task5Ptr(effect.PayloadExpiresAt), CreatedAt: now}
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
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, OrderingSequence: seq, Version: 1}, nil
}

func (s *GORMStore) ClaimOutbox(ctx context.Context, req OutboxClaimRequest) (lease OutboxLease, err error) {
	if err := s.requireReady(ctx); err != nil {
		return OutboxLease{}, err
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return OutboxLease{}, err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	now := s.task5Now()
	var expiredRows []outboxEffectRow
	expiredQuery := locked(tx).Where("status IN ? AND payload_expires_at IS NOT NULL AND payload_expires_at <= ? AND (payload_ciphertext IS NOT NULL OR payload_nonce IS NOT NULL)", []string{OutboxStatusPending, OutboxStatusLeased, OutboxStatusDispatched, OutboxStatusAmbiguous}, now).Find(&expiredRows)
	if expiredQuery.Error != nil {
		return OutboxLease{}, errors.New("eventstore: scrub outbox query failed")
	}
	expiredObserved := len(expiredRows) > 0
	for i := range expiredRows {
		if expiredRows[i].Status == OutboxStatusDispatched && expiredRows[i].DispatchedAt != nil && expiredRows[i].RiskClass != RiskProviderIdempotent {
			expiredRows[i].Status = OutboxStatusAmbiguous
			expiredRows[i].LeaseExpiry = nil
			expiredRows[i].ResolutionReason = "expired-after-dispatch"
			expiredRows[i].ResolutionAt = task5Ptr(now)
		}
		if err = task5ScrubOutbox(tx, &expiredRows[i], now); err != nil {
			return OutboxLease{}, err
		}
	}
	commitObservedScrub := func(candidateErr error) error {
		if !expiredObserved {
			return candidateErr
		}
		if commitErr := task5Commit(tx); commitErr != nil {
			return commitErr
		}
		return candidateErr
	}
	var row outboxEffectRow
	q := locked(tx).Where("((status = ? AND (next_attempt_at IS NULL OR next_attempt_at <= ?)) OR (status = ? AND (lease_expiry IS NULL OR lease_expiry <= ?)) OR (status = ? AND lease_expiry IS NOT NULL AND lease_expiry <= ?))", OutboxStatusPending, now, OutboxStatusLeased, now, OutboxStatusDispatched, now).Where("NOT EXISTS (SELECT 1 FROM outbox_effects p WHERE p.lane_hmac = outbox_effects.lane_hmac AND p.ordering_sequence < outbox_effects.ordering_sequence AND p.status IN ?)", []string{OutboxStatusPending, OutboxStatusLeased, OutboxStatusDispatched, OutboxStatusAmbiguous}).Order("ordering_sequence ASC").First(&row)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		if err = task5Commit(tx); err != nil {
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
	if (row.Status == OutboxStatusLeased || row.Status == OutboxStatusDispatched) && row.LeaseExpiry != nil && !row.LeaseExpiry.After(now) && row.DispatchedAt != nil && row.RiskClass != RiskProviderIdempotent {
		version, vErr := nextVersion(row.Version)
		if vErr != nil {
			return OutboxLease{}, commitObservedScrub(vErr)
		}
		row.Status, row.Version, row.ResolutionReason, row.ResolutionAt, row.LeaseExpiry = OutboxStatusAmbiguous, version, "expired-after-dispatch", task5Ptr(now), nil
		q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, version-1).Updates(outboxMap(row))
		if q.Error != nil || q.RowsAffected != 1 {
			return OutboxLease{}, commitObservedScrub(ErrStaleLease)
		}
		if err = task5Commit(tx); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrNotFound
	}
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if len(row.PayloadCiphertext) > 0 || len(row.PayloadNonce) > 0 {
			if err = task5ScrubOutbox(tx, &row, now); err != nil {
				return OutboxLease{}, err
			}
		}
		if err = task5Commit(tx); err != nil {
			return OutboxLease{}, err
		}
		return OutboxLease{}, ErrPayloadExpired
	}
	if err = s.task5ValidatePayload(ctx, tx, "outbox/v1", row.EffectID, row.EndpointID, task5PayloadVersion(row.PayloadVersion), row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID, false); err != nil {
		return OutboxLease{}, commitObservedScrub(err)
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
	q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ?", row.EffectID, row.Version).Updates(updates)
	if q.Error != nil {
		return OutboxLease{}, commitObservedScrub(errors.New("eventstore: claim outbox failed"))
	}
	if q.RowsAffected != 1 {
		return OutboxLease{}, commitObservedScrub(ErrStaleLease)
	}
	row.Status, row.Version, row.LeaseOwner, row.LeaseEpoch, row.LeaseExpiry, row.AttemptID, row.RetryCount = OutboxStatusLeased, version, req.WorkerID, row.LeaseEpoch+1, &expires, attempt, retry
	lease.Effect = effectFromRow(row)
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) UpdateOutbox(ctx context.Context, effect NewEffect) (result CommitResult, err error) {
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
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
	if err = task5Commit(tx); err != nil {
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
	if err := s.requireReady(ctx); err != nil {
		return OutboxLease{}, err
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5Commit(tx); err != nil {
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
	if err = task5Commit(tx); err != nil {
		return OutboxLease{}, err
	}
	return lease, nil
}

func (s *GORMStore) MarkOutboxDispatched(ctx context.Context, req OutboxDispatchRequest) (lease OutboxLease, err error) {
	if err := s.requireReady(ctx); err != nil {
		return OutboxLease{}, err
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return OutboxLease{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return OutboxLease{}, err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return OutboxLease{}, err
		}
		if err = task5Commit(tx); err != nil {
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
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return CommitResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return CommitResult{}, err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if row.Status != OutboxStatusAmbiguous && outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
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
	if err = task5Commit(tx); err != nil {
		return CommitResult{}, err
	}
	return CommitResult{EffectIDs: []string{row.EffectID}, Version: row.Version}, nil
}
func (s *GORMStore) DispatchOutbox(ctx context.Context, req OutboxDispatchRequest) (OutboxLease, error) {
	return s.MarkOutboxDispatched(ctx, req)
}

func (s *GORMStore) ResolveOutbox(ctx context.Context, req OutboxResolutionRequest) (result CommitResult, err error) {
	if err := s.requireReady(ctx); err != nil {
		return CommitResult{}, err
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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
	now := s.task5Now()
	if row.Status != OutboxStatusAmbiguous && outboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
		if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return CommitResult{}, err
		}
		if err = task5Commit(tx); err != nil {
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
		if row.RetryCount < math.MaxUint32 {
			row.RetryCount++
		}
		row.NextAttemptAt = task5Ptr(now)
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
func task5LeaseActive(expiry *time.Time, now time.Time) bool {
	return expiry != nil && expiry.After(now)
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
func task5ScrubOutbox(tx *gorm.DB, row *outboxEffectRow, now time.Time) error {
	nonIdempotentDispatch := row.Status == OutboxStatusDispatched && row.DispatchedAt != nil && row.RiskClass != RiskProviderIdempotent
	if len(row.PayloadCiphertext) == 0 && len(row.PayloadNonce) == 0 && !nonIdempotentDispatch {
		return nil
	}
	row.PayloadCiphertext = nil
	row.PayloadNonce = nil
	if nonIdempotentDispatch {
		row.Status = OutboxStatusAmbiguous
		row.LeaseExpiry = nil
	}
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

func inboxMap(row inboxMessageRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "attempt_id": row.AttemptID, "callback_started_at": row.CallbackStartedAt, "completed_at": row.CompletedAt, "payload_ciphertext": row.PayloadCiphertext, "payload_nonce": row.PayloadNonce, "encryption_key_id": row.EncryptionKeyID, "content_digest": row.ContentDigest, "content_digest_key_id": row.ContentDigestKeyID, "payload_expires_at": row.PayloadExpiresAt, "workflow_id": row.WorkflowID, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}
func outboxMap(row outboxEffectRow) map[string]any {
	return map[string]any{"version": row.Version, "status": row.Status, "attempt_id": row.AttemptID, "lease_owner": row.LeaseOwner, "lease_epoch": row.LeaseEpoch, "lease_expiry": row.LeaseExpiry, "dispatched_at": row.DispatchedAt, "deadline_at": row.DeadlineAt, "next_attempt_at": row.NextAttemptAt, "payload_ciphertext": row.PayloadCiphertext, "payload_nonce": row.PayloadNonce, "encryption_key_id": row.EncryptionKeyID, "content_digest": row.ContentDigest, "content_digest_key_id": row.ContentDigestKeyID, "result_code": row.ResultCode, "error_code": row.ErrorCode, "provider_message_id": row.ProviderMessageID, "completed_at": row.CompletedAt, "payload_expires_at": row.PayloadExpiresAt, "retry_count": row.RetryCount, "scrubbed_at": row.ScrubbedAt, "resolution_principal": row.ResolutionPrincipal, "resolution_reason": row.ResolutionReason, "resolution_at": row.ResolutionAt}
}
func (s *GORMStore) task5PersistExpiredArtifacts(ctx context.Context, work UnitOfWork, first *task5ExpiredArtifactError) error {
	base, err := s.task5Base(ctx)
	if err != nil {
		return err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return err
	}
	defer func() {
		if err != nil {
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
	base, err := s.task5Base(ctx)
	if err != nil {
		return err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return err
	}
	defer func() {
		if err != nil {
			task5Rollback(tx)
		}
	}()
	seenInbox := map[string]bool{}
	seenOutbox := map[string]bool{}
	scrubInbox := func(id string, now time.Time) error {
		if id == "" || seenInbox[id] {
			return nil
		}
		var row inboxMessageRow
		if q := locked(tx).Where("inbox_id = ?", id).First(&row); q.Error != nil {
			return ErrParticipantFailure
		} else if len(row.PayloadCiphertext) == 0 && len(row.PayloadNonce) == 0 {
			seenInbox[id] = true
			return nil
		} else if err = task5ScrubInbox(tx, &row, now, false); err != nil {
			return err
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
		} else if len(row.PayloadCiphertext) == 0 && len(row.PayloadNonce) == 0 {
			seenOutbox[id] = true
			return nil
		} else if err = task5ScrubOutbox(tx, &row, now); err != nil {
			return err
		}
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
	if first.table == tableInboxMessages {
		if err = scrubInbox(first.id, first.now); err != nil {
			return err
		}
	} else if first.table == tableOutboxEffects {
		if err = scrubOutbox(first.id, first.now); err != nil {
			return err
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
			if err = scrubInbox(row.InboxID, first.now); err != nil {
				return err
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
			if err = scrubOutbox(row.EffectID, first.now); err != nil {
				return err
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
			if err = scrubArtifact(row.ArtifactID, first.now); err != nil {
				return err
			}
		}
	}
	return task5Commit(tx)
}

func inboxUpdateFromRow(row inboxMessageRow) InboxUpdate {
	return InboxUpdate{
		InboxID: row.InboxID, ExpectedVersion: row.Version, Version: row.Version,
		EndpointID: row.EndpointID, ProviderEventKey: row.ProviderEventKey, LaneHMAC: task5Copy(row.LaneHMAC),
		OrderingSequence: row.OrderingSequence, Status: row.Status, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch,
		LeaseExpiresAt: valueTime(row.LeaseExpiry), AttemptID: row.AttemptID, PayloadCiphertext: task5Copy(row.PayloadCiphertext),
		PayloadNonce: task5Copy(row.PayloadNonce), ContentDigest: task5Copy(row.ContentDigest), DigestKeyID: row.ContentDigestKeyID,
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
		RiskClass: row.RiskClass, Status: row.Status, AttemptID: row.AttemptID, LeaseOwner: row.LeaseOwner,
		LeaseEpoch: row.LeaseEpoch, LeaseExpiresAt: valueTime(row.LeaseExpiry), DeadlineAt: valueTime(row.DeadlineAt),
		NextAttemptAt: valueTime(row.NextAttemptAt), DispatchedAt: valueTime(row.DispatchedAt),
		PayloadCiphertext: task5Copy(row.PayloadCiphertext), PayloadNonce: task5Copy(row.PayloadNonce),
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
func sealBoundPayload(ctx context.Context, codec any, domain, identity, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	if bound, ok := codec.(interface {
		EncryptBound(context.Context, string, string, string, uint64, []byte) ([]byte, []byte, string, error)
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
		DecryptBound(context.Context, string, string, string, uint64, []byte, []byte, string) ([]byte, error)
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
	if err := s.requireReady(ctx); err != nil {
		return ArtifactPutResult{}, err
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
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
		return ArtifactPutResult{}, err
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
	if err := s.requireReady(ctx); err != nil {
		return ArtifactResult{}, err
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return ArtifactResult{}, err
	}
	tx, err := task5Begin(base)
	if err != nil {
		return ArtifactResult{}, err
	}
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		task5Rollback(tx)
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

func task5ParticipantExpiry(expiry time.Time, now time.Time, max time.Duration) (time.Time, error) {
	if expiry.IsZero() {
		return now.Add(max), nil
	}
	expiry = expiry.UTC()
	if !expiry.After(now) {
		return time.Time{}, ErrPayloadExpired
	}
	if expiry.After(now.Add(max)) {
		return time.Time{}, ErrInvalidTTL
	}
	return expiry, nil
}

func (s *GORMStore) applyTask5InboxParticipants(ctx context.Context, tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	updates := append([]InboxUpdate(nil), work.InboxUpdates...)
	sort.Slice(updates, func(i, j int) bool {
		if laneCompare := bytes.Compare(updates[i].LaneHMAC, updates[j].LaneHMAC); laneCompare != 0 {
			return laneCompare < 0
		}
		return updates[i].InboxID < updates[j].InboxID
	})
	for _, update := range updates {
		payloadKeyID := task5PayloadKeyID(update)
		if err := task5ValidateKeyFields(s.keySource, update.DigestKeyID, update.PayloadEncryptionKeyID); err != nil {
			return err
		}
		digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, update.ContentDigestKeyID)
		if digestErr != nil {
			return digestErr
		}
		update.ContentDigestKeyID = digestKeyID
		if update.InboxID == "" {
			return ErrParticipantFailure
		}
		var row inboxMessageRow
		q := tx.Where("inbox_id = ?", update.InboxID).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
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
				continue
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
			row = inboxMessageRow{InboxID: update.InboxID, EndpointID: update.EndpointID, ProviderEventKey: update.ProviderEventKey, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, Status: status, Version: 1, PayloadVersion: 1, LeaseOwner: update.LeaseOwner, LeaseEpoch: update.LeaseEpoch, LeaseExpiry: task5Ptr(update.LeaseExpiresAt), AttemptID: update.AttemptID, CallbackStartedAt: task5Ptr(update.CallbackStartedAt), CompletedAt: task5Ptr(update.CompletedAt), PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID), PayloadExpiresAt: task5Ptr(expiry), WorkflowID: update.WorkflowID, ResolutionPrincipal: update.PrincipalID, ResolutionReason: update.Reason, ResolutionAt: task5Ptr(update.ResolutionAt)}
			if q = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row); q.Error != nil {
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
				continue
			}
			result.OrderingSequence, result.Version = sequence, row.Version
		} else if q.Error != nil {
			return ErrParticipantFailure
		} else {
			now := s.task5Now()
			if inboxUnresolved(row.Status) && row.PayloadExpiresAt != nil && !row.PayloadExpiresAt.After(now) {
				return &task5ExpiredPayloadError{table: tableInboxMessages, id: row.InboxID, now: now}
			}
			hasOpaqueReplay := len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0
			if hasOpaqueReplay {
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
				continue
			}
			if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableInboxMessages, "<redacted>"); err != nil {
				return err
			}
			if row.Status == InboxStatusFailed || row.Status == InboxStatusConfirmedConsumed || row.Status == InboxStatusSkipped {
				return ErrInvalidTransition
			}
			if update.EndpointID != "" || update.ProviderEventKey != "" || len(update.LaneHMAC) > 0 || update.OrderingSequence != 0 || update.WorkflowID != "" ||
				len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.DigestKeyID != "" ||
				update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || !update.PayloadExpiresAt.IsZero() {
				return ErrInvalidTransition
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
				if !task5LeaseMatches(row.LeaseOwner, row.LeaseEpoch, row.AttemptID, update.LeaseOwner, update.LeaseEpoch, update.AttemptID) || !task5LeaseActive(row.LeaseExpiry, now) {
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
			if update.Status == InboxStatusFailed || update.Status == InboxStatusConfirmedConsumed || update.Status == InboxStatusSkipped {
				row.LeaseExpiry = nil
				row.PayloadCiphertext = nil
				row.PayloadNonce = nil
				row.ResolutionAt = task5Ptr(now)
			}
			row.Version = version
			q = tx.Model(&inboxMessageRow{}).Where("inbox_id = ? AND version = ? AND (lease_expiry IS NULL OR lease_expiry > ?)", row.InboxID, update.ExpectedVersion, now).Updates(inboxParticipantMap(row))
			if q.Error != nil || q.RowsAffected != 1 {
				return ErrStaleLease
			}
		}
		result.InboxIDs = append(result.InboxIDs, update.InboxID)
	}
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
	sort.Slice(updates, func(i, j int) bool {
		if laneCompare := bytes.Compare(updates[i].LaneHMAC, updates[j].LaneHMAC); laneCompare != 0 {
			return laneCompare < 0
		}
		return updates[i].EffectID < updates[j].EffectID
	})
	for _, update := range updates {
		payloadKeyID := task5EffectPayloadKeyID(update)
		if err := task5ValidateKeyFields(s.keySource, update.DigestKeyID, update.PayloadEncryptionKeyID); err != nil {
			return err
		}
		digestKeyID, digestErr := s.task5CanonicalDigestKeyID(ctx, update.ContentDigestKeyID)
		if digestErr != nil {
			return digestErr
		}
		update.ContentDigestKeyID = digestKeyID
		if update.EffectID == "" {
			return ErrParticipantFailure
		}
		var row outboxEffectRow
		q := tx.Where("effect_id = ?", update.EffectID).First(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
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
				continue
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
			row = outboxEffectRow{EffectID: update.EffectID, Version: 1, PayloadVersion: 1, EndpointID: update.EndpointID, LaneHMAC: task5Copy(update.LaneHMAC), OrderingSequence: sequence, EffectClass: update.EffectType, RiskClass: risk, Status: status, AttemptID: update.AttemptID, LeaseOwner: update.LeaseOwner, LeaseEpoch: update.LeaseEpoch, LeaseExpiry: task5Ptr(update.LeaseExpiresAt), DispatchedAt: task5Ptr(update.DispatchedAt), DeadlineAt: task5Ptr(update.DeadlineAt), NextAttemptAt: task5Ptr(update.NextAttemptAt), PayloadCiphertext: task5Copy(update.PayloadCiphertext), PayloadNonce: task5Copy(update.PayloadNonce), EncryptionKeyID: payloadKeyID, ContentDigest: task5Copy(update.ContentDigest), ContentDigestKeyID: task5ContentDigestKeyID(update.DigestKeyID, update.ContentDigestKeyID), ResultCode: update.ResultCode, ErrorCode: update.ErrorCode, ProviderMessageID: update.ProviderMessageID, CompletedAt: task5Ptr(update.CompletedAt), PayloadExpiresAt: task5Ptr(expiry), CreatedAt: now, RetryCount: update.RetryCount}
			if q = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row); q.Error != nil {
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
				continue
			}
			result.OrderingSequence, result.Version = sequence, row.Version
		} else if q.Error != nil {
			return ErrParticipantFailure
		} else {
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
				if (update.Status != "" && update.Status != OutboxStatusPending) || update.LeaseOwner != "" || update.LeaseEpoch != 0 || update.AttemptID != "" || !update.LeaseExpiresAt.IsZero() || !update.DispatchedAt.IsZero() || !update.CompletedAt.IsZero() || update.ProviderMessageID != "" || update.ResultCode != "" || update.ErrorCode != "" || update.RetryCount != 0 || update.PrincipalID != "" || update.Reason != "" || update.Resolution != "" || !update.ResolutionAt.IsZero() {
					return ErrInvalidTransition
				}
				result.EffectIDs = append(result.EffectIDs, row.EffectID)
				result.Deduplicated, result.Idempotent, result.OrderingSequence, result.Version = true, true, row.OrderingSequence, row.Version
				continue
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
			if update.EndpointID != "" || len(update.LaneHMAC) > 0 || update.OrderingSequence != 0 || update.EffectType != "" ||
				len(update.PayloadCiphertext) > 0 || len(update.PayloadNonce) > 0 || len(update.ContentDigest) > 0 || update.DigestKeyID != "" ||
				update.PayloadEncryptionKeyID != "" || update.ContentDigestKeyID != "" || !update.PayloadExpiresAt.IsZero() || !update.DispatchedAt.IsZero() || update.ResultCode != "" || update.ErrorCode != "" || update.ProviderMessageID != "" {
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
			if row.Status == OutboxStatusDispatched && (update.Status == OutboxStatusSucceeded || update.Status == OutboxStatusFailed) {
				return ErrInvalidTransition
			}
			if update.Status != "" {
				if !validOutboxStatus(update.Status) || !outboxTransitionAllowed(row.Status, update.Status) {
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
			q = tx.Model(&outboxEffectRow{}).Where("effect_id = ? AND version = ? AND (lease_expiry IS NULL OR lease_expiry > ?)", row.EffectID, update.ExpectedVersion, now).Updates(outboxMap(row))
			if q.Error != nil || q.RowsAffected != 1 {
				return ErrStaleLease
			}
		}
		result.EffectIDs = append(result.EffectIDs, update.EffectID)
	}
	return nil
}

func (s *GORMStore) applyTask5ArtifactParticipants(tx *gorm.DB, work UnitOfWork, result *CommitResult) error {
	updates := append([]ArtifactUpdate(nil), work.ArtifactUpdates...)
	sort.Slice(updates, func(i, j int) bool { return updates[i].ArtifactID < updates[j].ArtifactID })
	for _, update := range updates {
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
			plaintext, decryptErr := openBoundPayload(context.Background(), s.codec, "artifact/v1", update.ArtifactID, owner, 1, update.Ciphertext, update.Nonce, update.EncryptionKeyID)
			if errors.Is(decryptErr, ErrEncryptionUnavailable) {
				return ErrEncryptionUnavailable
			}
			if decryptErr != nil || int64(len(plaintext)) != update.Size {
				return ErrInvalidMetadata
			}
			expiry := update.ExpiresAt.UTC()
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
			if q = tx.Create(&row); q.Error != nil {
				return ErrParticipantFailure
			}
		} else if q.Error != nil {
			return ErrParticipantFailure
		} else {
			if (row.Status == "available" || row.Status == "ready") && !row.ExpiresAt.After(now) {
				return &task5ExpiredArtifactError{id: row.ArtifactID, now: now}
			}
			if err := participantVersion(update.ExpectedVersion, row.Version, update.Version, tableOperationArtifacts, "<redacted>"); err != nil {
				return err
			}
			if row.Status != "ready" && row.Status != "available" {
				return ErrArtifactGone
			}
			if update.Status != "" && update.Status != row.Status && !(row.Status == "ready" && update.Status == "available") {
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
			q = tx.Model(&operationArtifactRow{}).Where("artifact_id = ? AND version = ?", row.ArtifactID, update.ExpectedVersion).Updates(map[string]any{"version": row.Version, "operation_id": row.OperationID, "owner_principal_id": row.OwnerPrincipalID, "media_type": row.MediaType, "safe_filename": row.SafeFilename, "size": row.Size, "status": row.Status, "ciphertext": row.Ciphertext, "nonce": row.Nonce, "encryption_key_id": row.EncryptionKeyID, "expires_at": row.ExpiresAt, "consumed_at": row.ConsumedAt})
			if q.Error != nil || q.RowsAffected != 1 {
				return ErrStaleLease
			}
		}
		result.ArtifactIDs = append(result.ArtifactIDs, update.ArtifactID)
	}
	return nil
}

var _ InboxRepository = (*GORMStore)(nil)
var _ OutboxRepository = (*GORMStore)(nil)
var _ ArtifactRepository = (*GORMStore)(nil)
var _ OperationRepository = (*GORMStore)(nil)
var _ PrivacyPurger = (*GORMStore)(nil)
