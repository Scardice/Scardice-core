package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"gorm.io/gorm"
)

const (
	ExecutionStatusUnknown   = "unknown"
	ExecutionStatusStarted   = "started"
	ExecutionStatusCommitted = "committed"
	ExecutionStatusAmbiguous = "ambiguous"

	MaxExecutionIdentityBytes    = 1024
	MaxExecutionDigestInputBytes = MaxUnitOfWorkBytes
	MaxExecutionLease            = 24 * time.Hour
	DefaultExecutionLease        = time.Minute
)

type ExecutionAdmissionRequest struct {
	Identity      string
	RequestDigest []byte
	LeaseOwner    string
	LeaseDuration time.Duration
}

type ExecutionRenewRequest struct {
	Identity        string
	RequestDigest   []byte
	AttemptID       string
	ExpectedVersion uint64
	LeaseOwner      string
	LeaseEpoch      uint64
	LeaseDuration   time.Duration
}

type ExecutionRecoveryRequest struct {
	Identity        string
	RequestDigest   []byte
	AttemptID       string
	ExpectedVersion uint64
	LeaseOwner      string
	LeaseEpoch      uint64
}

type ExecutionAttemptCommit struct {
	Identity        string
	RequestDigest   []byte
	AttemptID       string
	ExpectedVersion uint64
	LeaseOwner      string
	LeaseEpoch      uint64
}

type ExecutionReceipt struct {
	Status         string
	RequestDigest  []byte
	AttemptID      string
	Version        uint64
	LeaseOwner     string
	LeaseEpoch     uint64
	LeaseExpiresAt time.Time
	StartedAt      time.Time
	CompletedAt    time.Time
	Admitted       bool
}

type ExecutionReceiptRepository interface {
	ExecutionRequestDigest(ctx context.Context, canonicalRequest []byte) ([]byte, error)
	AdmitExecution(ctx context.Context, request ExecutionAdmissionRequest) (ExecutionReceipt, error)
	RenewExecution(ctx context.Context, request ExecutionRenewRequest) (ExecutionReceipt, error)
	RecoverExecution(ctx context.Context, request ExecutionRecoveryRequest) (ExecutionReceipt, error)
	LookupExecution(ctx context.Context, identity string) (ExecutionReceipt, error)
}

type preparedExecutionCommit struct {
	request  ExecutionAttemptCommit
	identity string
}

func executionAdmissionResource(identity string) revisionResourceKey {
	return revisionResourceKey{
		kind:   "execution-admission",
		scope:  identity,
		member: "",
	}
}

func (s *GORMStore) ensureExecutionAdmissionHead(ctx context.Context, identity string) (revisionResourceKey, error) {
	resource := executionAdmissionResource(identity)
	exists, err := s.revisionHeadExists(ctx, resource)
	if err != nil || exists {
		return resource, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return resource, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err = s.lockMutationPublication(ctx, tx); err != nil {
		return resource, err
	}
	if err = s.materializeRevisionHead(tx, resource, 0, true); err != nil {
		return resource, err
	}
	if err = tx.Commit().Error; err != nil {
		return resource, ErrParticipantFailure
	}
	return resource, nil
}

func executionLeaseDuration(duration time.Duration) (time.Duration, error) {
	if duration == 0 {
		return DefaultExecutionLease, nil
	}
	if duration < 0 || duration > MaxExecutionLease {
		return 0, ErrInvalidTTL
	}
	return duration, nil
}

func validateExecutionIdentity(identity string) error {
	if identity == "" || len(identity) > MaxExecutionIdentityBytes {
		return ErrInvalidMetadata
	}
	return nil
}

func validateExecutionDigest(digest []byte) error {
	if len(digest) != sha256.Size {
		return ErrInvalidMetadata
	}
	return nil
}

func validateExecutionAttemptCommit(request ExecutionAttemptCommit) error {
	if err := validateExecutionIdentity(request.Identity); err != nil {
		return err
	}
	if err := validateExecutionDigest(request.RequestDigest); err != nil {
		return err
	}
	if request.AttemptID == "" || len(request.AttemptID) > 255 || request.LeaseOwner == "" || len(request.LeaseOwner) > 255 || request.ExpectedVersion == 0 || request.LeaseEpoch == 0 {
		return ErrInvalidMetadata
	}
	return nil
}

func validateExecutionAdmission(request ExecutionAdmissionRequest) (time.Duration, error) {
	if err := validateExecutionIdentity(request.Identity); err != nil {
		return 0, err
	}
	if err := validateExecutionDigest(request.RequestDigest); err != nil {
		return 0, err
	}
	if request.LeaseOwner == "" || len(request.LeaseOwner) > 255 {
		return 0, ErrInvalidMetadata
	}
	return executionLeaseDuration(request.LeaseDuration)
}

func validateExecutionRenew(request ExecutionRenewRequest) (time.Duration, error) {
	if err := validateExecutionAttemptCommit(ExecutionAttemptCommit{
		Identity: request.Identity, RequestDigest: request.RequestDigest, AttemptID: request.AttemptID,
		ExpectedVersion: request.ExpectedVersion, LeaseOwner: request.LeaseOwner, LeaseEpoch: request.LeaseEpoch,
	}); err != nil {
		return 0, err
	}
	return executionLeaseDuration(request.LeaseDuration)
}

func validateExecutionRecovery(request ExecutionRecoveryRequest) error {
	if err := validateExecutionIdentity(request.Identity); err != nil {
		return err
	}
	if err := validateExecutionDigest(request.RequestDigest); err != nil {
		return err
	}
	if request.AttemptID == "" || len(request.AttemptID) > 255 || request.ExpectedVersion == 0 ||
		(request.LeaseOwner == "") != (request.LeaseEpoch == 0) || len(request.LeaseOwner) > 255 {
		return ErrInvalidMetadata
	}
	return nil
}

func (s *GORMStore) ExecutionRequestDigest(ctx context.Context, canonicalRequest []byte) ([]byte, error) {
	if len(canonicalRequest) > MaxExecutionDigestInputBytes {
		return nil, &OversizeError{Bound: "execution digest input", Limit: MaxExecutionDigestInputBytes, Actual: len(canonicalRequest)}
	}
	return DigestBytes("execution-request/v1", canonicalRequest), nil
}

func executionReceipt(row executionReceiptRow, admitted bool) ExecutionReceipt {
	result := ExecutionReceipt{
		Status: row.Status, RequestDigest: copyDigest(row.RequestDigest), AttemptID: row.AttemptID,
		Version: row.Version, LeaseOwner: row.LeaseOwner, LeaseEpoch: row.LeaseEpoch,
		StartedAt: row.StartedAt, Admitted: admitted,
	}
	if row.LeaseExpiry != nil {
		result.LeaseExpiresAt = *row.LeaseExpiry
	}
	if row.CompletedAt != nil {
		result.CompletedAt = *row.CompletedAt
	}
	return result
}

func lockExecutionContinuationPublication(tx *gorm.DB) error {
	var readiness struct {
		SingletonID string `gorm:"column:singleton_id"`
	}
	if err := lockedShared(tx).Model(&storeReadinessRow{}).
		Select("singleton_id").
		Where("singleton_id = ?", "default").
		First(&readiness).Error; err != nil {
		return ErrParticipantFailure
	}
	var control projectionControlRow
	if err := lockedShared(tx).Where("singleton_id = ?", "default").First(&control).Error; err != nil {
		return ErrParticipantFailure
	}
	if control.PublicationState != "published" {
		return ErrReadinessQuarantined
	}
	return nil
}

func executionDigestMatches(row executionReceiptRow, digest []byte) bool {
	return len(row.RequestDigest) == sha256.Size && bytes.Equal(row.RequestDigest, digest)
}

func (s *GORMStore) AdmitExecution(ctx context.Context, request ExecutionAdmissionRequest) (ExecutionReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	leaseDuration, err := validateExecutionAdmission(request)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	if err = s.requireReady(ctx); err != nil {
		return ExecutionReceipt{}, err
	}
	identity := request.Identity
	admissionResource, err := s.ensureExecutionAdmissionHead(ctx, identity)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	attemptID, err := s.task5ID()
	if err != nil {
		return ExecutionReceipt{}, err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err = lockExecutionContinuationPublication(tx); err != nil {
		return ExecutionReceipt{}, err
	}
	var admissionHead revisionHeadRow
	if err = revisionQuery(locked(tx), admissionResource.kind, admissionResource.scope, admissionResource.member).
		First(&admissionHead).Error; err != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	var existing executionReceiptRow
	queryErr := executionQuery(locked(tx), identity).First(&existing).Error
	if queryErr == nil {
		if !executionDigestMatches(existing, request.RequestDigest) {
			return ExecutionReceipt{}, ErrConflict
		}
		return executionReceipt(existing, false), nil
	}
	if !errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	now := s.task5Now()
	expires := now.Add(leaseDuration)
	row := executionReceiptRow{
		Identity: identity, RequestDigest: copyDigest(request.RequestDigest), AttemptID: attemptID,
		Version: 1, Status: ExecutionStatusStarted, LeaseOwner: request.LeaseOwner, LeaseEpoch: 1,
		LeaseExpiry: &expires, StartedAt: now, UpdatedAt: now,
	}
	if err = tx.Create(&row).Error; err != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	if err = tx.Commit().Error; err != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	return executionReceipt(row, true), nil
}

func (s *GORMStore) LookupExecution(ctx context.Context, identity string) (ExecutionReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateExecutionIdentity(identity); err != nil {
		return ExecutionReceipt{}, err
	}
	if err := s.requireReady(ctx); err != nil {
		return ExecutionReceipt{}, err
	}
	identityKey := identity
	result := ExecutionReceipt{Status: ExecutionStatusUnknown}
	err := s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		if _, readErr := readDependencyControl(tx); readErr != nil {
			return readErr
		}
		var row executionReceiptRow
		readErr := executionQuery(tx, identityKey).First(&row).Error
		if errors.Is(readErr, gorm.ErrRecordNotFound) {
			return nil
		}
		if readErr != nil {
			return ErrParticipantFailure
		}
		result = executionReceipt(row, false)
		return nil
	})
	return result, err
}

func (s *GORMStore) RenewExecution(ctx context.Context, request ExecutionRenewRequest) (ExecutionReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	leaseDuration, err := validateExecutionRenew(request)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	if err = s.requireReady(ctx); err != nil {
		return ExecutionReceipt{}, err
	}
	identity := request.Identity
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err = lockExecutionContinuationPublication(tx); err != nil {
		return ExecutionReceipt{}, err
	}
	var row executionReceiptRow
	if err = executionQuery(locked(tx), identity).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ExecutionReceipt{}, ErrStaleLease
		}
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	now := s.task5Now()
	if !executionDigestMatches(row, request.RequestDigest) || row.Status != ExecutionStatusStarted || row.AttemptID != request.AttemptID || row.Version != request.ExpectedVersion || row.LeaseOwner != request.LeaseOwner || row.LeaseEpoch != request.LeaseEpoch || row.LeaseExpiry == nil || !row.LeaseExpiry.After(now) {
		return ExecutionReceipt{}, ErrStaleLease
	}
	nextVersion, err := nextVersion(row.Version)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	expires := now.Add(leaseDuration)
	q := executionQuery(tx.Model(&executionReceiptRow{}), identity).Where("version = ? AND status = ? AND attempt_id = ? AND lease_owner = ? AND lease_epoch = ? AND lease_expiry > ?", row.Version, ExecutionStatusStarted, row.AttemptID, row.LeaseOwner, row.LeaseEpoch, now).
		Updates(map[string]any{"version": nextVersion, "lease_expiry": expires, "updated_at": now})
	if q.Error != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	if q.RowsAffected != 1 {
		return ExecutionReceipt{}, ErrStaleLease
	}
	row.Version = nextVersion
	row.LeaseExpiry = &expires
	row.UpdatedAt = now
	if err = tx.Commit().Error; err != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	return executionReceipt(row, false), nil
}

func (s *GORMStore) RecoverExecution(ctx context.Context, request ExecutionRecoveryRequest) (ExecutionReceipt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateExecutionRecovery(request); err != nil {
		return ExecutionReceipt{}, err
	}
	if err := s.requireReady(ctx); err != nil {
		return ExecutionReceipt{}, err
	}
	identity := request.Identity
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := lockExecutionContinuationPublication(tx); err != nil {
		return ExecutionReceipt{}, err
	}
	var row executionReceiptRow
	if err := executionQuery(locked(tx), identity).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ExecutionReceipt{Status: ExecutionStatusUnknown}, nil
		}
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	if !executionDigestMatches(row, request.RequestDigest) {
		return ExecutionReceipt{}, ErrConflict
	}
	if row.AttemptID != request.AttemptID {
		return ExecutionReceipt{}, ErrParticipantConflict
	}
	if row.Status == ExecutionStatusCommitted || row.Status == ExecutionStatusAmbiguous {
		return executionReceipt(row, false), nil
	}
	if row.Status != ExecutionStatusStarted || row.Version != request.ExpectedVersion {
		return ExecutionReceipt{}, ErrParticipantConflict
	}
	now := s.task5Now()
	if request.LeaseOwner != "" {
		if row.LeaseOwner != request.LeaseOwner || row.LeaseEpoch != request.LeaseEpoch {
			return ExecutionReceipt{}, ErrStaleLease
		}
	} else if row.LeaseExpiry == nil || row.LeaseExpiry.After(now) {
		return ExecutionReceipt{}, ErrStaleLease
	}
	nextVersion, err := nextVersion(row.Version)
	if err != nil {
		return ExecutionReceipt{}, err
	}
	query := executionQuery(tx.Model(&executionReceiptRow{}), identity).Where("version = ? AND status = ? AND attempt_id = ?", row.Version, ExecutionStatusStarted, row.AttemptID)
	if request.LeaseOwner != "" {
		query = query.Where("lease_owner = ? AND lease_epoch = ?", request.LeaseOwner, request.LeaseEpoch)
	} else {
		query = query.Where("lease_expiry <= ?", now)
	}
	q := query.Updates(map[string]any{"version": nextVersion, "status": ExecutionStatusAmbiguous, "completed_at": now, "updated_at": now})
	if q.Error != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	if q.RowsAffected != 1 {
		return ExecutionReceipt{}, ErrParticipantConflict
	}
	row.Version = nextVersion
	row.Status = ExecutionStatusAmbiguous
	row.CompletedAt = &now
	row.UpdatedAt = now
	if err = tx.Commit().Error; err != nil {
		return ExecutionReceipt{}, ErrParticipantFailure
	}
	return executionReceipt(row, false), nil
}

func (s *GORMStore) prepareExecutionCommit(ctx context.Context, request *ExecutionAttemptCommit) (*preparedExecutionCommit, error) {
	if err := validateExecutionAttemptCommit(*request); err != nil {
		return nil, err
	}
	identity := request.Identity
	copied := *request
	copied.RequestDigest = copyDigest(request.RequestDigest)
	return &preparedExecutionCommit{request: copied, identity: identity}, nil
}

func lockExecutionCommit(tx *gorm.DB, prepared *preparedExecutionCommit, now time.Time) (executionReceiptRow, error) {
	if prepared == nil {
		return executionReceiptRow{}, nil
	}
	var row executionReceiptRow
	if err := executionQuery(locked(tx), prepared.identity).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return executionReceiptRow{}, ErrParticipantConflict
		}
		return executionReceiptRow{}, ErrParticipantFailure
	}
	request := prepared.request
	if !executionDigestMatches(row, request.RequestDigest) || row.Status != ExecutionStatusStarted || row.AttemptID != request.AttemptID || row.Version != request.ExpectedVersion || row.LeaseOwner != request.LeaseOwner || row.LeaseEpoch != request.LeaseEpoch || row.LeaseExpiry == nil || !row.LeaseExpiry.After(now) {
		return executionReceiptRow{}, ErrParticipantConflict
	}
	return row, nil
}

func applyExecutionCommit(tx *gorm.DB, prepared *preparedExecutionCommit, row executionReceiptRow, now time.Time) error {
	if prepared == nil {
		return nil
	}
	nextVersion, err := nextVersion(row.Version)
	if err != nil {
		return err
	}
	request := prepared.request
	q := executionQuery(tx.Model(&executionReceiptRow{}), prepared.identity).Where("version = ? AND status = ? AND attempt_id = ? AND lease_owner = ? AND lease_epoch = ? AND lease_expiry > ?", request.ExpectedVersion, ExecutionStatusStarted, request.AttemptID, request.LeaseOwner, request.LeaseEpoch, now).
		Updates(map[string]any{"version": nextVersion, "status": ExecutionStatusCommitted, "completed_at": now, "updated_at": now})
	if q.Error != nil {
		return ErrParticipantFailure
	}
	if q.RowsAffected != 1 {
		return ErrParticipantConflict
	}
	return nil
}

var _ ExecutionReceiptRepository = (*GORMStore)(nil)
