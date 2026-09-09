package eventstore

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// GetOperationByIdempotency exposes only safe idempotency metadata.
func (s *GORMStore) GetOperationByIdempotency(ctx context.Context, principal, scope, key string) (OperationView, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return OperationView{}, ErrNotFound
	}
	if principal == "" || scope == "" || key == "" {
		return OperationView{}, ErrNotFound
	}
	var row operationRow
	if err := s.db.GORM().WithContext(ctx).Where("principal_id = ? AND idempotency_scope = ? AND idempotency_key = ?", principal, scope, key).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return OperationView{}, ErrNotFound
		}
		return OperationView{}, ErrParticipantFailure
	}
	return OperationView{
		OperationID: row.OperationID, Version: row.Version, Kind: row.Kind, Status: row.Status,
		ResultCode: row.ResultCode, ErrorCode: row.ErrorCode, ArtifactID: row.ArtifactRef,
		PrincipalID: row.PrincipalID, ResourceID: row.ResourceID,
		IdempotencyScope: row.IdempotencyScope, IdempotencyKey: row.IdempotencyKey,
		RequestID: row.RequestID, RequestDigest: append([]byte(nil), row.RequestDigest...),
		CorrelationID: row.CorrelationID, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		ExpiresAt: valueTime(row.ExpiresAt),
	}, nil
}
