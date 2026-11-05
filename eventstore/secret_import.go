package eventstore

import (
	"bytes"
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

// SecretVersionImport is one stored version of an adapter secret to be
// replayed with the version numbers it had.
type SecretVersionImport struct {
	SecretRef     string
	EndpointID    string
	AdapterID     string
	SecretVersion uint64
	// RowVersion is this version's place in the reference's chain: 1 for the
	// first, then 2, 3, ... with no gap.
	RowVersion uint64
	Value      []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ImportSecretVersions replays stored versions of adapter secrets, in one
// transaction, keeping the version numbers they had. It is for offline
// conversion of another store's secrets: the application writes a new version
// as "the version I read", so row version N has to sit at place N of the
// chain, which a normal commit (one new version per reference, numbered by
// the store) cannot reproduce. Versions of one reference must arrive in order
// and continue what is stored; versions of different references may be
// interleaved, so a caller can stream a table in the order it is laid out on
// disk instead of reading it reference by reference.
func (s *GORMStore) ImportSecretVersions(ctx context.Context, versions []SecretVersionImport) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrParticipantFailure
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return err
	}
	for _, version := range versions {
		if version.SecretRef == "" || version.EndpointID == "" || version.AdapterID == "" || version.RowVersion == 0 ||
			version.SecretVersion == 0 || version.SecretVersion >= maxPersistedVersion || version.RowVersion >= maxPersistedVersion {
			return ErrInvalidMetadata
		}
		if len(version.Value) > MaxSecretBytes {
			return ErrOversizeInput
		}
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	type chainHead struct{ row, secret uint64 }
	heads := make(map[string]chainHead)
	rows := make([]adapterSecretRow, 0, len(versions))
	for _, version := range versions {
		head, known := heads[version.SecretRef]
		if !known {
			var latest adapterSecretRow
			query := rawStringQuery(tx, "secret_ref", version.SecretRef).Order("row_version DESC").Take(&latest)
			if query.Error != nil && !errors.Is(query.Error, gorm.ErrRecordNotFound) {
				return ErrParticipantFailure
			}
			if query.Error == nil {
				head = chainHead{row: latest.RowVersion, secret: latest.SecretVersion}
			}
		}
		if version.RowVersion != head.row+1 || version.SecretVersion <= head.secret {
			return ErrParticipantConflict
		}
		heads[version.SecretRef] = chainHead{row: version.RowVersion, secret: version.SecretVersion}
		created, updated := version.CreatedAt, version.UpdatedAt
		if created.IsZero() {
			created = s.task5Now()
		}
		if updated.IsZero() {
			updated = created
		}
		rows = append(rows, adapterSecretRow{
			SecretRef: version.SecretRef, SecretVersion: version.SecretVersion, EndpointID: version.EndpointID, AdapterID: version.AdapterID,
			AdapterType: "opaque", Value: bytes.Clone(version.Value),
			RowVersion: version.RowVersion, CreatedAt: created.UTC(), UpdatedAt: updated.UTC(),
		})
	}
	if len(rows) != 0 {
		if err := tx.CreateInBatches(rows, 200).Error; err != nil {
			return ErrParticipantFailure
		}
	}
	if err := tx.Commit().Error; err != nil {
		return ErrParticipantFailure
	}
	return nil
}
