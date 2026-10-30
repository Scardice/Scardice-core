package eventstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"

	"gorm.io/gorm"
)

const importVerificationPageSize = MaxUnitOfWorkEvents

// ImportVerificationEvent is the integrity-checked projection of one persisted
// domain event used by offline import verification.
type ImportVerificationEvent struct {
	Stream        StreamID
	StreamVersion uint64
	EventID       string
	CommandID     string
	CorrelationID string
	EventType     string
	SchemaVersion uint16
	PayloadDigest [sha256.Size]byte
	PayloadSize   uint64
}

// ImportVerificationSecret contains one decrypted adapter secret. Plaintext is
// valid only during the visitor call and is cleared immediately afterwards.
type ImportVerificationSecret struct {
	SecretRef     string
	SecretVersion uint64
	EndpointID    string
	AdapterID     string
	Plaintext     []byte
}

// ImportVerificationVisitor receives a consistent, integrity-checked view of
// the records whose plaintext cannot be validated through SQL alone.
type ImportVerificationVisitor struct {
	Event    func(ImportVerificationEvent) error
	Secret   func(ImportVerificationSecret) error
	PluginKV func(PluginKVItem) error
}

// VisitImportVerification validates readiness once, holds one consistent read
// transaction, and visits persisted events and encrypted values in bounded
// pages. It avoids per-record readiness, transaction, and key-file lookups.
func (s *GORMStore) VisitImportVerification(ctx context.Context, visitor ImportVerificationVisitor) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return ErrParticipantFailure
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return err
	}
	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return ErrParticipantFailure
	}
	defer tx.Rollback()
	if err := s.lockMutationPublication(ctx, tx); err != nil {
		return err
	}
	readiness, err := readinessFromDB(ctx, tx)
	if err != nil {
		return err
	}
	admittedRoots := make(map[string]struct{}, len(readiness.EncryptionRootIDs))
	for _, rootID := range readiness.EncryptionRootIDs {
		admittedRoots[rootID] = struct{}{}
	}
	roots := newStoryLogImportRootCache()
	defer roots.clear()

	if visitor.Event != nil {
		if err := visitImportVerificationEvents(ctx, tx, visitor.Event); err != nil {
			return err
		}
	}
	if visitor.Secret != nil {
		if err := s.visitImportVerificationSecrets(ctx, tx, admittedRoots, roots, visitor.Secret); err != nil {
			return err
		}
	}
	if visitor.PluginKV != nil {
		_, material, err := keySourceIndex(ctx, s.keySource)
		if err != nil {
			return err
		}
		indexMaterial := append([]byte(nil), material...)
		defer clear(indexMaterial)
		if err := s.visitImportVerificationPluginKV(ctx, tx, admittedRoots, roots, indexMaterial, visitor.PluginKV); err != nil {
			return err
		}
	}
	return nil
}

func visitImportVerificationEvents(ctx context.Context, tx *gorm.DB, visit func(ImportVerificationEvent) error) error {
	var cursor uint64
	hasCursor := false
	for {
		query := tx.WithContext(ctx).Order("global_position ASC").Limit(importVerificationPageSize)
		if hasCursor {
			query = query.Where("global_position > ?", cursor)
		}
		var rows []domainEventRow
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			var checksum EventChecksum
			if len(row.Checksum) != len(checksum) {
				return ErrChecksumMismatch
			}
			copy(checksum[:], row.Checksum)
			envelope := Envelope{
				Stream:        StreamID{AggregateType: row.AggregateType, AggregateID: row.AggregateID},
				StreamVersion: row.AggregateVersion, GlobalPosition: row.GlobalPosition,
				EventID: row.EventID, EventType: row.EventType, SchemaVersion: row.SchemaVersion,
				Payload: row.Payload,
				Metadata: Metadata{
					EventID: row.EventID, CommandID: row.CommandID, CorrelationID: row.CorrelationID,
					CausationID: row.CausationID, PrincipalID: row.PrincipalID, Producer: row.Producer,
					OccurredAtUnixNanoUTC: row.OccurredAtUnixNanoUTC, OccurredAtUnixNanoSet: true,
				},
				Checksum: checksum,
			}
			if _, err := verifyEnvelopeChecksum(envelope); err != nil {
				return err
			}
			if err := visit(ImportVerificationEvent{
				Stream: envelope.Stream, StreamVersion: envelope.StreamVersion,
				EventID: envelope.EventID, CommandID: envelope.Metadata.CommandID, CorrelationID: envelope.Metadata.CorrelationID,
				EventType: envelope.EventType, SchemaVersion: envelope.SchemaVersion,
				PayloadDigest: sha256.Sum256(row.Payload), PayloadSize: uint64(len(row.Payload)),
			}); err != nil {
				return err
			}
		}
		cursor, hasCursor = rows[len(rows)-1].GlobalPosition, true
		if len(rows) < importVerificationPageSize {
			return nil
		}
	}
}

func (s *GORMStore) visitImportVerificationSecrets(
	ctx context.Context,
	tx *gorm.DB,
	admittedRoots map[string]struct{},
	roots *storyLogImportRootCache,
	visit func(ImportVerificationSecret) error,
) error {
	var cursorRef string
	var cursorVersion uint64
	hasCursor := false
	for {
		query := tx.WithContext(ctx).Order("secret_ref ASC, secret_version ASC").Limit(importVerificationPageSize)
		if hasCursor {
			query = query.Where("secret_ref > ? OR (secret_ref = ? AND secret_version > ?)", cursorRef, cursorRef, cursorVersion)
		}
		var rows []adapterSecretRow
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if len(row.Ciphertext) > MaxSecretBytes+16 {
				return &OversizeError{Bound: "encrypted secret bytes", Limit: MaxSecretBytes + 16, Actual: len(row.Ciphertext)}
			}
			if len(row.Nonce) != 12 {
				return ErrInvalidMetadata
			}
			if _, ok := admittedRoots[row.EncryptionKeyID]; !ok {
				return ErrKeyUnavailable
			}
			plain, err := s.openA6WithRootCache(ctx, roots, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, row.EncryptionKeyID, row.Ciphertext, row.Nonce)
			if err != nil {
				return ErrAuthenticationFailed
			}
			if len(plain) > MaxSecretBytes {
				clear(plain)
				return &OversizeError{Bound: "secret bytes", Limit: MaxSecretBytes, Actual: len(plain)}
			}
			visitErr := visit(ImportVerificationSecret{SecretRef: row.SecretRef, SecretVersion: row.SecretVersion, EndpointID: row.EndpointID, AdapterID: row.AdapterID, Plaintext: plain})
			clear(plain)
			if visitErr != nil {
				return visitErr
			}
		}
		last := rows[len(rows)-1]
		cursorRef, cursorVersion, hasCursor = last.SecretRef, last.SecretVersion, true
		if len(rows) < importVerificationPageSize {
			return nil
		}
	}
}

func (s *GORMStore) visitImportVerificationPluginKV(
	ctx context.Context,
	tx *gorm.DB,
	admittedRoots map[string]struct{},
	roots *storyLogImportRootCache,
	indexMaterial []byte,
	visit func(PluginKVItem) error,
) error {
	var cursorExtension string
	var cursorKey []byte
	hasCursor := false
	for {
		query := tx.WithContext(ctx).Order("extension_id ASC, key_hmac ASC").Limit(importVerificationPageSize)
		if hasCursor {
			query = query.Where("extension_id > ? OR (extension_id = ? AND key_hmac > ?)", cursorExtension, cursorExtension, cursorKey)
		}
		var rows []pluginKVRow
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if row.ValueSize < 0 || row.ValueSize > MaxPluginValueBytes {
				return &OversizeError{Bound: "plugin value bytes", Limit: MaxPluginValueBytes, Actual: int(row.ValueSize)}
			}
			if len(row.EncryptedKey) > MaxPluginKeyBytes+16 || len(row.EncryptedValue) > MaxPluginValueBytes+16 {
				return ErrOversizeInput
			}
			if len(row.KeyNonce) != 12 || len(row.ValueNonce) != 12 {
				return ErrInvalidMetadata
			}
			if _, ok := admittedRoots[row.EncryptionKeyID]; !ok {
				return ErrKeyUnavailable
			}
			key, err := s.openA6WithRootCache(ctx, roots, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedKey, row.KeyNonce)
			if err != nil {
				return ErrAuthenticationFailed
			}
			value, err := s.openA6WithRootCache(ctx, roots, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion, row.EncryptionKeyID, row.EncryptedValue, row.ValueNonce)
			if err != nil {
				clear(key)
				return ErrAuthenticationFailed
			}
			if len(row.ExtensionID) == 0 || len(row.ExtensionID) > MaxPluginExtensionBytes || len(key) > MaxPluginKeyBytes || len(value) > MaxPluginValueBytes || int64(len(value)) != row.ValueSize {
				clear(key)
				clear(value)
				return ErrInvalidMetadata
			}
			expected, err := privacyHMACWithMaterial(indexMaterial, "plugin-key-index/v1", row.ExtensionID, string(key))
			if err != nil || !hmac.Equal(expected, row.KeyHMAC) {
				clear(key)
				clear(value)
				return ErrAuthenticationFailed
			}
			item := PluginKVItem{ExtensionID: row.ExtensionID, Key: string(key), Value: value, Version: row.RowVersion}
			visitErr := visit(item)
			clear(key)
			clear(value)
			if visitErr != nil {
				return visitErr
			}
		}
		last := rows[len(rows)-1]
		cursorExtension = last.ExtensionID
		cursorKey = append(cursorKey[:0], last.KeyHMAC...)
		hasCursor = true
		if len(rows) < importVerificationPageSize {
			return nil
		}
	}
}
