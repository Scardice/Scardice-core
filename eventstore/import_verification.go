package eventstore

import (
	"context"
	"crypto/sha256"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// ImportVerificationSecret contains one persisted plaintext adapter secret.
// Value is valid only during the visitor call and is cleared immediately afterwards.
type ImportVerificationSecret struct {
	SecretRef     string
	SecretVersion uint64
	EndpointID    string
	AdapterID     string
	Value         []byte
}

// ImportVerificationVisitor compares actual persisted contents during offline
// conversion. Values are borrowed for the duration of their callback.
type ImportVerificationVisitor struct {
	Event    func(ImportVerificationEvent) error
	Secret   func(ImportVerificationSecret) error
	PluginKV func(PluginKVItem) error
}

// VisitImportVerification reads one consistent snapshot in bounded pages and
// verifies event checksums before passing actual plaintext contents to callers.
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
	return s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		if _, err := readPublishedProjectionControl(tx); err != nil {
			return err
		}
		if visitor.Event != nil {
			if err := visitImportVerificationEvents(ctx, tx, visitor.Event); err != nil {
				return err
			}
		}
		if visitor.Secret != nil {
			if err := visitImportVerificationSecrets(ctx, tx, visitor.Secret); err != nil {
				return err
			}
		}
		if visitor.PluginKV != nil {
			if err := visitImportVerificationPluginKV(ctx, tx, visitor.PluginKV); err != nil {
				return err
			}
		}
		return nil
	})
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

func visitImportVerificationSecrets(
	ctx context.Context,
	tx *gorm.DB,
	visit func(ImportVerificationSecret) error,
) error {
	var cursorRef string
	var cursorVersion uint64
	hasCursor := false
	for {
		query := tx.WithContext(ctx).Order("secret_ref ASC, secret_version ASC").Limit(importVerificationPageSize)
		if hasCursor {
			query = query.Where("secret_ref > ? OR (secret_ref = ? AND secret_version > ?)", []byte(cursorRef), []byte(cursorRef), cursorVersion)
		}
		var rows []adapterSecretRow
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if len(row.Value) > MaxSecretBytes {
				return &OversizeError{Bound: "secret bytes", Limit: MaxSecretBytes, Actual: len(row.Value)}
			}
			visitErr := visit(ImportVerificationSecret{SecretRef: row.SecretRef, SecretVersion: row.SecretVersion, EndpointID: row.EndpointID, AdapterID: row.AdapterID, Value: row.Value})
			clear(row.Value)
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

func visitImportVerificationPluginKV(ctx context.Context, tx *gorm.DB, visit func(PluginKVItem) error) error {
	var cursorExtension, cursorKey string
	hasCursor := false
	for {
		query := orderPluginKeys(tx.WithContext(ctx).Order(clause.OrderByColumn{Column: clause.Column{Name: "extension_id"}})).Limit(importVerificationPageSize)
		if hasCursor {
			query = query.Where(clause.Or(
				clause.Gt{Column: clause.Column{Name: "extension_id"}, Value: []byte(cursorExtension)},
				clause.And(clause.Eq{Column: clause.Column{Name: "extension_id"}, Value: []byte(cursorExtension)}, clause.Gt{Column: clause.Column{Name: "key"}, Value: []byte(cursorKey)}),
			))
		}
		var rows []pluginKVRow
		if err := query.Find(&rows).Error; err != nil {
			return ErrParticipantFailure
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if len(row.ExtensionID) == 0 || len(row.ExtensionID) > MaxPluginExtensionBytes || len(row.Key) > MaxPluginKeyBytes || len(row.Value) > MaxPluginValueBytes {
				return ErrInvalidMetadata
			}
			item := PluginKVItem{ExtensionID: row.ExtensionID, Key: row.Key, Value: row.Value, Version: row.RowVersion}
			if err := visit(item); err != nil {
				clear(item.Value)
				return err
			}
			clear(item.Value)
		}
		last := rows[len(rows)-1]
		cursorExtension, cursorKey, hasCursor = last.ExtensionID, last.Key, true
		if len(rows) < importVerificationPageSize {
			return nil
		}
	}
}
