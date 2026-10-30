package eventstore

import (
	"context"
	"strings"
)

type secretLookupKey struct {
	ref     string
	version uint64
}

// ResolveSecrets resolves exact secret versions in request order under one
// readiness snapshot. It is intended for bounded startup restoration paths.
func (s *GORMStore) ResolveSecrets(ctx context.Context, lookups []SecretLookup) (results []SecretResolution, err error) {
	if len(lookups) == 0 {
		return []SecretResolution{}, nil
	}
	if len(lookups) > MaxSecretBatchLookups {
		return nil, &OversizeError{Bound: "secret batch lookups", Limit: MaxSecretBatchLookups, Actual: len(lookups)}
	}
	if s == nil || s.db == nil || s.db.GORM() == nil || s.keySource == nil {
		return nil, ErrKeySourceUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	positions := make(map[secretLookupKey]int, len(lookups))
	for index, lookup := range lookups {
		key := secretLookupKey{ref: strings.TrimSpace(lookup.SecretRef), version: lookup.SecretVersion}
		if key.ref == "" || len(key.ref) > 255 || key.version == 0 {
			return nil, ErrInvalidMetadata
		}
		if _, duplicate := positions[key]; duplicate {
			return nil, ErrInvalidMetadata
		}
		positions[key] = index
	}
	if err = s.requireReady(ctx); err != nil {
		return nil, err
	}

	tx := s.db.GORM().WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, ErrParticipantFailure
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback().Error
		}
	}()
	if err = s.lockMutationPublication(ctx, tx); err != nil {
		return nil, err
	}
	readiness, semanticBytes, projectionBytes, readinessErr := runtimeReadinessFromDB(ctx, tx)
	if readinessErr != nil || validateReadinessMetadata(readiness, semanticBytes, projectionBytes) != nil {
		return nil, ErrReadinessQuarantined
	}
	admittedRoots := make(map[string]struct{}, len(readiness.EncryptionRootIDs))
	for _, keyID := range readiness.EncryptionRootIDs {
		admittedRoots[keyID] = struct{}{}
	}

	results = make([]SecretResolution, len(lookups))
	ownedResults := results
	roots := newStoryLogImportRootCache()
	defer roots.clear()
	defer func() {
		if err == nil {
			return
		}
		for index := range ownedResults {
			clear(ownedResults[index].Plaintext)
		}
		results = nil
	}()
	found := make(map[secretLookupKey]struct{}, len(lookups))
	for start := 0; start < len(lookups); start += secretBatchPageSize {
		end := min(start+secretBatchPageSize, len(lookups))
		clauses := make([]string, 0, end-start)
		args := make([]any, 0, (end-start)*2)
		for _, lookup := range lookups[start:end] {
			clauses = append(clauses, "(secret_ref = ? AND secret_version = ?)")
			args = append(args, strings.TrimSpace(lookup.SecretRef), lookup.SecretVersion)
		}
		var rows []adapterSecretRow
		if queryErr := locked(tx).Where(strings.Join(clauses, " OR "), args...).Find(&rows).Error; queryErr != nil {
			return nil, ErrParticipantFailure
		}
		for _, row := range rows {
			key := secretLookupKey{ref: row.SecretRef, version: row.SecretVersion}
			position, requested := positions[key]
			if !requested {
				return nil, ErrParticipantFailure
			}
			if _, duplicate := found[key]; duplicate {
				return nil, ErrParticipantFailure
			}
			if len(row.Ciphertext) > MaxSecretBytes+16 {
				return nil, &OversizeError{Bound: "encrypted secret bytes", Limit: MaxSecretBytes + 16, Actual: len(row.Ciphertext)}
			}
			if len(row.Nonce) != 12 {
				return nil, ErrInvalidMetadata
			}
			if _, admitted := admittedRoots[row.EncryptionKeyID]; !admitted {
				return nil, ErrReadinessQuarantined
			}
			plain, openErr := s.openA6WithRootCache(ctx, roots, "adapter-secret/v1", row.SecretRef, row.EndpointID+"/"+row.AdapterID, row.SecretVersion, row.EncryptionKeyID, row.Ciphertext, row.Nonce)
			if openErr != nil {
				return nil, ErrAuthenticationFailed
			}
			if len(plain) > MaxSecretBytes {
				clear(plain)
				return nil, &OversizeError{Bound: "secret bytes", Limit: MaxSecretBytes, Actual: len(plain)}
			}
			results[position] = SecretResolution{SecretRef: row.SecretRef, SecretVersion: row.SecretVersion, Plaintext: plain}
			found[key] = struct{}{}
		}
	}
	if len(found) != len(lookups) {
		return nil, ErrNotFound
	}
	if err = tx.Commit().Error; err != nil {
		return nil, ErrParticipantFailure
	}
	committed = true
	return results, nil
}

var _ SecretBatchResolver = (*GORMStore)(nil)
