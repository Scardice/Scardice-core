package eventstore

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"gorm.io/gorm"
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
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, ErrReadinessInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	positions := make(map[secretLookupKey]int, len(lookups))
	for index, lookup := range lookups {
		key := secretLookupKey{ref: lookup.SecretRef, version: lookup.SecretVersion}
		if key.ref == "" || len(key.ref) > MaxSecretRefBytes || key.version == 0 {
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
	rowsByKey := make(map[secretLookupKey]adapterSecretRow, len(lookups))
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		_, readinessErr := readinessFromDB(ctx, tx)
		if readinessErr != nil {
			return ErrReadinessQuarantined
		}
		for start := 0; start < len(lookups); start += secretBatchPageSize {
			end := min(start+secretBatchPageSize, len(lookups))
			clauses := make([]string, 0, end-start)
			args := make([]any, 0, (end-start)*2)
			for _, lookup := range lookups[start:end] {
				clauses = append(clauses, "(secret_ref = ? AND secret_version = ?)")
				args = append(args, []byte(lookup.SecretRef), lookup.SecretVersion)
			}
			var page []adapterSecretRow
			if queryErr := tx.Where(strings.Join(clauses, " OR "), args...).Find(&page).Error; queryErr != nil {
				return ErrParticipantFailure
			}
			for _, row := range page {
				key := secretLookupKey{ref: row.SecretRef, version: row.SecretVersion}
				if _, requested := positions[key]; !requested {
					return ErrParticipantFailure
				}
				if _, duplicate := rowsByKey[key]; duplicate {
					return ErrParticipantFailure
				}
				if len(row.Value) > MaxSecretBytes {
					return &OversizeError{Bound: "secret bytes", Limit: MaxSecretBytes, Actual: len(row.Value)}
				}
				rowsByKey[key] = row
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(rowsByKey) != len(lookups) {
		return nil, ErrNotFound
	}
	orderedRows := make([]adapterSecretRow, 0, len(rowsByKey))
	for _, row := range rowsByKey {
		orderedRows = append(orderedRows, row)
	}
	sort.Slice(orderedRows, func(i, j int) bool {
		if orderedRows[i].SecretRef != orderedRows[j].SecretRef {
			return orderedRows[i].SecretRef < orderedRows[j].SecretRef
		}
		return orderedRows[i].SecretVersion < orderedRows[j].SecretVersion
	})
	results = make([]SecretResolution, len(lookups))
	ownedResults := results
	defer func() {
		if err == nil {
			return
		}
		for index := range ownedResults {
			clear(ownedResults[index].Value)
		}
		results = nil
	}()
	for _, row := range orderedRows {
		key := secretLookupKey{ref: row.SecretRef, version: row.SecretVersion}
		results[positions[key]] = SecretResolution{SecretRef: row.SecretRef, SecretVersion: row.SecretVersion, Value: row.Value}
	}
	err = s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if lockErr := lockReadPublication(tx); lockErr != nil {
			return lockErr
		}
		for _, row := range orderedRows {
			var current adapterSecretRow
			if queryErr := rawStringQuery(lockedShared(tx), "secret_ref", row.SecretRef).Where("secret_version = ?", row.SecretVersion).Take(&current).Error; queryErr != nil {
				return ErrParticipantConflict
			}
			if current.RowVersion != row.RowVersion || current.EndpointID != row.EndpointID || current.AdapterID != row.AdapterID || !bytes.Equal(current.Value, row.Value) {
				return ErrParticipantConflict
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

var _ SecretBatchResolver = (*GORMStore)(nil)
