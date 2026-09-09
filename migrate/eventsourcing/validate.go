package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"Scardice-core/eventstore"
)

func ValidateManifest(manifest SemanticManifest, encoded, digest []byte) error {
	canonical, expected, err := CanonicalManifest(manifest)
	if err != nil { return errors.Join(ErrValidation, err) }
	if !bytes.Equal(canonical, encoded) || !bytes.Equal(expected, digest) { return ErrValidation }
	return nil
}

func ValidateBatches(records []ManifestRecord) error {
	batches, err := DeterministicBatches(records)
	if err != nil { return errors.Join(ErrValidation, err) }
	for _, batch := range batches {
		if len(batch) > MaxBatchRecords { return ErrBatchLimit }
		encoded, _, err := CanonicalManifest(SemanticManifest{Version: 1, Records: batch})
		if err != nil || len(encoded) > MaxBatchBytes { return ErrBatchLimit }
	}
	return nil
}

func ValidatePublication(readiness eventstore.Readiness) error {
	if readiness.Mode != string(ModeFresh) && readiness.Mode != string(ModeImport) { return ErrValidation }
	if readiness.SchemaVersion == 0 || readiness.DatabaseIdentity == "" || readiness.IndexRootID == "" { return ErrValidation }
	if readiness.Mode == string(ModeFresh) {
		if len(readiness.SourceManifestDigest) != 0 || len(readiness.TargetManifestDigest) != 0 || !readiness.CompletedAt.IsZero() { return ErrValidation }
		return nil
	}
	if len(readiness.SourceManifestDigest) != sha256.Size || len(readiness.TargetManifestDigest) != sha256.Size || readiness.CompletedAt.IsZero() { return ErrValidation }
	return nil
}

func ValidateSourceMetadata(ctx context.Context, source Source, before SourceMetadata) error {
	if source == nil { return ErrSourceRequired }
	if err := source.Recheck(ctx, before); err != nil {
		if errors.Is(err, ErrSourceDrift) { return err }
		return errors.Join(ErrSourceDrift, err)
	}
	return nil
}
