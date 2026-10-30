package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"Scardice-core/eventstore"
)

func ValidateManifest(manifest SemanticManifest, encoded, digest []byte) error {
	canonical, expected, err := CanonicalManifest(manifest)
	if err != nil {
		return fmt.Errorf("%w: canonicalize semantic manifest: %w", ErrValidation, err)
	}
	if !bytes.Equal(canonical, encoded) {
		return fmt.Errorf("%w: semantic manifest is not canonical", ErrValidation)
	}
	if !bytes.Equal(expected, digest) {
		return fmt.Errorf("%w: semantic manifest digest mismatch", ErrValidation)
	}
	return nil
}

func ValidateBatches(records []ManifestRecord) error {
	batches, err := DeterministicBatches(records)
	if err != nil {
		return errors.Join(ErrValidation, err)
	}
	for _, batch := range batches {
		if len(batch) > MaxBatchRecords {
			return ErrBatchLimit
		}
		encoded, _, err := CanonicalManifest(SemanticManifest{Version: 1, Records: batch})
		if err != nil || len(encoded) > MaxBatchBytes {
			return ErrBatchLimit
		}
	}
	return nil
}

func ValidatePublication(readiness eventstore.Readiness) error {
	if readiness.Mode != string(ModeFresh) && readiness.Mode != string(ModeImport) {
		return fmt.Errorf("%w: unsupported readiness mode", ErrValidation)
	}
	if readiness.SchemaVersion == 0 {
		return fmt.Errorf("%w: missing readiness schema version", ErrValidation)
	}
	if readiness.DatabaseIdentity == "" {
		return fmt.Errorf("%w: missing readiness database identity", ErrValidation)
	}
	if readiness.IndexRootID == "" {
		return fmt.Errorf("%w: missing readiness index root", ErrValidation)
	}
	if readiness.Mode == string(ModeFresh) {
		if len(readiness.SourceManifestDigest) != 0 || len(readiness.TargetManifestDigest) != 0 ||
			len(readiness.SemanticManifest) != 0 || len(readiness.ProjectionManifest) != 0 ||
			len(readiness.ProjectionManifestDigest) != 0 || !readiness.CompletedAt.IsZero() {
			return fmt.Errorf("%w: fresh readiness contains import-only fields", ErrValidation)
		}
		return nil
	}
	if len(readiness.SourceManifestDigest) != sha256.Size {
		return fmt.Errorf("%w: source manifest digest length is %d, want %d", ErrValidation, len(readiness.SourceManifestDigest), sha256.Size)
	}
	if len(readiness.TargetManifestDigest) != sha256.Size {
		return fmt.Errorf("%w: target manifest digest length is %d, want %d", ErrValidation, len(readiness.TargetManifestDigest), sha256.Size)
	}
	if readiness.CompletedAt.IsZero() {
		return fmt.Errorf("%w: import completion time is missing", ErrValidation)
	}
	if len(readiness.SemanticManifest) != 0 {
		digest := sha256.Sum256(readiness.SemanticManifest)
		if !bytes.Equal(digest[:], readiness.SourceManifestDigest) {
			return fmt.Errorf("%w: semantic manifest does not match source digest", ErrValidation)
		}
		if !bytes.Equal(digest[:], readiness.TargetManifestDigest) {
			return fmt.Errorf("%w: semantic manifest does not match target digest", ErrValidation)
		}
	}
	if (len(readiness.ProjectionManifest) == 0) != (len(readiness.ProjectionManifestDigest) == 0) {
		return fmt.Errorf("%w: projection manifest and digest presence differ", ErrValidation)
	}
	if len(readiness.ProjectionManifest) != 0 {
		digest := sha256.Sum256(readiness.ProjectionManifest)
		if !bytes.Equal(digest[:], readiness.ProjectionManifestDigest) {
			return fmt.Errorf("%w: projection manifest digest mismatch", ErrValidation)
		}
	}
	return nil
}

func ValidateSourceMetadata(ctx context.Context, source Source, before SourceMetadata) error {
	if source == nil {
		return ErrSourceRequired
	}
	if err := source.Recheck(ctx, before); err != nil {
		if errors.Is(err, ErrSourceDrift) {
			return err
		}
		return errors.Join(ErrSourceDrift, err)
	}
	return nil
}
