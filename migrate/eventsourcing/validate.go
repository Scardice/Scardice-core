package eventsourcing

import (
	"bytes"
	"context"
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
	if readiness.SchemaVersion != readinessSchemaVersion {
		return fmt.Errorf("%w: unsupported readiness schema version", ErrValidation)
	}
	if readiness.DatabaseIdentity == "" {
		return fmt.Errorf("%w: missing readiness database identity", ErrValidation)
	}
	if readiness.Mode == string(ModeFresh) && !readiness.CompletedAt.IsZero() {
		return fmt.Errorf("%w: fresh readiness contains an import completion time", ErrValidation)
	}
	if readiness.Mode == string(ModeImport) && readiness.CompletedAt.IsZero() {
		return fmt.Errorf("%w: import completion time is missing", ErrValidation)
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
