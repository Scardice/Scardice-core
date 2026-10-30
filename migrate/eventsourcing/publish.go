package eventsourcing

import (
	"context"
	"errors"
	"time"

	"Scardice-core/eventstore"
)

func buildFreshReadiness(previous eventstore.Readiness, target string) eventstore.Readiness {
	return eventstore.Readiness{
		Mode: string(ModeFresh), SchemaVersion: 1, DatabaseIdentity: target,
		IndexRootID: previous.IndexRootID, IndexRootFingerprint: append([]byte(nil), previous.IndexRootFingerprint...),
		EncryptionRootIDs: append([]string(nil), previous.EncryptionRootIDs...),
	}
}

func buildImportReadiness(
	previous eventstore.Readiness,
	target string,
	semanticManifest, digest, projectionManifest, projectionDigest []byte,
	terminalPosition uint64,
	completed time.Time,
) eventstore.Readiness {
	return eventstore.Readiness{
		Mode: string(ModeImport), SchemaVersion: 1, DatabaseIdentity: target,
		IndexRootID: previous.IndexRootID, IndexRootFingerprint: append([]byte(nil), previous.IndexRootFingerprint...),
		EncryptionRootIDs:          append([]string(nil), previous.EncryptionRootIDs...),
		SourceManifestDigest:       append([]byte(nil), digest...),
		TargetManifestDigest:       append([]byte(nil), digest...),
		SemanticManifest:           append([]byte(nil), semanticManifest...),
		ProjectionManifest:         append([]byte(nil), projectionManifest...),
		ProjectionManifestDigest:   append([]byte(nil), projectionDigest...),
		TerminalGlobalPosition:     terminalPosition,
		TerminalProjectionPosition: terminalPosition,
		CompletedAt:                completed.UTC(),
	}
}

func PublishReadiness(ctx context.Context, repository eventstore.ReadinessRepository, readiness eventstore.Readiness) error {
	if repository == nil {
		return errors.Join(ErrPublication, eventstore.ErrReadinessInvalid)
	}
	if err := ValidatePublication(readiness); err != nil {
		return errors.Join(ErrPublication, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := repository.SetReadiness(ctx, readiness); err != nil {
		return errors.Join(ErrPublication, err)
	}
	return nil
}
