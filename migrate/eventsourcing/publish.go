package eventsourcing

import (
	"context"
	"errors"
	"time"

	"Scardice-core/eventstore"
)

// readinessSchemaVersion 是无密钥的 v2 事件库就绪行 schema 版本,
// 与 v1reader 对 schema_version == "2" 的识别保持一致。
const readinessSchemaVersion = 2

func buildFreshReadiness(target string) eventstore.Readiness {
	return eventstore.Readiness{
		Mode: string(ModeFresh), SchemaVersion: readinessSchemaVersion, DatabaseIdentity: target,
	}
}

func buildImportReadiness(target string, completed time.Time) eventstore.Readiness {
	return eventstore.Readiness{
		Mode: string(ModeImport), SchemaVersion: readinessSchemaVersion, DatabaseIdentity: target,
		CompletedAt: completed.UTC(),
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
