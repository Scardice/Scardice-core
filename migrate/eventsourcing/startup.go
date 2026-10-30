package eventsourcing

import (
	"context"
	"errors"

	"Scardice-core/eventstore"
)

var (
	ErrMigrationRequired      = errors.New("eventsourcing: imported readiness is required for existing legacy state")
	ErrFreshReadinessRequired = errors.New("eventsourcing: fresh readiness is required for an empty legacy state")
)

// ValidateStartupReadiness is the read-only startup gate. It is deliberately
// separate from import/publication: the process must not construct legacy
// runtime objects, JavaScript, timers, or providers until this check succeeds.
func ValidateStartupReadiness(ctx context.Context, repository eventstore.ReadinessRepository, legacyStatePresent bool) (eventstore.Readiness, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if repository == nil {
		return eventstore.Readiness{}, eventstore.ErrReadinessInvalid
	}
	var readiness eventstore.Readiness
	var err error
	if metadata, ok := repository.(eventstore.ReadinessMetadataRepository); ok {
		readiness, err = metadata.GetReadinessMetadata(ctx)
	} else {
		readiness, err = repository.GetReadiness(ctx)
		if err == nil {
			err = ValidatePublication(readiness)
		}
	}
	if err != nil {
		return eventstore.Readiness{}, err
	}
	if legacyStatePresent {
		if readiness.Mode != string(ModeImport) {
			return eventstore.Readiness{}, ErrMigrationRequired
		}
	} else if readiness.Mode != string(ModeFresh) {
		return eventstore.Readiness{}, ErrFreshReadinessRequired
	}
	return readiness, nil
}
