package eventsourcing

import (
	"context"
	"errors"

	"Scardice-core/eventstore"
)

var (
	ErrMigrationRequired   = errors.New("eventsourcing: imported readiness is required for existing legacy state")
	ErrLegacyStateConflict = errors.New("eventsourcing: legacy files coexist with a populated fresh event store; choose the authoritative source explicitly before importing")
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
	readiness, err := repository.GetReadiness(ctx)
	if err == nil {
		err = ValidatePublication(readiness)
	}
	if err != nil {
		return eventstore.Readiness{}, err
	}
	if readiness.Mode == string(ModeImport) || !legacyStatePresent {
		return readiness, nil
	}
	inspector, ok := repository.(interface {
		HasPersistentState(context.Context) (bool, error)
	})
	if !ok {
		return eventstore.Readiness{}, ErrLegacyStateConflict
	}
	populated, err := inspector.HasPersistentState(ctx)
	if err != nil {
		return eventstore.Readiness{}, err
	}
	if populated {
		return eventstore.Readiness{}, ErrLegacyStateConflict
	}
	return eventstore.Readiness{}, ErrMigrationRequired
}
