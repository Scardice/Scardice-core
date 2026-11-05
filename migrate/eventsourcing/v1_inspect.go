package eventsourcing

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"Scardice-core/migrate/eventsourcing/v1reader"
)

type V1CurrentState struct {
	Mode               string
	DatabaseIdentity   string
	HasPersistentState bool
	proof              SourceMetadata
}

// InspectV1CurrentState uses the same byte-isolated WAL snapshot as conversion,
// but reads metadata/counts only. Empty old schemas can therefore select source
// A even when their retired key files are unavailable.
func InspectV1CurrentState(ctx context.Context, path string) (state V1CurrentState, inspectErr error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return state, err
	}
	if err = CheckUnfinishedV1Publication(absolute); err != nil {
		return state, err
	}
	snapshot, proof, cleanup, err := snapshotV1SQLite(ctx, absolute)
	if err != nil {
		return state, err
	}
	defer func() { inspectErr = errors.Join(inspectErr, cleanup()) }()
	format, err := v1reader.Detect(ctx, snapshot)
	if err != nil {
		return state, err
	}
	if format != v1reader.FormatV1Encrypted {
		return state, ErrNotV1Store
	}
	current, err := v1reader.InspectCurrentState(ctx, snapshot)
	if err != nil {
		return state, err
	}
	return V1CurrentState{Mode: current.Mode, DatabaseIdentity: current.DatabaseIdentity, HasPersistentState: current.HasPersistentState, proof: proof}, nil
}

type legacyV1Publication struct {
	stamp string
	state V1CurrentState
}

// NewSQLiteLegacyV1PublicationTarget lets source A replace only an inspected,
// empty fresh v1 schema. It retains the old schema/WAL/SHM with the same durable
// swap protocol as source B, rather than opening it with the plaintext store.
func NewSQLiteLegacyV1PublicationTarget(ctx context.Context, candidate, active string, now time.Time) (*SQLiteTarget, error) {
	state, err := InspectV1CurrentState(ctx, active)
	if err != nil {
		return nil, err
	}
	if state.Mode != string(ModeFresh) || state.HasPersistentState {
		return nil, ErrLegacyStateConflict
	}
	target := NewSQLitePublicationTarget(candidate, active)
	target.legacyV1 = &legacyV1Publication{stamp: now.UTC().Format("20060102T150405.000000000Z"), state: state}
	return target, nil
}

func validateV1SelectedIdentity(state V1CurrentState, identity string) error {
	if identity == "" || state.DatabaseIdentity != identity {
		return fmt.Errorf("v1 source identity differs from configuration: %w", ErrTargetIdentity)
	}
	return nil
}
