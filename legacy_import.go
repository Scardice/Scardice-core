package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing"
)

// importPersistentState is the durable readiness state observed on the active
// event database before it is closed for the legacy import. The importer asks
// for this through an optional capability interface; capturing it up front
// keeps that decision identical to a live store instead of silently dropping
// the capability when the store is no longer open.
type importPersistentState struct {
	value bool
}

// importReadinessSnapshot is the read-only readiness view handed to the
// importer. It carries the captured persistent-state result so the importer's
// fresh-identity reuse decision still sees whether the active database held
// real runtime rows.
type importReadinessSnapshot struct {
	value           eventstore.Readiness
	persistentState importPersistentState
}

func (snapshot importReadinessSnapshot) GetReadiness(context.Context) (eventstore.Readiness, error) {
	return snapshot.value, nil
}

func (snapshot importReadinessSnapshot) HasPersistentState(context.Context) (bool, error) {
	return snapshot.persistentState.value, nil
}

func (importReadinessSnapshot) SetReadiness(context.Context, eventstore.Readiness) error {
	return errors.New("legacy import readiness snapshot is read-only")
}

// captureImportPersistentState observes the active event database before it is
// closed for import. Inspection is required: an uninspectable repository fails
// rather than letting the importer assume an empty database and reuse an
// occupied target identity.
func captureImportPersistentState(ctx context.Context, inspector interface {
	HasPersistentState(context.Context) (bool, error)
}) (importPersistentState, error) {
	if inspector == nil {
		return importPersistentState{}, eventstore.ErrReadinessInvalid
	}
	hasState, err := inspector.HasPersistentState(ctx)
	if err != nil {
		return importPersistentState{}, err
	}
	return importPersistentState{value: hasState}, nil
}

func legacySourceRoot(installationRoot string) (string, error) {
	if strings.TrimSpace(installationRoot) == "" || strings.ContainsRune(installationRoot, '\x00') {
		return "", eventsourcing.ErrSourceRequired
	}
	root, err := filepath.Abs(installationRoot)
	if err != nil {
		return "", err
	}
	dataRoot := filepath.Join(root, "data")
	info, err := os.Lstat(filepath.Join(dataRoot, "dice.yaml"))
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", eventsourcing.ErrSourceRequired
	}
	return dataRoot, nil
}

func importLegacyInstallation(ctx context.Context, config eventstore.DatabaseConfig, readiness eventstore.Readiness, persistentState importPersistentState, sourceRoot string, now time.Time) (eventsourcing.ImportResult, error) {
	source, err := legacyImportSourceFromEnv(sourceRoot, os.Getenv, config.KeySource)
	if err != nil {
		return eventsourcing.ImportResult{}, err
	}
	target, targetIdentity, err := legacyImportTargetFromEnv(config, now, os.Getenv)
	if err != nil {
		return eventsourcing.ImportResult{}, err
	}
	stamp := now.UTC().Format("20060102T150405.000000000Z")
	snapshotRoot, err := filepath.Abs(filepath.Join("backups", "eventsourcing-import-"+stamp))
	if err != nil {
		return eventsourcing.ImportResult{}, err
	}
	result, runErr := eventsourcing.NewImporter(eventsourcing.ImporterOptions{
		Readiness:      importReadinessSnapshot{value: readiness, persistentState: persistentState},
		Source:         source,
		Target:         target,
		SnapshotRoot:   snapshotRoot,
		TargetIdentity: targetIdentity,
		Now:            now.UTC,
	}).Run(ctx, eventsourcing.Request{Mode: eventsourcing.ModeImport})
	return finishLegacyImport(sourceRoot, result, runErr)
}

func finishLegacyImport(sourceRoot string, result eventsourcing.ImportResult, runErr error) (eventsourcing.ImportResult, error) {
	if runErr != nil {
		return result, runErr
	}
	for _, relative := range []string{
		"names/data-logs.db",
		"names/names.zip",
		"names/serve.yaml",
		"names/names/names.xlsx",
		"names/names/names-dnd.xlsx",
		"names/names",
		"helpdoc/DND/3R",
		"helpdoc/DND/核心",
		"helpdoc/DND/扩展",
		"helpdoc/DND/模组",
		"helpdoc/DND/破解奥秘",
		"helpdoc/DND/法术列表大全.xlsx",
		"helpdoc/DND/名词解释.xlsx",
		"helpdoc/DND/子职列表大全.xlsx",
	} {
		removeLegacyArtifact(sourceRoot, filepath.FromSlash(relative))
	}
	return result, nil
}

func removeLegacyArtifact(root, relative string) {
	root, err := filepath.Abs(root)
	if err != nil {
		return
	}
	root = filepath.Clean(root)
	candidate := filepath.Join(root, relative)
	within, err := filepath.Rel(root, candidate)
	if err != nil || within == "." || strings.HasPrefix(within, ".."+string(filepath.Separator)) || filepath.IsAbs(within) {
		return
	}
	parent := root
	if info, statErr := os.Lstat(parent); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return
	}
	parts := strings.Split(filepath.Dir(within), string(filepath.Separator))
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		parent = filepath.Join(parent, part)
		info, statErr := os.Lstat(parent)
		if errors.Is(statErr, os.ErrNotExist) {
			return
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return
		}
	}
	_ = os.RemoveAll(candidate)
}

func legacyImportSourceFromEnv(sourceRoot string, getenv func(string) string, keySource eventstore.KeySource) (eventsourcing.Source, error) {
	if getenv == nil {
		return nil, eventsourcing.ErrSourceRequired
	}
	databaseType := strings.ToLower(strings.TrimSpace(getenv("DB_TYPE")))
	switch databaseType {
	case "", "sqlite", "sqlite3":
		return eventsourcing.NewLegacySourceWithKeySource(sourceRoot, keySource), nil
	case "postgresql":
		databaseType = "postgres"
	case "mysql", "postgres":
	default:
		return nil, &eventsourcing.UnsupportedPreflightError{Feature: "legacy database type"}
	}
	dsn := strings.TrimSpace(getenv("DB_DSN"))
	if dsn == "" {
		return nil, eventsourcing.ErrSourceRequired
	}
	tlsVerify, err := optionalBool(getenv("DB_TLS_VERIFY"))
	if err != nil {
		return nil, err
	}
	allowLoopback, err := optionalBool(getenv("DB_ALLOW_INSECURE_LOOPBACK"))
	if err != nil {
		return nil, err
	}
	config := eventstore.DatabaseConfig{
		Type: databaseType, DSN: dsn,
		TLSVerify: tlsVerify, AllowInsecureLoopback: allowLoopback,
	}
	if err = eventstore.ValidateRemoteDatabaseConfig(config); err != nil {
		return nil, err
	}
	return eventsourcing.NewRemoteSQLSourceWithKeySource(sourceRoot, config, keySource), nil
}

func legacyImportTargetFromEnv(active eventstore.DatabaseConfig, now time.Time, getenv func(string) string) (eventsourcing.Target, string, error) {
	databaseType := strings.ToLower(strings.TrimSpace(active.Type))
	if databaseType == "" {
		databaseType = "sqlite"
	}
	if databaseType == "sqlite" || databaseType == "sqlite3" {
		activePath := strings.TrimSpace(active.DSN)
		if activePath == "" || strings.HasPrefix(activePath, "file:") || strings.ContainsRune(activePath, '\x00') {
			return nil, "", fmt.Errorf("legacy import requires a plain SQLite database path: %w", eventsourcing.ErrTargetRequired)
		}
		absolute, err := filepath.Abs(activePath)
		if err != nil {
			return nil, "", err
		}
		stamp := now.UTC().Format("20060102T150405.000000000Z")
		candidate := absolute + ".import-" + stamp
		return eventsourcing.NewSQLitePublicationTarget(candidate, absolute, active.KeySource), active.DatabaseIdentity, nil
	}
	if databaseType == "postgresql" {
		databaseType = "postgres"
	}
	if databaseType != "mysql" && databaseType != "postgres" || getenv == nil {
		return nil, "", &eventsourcing.UnsupportedPreflightError{Feature: "remote target type"}
	}
	slotFile := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_DB_SLOT_FILE"))
	candidateSlot := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_IMPORT_SLOT"))
	activeSlot, err := readEndpointDatabaseSlot(slotFile)
	if err != nil || !validEndpointDatabaseSlot(candidateSlot) || candidateSlot == activeSlot {
		return nil, "", &eventsourcing.UnsupportedPreflightError{Feature: "remote target blue/green slot"}
	}
	candidate, err := endpointDatabaseConfigForSlot(getenv, candidateSlot)
	if err != nil {
		return nil, "", err
	}
	candidateType := strings.ToLower(strings.TrimSpace(candidate.Type))
	if candidateType == "postgresql" {
		candidateType = "postgres"
	}
	if candidateType != databaseType || strings.TrimSpace(candidate.DSN) == "" || candidate.DSN == active.DSN ||
		strings.TrimSpace(candidate.DatabaseIdentity) == "" || candidate.DatabaseIdentity == active.DatabaseIdentity {
		return nil, "", &eventsourcing.UnsupportedPreflightError{Feature: "isolated remote target slot"}
	}
	if err = eventstore.ValidateRemoteDatabaseConfig(candidate); err != nil {
		return nil, "", err
	}
	activate := endpointDatabaseSlotActivation(slotFile, candidateSlot, candidate.DatabaseIdentity)
	return eventsourcing.NewRemoteSQLTarget(candidate, activate), candidate.DatabaseIdentity, nil
}

func endpointDatabaseSlotActivation(path, slot, identity string) func(context.Context, string) error {
	return func(ctx context.Context, requestedIdentity string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if requestedIdentity != identity {
			return eventsourcing.ErrTargetIdentity
		}
		return writeEndpointDatabaseSlot(path, slot)
	}
}
