package eventsourcing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"Scardice-core/eventstore"
)

type FailureInjector interface { Inject(stage string) error }
type FailureFunc func(string) error
func (f FailureFunc) Inject(stage string) error { if f == nil { return nil }; return f(stage) }

type ImporterOptions struct {
	Readiness eventstore.ReadinessRepository
	Source Source
	FileSystem FileSystem
	FailureInjector FailureInjector
	SnapshotRoot string
	TargetIdentity string
	IdentityGenerator func() (string, error)
	Now func() time.Time
}

type Importer struct { options ImporterOptions }
func NewImporter(options ImporterOptions) *Importer {
	if options.FileSystem == nil { options.FileSystem = DefaultFileSystem() }
	if options.Now == nil { options.Now = func() time.Time { return time.Now().UTC() } }
	return &Importer{options: options}
}
func Import(ctx context.Context, options ImporterOptions, request Request) (ImportResult, error) {
	return NewImporter(options).Run(ctx, request)
}

type ImportResult struct {
	Mode Mode
	TargetIdentity string
	ManifestDigest []byte
	Snapshot SnapshotResult
	Batches int
	QuarantineMarker string
}

func (i *Importer) Run(ctx context.Context, request Request) (ImportResult, error) {
	var result ImportResult
	if i == nil { return result, ErrPublication }
	if err := i.inject("start"); err != nil { return result, err }
	if err := ctx.Err(); err != nil { return result, err }
	target, err := i.targetIdentity()
	if err != nil { return result, err }
	if i.options.Readiness == nil { return result, ErrPublication }
	previous, err := i.options.Readiness.GetReadiness(ctx)
	if err != nil { return result, err }

	var inventory *SourceInventory
	if request.Mode == ModeImport {
		if i.options.Source == nil { return result, ErrSourceRequired }
		value, inventoryErr := i.options.Source.Inventory(ctx)
		if inventoryErr != nil { return result, inventoryErr }
		inventory = &value
	} else if request.Mode == ModeFresh && i.options.Source != nil {
		return result, ErrSourceMutation
	}
	if err := i.inject("preflight"); err != nil { return result, err }
	decision, err := DecidePreflight(ctx, request, target, inventory, previous)
	if err != nil { return result, err }
	result.Mode, result.TargetIdentity = decision.Mode, decision.TargetIdentity
	if decision.Mode == ModeFresh {
		fresh := buildFreshReadiness(previous, target)
		if err := i.inject("validate"); err != nil { return result, err }
		if err := ValidatePublication(fresh); err != nil { return result, err }
		if err := i.inject("publish"); err != nil { return result, err }
		return result, PublishReadiness(ctx, i.options.Readiness, fresh)
	}

	root := i.options.SnapshotRoot
	if strings.TrimSpace(root) == "" { return result, &UnsupportedPreflightError{Feature: "snapshot destination"} }
	if err := i.inject("snapshot"); err != nil { return i.quarantine(result, root, err) }
	snapshot, err := i.options.Source.Snapshot(ctx, root)
	result.Snapshot = snapshot
	if err != nil { return i.quarantine(result, root, err) }
	if err := ValidateSourceMetadata(ctx, i.options.Source, decision.Source.Metadata); err != nil { return i.quarantine(result, root, err) }
	if err := i.inject("manifest"); err != nil { return i.quarantine(result, root, err) }
	manifest := SemanticManifest{Version: 1, SourceIdentity: decision.Source.Identity, Records: make([]ManifestRecord, 0, len(decision.Source.Records))}
	for _, sourceRecord := range decision.Source.Records {
		manifest.Records = append(manifest.Records, ManifestRecord{Domain: sourceRecord.Domain, Identity: sourceRecord.Identity, Kind: sourceRecord.Kind,
			SchemaVersion: sourceRecord.SchemaVersion, ContentDigest: append([]byte(nil), sourceRecord.ContentDigest...), Size: sourceRecord.Size})
	}
	if err := ValidateBatches(manifest.Records); err != nil { return i.quarantine(result, root, err) }
	encoded, digest, err := CanonicalManifest(manifest)
	if err != nil { return i.quarantine(result, root, err) }
	if err := ValidateManifest(manifest, encoded, digest); err != nil { return i.quarantine(result, root, err) }
	if err := i.inject("validate"); err != nil { return i.quarantine(result, root, err) }
	result.ManifestDigest = append([]byte(nil), digest...)
	result.Batches = batchCount(manifest.Records)
	published := buildImportReadiness(previous, target, digest, i.options.Now())
	if err := i.inject("publish"); err != nil { return i.quarantine(result, root, err) }
	if err := PublishReadiness(ctx, i.options.Readiness, published); err != nil { return i.quarantine(result, root, err) }
	return result, nil
}

func (i *Importer) inject(stage string) error {
	if i.options.FailureInjector == nil { return nil }
	return i.options.FailureInjector.Inject(stage)
}
func (i *Importer) targetIdentity() (string, error) {
	identity := strings.TrimSpace(i.options.TargetIdentity)
	if identity == "" && i.options.IdentityGenerator != nil {
		generated, err := i.options.IdentityGenerator()
		if err != nil { return "", err }
		identity = strings.TrimSpace(generated)
	}
	if identity == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil { return "", ErrTargetIdentity }
		identity = "target-" + hex.EncodeToString(raw)
	}
	if identity == "" || strings.ContainsAny(identity, "/\\\x00") { return "", ErrTargetIdentity }
	return identity, nil
}
func batchCount(records []ManifestRecord) int {
	batches, err := DeterministicBatches(records)
	if err != nil { return 0 }
	return len(batches)
}

func (i *Importer) quarantine(result ImportResult, root string, cause error) (ImportResult, error) {
	marker := filepath.Join(root, ".quarantine")
	fs := i.options.FileSystem
	if secureErr := secureDestination(fs, root); secureErr != nil { return result, errors.Join(cause, ErrQuarantined, secureErr) }
	_ = fs.MkdirAll(root, SnapshotTreeMode)
	_ = fs.Chmod(root, SnapshotTreeMode)
	if err := fs.WriteFile(marker, []byte("quarantined\n"), SnapshotFileMode); err == nil {
		_ = fs.Chmod(marker, SnapshotFileMode)
		result.QuarantineMarker = marker
	}
	if cause == nil { cause = ErrQuarantined }
	return result, errors.Join(cause, ErrQuarantined)
}
