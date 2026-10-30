package eventsourcing

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"Scardice-core/eventstore"
)

type FailureInjector interface{ Inject(stage string) error }
type FailureFunc func(string) error

func (f FailureFunc) Inject(stage string) error {
	if f == nil {
		return nil
	}
	return f(stage)
}

type ImporterOptions struct {
	Readiness         eventstore.ReadinessRepository
	Source            Source
	Target            Target
	FileSystem        FileSystem
	FailureInjector   FailureInjector
	SnapshotRoot      string
	TargetIdentity    string
	IdentityGenerator func() (string, error)
	Now               func() time.Time
}

type Importer struct{ options ImporterOptions }

func NewImporter(options ImporterOptions) *Importer {
	if options.FileSystem == nil {
		options.FileSystem = DefaultFileSystem()
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Importer{options: options}
}
func Import(ctx context.Context, options ImporterOptions, request Request) (ImportResult, error) {
	return NewImporter(options).Run(ctx, request)
}

type ImportResult struct {
	Mode             Mode
	TargetIdentity   string
	ManifestDigest   []byte
	Snapshot         SnapshotResult
	Batches          int
	QuarantineMarker string
	Warnings         []string
}

func (i *Importer) Run(ctx context.Context, request Request) (result ImportResult, runErr error) {
	if i == nil {
		return result, ErrPublication
	}
	if err := i.inject("start"); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	target, targetErr := i.targetIdentity()
	if targetErr != nil {
		return result, targetErr
	}
	if i.options.Readiness == nil {
		return result, ErrPublication
	}
	previous, readinessErr := i.options.Readiness.GetReadiness(ctx)
	if readinessErr != nil {
		return result, readinessErr
	}

	preflightReadiness := previous
	if reuse, ok := i.options.Target.(interface{ AllowsReadinessIdentityReuse() bool }); ok &&
		reuse.AllowsReadinessIdentityReuse() && previous.Mode == string(ModeFresh) &&
		previous.TerminalGlobalPosition == 0 && previous.TerminalProjectionPosition == 0 {
		inspector, supportsInspection := i.options.Readiness.(interface {
			HasPersistentState(context.Context) (bool, error)
		})
		if supportsInspection {
			hasState, inspectErr := inspector.HasPersistentState(ctx)
			if inspectErr != nil {
				return result, inspectErr
			}
			if !hasState {
				preflightReadiness.DatabaseIdentity = ""
			}
		}
	}
	if request.Mode == ModeFresh {
		if i.options.Source != nil {
			return result, ErrSourceMutation
		}
		if err := i.inject("preflight"); err != nil {
			return result, err
		}
		decision, decisionErr := DecidePreflight(ctx, request, target, nil, preflightReadiness)
		if decisionErr != nil {
			return result, decisionErr
		}
		result.Mode, result.TargetIdentity = decision.Mode, decision.TargetIdentity
		fresh := buildFreshReadiness(previous, target)
		if err := i.inject("validate"); err != nil {
			return result, err
		}
		if err := ValidatePublication(fresh); err != nil {
			return result, err
		}
		if err := i.inject("publish"); err != nil {
			return result, err
		}
		return result, PublishReadiness(ctx, i.options.Readiness, fresh)
	}
	if request.Mode != ModeImport {
		return result, ErrInvalidMode
	}
	if i.options.Source == nil {
		return result, ErrSourceRequired
	}
	root := i.options.SnapshotRoot
	if strings.TrimSpace(root) == "" {
		return result, &UnsupportedPreflightError{Feature: "snapshot destination"}
	}
	if err := i.inject("snapshot"); err != nil {
		return i.quarantine(result, root, err)
	}
	snapshot, snapshotErr := i.options.Source.Snapshot(ctx, root)
	result.Snapshot = snapshot
	result.Snapshot.Source = nil
	if snapshotErr != nil {
		return i.quarantine(result, root, fmt.Errorf("create source snapshot: %w", snapshotErr))
	}
	if snapshot.Source == nil {
		return i.quarantine(result, root, &UnsupportedPreflightError{Feature: "snapshot source"})
	}
	value, inventoryErr := snapshot.Source.Inventory(ctx)
	if inventoryErr != nil {
		return i.quarantine(result, root, fmt.Errorf("inventory snapshot source: %w", inventoryErr))
	}
	if err := ValidateSourceMetadata(ctx, i.options.Source, snapshot.Metadata); err != nil {
		clearSensitiveSourceRecords(value.Records)
		return i.quarantine(result, root, fmt.Errorf("recheck source after snapshot: %w", err))
	}
	if err := i.inject("preflight"); err != nil {
		clearSensitiveSourceRecords(value.Records)
		return i.quarantine(result, root, fmt.Errorf("run import preflight: %w", err))
	}
	decision, decisionErr := DecidePreflight(ctx, request, target, &value, preflightReadiness)
	if decisionErr != nil {
		clearSensitiveSourceRecords(value.Records)
		return i.quarantine(result, root, fmt.Errorf("decide import preflight: %w", decisionErr))
	}
	result.Mode, result.TargetIdentity = decision.Mode, decision.TargetIdentity
	defer clearSensitiveSourceRecords(decision.Source.Records)
	if i.options.Target == nil {
		return result, ErrTargetRequired
	}
	if err := i.inject("manifest"); err != nil {
		return i.quarantine(result, root, err)
	}
	sourceManifest := SemanticManifest{Version: 1, SourceIdentity: decision.Source.Identity}
	defer func() { clearSensitiveManifestRecords(sourceManifest.Records) }()
	if err := i.inject("initialize"); err != nil {
		return i.quarantine(result, root, err)
	}
	if err := i.options.Target.Initialize(ctx, target); err != nil {
		return i.quarantine(result, root, fmt.Errorf("initialize isolated import target: %w", err))
	}
	targetOpen := true
	defer func() {
		if targetOpen {
			runErr = errors.Join(runErr, i.options.Target.Close())
		}
	}()
	importRecords := func(records []SourceRecord) error {
		batches, err := deterministicImportBatches(records)
		if err != nil {
			return fmt.Errorf("validate source record batch: %w", err)
		}
		defer clearSensitiveSourceRecordBatches(batches)
		for _, batch := range batches {
			if len(sourceManifest.Records) > MaxManifestRecords-len(batch) {
				return fmt.Errorf("source semantic manifest exceeds %d records: %w", MaxManifestRecords, ErrBatchLimit)
			}
			for _, record := range batch {
				sourceManifest.Records = append(sourceManifest.Records, sourceManifestRecord(record))
			}
			if err = i.inject("import"); err != nil {
				return fmt.Errorf("prepare source batch %d: %w", result.Batches+1, err)
			}
			if err = i.options.Target.ImportBatch(ctx, batch); err != nil {
				return fmt.Errorf("import source batch %d: %w", result.Batches+1, err)
			}
			result.Batches++
		}
		return nil
	}
	if streamer, ok := snapshot.Source.(RecordStreamer); ok {
		if err := streamer.StreamRecords(ctx, importRecords); err != nil {
			return i.quarantine(result, root, fmt.Errorf("stream snapshot records: %w", err))
		}
	} else if err := importRecords(decision.Source.Records); err != nil {
		return i.quarantine(result, root, err)
	}
	sourceCanonical, sourceDigest, sourceManifestErr := canonicalImportManifest(sourceManifest, MaxManifestBytes)
	if sourceManifestErr != nil {
		return i.quarantine(result, root, fmt.Errorf("canonicalize source manifest: %w", sourceManifestErr))
	}
	clearSensitiveManifestRecords(sourceManifest.Records)
	sourceManifest.Records = nil
	if err := i.inject("rebuild"); err != nil {
		return i.quarantine(result, root, err)
	}
	rebuild, rebuildErr := i.options.Target.Rebuild(ctx)
	if rebuildErr != nil {
		return i.quarantine(result, root, fmt.Errorf("rebuild target projections: %w", rebuildErr))
	}
	projectionBefore, projectionDigest, projectionErr := i.options.Target.ProjectionManifest(ctx)
	if projectionErr != nil {
		return i.quarantine(result, root, fmt.Errorf("read projection manifest after rebuild: %w", errors.Join(ErrValidation, projectionErr)))
	}
	if !validCanonicalManifestDigest(projectionBefore, projectionDigest) {
		return i.quarantine(result, root, fmt.Errorf("projection manifest after rebuild is invalid: %w", ErrValidation))
	}
	if err := i.inject("reopen"); err != nil {
		return i.quarantine(result, root, err)
	}
	if err := i.options.Target.Reopen(ctx); err != nil {
		return i.quarantine(result, root, fmt.Errorf("reopen isolated import target: %w", err))
	}
	projectionAfter, reopenedProjectionDigest, projectionErr := i.options.Target.ProjectionManifest(ctx)
	if projectionErr != nil {
		return i.quarantine(result, root, fmt.Errorf("read projection manifest after target reopen: %w", errors.Join(ErrValidation, projectionErr)))
	}
	if !validCanonicalManifestDigest(projectionAfter, reopenedProjectionDigest) {
		return i.quarantine(result, root, fmt.Errorf("projection manifest after target reopen is invalid: %w", ErrValidation))
	}
	if !bytes.Equal(projectionBefore, projectionAfter) || !bytes.Equal(projectionDigest, reopenedProjectionDigest) {
		return i.quarantine(result, root, fmt.Errorf("projection manifest changed after target reopen: %w", ErrValidation))
	}
	if err := i.inject("target-manifest"); err != nil {
		return i.quarantine(result, root, err)
	}
	targetManifest, targetManifestErr := i.options.Target.Manifest(ctx)
	if targetManifestErr != nil {
		return i.quarantine(result, root, fmt.Errorf("read target semantic manifest: %w", targetManifestErr))
	}
	defer func() { clearSensitiveManifestRecords(targetManifest.Records) }()
	targetManifest.SourceIdentity = decision.Source.Identity
	targetCanonical, targetDigest, targetDigestErr := canonicalImportManifest(targetManifest, MaxManifestBytes)
	if targetDigestErr != nil {
		return i.quarantine(result, root, fmt.Errorf("canonicalize target semantic manifest: %w", targetDigestErr))
	}
	clearSensitiveManifestRecords(targetManifest.Records)
	targetManifest.Records = nil
	if !bytes.Equal(sourceCanonical, targetCanonical) || !bytes.Equal(sourceDigest, targetDigest) {
		return i.quarantine(result, root, fmt.Errorf("source and target semantic manifests differ: %w", ErrValidation))
	}
	targetBaseline, baselineErr := i.options.Target.GetReadiness(ctx)
	if baselineErr != nil {
		return i.quarantine(result, root, fmt.Errorf("read target readiness baseline: %w", baselineErr))
	}
	if targetBaseline.Mode != string(ModeFresh) || targetBaseline.DatabaseIdentity != target {
		return i.quarantine(result, root, fmt.Errorf("target readiness baseline does not identify the isolated fresh target: %w", ErrValidation))
	}
	if err := ValidatePublication(targetBaseline); err != nil {
		return i.quarantine(result, root, fmt.Errorf("validate target readiness baseline: %w", err))
	}
	if err := ValidateSourceMetadata(ctx, i.options.Source, snapshot.Metadata); err != nil {
		return i.quarantine(result, root, fmt.Errorf("recheck source before publication: %w", err))
	}
	if err := i.inject("validate"); err != nil {
		return i.quarantine(result, root, err)
	}
	result.ManifestDigest = append([]byte(nil), sourceDigest...)
	published := buildImportReadiness(
		targetBaseline, target, sourceCanonical, sourceDigest, projectionAfter, reopenedProjectionDigest,
		rebuild.TerminalPosition, i.options.Now(),
	)
	if err := i.inject("publish"); err != nil {
		return i.quarantine(result, root, err)
	}
	if err := PublishReadiness(ctx, i.options.Target, published); err != nil {
		return i.quarantine(result, root, fmt.Errorf("publish readiness in isolated target: %w", err))
	}
	if publisher, ok := i.options.Target.(PublicationTarget); ok {
		if err := publisher.Publish(ctx); err != nil {
			return i.quarantine(result, root, fmt.Errorf("atomically activate imported target: %w", err))
		}
	}
	if err := i.options.Target.Close(); err != nil {
		targetOpen = false
		result.Warnings = append(result.Warnings, fmt.Sprintf("close published import target: %v", err))
		return result, nil
	}
	targetOpen = false
	return result, nil
}

func (i *Importer) inject(stage string) error {
	if i.options.FailureInjector == nil {
		return nil
	}
	return i.options.FailureInjector.Inject(stage)
}
func (i *Importer) targetIdentity() (string, error) {
	identity := strings.TrimSpace(i.options.TargetIdentity)
	if identity == "" && i.options.IdentityGenerator != nil {
		generated, err := i.options.IdentityGenerator()
		if err != nil {
			return "", err
		}
		identity = strings.TrimSpace(generated)
	}
	if identity == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", ErrTargetIdentity
		}
		identity = "target-" + hex.EncodeToString(raw)
	}
	if identity == "" || strings.ContainsAny(identity, "/\\\x00") {
		return "", ErrTargetIdentity
	}
	return identity, nil
}
func validCanonicalManifestDigest(manifest, digest []byte) bool {
	if len(manifest) == 0 || len(digest) != sha256.Size {
		return false
	}
	actual := sha256.Sum256(manifest)
	return bytes.Equal(actual[:], digest)
}

func manifestFromSource(inventory SourceInventory) SemanticManifest {
	manifest := SemanticManifest{Version: 1, SourceIdentity: inventory.Identity, Records: make([]ManifestRecord, 0, len(inventory.Records))}
	for _, record := range inventory.Records {
		manifest.Records = append(manifest.Records, sourceManifestRecord(record))
	}
	return manifest
}

func deterministicImportBatches(records []SourceRecord) ([][]SourceRecord, error) {
	type sortableRecord struct {
		source   SourceRecord
		manifest ManifestRecord
	}
	sorted := make([]sortableRecord, len(records))
	for index, record := range records {
		if err := validateSourceRecord(record); err != nil {
			return nil, fmt.Errorf("source record %d (type=%q version=%d): %w", index+1, record.RecordType, record.Version, err)
		}
		sorted[index] = sortableRecord{source: record, manifest: sourceManifestRecord(record)}
	}
	sort.Slice(sorted, func(left, right int) bool {
		return manifestRecordLess(sorted[left].manifest, sorted[right].manifest)
	})
	manifestRecords := make([]ManifestRecord, len(sorted))
	sortedRecords := make([]SourceRecord, len(sorted))
	for index := range sorted {
		manifestRecords[index] = sorted[index].manifest
		sortedRecords[index] = sorted[index].source
	}
	batches, err := DeterministicBatches(manifestRecords)
	if err != nil {
		return nil, err
	}
	sourceBatches := make([][]SourceRecord, 0, len(batches))
	offset := 0
	for _, batch := range batches {
		records := sortedRecords[offset : offset+len(batch)]
		start := 0
		streams := make(map[eventstore.StreamID]struct{}, eventstore.MaxUnitOfWorkStreams)
		for index, record := range records {
			if record.RecordType != RecordTypeEvent {
				continue
			}
			stream := eventstore.StreamID{AggregateType: record.Domain, AggregateID: record.Identity}
			if _, exists := streams[stream]; exists {
				continue
			}
			if len(streams) == eventstore.MaxUnitOfWorkStreams {
				sourceBatches = append(sourceBatches, records[start:index])
				start = index
				clear(streams)
			}
			streams[stream] = struct{}{}
		}
		if start < len(records) {
			sourceBatches = append(sourceBatches, records[start:])
		}
		offset += len(batch)
	}
	return sourceBatches, nil
}

func sourceManifestRecord(record SourceRecord) ManifestRecord {
	identityDigest := sha256.Sum256([]byte(record.Identity))
	return ManifestRecord{
		RecordType: record.RecordType, Domain: record.Domain, Identity: record.Identity, IdentityDigest: hex.EncodeToString(identityDigest[:]), Kind: record.Kind,
		SchemaVersion: record.SchemaVersion, ContentDigest: append([]byte(nil), record.ContentDigest...),
		Size: record.Size, Sensitive: record.Sensitive, Version: record.Version,
	}
}

func clearSensitiveSourceRecordBatches(batches [][]SourceRecord) {
	for _, batch := range batches {
		clearSensitiveSourceRecords(batch)
	}
}

func clearSensitiveSourceRecords(records []SourceRecord) {
	for index := range records {
		if records[index].Sensitive {
			clear(records[index].Payload)
			records[index].Payload = nil
			records[index].Identity = ""
		}
	}
}

func clearSensitiveManifestRecords(records []ManifestRecord) {
	for index := range records {
		if records[index].Sensitive {
			records[index].Identity = ""
		}
	}
}

func (i *Importer) quarantine(result ImportResult, root string, cause error) (ImportResult, error) {
	marker := filepath.Join(root, ".quarantine")
	fs := i.options.FileSystem
	if secureErr := secureDestination(fs, root); secureErr != nil {
		return result, errors.Join(cause, ErrQuarantined, secureErr)
	}
	_ = fs.MkdirAll(root, SnapshotTreeMode)
	_ = fs.Chmod(root, SnapshotTreeMode)
	if err := fs.WriteFile(marker, []byte("quarantined\n"), SnapshotFileMode); err == nil {
		_ = fs.Chmod(marker, SnapshotFileMode)
		result.QuarantineMarker = marker
	}
	if cause == nil {
		cause = ErrQuarantined
	}
	return result, errors.Join(cause, ErrQuarantined)
}
