package eventsourcing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"Scardice-core/eventstore"
)

type readinessFake struct {
	value    eventstore.Readiness
	sets     []eventstore.Readiness
	err      error
	hasState bool
}

func (f *readinessFake) GetReadiness(context.Context) (eventstore.Readiness, error) {
	return f.value, nil
}
func (f *readinessFake) SetReadiness(_ context.Context, value eventstore.Readiness) error {
	if f.err != nil {
		return f.err
	}
	f.value = value
	f.sets = append(f.sets, value)
	return nil
}
func (f *readinessFake) HasPersistentState(context.Context) (bool, error) {
	return f.hasState, nil
}

type sourceFake struct {
	inventory   SourceInventory
	snapshot    SnapshotResult
	recheckErr  error
	recheckErrs []error
	rechecked   bool
	rechecks    int
	calls       []string
}

func (s *sourceFake) Inventory(context.Context) (SourceInventory, error) {
	s.calls = append(s.calls, "inventory")
	return s.inventory, nil
}
func (s *sourceFake) Snapshot(_ context.Context, target string) (SnapshotResult, error) {
	s.calls = append(s.calls, "snapshot")
	result := s.snapshot
	if result.Root == "" {
		result = SnapshotResult{Root: target, Metadata: s.inventory.Metadata}
	}
	if result.Source == nil {
		result.Source = s
	}
	return result, nil
}
func (s *sourceFake) Recheck(context.Context, SourceMetadata) error {
	s.rechecked = true
	s.rechecks++
	if s.rechecks <= len(s.recheckErrs) {
		return s.recheckErrs[s.rechecks-1]
	}
	return s.recheckErr
}

type targetFake struct {
	initialized         string
	batches             [][]SourceRecord
	rebuilt             bool
	reopened            bool
	manifest            SemanticManifest
	errAt               string
	published           []eventstore.Readiness
	projectionManifests [][]byte
	projectionCalls     int
}

func (t *targetFake) Initialize(_ context.Context, identity string) error {
	if t.errAt == "initialize" {
		return errors.New("initialize failed")
	}
	t.initialized = identity
	return nil
}

func (t *targetFake) ImportBatch(_ context.Context, records []SourceRecord) error {
	if t.errAt == "import" {
		return errors.New("import failed")
	}
	t.batches = append(t.batches, append([]SourceRecord(nil), records...))
	return nil
}

func (t *targetFake) Rebuild(context.Context) (eventstore.RebuildResult, error) {
	if t.errAt == "rebuild" {
		return eventstore.RebuildResult{}, errors.New("rebuild failed")
	}
	t.rebuilt = true
	return eventstore.RebuildResult{TerminalPosition: uint64(len(t.manifest.Records))}, nil
}

func (t *targetFake) Manifest(context.Context) (SemanticManifest, error) {
	if t.errAt == "manifest" {
		return SemanticManifest{}, errors.New("manifest failed")
	}
	return t.manifest, nil
}
func (t *targetFake) ProjectionManifest(context.Context) ([]byte, []byte, error) {
	index := t.projectionCalls
	t.projectionCalls++
	if len(t.projectionManifests) == 0 {
		manifest, digest, err := CanonicalManifest(SemanticManifest{Version: 1, SourceIdentity: t.initialized})
		return manifest, digest, err
	}
	if index >= len(t.projectionManifests) {
		index = len(t.projectionManifests) - 1
	}
	manifest := append([]byte(nil), t.projectionManifests[index]...)
	digest := sha256.Sum256(manifest)
	return manifest, digest[:], nil
}

func (t *targetFake) Reopen(context.Context) error {
	if t.errAt == "reopen" {
		return errors.New("reopen failed")
	}
	t.reopened = true
	return nil
}

func (t *targetFake) GetReadiness(context.Context) (eventstore.Readiness, error) {
	return eventstore.Readiness{
		Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: t.initialized, IndexRootID: "target-index",
		EncryptionRootIDs: []string{"target-root"},
	}, nil
}

func (t *targetFake) SetReadiness(_ context.Context, value eventstore.Readiness) error {
	if t.errAt == "publish" {
		return errors.New("write refused")
	}
	t.published = append(t.published, value)
	return nil
}

func (t *targetFake) Close() error { return nil }

type reusableTargetFake struct{ targetFake }

func (*reusableTargetFake) AllowsReadinessIdentityReuse() bool { return true }

type closeFailPublicationTarget struct {
	targetFake
	activated bool
}

func (t *closeFailPublicationTarget) Publish(context.Context) error {
	t.activated = true
	return nil
}

func (t *closeFailPublicationTarget) Close() error {
	if t.activated {
		return errors.New("close after activation failed")
	}
	return nil
}

func validSourceRecord(domain, identity, kind string, payload []byte) SourceRecord {
	digest := sha256.Sum256(payload)
	return SourceRecord{
		RecordType: RecordTypeEvent, Domain: domain, Identity: identity, Kind: kind, SchemaVersion: 1, Version: 1,
		ContentDigest: digest[:], Payload: append([]byte(nil), payload...), Size: uint64(len(payload)),
	}
}

func TestCanonicalManifestSortsAndRedactsSensitiveIdentity(t *testing.T) {
	manifest := SemanticManifest{Version: 1, SourceIdentity: "source"}
	manifest.Records = []ManifestRecord{
		{Domain: "z", Identity: "secret-message", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{1}, 32)},
		{Domain: "a", Identity: "token", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{2}, 32)},
	}
	encoded, digest, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || len(digest) != 32 {
		t.Fatalf("manifest output not bounded: %d/%d", len(encoded), len(digest))
	}
	if bytes.Contains(encoded, []byte("secret-message")) || bytes.Contains(encoded, []byte("token")) {
		t.Fatal("manifest persisted raw identity")
	}
	if manifest.Records[0].Domain != "z" {
		t.Fatal("canonicalization mutated caller")
	}
	ordered := manifest.SortedRecords()
	if ordered[0].Domain != "a" || ordered[1].Domain != "z" {
		t.Fatalf("order = %#v", ordered)
	}
	_, digest2, err := CanonicalManifest(SemanticManifest{Version: 1, SourceIdentity: "source", Records: []ManifestRecord{
		{Domain: "a", Identity: "token", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{2}, 32)},
		{Domain: "z", Identity: "secret-message", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{1}, 32)},
	}})
	if err != nil || !reflect.DeepEqual(digest, digest2) {
		t.Fatalf("canonical digest changed with order: %x/%x err=%v", digest, digest2, err)
	}
	sensitive := SemanticManifest{Version: 1, SourceIdentity: "source", Records: []ManifestRecord{{
		RecordType: RecordTypeSecret, Domain: "onebot", Identity: "secret-ref", Kind: "endpoint",
		SchemaVersion: 1, Version: 1, Sensitive: true, Size: 12,
	}}}
	_, firstSensitiveDigest, err := CanonicalManifest(sensitive)
	if err != nil {
		t.Fatal(err)
	}
	sensitive.Records[0].Size = 200
	_, secondSensitiveDigest, err := CanonicalManifest(sensitive)
	if err != nil || !bytes.Equal(firstSensitiveDigest, secondSensitiveDigest) {
		t.Fatalf("sensitive size leaked into manifest: %x/%x err=%v", firstSensitiveDigest, secondSensitiveDigest, err)
	}
}

func TestValidatePublicationReportsFailedInvariant(t *testing.T) {
	err := ValidatePublication(eventstore.Readiness{
		Mode:             string(ModeImport),
		SchemaVersion:    1,
		DatabaseIdentity: "target",
		IndexRootID:      "index",
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "source manifest digest length") {
		t.Fatalf("validation error lacks failed invariant: %v", err)
	}
}

func TestCanonicalImportManifestOmitsOversizedEncodingButKeepsDigest(t *testing.T) {
	manifest := SemanticManifest{Version: 1, SourceIdentity: "source", Records: []ManifestRecord{
		{Domain: "group", Identity: "group-1", Kind: "created", SchemaVersion: 1, Version: 1, ContentDigest: bytes.Repeat([]byte{1}, sha256.Size)},
	}}
	canonical, wantDigest, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	omitted, digest, err := canonicalImportManifest(manifest, len(canonical)-1)
	if err != nil {
		t.Fatal(err)
	}
	if omitted != nil || !bytes.Equal(digest, wantDigest) {
		t.Fatalf("digest-only manifest = %d bytes/%x, want omitted/%x", len(omitted), digest, wantDigest)
	}
	retained, retainedDigest, err := canonicalImportManifest(manifest, len(canonical))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, canonical) || !bytes.Equal(retainedDigest, wantDigest) {
		t.Fatal("bounded import manifest did not retain the canonical encoding")
	}
}

func TestLocalSQLiteSnapshotPreservesMainAndWALReadOnly(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "data.db")
	wal := main + "-wal"
	if err := os.WriteFile(main, []byte("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wal, []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := NewSQLiteSource(main)
	result, err := source.Snapshot(context.Background(), filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"data.db": "main", "data.db-wal": "wal"} {
		got, readErr := os.ReadFile(filepath.Join(result.Root, name))
		if readErr != nil || string(got) != want {
			t.Fatalf("snapshot %s = %q/%v", name, got, readErr)
		}
		if info, statErr := os.Stat(filepath.Join(result.Root, name)); statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("snapshot mode = %v/%v", info.Mode().Perm(), statErr)
		}
	}
	if info, err := os.Stat(result.Root); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot root mode = %v/%v", info.Mode().Perm(), err)
	}
}

func TestImporterFreshPublishesOnlyFreshReadiness(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "initial", IndexRootID: "index"}}
	result, err := NewImporter(ImporterOptions{Readiness: readiness, TargetIdentity: "target-1"}).Run(context.Background(), Request{Mode: ModeFresh})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != ModeFresh || result.TargetIdentity != "target-1" {
		t.Fatalf("result = %#v", result)
	}
	if len(readiness.sets) != 1 || readiness.sets[0].Mode != "fresh" || readiness.sets[0].DatabaseIdentity != "target-1" {
		t.Fatalf("published = %#v", readiness.sets)
	}
}

func TestImporterQuarantinesOnSourceDriftBeforePublication(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "initial", IndexRootID: "index"}}
	source := &sourceFake{inventory: SourceInventory{
		Kind: SourceKindLegacy, Identity: "legacy-1", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy-1"},
		Records:  []SourceRecord{validSourceRecord("events", "id", "event", []byte(`{"value":1}`))},
	}, recheckErr: errors.New("drift")}
	root := filepath.Join(t.TempDir(), "snapshot")
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: source, SnapshotRoot: root, TargetIdentity: "target-1"}).Run(context.Background(), Request{Mode: ModeImport})
	if err == nil || !errors.Is(err, ErrSourceDrift) {
		t.Fatalf("err = %v", err)
	}
	if len(readiness.sets) != 0 {
		t.Fatal("readiness published despite source drift")
	}
	if result.QuarantineMarker == "" {
		t.Fatal("missing quarantine marker")
	}
	if _, statErr := os.Stat(result.QuarantineMarker); statErr != nil {
		t.Fatalf("marker: %v", statErr)
	}
	if !source.rechecked {
		t.Fatal("source was not rechecked")
	}
}

func TestImporterQuarantinesOnLateSourceDrift(t *testing.T) {
	source := validImportSource()
	source.recheckErrs = []error{nil, errors.New("late drift")}
	target := &targetFake{manifest: manifestFromSource(source.inventory)}
	root := filepath.Join(t.TempDir(), "snapshot")
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}},
		Source:    source, Target: target, SnapshotRoot: root, TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if !errors.Is(err, ErrSourceDrift) || !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v", err)
	}
	if source.rechecks != 2 || len(target.published) != 0 || result.QuarantineMarker == "" {
		t.Fatalf("rechecks/publication/result = %d/%#v/%#v", source.rechecks, target.published, result)
	}
}

func TestImporterRejectsIncompleteOwnershipMap(t *testing.T) {
	source := &sourceFake{inventory: SourceInventory{Kind: SourceKindLegacy, Identity: "legacy", Metadata: SourceMetadata{Identity: "legacy"}}}
	_, err := NewImporter(ImporterOptions{Readiness: &readinessFake{value: eventstore.Readiness{IndexRootID: "index"}}, Source: source, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "target"}).Run(context.Background(), Request{Mode: ModeImport})
	var unsupported *UnsupportedPreflightError
	if !errors.As(err, &unsupported) {
		t.Fatalf("err = %v, want unsupported preflight", err)
	}
}

func TestManifestUsesBoundedBatches(t *testing.T) {
	if MaxBatchRecords != eventstore.MaxUnitOfWorkEvents || MaxBatchBytes != 8*1024*1024 {
		t.Fatalf("limits = %d/%d", MaxBatchRecords, MaxBatchBytes)
	}
	records := make([]ManifestRecord, MaxBatchRecords+1)
	for index := range records {
		records[index] = ManifestRecord{Domain: "events", Identity: strconv.Itoa(index), Kind: "event"}
	}
	batches, err := DeterministicBatches(records)
	if err != nil || len(batches) != 2 || len(batches[0]) != MaxBatchRecords {
		t.Fatalf("batches = %d/%d err=%v", len(batches), len(batches[0]), err)
	}
	payloadSized := []ManifestRecord{
		{Domain: "events", Identity: "a", Kind: "event", Size: 5 * 1024 * 1024},
		{Domain: "events", Identity: "b", Kind: "event", Size: 5 * 1024 * 1024},
	}
	batches, err = DeterministicBatches(payloadSized)
	if err != nil || len(batches) != 2 {
		t.Fatalf("payload-sized batches = %d err=%v", len(batches), err)
	}
}

func TestImporterBoundsEventStreamsPerUnitOfWork(t *testing.T) {
	source := validImportSource()
	source.inventory.Records = make([]SourceRecord, eventstore.MaxUnitOfWorkStreams+1)
	for index := range source.inventory.Records {
		source.inventory.Records[index] = validSourceRecord("events", strconv.Itoa(index), "event", []byte(`{"value":1}`))
	}
	target := &targetFake{manifest: manifestFromSource(source.inventory)}
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Batches != 2 || len(target.batches) != 2 || len(target.batches[0]) != eventstore.MaxUnitOfWorkStreams {
		t.Fatalf("batches = %d/%d/%d", result.Batches, len(target.batches), len(target.batches[0]))
	}
}
func TestImporterSnapshotsBeforeReadingSourceInventory(t *testing.T) {
	source := validImportSource()
	target := &targetFake{manifest: manifestFromSource(source.inventory)}
	_, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if len(source.calls) < 2 || source.calls[0] != "snapshot" || source.calls[1] != "inventory" {
		t.Fatalf("source calls = %v, want snapshot before inventory", source.calls)
	}
}

func validImportSource() *sourceFake {
	return &sourceFake{inventory: SourceInventory{Kind: SourceKindLegacy, Identity: "legacy", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy"},
		Records:  []SourceRecord{validSourceRecord("events", "id", "event", []byte(`{"value":1}`))}}}
}

func TestImporterRejectsImportWithoutTarget(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}}
	_, err := NewImporter(ImporterOptions{Readiness: readiness, Source: validImportSource(), SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new"}).Run(context.Background(), Request{Mode: ModeImport})
	if !errors.Is(err, ErrTargetRequired) {
		t.Fatalf("err = %v", err)
	}
	if len(readiness.sets) != 0 {
		t.Fatal("readiness published without importing data")
	}
}

func TestImporterRejectsPayloadDigestMismatch(t *testing.T) {
	source := validImportSource()
	source.inventory.Records[0].Payload = []byte(`{"value":2}`)
	root := filepath.Join(t.TempDir(), "snapshot")
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}},
		Source:    source, Target: &targetFake{}, SnapshotRoot: root, TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if !errors.Is(err, ErrValidation) || !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v", err)
	}
	if message := err.Error(); !strings.Contains(message, "validate source record batch") ||
		!strings.Contains(message, "source record 1") ||
		!strings.Contains(message, "content digest mismatch") {
		t.Fatalf("validation error lacks safe record context: %v", err)
	}
	if result.QuarantineMarker == "" {
		t.Fatal("missing quarantine marker")
	}
}

func TestImporterReportsPostPublicationCloseAsWarning(t *testing.T) {
	source := validImportSource()
	target := &closeFailPublicationTarget{targetFake: targetFake{manifest: manifestFromSource(source.inventory)}}
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{
			Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index",
		}},
		Source: source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if err != nil {
		t.Fatalf("published import reported as failed: %v", err)
	}
	if !target.activated || result.QuarantineMarker != "" {
		t.Fatalf("activation/quarantine = %t/%q", target.activated, result.QuarantineMarker)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "close published import target") {
		t.Fatalf("cleanup warnings = %v", result.Warnings)
	}
}

func TestImporterSortsVersionsBeforeImport(t *testing.T) {
	source := validImportSource()
	versionOne := source.inventory.Records[0]
	versionTwo := validSourceRecord(versionOne.Domain, versionOne.Identity, versionOne.Kind, []byte(`{"value":2}`))
	versionTwo.Version = 2
	source.inventory.Records = []SourceRecord{versionTwo, versionOne}
	target := &targetFake{manifest: manifestFromSource(source.inventory)}
	_, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if len(target.batches) != 1 || len(target.batches[0]) != 2 || target.batches[0][0].Version != 1 || target.batches[0][1].Version != 2 {
		t.Fatalf("batches = %#v", target.batches)
	}
}

func TestImporterImportsRebuildsReopensAndPublishes(t *testing.T) {
	source := validImportSource()
	target := &targetFake{manifest: manifestFromSource(source.inventory)}
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}}
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new"}).Run(context.Background(), Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if target.initialized != "new" || len(target.batches) != 1 || !target.rebuilt || !target.reopened {
		t.Fatalf("target = %#v", target)
	}
	if result.Batches != 1 || len(result.ManifestDigest) != 32 || len(readiness.sets) != 0 || len(target.published) != 1 {
		t.Fatalf("result/publication = %#v/%#v/%#v", result, readiness.sets, target.published)
	}
	published := target.published[0]
	if published.Mode != "import" || published.DatabaseIdentity != "new" || published.IndexRootID != "target-index" || published.CompletedAt.IsZero() {
		t.Fatalf("readiness = %#v", published)
	}
	if len(published.SemanticManifest) == 0 || len(published.ProjectionManifest) == 0 || len(published.ProjectionManifestDigest) != sha256.Size {
		t.Fatalf("readiness omitted semantic manifests: %#v", published)
	}
}

func TestImporterQuarantinesTargetManifestMismatch(t *testing.T) {
	source := validImportSource()
	target := &targetFake{manifest: manifestFromSource(source.inventory)}
	target.manifest.Records[0].ContentDigest = bytes.Repeat([]byte{2}, 32)
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}}
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new"}).Run(context.Background(), Request{Mode: ModeImport})
	if !errors.Is(err, ErrValidation) || !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "source and target semantic manifests differ") {
		t.Fatalf("validation error lacks manifest mismatch stage: %v", err)
	}
	if len(readiness.sets) != 0 || result.QuarantineMarker == "" {
		t.Fatalf("publication/quarantine = %#v/%q", readiness.sets, result.QuarantineMarker)
	}
}

func TestImporterQuarantinesProjectionManifestDriftAfterReopen(t *testing.T) {
	source := validImportSource()
	target := &targetFake{
		manifest:            manifestFromSource(source.inventory),
		projectionManifests: [][]byte{[]byte("rebuilt"), []byte("reopened-drift")},
	}
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new",
	}).Run(context.Background(), Request{Mode: ModeImport})
	if !errors.Is(err, ErrValidation) || !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "projection manifest changed after target reopen") {
		t.Fatalf("validation error lacks projection reopen stage: %v", err)
	}
	if target.projectionCalls != 2 || result.QuarantineMarker == "" {
		t.Fatalf("projection calls/quarantine = %d/%q", target.projectionCalls, result.QuarantineMarker)
	}
}

func TestImporterRejectsFreshIdentityReuseWhenDatabaseHasStandaloneState(t *testing.T) {
	readiness := &readinessFake{
		value:    eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "existing", IndexRootID: "index"},
		hasState: true,
	}
	_, err := NewImporter(ImporterOptions{
		Readiness: readiness, Target: &reusableTargetFake{}, TargetIdentity: "existing",
	}).Run(context.Background(), Request{Mode: ModeFresh})
	if !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("identity reuse error = %v", err)
	}
}

func TestPreflightRejectsPendingMigrationBackupMismatchAndCapacityOverflow(t *testing.T) {
	base := SourceInventory{
		Kind: SourceKindLegacy, Identity: "source", Metadata: SourceMetadata{
			Identity: "source", Files: []FileMetadata{{Name: "data.db", Size: 1}},
		},
		BackupIdentity: "source", LegacyOwnershipComplete: true,
	}
	readiness := eventstore.Readiness{DatabaseIdentity: "old", IndexRootID: "index"}
	pending := base
	pending.PendingMigrations = []string{"006_V150UpgradeAttrsMigration"}
	if _, err := DecidePreflight(context.Background(), Request{Mode: ModeImport}, "new", &pending, readiness); !errors.Is(err, ErrUnsupportedPreflight) {
		t.Fatalf("pending migration error = %v", err)
	}
	mismatched := base
	mismatched.BackupIdentity = "other"
	if _, err := DecidePreflight(context.Background(), Request{Mode: ModeImport}, "new", &mismatched, readiness); !errors.Is(err, ErrSourceDrift) {
		t.Fatalf("backup identity error = %v", err)
	}
	oversized := base
	oversized.Metadata.Files[0].Size = MaxSnapshotBytes + 1
	if _, err := DecidePreflight(context.Background(), Request{Mode: ModeImport}, "new", &oversized, readiness); !errors.Is(err, ErrBatchLimit) {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestImporterQuarantinesPublicationFailure(t *testing.T) {
	source := validImportSource()
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}}
	root := filepath.Join(t.TempDir(), "snapshot")
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: source, Target: &targetFake{manifest: manifestFromSource(source.inventory), errAt: "publish"}, SnapshotRoot: root, TargetIdentity: "new"}).Run(context.Background(), Request{Mode: ModeImport})
	if err == nil || !errors.Is(err, ErrPublication) || !errors.Is(err, ErrQuarantined) {
		t.Fatalf("err = %v", err)
	}
	if result.QuarantineMarker == "" {
		t.Fatal("missing quarantine marker")
	}
	if info, statErr := os.Stat(result.QuarantineMarker); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %v/%v", info.Mode().Perm(), statErr)
	}
}

func TestImporterQuarantinesEveryTargetPhaseWithoutChangingCurrentReadiness(t *testing.T) {
	for _, stage := range []string{"initialize", "import", "rebuild", "reopen", "manifest", "publish"} {
		t.Run(stage, func(t *testing.T) {
			source := validImportSource()
			current := &readinessFake{value: eventstore.Readiness{
				Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "current", IndexRootID: "current-index",
			}}
			target := &targetFake{manifest: manifestFromSource(source.inventory), errAt: stage}
			result, err := NewImporter(ImporterOptions{
				Readiness: current, Source: source, Target: target,
				SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new-" + stage,
			}).Run(context.Background(), Request{Mode: ModeImport})
			if err == nil || !errors.Is(err, ErrQuarantined) {
				t.Fatalf("err = %v", err)
			}
			if len(current.sets) != 0 || len(target.published) != 0 || result.QuarantineMarker == "" {
				t.Fatalf("current/target/quarantine = %#v/%#v/%q", current.sets, target.published, result.QuarantineMarker)
			}
		})
	}
}

func TestImporterFailureInjectionNeverPublishesPartialTarget(t *testing.T) {
	stages := []struct {
		name       string
		quarantine bool
	}{
		{name: "start"},
		{name: "snapshot", quarantine: true}, {name: "preflight", quarantine: true}, {name: "manifest", quarantine: true},
		{name: "initialize", quarantine: true}, {name: "import", quarantine: true},
		{name: "rebuild", quarantine: true}, {name: "reopen", quarantine: true},
		{name: "target-manifest", quarantine: true}, {name: "validate", quarantine: true},
		{name: "publish", quarantine: true},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			source := validImportSource()
			current := &readinessFake{value: eventstore.Readiness{
				Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "current", IndexRootID: "current-index",
			}}
			target := &targetFake{manifest: manifestFromSource(source.inventory)}
			injected := errors.New("injected " + stage.name)
			result, err := NewImporter(ImporterOptions{
				Readiness: current, Source: source, Target: target,
				SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new-" + stage.name,
				FailureInjector: FailureFunc(func(candidate string) error {
					if candidate == stage.name {
						return injected
					}
					return nil
				}),
			}).Run(context.Background(), Request{Mode: ModeImport})
			if !errors.Is(err, injected) || len(current.sets) != 0 || len(target.published) != 0 {
				t.Fatalf("err/current/target = %v/%#v/%#v", err, current.sets, target.published)
			}
			if stage.quarantine != (result.QuarantineMarker != "") {
				t.Fatalf("quarantine = %q, want=%v", result.QuarantineMarker, stage.quarantine)
			}
		})
	}
}
