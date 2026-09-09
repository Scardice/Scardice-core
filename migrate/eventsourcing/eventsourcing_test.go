package eventsourcing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"Scardice-core/eventstore"
)

type readinessFake struct {
	value eventstore.Readiness
	sets  []eventstore.Readiness
	err   error
}

func (f *readinessFake) GetReadiness(context.Context) (eventstore.Readiness, error) { return f.value, nil }
func (f *readinessFake) SetReadiness(_ context.Context, value eventstore.Readiness) error {
	if f.err != nil { return f.err }
	f.value = value
	f.sets = append(f.sets, value)
	return nil
}

type sourceFake struct {
	inventory SourceInventory
	snapshot SnapshotResult
	recheckErr error
	rechecked bool
}
func (s *sourceFake) Inventory(context.Context) (SourceInventory, error) { return s.inventory, nil }
func (s *sourceFake) Snapshot(_ context.Context, target string) (SnapshotResult, error) {
	if s.snapshot.Root != "" { return s.snapshot, nil }
	return SnapshotResult{Root: target, Metadata: s.inventory.Metadata}, nil
}
func (s *sourceFake) Recheck(context.Context, SourceMetadata) error { s.rechecked = true; return s.recheckErr }

func TestCanonicalManifestSortsAndRedactsSensitiveIdentity(t *testing.T) {
	manifest := SemanticManifest{Version: 1, SourceIdentity: "source"}
	manifest.Records = []ManifestRecord{
		{Domain: "z", Identity: "secret-message", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{1}, 32)},
		{Domain: "a", Identity: "token", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{2}, 32)},
	}
	encoded, digest, err := CanonicalManifest(manifest)
	if err != nil { t.Fatal(err) }
	if len(encoded) == 0 || len(digest) != 32 { t.Fatalf("manifest output not bounded: %d/%d", len(encoded), len(digest)) }
	if string(encoded) == "secret-message" || string(encoded) == "token" { t.Fatal("manifest persisted raw identity") }
	if manifest.Records[0].Domain != "z" { t.Fatal("canonicalization mutated caller") }
	ordered := manifest.SortedRecords()
	if ordered[0].Domain != "a" || ordered[1].Domain != "z" { t.Fatalf("order = %#v", ordered) }
	_, digest2, err := CanonicalManifest(SemanticManifest{Version: 1, SourceIdentity: "source", Records: []ManifestRecord{
		{Domain: "a", Identity: "token", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{2}, 32)},
		{Domain: "z", Identity: "secret-message", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{1}, 32)},
	}})
	if err != nil || !reflect.DeepEqual(digest, digest2) { t.Fatalf("canonical digest changed with order: %x/%x err=%v", digest, digest2, err) }
}

func TestLocalSQLiteSnapshotPreservesMainAndWALReadOnly(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "data.db")
	wal := main + "-wal"
	if err := os.WriteFile(main, []byte("main"), 0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(wal, []byte("wal"), 0o600); err != nil { t.Fatal(err) }
	source := NewSQLiteSource(main)
	result, err := source.Snapshot(context.Background(), filepath.Join(t.TempDir(), "snapshot"))
	if err != nil { t.Fatal(err) }
	for name, want := range map[string]string{"data.db": "main", "data.db-wal": "wal"} {
		got, readErr := os.ReadFile(filepath.Join(result.Root, name))
		if readErr != nil || string(got) != want { t.Fatalf("snapshot %s = %q/%v", name, got, readErr) }
		if info, statErr := os.Stat(filepath.Join(result.Root, name)); statErr != nil || info.Mode().Perm() != 0o600 { t.Fatalf("snapshot mode = %v/%v", info.Mode().Perm(), statErr) }
	}
	if info, err := os.Stat(result.Root); err != nil || info.Mode().Perm() != 0o700 { t.Fatalf("snapshot root mode = %v/%v", info.Mode().Perm(), err) }
}

func TestImporterFreshPublishesOnlyFreshReadiness(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "initial", IndexRootID: "index"}}
	result, err := NewImporter(ImporterOptions{Readiness: readiness, TargetIdentity: "target-1"}).Run(context.Background(), Request{Mode: ModeFresh})
	if err != nil { t.Fatal(err) }
	if result.Mode != ModeFresh || result.TargetIdentity != "target-1" { t.Fatalf("result = %#v", result) }
	if len(readiness.sets) != 1 || readiness.sets[0].Mode != "fresh" || readiness.sets[0].DatabaseIdentity != "target-1" { t.Fatalf("published = %#v", readiness.sets) }
}

func TestImporterQuarantinesOnSourceDriftBeforePublication(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "initial", IndexRootID: "index"}}
	source := &sourceFake{inventory: SourceInventory{
		Kind: SourceKindLegacy, Identity: "legacy-1", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy-1"},
		Records: []SourceRecord{{Domain: "events", Identity: "id", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{1}, 32)}},
	}, recheckErr: errors.New("drift")}
	root := filepath.Join(t.TempDir(), "snapshot")
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: source, SnapshotRoot: root, TargetIdentity: "target-1"}).Run(context.Background(), Request{Mode: ModeImport})
	if err == nil || !errors.Is(err, ErrSourceDrift) { t.Fatalf("err = %v", err) }
	if len(readiness.sets) != 0 { t.Fatal("readiness published despite source drift") }
	if result.QuarantineMarker == "" { t.Fatal("missing quarantine marker") }
	if _, statErr := os.Stat(result.QuarantineMarker); statErr != nil { t.Fatalf("marker: %v", statErr) }
	if !source.rechecked { t.Fatal("source was not rechecked") }
}

func TestImporterRejectsIncompleteOwnershipMap(t *testing.T) {
	source := &sourceFake{inventory: SourceInventory{Kind: SourceKindLegacy, Identity: "legacy", Metadata: SourceMetadata{Identity: "legacy"}}}
	_, err := NewImporter(ImporterOptions{Readiness: &readinessFake{value: eventstore.Readiness{IndexRootID: "index"}}, Source: source, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "target"}).Run(context.Background(), Request{Mode: ModeImport})
	var unsupported *UnsupportedPreflightError
	if !errors.As(err, &unsupported) { t.Fatalf("err = %v, want unsupported preflight", err) }
}

func TestManifestUsesBoundedBatches(t *testing.T) {
	if MaxBatchRecords != 500 || MaxBatchBytes != 8*1024*1024 { t.Fatalf("limits = %d/%d", MaxBatchRecords, MaxBatchBytes) }
	records := make([]ManifestRecord, MaxBatchRecords+1)
	for index := range records { records[index] = ManifestRecord{Domain: "events", Identity: fmt.Sprint(index), Kind: "event"} }
	batches, err := DeterministicBatches(records)
	if err != nil || len(batches) != 2 || len(batches[0]) != MaxBatchRecords { t.Fatalf("batches = %d/%d err=%v", len(batches), len(batches[0]), err) }
}
func validImportSource() *sourceFake {
	return &sourceFake{inventory: SourceInventory{Kind: SourceKindLegacy, Identity: "legacy", LegacyOwnershipComplete: true,
		Metadata: SourceMetadata{Identity: "legacy"},
		Records: []SourceRecord{{Domain: "events", Identity: "id", Kind: "event", SchemaVersion: 1, ContentDigest: bytes.Repeat([]byte{1}, 32)}}}}
}

func TestImporterPublishesImportReadinessAfterValidation(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}}
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: validImportSource(), SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "new"}).Run(context.Background(), Request{Mode: ModeImport})
	if err != nil { t.Fatal(err) }
	if result.Batches != 1 || len(result.ManifestDigest) != 32 || len(readiness.sets) != 1 { t.Fatalf("result/publication = %#v/%#v", result, readiness.sets) }
	if readiness.sets[0].Mode != "import" || readiness.sets[0].DatabaseIdentity != "new" || readiness.sets[0].CompletedAt.IsZero() { t.Fatalf("readiness = %#v", readiness.sets[0]) }
}

func TestImporterQuarantinesPublicationFailure(t *testing.T) {
	readiness := &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "index"}, err: errors.New("write refused")}
	root := filepath.Join(t.TempDir(), "snapshot")
	result, err := NewImporter(ImporterOptions{Readiness: readiness, Source: validImportSource(), SnapshotRoot: root, TargetIdentity: "new"}).Run(context.Background(), Request{Mode: ModeImport})
	if err == nil || !errors.Is(err, ErrPublication) || !errors.Is(err, ErrQuarantined) { t.Fatalf("err = %v", err) }
	if result.QuarantineMarker == "" { t.Fatal("missing quarantine marker") }
	if info, statErr := os.Stat(result.QuarantineMarker); statErr != nil || info.Mode().Perm() != 0o600 { t.Fatalf("marker mode = %v/%v", info.Mode().Perm(), statErr) }
}
