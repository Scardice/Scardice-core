package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestReadinessPinAndRootAvailability(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	readiness := Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), TerminalGlobalPosition: 0, TerminalProjectionPosition: 0, CompletedAt: time.Unix(1, 0).UTC()}
	if err := store.SetReadiness(context.Background(), Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "db-1", IndexRootID: source.IndexID, EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); !errors.Is(err, ErrReadinessInvalid) {
		t.Fatalf("unsupported readiness schema err=%v", err)
	}
	if err := store.SetReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetReadiness(context.Background())
	if err != nil || got.Mode != "import" || got.IndexRootID != "index-v1" {
		t.Fatalf("readiness=%#v err=%v", got, err)
	}
	source.IndexMaterial[0] ^= 0xff
	if err := store.SetReadiness(context.Background(), Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID, EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("changed index material was silently repinned")
	}
	source.IndexMaterial[0] ^= 0xff
	source.IndexMaterial[0] ^= 0xff
	if !errors.Is(store.ValidateReadiness(context.Background()), ErrReadinessQuarantined) {
		t.Fatalf("changed index material readiness was accepted")
	}
	source.IndexMaterial[0] ^= 0xff
	source.IndexID = "changed-index"
	if !errors.Is(store.ValidateReadiness(context.Background()), ErrReadinessQuarantined) {
		t.Fatalf("changed index readiness was accepted")
	}
	if err := store.SetReadiness(context.Background(), Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "changed-index", EncryptionRootIDs: []string{"root-v1"}}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("changed pin write err=%v", err)
	}
}
func TestGetReadinessReturnsOwnedByteSlices(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	semanticManifest := []byte("semantic-manifest")
	semanticDigest := sha256.Sum256(semanticManifest)
	projectionManifest := []byte("projection-manifest")
	projectionDigest := sha256.Sum256(projectionManifest)
	if err := store.SetReadiness(ctx, Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: semanticDigest[:],
		TargetManifestDigest: semanticDigest[:], SemanticManifest: semanticManifest,
		ProjectionManifest: projectionManifest, ProjectionManifestDigest: projectionDigest[:],
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.IndexRootFingerprint) == 0 || len(got.EncryptionRootIDs) == 0 ||
		len(got.SourceManifestDigest) == 0 || len(got.TargetManifestDigest) == 0 ||
		len(got.SemanticManifest) == 0 || len(got.ProjectionManifest) == 0 ||
		len(got.ProjectionManifestDigest) == 0 {
		t.Fatalf("readiness omitted owned values: %#v", got)
	}
	got.IndexRootFingerprint[0] ^= 0xff
	got.EncryptionRootIDs[0] = "mutated-root"
	got.SourceManifestDigest[0] ^= 0xff
	got.TargetManifestDigest[0] ^= 0xff
	got.SemanticManifest[0] ^= 0xff
	got.ProjectionManifest[0] ^= 0xff
	got.ProjectionManifestDigest[0] ^= 0xff

	again, err := store.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	indexFingerprint := sha256.Sum256(source.IndexMaterial)
	if !bytes.Equal(again.IndexRootFingerprint, indexFingerprint[:]) ||
		len(again.EncryptionRootIDs) != 1 || again.EncryptionRootIDs[0] != "root-v1" ||
		!bytes.Equal(again.SourceManifestDigest, semanticDigest[:]) ||
		!bytes.Equal(again.TargetManifestDigest, semanticDigest[:]) ||
		!bytes.Equal(again.SemanticManifest, semanticManifest) ||
		!bytes.Equal(again.ProjectionManifest, projectionManifest) ||
		!bytes.Equal(again.ProjectionManifestDigest, projectionDigest[:]) {
		t.Fatalf("mutating returned readiness changed stored value: %#v", again)
	}
}
func TestCommitRejectsTamperedReadinessManifestHashes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		column string
	}{
		{name: "semantic", column: "semantic_manifest"},
		{name: "projection", column: "projection_manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db, source := openEncryptedTestStore(t)
			defer db.Close()
			ctx := context.Background()
			semanticManifest := []byte("semantic-manifest")
			semanticDigest := sha256.Sum256(semanticManifest)
			projectionManifest := []byte("projection-manifest")
			projectionDigest := sha256.Sum256(projectionManifest)
			if err := store.SetReadiness(ctx, Readiness{
				Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
				EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: semanticDigest[:],
				TargetManifestDigest: semanticDigest[:], SemanticManifest: semanticManifest,
				ProjectionManifest: projectionManifest, ProjectionManifestDigest: projectionDigest[:],
				CompletedAt: time.Unix(1, 0).UTC(),
			}); err != nil {
				t.Fatal(err)
			}
			manifest := semanticManifest
			if tc.column == "projection_manifest" {
				manifest = projectionManifest
			}
			tampered := append([]byte(nil), manifest...)
			tampered[0] ^= 0x20
			if err := db.GORM().Model(&storeReadinessRow{}).
				Where("singleton_id = ?", "default").Update(tc.column, tampered).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(ctx, UnitOfWork{
				Operations: []OperationUpdate{{OperationID: "tampered-" + tc.name}},
			}); !errors.Is(err, ErrReadinessInvalid) {
				t.Fatalf("commit with tampered %s manifest err=%v", tc.name, err)
			}
		})
	}
}
func TestA6FreshInitializationAllowsSubsequentCommit(t *testing.T) {
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "fresh-commit.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := newTestKeySource()
	store := NewStore(db, WithKeySource(source))
	ctx := context.Background()
	for _, operationID := range []string{"fresh-operation-1", "fresh-operation-2"} {
		if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: operationID}}}); err != nil {
			t.Fatalf("fresh commit %s err=%v", operationID, err)
		}
	}
}
func TestReadinessRequiresCurrentEncryptionRoot(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(*Readiness)
	}{
		{name: "global position", mutate: func(r *Readiness) { r.TerminalGlobalPosition = 1 }},
		{name: "projection position", mutate: func(r *Readiness) { r.TerminalProjectionPosition = 1 }},
		{name: "source manifest", mutate: func(r *Readiness) { r.SourceManifestDigest = make([]byte, 32) }},
		{name: "target manifest", mutate: func(r *Readiness) { r.TargetManifestDigest = make([]byte, 32) }},
		{name: "completion", mutate: func(r *Readiness) { r.CompletedAt = time.Unix(1, 0).UTC() }},
	}
	for _, tc := range cases {
		readiness := Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID, EncryptionRootIDs: []string{"root-v1"}}
		tc.mutate(&readiness)
		if err := store.SetReadiness(ctx, readiness); !errors.Is(err, ErrReadinessInvalid) {
			t.Fatalf("fresh %s err=%v", tc.name, err)
		}
	}
	err := store.SetReadiness(ctx, Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID})
	if !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("empty encryption roots err=%v", err)
	}
}
func TestReadinessMutationSerialization(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	readiness := Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}
	if err := store.SetReadiness(ctx, readiness); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 4 {
		extensionID := fmt.Sprintf("serialized-ext-%d", i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: extensionID, Key: "key", Value: []byte("value")})
			errs <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			errs <- store.SetReadiness(ctx, readiness)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent readiness/mutation error: %v", err)
		}
	}
}
func TestReadinessRejectsUnpublishedProjection(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	if err := db.GORM().Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Update("publication_state", "building").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateReadiness(context.Background()); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unpublished readiness err=%v", err)
	}
}
func TestReadinessLockFailureRollsBackTransaction(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "inbox/v1", "rollback-inbox", "endpoint", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	inbox := InboxUpdate{
		InboxID: "rollback-inbox", EndpointID: "endpoint", ProviderEventKey: "rollback-provider", LaneHMAC: []byte("rollback-lane"),
		PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID,
	}
	if err := db.GORM().Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Update("publication_state", "building").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, inbox); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("lock failure err=%v", err)
	}
	if err := db.GORM().Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Update("publication_state", "published").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, inbox); err != nil {
		t.Fatalf("post-lock-failure accept err=%v", err)
	}
}
func TestReadinessRejectsTamperedValidFreshMode(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	event := NewEvent{EventType: "task6.event", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "event-1", CommandID: "command-1", CorrelationID: "correlation-1", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "task6", AggregateID: "1"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	var existing storeReadinessRow
	if err := db.GORM().Where("singleton_id = ?", "default").First(&existing).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Updates(map[string]any{
		"mode": "fresh", "schema_version": "1", "database_identity": "db-1", "index_root_id": source.IndexID,
		"index_root_fingerprint": existing.IndexRootFingerprint, "encryption_root_ids": existing.EncryptionRootIDs,
		"source_manifest_digest": nil, "target_manifest_digest": nil, "terminal_global_position": 0,
		"terminal_projection_position": 0, "completed_at": nil,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateReadiness(context.Background()); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("tampered valid fresh readiness err=%v", err)
	}
}
func TestImportReadinessAdvancesWithEventCommit(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	event := NewEvent{EventType: "import.event", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "import-event-1", CommandID: "import-command-1", CorrelationID: "import-correlation-1", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "import", AggregateID: "1"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	readiness, err := store.GetReadiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readiness.TerminalGlobalPosition == 0 || readiness.TerminalProjectionPosition == 0 {
		t.Fatalf("import readiness terminals not advanced: %#v", readiness)
	}
	if err := store.ValidateReadiness(context.Background()); err != nil {
		t.Fatalf("import readiness after event commit err=%v", err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{Operations: []OperationUpdate{{OperationID: "import-followup"}}}); err != nil {
		t.Fatalf("follow-up participant commit err=%v", err)
	}
}
func TestFreshReadinessSurvivesReopenAfterCommit(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fresh-reopen.db")
	source := newTestKeySource()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, WithKeySource(source))
	if err := store.SetReadiness(ctx, Readiness{
		Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"},
	}); err != nil {
		t.Fatal(err)
	}
	event := NewEvent{
		EventType: "fresh.event", SchemaVersion: 1, Payload: []byte(`{}`),
		Metadata: Metadata{
			EventID: "fresh-event-1", CommandID: "fresh-command-1",
			CorrelationID: "fresh-correlation-1", OccurredAtUnixNanoUTC: 1,
			OccurredAtUnixNanoSet: true,
		},
	}
	if _, err := store.Commit(ctx, UnitOfWork{
		Streams: []StreamAppend{{Stream: StreamID{AggregateType: "fresh", AggregateID: "1"}, Events: []NewEvent{event}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source})
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened := NewStore(reopenedDB, WithKeySource(source))
	if err := reopened.ValidateReadiness(ctx); err != nil {
		t.Fatalf("fresh readiness after reopen err=%v", err)
	}
}
func TestA6StartupReadinessGate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "startup-gate.db")
	source := newTestKeySource()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, WithKeySource(source))
	event := NewEvent{EventType: "startup.gate", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "startup-event", CommandID: "startup-command", CorrelationID: "startup-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "startup", AggregateID: "1"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("fresh_initialized", false).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reopened := NewStore(db)
	if _, err := reopened.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "startup", AggregateID: "2"}, Events: []NewEvent{event}}}}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("startup readiness gate err=%v", err)
	}
}
func TestA6StartupRejectsMalformedUnconfiguredReadiness(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "malformed-readiness.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("schema_version", "2").Error; err != nil {
		t.Fatal(err)
	}
	store := NewStore(db, WithKeySource(newTestKeySource()))
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "malformed-readiness-op"}}}); !errors.Is(err, ErrReadinessInvalid) {
		t.Fatalf("malformed unconfigured readiness err=%v", err)
	}
}
func TestA6ReadinessBootstrapPreservesProjectorInitError(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "projector-readiness.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, WithProjection(ProjectionDescriptor{Name: " ", Version: "v1", Apply: func(context.Context, *gorm.DB, []Envelope) error { return nil }}), WithKeySource(newTestKeySource()))
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "projector-readiness-op"}}}); !errors.Is(err, ErrInvalidProjector) {
		t.Fatalf("projector init error was cleared: %v", err)
	}
}
func TestRemoteDatabaseRequiresExternalKeySource(t *testing.T) {
	_, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "postgres", DSN: "postgres://invalid.invalid/eventstore"})
	if !errors.Is(err, ErrKeySourceUnavailable) {
		t.Fatalf("remote source error=%v", err)
	}
}
