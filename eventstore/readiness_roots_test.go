package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestReadinessRootAdmissionCoversEveryCiphertextColumn(t *testing.T) {
	for _, tc := range []struct {
		name, keyColumn, cipherColumn string
		nullable                      bool
		row                           func() any
	}{
		{"adapter", "encryption_key_id", "ciphertext", false, func() any {
			return &adapterSecretRow{SecretRef: "s", Ciphertext: []byte{1}, Nonce: []byte{}, EncryptionKeyID: "root-v1"}
		}},
		{"private-context", "private_key_id", "private_context", true, func() any {
			return &operationRow{OperationID: "op", PrivateContext: []byte{1}, PrivateKeyID: "root-v1"}
		}},
		{"artifact", "encryption_key_id", "ciphertext", true, func() any {
			return &operationArtifactRow{ArtifactID: "a", OperationID: "artifact-operation", Ciphertext: []byte{1}, EncryptionKeyID: "root-v1"}
		}},
		{"inbox", "encryption_key_id", "payload_ciphertext", true, func() any {
			return &inboxMessageRow{InboxID: "i", LaneHMAC: []byte{1}, PayloadCiphertext: []byte{1}, EncryptionKeyID: "root-v1"}
		}},
		{"outbox", "encryption_key_id", "payload_ciphertext", true, func() any {
			return &outboxEffectRow{EffectID: "o", LaneHMAC: []byte{1}, PayloadCiphertext: []byte{1}, EncryptionKeyID: "root-v1"}
		}},
		{"plugin-value", "encryption_key_id", "encrypted_value", false, func() any {
			return &pluginKVRow{ExtensionID: "p", KeyHMAC: []byte{1}, EncryptedKey: []byte{}, KeyNonce: []byte{}, EncryptedValue: []byte{1}, ValueNonce: []byte{}, EncryptionKeyID: "root-v1"}
		}},
		{"plugin-key", "encryption_key_id", "encrypted_key", false, func() any {
			return &pluginKVRow{ExtensionID: "p", KeyHMAC: []byte{1}, EncryptedKey: []byte{1}, KeyNonce: []byte{}, EncryptedValue: []byte{}, ValueNonce: []byte{}, EncryptionKeyID: "root-v1"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db, _ := openEncryptedTestStore(t)
			defer db.Close()
			ctx := context.Background()
			row := tc.row()
			if artifact, ok := row.(*operationArtifactRow); ok {
				if err := db.GORM().Create(&operationRow{OperationID: artifact.OperationID}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := db.GORM().Create(row).Error; err != nil {
				t.Fatal(err)
			}
			if err := store.ValidateReadiness(ctx); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"unadmitted", "ROOT-v1", "root-v1 ", " \t ", ""} {
				if err := db.GORM().Model(row).Where("1 = 1").Update(tc.keyColumn, key).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.ValidateReadiness(ctx); !errors.Is(err, ErrReadinessQuarantined) {
					t.Fatalf("key %q admitted: %v", key, err)
				}
			}
			if err := db.GORM().Model(row).Where("1 = 1").Update(tc.cipherColumn, []byte{}).Error; err != nil {
				t.Fatal(err)
			}
			if err := store.ValidateReadiness(ctx); err != nil {
				t.Fatalf("empty ciphertext retains a root reference: %v", err)
			}
			if tc.nullable {
				if err := db.GORM().Model(row).Where("1 = 1").Update(tc.cipherColumn, nil).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.ValidateReadiness(ctx); err != nil {
					t.Fatalf("NULL ciphertext retains a root reference: %v", err)
				}
			}
		})
	}
}

func TestCommitDefersHistoricalRootReferenceAudit(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rootID        string
		rootMaterial  []byte
		sourceHasRoot bool
	}{
		{
			name:          "retired",
			rootID:        "root-retired",
			rootMaterial:  []byte("retired-root-material-1234567890"),
			sourceHasRoot: true,
		},
		{
			name:         "unavailable",
			rootID:       "root-unavailable",
			rootMaterial: []byte("missing-root-material-1234567890"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, db, source := openEncryptedTestStore(t)
			defer db.Close()
			ctx := context.Background()
			if tc.sourceHasRoot {
				source.Roots[tc.rootID] = append([]byte(nil), tc.rootMaterial...)
			}
			root := EncryptionRoot{ID: tc.rootID, Material: tc.rootMaterial}
			ciphertext, nonce, keyID, err := a6SealWithRoot(root, "inbox/v1", "historical-"+tc.name, "endpoint", 1, []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.GORM().Create(&inboxMessageRow{
				InboxID:           "historical-" + tc.name,
				EndpointID:        "endpoint",
				ProviderEventKey:  "provider-" + tc.name,
				LaneHMAC:          []byte("lane-" + tc.name),
				OrderingSequence:  1,
				Status:            InboxStatusConfirmedConsumed,
				Version:           1,
				PayloadCiphertext: ciphertext,
				PayloadNonce:      nonce,
				EncryptionKeyID:   keyID,
				PayloadVersion:    1,
			}).Error; err != nil {
				t.Fatal(err)
			}

			if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{
				OperationID: "legal-after-" + tc.name,
			}}}); err != nil {
				t.Fatalf("unrelated legal commit rejected by historical %s root: %v", tc.name, err)
			}
			if err := store.ValidateReadiness(ctx); !errors.Is(err, ErrReadinessQuarantined) {
				t.Fatalf("explicit readiness audit accepted historical %s root: %v", tc.name, err)
			}

			secretCiphertext, secretNonce, secretKeyID, err := a6SealWithRoot(
				root,
				"adapter-secret/v1",
				"current-"+tc.name,
				"endpoint/adapter",
				1,
				[]byte("secret"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(ctx, UnitOfWork{SecretUpdates: []SecretUpdate{{
				SecretRef:       "current-" + tc.name,
				EndpointID:      "endpoint",
				AdapterID:       "adapter",
				SecretVersion:   1,
				Ciphertext:      secretCiphertext,
				Nonce:           secretNonce,
				EncryptionKeyID: secretKeyID,
			}}}); !errors.Is(err, ErrReadinessQuarantined) {
				t.Fatalf("current write with %s root err=%v", tc.name, err)
			}
		})
	}
}

func TestCommitDoesNotOpenUnusedHistoricalReadinessRoots(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	const retiredRootID = "root-retired"
	source.Roots[retiredRootID] = []byte("retired-root-material-1234567890")
	readiness, err := store.GetReadiness(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readiness.EncryptionRootIDs = append(readiness.EncryptionRootIDs, retiredRootID)
	if err := store.SetReadiness(ctx, readiness); err != nil {
		t.Fatal(err)
	}
	delete(source.Roots, retiredRootID)

	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{
		OperationID: "legal-with-unused-retired-root",
	}}}); err != nil {
		t.Fatalf("unrelated legal commit opened unused historical root: %v", err)
	}
	if err := store.ValidateReadiness(ctx); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("explicit readiness audit accepted unavailable historical root: %v", err)
	}
}
func TestResolveSecretKeepsReadinessProofOutOfHotPath(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	projectionManifest := make([]byte, 8<<20)
	projectionDigest := sha256.Sum256(projectionManifest)
	if err := store.SetReadiness(ctx, Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, sha256.Size),
		TargetManifestDigest: make([]byte, sha256.Size), ProjectionManifest: projectionManifest,
		ProjectionManifestDigest: projectionDigest[:], CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	metadata, err := store.GetReadinessMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.SemanticManifest) != 0 || len(metadata.ProjectionManifest) != 0 || !bytes.Equal(metadata.ProjectionManifestDigest, projectionDigest[:]) {
		t.Fatalf("bounded readiness metadata=%#v", metadata)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{
		SecretRef: "bounded-readiness", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret"),
	}); err != nil {
		t.Fatal(err)
	}

	readinessQueries := 0
	const callbackName = "test:count-hot-path-readiness-queries"
	if err := db.GORM().Callback().Query().After("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if strings.Contains(strings.ToLower(tx.Statement.SQL.String()), tableStoreReadiness) {
			readinessQueries++
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.GORM().Callback().Query().Remove(callbackName)
	})

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	resolved, err := store.ResolveSecret(ctx, "bounded-readiness", 0)
	runtime.ReadMemStats(&after)
	if err != nil || string(resolved.Plaintext) != "secret" {
		t.Fatalf("resolve secret=%q err=%v", resolved.Plaintext, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 4<<20 {
		t.Fatalf("single secret lookup allocated %d bytes with an immutable readiness proof", allocated)
	}
	if readinessQueries > 1 {
		t.Fatalf("single secret lookup queried immutable readiness metadata %d times, want at most the publication fence", readinessQueries)
	}
}
func TestA6KeyAdmissionRejectsRuntimeReadinessRootRemoval(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{
		SecretRef: "revoked-root", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&storeReadinessRow{}).
		Where("singleton_id = ?", "default").
		Update("encryption_root_ids", []byte(`["root-v2"]`)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveSecret(ctx, "revoked-root", 0); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("runtime readiness root removal err=%v", err)
	}
}
func TestNewStoreKeepsReadinessProofOutOfStartupHotPath(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	projectionManifest := make([]byte, 8<<20)
	projectionDigest := sha256.Sum256(projectionManifest)
	if err := store.SetReadiness(ctx, Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, sha256.Size),
		TargetManifestDigest: make([]byte, sha256.Size), ProjectionManifest: projectionManifest,
		ProjectionManifestDigest: projectionDigest[:], CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	countQueries := 0
	var businessQueries []string
	businessTables := []string{
		"domain_events", "aggregate_heads", "projection_read_models", "operations", "operation_artifacts",
		"inbox_messages", "outbox_effects", "adapter_secrets", "plugin_kv", "subject_fences",
		"story_log_sessions", "story_log_entries", "story_log_states", "story_log_outbound_intents", "story_log_imports",
	}
	if err := db.GORM().Callback().Query().After("gorm:query").Register("test:no-startup-business-reads", func(tx *gorm.DB) {
		statement := strings.ToLower(strings.TrimSpace(tx.Statement.SQL.String()))
		if strings.Contains(statement, "count(") {
			countQueries++
		}
		if !strings.HasPrefix(statement, "select") {
			return
		}
		for _, table := range businessTables {
			if strings.Contains(statement, table) {
				businessQueries = append(businessQueries, table)
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	reopened := NewStore(db, WithKeySource(source))
	runtime.ReadMemStats(&after)
	if err := reopened.initializationError(); err != nil {
		t.Fatal(err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 4<<20 {
		t.Fatalf("store startup allocated %d bytes for an immutable readiness proof", allocated)
	}
	if countQueries != 0 {
		t.Fatalf("store startup issued %d runtime table count queries", countQueries)
	}
	if len(businessQueries) != 0 {
		t.Fatalf("store startup queried runtime business tables: %v", businessQueries)
	}
}
func TestA6KeyIDsRequireReadinessAdmission(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	ciphertext, nonce, keyID, err := a6SealWithRoot(EncryptionRoot{ID: "root-v2", Material: source.Roots["root-v2"]}, "adapter-secret/v1", "unadmitted-secret", "endpoint/adapter", 1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{SecretUpdates: []SecretUpdate{{
		SecretRef: "unadmitted-secret", EndpointID: "endpoint", AdapterID: "adapter", SecretVersion: 1,
		Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID,
	}}}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unadmitted UoW root err=%v", err)
	}
	now := time.Now().UTC()
	if err := db.GORM().Create(&adapterSecretRow{
		SecretRef: "unadmitted-secret", SecretVersion: 1, EndpointID: "endpoint", AdapterID: "adapter", AdapterType: "opaque",
		Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID, RowVersion: 1, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveSecret(ctx, "unadmitted-secret", 1); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unadmitted stored root err=%v", err)
	}
}
func TestA6WritesUseReadinessAdmittedCurrentRoot(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	source.CurrentID = "root-v2"
	if _, err := store.PutSecret(context.Background(), SecretPutRequest{SecretRef: "current-root", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret")}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unadmitted current root secret err=%v", err)
	}
	source.CurrentID = "root-v1"
	if _, err := store.PutSecret(context.Background(), SecretPutRequest{SecretRef: "current-root", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret")}); err != nil {
		t.Fatalf("admitted current root secret err=%v", err)
	}
}
func TestAcceptRejectsKeyAfterReadinessRootRemoval(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	if err := store.SetReadiness(ctx, Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1", "root-v2"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	source.CurrentID = "root-v2"
	if err := store.SetReadiness(ctx, Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v2"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, keyID, err := a6SealWithRoot(EncryptionRoot{ID: "root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, "inbox/v1", "old-root-inbox", "endpoint", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{
		InboxID: "old-root-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"),
		PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID,
	}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("removed-root inbox err=%v", err)
	}
}
func TestA6ReadFenceBlocksConcurrentRootRemoval(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{
		SecretRef: "read-fence-secret", EndpointID: "endpoint", AdapterID: "adapter",
		Plaintext: []byte("secret"),
	}); err != nil {
		t.Fatal(err)
	}
	gated := &gatedRootKeySource{
		MemoryKeySource: source,
		blocked:         make(chan struct{}),
		release:         make(chan struct{}),
	}
	store.keySource = gated
	resolveDone := make(chan struct {
		res SecretResolution
		err error
	}, 1)
	go func() {
		res, err := store.ResolveSecret(ctx, "read-fence-secret", 1)
		resolveDone <- struct {
			res SecretResolution
			err error
		}{res: res, err: err}
	}()
	select {
	case <-gated.blocked:
	case <-time.After(time.Second):
		t.Fatal("ResolveSecret did not reach gated decrypt")
	}
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	source.CurrentID = "root-v2"
	removal := Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v2"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}
	removalDone := make(chan error, 1)
	go func() { removalDone <- store.SetReadiness(ctx, removal) }()
	select {
	case err := <-removalDone:
		if err == nil {
			t.Fatal("root removal committed while secret read held publication fence")
		}
	case <-time.After(100 * time.Millisecond):
	}
	close(gated.release)
	select {
	case result := <-resolveDone:
		if result.err != nil || string(result.res.Plaintext) != "secret" {
			t.Fatalf("fenced secret read=%q err=%v", result.res.Plaintext, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("ResolveSecret did not finish after releasing gate")
	}
	var removalErr error
	select {
	case removalErr = <-removalDone:
	case <-time.After(time.Second):
		t.Fatal("root removal did not finish after releasing read fence")
	}
	if removalErr == nil {
		t.Fatal("root removal unexpectedly succeeded")
	}
	source.CurrentID = "root-v1"
	if _, err := store.ResolveSecret(ctx, "read-fence-secret", 1); err != nil {
		t.Fatalf("post-fence secret read err=%v", err)
	}
}
