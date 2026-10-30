package eventstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSecretHistoryAndWrongKey(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	first, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", ExpectedVersion: 1, Plaintext: []byte("two")})
	if err != nil {
		t.Fatal(err)
	}
	if first.SecretVersion != 1 || second.SecretVersion != 2 {
		t.Fatalf("secret versions=%d,%d", first.SecretVersion, second.SecretVersion)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "other-endpoint", AdapterID: "adapter", ExpectedVersion: 2, Plaintext: []byte("rebind")}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("secret endpoint rebind err=%v", err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "other-adapter", ExpectedVersion: 2, Plaintext: []byte("rebind")}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("secret adapter rebind err=%v", err)
	}
	resolved, err := store.ResolveSecret(ctx, "secret-ref", 1)
	if err != nil || string(resolved.Plaintext) != "one" {
		t.Fatalf("resolve v1=%q err=%v", resolved.Plaintext, err)
	}
	var row adapterSecretRow
	if err := db.GORM().Where("secret_ref = ? AND secret_version = ?", "secret-ref", 1).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(row.Ciphertext), "one") {
		t.Fatal("secret plaintext persisted")
	}
	source.Roots["root-v1"] = []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA987654")
	if _, err := store.ResolveSecret(ctx, "secret-ref", 1); !errors.Is(err, ErrAuthenticationFailed) && !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("wrong root err=%v", err)
	}
}

func TestResolveSecretsPreservesLookupOrderAndExactVersion(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "batch-a", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("a1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "batch-a", EndpointID: "endpoint", AdapterID: "adapter", ExpectedVersion: 1, Plaintext: []byte("a2")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "batch-b", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("b1")}); err != nil {
		t.Fatal(err)
	}

	resolved, err := store.ResolveSecrets(ctx, []SecretLookup{
		{SecretRef: "batch-b", SecretVersion: 1},
		{SecretRef: "batch-a", SecretVersion: 1},
		{SecretRef: "batch-a", SecretVersion: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 3 || string(resolved[0].Plaintext) != "b1" || string(resolved[1].Plaintext) != "a1" || string(resolved[2].Plaintext) != "a2" {
		t.Fatalf("batch resolution=%+v", resolved)
	}
	if _, err = store.ResolveSecrets(ctx, []SecretLookup{{SecretRef: "missing", SecretVersion: 1}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing batch secret err=%v", err)
	}
	if _, err = store.ResolveSecrets(ctx, []SecretLookup{
		{SecretRef: "batch-a", SecretVersion: 1},
		{SecretRef: "batch-a", SecretVersion: 1},
	}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("duplicate batch lookup err=%v", err)
	}
}

func TestA6SecretDecodedBounds(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	oversized := make([]byte, MaxSecretBytes+1)
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "adapter-secret/v1", "oversized-secret", "endpoint/adapter", 1, oversized)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{SecretUpdates: []SecretUpdate{{
		SecretRef: "oversized-secret", EndpointID: "endpoint", AdapterID: "adapter", SecretVersion: 1,
		Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID,
	}}}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversized encrypted UoW secret err=%v", err)
	}
	var count int64
	if err := db.GORM().Model(&adapterSecretRow{}).Where("secret_ref = ?", "oversized-secret").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("oversized UoW secret persisted: %d", count)
	}
	now := time.Now().UTC()
	if err := db.GORM().Create(&adapterSecretRow{
		SecretRef: "oversized-secret", SecretVersion: 1, EndpointID: "endpoint", AdapterID: "adapter", AdapterType: "opaque",
		Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID, RowVersion: 1, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveSecret(ctx, "oversized-secret", 1)
	if !errors.Is(err, ErrOversizeInput) || len(resolved.Plaintext) != 0 {
		t.Fatalf("oversized resolved secret=%d err=%v", len(resolved.Plaintext), err)
	}
}

func TestPluginKVExactAndPrefixIsolation(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext-a", Key: "alpha", Value: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext-a", Key: "alpine", Value: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext-b", Key: "alpha", Value: []byte("other")}); err != nil {
		t.Fatal(err)
	}
	item, err := store.GetPluginKV(ctx, "ext-a", "alpha")
	if err != nil || string(item.Value) != "one" {
		t.Fatalf("get=%#v err=%v", item, err)
	}
	items, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: "ext-a", Prefix: "alp"})
	if err != nil || len(items) != 2 {
		t.Fatalf("list=%#v err=%v", items, err)
	}
	if _, err := store.GetPluginKV(ctx, "ext-b", "alpine"); !errors.Is(err, ErrPluginKVNotFound) {
		t.Fatalf("extension isolation err=%v", err)
	}
	if err := store.DeletePluginKV(ctx, "ext-a", "alpha", item.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPluginKV(ctx, "ext-a", "alpha"); !errors.Is(err, ErrPluginKVNotFound) {
		t.Fatalf("delete err=%v", err)
	}
}
func TestPluginKVEmptyOpaqueKeyRoundTrips(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	item, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "legacy-ext", Key: "", Value: []byte("[object Object]")})
	if err != nil {
		t.Fatal(err)
	}
	if item.Key != "" || string(item.Value) != "[object Object]" {
		t.Fatalf("set empty-key item = %#v", item)
	}
	if _, err = store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "legacy-ext", Key: "other", Value: []byte("still-readable")}); err != nil {
		t.Fatalf("set another key after empty key: %v", err)
	}
	loaded, err := store.GetPluginKV(ctx, "legacy-ext", "")
	if err != nil || loaded.Key != "" || string(loaded.Value) != "[object Object]" {
		t.Fatalf("get empty-key item = %#v, err=%v", loaded, err)
	}
	items, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: "legacy-ext"})
	emptyFound := false
	for _, listed := range items {
		emptyFound = emptyFound || listed.Key == "" && string(listed.Value) == "[object Object]"
	}
	if err != nil || len(items) != 2 || !emptyFound {
		t.Fatalf("list empty-key item = %#v, err=%v", items, err)
	}
	if err = store.DeletePluginKV(ctx, "legacy-ext", "", loaded.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetPluginKV(ctx, "legacy-ext", ""); !errors.Is(err, ErrPluginKVNotFound) {
		t.Fatalf("deleted empty key error = %v", err)
	}
}

func TestPluginKVLookupBounds(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	longKey := strings.Repeat("k", MaxPluginKeyBytes+1)
	if _, err := store.GetPluginKV(ctx, "ext", longKey); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversized get key err=%v", err)
	}
	if err := store.DeletePluginKV(ctx, "ext", longKey, 0); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversized delete key err=%v", err)
	}
	if _, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: strings.Repeat("e", MaxPluginExtensionBytes+1)}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversized list extension err=%v", err)
	}
	if _, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: "ext", Prefix: longKey}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("oversized list prefix err=%v", err)
	}
}
func TestOperationViewAndPrivacyPurge(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	now := time.Now().UTC()
	if err := db.GORM().Create(&operationRow{
		OperationID: "purge-operation", Version: 1, Kind: "test", Status: "succeeded",
		PrincipalID: "principal", IdempotencyScope: "scope", IdempotencyKey: "key",
		PrivateContext: []byte("ciphertext"), PrivateNonce: []byte("nonce"), PrivateKeyID: "root-v1",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Create(&operationArtifactRow{
		ArtifactID: "purge-artifact", Version: 1, OperationID: "purge-operation", OwnerPrincipalID: "principal",
		MediaType: "application/octet-stream", Size: 1, Status: "available", Ciphertext: []byte("ciphertext"),
		Nonce: []byte("nonce"), EncryptionKeyID: "root-v1", ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	view, err := store.GetOperation(context.Background(), "purge-operation")
	if err != nil || view.OperationID != "purge-operation" || view.Status != "succeeded" {
		t.Fatalf("operation view=%#v err=%v", view, err)
	}
	purged, err := store.Purge(context.Background(), PrivacyPurgeRequest{OperationID: "purge-operation", Scope: "all"})
	if err != nil || purged.Deleted != 2 {
		t.Fatalf("purge=%#v err=%v", purged, err)
	}
	var operation operationRow
	if err := db.GORM().Where("operation_id = ?", "purge-operation").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if len(operation.PrivateContext) != 0 || len(operation.PrivateNonce) != 0 || operation.PrivateKeyID != "" {
		t.Fatalf("private context survived purge: %#v", operation)
	}
	var artifactCount int64
	if operation.Version != 2 {
		t.Fatalf("purge did not fence operation version: %d", operation.Version)
	}
	if err := db.GORM().Model(&operationArtifactRow{}).Where("operation_id = ?", "purge-operation").Count(&artifactCount).Error; err != nil {
		t.Fatal(err)
	}
	if artifactCount != 0 {
		t.Fatalf("artifacts survived purge: %d", artifactCount)
	}
	if err := db.GORM().Create(&operationRow{
		OperationID: "purge-artifacts-only", Version: 1, Kind: "test", Status: "succeeded",
		PrincipalID: "principal", IdempotencyScope: "scope", IdempotencyKey: "key-artifacts-only",
		CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Create(&operationArtifactRow{
		ArtifactID: "purge-artifacts-only-artifact", Version: 1, OperationID: "purge-artifacts-only", OwnerPrincipalID: "principal",
		MediaType: "application/octet-stream", Size: 1, Status: "available", Ciphertext: []byte("ciphertext"),
		Nonce: []byte("nonce"), EncryptionKeyID: "root-v1", ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if purged, err := store.Purge(context.Background(), PrivacyPurgeRequest{OperationID: "purge-artifacts-only", Scope: "artifacts"}); err != nil || purged.Deleted != 1 {
		t.Fatalf("artifact-only purge=%#v err=%v", purged, err)
	}
	operation = operationRow{}
	if err := db.GORM().Where("operation_id = ?", "purge-artifacts-only").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if operation.Version != 2 {
		t.Fatalf("artifact-only purge did not fence operation: %d", operation.Version)
	}
	if purged, err := store.Purge(context.Background(), PrivacyPurgeRequest{OperationID: "purge-artifacts-only", Scope: "private"}); err != nil || purged.Deleted != 0 {
		t.Fatalf("empty-private purge=%#v err=%v", purged, err)
	}
	if err := db.GORM().Where("operation_id = ?", "purge-artifacts-only").First(&operation).Error; err != nil {
		t.Fatal(err)
	}
	if operation.Version != 3 {
		t.Fatalf("empty-private purge did not fence operation: %d", operation.Version)
	}
}

func TestGetOperationQueryFailureIsNotNotFound(t *testing.T) {
	store, db, _ := openQueueTestStore(t)
	defer db.Close()
	if err := db.GORM().Migrator().DropTable(&operationRow{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOperation(context.Background(), "query-failure"); !errors.Is(err, ErrParticipantFailure) {
		t.Fatalf("operation query failure err=%v", err)
	}
}

func TestVersionOverflowFailsBeforeMutation(t *testing.T) {
	if _, err := nextVersion(maxUint64); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("nextVersion overflow err=%v", err)
	}
}
func TestA6OperationPrincipalAndCiphertextInvariants(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "operation-private/v1", "principal-op", "owner-a", 1, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "principal-op", PrincipalID: "owner-a", PrivateContextCiphertext: ciphertext, PrivateContextNonce: nonce, EncryptionKeyID: keyID}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "principal-op", ExpectedVersion: 1, PrincipalID: "owner-b"}}}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("principal mutation err=%v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "partial-op", PrincipalID: "owner", EncryptionKeyID: keyID}}}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("partial ciphertext err=%v", err)
	}
}

func TestA6DeletedPluginAuthenticatesBeforeDelete(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	item, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "delete-auth", Key: "key", Value: []byte("value")})
	if err != nil {
		t.Fatal(err)
	}
	var row pluginKVRow
	if err := db.GORM().Where("extension_id = ?", item.ExtensionID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	row.EncryptedKey[0] ^= 1
	if err := db.GORM().Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ?", row.ExtensionID, row.KeyHMAC).Update("encrypted_key", row.EncryptedKey).Error; err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{ExtensionID: row.ExtensionID, KeyHMAC: row.KeyHMAC, Deleted: true, ExpectedVersion: item.Version}}})
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered delete err=%v", err)
	}
}

func TestRotationReencryptsSecretAndPlugin(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "rotate-secret", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "rotate-ext", Key: "", Value: []byte("value")}); err != nil {
		t.Fatal(err)
	}
	var beforeSecret adapterSecretRow
	if err := db.GORM().Where("secret_ref = ?", "rotate-secret").First(&beforeSecret).Error; err != nil {
		t.Fatal(err)
	}
	var beforePlugin pluginKVRow
	if err := db.GORM().Where("extension_id = ?", "rotate-ext").First(&beforePlugin).Error; err != nil {
		t.Fatal(err)
	}
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	if err := store.SetReadiness(ctx, Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1", "root-v2"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), TerminalGlobalPosition: 0, TerminalProjectionPosition: 0, CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	source.IndexMaterial[0] ^= 0xff
	if _, err := store.RotateEncryptionRoots(ctx); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("changed index material rotation err=%v", err)
	}
	source.IndexMaterial[0] ^= 0xff
	source.CurrentID = "root-v2"
	result, err := store.RotateEncryptionRoots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated < 2 || result.CurrentRootID != "root-v2" {
		t.Fatalf("rotation result=%#v", result)
	}
	var afterSecret adapterSecretRow
	if err := db.GORM().Where("secret_ref = ?", "rotate-secret").First(&afterSecret).Error; err != nil {
		t.Fatal(err)
	}
	var afterPlugin pluginKVRow
	if err := db.GORM().Where("extension_id = ?", "rotate-ext").First(&afterPlugin).Error; err != nil {
		t.Fatal(err)
	}
	if afterSecret.RowVersion != beforeSecret.RowVersion || afterSecret.SecretVersion != beforeSecret.SecretVersion || afterSecret.EncryptionKeyID != "root-v2" {
		t.Fatalf("rotation changed secret logical version: before=%#v after=%#v", beforeSecret, afterSecret)
	}
	if afterPlugin.RowVersion != beforePlugin.RowVersion || afterPlugin.EncryptionKeyID != "root-v2" {
		t.Fatalf("rotation changed plugin logical version: before=%#v after=%#v", beforePlugin, afterPlugin)
	}
	if got, err := store.ResolveSecret(ctx, "rotate-secret", 0); err != nil || string(got.Plaintext) != "secret" {
		t.Fatalf("rotated secret=%q err=%v", got.Plaintext, err)
	}
	if got, err := store.GetPluginKV(ctx, "rotate-ext", ""); err != nil || string(got.Value) != "value" {
		t.Fatalf("rotated plugin=%q err=%v", got.Value, err)
	}
}

func TestPluginKVCiphertextBoundsAtMaximum(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	key := strings.Repeat("k", MaxPluginKeyBytes)
	value := make([]byte, MaxPluginValueBytes)
	for i := range value {
		value[i] = byte(i)
	}
	item, err := store.SetPluginKV(context.Background(), PluginKVPutRequest{ExtensionID: "max-ext", Key: key, Value: value})
	if err != nil {
		t.Fatal(err)
	}
	if len(item.Value) != MaxPluginValueBytes {
		t.Fatalf("stored max value len=%d", len(item.Value))
	}
	got, err := store.GetPluginKV(context.Background(), "max-ext", key)
	if err != nil || len(got.Value) != MaxPluginValueBytes {
		t.Fatalf("loaded max value len=%d err=%v", len(got.Value), err)
	}
}

func TestA6PluginUoWResealedUpdateRoundtrip(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "uow-ext", Key: "key", Value: []byte("value")}); err != nil {
		t.Fatal(err)
	}
	var row pluginKVRow
	if err := db.GORM().Where("extension_id = ?", "uow-ext").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	keyCipher, keyNonce, keyID, err := a6Seal(ctx, source, "plugin-kv-key/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion+1, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	valueCipher, valueNonce, valueKeyID, err := a6Seal(ctx, source, "plugin-kv-value/v1", string(row.KeyHMAC), row.ExtensionID, row.RowVersion+1, []byte("value"))
	if err != nil || valueKeyID != keyID {
		t.Fatalf("value seal err=%v key=%q", err, valueKeyID)
	}
	result, err := store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{
		ExtensionID: "uow-ext", KeyHMAC: row.KeyHMAC, ExpectedVersion: row.RowVersion, Version: row.RowVersion + 1,
		KeyCiphertext: keyCipher, KeyNonce: keyNonce, ValueCiphertext: valueCipher, ValueNonce: valueNonce,
		ValueSize: 5, EncryptionKeyID: keyID,
	}}})
	if err != nil || len(result.PluginKVIndexes) != 1 {
		t.Fatalf("encrypted PluginKV UoW update result=%#v err=%v", result, err)
	}
	item, err := store.GetPluginKV(ctx, "uow-ext", "key")
	if err != nil || string(item.Value) != "value" || item.Version != row.RowVersion+1 {
		t.Fatalf("encrypted PluginKV UoW roundtrip item=%#v err=%v", item, err)
	}
}

func TestA6SparseSecretUpdateResealsNewVersion(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "sparse-secret", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{SecretUpdates: []SecretUpdate{{SecretRef: "sparse-secret", ExpectedVersion: 1}}}); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveSecret(ctx, "sparse-secret", 2)
	if err != nil || string(resolved.Plaintext) != "secret" {
		t.Fatalf("sparse secret=%q err=%v", resolved.Plaintext, err)
	}
}

func TestA6PluginKeyHMACBinding(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	badIndex := []byte("01234567890123456789012345678901")
	keyCipher, keyNonce, keyID, err := a6Seal(ctx, source, "plugin-kv-key/v1", string(badIndex), "ext", 1, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	valueCipher, valueNonce, valueKeyID, err := a6Seal(ctx, source, "plugin-kv-value/v1", string(badIndex), "ext", 1, []byte("value"))
	if err != nil || valueKeyID != keyID {
		t.Fatalf("value seal err=%v key=%q", err, valueKeyID)
	}
	_, err = store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{
		ExtensionID: "ext", KeyHMAC: badIndex, KeyCiphertext: keyCipher, KeyNonce: keyNonce,
		ValueCiphertext: valueCipher, ValueNonce: valueNonce, EncryptionKeyID: keyID, ValueSize: 5,
	}}})
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("invalid plugin index UoW err=%v", err)
	}
	if _, err = store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext", Key: "key", Value: []byte("value")}); err != nil {
		t.Fatal(err)
	}
	var row pluginKVRow
	if err := db.GORM().Where("extension_id = ? AND key_hmac = ?", "ext", itemKeyHMAC(t, source, "ext", "key")).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	badIndex = append([]byte(nil), row.KeyHMAC...)
	badIndex[0] ^= 0xff
	keyCipher, keyNonce, keyID, err = a6Seal(ctx, source, "plugin-kv-key/v1", string(badIndex), "ext", row.RowVersion, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	valueCipher, valueNonce, valueKeyID, err = a6Seal(ctx, source, "plugin-kv-value/v1", string(badIndex), "ext", row.RowVersion, []byte("value"))
	if err != nil || valueKeyID != keyID {
		t.Fatalf("tampered value seal err=%v key=%q", err, valueKeyID)
	}
	if err := db.GORM().Model(&pluginKVRow{}).Where("extension_id = ? AND key_hmac = ?", "ext", row.KeyHMAC).Updates(map[string]any{
		"key_hmac": badIndex, "encrypted_key": keyCipher, "key_nonce": keyNonce,
		"encrypted_value": valueCipher, "value_nonce": valueNonce, "encryption_key_id": keyID,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPluginKV(ctx, "ext", "key"); !errors.Is(err, ErrPluginKVNotFound) && !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered plugin get err=%v", err)
	}
	if _, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: "ext"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered plugin list err=%v", err)
	}
}

func TestA6UOWPluginVersionOverflowFailsBeforeAuthentication(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	keyHMAC := itemKeyHMAC(t, source, "plugin-key-index/v1", "overflow-key")
	now := time.Now().UTC()
	row := pluginKVRow{
		ExtensionID: "overflow-extension", KeyHMAC: keyHMAC, EncryptedKey: []byte{1}, KeyNonce: make([]byte, 12),
		EncryptedValue: []byte{1}, ValueNonce: make([]byte, 12), ValueSize: 1, RowVersion: ^uint64(0) >> 1,
		EncryptionKeyID: source.CurrentID, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	_, err := store.Commit(context.Background(), UnitOfWork{PluginKVUpdates: []PluginKVUpdate{{
		ExtensionID: row.ExtensionID, KeyHMAC: row.KeyHMAC, KeyCiphertext: []byte{1}, KeyNonce: make([]byte, 12),
		ValueCiphertext: []byte{1}, ValueNonce: make([]byte, 12), ValueSize: 1, EncryptionKeyID: source.CurrentID,
	}}})
	if !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("plugin version overflow err=%v", err)
	}
}

func TestSetPluginKVVersionOverflowFailsBeforeSeal(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	extensionID := "public-overflow-extension"
	key := "public-overflow-key"
	keyHMAC := itemKeyHMAC(t, source, extensionID, key)
	now := time.Now().UTC()
	row := pluginKVRow{
		ExtensionID: extensionID, KeyHMAC: keyHMAC, EncryptedKey: []byte{1}, KeyNonce: make([]byte, 12),
		EncryptedValue: []byte{1}, ValueNonce: make([]byte, 12), ValueSize: 1, RowVersion: ^uint64(0) >> 1,
		EncryptionKeyID: source.CurrentID, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	_, err := store.SetPluginKV(context.Background(), PluginKVPutRequest{ExtensionID: extensionID, Key: key, Value: []byte("value"), ExpectedVersion: row.RowVersion})
	if !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("public plugin version overflow err=%v", err)
	}
}

func TestSecretVersionOverflowFailsBeforeAuthenticationAndSeal(t *testing.T) {
	store, db, source := openEncryptedTestStore(t)
	defer db.Close()
	now := time.Now().UTC()
	row := adapterSecretRow{
		SecretRef: "overflow-secret", SecretVersion: ^uint64(0) >> 1, EndpointID: "endpoint", AdapterID: "adapter",
		AdapterType: "opaque", Ciphertext: []byte{1}, Nonce: make([]byte, 12), EncryptionKeyID: source.CurrentID,
		RowVersion: ^uint64(0) >> 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{SecretUpdates: []SecretUpdate{{SecretRef: row.SecretRef}}}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("UoW secret version overflow err=%v", err)
	}
	if _, err := store.PutSecret(context.Background(), SecretPutRequest{SecretRef: row.SecretRef, EndpointID: row.EndpointID, AdapterID: row.AdapterID, Plaintext: []byte("value")}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("public secret version overflow err=%v", err)
	}
}
