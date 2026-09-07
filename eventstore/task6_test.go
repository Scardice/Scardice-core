package eventstore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"sync"
	"time"
)

type MemoryKeySource struct {
	IndexID       string
	IndexMaterial []byte
	Roots         map[string][]byte
	CurrentID     string
}

func NewMemoryKeySource(indexID string, indexMaterial []byte, roots map[string][]byte, currentID string) *MemoryKeySource {
	copyRoots := make(map[string][]byte, len(roots))
	for id, material := range roots {
		copyRoots[id] = append([]byte(nil), material...)
	}
	return &MemoryKeySource{IndexID: indexID, IndexMaterial: append([]byte(nil), indexMaterial...), Roots: copyRoots, CurrentID: currentID}
}
func (m *MemoryKeySource) IndexRootID(context.Context) (string, error) { if m == nil || m.IndexID == "" { return "", ErrKeySourceUnavailable }; return m.IndexID, nil }
func (m *MemoryKeySource) IndexRootMaterial(context.Context) ([]byte, error) { if m == nil || len(m.IndexMaterial) != 32 { return nil, ErrKeySourceUnavailable }; return append([]byte(nil), m.IndexMaterial...), nil }
func (m *MemoryKeySource) CurrentEncryptionRoot(ctx context.Context) (EncryptionRoot, error) { if m == nil || m.CurrentID == "" { return EncryptionRoot{}, ErrKeySourceUnavailable }; material, err := m.EncryptionRoot(ctx, m.CurrentID); return EncryptionRoot{ID: m.CurrentID, Material: material}, err }
func (m *MemoryKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) { if m == nil { return nil, ErrKeySourceUnavailable }; material, ok := m.Roots[id]; if !ok || len(material) != 32 { return nil, ErrKeyUnavailable }; return append([]byte(nil), material...), nil }
func (m *MemoryKeySource) EncryptionRoots(ctx context.Context) ([]EncryptionRoot, error) { if m == nil { return nil, ErrKeySourceUnavailable }; ids := make([]string, 0, len(m.Roots)); for id := range m.Roots { ids = append(ids, id) }; sort.Strings(ids); out := make([]EncryptionRoot, 0, len(ids)); for _, id := range ids { material, err := m.EncryptionRoot(ctx, id); if err != nil { return nil, err }; out = append(out, EncryptionRoot{ID: id, Material: material}) }; return out, nil }

type gatedRootKeySource struct {
	*MemoryKeySource
	mu      sync.Mutex
	calls   int
	blocked chan struct{}
	release chan struct{}
}

func (s *gatedRootKeySource) EncryptionRoot(ctx context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()
	if call == 2 {
		close(s.blocked)
		<-s.release
	}
	return s.MemoryKeySource.EncryptionRoot(ctx, id)
}

func TestCryptoKnownVector(t *testing.T) {
	source := task6Source()
	got, err := a6HMAC(context.Background(), source, "plugin-key-index/v1", "ext", "key")
	if err != nil {
		t.Fatal(err)
	}
	const want = "0c8ff04fa7aed3f959d1149243a62e586c79c8a4ccc5f8283abd5c00c0f71b88"
	if hex.EncodeToString(got) != want {
		t.Fatalf("HMAC vector=%x want=%s", got, want)
	}
}

func task6Source() *MemoryKeySource {
	return NewMemoryKeySource("index-v1", []byte("01234567890123456789012345678901"), map[string][]byte{
		"root-v1": []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}, "root-v1")
}

func task6Store(t *testing.T) (*GORMStore, *Database, *MemoryKeySource) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task6.db")})
	if err != nil { t.Fatal(err) }
	source := task6Source()
	store := NewStore(db, WithKeySource(source))
	if err := store.SetReadiness(context.Background(), Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.IndexID,
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return store, db, source
}

func TestA6CryptoRoundTripAndAuthentication(t *testing.T) {
	source := task6Source()
	ciphertext, nonce, keyID, err := a6Seal(context.Background(), source, "adapter-secret/v1", "secret-ref", "endpoint/adapter", 1, []byte("secret"))
	if err != nil { t.Fatal(err) }
	if keyID != "root-v1" || string(ciphertext) == "secret" || len(nonce) != 12 { t.Fatalf("crypto output key=%q nonce=%d ciphertext=%q", keyID, len(nonce), ciphertext) }
	plain, err := a6Open(context.Background(), source, "adapter-secret/v1", "secret-ref", "endpoint/adapter", 1, keyID, ciphertext, nonce)
	if err != nil || string(plain) != "secret" { t.Fatalf("round trip plaintext=%q err=%v", plain, err) }
	if _, err := a6Open(context.Background(), source, "adapter-secret/v1", "other-ref", "endpoint/adapter", 1, keyID, ciphertext, nonce); !errors.Is(err, ErrAuthenticationFailed) { t.Fatalf("wrong AAD err=%v", err) }
}

func TestSecretHistoryAndWrongKey(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	first, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("one")})
	if err != nil { t.Fatal(err) }
	second, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", ExpectedVersion: 1, Plaintext: []byte("two")})
	if err != nil { t.Fatal(err) }
	if first.SecretVersion != 1 || second.SecretVersion != 2 { t.Fatalf("secret versions=%d,%d", first.SecretVersion, second.SecretVersion) }
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "other-endpoint", AdapterID: "adapter", ExpectedVersion: 2, Plaintext: []byte("rebind")}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("secret endpoint rebind err=%v", err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "other-adapter", ExpectedVersion: 2, Plaintext: []byte("rebind")}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("secret adapter rebind err=%v", err)
	}
	resolved, err := store.ResolveSecret(ctx, "secret-ref", 1)
	if err != nil || string(resolved.Plaintext) != "one" { t.Fatalf("resolve v1=%q err=%v", resolved.Plaintext, err) }
	var row adapterSecretRow
	if err := db.GORM().Where("secret_ref = ? AND secret_version = ?", "secret-ref", 1).First(&row).Error; err != nil { t.Fatal(err) }
	if strings.Contains(string(row.Ciphertext), "one") { t.Fatal("secret plaintext persisted") }
	source.Roots["root-v1"] = []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA987654")
	if _, err := store.ResolveSecret(ctx, "secret-ref", 1); !errors.Is(err, ErrAuthenticationFailed) && !errors.Is(err, ErrKeyUnavailable) { t.Fatalf("wrong root err=%v", err) }
}
func TestA6SecretDecodedBounds(t *testing.T) {
	store, db, source := task6Store(t)
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
func TestA6KeyIDsRequireReadinessAdmission(t *testing.T) {
	store, db, source := task6Store(t)
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


func TestPluginKVExactAndPrefixIsolation(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext-a", Key: "alpha", Value: []byte("one")}); err != nil { t.Fatal(err) }
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext-a", Key: "alpine", Value: []byte("two")}); err != nil { t.Fatal(err) }
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "ext-b", Key: "alpha", Value: []byte("other")}); err != nil { t.Fatal(err) }
	item, err := store.GetPluginKV(ctx, "ext-a", "alpha")
	if err != nil || string(item.Value) != "one" { t.Fatalf("get=%#v err=%v", item, err) }
	items, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: "ext-a", Prefix: "alp"})
	if err != nil || len(items) != 2 { t.Fatalf("list=%#v err=%v", items, err) }
	if _, err := store.GetPluginKV(ctx, "ext-b", "alpine"); !errors.Is(err, ErrPluginKVNotFound) { t.Fatalf("extension isolation err=%v", err) }
	if err := store.DeletePluginKV(ctx, "ext-a", "alpha", item.Version); err != nil { t.Fatal(err) }
	if _, err := store.GetPluginKV(ctx, "ext-a", "alpha"); !errors.Is(err, ErrPluginKVNotFound) { t.Fatalf("delete err=%v", err) }
}
func TestPluginKVLookupBounds(t *testing.T) {
	store, db, _ := task6Store(t)
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
func TestA6WritesUseReadinessAdmittedCurrentRoot(t *testing.T) {
	store, db, source := task6Store(t)
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

	store, db, source := task6Store(t)
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
	store, db, source := task6Store(t)
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
func TestOperationViewAndPrivacyPurge(t *testing.T) {
	store, db, _ := task6Store(t)
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
	store, db, _ := task5Store(t)
	defer db.Close()
	if err := db.GORM().Migrator().DropTable(&operationRow{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetOperation(context.Background(), "query-failure"); !errors.Is(err, ErrParticipantFailure) {
		t.Fatalf("operation query failure err=%v", err)
	}
}



func TestReadinessPinAndRootAvailability(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	readiness := Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), TerminalGlobalPosition: 0, TerminalProjectionPosition: 0, CompletedAt: time.Unix(1, 0).UTC()}
	if err := store.SetReadiness(context.Background(), Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "db-1", IndexRootID: source.IndexID, EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); !errors.Is(err, ErrReadinessInvalid) {
		t.Fatalf("unsupported readiness schema err=%v", err)
	}
	if err := store.SetReadiness(context.Background(), readiness); err != nil { t.Fatal(err) }
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
func TestReadinessRequiresCurrentEncryptionRoot(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	cases := []struct {
		name string
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
	store, db, _ := task6Store(t)
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
	for i := 0; i < 4; i++ {
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


func TestPublicA6OperationRevalidatesReadiness(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("index_root_id", "tampered").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecret(context.Background(), SecretPutRequest{SecretRef: "revalidate", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret")}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("tampered readiness write err=%v", err)
	}
}
func TestPublicMutationRejectsFreshNonemptyReadinessTamper(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	event := NewEvent{EventType: "readiness.tamper", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "readiness-tamper-1", CommandID: "readiness-tamper-command-1", CorrelationID: "readiness-tamper-correlation-1", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "readiness", AggregateID: "1"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&storeReadinessRow{}).Where("singleton_id = ?", "default").Update("mode", "fresh").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "readiness", AggregateID: "2"}, Events: []NewEvent{event}}}}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("fresh nonempty readiness mutation err=%v", err)
	}
}


func TestReadinessRejectsUnpublishedProjection(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	if err := db.GORM().Model(&projectionControlRow{}).Where("singleton_id = ?", "default").Update("publication_state", "building").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateReadiness(context.Background()); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unpublished readiness err=%v", err)
	}
}
func TestTask5LockFailureRollsBackTransaction(t *testing.T) {
	store, db, source := task6Store(t)
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

func TestVersionOverflowFailsBeforeMutation(t *testing.T) {
	if _, err := nextVersion(maxUint64); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("nextVersion overflow err=%v", err)
	}
}
func TestA6OperationPrincipalAndCiphertextInvariants(t *testing.T) {
	store, db, source := task6Store(t)
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
	store, db, _ := task6Store(t)
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

func TestKeyFileSecurity(t *testing.T) {
	if os.Getenv("GOOS") == "windows" { t.Skip("Unix key file contract") }
	path := filepath.Join(t.TempDir(), "root.key")
	material := []byte("01234567890123456789012345678901")
	if err := CreateUnixKeyFile(path, material); err != nil { t.Fatal(err) }
	got, err := readKeyFile(path)
	if err != nil || string(got) != string(material) { t.Fatalf("key read=%q err=%v", got, err) }
	if err := os.Chmod(path, 0644); err != nil { t.Fatal(err) }
	if _, err := readKeyFile(path); !errors.Is(err, ErrKeyUnavailable) { t.Fatalf("insecure mode err=%v", err) }
}
func TestRotationReencryptsSecretAndPlugin(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "rotate-secret", EndpointID: "endpoint", AdapterID: "adapter", Plaintext: []byte("secret")}); err != nil { t.Fatal(err) }
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "rotate-ext", Key: "key", Value: []byte("value")}); err != nil { t.Fatal(err) }
	var beforeSecret adapterSecretRow
	if err := db.GORM().Where("secret_ref = ?", "rotate-secret").First(&beforeSecret).Error; err != nil { t.Fatal(err) }
	var beforePlugin pluginKVRow
	if err := db.GORM().Where("extension_id = ?", "rotate-ext").First(&beforePlugin).Error; err != nil { t.Fatal(err) }
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	if err := store.SetReadiness(ctx, Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1", "root-v2"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), TerminalGlobalPosition: 0, TerminalProjectionPosition: 0, CompletedAt: time.Unix(1, 0).UTC()}); err != nil { t.Fatal(err) }
	source.IndexMaterial[0] ^= 0xff
	if _, err := store.RotateEncryptionRoots(ctx); !errors.Is(err, ErrReadinessQuarantined) { t.Fatalf("changed index material rotation err=%v", err) }
	source.IndexMaterial[0] ^= 0xff
	source.CurrentID = "root-v2"
	result, err := store.RotateEncryptionRoots(ctx)
	if err != nil { t.Fatal(err) }
	if result.Updated < 2 || result.CurrentRootID != "root-v2" { t.Fatalf("rotation result=%#v", result) }
	var afterSecret adapterSecretRow
	if err := db.GORM().Where("secret_ref = ?", "rotate-secret").First(&afterSecret).Error; err != nil { t.Fatal(err) }
	var afterPlugin pluginKVRow
	if err := db.GORM().Where("extension_id = ?", "rotate-ext").First(&afterPlugin).Error; err != nil { t.Fatal(err) }
	if afterSecret.RowVersion != beforeSecret.RowVersion || afterSecret.SecretVersion != beforeSecret.SecretVersion || afterSecret.EncryptionKeyID != "root-v2" {
		t.Fatalf("rotation changed secret logical version: before=%#v after=%#v", beforeSecret, afterSecret)
	}
	if afterPlugin.RowVersion != beforePlugin.RowVersion || afterPlugin.EncryptionKeyID != "root-v2" {
		t.Fatalf("rotation changed plugin logical version: before=%#v after=%#v", beforePlugin, afterPlugin)
	}
	if got, err := store.ResolveSecret(ctx, "rotate-secret", 0); err != nil || string(got.Plaintext) != "secret" { t.Fatalf("rotated secret=%q err=%v", got.Plaintext, err) }
	if got, err := store.GetPluginKV(ctx, "rotate-ext", "key"); err != nil || string(got.Value) != "value" { t.Fatalf("rotated plugin=%q err=%v", got.Value, err) }
}
func TestReadinessRejectsNonEmptyFresh(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	event := NewEvent{EventType: "task6.event", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "event-1", CommandID: "command-1", CorrelationID: "correlation-1", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
	if _, err := store.Commit(context.Background(), UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "task6", AggregateID: "1"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateReadiness(context.Background()); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("unconfigured nonempty readiness err=%v", err)
	}
	if err := store.SetReadiness(context.Background(), Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1"}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("fresh nonempty readiness err=%v", err)
	}
}
func TestA6StartupReadinessGate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "startup-gate.db")
	source := task6Source()
	db, err := OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path})
	if err != nil { t.Fatal(err) }
	store := NewStore(db, WithKeySource(source))
	event := NewEvent{EventType: "startup.gate", SchemaVersion: 1, Payload: []byte(`{}`), Metadata: Metadata{EventID: "startup-event", CommandID: "startup-command", CorrelationID: "startup-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "startup", AggregateID: "1"}, Events: []NewEvent{event}}}}); err != nil { t.Fatal(err) }
	if err := db.Close(); err != nil { t.Fatal(err) }
	db, err = OpenDatabase(ctx, DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	reopened := NewStore(db)
	if _, err := reopened.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "startup", AggregateID: "2"}, Events: []NewEvent{event}}}}); !errors.Is(err, ErrReadinessQuarantined) {
		t.Fatalf("startup readiness gate err=%v", err)
	}
}

func TestRemoteDatabaseRequiresExternalKeySource(t *testing.T) {
	_, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "postgres", DSN: "postgres://invalid.invalid/eventstore"})
	if !errors.Is(err, ErrKeySourceUnavailable) {
		t.Fatalf("remote source error=%v", err)
	}
}

func TestUnixKeySourceUsesExplicitCurrentRoot(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("Unix key source contract")
	}
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.key")
	if err := CreateUnixKeyFile(indexPath, []byte("01234567890123456789012345678901")); err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(dir, "roots")
	if err := os.Mkdir(roots, 0700); err != nil {
		t.Fatal(err)
	}
	if err := CreateUnixKeyFile(filepath.Join(roots, "root-a.key"), []byte("abcdefghijklmnopqrstuvwxyz123456")); err != nil {
		t.Fatal(err)
	}
	if err := CreateUnixKeyFile(filepath.Join(roots, "root-z.key"), []byte("12345678901234567890123456789012")); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(roots, "current")
	if err := os.WriteFile(current, []byte("root-a"), 0600); err != nil {
		t.Fatal(err)
	}
	source := NewUnixFileKeySource(indexPath, roots)
	root, err := source.CurrentEncryptionRoot(context.Background())
	if err != nil || root.ID != "root-a" {
		t.Fatalf("current root=%#v err=%v", root, err)
	}
}
func TestPluginKVCiphertextBoundsAtMaximum(t *testing.T) {
	store, db, _ := task6Store(t)
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
func TestA6ArtifactAADBindsRowIdentity(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	for _, operationID := range []string{"artifact-op-1", "artifact-op-2"} {
		if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: operationID, PrincipalID: "owner-" + operationID}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "artifact-a", OperationID: "artifact-op-1", OwnerPrincipalID: "owner-artifact-op-1", Plaintext: []byte("alpha")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "artifact-b", OperationID: "artifact-op-2", OwnerPrincipalID: "owner-artifact-op-2", Plaintext: []byte("bravo")}); err != nil {
		t.Fatal(err)
	}
	var first, second operationArtifactRow
	if err := db.GORM().Where("artifact_id = ?", "artifact-a").First(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Where("artifact_id = ?", "artifact-b").First(&second).Error; err != nil {
		t.Fatal(err)
	}
	first.Ciphertext, second.Ciphertext = second.Ciphertext, first.Ciphertext
	first.Nonce, second.Nonce = second.Nonce, first.Nonce
	if err := db.GORM().Save(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Save(&second).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-a"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("swapped artifact err=%v", err)
	}
}
func TestA6ArtifactUoWBoundCiphertext(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-uow-op", PrincipalID: "artifact-uow-owner"}}}); err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "artifact/v1", "artifact-uow", "artifact-uow-owner", 1, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "artifact-uow", OperationID: "artifact-uow-op", OwnerPrincipalID: "artifact-uow-owner", Size: 7, Ciphertext: ciphertext, Nonce: nonce, EncryptionKeyID: keyID}}}); err != nil {
		t.Fatalf("bound artifact UoW err=%v", err)
	}
}
func TestA6UoWRejectsWrongCiphertextKey(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "operation-private/v1", "uow-op", "owner", 1, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	source.Roots["root-v1"] = []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA987654")
	_, err = store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "uow-op", Version: 0, PrincipalID: "owner", PrivateContextCiphertext: ciphertext, PrivateContextNonce: nonce, EncryptionKeyID: keyID}}})
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong-key UoW err=%v", err)
	}
}

func TestA6ArtifactStatusUpdateKeepsPayloadDecryptable(t *testing.T) {
	store, db, _ := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "artifact-status-op", PrincipalID: "artifact-status-owner"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutArtifact(ctx, ArtifactPutRequest{ArtifactID: "artifact-status", OperationID: "artifact-status-op", OwnerPrincipalID: "artifact-status-owner", Plaintext: []byte("status")}); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Model(&operationArtifactRow{}).Where("artifact_id = ?", "artifact-status").Update("status", "ready").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "artifact-status", Status: "available", ExpectedVersion: 1}}}); err != nil {
		t.Fatal(err)
	}
	result, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-status"})
	if err != nil || string(result.Plaintext) != "status" {
		t.Fatalf("status update consume=%q err=%v", result.Plaintext, err)
	}
}

func TestA6ClaimRejectsTamperedPayloadBeforeLease(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	inboxCipher, inboxNonce, inboxKey, err := a6Seal(ctx, source, "inbox/v1", "claim-inbox", "endpoint", 1, []byte("inbox"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "claim-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Status: InboxStatusPending, PayloadCiphertext: inboxCipher, PayloadNonce: inboxNonce, PayloadEncryptionKeyID: inboxKey}); err != nil {
		t.Fatal(err)
	}
	var inbox inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "claim-inbox").First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	inbox.PayloadCiphertext[0] ^= 1
	if err := db.GORM().Model(&inboxMessageRow{}).Where("inbox_id = ?", inbox.InboxID).Update("payload_ciphertext", inbox.PayloadCiphertext).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered inbox claim err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Status != InboxStatusPending || inbox.Version != 1 {
		t.Fatalf("tampered inbox mutated row=%#v", inbox)
	}
}

func TestA6ClaimsCommitExpiredScrubBeforeAuthFailure(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	expiredAt := now.Add(-time.Minute)
	futureAt := now.Add(time.Hour)
	expiredInboxCipher, expiredInboxNonce, keyID, err := a6Seal(ctx, source, "inbox/v1", "expired-inbox", "endpoint", 1, []byte("expired"))
	if err != nil {
		t.Fatal(err)
	}
	candidateInboxCipher, candidateInboxNonce, _, err := a6Seal(ctx, source, "inbox/v1", "candidate-inbox", "endpoint", 1, []byte("candidate"))
	if err != nil {
		t.Fatal(err)
	}
	candidateInboxCipher[0] ^= 1
	inboxRows := []inboxMessageRow{
		{InboxID: "blocked-inbox", EndpointID: "endpoint", ProviderEventKey: "blocked-provider", LaneHMAC: []byte("blocked-lane"), OrderingSequence: 1, Status: InboxStatusCallbackStarted, Version: 1, PayloadVersion: 1},
		{InboxID: "expired-inbox", EndpointID: "endpoint", ProviderEventKey: "expired-provider", LaneHMAC: []byte("blocked-lane"), OrderingSequence: 2, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: expiredInboxCipher, PayloadNonce: expiredInboxNonce, EncryptionKeyID: keyID, PayloadExpiresAt: &expiredAt},
		{InboxID: "candidate-inbox", EndpointID: "endpoint", ProviderEventKey: "candidate-provider", LaneHMAC: []byte("candidate-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: candidateInboxCipher, PayloadNonce: candidateInboxNonce, EncryptionKeyID: keyID, PayloadExpiresAt: &futureAt},
	}
	if err := db.GORM().Create(&inboxRows).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered inbox claim err=%v", err)
	}
	var expiredInbox inboxMessageRow
	if err := db.GORM().Where("inbox_id = ?", "expired-inbox").First(&expiredInbox).Error; err != nil {
		t.Fatal(err)
	}
	if expiredInbox.Version != 2 || len(expiredInbox.PayloadCiphertext) != 0 || len(expiredInbox.PayloadNonce) != 0 {
		t.Fatalf("expired inbox scrub was rolled back: %#v", expiredInbox)
	}

	expiredOutboxCipher, expiredOutboxNonce, outboxKeyID, err := a6Seal(ctx, source, "outbox/v1", "expired-effect", "endpoint", 1, []byte("expired"))
	if err != nil {
		t.Fatal(err)
	}
	candidateOutboxCipher, candidateOutboxNonce, _, err := a6Seal(ctx, source, "outbox/v1", "candidate-effect", "endpoint", 1, []byte("candidate"))
	if err != nil {
		t.Fatal(err)
	}
	candidateOutboxCipher[0] ^= 1
	outboxRows := []outboxEffectRow{
		{EffectID: "blocked-effect", EndpointID: "endpoint", LaneHMAC: []byte("blocked-outbox-lane"), OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusAmbiguous, Version: 1, PayloadVersion: 1},
		{EffectID: "expired-effect", EndpointID: "endpoint", LaneHMAC: []byte("blocked-outbox-lane"), OrderingSequence: 2, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: expiredOutboxCipher, PayloadNonce: expiredOutboxNonce, EncryptionKeyID: outboxKeyID, PayloadExpiresAt: &expiredAt},
		{EffectID: "candidate-effect", EndpointID: "endpoint", LaneHMAC: []byte("candidate-outbox-lane"), OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: candidateOutboxCipher, PayloadNonce: candidateOutboxNonce, EncryptionKeyID: outboxKeyID, PayloadExpiresAt: &futureAt},
	}
	if err := db.GORM().Create(&outboxRows).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered outbox claim err=%v", err)
	}
	var expiredOutbox outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "expired-effect").First(&expiredOutbox).Error; err != nil {
		t.Fatal(err)
	}
	if expiredOutbox.Version != 2 || len(expiredOutbox.PayloadCiphertext) != 0 || len(expiredOutbox.PayloadNonce) != 0 {
		t.Fatalf("expired outbox scrub was rolled back: %#v", expiredOutbox)
	}
}

func TestA6AcceptExpiredRowsPrecedePayloadAuthentication(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	inbox := inboxMessageRow{
		InboxID: "expired-accept-inbox", EndpointID: "endpoint", ProviderEventKey: "expired-provider",
		LaneHMAC: []byte("expired-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1,
		PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{
		InboxID: inbox.InboxID, EndpointID: inbox.EndpointID, ProviderEventKey: inbox.ProviderEventKey,
		LaneHMAC: inbox.LaneHMAC, PayloadCiphertext: []byte{0x02}, PayloadNonce: make([]byte, 12),
		PayloadEncryptionKeyID: source.CurrentID,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired inbox auth/dedupe precedence err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Version != 2 || len(inbox.PayloadCiphertext) != 0 || len(inbox.PayloadNonce) != 0 {
		t.Fatalf("expired inbox was not scrubbed before auth: %#v", inbox)
	}

	effect := outboxEffectRow{
		EffectID: "expired-accept-effect", EndpointID: "endpoint", LaneHMAC: []byte("expired-effect-lane"),
		OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
		Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, NewEffect{
		EffectID: effect.EffectID, EndpointID: effect.EndpointID, LaneHMAC: effect.LaneHMAC,
		EffectType: effect.EffectClass, RiskClass: effect.RiskClass, PayloadCiphertext: []byte{0x02},
		PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired outbox auth/dedupe precedence err=%v", err)
	}
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if effect.Version != 2 || len(effect.PayloadCiphertext) != 0 || len(effect.PayloadNonce) != 0 {
		t.Fatalf("expired outbox was not scrubbed before auth: %#v", effect)
	}
}

func TestA6PluginUoWResealedUpdateRoundtrip(t *testing.T) {
	store, db, source := task6Store(t)
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
	store, db, _ := task6Store(t)
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

func TestA6ClaimOutboxRejectsTamperedPayloadBeforeLease(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "outbox/v1", "claim-effect", "endpoint", 1, []byte("effect"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, NewEffect{EffectID: "claim-effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID}); err != nil {
		t.Fatal(err)
	}
	var effect outboxEffectRow
	if err := db.GORM().Where("effect_id = ?", "claim-effect").First(&effect).Error; err != nil {
		t.Fatal(err)
	}
	effect.PayloadCiphertext[0] ^= 1
	if err := db.GORM().Model(&outboxEffectRow{}).Where("effect_id = ?", effect.EffectID).Update("payload_ciphertext", effect.PayloadCiphertext).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimOutbox(ctx, OutboxClaimRequest{WorkerID: "worker"}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("tampered effect claim err=%v", err)
	}
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if effect.Status != OutboxStatusPending || effect.Version != 1 {
		t.Fatalf("tampered effect mutated row=%#v", effect)
	}
}
func TestA6PluginKeyHMACBinding(t *testing.T) {
	store, db, source := task6Store(t)
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

func TestA6UOWExpiredRowsPrecedePayloadAuthentication(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	inbox := inboxMessageRow{
		InboxID: "uow-expired-auth-inbox", EndpointID: "endpoint", ProviderEventKey: "uow-provider",
		LaneHMAC: []byte("uow-expired-lane"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1,
		PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{InboxUpdates: []InboxUpdate{{
		InboxID: inbox.InboxID, ExpectedVersion: 1, Version: 2, Status: InboxStatusPending,
		EndpointID: inbox.EndpointID, PayloadCiphertext: []byte{0x02}, PayloadNonce: make([]byte, 12),
		PayloadEncryptionKeyID: source.CurrentID,
	}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired inbox auth precedence err=%v", err)
	}
	if err := db.GORM().Where("inbox_id = ?", inbox.InboxID).First(&inbox).Error; err != nil {
		t.Fatal(err)
	}
	if inbox.Version != 2 || len(inbox.PayloadCiphertext) != 0 || len(inbox.PayloadNonce) != 0 {
		t.Fatalf("uow expired inbox was not scrubbed: %#v", inbox)
	}

	effect := outboxEffectRow{
		EffectID: "uow-expired-auth-effect", EndpointID: "endpoint", LaneHMAC: []byte("uow-expired-effect-lane"),
		OrderingSequence: 1, EffectClass: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending,
		Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{0x01}, PayloadNonce: make([]byte, 12),
		EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt,
	}
	if err := db.GORM().Create(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{{
		EffectID: effect.EffectID, ExpectedVersion: 1, Version: 2, Status: OutboxStatusPending,
		EndpointID: effect.EndpointID, EffectType: effect.EffectClass, RiskClass: effect.RiskClass,
		PayloadCiphertext: []byte{0x02}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID,
	}}}); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("uow expired outbox auth precedence err=%v", err)
	}
	if err := db.GORM().Where("effect_id = ?", effect.EffectID).First(&effect).Error; err != nil {
		t.Fatal(err)
	}
	if effect.Version != 2 || len(effect.PayloadCiphertext) != 0 || len(effect.PayloadNonce) != 0 {
		t.Fatalf("uow expired outbox was not scrubbed: %#v", effect)
	}
}

func TestA6MixedUOWExpiryScrubsExplicitAndDedupeRows(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	expiredAt := time.Now().UTC().Add(-time.Minute)
	rows := []inboxMessageRow{
		{InboxID: "mixed-explicit", EndpointID: "endpoint", ProviderEventKey: "explicit-provider", LaneHMAC: []byte("mixed-lane-a"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{1}, PayloadNonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt},
		{InboxID: "mixed-dedupe", EndpointID: "endpoint", ProviderEventKey: "dedupe-provider", LaneHMAC: []byte("mixed-lane-b"), OrderingSequence: 1, Status: InboxStatusPending, Version: 1, PayloadVersion: 1, PayloadCiphertext: []byte{1}, PayloadNonce: make([]byte, 12), EncryptionKeyID: source.CurrentID, PayloadExpiresAt: &expiredAt},
	}
	if err := db.GORM().Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	work := UnitOfWork{InboxUpdates: []InboxUpdate{
		{InboxID: rows[0].InboxID, EndpointID: rows[0].EndpointID, ProviderEventKey: rows[0].ProviderEventKey, PayloadCiphertext: []byte{2}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID},
		{InboxID: "mixed-new-id", EndpointID: rows[1].EndpointID, ProviderEventKey: rows[1].ProviderEventKey, PayloadCiphertext: []byte{2}, PayloadNonce: make([]byte, 12), PayloadEncryptionKeyID: source.CurrentID},
	}}
	if _, err := store.Commit(ctx, work); !errors.Is(err, ErrPayloadExpired) {
		t.Fatalf("mixed UoW expiry err=%v", err)
	}
	for i := range rows {
		if err := db.GORM().Where("inbox_id = ?", rows[i].InboxID).First(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
		if rows[i].Version != 2 || len(rows[i].PayloadCiphertext) != 0 || len(rows[i].PayloadNonce) != 0 {
			t.Fatalf("mixed UoW row not scrubbed: %#v", rows[i])
		}
	}
}

func itemKeyHMAC(t *testing.T, source KeySource, extension, key string) []byte {
	t.Helper()
	index, err := a6HMAC(context.Background(), source, "plugin-key-index/v1", extension, key)
	if err != nil {
		t.Fatal(err)
	}
	return index
}
