package eventstore

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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
	return NewStore(db, WithKeySource(source)), db, source
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
	resolved, err := store.ResolveSecret(ctx, "secret-ref", 1)
	if err != nil || string(resolved.Plaintext) != "one" { t.Fatalf("resolve v1=%q err=%v", resolved.Plaintext, err) }
	var row adapterSecretRow
	if err := db.GORM().Where("secret_ref = ? AND secret_version = ?", "secret-ref", 1).First(&row).Error; err != nil { t.Fatal(err) }
	if strings.Contains(string(row.Ciphertext), "one") { t.Fatal("secret plaintext persisted") }
	source.Roots["root-v1"] = []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA987654")
	if _, err := store.ResolveSecret(ctx, "secret-ref", 1); !errors.Is(err, ErrAuthenticationFailed) && !errors.Is(err, ErrKeyUnavailable) { t.Fatalf("wrong root err=%v", err) }
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

func TestReadinessPinAndRootAvailability(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	readiness := Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), TerminalGlobalPosition: 1, TerminalProjectionPosition: 1, CompletedAt: time.Unix(1, 0).UTC()}
	if err := store.SetReadiness(context.Background(), readiness); err != nil { t.Fatal(err) }
	got, err := store.GetReadiness(context.Background())
	if err != nil || got.Mode != "import" || got.IndexRootID != "index-v1" { t.Fatalf("readiness=%#v err=%v", got, err) }
	if err := store.ValidateReadiness(context.Background()); err != nil { t.Fatal(err) }
	source.IndexID = "changed-index"
	if !errors.Is(store.ValidateReadiness(context.Background()), ErrReadinessQuarantined) { t.Fatalf("changed index readiness was accepted") }
	if err := store.SetReadiness(context.Background(), Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "changed-index"}); !errors.Is(err, ErrReadinessQuarantined) { t.Fatalf("changed pin write err=%v", err) }
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
	source.Roots["root-v2"] = []byte("12345678901234567890123456789012")
	source.CurrentID = "root-v2"
	result, err := store.RotateEncryptionRoots(ctx)
	if err != nil { t.Fatal(err) }
	if result.Updated < 2 || result.CurrentRootID != "root-v2" { t.Fatalf("rotation result=%#v", result) }
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
	if _, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: "artifact-a"}); !errors.Is(err, ErrEncryptionUnavailable) {
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
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "claim-inbox", EndpointID: "endpoint", ProviderEventKey: "provider", LaneHMAC: []byte("lane"), Status: InboxStatusPending, PayloadCiphertext: inboxCipher, PayloadNonce: inboxNonce, DigestKeyID: inboxKey}); err != nil {
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
	if _, err := store.AcceptOutbox(ctx, NewEffect{EffectID: "claim-effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, PayloadCiphertext: ciphertext, PayloadNonce: nonce, DigestKeyID: keyID}); err != nil {
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
