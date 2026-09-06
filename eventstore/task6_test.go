package eventstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	readiness := Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}
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
