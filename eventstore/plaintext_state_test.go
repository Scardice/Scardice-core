package eventstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSecretHistory(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	ctx := context.Background()
	first, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", Value: []byte("one")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "adapter", ExpectedVersion: 1, Value: []byte("two")})
	if err != nil {
		t.Fatal(err)
	}
	if first.SecretVersion != 1 || second.SecretVersion != 2 {
		t.Fatalf("secret versions=%d,%d", first.SecretVersion, second.SecretVersion)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "other-endpoint", AdapterID: "adapter", ExpectedVersion: 2, Value: []byte("rebind")}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("secret endpoint rebind err=%v", err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-ref", EndpointID: "endpoint", AdapterID: "other-adapter", ExpectedVersion: 2, Value: []byte("rebind")}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("secret adapter rebind err=%v", err)
	}
	resolved, err := store.ResolveSecret(ctx, "secret-ref", 1)
	if err != nil || string(resolved.Value) != "one" {
		t.Fatalf("resolve v1=%q err=%v", resolved.Value, err)
	}
}

func TestResolveSecretsPreservesLookupOrderAndExactVersion(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "batch-a", EndpointID: "endpoint", AdapterID: "adapter", Value: []byte("a1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "batch-a", EndpointID: "endpoint", AdapterID: "adapter", ExpectedVersion: 1, Value: []byte("a2")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "batch-b", EndpointID: "endpoint", AdapterID: "adapter", Value: []byte("b1")}); err != nil {
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
	if len(resolved) != 3 || string(resolved[0].Value) != "b1" || string(resolved[1].Value) != "a1" || string(resolved[2].Value) != "a2" {
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

func TestPluginKVExactAndPrefixIsolation(t *testing.T) {
	store, db := openPlainTestStore(t)
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
	store, db := openPlainTestStore(t)
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
	store, db := openPlainTestStore(t)
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

func TestSecretVersionOverflowFailsBeforeMutation(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	now := time.Now().UTC()
	row := adapterSecretRow{
		SecretRef: "overflow-secret", SecretVersion: ^uint64(0) >> 1, EndpointID: "endpoint", AdapterID: "adapter",
		AdapterType: "opaque", Value: []byte{1}, RowVersion: ^uint64(0) >> 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), UnitOfWork{SecretUpdates: []SecretUpdate{{SecretRef: row.SecretRef, ExpectedVersion: row.RowVersion, Value: []byte("next")}}}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("UoW secret version overflow err=%v", err)
	}
	if _, err := store.PutSecret(context.Background(), SecretPutRequest{SecretRef: row.SecretRef, EndpointID: row.EndpointID, AdapterID: row.AdapterID, Value: []byte("value")}); !errors.Is(err, ErrVersionExhausted) {
		t.Fatalf("public secret version overflow err=%v", err)
	}
}
