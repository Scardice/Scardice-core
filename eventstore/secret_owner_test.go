package eventstore

import (
	"context"
	"errors"
	"testing"
)

func TestResolveSecretForOwnerRejectsCrossEndpointReferences(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()

	if _, err := store.PutSecret(ctx, SecretPutRequest{
		SecretRef: "shared-ref", EndpointID: "endpoint-a", AdapterID: "adapter-a", Plaintext: []byte("secret-a"),
	}); err != nil {
		t.Fatal(err)
	}

	resolved, err := store.ResolveSecretForOwner(ctx, "endpoint-a", "adapter-a", "shared-ref", 1)
	if err != nil || string(resolved.Plaintext) != "secret-a" {
		t.Fatalf("owner resolution = %#v, %v", resolved, err)
	}

	for _, owner := range []struct {
		endpoint string
		adapter  string
	}{
		{endpoint: "endpoint-b", adapter: "adapter-a"},
		{endpoint: "endpoint-a", adapter: "adapter-b"},
	} {
		if _, err := store.ResolveSecretForOwner(ctx, owner.endpoint, owner.adapter, "shared-ref", 1); !errors.Is(err, ErrNotFound) {
			t.Errorf("owner %q/%q resolved another endpoint's secret: %v", owner.endpoint, owner.adapter, err)
		}
	}
}
