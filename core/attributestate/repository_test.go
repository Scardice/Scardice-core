package attributestate

import (
	"context"
	"fmt"
	"testing"

	"Scardice-core/eventstore"
)

type batchSecretStore struct {
	eventstore.Store
	calls []int
}

func (*batchSecretStore) PrepareSecretUpdate(context.Context, eventstore.SecretPutRequest) (eventstore.SecretUpdate, error) {
	return eventstore.SecretUpdate{}, nil
}

func (*batchSecretStore) ResolveSecret(context.Context, string, uint64) (eventstore.SecretResolution, error) {
	return eventstore.SecretResolution{}, eventstore.ErrNotFound
}

func (store *batchSecretStore) ResolveSecrets(_ context.Context, lookups []eventstore.SecretLookup) ([]eventstore.SecretResolution, error) {
	store.calls = append(store.calls, len(lookups))
	resolved := make([]eventstore.SecretResolution, len(lookups))
	for index, lookup := range lookups {
		resolved[index] = eventstore.SecretResolution{
			SecretRef: lookup.SecretRef, SecretVersion: lookup.SecretVersion, Plaintext: []byte("{}"),
		}
	}
	return resolved, nil
}

func TestLoadBatchPagesBeyondResolverLimit(t *testing.T) {
	const count = 100001
	states := make([]State, count)
	for index := range states {
		states[index] = State{
			Version: 1, SecretVersion: 1, DiceID: "dice",
			ID: fmt.Sprintf("attrs-%d", index), SecretRef: fmt.Sprintf("vault:attrs-%d", index),
		}
	}
	store := &batchSecretStore{}
	repository, err := NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.LoadBatch(context.Background(), states)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for index := range loaded {
			clear(loaded[index].Plaintext)
		}
	}()
	if len(loaded) != count {
		t.Fatalf("loaded states = %d, want %d", len(loaded), count)
	}
	if len(store.calls) != 2 || store.calls[0] != 100000 || store.calls[1] != 1 {
		t.Fatalf("resolver batch sizes = %v, want [100000 1]", store.calls)
	}
}
