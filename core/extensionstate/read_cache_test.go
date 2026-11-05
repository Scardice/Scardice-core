package extensionstate

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"Scardice-core/eventstore"
)

// payloadReadCounter counts the reads that fetch the projection payload.
type payloadReadCounter struct {
	*eventstore.GORMStore
	rows atomic.Int64
}

func (s *payloadReadCounter) ReadProjectionRowStamped(ctx context.Context, name, key string, stream eventstore.StreamID) (eventstore.ProjectionRow, eventstore.ProjectionStamp, error) {
	s.rows.Add(1)
	return s.GORMStore.ReadProjectionRowStamped(ctx, name, key, stream)
}

func openGORMExtensionStore(t *testing.T, name string) *eventstore.GORMStore {
	t.Helper()
	store, ok := openExtensionStore(t, name).(*eventstore.GORMStore)
	if !ok {
		t.Fatal("extension test store is not a GORMStore")
	}
	return store
}

func TestReadCacheServesRepeatedReadsWithoutFetchingThePayload(t *testing.T) {
	ctx := context.Background()
	store := &payloadReadCounter{GORMStore: openGORMExtensionStore(t, "hits")}
	repo := NewRepository(store)
	for i := range 3 {
		discover(t, repo, fmt.Sprintf("plugin-%02d", i))
	}
	cache := NewReadCache()
	first, err := cache.ReadShared(ctx, store, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	fetched := store.rows.Load()
	for range 50 {
		again, err := cache.ReadShared(ctx, store, "dice-1")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again, first) {
			t.Fatalf("cached read differs from the first read")
		}
	}
	if got := store.rows.Load(); got != fetched {
		t.Fatalf("payload fetched %d more times while the stream was unchanged", got-fetched)
	}
}

func TestReadCacheSeesEveryCommittedChange(t *testing.T) {
	ctx := context.Background()
	store := &payloadReadCounter{GORMStore: openGORMExtensionStore(t, "fresh")}
	repo := NewRepository(store)
	cache := NewReadCache()
	for i := range 6 {
		id := fmt.Sprintf("plugin-%02d", i)
		discover(t, repo, id)
		got, err := cache.ReadShared(ctx, store, "dice-1")
		if err != nil {
			t.Fatal(err)
		}
		want, err := ReadProjected(ctx, store, "dice-1")
		if err != nil {
			t.Fatal(err)
		}
		if _, known := got.Extensions[id]; !known || !reflect.DeepEqual(got, want) {
			t.Fatalf("after committing %s the cached read is stale: have %d extensions, want %d", id, len(got.Extensions), len(want.Extensions))
		}
	}
}

// A store that cannot stamp its projections still reads correctly, just
// without caching.
func TestReadCacheFallsBackForStoresWithoutStamps(t *testing.T) {
	ctx := context.Background()
	inner := openGORMExtensionStore(t, "plain")
	discover(t, NewRepository(inner), "plugin-00")
	plain := plainProjectionStore{inner}
	got, err := NewReadCache().ReadShared(ctx, plain, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadProjected(ctx, inner, "dice-1")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback read = %+v, %v; want %+v", got, err, want)
	}
}

type plainProjectionStore struct{ inner *eventstore.GORMStore }

func (s plainProjectionStore) ReadProjectionRow(ctx context.Context, name, key string) (eventstore.ProjectionRow, error) {
	return s.inner.ReadProjectionRow(ctx, name, key)
}

func (s plainProjectionStore) Load(ctx context.Context, stream eventstore.StreamID, after uint64) ([]eventstore.Envelope, error) {
	return s.inner.Load(ctx, stream, after)
}

// Readers keep getting a complete, consistent state while commits land.
func TestReadCacheStaysConsistentUnderConcurrentCommits(t *testing.T) {
	ctx := context.Background()
	store := openGORMExtensionStore(t, "concurrent")
	repo := NewRepository(store)
	cache := NewReadCache()
	const commits = 15
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 60 {
				state, err := cache.ReadShared(ctx, store, "dice-1")
				if err != nil {
					t.Error(err)
					return
				}
				if len(state.Extensions) != len(state.ExtensionOrder) {
					t.Errorf("torn state: %d extensions, %d in order", len(state.Extensions), len(state.ExtensionOrder))
					return
				}
			}
		}()
	}
	for i := range commits {
		discover(t, repo, fmt.Sprintf("plugin-%02d", i))
	}
	wg.Wait()
	final, err := cache.ReadShared(ctx, store, "dice-1")
	if err != nil || len(final.Extensions) != commits {
		t.Fatalf("final read has %d extensions (err=%v), want %d", len(final.Extensions), err, commits)
	}
}
