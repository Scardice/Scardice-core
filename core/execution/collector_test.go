package execution

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"Scardice-core/eventstore"
)

func TestCollectorCommitsDistinctEmptyAndWhitespacePluginKeys(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "plugin-keys.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database)
	collector := NewMutationCollector(eventstore.EventFactory{})
	values := map[string][]byte{"": []byte("empty-key"), " ": {}}
	for key, value := range values {
		if err := collector.AddUnitOfWork(eventstore.UnitOfWork{
			PluginKVUpdates: []eventstore.PluginKVUpdate{{
				ExtensionID: "plugin", Key: key, Value: value,
			}},
		}); err != nil {
			t.Fatalf("collect opaque key %q: %v", key, err)
		}
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatal(err)
	}
	for key, want := range values {
		item, err := store.GetPluginKV(ctx, "plugin", key)
		if err != nil || item.Key != key || !bytes.Equal(item.Value, want) {
			t.Fatalf("opaque key %q: item=%+v err=%v", key, item, err)
		}
	}
}

func TestCollectorKeepsUnambiguousPluginNamespaceAndKeyPairs(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "plugin-pairs.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database)
	collector := NewMutationCollector(eventstore.EventFactory{})
	updates := []eventstore.PluginKVUpdate{
		{ExtensionID: "plugin", Key: "\x00key", Value: []byte("first")},
		{ExtensionID: "plugin\x00", Key: "key", Value: []byte("second")},
	}
	for _, update := range updates {
		if err := collector.AddUnitOfWork(eventstore.UnitOfWork{PluginKVUpdates: []eventstore.PluginKVUpdate{update}}); err != nil {
			t.Fatalf("collect opaque pair %q/%q: %v", update.ExtensionID, update.Key, err)
		}
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatal(err)
	}
	for _, update := range updates {
		item, err := store.GetPluginKV(ctx, update.ExtensionID, update.Key)
		if err != nil || !bytes.Equal(item.Value, update.Value) {
			t.Fatalf("opaque pair lost its distinct value: namespace=%q key=%q item=%+v err=%v", update.ExtensionID, update.Key, item, err)
		}
	}
}
