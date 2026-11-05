package dice

import (
	"context"
	"errors"
	"strings"
	"testing"

	"Scardice-core/eventstore"
)

func TestPluginQuotaTransactionAllowsSmallPutAfterMaximumValue(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	ctx := context.Background()
	const extension = "quota-maximum-value"
	value := strings.Repeat("a", 8<<20)
	withCanonicalTestRoot(t, d, "maximum-value", func(transaction *DurableCallbackTransaction) error {
		return transaction.StorageSet(ctx, extension, "large", value)
	})
	withCanonicalTestRoot(t, d, "small-value-after-maximum", func(transaction *DurableCallbackTransaction) error {
		return transaction.StorageSet(ctx, extension, "small", "x")
	})
	item, err := store.GetPluginKV(ctx, extension, "small")
	if err != nil || string(item.Value) != "x" || item.Version != 1 {
		t.Fatalf("small key after maximum value: bytes=%d version=%d err=%v", len(item.Value), item.Version, err)
	}
	item, err = store.GetPluginKV(ctx, extension, "large")
	if err != nil || string(item.Value) != value || item.Version != 1 {
		t.Fatalf("existing maximum value changed: bytes=%d version=%d err=%v", len(item.Value), item.Version, err)
	}
}

func TestPluginQuotaTransactionAllowsLargeBatchAndLaterRoot(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	ctx := context.Background()
	const extension = "quota-large-batch"
	value := strings.Repeat("b", 5<<20)
	withCanonicalTestRoot(t, d, "two-large-values", func(transaction *DurableCallbackTransaction) error {
		if err := transaction.StorageSet(ctx, extension, "first", value); err != nil {
			return err
		}
		return transaction.StorageSet(ctx, extension, "second", value)
	})
	withCanonicalTestRoot(t, d, "small-value-after-large-batch", func(transaction *DurableCallbackTransaction) error {
		return transaction.StorageSet(ctx, extension, "later", "x")
	})
	for _, key := range []string{"first", "second"} {
		item, err := store.GetPluginKV(ctx, extension, key)
		if err != nil || string(item.Value) != value || item.Version != 1 {
			t.Fatalf("large batch key %q: bytes=%d version=%d err=%v", key, len(item.Value), item.Version, err)
		}
	}
	item, err := store.GetPluginKV(ctx, extension, "later")
	if err != nil || string(item.Value) != "x" || item.Version != 1 {
		t.Fatalf("later root key: bytes=%d version=%d err=%v", len(item.Value), item.Version, err)
	}
}

func TestPluginQuotaTransactionListObservationConflictsOnNamespaceChange(t *testing.T) {
	for _, test := range []struct {
		name       string
		stageFirst bool
	}{
		{name: "list-before-put"},
		{name: "list-after-put", stageFirst: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, store := newCanonicalTestDice(t)
			ctx := context.Background()
			const extension = "quota-observed-list"
			withCanonicalTestRoot(t, d, "seed-list", func(transaction *DurableCallbackTransaction) error {
				return transaction.StorageSet(ctx, extension, "existing", "original")
			})
			root := newCanonicalTestRoot(t, d, "observe-list")
			transaction := root.Transaction
			if test.stageFirst {
				if err := transaction.StorageSet(ctx, extension, "local", "must-roll-back"); err != nil {
					t.Fatal(err)
				}
			}
			keys, err := transaction.StorageList(ctx, extension)
			if err != nil || len(keys) == 0 || keys[0] != "existing" {
				t.Fatalf("observed list = %q, err=%v", keys, err)
			}
			if test.stageFirst {
				if len(keys) != 2 || keys[1] != "local" {
					t.Fatalf("list did not include the same-root put: %q", keys)
				}
			} else {
				if len(keys) != 1 {
					t.Fatalf("initial list = %q, want only existing", keys)
				}
				if err = transaction.StorageSet(ctx, extension, "local", "must-roll-back"); err != nil {
					t.Fatal(err)
				}
			}
			withCanonicalTestRoot(t, d, "concurrent-namespace-write", func(writer *DurableCallbackTransaction) error {
				return writer.StorageSet(ctx, extension, "concurrent", "committed")
			})
			keys, err = transaction.StorageList(ctx, extension)
			if err != nil || len(keys) != 2 || keys[0] != "existing" || keys[1] != "local" {
				t.Fatalf("same-root list lost its snapshot or overlay: keys=%q err=%v", keys, err)
			}
			if err = transaction.Finalize(ctx); err != nil {
				t.Fatal(err)
			}
			work, err := root.Collector.UnitOfWork()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.Commit(ctx, work); !errors.Is(err, eventstore.ErrParticipantConflict) {
				t.Fatalf("changed observed namespace committed: %v", err)
			}
			if _, err = store.GetPluginKV(ctx, extension, "local"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
				t.Fatalf("conflicting list consumer published its put: %v", err)
			}
			item, err := store.GetPluginKV(ctx, extension, "concurrent")
			if err != nil || string(item.Value) != "committed" {
				t.Fatalf("independent namespace writer: value=%q err=%v", item.Value, err)
			}
		})
	}
}
