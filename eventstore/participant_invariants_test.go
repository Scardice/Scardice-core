package eventstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func seedParticipantPluginQuota(t *testing.T, database *Database, extension string, count, totalBytes int) {
	t.Helper()
	valueSize := totalBytes
	if valueSize > MaxPluginValueBytes {
		valueSize = MaxPluginValueBytes
	}
	value := make([]byte, valueSize)
	rows := make([]pluginKVRow, count)
	remaining := totalBytes
	for index := range rows {
		size := remaining
		if size > MaxPluginValueBytes {
			size = MaxPluginValueBytes
		}
		rows[index] = pluginKVRow{
			ExtensionID: extension, Key: fmt.Sprintf("seed/%05d", index), Value: value[:size],
			RowVersion: 1, CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC(),
		}
		remaining -= size
	}
	if remaining != 0 {
		t.Fatalf("invalid quota fixture: %d bytes did not fit", remaining)
	}
	if err := database.GORM().CreateInBatches(&rows, 100).Error; err != nil {
		t.Fatal(err)
	}
}

func participantPluginSnapshot(t *testing.T, store *GORMStore, extension, key string) PluginKVLookupSnapshot {
	t.Helper()
	snapshot, err := store.LookupPluginKVSnapshot(context.Background(), extension, key)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertParticipantPluginSnapshotUnchanged(t *testing.T, store *GORMStore, before PluginKVLookupSnapshot) {
	t.Helper()
	after := participantPluginSnapshot(t, store, before.Namespace, before.Key)
	if after.Found != before.Found || after.KeyRevision != before.KeyRevision || after.NamespaceRevision != before.NamespaceRevision || after.Item.Version != before.Item.Version || !bytes.Equal(after.Item.Value, before.Item.Value) {
		t.Fatalf("rejected participant published plugin state: before=%+v after=%+v", before, after)
	}
}

func TestCommitPluginQuotaBatchCountAndRollback(t *testing.T) {
	store, database := testStore(t)
	defer database.Close()
	ctx := context.Background()
	const extension = "participant-count"
	seedParticipantPluginQuota(t, database, extension, MaxPluginKeys-2, 0)
	{
		first := participantPluginSnapshot(t, store, extension, "batch/1")
		second := participantPluginSnapshot(t, store, extension, "batch/2")
		third := participantPluginSnapshot(t, store, extension, "batch/3")
		_, err := store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
			{ExtensionID: extension, Key: first.Key, Value: []byte("x")},
			{ExtensionID: extension, Key: second.Key, Value: []byte("x")},
			{ExtensionID: extension, Key: third.Key, Value: []byte("x")},
		}})
		if !errors.Is(err, ErrOversizeInput) {
			t.Fatalf("joint batch count exceeded the quota: %v", err)
		}
		assertParticipantPluginSnapshotUnchanged(t, store, first)
		assertParticipantPluginSnapshotUnchanged(t, store, second)
		assertParticipantPluginSnapshotUnchanged(t, store, third)
	}
	// Trailing bytes are part of the key identity, even at the quota boundary.
	if _, err := store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "z-last", Value: []byte("first")},
		{ExtensionID: extension, Key: "z-last ", Value: []byte("second")},
	}}); err != nil {
		t.Fatalf("batch reaching the exact key quota: %v", err)
	}
	before := participantPluginSnapshot(t, store, extension, "z-last")
	absent := participantPluginSnapshot(t, store, extension, "a-overflow")
	catalog, err := store.ReadCatalogRevision(ctx, "participant-quota", "owner")
	if err != nil {
		t.Fatal(err)
	}
	stream := StreamID{AggregateType: "participant-quota", AggregateID: "rejected-count"}
	_, err = store.Commit(ctx, UnitOfWork{
		Streams:        []StreamAppend{{Stream: stream, Events: []NewEvent{testEvent("participant-count-rejected")}}},
		Operations:     []OperationUpdate{{OperationID: "participant-count-rejected"}},
		SecretUpdates:  []SecretUpdate{{SecretRef: "participant-count-rejected", Value: []byte("secret")}},
		CatalogUpdates: []CatalogRevisionUpdate{{Catalog: catalog.Catalog, Owner: catalog.Owner, ExpectedRevision: catalog.Revision}},
		PluginKVUpdates: []PluginKVUpdate{
			{ExtensionID: extension, Key: "a-overflow", Value: []byte("new")},
			{ExtensionID: extension, Key: "z-last", ExpectedVersion: 1, Value: []byte("must roll back")},
		},
	})
	if !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("over-quota Commit error = %v, want ErrOversizeInput", err)
	}
	assertParticipantPluginSnapshotUnchanged(t, store, before)
	assertParticipantPluginSnapshotUnchanged(t, store, absent)
	if snapshot, loadErr := store.LoadStreamSnapshot(ctx, stream, 0); loadErr != nil || snapshot.Version != 0 || len(snapshot.Events) != 0 {
		t.Fatalf("quota failure published a stream: %+v, error=%v", snapshot, loadErr)
	}
	if _, lookupErr := store.GetOperation(ctx, "participant-count-rejected"); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("quota failure published an operation: %v", lookupErr)
	}
	if _, lookupErr := store.ResolveSecret(ctx, "participant-count-rejected", 0); !errors.Is(lookupErr, ErrNotFound) {
		t.Fatalf("quota failure published a secret: %v", lookupErr)
	}
	if after, readErr := store.ReadCatalogRevision(ctx, catalog.Catalog, catalog.Owner); readErr != nil || after.Revision != catalog.Revision {
		t.Fatalf("quota failure advanced catalog revision: %+v, error=%v", after, readErr)
	}
	var sequence eventGlobalSequenceRow
	if err = database.GORM().First(&sequence).Error; err != nil || sequence.NextPosition != 1 {
		t.Fatalf("quota failure advanced event sequence: %+v, error=%v", sequence, err)
	}

	// The new key sorts before the delete. Only the final namespace state is
	// quota-limited, not an arbitrary intermediate state inside the batch.
	if _, err = store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "a-replacement", Value: []byte("new")},
		{ExtensionID: extension, Key: "z-last", ExpectedVersion: 1, Value: []byte("updated")},
		{ExtensionID: extension, Key: "z-last ", ExpectedVersion: 1, Deleted: true},
	}}); err != nil {
		t.Fatalf("batch replacing a key at the count limit: %v", err)
	}
	if _, lookupErr := store.GetPluginKV(ctx, extension, "z-last "); !errors.Is(lookupErr, ErrPluginKVNotFound) {
		t.Fatalf("deleted raw key remains: %v", lookupErr)
	}
	updated := participantPluginSnapshot(t, store, extension, "z-last")
	if !updated.Found || updated.Item.Version != 2 || string(updated.Item.Value) != "updated" {
		t.Fatalf("overwriting at the count limit = %+v", updated)
	}
	replacement := participantPluginSnapshot(t, store, extension, "a-replacement")
	_, err = store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "a-replacement", ExpectedVersion: 1, Value: []byte("must roll back")},
		{ExtensionID: extension, Key: "z-last", ExpectedVersion: 1, Value: []byte("stale")},
	}})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("stale participant CAS error = %v", err)
	}
	assertParticipantPluginSnapshotUnchanged(t, store, replacement)
	assertParticipantPluginSnapshotUnchanged(t, store, updated)
	if _, err = store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: extension, Key: "direct-overflow", Value: []byte("x")}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("direct put exceeded the shared count quota: %v", err)
	}
	if item, putErr := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: extension, Key: "a-replacement", ExpectedVersion: 1, Value: []byte("direct")}); putErr != nil || item.Version != 2 || string(item.Value) != "direct" {
		t.Fatalf("direct overwrite at the count quota = %+v, error=%v", item, putErr)
	}
}

func TestCommitPluginQuotaBatchBytes(t *testing.T) {
	store, database := testStore(t)
	defer database.Close()
	ctx := context.Background()
	const extension = "participant-bytes"
	seedParticipantPluginQuota(t, database, extension, 8, MaxPluginBytes-3)
	{
		first := participantPluginSnapshot(t, store, extension, "batch/1")
		second := participantPluginSnapshot(t, store, extension, "batch/2")
		_, err := store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
			{ExtensionID: extension, Key: first.Key, Value: []byte("ab")},
			{ExtensionID: extension, Key: second.Key, Value: []byte("cd")},
		}})
		if !errors.Is(err, ErrOversizeInput) {
			t.Fatalf("joint batch bytes exceeded the quota: %v", err)
		}
		assertParticipantPluginSnapshotUnchanged(t, store, first)
		assertParticipantPluginSnapshotUnchanged(t, store, second)
	}
	if _, err := store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "quota", Value: []byte("ab")},
		{ExtensionID: extension, Key: "quota ", Value: []byte("c")},
	}}); err != nil {
		t.Fatalf("batch reaching the exact byte quota: %v", err)
	}
	absent := participantPluginSnapshot(t, store, extension, "a-overflow")
	_, err := store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "a-overflow", Value: []byte("d")},
	}})
	if !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("over-byte-quota Commit error = %v, want ErrOversizeInput", err)
	}
	assertParticipantPluginSnapshotUnchanged(t, store, absent)
	if _, err = store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "a-replacement", Value: []byte("four")},
		{ExtensionID: extension, Key: "seed/00007", ExpectedVersion: 1, Value: make([]byte, MaxPluginValueBytes-7)},
	}}); err != nil {
		t.Fatalf("batch reusing overwritten bytes at the quota: %v", err)
	}
	if _, err = store.Commit(ctx, UnitOfWork{PluginKVUpdates: []PluginKVUpdate{
		{ExtensionID: extension, Key: "a-after-delete", Value: []byte("ab")},
		{ExtensionID: extension, Key: "quota", ExpectedVersion: 1, Deleted: true},
	}}); err != nil {
		t.Fatalf("batch reusing deleted bytes at the quota: %v", err)
	}
	item, err := store.GetPluginKV(ctx, extension, "a-after-delete")
	if err != nil || string(item.Value) != "ab" || item.Version != 1 {
		t.Fatalf("replacement after byte reuse = %+v, error=%v", item, err)
	}
	if _, lookupErr := store.GetPluginKV(ctx, extension, "quota"); !errors.Is(lookupErr, ErrPluginKVNotFound) {
		t.Fatalf("deleted byte-quota key remains: %v", lookupErr)
	}
	if _, err = store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: extension, Key: "direct-overflow", Value: []byte("x")}); !errors.Is(err, ErrOversizeInput) {
		t.Fatalf("direct put exceeded the shared byte quota: %v", err)
	}
	if item, putErr := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: extension, Key: "a-after-delete", ExpectedVersion: 1, Value: []byte("cd")}); putErr != nil || item.Version != 2 || string(item.Value) != "cd" {
		t.Fatalf("direct overwrite at the byte quota = %+v, error=%v", item, putErr)
	}
}

func TestCommitPluginQuotaConcurrentRoots(t *testing.T) {
	for _, quota := range []struct {
		name       string
		count      int
		totalBytes int
	}{
		{name: "count", count: MaxPluginKeys - 1},
		{name: "bytes", count: 8, totalBytes: MaxPluginBytes - 1},
	} {
		t.Run(quota.name, func(t *testing.T) {
			left, database := testStore(t)
			defer database.Close()
			right := NewStore(database)
			ctx := context.Background()
			extension := "participant-race-" + quota.name
			seedParticipantPluginQuota(t, database, extension, quota.count, quota.totalBytes)
			stores := []*GORMStore{left, right}
			snapshots := make([]PluginKVLookupSnapshot, len(stores))
			for index, store := range stores {
				snapshots[index] = participantPluginSnapshot(t, store, extension, fmt.Sprintf("writer/%d", index))
			}
			type outcome struct {
				index int
				err   error
			}
			start := make(chan struct{})
			results := make(chan outcome, len(stores))
			for index, store := range stores {
				go func() {
					<-start
					root := fmt.Sprintf("participant-race-%s-%d", quota.name, index)
					snapshot := snapshots[index]
					_, err := store.Commit(ctx, UnitOfWork{
						PluginKVReads: []PluginKVReadExpectation{{Namespace: snapshot.Namespace, Key: snapshot.Key, ExpectedRevision: snapshot.KeyRevision, ExpectedExists: false}},
						Streams:       []StreamAppend{{Stream: StreamID{AggregateType: "participant-root", AggregateID: root}, Events: []NewEvent{testEvent(root)}}},
						Operations:    []OperationUpdate{{OperationID: root}},
						PluginKVUpdates: []PluginKVUpdate{
							{ExtensionID: extension, Key: snapshot.Key, Value: []byte("x")},
						},
					})
					results <- outcome{index: index, err: err}
				}()
			}
			close(start)
			committed, rejected := 0, 0
			for range stores {
				result := <-results
				if result.err == nil {
					committed++
					continue
				}
				if !errors.Is(result.err, ErrOversizeInput) {
					t.Fatalf("competing root error = %v, want ErrOversizeInput", result.err)
				}
				rejected++
				root := fmt.Sprintf("participant-race-%s-%d", quota.name, result.index)
				after := participantPluginSnapshot(t, left, extension, snapshots[result.index].Key)
				if after.Found || after.KeyRevision != 0 {
					t.Fatalf("losing root published a key or revision: %+v", after)
				}
				if stream, err := left.LoadStreamSnapshot(ctx, StreamID{AggregateType: "participant-root", AggregateID: root}, 0); err != nil || stream.Version != 0 || len(stream.Events) != 0 {
					t.Fatalf("losing root published a stream: %+v, error=%v", stream, err)
				}
				if _, err := left.GetOperation(ctx, root); !errors.Is(err, ErrNotFound) {
					t.Fatalf("losing root published an operation: %v", err)
				}
			}
			if committed != 1 || rejected != 1 {
				t.Fatalf("last quota slot admitted %d roots and rejected %d, want 1 each", committed, rejected)
			}
			final := participantPluginSnapshot(t, left, extension, snapshots[0].Key)
			if final.NamespaceRevision != snapshots[0].NamespaceRevision+1 {
				t.Fatalf("losing root advanced namespace revision: before=%d after=%d", snapshots[0].NamespaceRevision, final.NamespaceRevision)
			}
			var sequence eventGlobalSequenceRow
			if err := database.GORM().First(&sequence).Error; err != nil || sequence.NextPosition != 2 {
				t.Fatalf("losing root advanced event sequence: %+v, error=%v", sequence, err)
			}
		})
	}
}

func TestCommitOperationUpdatedAtPreservesContext(t *testing.T) {
	for _, explicit := range []bool{true, false} {
		name := "clock"
		if explicit {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			store, database, clock := openQueueTestStore(t)
			defer database.Close()
			ctx := context.Background()
			created := time.Unix(10, 0).UTC()
			expires := time.Unix(1000, 0).UTC()
			private := []byte{0, 255, 1, 0, 128}
			if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{
				OperationID: "participant-operation", Kind: "action", Status: "running", PrincipalID: "owner",
				ResourceID: "resource", IdempotencyScope: "action", IdempotencyKey: "request-key",
				RequestID: "request", RequestDigest: []byte("digest"), CorrelationID: "correlation",
				PrivateContext: private, CreatedAt: created, UpdatedAt: created, ExpiresAt: expires,
			}}}); err != nil {
				t.Fatal(err)
			}
			clock.Advance(time.Minute)
			updateTime := time.Time{}
			wantTime := time.Unix(160, 0).UTC()
			if explicit {
				updateTime = time.Unix(50, 0).UTC()
				wantTime = updateTime
			}
			if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{
				OperationID: "participant-operation", ExpectedVersion: 1, Status: "succeeded", ResultCode: "ok", UpdatedAt: updateTime,
			}}}); err != nil {
				t.Fatal(err)
			}
			view, err := store.GetOperation(ctx, "participant-operation")
			if err != nil {
				t.Fatal(err)
			}
			if view.Version != 2 || view.Status != "succeeded" || view.ResultCode != "ok" || !view.UpdatedAt.Equal(wantTime) {
				t.Fatalf("consumer operation update = %+v, want updatedAt=%s", view, wantTime)
			}
			if !view.CreatedAt.Equal(created) || !view.ExpiresAt.Equal(expires) || view.Kind != "action" || view.PrincipalID != "owner" || view.ResourceID != "resource" || view.IdempotencyScope != "action" || view.IdempotencyKey != "request-key" || view.RequestID != "request" || string(view.RequestDigest) != "digest" || view.CorrelationID != "correlation" {
				t.Fatalf("sparse update lost operation metadata: %+v", view)
			}
			var row operationRow
			if err = database.GORM().Where("operation_id = ?", "participant-operation").First(&row).Error; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(row.PrivateContext, private) {
				t.Fatalf("sparse update changed private context: %v", row.PrivateContext)
			}
		})
	}
}
