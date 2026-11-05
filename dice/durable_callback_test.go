package dice

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

type countingDomainParticipant struct{ calls atomic.Int32 }

func (p *countingDomainParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	p.calls.Add(1)
	return eventstore.UnitOfWork{}, nil
}

func TestDurableCallbackFinalizeSealsExactlyOnce(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	root := newCanonicalTestRoot(t, d, "finalize-once")
	transaction := root.Transaction
	key := execution.ParticipantKey{Kind: "test-participant", ID: "one"}
	participant := &countingDomainParticipant{}
	if _, err := transaction.Domain().Owner(context.Background(), key, func(context.Context) (execution.Participant, execution.ReadDependencies, error) {
		return participant, execution.ReadDependencies{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Finalize(context.Background()); !errors.Is(err, execution.ErrDomainTxClosed) {
		t.Fatalf("second finalize error = %v, want domain closed", err)
	}
	if got := participant.calls.Load(); got != 1 {
		t.Fatalf("participant contributions = %d, want 1", got)
	}
}

func TestDurableCallbackPluginStorageUsesOneCanonicalParticipant(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	root := newCanonicalTestRoot(t, d, "plugin-storage")
	transaction, collector := root.Transaction, root.Collector
	if err := transaction.StorageSet(context.Background(), "test-extension", "key", "first"); err != nil {
		t.Fatal(err)
	}
	if err := transaction.StorageSet(context.Background(), "test-extension", "key", "last"); err != nil {
		t.Fatal(err)
	}
	value, err := transaction.StorageGet(context.Background(), "test-extension", "key")
	if err != nil || value != "last" {
		t.Fatalf("transaction storage value = %q, err=%v", value, err)
	}
	if err = transaction.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.PluginKVUpdates) != 1 {
		t.Fatalf("plugin updates = %d, want one final update", len(work.PluginKVUpdates))
	}
	if _, err = store.Commit(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	if err = transaction.StorageSet(context.Background(), "test-extension", "late", "value"); !errors.Is(err, execution.ErrDomainTxClosed) {
		t.Fatalf("post-seal storage error = %v, want domain closed", err)
	}

	deletingRoot := newCanonicalTestRoot(t, d, "plugin-storage-delete")
	deleting, deletingCollector := deletingRoot.Transaction, deletingRoot.Collector
	value, err = deleting.StorageGet(context.Background(), "test-extension", "key")
	if err != nil || value != "last" {
		t.Fatalf("persisted storage value = %q, err=%v", value, err)
	}
	if err = deleting.StorageDelete(context.Background(), "test-extension", "key"); err != nil {
		t.Fatal(err)
	}
	if err = deleting.StorageDelete(context.Background(), "test-extension", "missing"); err != nil {
		t.Fatalf("deleting missing key: %v", err)
	}
	value, err = deleting.StorageGet(context.Background(), "test-extension", "key")
	if err != nil || value != "" {
		t.Fatalf("deleted transaction value = %q, err=%v", value, err)
	}
	if err = deleting.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	deleteWork, err := deletingCollector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(context.Background(), deleteWork); err != nil {
		t.Fatal(err)
	}
	verification := newCanonicalTestRoot(t, d, "plugin-storage-delete-verification")
	value, err = verification.Transaction.StorageGet(context.Background(), "test-extension", "key")
	if err != nil || value != "" {
		t.Fatalf("persisted deleted storage value = %q, err=%v", value, err)
	}
}

func TestDurableCallbackLogAndAfterCommitContribution(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	root := newCanonicalTestRoot(t, d, "story-log-state")
	transaction, collector := root.Transaction, root.Collector
	session, err := store.CreateStoryLog(context.Background(), d.BaseConfig.Name, "QQ-Group:1", "campaign")
	if err != nil {
		t.Fatal(err)
	}
	state := eventstore.StoryLogState{
		DiceID: d.BaseConfig.Name, GroupID: "QQ-Group:1",
		SessionID: session.ID, Name: "campaign", On: true, BaselineSeq: 42,
	}
	if err := transaction.SetStoryLogState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if !transaction.HasStoryLogStateUpdate(state.DiceID, state.GroupID) {
		t.Fatal("staged story log state was not visible")
	}
	visible, err := transaction.ReadStoryLogState(context.Background(), state.DiceID, state.GroupID)
	if err != nil || visible != state {
		t.Fatalf("read-your-writes story state = %#v, err=%v", visible, err)
	}
	called := false
	if err = transaction.AfterCommit(func() { called = true }); err != nil {
		t.Fatal(err)
	}
	if err = transaction.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.LogUpdates) != 1 || len(transaction.callbackAfterCommit) != 1 || called {
		t.Fatalf("log/after-commit staging = logs:%d callbacks:%d called:%v", len(work.LogUpdates), len(transaction.callbackAfterCommit), called)
	}
	if _, err = store.Commit(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	for _, afterCommit := range transaction.callbackAfterCommit {
		afterCommit()
	}
	persisted, err := store.GetStoryLogState(context.Background(), state.DiceID, state.GroupID)
	if err != nil || persisted != state || !called {
		t.Fatalf("committed story state = %#v, callback=%v, err=%v", persisted, called, err)
	}
	if err = transaction.AfterCommit(func() {}); !errors.Is(err, execution.ErrDomainTxClosed) {
		t.Fatalf("post-seal AfterCommit error = %v, want domain closed", err)
	}
}
