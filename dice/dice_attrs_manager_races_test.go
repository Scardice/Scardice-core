package dice

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

type countingAttributeStore struct {
	*eventstore.GORMStore
	mu           sync.Mutex
	prepareCount int
}

func (s *countingAttributeStore) PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error) {
	s.mu.Lock()
	s.prepareCount++
	s.mu.Unlock()
	return s.GORMStore.PrepareSecretUpdate(ctx, request)
}

func (s *countingAttributeStore) preparations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prepareCount
}

func newAttributeExecutionFixture(t *testing.T) (*AttrsManager, *countingAttributeStore) {
	t.Helper()
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "attributes.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	base := eventstore.NewStore(database, eventstore.WithProjection(attributestate.Projection()))
	if err = base.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "attribute-execution-test",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	store := &countingAttributeStore{GORMStore: base}
	manager := &AttrsManager{}
	if err = manager.InitDurable(&Dice{BaseConfig: BaseConfig{Name: "dice-attributes"}, DurableStore: store}); err != nil {
		t.Fatal(err)
	}
	return manager, store
}

var attributeCommandSequence atomic.Uint64

func newAttributeTransaction(t *testing.T, store eventstore.Store) (*DurableCallbackTransaction, *execution.MutationCollector) {
	t.Helper()
	sequence := attributeCommandSequence.Add(1)
	metadata := eventstore.Metadata{
		CommandID:     "attribute-command-" + strconv.FormatUint(sequence, 10),
		CorrelationID: "attribute-correlation-" + strconv.FormatUint(sequence, 10),
		Producer:      "dice/attribute-test", OccurredAt: time.Unix(int64(sequence)+100, 0).UTC(),
	}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(context.Background(), store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return transaction, collector
}

func commitAttributeTransaction(t *testing.T, store eventstore.Store, transaction *DurableCallbackTransaction, collector *execution.MutationCollector) error {
	t.Helper()
	if err := transaction.Finalize(context.Background()); err != nil {
		return err
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		return err
	}
	_, err = store.Commit(context.Background(), work)
	return err
}

func TestAttributeNestedMutationPersistsOneSnapshot(t *testing.T) {
	manager, store := newAttributeExecutionFixture(t)
	transaction, collector := newAttributeTransaction(t, store)
	item, err := manager.LoadByTransaction(context.Background(), transaction, "QQ-Group:10-QQ:20")
	if err != nil {
		t.Fatal(err)
	}
	nested := &ds.ValueMap{}
	nested.Store("hp", ds.NewIntVal(10))
	if err = item.Store("stats", ds.NewDictVal(nested).V()); err != nil {
		t.Fatal(err)
	}
	exposed := item.Load("stats")
	dict, ok := exposed.ReadDictData()
	if !ok {
		t.Fatal("stored stats is not a dictionary")
	}
	dict.Dict.Store("hp", ds.NewIntVal(17))
	if err = commitAttributeTransaction(t, store, transaction, collector); err != nil {
		t.Fatal(err)
	}
	if got := store.preparations(); got != 1 {
		t.Fatalf("secret preparations = %d, want exactly one", got)
	}

	readTransaction, _ := newAttributeTransaction(t, store)
	persisted, err := manager.LoadByTransaction(context.Background(), readTransaction, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	persistedDict, ok := persisted.Load("stats").ReadDictData()
	if !ok {
		t.Fatal("persisted stats is not a dictionary")
	}
	hp, ok := persistedDict.Dict.Load("hp")
	if !ok || hp.MustReadInt() != 17 {
		t.Fatalf("persisted nested hp = %v, exists=%v; want 17", hp, ok)
	}
	readTransaction.Abort()
}

func TestAbortedAttributeRootCannotSaveLater(t *testing.T) {
	manager, store := newAttributeExecutionFixture(t)
	transaction, _ := newAttributeTransaction(t, store)
	item, err := manager.LoadByTransaction(context.Background(), transaction, "QQ-Group:30-QQ:40")
	if err != nil {
		t.Fatal(err)
	}
	if err = item.Store("discarded", ds.NewIntVal(1)); err != nil {
		t.Fatal(err)
	}
	transaction.Abort()
	if err = item.Store("late", ds.NewIntVal(2)); !errors.Is(err, execution.ErrDomainTxAborted) {
		t.Fatalf("late mutation error = %v, want domain aborted", err)
	}
	if store.preparations() != 0 {
		t.Fatal("aborted root prepared a secret")
	}

	fresh, collector := newAttributeTransaction(t, store)
	freshItem, err := manager.LoadByTransaction(context.Background(), fresh, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if freshItem.Load("discarded") != nil || freshItem.Load("late") != nil {
		t.Fatal("aborted values leaked into a fresh root")
	}
	if err = freshItem.Store("kept", ds.NewIntVal(3)); err != nil {
		t.Fatal(err)
	}
	if err = commitAttributeTransaction(t, store, fresh, collector); err != nil {
		t.Fatal(err)
	}
	if store.preparations() != 1 {
		t.Fatalf("secret preparations after fresh commit = %d, want 1", store.preparations())
	}
}

func TestBoundCardWriteConflictsWhenBindingRedirects(t *testing.T) {
	manager, store := newAttributeExecutionFixture(t)
	const userID = "QQ:200"
	const groupID = "QQ-Group:100"

	seed, seedCollector := newAttributeTransaction(t, store)
	cardB, err := manager.CharNewForTransaction(context.Background(), seed, userID, "B", "coc7")
	if err != nil {
		t.Fatal(err)
	}
	cardC, err := manager.CharNewForTransaction(context.Background(), seed, userID, "C", "coc7")
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.CharBindForTransaction(context.Background(), seed, cardB.Id, groupID, userID); err != nil {
		t.Fatal(err)
	}
	if err = commitAttributeTransaction(t, store, seed, seedCollector); err != nil {
		t.Fatal(err)
	}

	writer, writerCollector := newAttributeTransaction(t, store)
	bound, err := manager.LoadForTransaction(context.Background(), writer, groupID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if bound.ID != cardB.Id {
		t.Fatalf("bound card = %q, want %q", bound.ID, cardB.Id)
	}
	if err = bound.Store("hp", ds.NewIntVal(9)); err != nil {
		t.Fatal(err)
	}

	redirect, redirectCollector := newAttributeTransaction(t, store)
	if err = manager.CharBindForTransaction(context.Background(), redirect, cardC.Id, groupID, userID); err != nil {
		t.Fatal(err)
	}
	if err = commitAttributeTransaction(t, store, redirect, redirectCollector); err != nil {
		t.Fatal(err)
	}

	// The binding record is a read dependency of the stale writer; its stream
	// version moved, so the commit fails as a stream conflict on that record.
	err = commitAttributeTransaction(t, store, writer, writerCollector)
	var conflict *eventstore.ConflictError
	if !errors.Is(err, eventstore.ErrConflict) || !errors.As(err, &conflict) {
		t.Fatalf("stale bound-card commit error = %v, want stream conflict", err)
	}
	if len(conflict.Conflicts) != 1 || !strings.HasSuffix(conflict.Conflicts[0].Stream.AggregateID, groupID+"-"+userID) ||
		conflict.Conflicts[0].CurrentVersion <= conflict.Conflicts[0].ExpectedVersion {
		t.Fatalf("stale bound-card conflict = %+v, want the redirected binding stream", conflict.Conflicts)
	}
	check, _ := newAttributeTransaction(t, store)
	persisted, err := manager.LoadByTransaction(context.Background(), check, cardB.Id)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Load("hp") != nil {
		t.Fatal("stale bound-card value committed after binding redirect")
	}
	check.Abort()
}

func TestCharacterCatalogReadConflictsWithConcurrentCreate(t *testing.T) {
	manager, store := newAttributeExecutionFixture(t)
	const userID = "QQ:catalog-owner"

	reader, readerCollector := newAttributeTransaction(t, store)
	characters, err := manager.GetCharacterListForTransaction(context.Background(), reader, userID)
	if err != nil || len(characters) != 0 {
		t.Fatalf("initial character list = %#v, err=%v", characters, err)
	}
	// Read dependencies are held only together with writes; an unrelated
	// attribute write gives the reader a commit to protect.
	unrelated, err := manager.LoadByTransaction(context.Background(), reader, "QQ-Group:catalog-reader-QQ:catalog-reader")
	if err != nil {
		t.Fatal(err)
	}
	if err = unrelated.Store("seen", ds.NewIntVal(1)); err != nil {
		t.Fatal(err)
	}
	creator, creatorCollector := newAttributeTransaction(t, store)
	if _, err = manager.CharNewForTransaction(context.Background(), creator, userID, "new", "coc7"); err != nil {
		t.Fatal(err)
	}
	if err = commitAttributeTransaction(t, store, creator, creatorCollector); err != nil {
		t.Fatal(err)
	}
	if err = commitAttributeTransaction(t, store, reader, readerCollector); !errors.Is(err, eventstore.ErrParticipantConflict) {
		t.Fatalf("stale catalog commit error = %v, want participant conflict", err)
	}

	fresh, _ := newAttributeTransaction(t, store)
	characters, err = manager.GetCharacterListForTransaction(context.Background(), fresh, userID)
	if err != nil || len(characters) != 1 || characters[0].Name != "new" {
		t.Fatalf("fresh character list = %#v, err=%v", characters, err)
	}
	fresh.Abort()
}
