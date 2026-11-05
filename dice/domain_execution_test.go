package dice

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/core/groupstate"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

func newDomainExecutionFixture(t *testing.T) (*Dice, *eventstore.GORMStore) {
	t.Helper()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "executions.db"),
		DatabaseIdentity: "domain-execution-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	options := projectionset.StoreOptions()
	store := eventstore.NewStore(db, options...)
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "domain-execution-test",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	instance := &Dice{BaseConfig: BaseConfig{Name: "root-dice"}, DurableStore: store}
	seedCanonicalTestConfigBaseline(t, instance)
	return instance, store
}

func TestDomainExecutionConcurrentIdentityRunsHostOnce(t *testing.T) {
	instance, store := newDomainExecutionFixture(t)
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	var calls atomic.Int32
	run := func(transaction *DurableCallbackTransaction) error {
		calls.Add(1)
		group, err := transaction.Domain().Group(ctx, instance.BaseConfig.Name, "QQ-Group:root")
		if err != nil {
			return err
		}
		if err = group.Decide(groupstate.Command{Kind: groupstate.CommandCreate, DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:root", GroupName: "committed"}); err != nil {
			return err
		}
		close(entered)
		<-release
		return nil
	}
	go func() { finished <- instance.WithDomainExecution(ctx, "root-concurrent", []byte("same-request"), run) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first root did not enter Host")
	}
	duplicateErr := instance.WithDomainExecution(ctx, "root-concurrent", []byte("same-request"), run)
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(duplicateErr, ErrDomainExecutionInProgress) {
		t.Fatalf("duplicate root error = %v", duplicateErr)
	}
	if err := instance.WithDomainExecution(ctx, "root-concurrent", []byte("same-request"), run); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("Host executions = %d, want 1", calls.Load())
	}
	state, err := groupstate.ReadProjected(ctx, store, instance.BaseConfig.Name, "QQ-Group:root")
	if err != nil || state.GroupName != "committed" || state.Version != 1 {
		t.Fatalf("committed group = %#v, err=%v", state, err)
	}
	receipt, err := store.LookupExecution(ctx, "root-concurrent")
	if err != nil || receipt.Status != eventstore.ExecutionStatusCommitted {
		t.Fatalf("receipt = %#v, err=%v", receipt, err)
	}
}

func TestDomainExecutionFailureDoesNotPublishAndCannotReenter(t *testing.T) {
	instance, store := newDomainExecutionFixture(t)
	ctx := context.Background()
	failure := errors.New("consumer rejected execution")
	err := instance.WithDomainExecution(ctx, "root-failed", []byte("create-then-fail"), func(transaction *DurableCallbackTransaction) error {
		group, loadErr := transaction.Domain().Group(ctx, instance.BaseConfig.Name, "QQ-Group:failed")
		if loadErr != nil {
			return loadErr
		}
		if decideErr := group.Decide(groupstate.Command{Kind: groupstate.CommandCreate, DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:failed", GroupName: "must-not-persist"}); decideErr != nil {
			return decideErr
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("execution error = %v", err)
	}
	if _, loadErr := groupstate.ReadProjected(ctx, store, instance.BaseConfig.Name, "QQ-Group:failed"); !errors.Is(loadErr, eventstore.ErrNotFound) {
		t.Fatalf("failed group load = %v", loadErr)
	}
	receipt, err := store.LookupExecution(ctx, "root-failed")
	if err != nil || receipt.Status != eventstore.ExecutionStatusAmbiguous {
		t.Fatalf("failed receipt = %#v, err=%v", receipt, err)
	}
	calledAgain := false
	err = instance.WithDomainExecution(ctx, "root-failed", []byte("create-then-fail"), func(*DurableCallbackTransaction) error { calledAgain = true; return nil })
	if !errors.Is(err, ErrDomainExecutionAmbiguous) || calledAgain {
		t.Fatalf("failed root reentered=%v, error=%v", calledAgain, err)
	}
}
