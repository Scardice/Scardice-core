package dice

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
	"Scardice-core/utils/jsengine/native"
)

func requireNativeQuickJSRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	if root == "" {
		root = os.Getenv("SCARDICE_RUNTIME_ROOT")
	}
	if root == "" {
		t.Skip("native QuickJS package is not configured")
	}
	return root
}

func callbackQuickJSLoop(t *testing.T) jsengine.Loop {
	t.Helper()
	root := requireNativeQuickJSRoot(t)
	candidates, err := native.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("QuickJS candidates=%d", len(candidates))
	}
	provider, err := candidates[0].Load()
	if err != nil {
		t.Fatal(err)
	}
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = loop.Close() })
	return loop
}

func TestNativeExpiredMessageTimerCannotSendOrPersist(t *testing.T) {
	testExpiredMessageTimerCannotSendOrPersist(t, callbackQuickJSLoop(t))
}

func TestConcurrentGojaQuickJSCallbacksKeepTransactionsIsolated(t *testing.T) {
	nativeLoop := callbackQuickJSLoop(t)
	gojaLoop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	d, store := newCanonicalTestDice(t)
	manager := NewJsLoopManager()
	d.ExtLoopManager = manager
	d.Logger = zap.NewNop().Sugar()
	loops := []jsengine.Loop{gojaLoop, nativeLoop}
	messages := make([]*MsgContext, 2)
	collectors := make([]*execution.MutationCollector, 2)
	arrived := make(chan string, 2)
	release := make(chan struct{})
	returned := make(chan error, 2)
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	for i, loop := range loops {
		generation := manager.AddLoop(loop)
		ext := &ExtInfo{Name: string(loop.Engine()), dice: d, IsJsExt: true, JSLoopVersion: generation}
		metadata := eventstore.Metadata{CommandID: ext.Name, CorrelationID: ext.Name}
		collectors[i] = execution.NewMutationCollector(eventstore.EventFactory{})
		tx, err := NewDurableCallbackTransaction(context.Background(), store, collectors[i], metadata)
		if err != nil {
			t.Fatal(err)
		}
		messages[i] = &MsgContext{
			Dice: d, callbackTransaction: tx, callbackMetadata: metadata,
			executionContext: tx.executionContext,
		}
		if err := loop.Run(func(rt jsengine.Runtime) error {
			if vm, ok := gojaengine.Raw(rt); ok {
				vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
			}
			if err := rt.Bind("extension", newJSExtensionResource(ext, loop)); err != nil {
				return err
			}
			return rt.Bind("barrier", func() { arrived <- ext.Name; <-release })
		}); err != nil {
			t.Fatal(err)
		}
		go func(loop jsengine.Loop, ext *ExtInfo, msg *MsgContext) {
			returned <- jsengine.RunWithContext(loop, jsContextForMessage(ext, msg), func(rt jsengine.Runtime) error {
				_, err := rt.RunString("transaction.js", `extension.storageSet("key", "staged"); barrier(); if (extension.storageGet("key") !== "staged") throw Error("transaction ownership lost");`)
				return err
			})
		}(loop, ext, messages[i])
	}
	for range 2 {
		select {
		case name := <-arrived:
			if _, err := store.GetPluginKV(context.Background(), name, "key"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
				t.Fatalf("runtime %s bypassed transaction: %v", name, err)
			}
		case err := <-returned:
			t.Fatalf("runtime left before barrier: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("independent runtime blocked behind another owner")
		}
	}
	unblock.Do(func() { close(release) })
	for range 2 {
		select {
		case err := <-returned:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("runtime callback stuck")
		}
	}
	// Discard Goja's transaction; only the independent QuickJS transaction commits.
	messages[0].releaseExecutionState()
	if err := messages[1].stopJSExecution(); err != nil {
		t.Fatal(err)
	}
	if err := messages[1].callbackTransaction.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := collectors[1].UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetPluginKV(context.Background(), "goja", "key"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("Goja rollback leaked: %v", err)
	}
	value, err := store.GetPluginKV(context.Background(), "quickjs", "key")
	if err != nil || string(value.Value) != "staged" {
		t.Fatalf("QuickJS commit lost: %v %q", err, value.Value)
	}
}
