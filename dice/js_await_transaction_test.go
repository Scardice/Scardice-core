package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestAwaitStorageRemainsInOriginTransaction(t *testing.T) {
	store, _ := repairTestStore(t)
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	if err := gojaengine.InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	manager := NewJsLoopManager()
	generation := manager.SetLoop(loop)
	d := &Dice{DurableStore: store, ExtLoopManager: manager}
	ext := &ExtInfo{Name: "await-transaction-owner", IsJsExt: true, dice: d, JSLoopVersion: generation}
	makeMessage := func() (*MsgContext, *messageflow.MutationCollector) {
		collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
		transaction, err := NewDurableCallbackTransaction(store, collector)
		if err != nil {
			t.Fatal(err)
		}
		ctx := &MsgContext{Dice: d, callbackTransaction: transaction}
		t.Cleanup(ctx.releaseExecutionState)
		return ctx, collector
	}
	origin, originCollector := makeMessage()
	resolver, resolverCollector := makeMessage()
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		vm, _ := gojaengine.Raw(runtime)
		vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
		return runtime.Bind("extension", ext)
	}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, jsContextForMessage(ext, origin), func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("origin.js", `
			var resolveOrigin;
			(async function () {
				await new Promise(resolve => { resolveOrigin = resolve; });
				extension.storageSet("owner", "origin");
			})();
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, jsContextForMessage(ext, resolver), func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolver.js", `extension.storageSet("resolver", "own"); resolveOrigin();`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	commit := func(ctx *MsgContext, collector *messageflow.MutationCollector) {
		if err := ctx.stopJSExecution(); err != nil {
			t.Fatal(err)
		}
		if err := ctx.callbackTransaction.Finalize(context.Background()); err != nil {
			t.Fatal(err)
		}
		work, err := collector.UnitOfWork()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Commit(context.Background(), work); err != nil {
			t.Fatal(err)
		}
	}
	commit(resolver, resolverCollector)
	if value, err := store.GetPluginKV(context.Background(), ext.Name, "owner"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("resolver committed origin's write: value=%q err=%v", value.Value, err)
	}
	commit(origin, originCollector)
	value, err := store.GetPluginKV(context.Background(), ext.Name, "owner")
	if err != nil || string(value.Value) != "origin" {
		t.Fatalf("origin commit value=%q err=%v, want origin", value.Value, err)
	}
}
