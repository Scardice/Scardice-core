package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestAwaitStorageRemainsInOriginTransaction(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
	if err := gojaengine.InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	manager := NewJsLoopManager()
	generation := manager.SetLoop(loop)
	d.ExtLoopManager = manager
	ext := &ExtInfo{Name: "await-transaction-owner", IsJsExt: true, dice: d, JSLoopVersion: generation}
	// Independent roots writing one plugin namespace conflict on its namespace
	// revision by design, so the resolver owns a separate namespace.
	resolverExt := &ExtInfo{Name: "await-transaction-resolver", IsJsExt: true, dice: d, JSLoopVersion: generation}
	makeMessage := func(label string) (*MsgContext, *execution.MutationCollector) {
		metadata := eventstore.Metadata{CommandID: label, CorrelationID: label}
		collector := execution.NewMutationCollector(eventstore.EventFactory{})
		transaction, err := NewDurableCallbackTransaction(context.Background(), store, collector, metadata)
		if err != nil {
			t.Fatal(err)
		}
		ctx := &MsgContext{
			Dice: d, callbackTransaction: transaction, callbackMetadata: metadata,
			executionContext: transaction.executionContext,
		}
		t.Cleanup(ctx.releaseExecutionState)
		return ctx, collector
	}
	origin, originCollector := makeMessage("await-origin")
	resolver, resolverCollector := makeMessage("await-resolver")
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		vm, _ := gojaengine.Raw(runtime)
		vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
		if err := runtime.Bind("resolverExtension", newJSExtensionResource(resolverExt, loop)); err != nil {
			return err
		}
		return runtime.Bind("extension", newJSExtensionResource(ext, loop))
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
	if err := jsengine.RunWithContext(loop, jsContextForMessage(resolverExt, resolver), func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("resolver.js", `resolverExtension.storageSet("resolver", "own"); resolveOrigin();`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	commit := func(ctx *MsgContext, collector *execution.MutationCollector) {
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
			t.Fatalf("commit %s: %v", ctx.callbackMetadata.CommandID, err)
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
