package dice

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestJSPublicStorageJoinsCallbackTransaction(t *testing.T) {
	for _, commit := range []bool{false, true} {
		name := "rollback"
		if commit {
			name = "commit"
		}
		t.Run(name, func(t *testing.T) {
			d, store := newCanonicalTestDice(t)
			loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
			manager := NewJsLoopManager()
			generation := manager.SetLoop(loop)
			d.ExtLoopManager = manager
			d.Logger = zap.NewNop().Sugar()
			session := d.ImSession
			ext := &ExtInfo{Name: "writer", IsJsExt: true, dice: d, JSLoopVersion: generation}
			other := &ExtInfo{Name: "other-plugin", IsJsExt: true, dice: d, JSLoopVersion: generation}
			if err := loop.Run(func(runtime jsengine.Runtime) error {
				vm, _ := gojaengine.Raw(runtime)
				vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
				if err := runtime.Bind("extension", newJSExtensionResource(ext, loop)); err != nil {
					return err
				}
				return runtime.Bind("other", newJSExtensionResource(other, loop))
			}); err != nil {
				t.Fatal(err)
			}
			metadata := eventstore.Metadata{CommandID: name, CorrelationID: name}
			collector := execution.NewMutationCollector(eventstore.EventFactory{})
			tx, err := NewDurableCallbackTransaction(context.Background(), store, collector, metadata)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &MsgContext{
				Dice: d, Session: session, callbackTransaction: tx, callbackMetadata: metadata,
				executionContext: tx.executionContext,
			}
			item := &CmdItemInfo{Name: "write", JSLoopVersion: generation, SolveEngine: func(runtime jsengine.Runtime, _ *MsgContext, _ *Message, _ *CmdArgs) (jsengine.Value, error) {
				return runtime.RunString("storage.js", `extension.storageSet("key", "staged"); other.storageSet("key", "separate"); if (extension.storageGet("key") !== "staged" || other.storageGet("key") !== "separate" || extension.storageList()[0] !== "key") throw Error("read-your-writes lost"); ({matched:true, solved:true})`)
			}}
			if _, err := session.executeSolveEngine(ctx, &Message{}, &CmdArgs{}, item, ext); err != nil {
				t.Fatal(err)
			}
			for _, plugin := range []string{ext.Name, other.Name} {
				if _, err := store.GetPluginKV(context.Background(), plugin, "key"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
					t.Fatalf("public storage escaped callback transaction for %s: %v", plugin, err)
				}
			}
			if !commit {
				return
			}
			if err := tx.Finalize(context.Background()); err != nil {
				t.Fatal(err)
			}
			work, err := collector.UnitOfWork()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(context.Background(), work); err != nil {
				t.Fatal(err)
			}
			for plugin, want := range map[string]string{ext.Name: "staged", other.Name: "separate"} {
				got, err := store.GetPluginKV(context.Background(), plugin, "key")
				if err != nil || string(got.Value) != want {
					t.Fatalf("plugin=%s value=%s err=%v", plugin, got.Value, err)
				}
			}
		})
	}
}
