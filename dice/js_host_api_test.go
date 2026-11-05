package dice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"Scardice-core/core/execution"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestInstallJSHostAPI(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			if err := loop.Run(func(runtime jsengine.Runtime) error {
				d := &Dice{}
				if err := d.installJSHostAPI(runtime, loop); err != nil {
					return err
				}
				value, err := runtime.RunString("host-api.js", `
					typeof seal.vars.intGet === "function" &&
					typeof seal.ban.addBan === "function" &&
					typeof seal.coc.newRule === "function" &&
					typeof seal.deck.reload === "function" &&
					typeof seal.replyForward === "function" &&
					typeof seal.newForwardNode === "function" &&
					seal.newForwardNode("1001", "骰主", "转发内容").senderId === "1001" &&
					seal.newForwardElement().type === "forward" &&
					seal.newMessage().message === "" &&
					atob(btoa("Scardice")) === "Scardice" &&
					typeof seal.getVersion().version === "string"
				`)
				if err != nil {
					return err
				}
				if !value.ToBoolean() {
					details, diagnosticErr := runtime.RunString("host-api-diagnostic.js", `
						JSON.stringify({
							replyForward: typeof seal.replyForward,
							newForwardNode: typeof seal.newForwardNode,
							senderId: seal.newForwardNode("1001", "骰主", "转发内容").senderId,
							forwardType: seal.newForwardElement().type
						})
					`)
					if diagnosticErr != nil {
						return diagnosticErr
					}
					t.Fatalf("host API is incomplete: %v", details.Export())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJSExtensionCommandMapSupportsDeletion(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	extension := &ExtInfo{CmdMap: CmdMapCls{"legacy": {Name: "legacy"}}}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("extension", extension); err != nil {
			return err
		}
		_, err := runtime.RunString("delete-command.js", `delete extension.cmdMap.legacy`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, exists := extension.CmdMapSnapshot()["legacy"]; exists {
		t.Fatal("delete extension.cmdMap.legacy did not remove the Go command")
	}
}

func TestJSExtensionReplacementWarnsWithBothSources(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	dice := &Dice{
		Logger:      zap.New(core).Sugar(),
		ExtRegistry: new(SyncMap[string, *ExtInfo]),
	}
	loop := gojaengine.New()
	defer loop.Close()

	first := &JsScriptInfo{Name: "first", Filename: "first.js"}
	if err := jsengine.RunWithContext(loop, &jsExecutionContext{Script: first}, func(runtime jsengine.Runtime) error {
		if err := dice.installJSHostAPI(runtime, loop); err != nil {
			return err
		}
		if err := dice.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), 1, nil); err != nil {
			return err
		}
		_, err := runtime.RunString("first.js", `seal.ext.register(seal.ext.new("same-name", "first", "1"))`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	second := &JsScriptInfo{Name: "second", Filename: "second.js"}
	if err := jsengine.RunWithContext(loop, &jsExecutionContext{Script: second}, func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("second.js", `seal.ext.register(seal.ext.new("same-name", "second", "1"))`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	entries := logs.FilterMessageSnippet("正在替换同名扩展").All()
	if len(entries) != 1 || !strings.Contains(entries[0].Message, "first.js") || !strings.Contains(entries[0].Message, "second.js") {
		t.Fatalf("replacement warning = %#v, want both source filenames", entries)
	}
}

func TestJSExtensionSourceDescriptionIncludesOperatorIdentifiers(t *testing.T) {
	got := jsExtensionSourceDescription(&JsScriptInfo{
		Name:      "attacker",
		Filename:  "attacker.js",
		PackageID: "package-attacker",
		HomePage:  "https://example.test/attacker",
	})
	for _, want := range []string{"attacker", "attacker.js", "package-attacker", "https://example.test/attacker"} {
		if !strings.Contains(got, want) {
			t.Fatalf("source description %q does not include %q", got, want)
		}
	}
}

func TestJSExtensionRegistrationAdoptsImportedIdentityBeforeConfig(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/js-host.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "js-host-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository := extensionstate.NewRepository(store)
	baseline := extensionstate.Baseline{Extensions: []extensionstate.ExtensionIdentity{{
		ID: "imported-ext", Name: "imported-ext", Version: "legacy", Source: "legacy",
	}}}
	if _, err = repository.DecideAndAppend(ctx, extensionstate.State{}, 0, eventstore.Metadata{}, extensionstate.Command{
		Kind: extensionstate.CommandImportBaseline, DiceID: "dice-1", Baseline: &baseline,
	}); err != nil {
		t.Fatal(err)
	}

	d := &Dice{
		BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store,
		ExtRegistry: new(SyncMap[string, *ExtInfo]), Logger: zap.NewNop().Sugar(),
		ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json"),
	}
	d.ConfigManager.SetOwner(d)
	loop := gojaengine.New()
	manager := NewJsLoopManager()
	d.ExtLoopManager = manager
	generation := manager.AddLoop(loop)
	defer loop.Close()
	script := &JsScriptInfo{Name: "imported", Filename: "imported.js", runtimeGeneration: generation}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, eventstore.Metadata{CommandID: "imported-load"})
	if err != nil {
		t.Fatal(err)
	}
	realm := jsContextForRoot(transaction.executionContext, d, nil, script, transaction, true)
	err = runJSExecutionRoot(realm, func() error {
		defer realm.activatePersistentScheduler()
		return jsengine.RunWithContext(loop, realm, func(runtime jsengine.Runtime) error {
			if hostErr := d.installJSHostAPI(runtime, loop); hostErr != nil {
				return hostErr
			}
			if hostErr := d.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), generation, nil); hostErr != nil {
				return hostErr
			}
			_, runErr := runtime.RunString("imported.js", `
				const imported = seal.ext.new("imported-ext", "test", "1.0.0");
				seal.ext.register(imported);
				seal.ext.registerStringConfig(imported, "mode", "fast", "mode", "general");
			`)
			return runErr
		})
	})
	if err != nil {
		realm.completePersistentBinding(err)
		t.Fatalf("register imported extension and config: %v", err)
	}
	if err = transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, work); err != nil {
		t.Fatal(err)
	}
	notifyDomainCommit(transaction)
	script.replacePersistentBinding(realm.binding)
	realm.completePersistentBinding(nil)
	state, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Extensions["imported-ext"].Version != "1.0.0" || state.ConfigDefinitions["imported-ext"]["mode"].Key != "mode" {
		t.Fatalf("durable imported extension state = %#v", state)
	}
}

func TestJSBanRemoveInheritsAmbientDomainTransaction(t *testing.T) {
	_, store := openBanListEventStore(t, filepath.Join(t.TempDir(), "js-ban-remove-ambient.db"), true)
	d, list := newBanListEventStoreTestDice(t, "", store)
	const subjectID = "QQ:js-ban-ambient"
	if err := list.SetRankByID(d, subjectID, BanRankBanned, "member", "admin", "seed"); err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()

	err := d.WithDomainExecution(context.Background(), "test-js-ban-remove-ambient", []byte(subjectID), func(transaction *DurableCallbackTransaction) error {
		execution := &jsExecutionContext{Dice: d, Transaction: transaction}
		return jsengine.RunWithContext(loop, execution, func(runtime jsengine.Runtime) error {
			if hostErr := d.installJSHostAPI(runtime, loop); hostErr != nil {
				return hostErr
			}
			if _, runErr := runtime.RunString("ban-remove.js", `seal.ban.remove(null, "`+subjectID+`")`); runErr != nil {
				return runErr
			}
			if _, exists := list.GetByID(subjectID); !exists {
				return errors.New("JS ban removal committed independently of the ambient DomainTx")
			}
			items, snapshotErr := list.SnapshotForContext(jsHostMessageContext(d, loop))
			if snapshotErr != nil {
				return snapshotErr
			}
			if len(items) != 0 {
				return fmt.Errorf("ambient snapshot after JS removal = %#v", items)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if item, exists := list.GetByID(subjectID); exists {
		t.Fatalf("committed JS ban removal remains readable: %#v", item)
	}
}

func TestJSBanRemoveWithoutAmbientRootPropagatesCommitError(t *testing.T) {
	_, baseStore := openBanListEventStore(t, filepath.Join(t.TempDir(), "js-ban-remove-root.db"), true)
	store := &failingModerationStore{GORMStore: baseStore}
	d, list := newBanListEventStoreTestDice(t, "", store)
	const subjectID = "QQ:js-ban-root"
	if err := list.SetRankByID(d, subjectID, BanRankBanned, "member", "admin", "seed"); err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()
	run := func() error {
		return loop.Run(func(runtime jsengine.Runtime) error {
			if hostErr := d.installJSHostAPI(runtime, loop); hostErr != nil {
				return hostErr
			}
			_, runErr := runtime.RunString("ban-remove-root.js", `seal.ban.remove(null, "`+subjectID+`")`)
			return runErr
		})
	}

	store.fail = true
	if err := run(); err == nil || !strings.Contains(err.Error(), "injected moderation commit failure") {
		t.Fatalf("JS ban removal commit failure = %v, want propagated error", err)
	}
	if _, exists := list.GetByID(subjectID); !exists {
		t.Fatal("failed JS ban removal changed committed state")
	}

	store.fail = false
	if err := run(); err != nil {
		t.Fatalf("JS ban removal in an independent root: %v", err)
	}
	if item, exists := list.GetByID(subjectID); exists {
		t.Fatalf("independent-root JS ban removal remains readable: %#v", item)
	}
}
