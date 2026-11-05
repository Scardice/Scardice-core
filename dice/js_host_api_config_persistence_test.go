package dice

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestJSExtSensitiveConfigDefaultsSurviveDurableRestartAndCronGetter(t *testing.T) {
	ctx := context.Background()
	dsn := t.TempDir() + "/sensitive-config-restart.db"
	openStore := func() *eventstore.GORMStore {
		db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		options := projectionset.StoreOptions()
		return eventstore.NewStore(db, options...)
	}

	store := openStore()
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "sensitive-config-restart",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	baseline := configstate.Baseline{DiceID: "dice-1", ConfigVersion: 1, CommandPrefix: []string{"."}}
	if _, err := configstate.NewRepository(store).DecideAndAppend(
		ctx,
		configstate.State{},
		0,
		eventstore.Metadata{},
		configstate.Command{Kind: configstate.CommandImportBaseline, Baseline: &baseline},
	); err != nil {
		t.Fatal(err)
	}

	const pluginName = "HTTP依赖"
	first := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-1"},
		DurableStore:  store,
		ConfigManager: NewConfigManager(""),
	}
	first.ConfigManager.SetOwner(first)
	firstExt := &ExtInfo{Name: pluginName, Version: "1.2.0", IsJsExt: true, dice: first}
	if err := first.DurableDiscoverExtension(ctx, firstExt); err != nil {
		t.Fatal(err)
	}
	if err := first.ConfigManager.RegisterPluginConfig(pluginName,
		&ConfigItem{
			Key: "HTTP Access Token", Type: "template", Description: "token list",
			DefaultValue: []string{"test-access-token"}, Value: []string{"test-access-token"},
		},
		&ConfigItem{
			Key: "token", Type: "string", Description: "single token",
			DefaultValue: "test-string-token", Value: "test-string-token",
		},
		&ConfigItem{
			Key: "legacy token", Type: "string", Description: "legacy event value",
			DefaultValue: "replacement-default", Value: "replacement-default",
		},
		&ConfigItem{
			Key: "empty token", Type: "string", Description: "explicit empty value",
			DefaultValue: "non-empty-default", Value: "non-empty-default",
		},
		&ConfigItem{
			Key: "large-count", Type: "int", Description: "large integer",
			DefaultValue: int64(9007199254740991), Value: int64(9007199254740991),
		},
		&ConfigItem{
			Key: "ratio", Type: "float", Description: "floating point",
			DefaultValue: 1.25, Value: 1.25,
		},
	); err != nil {
		t.Fatal(err)
	}
	if err := first.ConfigManager.SetConfig(pluginName, "empty token", ""); err != nil {
		t.Fatal(err)
	}

	const legacyKey = "legacy token"
	repository, diceID, err := first.durableExtensionRepository()
	if err != nil {
		t.Fatal(err)
	}
	legacyState, err := repository.Load(ctx, diceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.DecideAndAppend(ctx, legacyState, legacyState.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:        extensionstate.CommandSetConfig,
		ExtensionID: pluginName,
		Key:         legacyKey,
		Value:       extensionstate.StringValue("legacy-explicit-value"),
	}); err != nil {
		t.Fatal(err)
	}

	const opaqueStorageKey = "\x00scardice-config\x00HTTP Access Token"
	if err := first.durableStorageSet(pluginName, opaqueStorageKey, "opaque-storage-value"); err != nil {
		t.Fatal(err)
	}
	if got, err := first.durableStorageGet(pluginName, opaqueStorageKey); err != nil || got != "opaque-storage-value" {
		t.Fatalf("opaque storage value = %q, %v", got, err)
	}
	keys, err := first.durableStorageList(pluginName)
	if err != nil {
		t.Fatal(err)
	}
	foundOpaqueKey := false
	for _, key := range keys {
		if key == opaqueStorageKey {
			foundOpaqueKey = true
			break
		}
	}
	if !foundOpaqueKey {
		t.Fatal("opaque storage key with the old reserved prefix was hidden")
	}
	if err := first.clearDurableExtensionStorage(pluginName); err != nil {
		t.Fatal(err)
	}
	if got, err := first.durableStorageGet(pluginName, opaqueStorageKey); err != nil || got != "" {
		t.Fatalf("opaque storage value after clear = %q, %v", got, err)
	}

	state, err := first.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HTTP Access Token", "token", legacyKey, "empty token"} {
		if !state.ConfigDefinitions[pluginName][key].DefaultSet {
			t.Fatalf("typed definition %q lost its default", key)
		}
	}
	if got := state.ConfigValues[pluginName]["HTTP Access Token"]; got.Type != extensionstate.ConfigTemplate || len(got.Strings) != 1 || got.Strings[0] != "test-access-token" {
		t.Fatalf("typed template config = %#v", got)
	}
	if got := state.ConfigValues[pluginName]["token"]; got.Type != extensionstate.ConfigString || got.String != "test-string-token" {
		t.Fatalf("typed string config = %#v", got)
	}
	if got := state.ConfigValues[pluginName]["empty token"]; got.Type != extensionstate.ConfigString || got.String != "" {
		t.Fatalf("explicit empty typed config = %#v", got)
	}
	if got := state.ConfigValues[pluginName][legacyKey]; got.Type != extensionstate.ConfigString || got.String != "legacy-explicit-value" {
		t.Fatalf("legacy event config value = %#v", got)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restartedStore := openStore()
	defer restartedStore.Close()
	restarted := &Dice{
		BaseConfig:     BaseConfig{Name: "dice-1"},
		DurableStore:   restartedStore,
		ConfigManager:  NewConfigManager(""),
		ExtRegistry:    new(SyncMap[string, *ExtInfo]),
		JsExtRegistry:  new(SyncMap[string, *ExtInfo]),
		ExtLoopManager: NewJsLoopManager(),
		Logger:         zap.NewNop().Sugar(),
	}
	restarted.ConfigManager.SetOwner(restarted)
	restarted.startJSScriptCron()
	defer restarted.stopJSScriptCron()

	loop := gojaengine.New()
	version := restarted.ExtLoopManager.SetLoop(loop)
	defer restarted.ExtLoopManager.SetLoop(nil)
	if err := restarted.ReloadConfigView(ctx); err != nil {
		t.Fatal(err)
	}
	script := &JsScriptInfo{Name: pluginName, Filename: "http-dependency.js", runtimeGeneration: version}
	var realm *jsExecutionContext
	err = restarted.WithDomainExecution(
		ctx,
		restarted.DomainExecutionIdentity("test-js-load", "sensitive-config-restart"),
		[]byte("sensitive-config-restart"),
		func(transaction *DurableCallbackTransaction) error {
			realm = jsContextForRoot(transaction.executionContext, restarted, nil, script, transaction, true)
			return runJSExecutionRoot(realm, func() error {
				defer realm.activatePersistentScheduler()
				return jsengine.RunWithContext(loop, realm, func(runtime jsengine.Runtime) error {
					if hostErr := restarted.installJSHostAPI(runtime, loop); hostErr != nil {
						return hostErr
					}
					if hostErr := restarted.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), version, nil); hostErr != nil {
						return hostErr
					}
					_, runErr := runtime.RunString("http-dependency.js", `
						globalThis.sensitiveConfigCronRan = false;
						const ext = seal.ext.new("HTTP依赖", "test", "1.2.0");
						seal.ext.register(ext);
						seal.ext.registerTemplateConfig(ext, "HTTP Access Token", ["test-access-token"], "token list", "");
						seal.ext.registerStringConfig(ext, "token", "test-string-token", "single token", "");
						seal.ext.registerStringConfig(ext, "legacy token", "replacement-default", "legacy event value", "");
						seal.ext.registerStringConfig(ext, "empty token", "changed-default", "explicit empty value", "");
						seal.ext.registerIntConfig(ext, "large-count", 9007199254740991, "large integer", "");
						seal.ext.registerFloatConfig(ext, "ratio", 1.25, "floating point", "");
						seal.ext.registerTask(ext, "cron", "0 0 1 1 *", () => {
							const tokens = seal.ext.getTemplateConfig(ext, "HTTP Access Token");
							const token = seal.ext.getStringConfig(ext, "token");
							const legacyToken = seal.ext.getStringConfig(ext, "legacy token");
							const emptyToken = seal.ext.getStringConfig(ext, "empty token");
							const largeCount = seal.ext.getIntConfig(ext, "large-count");
							const ratio = seal.ext.getFloatConfig(ext, "ratio");
							globalThis.sensitiveConfigCronRan = tokens.length === 1 &&
								tokens[0] === "test-access-token" && token === "test-string-token" &&
								legacyToken === "legacy-explicit-value" && emptyToken === "" &&
								largeCount === 9007199254740991 && ratio === 1.25;
						}, "", "", "");
					`)
					return runErr
				})
			})
		},
	)
	if realm != nil {
		if err == nil {
			script.replacePersistentBinding(realm.binding)
		}
		realm.completePersistentBinding(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	persisted, err := extensionstate.NewRepository(restartedStore).Load(ctx, "dice-1")
	if err != nil || persisted.ConfigValues[pluginName][legacyKey].String != "legacy-explicit-value" {
		t.Fatalf("restored typed config = %#v, err=%v", persisted.ConfigValues[pluginName], err)
	}

	realExt, ok := restarted.JsExtRegistry.Load(pluginName)
	if !ok || realExt == nil || len(realExt.taskList) != 1 {
		t.Fatalf("registered cron task = %#v", realExt)
	}
	task := realExt.taskList[0]
	defer task.Off()
	task.run()

	if err := jsengine.RunWithContext(loop, jsContextForPlugin(realExt), func(runtime jsengine.Runtime) error {
		if !runtime.Get("sensitiveConfigCronRan").ToBoolean() {
			t.Fatal("cron callback could not read typed sensitive configuration after restart")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestJSExtConfigRegistrationRollsBackDefinitionWhenInitialValueWriteFails(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  t.TempDir() + "/sensitive-config-atomicity.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db,
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	defer store.Close()
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "sensitive-config-atomicity",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	const pluginName = "atomic-sensitive-config"
	d := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-atomic"},
		DurableStore:  store,
		ConfigManager: NewConfigManager(""),
	}
	seedCanonicalTestConfigBaseline(t, d)
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: pluginName, Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec(`
		CREATE TRIGGER reject_initial_config_value
		BEFORE INSERT ON domain_events
		WHEN NEW.aggregate_type = 'extension-state' AND NEW.event_type = 'config_value_changed'
		BEGIN
			SELECT RAISE(ABORT, 'forced initial config value failure');
		END
	`).Error; err != nil {
		t.Fatal(err)
	}

	err = d.ConfigManager.RegisterPluginConfig(pluginName, &ConfigItem{
		Key:          "access token",
		Type:         "string",
		DefaultValue: "sensitive-default",
		Value:        "sensitive-default",
	})
	if err == nil {
		t.Fatal("config registration succeeded despite forced initial value failure")
	}
	state, loadErr := d.DurableExtensionState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, exists := state.ConfigDefinitions[pluginName]["access token"]; exists {
		t.Fatal("config definition committed without its initial value")
	}
}
