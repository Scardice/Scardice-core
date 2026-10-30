package dice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
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
		return eventstore.NewStore(db,
			eventstore.WithKeySource(compatKeySource{}),
			eventstore.WithProjection(extensionstate.ExtensionProjection()),
		)
	}

	store := openStore()
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "sensitive-config-restart",
		IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
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
	if err := first.durableDeleteEncryptedConfigValue(ctx, pluginName, legacyKey); err != nil {
		t.Fatal(err)
	}
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
	if err := first.durableStorageSet(durableConfigStorageExtensionID(pluginName), "public-key", "public-value"); !errors.Is(err, errDurableReservedStorageDomain) {
		t.Fatalf("public storage reached internal config namespace: %v", err)
	}

	state, err := first.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HTTP Access Token", "token", legacyKey, "empty token"} {
		if state.ConfigDefinitions[pluginName][key].DefaultSet {
			t.Fatalf("sensitive definition %q persisted its default in the event stream", key)
		}
	}
	for _, key := range []string{"HTTP Access Token", "token", "empty token"} {
		if _, exists := state.ConfigValues[pluginName][key]; exists {
			t.Fatalf("sensitive config %q persisted its value in the event stream", key)
		}
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
	script := &JsScriptInfo{Name: pluginName, Filename: "http-dependency.js"}
	if err := jsengine.RunWithContext(loop, &jsExecutionContext{Script: script}, func(runtime jsengine.Runtime) error {
		if err := restarted.installJSHostAPI(runtime); err != nil {
			return err
		}
		if err := restarted.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), version, nil); err != nil {
			return err
		}
		_, err := runtime.RunString("http-dependency.js", `
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
		return err
	}); err != nil {
		t.Fatal(err)
	}

	migratedValue, exists, err := restarted.durableEncryptedConfigValue(ctx, pluginName, legacyKey, extensionstate.ConfigString)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || migratedValue != "legacy-explicit-value" {
		t.Fatalf("migrated legacy value = %#v, exists=%v", migratedValue, exists)
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

func TestJSExtSensitiveConfigRegistrationRollsBackDefinitionWhenEncryptedValueWriteFails(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  t.TempDir() + "/sensitive-config-atomicity.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	defer store.Close()
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "sensitive-config-atomicity",
		IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
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
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: pluginName, Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec(`
		CREATE TRIGGER reject_internal_config_value
		BEFORE INSERT ON plugin_kv
		WHEN NEW.extension_id LIKE 'scardice.internal.config/v1/%'
		BEGIN
			SELECT RAISE(ABORT, 'forced encrypted config failure');
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
		t.Fatal("sensitive config registration succeeded despite forced encrypted value failure")
	}
	state, loadErr := d.DurableExtensionState(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, exists := state.ConfigDefinitions[pluginName]["access token"]; exists {
		t.Fatal("config definition committed without its encrypted initial value")
	}
}

func TestJSExtTypedGetterMismatchReportsIdentityWithoutValue(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()
	d := &Dice{
		ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json"),
		ExtRegistry:   new(SyncMap[string, *ExtInfo]),
		Logger:        zap.NewNop().Sugar(),
	}
	d.ConfigManager.SetOwner(d)

	const sensitiveValue = "must-not-appear-in-diagnostic"
	var diagnostic, caughtDiagnostic string
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := d.installJSHostAPI(runtime); err != nil {
			return err
		}
		if err := d.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), 1, nil); err != nil {
			return err
		}
		if _, err := runtime.RunString("diagnostic.js", `
			globalThis.diagnosticExt = seal.ext.new("diagnostic-ext", "test", "1.0.0");
			seal.ext.register(globalThis.diagnosticExt);
			seal.ext.registerIntConfig(globalThis.diagnosticExt, "count", 1, "count", "");
		`); err != nil {
			return err
		}

		d.ConfigManager.lock.Lock()
		d.ConfigManager.Plugins["diagnostic-ext"].Configs["count"].Value = sensitiveValue
		d.ConfigManager.lock.Unlock()

		_, err := runtime.RunString("diagnostic-getter.js", `seal.ext.getIntConfig(globalThis.diagnosticExt, "count")`)
		if err == nil {
			t.Fatal("getIntConfig accepted a string value")
		}
		diagnostic = err.Error()
		if _, err := runtime.RunString("diagnostic-catch.js", `
			globalThis.caughtConfigDiagnostic = "";
			try {
				seal.ext.getIntConfig(globalThis.diagnosticExt, "count");
			} catch (error) {
				globalThis.caughtConfigDiagnostic = String(error);
			}
		`); err != nil {
			return err
		}
		caught, err := runtime.Get("caughtConfigDiagnostic").ExportPrimitive()
		if err != nil {
			return err
		}
		caughtDiagnostic, _ = caught.(string)
		if caughtDiagnostic == "" {
			t.Fatal("typed getter error was not catchable in JavaScript")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, current := range []string{diagnostic, caughtDiagnostic} {
		for _, want := range []string{
			`plugin="diagnostic-ext"`,
			`key="count"`,
			`declared="int"`,
			`actual="string"`,
		} {
			if !strings.Contains(current, want) {
				t.Fatalf("diagnostic %q does not contain %q", current, want)
			}
		}
		if strings.Contains(current, sensitiveValue) {
			t.Fatal("typed getter diagnostic disclosed the configuration value")
		}
	}
}
