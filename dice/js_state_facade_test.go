package dice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"

	ds "github.com/sealdice/dicescript"

	"go.uber.org/zap"
)

func TestDurableCompatibilityConfigAndStorage(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/compat.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "compat-facade-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	d := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-1"},
		DurableStore:  store,
		ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json"),
	}
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: "compat-ext", Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	item := &ConfigItem{Key: "enabled", Type: "bool", DefaultValue: false, Value: false, Description: "enabled"}
	if err := d.DurableRegisterConfig(ctx, ext, item); err != nil {
		t.Fatal(err)
	}
	if err := d.DurableSetConfig(ctx, ext, "enabled", true); err != nil {
		t.Fatal(err)
	}
	projected, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := projected.ConfigValues[ext.Name][item.Key].Bool; !got {
		t.Fatalf("projected config value = %#v", projected.ConfigValues)
	}
	view, err := d.DurableConfigItem(ctx, ext, item.Key)
	if err != nil {
		t.Fatal(err)
	}
	if view == nil || view.Value != true {
		t.Fatalf("config view = %#v", view)
	}
	if missing := d.compatibilityConfigItem(ext, "optional-unregistered"); missing != nil {
		t.Fatalf("missing optional config = %#v, want nil", missing)
	}
	if err := d.DurableSetConfig(ctx, ext, "optional-unregistered", true); !errors.Is(err, extensionstate.ErrUnknownConfig) {
		t.Fatalf("setting an unregistered config must remain invalid: %v", err)
	}

	if err := ext.StorageSet("opaque", "value"); err != nil {
		t.Fatal(err)
	}
	if got, err := ext.StorageGet("opaque"); err != nil || got != "value" {
		t.Fatalf("storage get = %q, err=%v", got, err)
	}
	keys, err := ext.StorageList()
	if err != nil || len(keys) != 1 || keys[0] != "opaque" {
		t.Fatalf("storage keys = %#v, err=%v", keys, err)
	}
	if ext.Storage != nil {
		t.Fatal("durable storage opened legacy BuntDB")
	}
	if err := ClearExtStorage(d, ext, ext.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := ext.StorageGet("opaque"); err != nil && !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatal(err)
	}
}

// The WebUI and /js/set_config send a template (string list) as JSON, which
// decodes to []any; plain and sensitive template configs must both accept it.
func TestDurableTemplateConfigAcceptsAJSONStringList(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/template.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "template-config-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json")}
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: "http-dependency", Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"HTTP端口地址", "HTTP Access Token"} {
		item := &ConfigItem{Key: key, Type: "template", DefaultValue: []string{""}, Value: []string{""}}
		if err := d.DurableRegisterConfig(ctx, ext, item); err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal([]byte(`["first", "second"]`), &decoded); err != nil {
			t.Fatal(err)
		}
		if err := d.durableSetConfigByName(ctx, ext.Name, key, decoded); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		view, err := d.DurableConfigItem(ctx, ext, key)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := view.Value.([]string); !ok || len(got) != 2 || got[0] != "first" || got[1] != "second" {
			t.Fatalf("%s value = %#v", key, view.Value)
		}
		var mixed any
		if err := json.Unmarshal([]byte(`["first", 2]`), &mixed); err != nil {
			t.Fatal(err)
		}
		if err := d.durableSetConfigByName(ctx, ext.Name, key, mixed); err == nil {
			t.Fatalf("%s accepted a list holding a number", key)
		}
	}
}

func TestDurableDiscoveryAdoptsImportedIdentityAndDiscoversAfterBaseline(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/identity.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "identity-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
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

	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}
	imported := &ExtInfo{Name: "imported-ext", Version: "1.0.0", IsJsExt: true}
	if err = d.DurableDiscoverExtension(ctx, imported); err != nil {
		t.Fatalf("adopt imported identity: %v", err)
	}
	added := &ExtInfo{Name: "new-ext", Version: "2.0.0", IsJsExt: true}
	if err = d.DurableDiscoverExtension(ctx, added); err != nil {
		t.Fatalf("discover extension after non-empty baseline: %v", err)
	}
	state, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.Extensions["imported-ext"]; got.Version != "1.0.0" || got.Source != "script" {
		t.Fatalf("imported identity = %#v", got)
	}
	if got := state.Extensions["new-ext"]; got.Version != "2.0.0" || got.Source != "script" {
		t.Fatalf("new identity = %#v", got)
	}
}

func TestDurableCallbackTransactionStagesPluginKVWithoutDirectCommit(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-plugin.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-plugin-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.StorageSet(ctx, "callback-ext", "opaque", "value"); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPluginKV(ctx, "callback-ext", "opaque"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("callback storage committed directly: %v", err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.PluginKVUpdates) != 1 {
		t.Fatalf("staged plugin updates = %#v", work.PluginKVUpdates)
	}
}

func TestCallbackContextStorageFacadeStagesReadAfterWrite(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-context-storage.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-context-storage-db", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	messageCtx := &MsgContext{Dice: &Dice{DurableStore: store}, callbackTransaction: transaction}
	if err := messageCtx.ExtensionStorageSet("callback-ext", "opaque", "value"); err != nil {
		t.Fatal(err)
	}
	if value, err := messageCtx.ExtensionStorageGet("callback-ext", "opaque"); err != nil || value != "value" {
		t.Fatalf("callback storage read-after-write = %q, %v", value, err)
	}
	if _, err := store.GetPluginKV(ctx, "callback-ext", "opaque"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("callback storage committed directly: %v", err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.PluginKVUpdates) != 1 {
		t.Fatalf("callback storage work = %#v", work)
	}
}

func TestDurableCallbackTransactionStagesExtensionConfigWithoutDirectCommit(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-config.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(extensionstate.ExtensionProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-config-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	metadata := eventstore.Metadata{CommandID: "inbox-1", CorrelationID: "inbox-1", OccurredAt: time.Unix(2, 0).UTC()}
	identity := extensionstate.ExtensionIdentity{ID: "callback-ext", Name: "callback-ext", Version: "1.0.0", Source: "js"}
	definition := extensionstate.ConfigDefinition{ExtensionID: identity.ID, Key: "enabled", Type: extensionstate.ConfigBool, Default: extensionstate.BoolValue(false), DefaultSet: true}
	if err := transaction.StageExtensionCommand(extensionstate.State{}, extensionstate.Command{Kind: extensionstate.CommandDiscover, DiceID: "dice-1", Identity: identity}, metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.StageExtensionCommand(extensionstate.State{}, extensionstate.Command{Kind: extensionstate.CommandRegisterConfig, ExtensionID: identity.ID, Definition: definition}, metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.StageExtensionCommand(extensionstate.State{}, extensionstate.Command{Kind: extensionstate.CommandSetConfig, ExtensionID: identity.ID, Key: definition.Key, Value: extensionstate.BoolValue(true)}, metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	if state, err := extensionstate.NewRepository(store).Load(ctx, "dice-1"); err != nil || state.Version != 0 {
		t.Fatalf("callback config committed directly: state=%#v err=%v", state, err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || work.Streams[0].Stream != extensionstate.ExtensionStream("dice-1") || len(work.Streams[0].Events) != 4 {
		t.Fatalf("staged config streams = %#v", work.Streams)
	}
}

func TestCallbackContextConfigFacadeStagesReadAfterWrite(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-context-config.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(extensionstate.ExtensionProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-context-config-db", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	repository := extensionstate.NewRepository(store)
	metadata := eventstore.Metadata{CommandID: "bootstrap", CorrelationID: "bootstrap", OccurredAt: time.Unix(2, 0).UTC()}
	identity := extensionstate.ExtensionIdentity{ID: "callback-ext", Name: "callback-ext", Version: "1.0.0", Source: "js"}
	if _, err := repository.DecideAndAppend(ctx, extensionstate.State{}, 0, metadata, extensionstate.Command{Kind: extensionstate.CommandDiscover, DiceID: "dice-1", Identity: identity}); err != nil {
		t.Fatal(err)
	}
	state, err := repository.Load(ctx, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	definition := extensionstate.ConfigDefinition{ExtensionID: identity.ID, Key: "enabled", Type: extensionstate.ConfigBool, Default: extensionstate.BoolValue(false), DefaultSet: true}
	if _, err := repository.DecideAndAppend(ctx, state, state.Version, metadata, extensionstate.Command{Kind: extensionstate.CommandRegisterConfig, ExtensionID: identity.ID, Definition: definition}); err != nil {
		t.Fatal(err)
	}
	state, err = repository.Load(ctx, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	sensitiveDefinition := extensionstate.ConfigDefinition{
		ExtensionID: identity.ID,
		Key:         "access token",
		Type:        extensionstate.ConfigString,
	}
	if _, err := repository.DecideAndAppend(ctx, state, state.Version, metadata, extensionstate.Command{
		Kind:        extensionstate.CommandRegisterConfig,
		ExtensionID: identity.ID,
		Definition:  sensitiveDefinition,
	}); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}, callbackTransaction: transaction, callbackMetadata: eventstore.Metadata{CommandID: "inbox-config", CorrelationID: "inbox-config", OccurredAt: time.Unix(3, 0).UTC()}}
	if err := messageCtx.ExtensionConfigSet("callback-ext", "enabled", true); err != nil {
		t.Fatal(err)
	}
	if value, ok, err := messageCtx.ExtensionConfigValue("callback-ext", "enabled"); err != nil || !ok || value != true {
		t.Fatalf("callback config read-after-write = %#v, %v, %v", value, ok, err)
	}
	if err := messageCtx.ExtensionConfigSet("callback-ext", "access token", "callback-secret"); err != nil {
		t.Fatal(err)
	}
	if value, ok, err := messageCtx.ExtensionConfigValue("callback-ext", "access token"); err != nil || !ok || value != "callback-secret" {
		t.Fatalf("callback sensitive config read-after-write = %#v, %v, %v", value, ok, err)
	}
	if _, err := store.GetPluginKV(ctx, durableConfigStorageExtensionID("callback-ext"), durableConfigStorageKey("access token")); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("callback sensitive config committed before terminal unit of work: %v", err)
	}
	persisted, err := repository.Load(ctx, "dice-1")
	if err != nil || persisted.ConfigValues["callback-ext"]["enabled"].Bool {
		t.Fatalf("callback config committed directly: %#v, %v", persisted, err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Streams[0].Events) != 1 || len(work.PluginKVUpdates) != 1 {
		t.Fatalf("callback config work = %#v", work)
	}
}

func TestSensitiveConfigInternalSlotAcceptsOpaqueKeyAcrossDirectAndCallbackPaths(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  t.TempDir() + "/opaque-sensitive-config-key.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "opaque-sensitive-config-key",
		IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	const (
		pluginName = "opaque-config-key"
		configKey  = "access$t token"
	)
	longestConfigKey := strings.Repeat("k", extensionstate.MaxExtensionIdentityPartBytes)
	if encodedLength := len(durableConfigStorageKey(longestConfigKey)); encodedLength > eventstore.MaxPluginKeyBytes {
		t.Fatalf("longest config key encoded to %d bytes, plugin KV limit is %d", encodedLength, eventstore.MaxPluginKeyBytes)
	}
	if strings.Contains(durableConfigStorageKey(configKey), "$t") {
		t.Fatal("internal config slot retained a forbidden raw-key marker")
	}
	d := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-opaque-config"},
		DurableStore:  store,
		ConfigManager: NewConfigManager(""),
	}
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: pluginName, Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigManager.RegisterPluginConfig(pluginName, &ConfigItem{
		Key: configKey, Type: "string", DefaultValue: "declared-default", Value: "declared-default",
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigManager.SetConfig(pluginName, configKey, "direct-value"); err != nil {
		t.Fatal(err)
	}
	internalExtensionID := durableConfigStorageExtensionID(pluginName)
	if _, err := store.GetPluginKV(ctx, internalExtensionID, configKey); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
		t.Fatalf("raw config key was persisted in the internal namespace: %v", err)
	}
	if _, err := store.GetPluginKV(ctx, internalExtensionID, durableConfigStorageKey(configKey)); err != nil {
		t.Fatalf("encoded internal config slot is missing: %v", err)
	}
	if value, exists, err := d.durableEncryptedConfigValue(ctx, pluginName, configKey, extensionstate.ConfigString); err != nil || !exists || value != "direct-value" {
		t.Fatalf("direct sensitive config = %#v, exists=%v, err=%v", value, exists, err)
	}

	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	messageCtx := &MsgContext{
		Dice:                d,
		callbackTransaction: transaction,
		callbackMetadata: eventstore.Metadata{
			CommandID: "opaque-config-callback", CorrelationID: "opaque-config-callback",
			OccurredAt: time.Unix(2, 0).UTC(),
		},
	}
	if err := messageCtx.ExtensionConfigSet(pluginName, configKey, "callback-value"); err != nil {
		t.Fatal(err)
	}
	if value, exists, err := messageCtx.ExtensionConfigValue(pluginName, configKey); err != nil || !exists || value != "callback-value" {
		t.Fatalf("callback sensitive config read-after-write = %#v, exists=%v, err=%v", value, exists, err)
	}
	if value, exists, err := d.durableEncryptedConfigValue(ctx, pluginName, configKey, extensionstate.ConfigString); err != nil || !exists || value != "direct-value" {
		t.Fatalf("callback config committed before terminal unit of work: value=%#v, exists=%v, err=%v", value, exists, err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 0 || len(work.PluginKVUpdates) != 1 {
		t.Fatalf("callback sensitive config work = %#v", work)
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatal(err)
	}
	if value, exists, err := d.durableEncryptedConfigValue(ctx, pluginName, configKey, extensionstate.ConfigString); err != nil || !exists || value != "callback-value" {
		t.Fatalf("committed callback sensitive config = %#v, exists=%v, err=%v", value, exists, err)
	}
}

func TestDurableCallbackTransactionStagesAttributeSnapshotWithSecret(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-attrs.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-attrs-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	state := attributestate.State{DiceID: "dice-1", ID: "QQ-Group:2002-QQ:1001", AttrsType: "group_user", SecretRef: attributestate.SecretRef("dice-1", "QQ-Group:2002-QQ:1001"), CreatedAt: 2, UpdatedAt: 2}
	metadata := eventstore.Metadata{CommandID: "inbox-attrs", CorrelationID: "inbox-attrs", OccurredAt: time.Unix(2, 0).UTC()}
	if err := transaction.StageAttributeSnapshot(ctx, state, []byte(`{"hp":{"t":7,"v":1}}`), metadata); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || work.Streams[0].Stream != attributestate.Stream(state.DiceID, state.ID) || len(work.SecretUpdates) != 1 {
		t.Fatalf("staged attributes work = %#v", work)
	}
}

func TestDurableCallbackTransactionAttributeOverlayDoesNotMutateSharedCache(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-attrs-overlay.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-attrs-overlay-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	state := attributestate.State{DiceID: "dice-1", ID: "QQ-Group:2002-QQ:1001", AttrsType: "group_user", SecretRef: attributestate.SecretRef("dice-1", "QQ-Group:2002-QQ:1001"), CreatedAt: 2, UpdatedAt: 2}
	sharedValues := &ds.ValueMap{}
	sharedValues.Store("hp", ds.NewIntVal(1))
	shared := &AttributesItem{ID: state.ID, valueMap: sharedValues, IsSaved: true}
	overlay, err := transaction.AttributeOverlay(state, shared, eventstore.Metadata{CommandID: "inbox-overlay", CorrelationID: "inbox-overlay", OccurredAt: time.Unix(2, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	overlay.Store("hp", ds.NewIntVal(2))
	if got := shared.Load("hp"); got == nil || got.ToString() != "1" {
		t.Fatalf("shared cache mutated by callback overlay: %v", got)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("overlay mutation was not staged: %#v", work)
	}
}

func TestCallbackVariableOverlayReadsOwnWriteWithoutMutatingDurableState(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-variable-overlay.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-variable-overlay-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	id := "QQ-Group:2002-QQ:1001"
	baseline := attributestate.State{DiceID: "dice-1", ID: id, AttrsType: "group_user", SecretRef: attributestate.SecretRef("dice-1", id), CreatedAt: 2, UpdatedAt: 2}
	baselineValues := &ds.ValueMap{}
	baselineValues.Store("hp", ds.NewIntVal(1))
	baselinePayload, err := ds.NewDictVal(baselineValues).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Save(ctx, baseline, baselinePayload); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, AttrsManager: &AttrsManager{durable: repository, store: store, diceID: "dice-1"}}
	messageCtx := &MsgContext{Dice: d, Session: &IMSession{}, Group: &GroupInfo{GroupID: "QQ-Group:2002"}, Player: &GroupPlayerInfo{UserID: "QQ:1001"}, callbackTransaction: transaction, callbackMetadata: eventstore.Metadata{CommandID: "inbox-vars", CorrelationID: "inbox-vars", OccurredAt: time.Unix(3, 0).UTC()}}
	VarSetValueInt64(messageCtx, "hp", 2)
	if got, ok := VarGetValueInt64(messageCtx, "hp"); !ok || got != 2 {
		t.Fatalf("callback read-after-write = %d, %v", got, ok)
	}
	if item, err := d.AttrsManager.LoadByCtx(messageCtx); err != nil || item.Load("hp").ToString() != "2" {
		t.Fatalf("direct attrs facade read = %#v, %v", item, err)
	}
	_, plaintext, err := repository.Load(ctx, "dice-1", id)
	if err != nil || string(plaintext) != string(baselinePayload) {
		t.Fatalf("callback wrote durable attribute directly: %s, %v", plaintext, err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("callback variable mutation not staged: %#v", work)
	}
}

func TestCallbackCharacterBindingLifecycleStagesWithoutDurableWrite(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-character-binding.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-character-binding-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	id := "QQ-Group:2002-QQ:1001"
	state := attributestate.State{DiceID: "dice-1", ID: id, AttrsType: "group_user", SecretRef: attributestate.SecretRef("dice-1", id), CreatedAt: 2, UpdatedAt: 2}
	payload, err := ds.NewDictVal(&ds.ValueMap{}).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Save(ctx, state, payload); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, AttrsManager: manager}, Group: &GroupInfo{GroupID: "QQ-Group:2002"}, Player: &GroupPlayerInfo{UserID: "QQ:1001"}, callbackTransaction: transaction, callbackMetadata: eventstore.Metadata{CommandID: "inbox-character", CorrelationID: "inbox-character", OccurredAt: time.Unix(3, 0).UTC()}}
	if err := manager.CharBindForCtx(messageCtx, "character-7", messageCtx.Group.GroupID, messageCtx.Player.UserID); err != nil {
		t.Fatal(err)
	}
	if binding, err := manager.CharGetBindingIdForCtx(messageCtx, messageCtx.Group.GroupID, messageCtx.Player.UserID); err != nil || binding != "character-7" {
		t.Fatalf("callback binding read = %q, %v", binding, err)
	}
	if groups := manager.CharUnbindAllForCtx(messageCtx, "character-7"); len(groups) != 1 || groups[0] != "QQ-Group:2002" {
		t.Fatalf("callback unbound groups = %#v", groups)
	}
	if binding, err := manager.CharGetBindingIdForCtx(messageCtx, messageCtx.Group.GroupID, messageCtx.Player.UserID); err != nil || binding != "" {
		t.Fatalf("callback unbinding read = %q, %v", binding, err)
	}
	persisted, _, err := repository.Load(ctx, "dice-1", id)
	if err != nil || persisted.BindingSheetID != "" {
		t.Fatalf("callback wrote binding directly: %#v, %v", persisted, err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("callback binding was not staged: %#v", work)
	}
}

func TestCallbackCharacterCreationStagesWithoutDurableWrite(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-character-creation.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-character-creation-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, AttrsManager: manager}, Group: &GroupInfo{GroupID: "QQ-Group:2002"}, Player: &GroupPlayerInfo{UserID: "QQ:1001"}, callbackTransaction: transaction, callbackMetadata: eventstore.Metadata{CommandID: "inbox-character-create", CorrelationID: "inbox-character-create", OccurredAt: time.Unix(3, 0).UTC()}}
	character, err := manager.CharNewForCtx(messageCtx, messageCtx.Player.UserID, "Alice", "coc7")
	if err != nil {
		t.Fatal(err)
	}
	if character.Name != "Alice" || character.AttrsType != service.AttrsTypeCharacter || character.SheetType != "coc7" {
		t.Fatalf("callback character = %#v", character)
	}
	if _, _, err := repository.Load(ctx, "dice-1", character.Id); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("callback wrote character directly: %v", err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("callback character creation was not staged: %#v", work)
	}
}

func TestCallbackCharacterRenameStagesWithoutDurableWrite(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-character-rename.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-character-rename-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	id := "character-7"
	state := attributestate.State{DiceID: "dice-1", ID: id, AttrsType: service.AttrsTypeCharacter, Name: "Alice", OwnerID: "QQ:1001", SheetType: "coc7", SecretRef: attributestate.SecretRef("dice-1", id), CreatedAt: 2, UpdatedAt: 2}
	payload, err := ds.NewDictVal(&ds.ValueMap{}).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Save(ctx, state, payload); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, AttrsManager: manager}, callbackTransaction: transaction, callbackMetadata: eventstore.Metadata{CommandID: "inbox-character-rename", CorrelationID: "inbox-character-rename", OccurredAt: time.Unix(3, 0).UTC()}}
	item, err := manager.LoadByIdForCtx(messageCtx, id)
	if err != nil {
		t.Fatal(err)
	}
	item.Name = "Alicia"
	if err := manager.SaveForCtx(messageCtx, item); err != nil {
		t.Fatal(err)
	}
	if staged, ok := transaction.AttributeState("dice-1", id); !ok || staged.Name != "Alicia" {
		t.Fatalf("callback rename state = %#v, %v", staged, ok)
	}
	persisted, _, err := repository.Load(ctx, "dice-1", id)
	if err != nil || persisted.Name != "Alice" {
		t.Fatalf("callback wrote rename directly: %#v, %v", persisted, err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("callback rename was not staged: %#v", work)
	}
}
func TestDurableLegacyConfigSnapshotIsProjected(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/config.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(configstate.ConfigProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "config-facade-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, Config: NewConfig(nil), DurableStore: store}
	repo := configstate.NewRepository(store)
	_, err = repo.DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandImportBaseline,
		Baseline: &configstate.Baseline{
			DiceID:        "dice-1",
			ConfigVersion: 1,
			Base:          configstate.BaseConfig{CommandCompatibleMode: true, MessageDelayRangeEnd: 1, UILogLimit: 100},
			Rate:          configstate.RateConfig{PersonalReplenishRate: "@every 3s", GroupReplenishRate: "@every 3s", PersonalBurst: 3, GroupBurst: 3, SpamSameCommandWindowSec: 30, SpamRecoveryMultiplierMax: 5},
			Quit:          configstate.QuitConfig{QuitInactiveThreshold: "0s", QuitInactiveBatchSize: 10},
			Extension:     configstate.ExtensionConfig{MaxExecuteTime: 12, MaxCocCardGen: 5},
			StoryLog:      configstate.StoryLogConfig{LogSizeNoticeCount: 500},
			Advanced:      configstate.AdvancedConfig{CustomReplyCooldown: 5},
			CommandPrefix: []string{"!"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	config := NewConfig(d)
	config.FriendAddComment = "projection-owned"
	config.Avatar = "avatar-ref"
	runtimePayload := json.RawMessage(`{"memoryLimitMiB":384}`)
	config.JsRuntimeOptions = map[string]json.RawMessage{"quickjs": runtimePayload}
	if err := d.DurableCommitConfigSnapshot(ctx, config, []string{"!"}, []string{"QQ:100"}, nil); err != nil {
		t.Fatal(err)
	}
	state, err := d.DurableConfigState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Base.FriendAddComment != "projection-owned" || state.PublicDice.Avatar != "avatar-ref" ||
		string(state.JS.JsRuntimeOptions["quickjs"]) != string(runtimePayload) {
		t.Fatalf("projected config = %#v", state)
	}
	view, advanced, _, err := d.DurableLegacyConfigView(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.FriendAddComment != "projection-owned" || view.Avatar != "avatar-ref" ||
		string(view.JsRuntimeOptions["quickjs"]) != string(runtimePayload) {
		t.Fatalf("legacy config view = %#v", view)
	}
	if advanced.CustomReplyCooldown != 5 {
		t.Fatalf("advanced view = %#v", advanced)
	}

	beforeVersion := state.Version
	config.MailPassword = "plaintext"

	if err := d.DurableCommitConfigSnapshot(ctx, config, []string{"!"}, []string{"QQ:100"}, &config.MailPassword); err == nil {
		t.Fatal("plaintext mail password was accepted")
	}
	afterState, err := d.DurableConfigState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterState.Version != beforeVersion {
		t.Fatalf("rejected secret advanced version: before=%d after=%d", beforeVersion, afterState.Version)
	}
}
func TestCallbackCharacterDeletionStagesWithoutDurableWrite(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-character-deletion.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-character-deletion-db", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	id := "character-7"
	state := attributestate.State{DiceID: "dice-1", ID: id, AttrsType: service.AttrsTypeCharacter, Name: "Alice", OwnerID: "QQ:1001", SheetType: "coc7", SecretRef: attributestate.SecretRef("dice-1", id), CreatedAt: 2, UpdatedAt: 2}
	payload, err := ds.NewDictVal(&ds.ValueMap{}).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Save(ctx, state, payload); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(store, collector)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, AttrsManager: manager}, callbackTransaction: transaction, callbackMetadata: eventstore.Metadata{CommandID: "inbox-character-delete", CorrelationID: "inbox-character-delete", OccurredAt: time.Unix(3, 0).UTC()}}
	if err := manager.CharDeleteForCtx(messageCtx, id); err != nil {
		t.Fatal(err)
	}
	if staged, ok := transaction.AttributeState("dice-1", id); !ok || staged.AttrsType != "" {
		t.Fatalf("callback deletion state = %#v, %v", staged, ok)
	}
	persisted, _, err := repository.Load(ctx, "dice-1", id)
	if err != nil || persisted.AttrsType != service.AttrsTypeCharacter {
		t.Fatalf("callback deleted character directly: %#v, %v", persisted, err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("callback character deletion was not staged: %#v", work)
	}
}

type durableSaveStoreStub struct{}

func (durableSaveStoreStub) Commit(context.Context, eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, errors.New("not used")
}
func (durableSaveStoreStub) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, errors.New("not used")
}
func (durableSaveStoreStub) Close() error { return nil }

func TestDurableSaveDoesNotWriteMigratedYAML(t *testing.T) {
	dir := t.TempDir()
	d := &Dice{
		BaseConfig:      BaseConfig{Name: "dice-1", DataDir: dir},
		Config:          NewConfig(nil),
		AdvancedConfig:  AdvancedConfig{CustomReplyCooldown: 5},
		DurableStore:    durableSaveStoreStub{},
		AttrsManager:    &AttrsManager{},
		Logger:          zap.NewNop().Sugar(),
		ImSession:       &IMSession{},
		LastUpdatedTime: 1,
	}
	d.Config.FriendAddComment = "must not be serialized"
	d.Save(false)
	if _, err := os.Stat(dir + "/serve.yaml"); !os.IsNotExist(err) {
		t.Fatalf("serve.yaml exists or stat failed: %v", err)
	}
	if _, err := os.Stat(dir + "/advanced.yaml"); !os.IsNotExist(err) {
		t.Fatalf("advanced.yaml exists or stat failed: %v", err)
	}
}

func TestDurableConfigExtensionRestartAndRebuild(t *testing.T) {
	ctx := context.Background()
	dsn := t.TempDir() + "/restart.db"
	openStore := func() (*eventstore.Database, *eventstore.GORMStore) {
		db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(configstate.ConfigProjection()), eventstore.WithProjection(extensionstate.ExtensionProjection()))
		return db, store
	}

	db, store := openStore()
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "restart-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	configRepo := configstate.NewRepository(store)
	if _, err := configRepo.DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandImportBaseline,
		Baseline: &configstate.Baseline{
			DiceID: "dice-1", ConfigVersion: 1,
			Base:          configstate.BaseConfig{CommandCompatibleMode: true, MessageDelayRangeEnd: 1, UILogLimit: 100},
			Rate:          configstate.RateConfig{PersonalReplenishRate: "@every 3s", GroupReplenishRate: "@every 3s", PersonalBurst: 3, GroupBurst: 3, SpamSameCommandWindowSec: 30, SpamRecoveryMultiplierMax: 5},
			Quit:          configstate.QuitConfig{QuitInactiveThreshold: "0s", QuitInactiveBatchSize: 10},
			Extension:     configstate.ExtensionConfig{MaxExecuteTime: 12, MaxCocCardGen: 5},
			StoryLog:      configstate.StoryLogConfig{LogSizeNoticeCount: 500},
			Advanced:      configstate.AdvancedConfig{CustomReplyCooldown: 5},
			CommandPrefix: []string{"!"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	extensionRepo := extensionstate.NewRepository(store)
	if _, err := extensionRepo.DecideAndAppend(ctx, extensionstate.State{}, 0, eventstore.Metadata{}, extensionstate.Command{
		Kind: extensionstate.CommandImportBaseline, DiceID: "dice-1",
		Baseline: &extensionstate.Baseline{Extensions: []extensionstate.ExtensionIdentity{{ID: "compat-ext", Name: "compat-ext", Version: "1", Source: "script"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, eventstore.PluginKVPutRequest{ExtensionID: "compat-ext", Key: "opaque", Value: []byte("value"), ExpectedVersion: 0}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_ = db

	_, restarted := openStore()
	defer restarted.Close()
	if _, err := restarted.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: restarted}
	configState, err := d.DurableConfigState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if configState.DiceID != "dice-1" || configState.Advanced.CustomReplyCooldown != 5 {
		t.Fatalf("restarted config state = %#v", configState)
	}
	extensionState, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(extensionState.ExtensionOrder) != 1 || extensionState.ExtensionOrder[0] != "compat-ext" {
		t.Fatalf("restarted extension state = %#v", extensionState)
	}
	kv, err := restarted.GetPluginKV(ctx, "compat-ext", "opaque")
	if err != nil || string(kv.Value) != "value" {
		t.Fatalf("restarted plugin KV = %#v, err=%v", kv, err)
	}
}
