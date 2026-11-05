package dice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/configstate"
	"Scardice-core/core/execution"
	"Scardice-core/core/extensionstate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"

	ds "github.com/sealdice/dicescript"
)

// attributeStreamCount counts staged attribute appends. A callback context for
// a first-seen group/player also stages those canonical streams in the same
// root, which is unrelated to the attribute mutation under test.
func attributeStreamCount(work eventstore.UnitOfWork) int {
	count := 0
	for _, stream := range work.Streams {
		if stream.Stream.AggregateType == attributestate.AggregateType {
			count++
		}
	}
	return count
}

func newStateFacadeCallbackContext(
	t *testing.T,
	d *Dice,
	transaction *DurableCallbackTransaction,
	metadata eventstore.Metadata,
	groupID string,
	userID string,
) *MsgContext {
	t.Helper()
	if d.ImSession == nil {
		d.ImSession = &IMSession{Parent: d}
	}
	endpoint := newCanonicalTestEndpoint(d, "QQ:fixture-bot")
	message := newGroupMsg(groupID, userID, "")
	ctx, err := NewDomainMsgContext(transaction, d, d.ImSession, endpoint, message)
	if err != nil {
		t.Fatalf("build state facade callback context: %v", err)
	}
	ctx.callbackMetadata = metadata
	ctx.executionContext = transaction.executionContext
	t.Cleanup(ctx.releaseExecutionState)
	return ctx
}

func TestDurableCompatibilityConfigAndStorage(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/compat.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "compat-facade-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	d := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-1"},
		DurableStore:  store,
		ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json"),
	}
	d.ConfigManager.SetOwner(d)
	seedCanonicalTestConfigBaseline(t, d)
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
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "template-config-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, ConfigManager: NewConfigManager(t.TempDir() + "/plugin-configs.json")}
	d.ConfigManager.SetOwner(d)
	seedCanonicalTestConfigBaseline(t, d)
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
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "identity-db",
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

	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}
	seedCanonicalTestConfigBaseline(t, d)
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
	store := eventstore.NewStore(db)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-plugin-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, eventstore.Metadata{})
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
	store := eventstore.NewStore(db)
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-context-storage-db", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, eventstore.Metadata{})
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
	store := eventstore.NewStore(db, eventstore.WithProjection(extensionstate.ExtensionProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-config-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, eventstore.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}
	metadata := eventstore.Metadata{CommandID: "inbox-1", CorrelationID: "inbox-1", OccurredAt: time.Unix(2, 0).UTC()}
	identity := extensionstate.ExtensionIdentity{ID: "callback-ext", Name: "callback-ext", Version: "1.0.0", Source: "js"}
	definition := extensionstate.ConfigDefinition{ExtensionID: identity.ID, Key: "enabled", Type: extensionstate.ConfigBool, Default: extensionstate.BoolValue(false), DefaultSet: true}
	if err := d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{Kind: extensionstate.CommandDiscover, DiceID: "dice-1", Identity: identity}); err != nil {
		t.Fatal(err)
	}
	if err := d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{Kind: extensionstate.CommandRegisterConfig, ExtensionID: identity.ID, Definition: definition}); err != nil {
		t.Fatal(err)
	}
	if err := d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{Kind: extensionstate.CommandSetConfig, ExtensionID: identity.ID, Key: definition.Key, Value: extensionstate.BoolValue(true)}); err != nil {
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
	store := eventstore.NewStore(db, eventstore.WithProjection(extensionstate.ExtensionProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-context-config-db", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
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
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, eventstore.Metadata{})
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
	persisted, err := repository.Load(ctx, "dice-1")
	if err != nil || persisted.ConfigValues["callback-ext"]["enabled"].Bool {
		t.Fatalf("callback config committed directly: %#v, %v", persisted, err)
	}
	if _, exists := persisted.ConfigValues["callback-ext"]["access token"]; exists {
		t.Fatal("callback sensitive config committed before terminal unit of work")
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Streams[0].Events) != 2 || len(work.PluginKVUpdates) != 0 {
		t.Fatalf("callback config work = %#v", work)
	}
}

func TestSensitiveConfigPreservesRawKeyAcrossDirectAndCallbackPaths(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  t.TempDir() + "/sensitive-config-key.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithProjection(configstate.ConfigProjection()),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "sensitive-config-key",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	const (
		pluginName = "raw-config-key"
		configKey  = "access$t token"
	)
	d := &Dice{
		BaseConfig:    BaseConfig{Name: "dice-raw-config"},
		DurableStore:  store,
		ConfigManager: NewConfigManager(""),
	}
	d.ConfigManager.SetOwner(d)
	seedCanonicalTestConfigBaseline(t, d)
	ext := &ExtInfo{Name: pluginName, Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigManager.RegisterPluginConfig(pluginName, &ConfigItem{
		Key: configKey, Type: "string", DefaultValue: "declared-default", Value: "declared-default",
	}); err != nil {
		t.Fatal(err)
	}
	longestConfigKey := strings.Repeat("k", extensionstate.MaxExtensionIdentityPartBytes)
	if err := d.ConfigManager.RegisterPluginConfig(pluginName, &ConfigItem{
		Key: longestConfigKey, Type: "string", DefaultValue: "long-key-default", Value: "long-key-default",
	}); err != nil {
		t.Fatalf("register longest supported config key: %v", err)
	}
	if err := d.ConfigManager.SetConfig(pluginName, configKey, "direct-value"); err != nil {
		t.Fatal(err)
	}
	repository := extensionstate.NewRepository(store)
	persisted, err := repository.Load(ctx, d.BaseConfig.Name)
	if err != nil || persisted.ConfigValues[pluginName][configKey].String != "direct-value" ||
		persisted.ConfigValues[pluginName][longestConfigKey].String != "long-key-default" {
		t.Fatalf("direct typed config with raw keys = %#v, err=%v", persisted.ConfigValues[pluginName], err)
	}

	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, eventstore.Metadata{})
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
	persisted, err = repository.Load(ctx, d.BaseConfig.Name)
	if err != nil || persisted.ConfigValues[pluginName][configKey].String != "direct-value" {
		t.Fatalf("callback config committed before terminal unit of work: values=%#v, err=%v", persisted.ConfigValues[pluginName], err)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Streams[0].Events) != 1 || len(work.PluginKVUpdates) != 0 {
		t.Fatalf("callback sensitive config work = %#v", work)
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatal(err)
	}
	persisted, err = repository.Load(ctx, d.BaseConfig.Name)
	if err != nil || persisted.ConfigValues[pluginName][configKey].String != "callback-value" {
		t.Fatalf("committed callback typed config = %#v, err=%v", persisted.ConfigValues[pluginName], err)
	}
}

func TestDurableCallbackTransactionStagesAttributeSnapshotWithSecret(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-attrs.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-attrs-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	metadata := eventstore.Metadata{CommandID: "inbox-attrs", CorrelationID: "inbox-attrs", OccurredAt: time.Unix(2, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	state := attributestate.State{DiceID: "dice-1", ID: "QQ-Group:2002-QQ:1001", AttrsType: "group_user", SecretRef: attributestate.SecretRef("dice-1", "QQ-Group:2002-QQ:1001"), CreatedAt: 2, UpdatedAt: 2}
	item, err := manager.LoadByTransaction(ctx, transaction, state.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = item.Store("hp", ds.NewIntVal(1)); err != nil {
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

func TestDurableCallbackTransactionUsesOneCanonicalAttributeHandle(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-attrs-overlay.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-attrs-overlay-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	state := attributestate.State{DiceID: "dice-1", ID: "QQ-Group:2002-QQ:1001", AttrsType: "group_user", SecretRef: attributestate.SecretRef("dice-1", "QQ-Group:2002-QQ:1001"), CreatedAt: 2, UpdatedAt: 2}
	sharedValues := &ds.ValueMap{}
	sharedValues.Store("hp", ds.NewIntVal(1))
	seedPayload, err := ds.NewDictVal(sharedValues).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repository.Save(ctx, state, seedPayload); err != nil {
		t.Fatal(err)
	}
	metadata := eventstore.Metadata{CommandID: "inbox-overlay", CorrelationID: "inbox-overlay", OccurredAt: time.Unix(3, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	first, err := manager.LoadByTransaction(ctx, transaction, state.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.LoadByTransaction(ctx, transaction, state.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("one root loaded two attribute handles for one participant")
	}
	if err = first.Store("hp", ds.NewIntVal(2)); err != nil {
		t.Fatal(err)
	}
	if got := second.Load("hp"); got == nil || got.ToString() != "2" {
		t.Fatalf("canonical handle did not read its own write: %v", got)
	}
	_, persistedPayload, err := repository.Load(ctx, state.DiceID, state.ID)
	if err != nil {
		t.Fatal(err)
	}
	persistedValue, err := ds.VMValueFromJSON(persistedPayload)
	if err != nil {
		t.Fatal(err)
	}
	persistedDict, ok := persistedValue.ReadDictData()
	if !ok {
		t.Fatal("persisted attribute payload is not a dictionary")
	}
	if got, exists := persistedDict.Dict.Load("hp"); !exists || got.ToString() != "1" {
		t.Fatalf("canonical participant wrote through before commit: %v, exists=%v", got, exists)
	}
	if err := transaction.Finalize(ctx); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.SecretUpdates) != 1 {
		t.Fatalf("canonical attribute mutation was not staged: %#v", work)
	}
}

func TestCallbackVariableOverlayReadsOwnWriteWithoutMutatingDurableState(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-variable-overlay.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-variable-overlay-db",
		CompletedAt: time.Unix(1, 0).UTC(),
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
	metadata := eventstore.Metadata{CommandID: "inbox-vars", CorrelationID: "inbox-vars", OccurredAt: time.Unix(3, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	d := &Dice{
		BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store,
		AttrsManager: &AttrsManager{durable: repository, store: store, diceID: "dice-1"},
	}
	messageCtx := newStateFacadeCallbackContext(t, d, transaction, metadata, "QQ-Group:2002", "QQ:1001")
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
	if attributeStreamCount(work) != 1 || len(work.SecretUpdates) != 1 {
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
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-character-binding-db",
		CompletedAt: time.Unix(1, 0).UTC(),
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
	metadata := eventstore.Metadata{CommandID: "inbox-character", CorrelationID: "inbox-character", OccurredAt: time.Unix(3, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, AttrsManager: manager}
	messageCtx := newStateFacadeCallbackContext(t, d, transaction, metadata, "QQ-Group:2002", "QQ:1001")
	if err := manager.CharBindForCtx(messageCtx, "character-7", messageCtx.Group.GroupID(), messageCtx.Player.UserID()); err != nil {
		t.Fatal(err)
	}
	if binding, err := manager.CharGetBindingIdForCtx(messageCtx, messageCtx.Group.GroupID(), messageCtx.Player.UserID()); err != nil || binding != "character-7" {
		t.Fatalf("callback binding read = %q, %v", binding, err)
	}
	groups, err := manager.CharUnbindAllForCtx(messageCtx, "character-7")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != "QQ-Group:2002" {
		t.Fatalf("callback unbound groups = %#v", groups)
	}
	if binding, err := manager.CharGetBindingIdForCtx(messageCtx, messageCtx.Group.GroupID(), messageCtx.Player.UserID()); err != nil || binding != "" {
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
	if attributeStreamCount(work) != 1 || len(work.SecretUpdates) != 1 {
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
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-character-creation-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	metadata := eventstore.Metadata{CommandID: "inbox-character-create", CorrelationID: "inbox-character-create", OccurredAt: time.Unix(3, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, AttrsManager: manager}
	messageCtx := newStateFacadeCallbackContext(t, d, transaction, metadata, "QQ-Group:2002", "QQ:1001")
	character, err := manager.CharNewForCtx(messageCtx, messageCtx.Player.UserID(), "Alice", "coc7")
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
	if attributeStreamCount(work) != 1 || len(work.SecretUpdates) != 1 {
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
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-character-rename-db",
		CompletedAt: time.Unix(1, 0).UTC(),
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
	metadata := eventstore.Metadata{CommandID: "inbox-character-rename", CorrelationID: "inbox-character-rename", OccurredAt: time.Unix(3, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, AttrsManager: manager}, callbackTransaction: transaction, callbackMetadata: metadata}
	item, err := manager.LoadByIdForCtx(messageCtx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetName("Alicia"); err != nil {
		t.Fatal(err)
	}
	staged := item.State()
	if staged.Name != "Alicia" {
		t.Fatalf("callback rename state = %#v", staged)
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
	store := eventstore.NewStore(db, eventstore.WithProjection(configstate.ConfigProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "config-facade-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}
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
	if err = d.ReloadConfigView(ctx); err != nil {
		t.Fatal(err)
	}
	config, _ := d.ConfigEditSnapshot()
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
	config, _ = d.ConfigEditSnapshot()
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
	store := eventstore.NewStore(db, eventstore.WithProjection(attributestate.Projection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "callback-character-deletion-db", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
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
	metadata := eventstore.Metadata{CommandID: "inbox-character-delete", CorrelationID: "inbox-character-delete", OccurredAt: time.Unix(3, 0).UTC()}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(ctx, store, collector, metadata)
	if err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{durable: repository, store: store, diceID: "dice-1"}
	messageCtx := &MsgContext{Dice: &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, AttrsManager: manager}, callbackTransaction: transaction, callbackMetadata: metadata}
	if err := manager.CharDeleteForCtx(messageCtx, id); err != nil {
		t.Fatal(err)
	}
	item, err := manager.LoadByIdForCtx(messageCtx, id)
	if err != nil {
		t.Fatal(err)
	}
	staged := item.State()
	if staged.AttrsType != "" {
		t.Fatalf("callback deletion state = %#v", staged)
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
func TestDurableConfigExtensionRestartAndRebuild(t *testing.T) {
	ctx := context.Background()
	dsn := t.TempDir() + "/restart.db"
	openStore := func() (*eventstore.Database, *eventstore.GORMStore) {
		db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		store := eventstore.NewStore(db, eventstore.WithProjection(configstate.ConfigProjection()), eventstore.WithProjection(extensionstate.ExtensionProjection()))
		return db, store
	}

	db, store := openStore()
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "restart-db",
		CompletedAt: time.Unix(1, 0).UTC(),
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
