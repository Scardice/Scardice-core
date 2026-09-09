package dice

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
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
	config.PublicDiceConfig.Avatar = "avatar-ref"
	if err := d.DurableCommitConfigSnapshot(ctx, config, []string{"!"}, []string{"QQ:100"}, nil); err != nil {
		t.Fatal(err)
	}
	state, err := d.DurableConfigState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Base.FriendAddComment != "projection-owned" || state.PublicDice.Avatar != "avatar-ref" {
		t.Fatalf("projected config = %#v", state)
	}
	view, advanced, _, err := d.DurableLegacyConfigView(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.FriendAddComment != "projection-owned" || view.PublicDiceConfig.Avatar != "avatar-ref" {
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
	serve, err := os.ReadFile(dir + "/serve.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serve), "must not be serialized") || strings.Contains(string(serve), "friendAddComment") {
		t.Fatalf("migrated config leaked into serve.yaml: %s", serve)
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
