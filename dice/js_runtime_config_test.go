package dice

import (
	"context"
	"testing"
	"time"

	"Scardice-core/core/configstate"
	"Scardice-core/eventstore"
)

func TestSetJSRuntimeConfigPersistsRoutesThroughDurableFacade(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/runtime-routes.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(configstate.ConfigProjection()))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "runtime-routes-db",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	repository := configstate.NewRepository(store)
	baseline := configstate.Baseline{
		DiceID: "dice-1", ConfigVersion: 1,
		Base:          configstate.BaseConfig{CommandCompatibleMode: true, MessageDelayRangeEnd: 1, UILogLimit: 100},
		Rate:          configstate.RateConfig{PersonalReplenishRate: "@every 3s", GroupReplenishRate: "@every 3s", PersonalBurst: 3, GroupBurst: 3, SpamSameCommandWindowSec: 30, SpamRecoveryMultiplierMax: 5},
		Quit:          configstate.QuitConfig{QuitInactiveThreshold: "0s", QuitInactiveBatchSize: 10},
		Extension:     configstate.ExtensionConfig{MaxExecuteTime: 12, MaxCocCardGen: 5},
		StoryLog:      configstate.StoryLogConfig{LogSizeNoticeCount: 500},
		Advanced:      configstate.AdvancedConfig{CustomReplyCooldown: 5},
		CommandPrefix: []string{"!"},
		DiceMasters:   []string{"QQ:100"},
	}
	if _, err := repository.DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandImportBaseline, Baseline: &baseline,
	}); err != nil {
		t.Fatal(err)
	}

	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}
	if err := d.ReloadConfigView(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.SetJSRuntimeConfig(ctx, "goja", map[string]string{"author/example": "goja"}); err != nil {
		t.Fatal(err)
	}
	state, err := d.DurableConfigState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := state.JS.JsRuntimeRoutes["author/example"]; got != "goja" {
		t.Fatalf("projected extension route = %q, want goja", got)
	}
	view := d.Config()
	if got := view.JsRuntimeRoutes["author/example"]; got != "goja" {
		t.Fatalf("config view extension route = %q, want goja", got)
	}
}
