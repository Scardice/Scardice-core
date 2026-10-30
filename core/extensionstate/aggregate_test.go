package extensionstate

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"Scardice-core/eventstore"
)

func testMetadata() eventstore.Metadata {
	return eventstore.Metadata{CommandID: "command", CorrelationID: "correlation", OccurredAt: time.Unix(1700000000, 0).UTC()}
}

func TestExtensionBaselineReplayAndExcludesRuntimeFields(t *testing.T) {
	baseline := Baseline{
		Extensions:      []ExtensionIdentity{{ID: "alpha", Name: "Alpha", Version: "1.2.3", Source: "builtin"}, {ID: "beta", Name: "Beta", Version: "2.0.0", Source: "script"}},
		Enable:          []string{"alpha"},
		Defaults:        []DefaultCommandUpdate{{ExtensionID: "alpha", AutoActive: true, DisabledCommands: []string{"roll"}}},
		Definitions:     []ConfigDefinition{{ExtensionID: "alpha", Key: "enabled", Type: ConfigBool, Default: BoolValue(false)}, {ExtensionID: "alpha", Key: "mode", Type: ConfigOption, Options: []string{"safe", "fast"}, Default: OptionValue("safe")}},
		Values:          []ConfigUpdate{{ExtensionID: "alpha", Key: "enabled", Value: BoolValue(true)}, {ExtensionID: "alpha", Key: "mode", Value: OptionValue("fast")}},
		DisabledScripts: []string{"legacy.js"},
	}
	decision, err := Decide(State{}, Command{Kind: CommandImportBaseline, DiceID: "dice-1", Baseline: &baseline})
	if err != nil {
		t.Fatal(err)
	}
	state, err := Replay(decision.Events)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.ExtensionOrder, []string{"alpha", "beta"}) || !state.EnabledExtensions["alpha"] || state.EnabledExtensions["beta"] {
		t.Fatalf("baseline state = %#v", state)
	}
	if state.ConfigValues["alpha"]["mode"].String != "fast" || !state.DisabledScripts["legacy.js"] || !state.DefaultCommands["alpha"].AutoActive || !state.DefaultCommands["alpha"].DisabledCommands["roll"] {
		t.Fatalf("config state = %#v", state)
	}
	payload, err := MarshalEvents(decision.Events)
	if err != nil {
		t.Fatal(err)
	}
	for _, excluded := range []string{"callback", "taskList", "heap", "realm", "pluginKV", "storage", "runtime", "opaque"} {
		if strings.Contains(string(payload), excluded) {
			t.Fatalf("event payload contains excluded field %q: %s", excluded, payload)
		}
	}
}

func TestExtensionIdentityAdoptsLegacyPlaceholderAndTracksUpgrades(t *testing.T) {
	legacy := ExtensionIdentity{ID: "alpha", Name: "alpha", Version: "legacy", Source: "legacy"}
	state, err := Replay([]TypedEvent{NewExtensionDiscoveredV1("dice-1", legacy)})
	if err != nil {
		t.Fatal(err)
	}

	actual := ExtensionIdentity{ID: "alpha", Name: "Alpha", Aliases: []string{"a"}, Version: "1.0.0", Source: "script"}
	decision, err := Decide(state, Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: actual})
	if err != nil || len(decision.Events) != 1 || decision.Events[0].EventType() != EventExtensionIdentityChanged {
		t.Fatalf("legacy identity adoption = %#v, err=%v", decision, err)
	}
	state, err = Reduce(state, decision.Events[0])
	if err != nil || !reflectIdentityEqual(state.Extensions["alpha"], actual) {
		t.Fatalf("adopted identity = %#v, err=%v", state.Extensions["alpha"], err)
	}

	upgraded := actual
	upgraded.Version = "1.1.0"
	decision, err = Decide(state, Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: upgraded})
	if err != nil || len(decision.Events) != 1 {
		t.Fatalf("same-source upgrade = %#v, err=%v", decision, err)
	}
	state, err = Reduce(state, decision.Events[0])
	if err != nil || state.Extensions["alpha"].Version != "1.1.0" {
		t.Fatalf("upgraded identity = %#v, err=%v", state.Extensions["alpha"], err)
	}

	replaced := upgraded
	replaced.Source = "package:other"
	if _, err = Decide(state, Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: replaced}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("cross-source replacement error = %v", err)
	}
}

func TestExtensionTypedPatchValidationAndIdempotence(t *testing.T) {
	state, decisionErr := Replay([]TypedEvent{NewExtensionDiscoveredV1("dice-1", ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}), NewConfigDefinitionRegisteredV1(ConfigDefinition{ExtensionID: "alpha", Key: "count", Type: ConfigInt, Default: IntValue(1)})})
	if decisionErr != nil {
		t.Fatal(decisionErr)
	}
	decision, decisionErr := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "count", Value: IntValue(3)})
	if decisionErr != nil || len(decision.Events) != 1 {
		t.Fatalf("valid patch = %#v, err=%v", decision, decisionErr)
	}
	state, decisionErr = Replay(append([]TypedEvent{NewExtensionDiscoveredV1("dice-1", ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}), NewConfigDefinitionRegisteredV1(ConfigDefinition{ExtensionID: "alpha", Key: "count", Type: ConfigInt, Default: IntValue(1)})}, decision.Events...))
	if decisionErr != nil {
		t.Fatal(decisionErr)
	}
	noOp, decisionErr := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "count", Value: IntValue(3)})
	if decisionErr != nil || len(noOp.Events) != 0 {
		t.Fatalf("repeat should be idempotent: %#v, err=%v", noOp, decisionErr)
	}
	if _, err := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "count", Value: StringValue("bad")}); !errors.Is(err, ErrInvalidConfigValue) {
		t.Fatalf("invalid typed value = %v", err)
	}
	if _, err := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "missing", Value: IntValue(1)}); !errors.Is(err, ErrUnknownConfig) {
		t.Fatalf("unknown key = %v", err)
	}
	remove, decisionErr := Decide(state, Command{Kind: CommandUnregisterConfig, ExtensionID: "alpha", Key: "count"})
	if decisionErr != nil || len(remove.Events) != 1 || remove.Events[0].EventType() != EventConfigDefinitionRemoved {
		t.Fatalf("unregister config = %#v, err=%v", remove, decisionErr)
	}
	removed, decisionErr := Reduce(state, remove.Events[0])
	if decisionErr != nil {
		t.Fatal(decisionErr)
	}
	if _, ok := removed.ConfigDefinitions["alpha"]["count"]; ok {
		t.Fatalf("definition still present after unregister: %#v", removed.ConfigDefinitions)
	}
	if _, ok := removed.ConfigValues["alpha"]["count"]; ok {
		t.Fatalf("value still present after unregister: %#v", removed.ConfigValues)
	}
}

func TestExtensionRepositoryExpectedVersionAndNoWriteOnInvalid(t *testing.T) {
	db, repositoryErr := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/extension.db"})
	if repositoryErr != nil {
		t.Fatal(repositoryErr)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(ExtensionProjection()))
	repo := NewRepository(store)
	ctx := context.Background()
	meta := testMetadata()
	create := Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}}
	result, repositoryErr := repo.DecideAndAppend(ctx, State{}, 0, meta, create)
	if repositoryErr != nil {
		t.Fatal(repositoryErr)
	}
	if result.StreamVersions[ExtensionStream("dice-1")] != 1 {
		t.Fatalf("commit result = %#v", result)
	}
	loaded, repositoryErr := repo.Load(ctx, "dice-1")
	if repositoryErr != nil {
		t.Fatal(repositoryErr)
	}
	if _, err := repo.DecideAndAppend(ctx, loaded, loaded.Version, meta, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "unknown", Value: StringValue("x")}); !errors.Is(err, ErrUnknownConfig) {
		t.Fatalf("invalid command = %v", err)
	}
	after, repositoryErr := repo.Load(ctx, "dice-1")
	if repositoryErr != nil || after.Version != loaded.Version {
		t.Fatalf("invalid command wrote state: %#v, %v", after, repositoryErr)
	}
	if _, err := repo.DecideAndAppend(ctx, loaded, 0, meta, Command{Kind: CommandEnable, ExtensionID: "alpha"}); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale version = %v", err)
	}
	projected, repositoryErr := ReadProjected(ctx, store, "dice-1")
	if repositoryErr != nil || projected.DiceID != "dice-1" || projected.Extensions["alpha"].ID != "alpha" {
		t.Fatalf("projected state = %#v, err = %v", projected, repositoryErr)
	}
}

func TestExtensionReplayDigestAndProjection(t *testing.T) {
	events := []TypedEvent{
		NewExtensionDiscoveredV1("dice-1", ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}),
		NewExtensionEnablementChangedV1("alpha", true),
		NewScriptDisablementChangedV1("script.js", true),
	}
	state, err := Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalEvents(events)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEvents(encoded)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := Replay(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, replayed) {
		t.Fatalf("replay digest mismatch: %#v != %#v", state, replayed)
	}
	if ExtensionProjection().Name == "" || ExtensionProjection().Apply == nil {
		t.Fatal("projection descriptor incomplete")
	}
}

func TestReadProjectedTreatsAbsentExtensionStreamAsEmpty(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/empty-extension.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithProjection(ExtensionProjection()))

	state, err := ReadProjected(ctx, store, "dice-1")
	if err != nil {
		t.Fatalf("ReadProjected() on an absent stream = %v", err)
	}
	if state.Version != 0 || state.DiceID != "" || len(state.Extensions) != 0 {
		t.Fatalf("absent stream state = %#v, want an empty state", state)
	}
}

func TestReadProjectedReportsMissingRowWhenExtensionEventsExist(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/missing-extension-projection.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithProjection(ExtensionProjection()))
	repository := NewRepository(store)
	identity := ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}
	if _, err := repository.DecideAndAppend(ctx, State{}, 0, testMetadata(), Command{
		Kind: CommandDiscover, DiceID: "dice-1", Identity: identity,
	}); err != nil {
		t.Fatal(err)
	}

	deleteResult := database.GORM().
		Where("projection_name = ? AND row_key = ?", ExtensionProjectionName, "dice-1").
		Delete(&projectionRow{})
	if deleteResult.Error != nil {
		t.Fatal(deleteResult.Error)
	}
	if deleteResult.RowsAffected != 1 {
		t.Fatalf("deleted projection rows = %d, want 1", deleteResult.RowsAffected)
	}
	persisted, err := repository.Load(ctx, "dice-1")
	if err != nil || persisted.Version != 1 {
		t.Fatalf("persisted extension state = %#v, err = %v", persisted, err)
	}

	if _, err := ReadProjected(ctx, store, "dice-1"); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("ReadProjected() with stream events but no projection row = %v, want ErrNotFound", err)
	}
}

type extensionProjectionRaceStore struct {
	eventstore.Store
	reader   projectionReader
	appended bool
}

func (s *extensionProjectionRaceStore) ReadProjectionRow(ctx context.Context, projectionName, rowKey string) (eventstore.ProjectionRow, error) {
	row, err := s.reader.ReadProjectionRow(ctx, projectionName, rowKey)
	if errors.Is(err, eventstore.ErrNotFound) && !s.appended {
		s.appended = true
		identity := ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}
		if _, appendErr := NewRepository(s.Store).DecideAndAppend(ctx, State{}, 0, testMetadata(), Command{
			Kind: CommandDiscover, DiceID: "dice-1", Identity: identity,
		}); appendErr != nil {
			return eventstore.ProjectionRow{}, appendErr
		}
	}
	return row, err
}

func TestReadProjectedRechecksProjectionAfterConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/extension-append-race.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithProjection(ExtensionProjection()))
	racingStore := &extensionProjectionRaceStore{Store: store, reader: store}

	state, err := ReadProjected(ctx, racingStore, "dice-1")
	if err != nil {
		t.Fatalf("ReadProjected() after an append publishes the missing row = %v", err)
	}
	if state.Version != 1 || state.DiceID != "dice-1" || state.Extensions["alpha"].ID != "alpha" {
		t.Fatalf("projected state after concurrent append = %#v", state)
	}
}
