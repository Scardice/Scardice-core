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

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testIDs struct{ next int }

func (g *testIDs) NewID() (string, error) { g.next++; return "event-" + string(rune('0'+g.next)), nil }

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

func TestExtensionTypedPatchValidationAndIdempotence(t *testing.T) {
	state, err := Replay([]TypedEvent{NewExtensionDiscoveredV1("dice-1", ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}), NewConfigDefinitionRegisteredV1(ConfigDefinition{ExtensionID: "alpha", Key: "count", Type: ConfigInt, Default: IntValue(1)})})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "count", Value: IntValue(3)})
	if err != nil || len(decision.Events) != 1 {
		t.Fatalf("valid patch = %#v, err=%v", decision, err)
	}
	state, err = Replay(append([]TypedEvent{NewExtensionDiscoveredV1("dice-1", ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}), NewConfigDefinitionRegisteredV1(ConfigDefinition{ExtensionID: "alpha", Key: "count", Type: ConfigInt, Default: IntValue(1)})}, decision.Events...))
	if err != nil {
		t.Fatal(err)
	}
	noOp, err := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "count", Value: IntValue(3)})
	if err != nil || len(noOp.Events) != 0 {
		t.Fatalf("repeat should be idempotent: %#v, err=%v", noOp, err)
	}
	if _, err := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "count", Value: StringValue("bad")}); !errors.Is(err, ErrInvalidConfigValue) {
		t.Fatalf("invalid typed value = %v", err)
	}
	if _, err := Decide(state, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "missing", Value: IntValue(1)}); !errors.Is(err, ErrUnknownConfig) {
		t.Fatalf("unknown key = %v", err)
	}
	remove, err := Decide(state, Command{Kind: CommandUnregisterConfig, ExtensionID: "alpha", Key: "count"})
	if err != nil || len(remove.Events) != 1 || remove.Events[0].EventType() != EventConfigDefinitionRemoved {
		t.Fatalf("unregister config = %#v, err=%v", remove, err)
	}
	removed, err := Reduce(state, remove.Events[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := removed.ConfigDefinitions["alpha"]["count"]; ok {
		t.Fatalf("definition still present after unregister: %#v", removed.ConfigDefinitions)
	}
	if _, ok := removed.ConfigValues["alpha"]["count"]; ok {
		t.Fatalf("value still present after unregister: %#v", removed.ConfigValues)
	}
}

func TestExtensionRepositoryExpectedVersionAndNoWriteOnInvalid(t *testing.T) {
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/extension.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(ExtensionProjection()))
	repo := NewRepository(store)
	ctx := context.Background()
	meta := testMetadata()
	create := Command{Kind: CommandDiscover, DiceID: "dice-1", Identity: ExtensionIdentity{ID: "alpha", Name: "Alpha", Version: "1", Source: "builtin"}}
	result, err := repo.DecideAndAppend(ctx, State{}, 0, meta, create)
	if err != nil {
		t.Fatal(err)
	}
	if result.StreamVersions[ExtensionStream("dice-1")] != 1 {
		t.Fatalf("commit result = %#v", result)
	}
	loaded, err := repo.Load(ctx, "dice-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DecideAndAppend(ctx, loaded, loaded.Version, meta, Command{Kind: CommandSetConfig, ExtensionID: "alpha", Key: "unknown", Value: StringValue("x")}); !errors.Is(err, ErrUnknownConfig) {
		t.Fatalf("invalid command = %v", err)
	}
	after, err := repo.Load(ctx, "dice-1")
	if err != nil || after.Version != loaded.Version {
		t.Fatalf("invalid command wrote state: %#v, %v", after, err)
	}
	if _, err := repo.DecideAndAppend(ctx, loaded, 0, meta, Command{Kind: CommandEnable, ExtensionID: "alpha"}); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale version = %v", err)
	}
	projected, err := ReadProjected(ctx, store, "dice-1")
	if err != nil || projected.DiceID != "dice-1" || projected.Extensions["alpha"].ID != "alpha" {
		t.Fatalf("projected state = %#v, err = %v", projected, err)
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
