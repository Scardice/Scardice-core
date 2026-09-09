package configstate

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/eventstore"
)

func testBaseline() Baseline {
	return Baseline{DiceID: "dice-1", ConfigVersion: 1, Base: BaseConfig{CommandCompatibleMode: true, NoticeIDs: []string{"UI:1001"}, MessageDelayRangeEnd: .4, DiceRandomMode: "pcg", VMVersionForReply: "v1", VMVersionForDeck: "v2", VMVersionForCustomText: "v2", VMVersionForMsg: "v2"}, Rate: RateConfig{PersonalReplenishRate: "@every 3s", GroupReplenishRate: "@every 3s", PersonalBurst: 3, GroupBurst: 3, SpamSameCommandWindowSec: 30, SpamRecoveryMultiplierMax: 5}, Quit: QuitConfig{QuitInactiveThreshold: "0s", QuitInactiveBatchSize: 10, QuitInactiveBatchWait: 30}, Advanced: AdvancedConfig{CustomReplyCooldown: 5}, CommandPrefix: []string{"!", "."}, DiceMasters: []string{"UI:1001"}}
}
func decideEvents(t *testing.T, state State, command Command) []TypedEvent {
	t.Helper()
	decision, err := Decide(state, command)
	if err != nil {
		t.Fatal(err)
	}
	return decision.Events
}

func TestDecideBaselineEmitsExplicitGroupsAndReplays(t *testing.T) {
	baseline := testBaseline()
	decision, err := Decide(State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Events) < 4 {
		t.Fatalf("events=%d, want explicit group events", len(decision.Events))
	}
	state, err := Replay(decision.Events)
	if err != nil {
		t.Fatal(err)
	}
	if state.DiceID != baseline.DiceID || state.Base.MessageDelayRangeEnd != .4 || state.Outer.CommandPrefix[0] != "!" {
		t.Fatalf("state=%+v", state)
	}
	if state.Mail.MailPasswordRef != "" {
		t.Fatal("raw secret/reference unexpectedly imported")
	}
}
func TestDecideTypedPatchIsIdempotent(t *testing.T) {
	baseline := testBaseline()
	state, err := Replay(decideEvents(t, State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline}))
	if err != nil {
		t.Fatal(err)
	}
	patch := ConfigPatch{Base: &BaseConfig{CommandCompatibleMode: false, MessageDelayRangeEnd: .8}}
	decision, err := Decide(state, Command{Kind: CommandPatch, Patch: &patch})
	if err != nil || len(decision.Events) != 1 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	state, err = Replay(append(decideEvents(t, State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline}), decision.Events...))
	if err != nil || state.Base.MessageDelayRangeEnd != .8 || state.Base.CommandCompatibleMode {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	repeat, err := Decide(state, Command{Kind: CommandPatch, Patch: &patch})
	if err != nil {
		t.Fatal(err)
	}
	if len(repeat.Events) != 0 {
		t.Fatalf("repeat emitted %d events", len(repeat.Events))
	}
}
func TestInvalidPatchDoesNotDecide(t *testing.T) {
	baseline := testBaseline()
	state, err := Replay(decideEvents(t, State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decide(state, Command{Kind: CommandPatch, Patch: &ConfigPatch{Rate: &RateConfig{PersonalBurst: -1}}})
	if !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("err=%v", err)
	}
}
func TestRepositoryConflictAndProjectionReplay(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/config.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(ConfigProjection()))
	repo := NewRepository(store)
	baseline := testBaseline()
	metadata := eventstore.Metadata{CommandID: "c1", CorrelationID: "r1", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	result, err := repo.DecideAndAppend(ctx, State{}, 0, metadata, Command{Kind: CommandImportBaseline, Baseline: &baseline})
	if err != nil {
		t.Fatal(err)
	}
	if result.StreamVersions[ConfigStream("dice-1")] == 0 {
		t.Fatalf("result=%+v", result)
	}
	_, err = repo.DecideAndAppend(ctx, State{Version: 1, DiceID: "dice-1", ConfigVersion: 1}, 0, metadata, Command{Kind: CommandPatch, Patch: &ConfigPatch{Base: &BaseConfig{CommandCompatibleMode: true, MessageDelayRangeEnd: 1, VersionCode: 1}}})
	if !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("conflict=%v", err)
	}
	projected, err := ReadProjected(ctx, store, "dice-1")
	if err != nil || projected.DiceID != "dice-1" {
		t.Fatalf("projected=%+v err=%v", projected, err)
	}
	if _, err := store.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: ConfigProjectionVersion}); err != nil {
		t.Fatal(err)
	}
}
func TestRepositoryGeneratesDistinctIDsForExplicitMultiEventMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/config-ids.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(ConfigProjection()))
	repo := NewRepository(store)
	baseline := testBaseline()
	events := decideEvents(t, State{}, Command{Kind: CommandImportBaseline, Baseline: &baseline})
	metadata := eventstore.Metadata{EventID: "explicit-id", CommandID: "command-id", CorrelationID: "correlation-id", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	if _, err := repo.AppendTyped(ctx, baseline.DiceID, 0, metadata, events); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Load(ctx, ConfigStream(baseline.DiceID), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != len(events) || persisted[0].EventID != metadata.EventID {
		t.Fatalf("persisted event IDs=%v, want %d events with first %q", persisted, len(events), metadata.EventID)
	}
	seen := map[string]bool{}
	for _, event := range persisted {
		if event.EventID == "" || seen[event.EventID] {
			t.Fatalf("duplicate or empty event ID: %v", persisted)
		}
		seen[event.EventID] = true
	}
}
