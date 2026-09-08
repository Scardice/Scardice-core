package groupstate

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"Scardice-core/eventstore"
)

func TestGroupEventsReplayIntoRecordWithoutAttrsOrModeration(t *testing.T) {
	events := []TypedEvent{
		NewGroupCreatedV1("dice-1", "group-1", "name", 1700000000),
		NewGroupActivationChangedV1("bot-1", true, true),
		NewGroupExtensionChangedV1("coc7", true),
		NewGroupSystemChangedV1("coc7"),
		NewGroupWelcomeChangedV1(true, "hello"),
		NewGroupBotListChangedV1("bot-2", true),
		NewGroupPrivilegeChangedV1("user-1", 60),
	}

	state := State{}
	for _, typed := range events {
		var err error
		state, err = Reduce(state, typed)
		if err != nil {
			t.Fatalf("reduce %T: %v", typed, err)
		}
	}
	if !state.Active || state.System != "coc7" || !state.BotList["bot-2"] || state.Privileges["user-1"] != 60 {
		t.Fatalf("unexpected state: %#v", state)
	}
	encoded, err := MarshalTypedEvents(events)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || strings.Contains(string(encoded), "attrs") || strings.Contains(string(encoded), "moderation") || strings.Contains(string(encoded), "valueMap") {
		t.Fatalf("group record payload contains non-owned attrs/moderation: %s", encoded)
	}

	replayed, err := Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed, state) {
		t.Fatalf("replay mismatch: %#v != %#v", replayed, state)
	}
}

func TestGroupStreamAndOwnershipScopesAreIndependent(t *testing.T) {
	if got := GroupStream("dice-1", "group-1"); got != (eventstore.StreamID{AggregateType: "group", AggregateID: "dice-1/group-1"}) {
		t.Fatalf("group stream = %#v", got)
	}
	if got := AttrsStream("dice-1", "group-1"); got.AggregateType != "attrs/group" || got == GroupStream("dice-1", "group-1") {
		t.Fatalf("attrs stream = %#v", got)
	}
	if got := GroupUserAttrsStream("dice-1", "group-1", "user-1"); got.AggregateType != "attrs/group-user" {
		t.Fatalf("group-user attrs stream = %#v", got)
	}
	if got := ModerationStream("dice-1", "group-1"); got.AggregateType != "moderation/group" {
		t.Fatalf("moderation stream = %#v", got)
	}
}

func TestCompatibilityViewDoesNotExposeMutableAuthoritativeMaps(t *testing.T) {
	state, err := Reduce(State{}, NewGroupCreatedV1("dice-1", "group-1", "", 0))
	if err == nil {
		state, err = Reduce(state, NewGroupBotListChangedV1("bot-1", true))
	}
	if err != nil {
		t.Fatal(err)
	}
	view := state.CompatibilityView()
	view.BotList["bot-1"] = false
	if !state.BotList["bot-1"] {
		t.Fatal("compatibility view mutated authoritative state")
	}
}

func TestGroupDecideEmitsTypedRecordFacts(t *testing.T) {
	decision, err := Decide(State{}, Command{Kind: CommandCreate, DiceID: "dice-1", GroupID: "group-1", GroupName: "name", EnteredAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Events) != 1 {
		t.Fatalf("create events = %#v", decision.Events)
	}
	if _, ok := decision.Events[0].(GroupCreatedV1); !ok {
		t.Fatalf("create event type = %T", decision.Events[0])
	}
}

func TestGroupDeletePlanPreservesDryRunAllowActiveAndScopes(t *testing.T) {
	state := State{GroupID: "group-1", DiceIDActive: map[string]bool{"bot-1": true}, DiceIDExists: map[string]bool{"bot-1": true}}
	_, err := PlanDelete(state, DeleteRequest{Scopes: []Scope{ScopeGroupRecord}})
	if !errors.Is(err, ErrActiveGroup) {
		t.Fatalf("active delete error = %v", err)
	}
	plan, err := PlanDelete(state, DeleteRequest{Scopes: []Scope{ScopeGroupRecord}, AllowActive: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DryRun || !plan.AllowActive || len(plan.Streams) != 1 || plan.Streams[0].AggregateType != "group" {
		t.Fatalf("delete plan = %#v", plan)
}
	}

func TestAttrsDeletePlanDoesNotIncludeGroupRecordOrModeration(t *testing.T) {
	state := State{DiceID: "dice-1", GroupID: "group-1"}
	plan, err := PlanDelete(state, DeleteRequest{Scopes: []Scope{ScopeAttrs}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Streams) != 1 || plan.Streams[0].AggregateType != "attrs/group" || len(plan.StreamPrefixes) != 1 {
		t.Fatalf("attrs delete plan = %#v", plan)
	}
	if plan.IncludesModeration || plan.IncludesPlayers {
		t.Fatal("attrs purge crossed ownership boundaries")
	}
}
func TestGroupProjectorRebuildsTypedEvents(t *testing.T) {
	if got := GroupProjection().Name; got != GroupProjectionName {
		t.Fatalf("projection name = %q", got)
	}
	if _, err := NewRepository(nil).Load(context.Background(), "dice-1", "group-1"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("nil repository error = %v", err)
	}
}

func TestRepositoryAndProjectionReplayTypedEvents(t *testing.T) {
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(GroupProjection()))
	repository := NewRepository(store)
	metadata := eventstore.Metadata{EventID: "group-created-event", CommandID: "group-created-command", CorrelationID: "group-created-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	if _, err := repository.AppendTyped(context.Background(), "dice-1", "group-1", 0, metadata, []TypedEvent{NewGroupCreatedV1("dice-1", "group-1", "name", 1)}); err != nil {
		t.Fatal(err)
	}
	metadata.EventID, metadata.CommandID, metadata.CorrelationID = "group-bot-event", "group-bot-command", "group-bot-correlation"
	if _, err := repository.AppendTyped(context.Background(), "dice-1", "group-1", 1, metadata, []TypedEvent{NewGroupBotListChangedV1("bot-1", true)}); err != nil {
		t.Fatal(err)
	}
	state, err := repository.Load(context.Background(), "dice-1", "group-1")
	if err != nil || !state.BotList["bot-1"] {
		t.Fatalf("repository state = %#v, err = %v", state, err)
	}
	projected, err := ReadProjected(context.Background(), store, "dice-1", "group-1")
	if err != nil || !projected.BotList["bot-1"] {
		t.Fatalf("projected state = %#v, err = %v", projected, err)
	}
	rebuild, err := store.Rebuild(context.Background(), eventstore.RebuildRequest{ProjectorVersion: GroupProjectionVersion})
	if err != nil {
		t.Fatal(err)
	}
	if rebuild.GenerationID == "" {
		t.Fatal("rebuild did not publish a generation")
	}
	projected, err = ReadProjected(context.Background(), store, "dice-1", "group-1")
	if err != nil || !projected.BotList["bot-1"] {
		t.Fatalf("rebuilt projected state = %#v, err = %v", projected, err)
	}
	projected.BotList["bot-1"] = false
	again, err := ReadProjected(context.Background(), store, "dice-1", "group-1")
	if err != nil || !again.BotList["bot-1"] {
		t.Fatalf("projection read was mutable = %#v, err = %v", again, err)
	}
}

