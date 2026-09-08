package groupstate

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"Scardice-core/eventstore"
)
type fakeProjectionReader struct{ payload []byte }
func (r fakeProjectionReader) ReadProjectionRow(context.Context, string, string) (eventstore.ProjectionRow, error) {
	return eventstore.ProjectionRow{Payload: append([]byte(nil), r.payload...)}, nil
}

func TestGroupEventsReplayIntoRecordWithoutAttrsOrModeration(t *testing.T) {
	events := []TypedEvent{
		NewGroupCreatedV1("dice-1", "group-1", "name", 1700000000),
		NewGroupIdentityChangedV1("guild-1", "channel-1"),
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
	if got := GroupStream("dice-1", "group-1"); got != (eventstore.StreamID{AggregateType: "group", AggregateID: canonicalAggregateID("dice-1", "group-1")}) {
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

func TestStreamIdentityAndDeletePrefixesAreUnambiguous(t *testing.T) {
	if GroupStream("a/b", "c") == GroupStream("a", "b/c") {
		t.Fatal("group stream identity collided")
	}
	if _, err := PlanDelete(State{}, DeleteRequest{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("empty delete identity error = %v", err)
	}
	if _, err := PlanDelete(State{}, DeleteRequest{DiceID: strings.Repeat("x", MaxGroupIdentityPartBytes+1), GroupID: "group-1"}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("oversized delete identity error = %v", err)
	}
	maxPart := strings.Repeat("x", MaxGroupIdentityPartBytes)
	if ValidateIdentity(maxPart, maxPart) == nil || GroupStream(maxPart, maxPart).AggregateID != "" {
		t.Fatal("group stream exceeded aggregate ID bound")
	}
	if ValidatePlayerIdentity(maxPart, maxPart, maxPart) == nil || PlayerStream(maxPart, maxPart, maxPart).AggregateID != "" {
		t.Fatal("player stream exceeded aggregate ID bound")
	}
	if AttrsStream(maxPart, maxPart).AggregateID != "" || GroupUserAttrsStream(maxPart, maxPart, maxPart).AggregateID != "" {
		t.Fatal("attrs stream exceeded aggregate ID bound")
	}
	if _, err := ApplyEnvelope(
		State{Version: 1, DiceID: maxPart, GroupID: maxPart},
		eventstore.Envelope{
			Stream: eventstore.StreamID{AggregateType: GroupAggregateType, AggregateID: canonicalAggregateID(maxPart, maxPart)},
			StreamVersion: 2, EventType: string(EventGroupNameChanged), SchemaVersion: GroupEventSchemaVersion,
			Payload: []byte(`{"groupName":"x"}`),
		},
	); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("oversized envelope identity error = %v", err)
	}
	if _, err := PlanDelete(State{Version: 1, DiceID: "dice-1", GroupID: "group-1"}, DeleteRequest{DiceID: "dice-2", GroupID: "group-1"}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("mismatched delete selector error = %v", err)
	}
	plan, err := PlanDelete(State{}, DeleteRequest{DiceID: "dice-1", GroupID: "group-1", Scopes: []Scope{ScopePlayers, ScopeAttrs}})
	if err != nil || len(plan.StreamPrefixes) != 2 || plan.StreamPrefixes[0].AggregateType == plan.StreamPrefixes[1].AggregateType {
		t.Fatalf("typed delete prefixes = %#v, err = %v", plan.StreamPrefixes, err)
	}
	conflictingMetadata := eventstore.Metadata{
		EventID: "event", CommandID: "command", CorrelationID: "correlation",
		OccurredAt: time.Unix(1, 0), OccurredAtUnixNanoUTC: 2, OccurredAtUnixNanoSet: true,
	}
	if _, err := NewEvent(NewGroupNameChangedV1("name"), conflictingMetadata); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("conflicting metadata error = %v", err)
	}
}

func TestTypedEventRejectsNilOversizeAndInvalidPrivilege(t *testing.T) {
	var nilEvent *GroupNameChangedV1
	if _, err := Reduce(State{}, nilEvent); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("nil typed event error = %v", err)
	}
	oversized := NewGroupWelcomeChangedV1(true, strings.Repeat("x", MaxGroupEventPayloadBytes))
	if _, err := MarshalTypedEvent(oversized); !errors.As(err, new(*eventstore.OversizeError)) {
		t.Fatalf("oversized event error = %v", err)
	}
	oversizedID := strings.Repeat("x", MaxGroupIdentityPartBytes+1)
	if _, err := MarshalTypedEvent(NewGroupBotListChangedV1(oversizedID, true)); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("oversized typed identifier error = %v", err)
	}
	if _, err := MarshalTypedEvent(NewGroupActivationChangedV1(strings.Repeat("x", MaxGroupEventPayloadBytes), true, true)); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("oversized activation identifier error = %v", err)
	}
	for _, payload := range []string{"null", "[]"} {
		if _, err := DecodeTypedEvent(EventGroupNameChanged, []byte(payload)); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("malformed %s payload error = %v", payload, err)
		}
	}
	if _, err := ReplayEnvelopes([]eventstore.Envelope{{
		Stream: GroupStream("dice-1", "group-1"), StreamVersion: 1,
		EventType: string(EventGroupNameChanged), SchemaVersion: GroupEventSchemaVersion, Payload: []byte("null"),
	}}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("malformed replay payload error = %v", err)
	}
	malformedField := []byte(`{"userId":"` + strings.Repeat("x", MaxGroupIdentityPartBytes+1) + `","enabled":true}`)
	if _, err := ReplayEnvelopes([]eventstore.Envelope{{
		Stream: GroupStream("dice-1", "group-1"), StreamVersion: 1,
		EventType: string(EventGroupBotListChanged), SchemaVersion: GroupEventSchemaVersion, Payload: malformedField,
	}}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("malformed replay identifier error = %v", err)
	}
	for _, payload := range []string{
		`{"groupName":"ok","attrs":{"valueMap":{"x":1}}}`,
		`{"groupName":"ok"} {}`,
	} {
		if _, err := DecodeTypedEvent(EventGroupNameChanged, []byte(payload)); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("unknown/trailing payload error = %v", err)
		}
	}
	for _, malformed := range []struct {
		eventType EventType
		payload   string
	}{
		{EventGroupWelcomeChanged, `{"enabled":null}`},
		{EventGroupActivationChanged, `{"diceId":"dice-1","active":null,"exists":true}`},
		{EventGroupHelpChanged, `{"helpPackages":["core",null]}`},
	} {
		if _, err := ReplayEnvelopes([]eventstore.Envelope{{
			Stream: GroupStream("dice-1", "group-1"), StreamVersion: 1,
			EventType: string(malformed.eventType), SchemaVersion: GroupEventSchemaVersion, Payload: []byte(malformed.payload),
		}}); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("malformed null field %s error = %v", malformed.eventType, err)
		}
	}
	state, err := Reduce(State{}, NewGroupCreatedV1("dice-1", "group-1", "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reduce(state, NewGroupPrivilegeChangedV1("user-1", 101)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid privilege error = %v", err)
	}
	if _, err := Reduce(state, NewGroupExtensionChangedV1(oversizedID, true)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid direct reducer identifier error = %v", err)
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
func TestReadProjectedRejectsCorruptRows(t *testing.T) {
	for _, payload := range []string{
		"null",
		`{"version":0}`,
		`{"version":1}`,
		`{"version":1,"diceId":"dice-1","groupId":"group-1","active":true}`,
		`{"version":1,"diceId":"dice-1","groupId":"group-1","diceIdActive":{"":true}}`,
		`{"version":1,"diceId":"dice-1","groupId":"group-1","privileges":{"user-1":101}}`,
		`{"version":1,"diceId":"dice-1","groupId":"group-1","deleted":true,"active":true}`,
	} {
		if _, err := ReadProjected(context.Background(), fakeProjectionReader{payload: []byte(payload)}, "dice-1", "group-1"); !errors.Is(err, ErrInvalidState) && !errors.Is(err, ErrDeletedGroup) {
			t.Fatalf("corrupt projection %s error = %v", payload, err)
		}
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
	if _, err := Decide(State{}, Command{Kind: CommandCreate, DiceID: "dice-1", GroupID: "group-1", ExpectedVersion: 1, ExpectedVersionSet: true}); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("empty-state stale version error = %v", err)
	}
}
func TestDecideWelcomeUsesExplicitEnabledField(t *testing.T) {
	state := State{Version: 1, DiceID: "dice-1", GroupID: "group-1"}
	decision, err := Decide(state, Command{Kind: CommandWelcome, Active: true, WelcomeEnabled: false, WelcomeMessage: "hello"})
	if err != nil { t.Fatal(err) }
	welcome, ok := decision.Events[0].(GroupWelcomeChangedV1)
	if !ok || welcome.Enabled {
		t.Fatalf("welcome decision = %#v", decision.Events)
	}
}

func TestGroupCreatedAndTemplateReplayInviteAndCocRuleFacts(t *testing.T) {
	created := NewGroupCreatedWithInviteV1("dice-1", "group-1", "name", "user-1", 1)
	template := NewGroupTemplateWithCocRuleV1(20, "1d20", "soft", 7)
	state, err := Replay([]TypedEvent{created, template})
	if err != nil {
		t.Fatal(err)
	}
	if state.InviteUserID != "user-1" || state.CocRuleIndex != 7 {
		t.Fatalf("record facts = %#v", state)
	}
	payload, err := MarshalTypedEvents([]TypedEvent{created, template})
	if err != nil || !strings.Contains(string(payload), "user-1") || !strings.Contains(string(payload), "cocRuleIndex") {
		t.Fatalf("typed payload = %s, err = %v", payload, err)
	}
}

func TestDecideAndAppendCreateUsesCommandIdentity(t *testing.T) {
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group-create.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(GroupProjection()))
	repository := NewRepository(store)
	metadata := eventstore.Metadata{EventID: "create-event", CommandID: "create-command", CorrelationID: "create-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	_, err = repository.DecideAndAppend(context.Background(), State{}, 0, metadata, Command{Kind: CommandCreate, DiceID: "dice-1", GroupID: "group-1", GroupName: "name"})
	if err != nil {
		t.Fatal(err)
	}
	state, err := repository.Load(context.Background(), "dice-1", "group-1")
	if err != nil || state.DiceID != "dice-1" || state.GroupID != "group-1" {
		t.Fatalf("created state = %#v, err = %v", state, err)
	}
	projected, err := ReadProjected(context.Background(), store, "dice-1", "group-1")
	if err != nil || projected.DiceID != "dice-1" || projected.GroupID != "group-1" {
		t.Fatalf("created projection = %#v, err = %v", projected, err)
	}
}
func TestAppendRejectsUnreplayableFirstEventWithoutProjector(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group-no-projector.db"})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	repository := NewRepository(eventstore.NewStore(db))
	created, err := NewEvent(NewGroupCreatedV1("dice-1", "group-1", "name", 1), eventstore.Metadata{
		EventID: "created-event", CommandID: "created-command", CorrelationID: "created-correlation",
		OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true,
	})
	if err != nil { t.Fatal(err) }
	name, err := NewEvent(NewGroupNameChangedV1("unreachable"), eventstore.Metadata{
		EventID: "name-event", CommandID: "name-command", CorrelationID: "name-correlation",
		OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true,
	})
	if err != nil { t.Fatal(err) }
	if _, err := repository.Append(ctx, "dice-1", "group-1", 0, []eventstore.NewEvent{name}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unreplayable first event error = %v", err)
	}
	if _, err := repository.Append(ctx, "dice-1", "group-1", 0, []eventstore.NewEvent{created}); err != nil {
		t.Fatal(err)
	}
	duplicateSystem, err := NewEvent(NewGroupSystemChangedV1("coc7"), eventstore.Metadata{
		EventID: "name-event", CommandID: "name-command", CorrelationID: "name-correlation",
		OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true,
	})
	if err != nil { t.Fatal(err) }
	if _, err := repository.Append(ctx, "dice-1", "group-1", 1, []eventstore.NewEvent{name, duplicateSystem}); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("duplicate raw event ID error = %v", err)
	}
	state, err := repository.Load(ctx, "dice-1", "group-1")
	if err != nil || state.Version != 1 || state.GroupName != "name" {
		t.Fatalf("replayed no-projector state = %#v, err = %v", state, err)
	}
}

func TestGroupDeletePlanPreservesDryRunAllowActiveAndScopes(t *testing.T) {
	state := State{DiceID: "dice-1", GroupID: "group-1", DiceIDActive: map[string]bool{"bot-1": true}, DiceIDExists: map[string]bool{"bot-1": true}}
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
func TestGroupProjectionRejectsCorruptExistingRow(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group-corrupt-projection.db"})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(GroupProjection()))
	repository := NewRepository(store)
	metadata := eventstore.Metadata{EventID: "projection-created-event", CommandID: "projection-created-command", CorrelationID: "projection-created-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	if _, err := repository.AppendTyped(ctx, "dice-1", "group-1", 0, metadata, []TypedEvent{NewGroupCreatedV1("dice-1", "group-1", "name", 1)}); err != nil {
		t.Fatal(err)
	}
	stream := GroupStream("dice-1", "group-1")
	update := db.GORM().Model(&projectionRow{}).Where("projection_name = ? AND row_key = ?", GroupProjectionName, stream.AggregateID).Update("payload", []byte(`{"version":1}`))
	if update.Error != nil || update.RowsAffected != 1 {
		t.Fatalf("corrupt projection update rows=%d err=%v", update.RowsAffected, update.Error)
	}
	metadata.EventID, metadata.CommandID, metadata.CorrelationID = "projection-next-event", "projection-next-command", "projection-next-correlation"
	if _, err := repository.AppendTyped(ctx, "dice-1", "group-1", 1, metadata, []TypedEvent{NewGroupNameChangedV1("renamed")}); !errors.Is(err, eventstore.ErrProjectorFailure) {
		t.Fatalf("corrupt existing projection error = %v", err)
	}
}

func TestAppendTypedAllocatesUniqueEventIDsForBatch(t *testing.T) {
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group-batch.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(GroupProjection()))
	repository := NewRepository(store)
	metadata := eventstore.Metadata{CommandID: "batch-command", CorrelationID: "batch-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	_, err = repository.AppendTyped(context.Background(), "dice-1", "group-1", 0, metadata, []TypedEvent{
		NewGroupCreatedV1("dice-1", "group-1", "name", 1),
		NewGroupNameChangedV1("renamed"),
	})
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.Load(context.Background(), GroupStream("dice-1", "group-1"), 1)
	if err != nil || len(events) != 2 || events[0].EventID == events[1].EventID {
		t.Fatalf("batch events = %#v, err = %v", events, err)
	}
}
func TestAppendTypedRejectsDuplicateExplicitEventID(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group-duplicate.db"})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	repository := NewRepository(eventstore.NewStore(db))
	metadata := eventstore.Metadata{EventID: "duplicate-event", CommandID: "duplicate-command", CorrelationID: "duplicate-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	if _, err := repository.AppendTyped(ctx, "dice-1", "group-1", 0, metadata, []TypedEvent{
		NewGroupCreatedV1("dice-1", "group-1", "name", 1), NewGroupNameChangedV1("renamed"),
	}); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("duplicate explicit event ID error = %v", err)
	}
	events, err := repository.Store.Load(ctx, GroupStream("dice-1", "group-1"), 1)
	if err != nil || len(events) != 0 {
		t.Fatalf("duplicate batch committed events = %#v, err = %v", events, err)
	}
}

