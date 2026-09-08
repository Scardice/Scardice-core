package playerstate

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"Scardice-core/eventstore"
)

func TestOwnershipStreamsAndPurgeScopesAreDisjoint(t *testing.T) {
	player := PlayerStream("dice-1", "group-1", "user-1")
	attrs := GroupUserAttrsStream("dice-1", "group-1", "user-1")
	character := CharacterStream("dice-1", "user-1", "character-1")
	moderation := ModerationStream("dice-1", "group-1", "QQ:1")
	if player == attrs || player == character || player == moderation || attrs == character { t.Fatalf("ownership streams overlap") }
	if got := PlayerStreamPrefix("dice-1", "group-1"); got.AggregateType != PlayerAggregateType || !strings.Contains(got.Prefix, "dice-1") { t.Fatalf("player prefix = %#v", got) }
	if got := GroupUserAttrsStreamPrefix("dice-1", "group-1"); got.AggregateType != GroupUserAttrsAggregateType { t.Fatalf("attrs prefix = %#v", got) }
	plan, err := PlanDeleteForUser("dice-1", "group-1", "user-1", []Scope{ScopePlayers, ScopeAttrs, ScopeCharacters, ScopeModeration})
	if err != nil { t.Fatal(err) }
	if len(plan.StreamPrefixes) != 4 || len(plan.Streams) != 0 { t.Fatalf("purge plan = %#v", plan) }
	if plan.StreamPrefixes[0].AggregateType != PlayerAggregateType || plan.StreamPrefixes[1].AggregateType != GroupUserAttrsAggregateType || plan.StreamPrefixes[2].AggregateType != CharacterAggregateType || plan.StreamPrefixes[3].AggregateType != ModerationAggregateType { t.Fatalf("mixed purge owners = %#v", plan.StreamPrefixes) }
}

func TestPlayerReplayAndCompatibilityReadExcludeLocalOverlayAndOtherOwners(t *testing.T) {
	events := []PlayerEvent{NewPlayerCreatedV1("dice-1", "group-1", "user-1", "old"), NewPlayerNameChangedV1("new"), NewPlayerPrivilegeChangedV1(60), NewPlayerAutoSetNameTemplateChangedV1("HP{hp}")}
	state, err := ReplayPlayer(events)
	if err != nil { t.Fatal(err) }
	if state.Name != "new" || state.Privilege != 60 || state.AutoSetNameTemplate == "" { t.Fatalf("player state = %#v", state) }
	local := NewLocalOverlay(); local.Set("$t玩家", "<new>")
	payload, err := MarshalPlayerEvents(events)
	if err != nil || strings.Contains(string(payload), "attrs") || strings.Contains(string(payload), "character") || strings.Contains(string(payload), "valueMap") { t.Fatalf("player payload leaked another owner/local value: %s", payload) }
	view := state.CompatibilityView(); view.Name = "mutated"
	if state.Name != "new" { t.Fatal("compatibility read aliases authoritative state") }
}

func TestOpaqueAttrsAndCharacterReplayPreserveSemanticsWithoutPlaintext(t *testing.T) {
	secret := []byte("encrypted-attrs-ciphertext")
	attrsEvents := []GroupUserAttrsEvent{NewGroupUserAttrsCreatedV1("dice-1", "group-1", "user-1"), NewGroupUserAttrsBindingChangedV1("character-1"), NewGroupUserAttrsSetV1("hp", secret, "key-v1"), NewGroupUserAttrsIncrementedV1("hp", 2), NewGroupUserAttrsDeletedV1("old")}
	attrs, err := ReplayGroupUserAttrs(attrsEvents)
	if err != nil { t.Fatal(err) }
	if attrs.BindingSheetID != "character-1" || string(attrs.Values["hp"].Ciphertext) != string(secret) || len(attrs.Operations) != 3 { t.Fatalf("attrs state = %#v", attrs) }
	encoded, err := MarshalGroupUserAttrsEvents(attrsEvents)
	if err != nil || strings.Contains(string(encoded), "encrypted-attrs-ciphertext") { t.Fatalf("attrs payload exposed sensitive plaintext: %s", encoded) }
	characters := []CharacterEvent{NewCharacterCreatedV1("dice-1", "user-1", "character-1", "Hero", "coc7"), NewCharacterSheetReplacedV1([]byte("encrypted-character-sheet"), "key-v1")}
	character, err := ReplayCharacters(characters)
	if err != nil || string(character.Sheet.Ciphertext) != "encrypted-character-sheet" { t.Fatalf("character replay = %#v, err = %v", character, err) }
	characterPayload, err := MarshalCharacterEvents(characters)
	if err != nil || strings.Contains(string(characterPayload), "encrypted-character-sheet") { t.Fatalf("character payload exposed ciphertext as plaintext field: %s", characterPayload) }
}

func TestPlayerRepositoryReplaysProjectionAndScopedCharacterSurvival(t *testing.T) {
	ctx := context.Background(); db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/player.db"}); if err != nil { t.Fatal(err) }; defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithProjection(PlayerProjection()), eventstore.WithProjection(GroupUserAttrsProjection()), eventstore.WithProjection(CharacterProjection()), eventstore.WithProjection(ModerationProjection())); repo := NewRepository(store)
	meta := eventstore.Metadata{EventID: "p-create", CommandID: "p-command", CorrelationID: "p-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	if _, err := repo.AppendPlayerTyped(ctx, "dice-1", "group-1", "user-1", 0, meta, []PlayerEvent{NewPlayerCreatedV1("dice-1", "group-1", "user-1", "Alice")}); err != nil { t.Fatal(err) }
	meta.EventID, meta.CommandID, meta.CorrelationID = "a-create", "a-command", "a-correlation"; if _, err := repo.AppendGroupUserAttrsTyped(ctx, "dice-1", "group-1", "user-1", 0, meta, []GroupUserAttrsEvent{NewGroupUserAttrsCreatedV1("dice-1", "group-1", "user-1"), NewGroupUserAttrsSetV1("hp", []byte("ciphertext"), "key-v1")}); err != nil { t.Fatal(err) }
	meta.EventID, meta.CommandID, meta.CorrelationID = "c-create", "c-command", "c-correlation"; if _, err := repo.AppendCharacterTyped(ctx, "dice-1", "user-1", "character-1", 0, meta, []CharacterEvent{NewCharacterCreatedV1("dice-1", "user-1", "character-1", "Hero", "coc7")}); err != nil { t.Fatal(err) }
	got, err := repo.LoadPlayer(ctx, "dice-1", "group-1", "user-1"); if err != nil || got.Name != "Alice" { t.Fatalf("player load = %#v, err = %v", got, err) }
	projected, err := ReadProjectedPlayer(ctx, store, "dice-1", "group-1", "user-1"); if err != nil || projected.Name != "Alice" { t.Fatalf("player projection = %#v, err = %v", projected, err) }
	attrsProjected, err := ReadProjectedGroupUserAttrs(ctx, store, "dice-1", "group-1", "user-1")
	if err != nil || string(attrsProjected.Values["hp"].Ciphertext) != "ciphertext" { t.Fatalf("attrs projection = %#v, err = %v", attrsProjected, err) }
	characterProjected, err := ReadProjectedCharacter(ctx, store, "dice-1", "user-1", "character-1")
	if err != nil || characterProjected.CharacterID != "character-1" { t.Fatalf("character projection = %#v, err = %v", characterProjected, err) }
	attrs, err := repo.LoadGroupUserAttrs(ctx, "dice-1", "group-1", "user-1"); if err != nil || string(attrs.Values["hp"].Ciphertext) != "ciphertext" { t.Fatalf("attrs before purge = %#v, err = %v", attrs, err) }
	if _, err := repo.LoadCharacter(ctx, "dice-1", "user-1", "character-1"); err != nil { t.Fatal(err) }
	purge, err := PlanDelete("dice-1", "group-1", []Scope{ScopeAttrs}); if err != nil || len(purge.StreamPrefixes) != 1 || len(purge.Streams) != 0 { t.Fatalf("attrs-only purge = %#v, err = %v", purge, err) }
	if reflect.DeepEqual(purge.StreamPrefixes[0], PlayerStreamPrefix("dice-1", "group-1")) { t.Fatal("attrs-only purge selected player streams") }
}
func TestMultipleCharactersHaveIndependentGlobalStreams(t *testing.T) {
	first, err := ReplayCharacters([]CharacterEvent{NewCharacterCreatedV1("dice-1", "user-1", "character-1", "Hero", "coc7")})
	if err != nil || first.CharacterID != "character-1" { t.Fatalf("first character = %#v, err = %v", first, err) }
	second, err := ReplayCharacters([]CharacterEvent{NewCharacterCreatedV1("dice-1", "user-1", "character-2", "Villain", "coc7")})
	if err != nil || second.CharacterID != "character-2" { t.Fatalf("second character = %#v, err = %v", second, err) }
	if CharacterStream("dice-1", "user-1", "character-1") == CharacterStream("dice-1", "user-1", "character-2") { t.Fatal("characters share one global stream") }
}
func TestModerationIsSeparateAndRebuildable(t *testing.T) {
	events := []ModerationEvent{NewModerationCreatedV1("dice-1", "group-1", "QQ:1", -10, 4), NewModerationScoreChangedV1(9, strings.Repeat("a", 64)), NewModerationRankChangedV1(-30)}
	state, err := ReplayModeration(events)
	if err != nil || state.Rank != -30 || state.Score != 9 || state.SubjectID != "QQ:1" { t.Fatalf("moderation = %#v, err = %v", state, err) }
	payload, err := MarshalModerationEvents(events)
	if err != nil || strings.Contains(string(payload), "player") || strings.Contains(string(payload), "attrs") { t.Fatalf("moderation payload crossed owners: %s", payload) }
}
func TestModerationSubjectsHaveIndependentStreamsAndGroupPurgePrefix(t *testing.T) {
	first := NewModerationCreatedV1("dice-1", "group-1", "QQ:1", -10, 1)
	second := NewModerationCreatedV1("dice-1", "group-1", "QQ:2", -30, 2)
	if ModerationStream(first.DiceID, first.GroupID, first.SubjectID) == ModerationStream(second.DiceID, second.GroupID, second.SubjectID) { t.Fatal("moderation subjects share one stream") }
	firstState, err := ReplayModeration([]ModerationEvent{first}); if err != nil || firstState.SubjectID != "QQ:1" { t.Fatalf("first moderation = %#v, err = %v", firstState, err) }
	secondState, err := ReplayModeration([]ModerationEvent{second}); if err != nil || secondState.SubjectID != "QQ:2" { t.Fatalf("second moderation = %#v, err = %v", secondState, err) }
	plan, err := PlanDelete("dice-1", "group-1", []Scope{ScopeModeration}); if err != nil || len(plan.StreamPrefixes) != 1 || plan.StreamPrefixes[0] != ModerationStreamPrefix("dice-1", "group-1") { t.Fatalf("moderation purge = %#v, err = %v", plan, err) }
}
func TestModerationReasonDigestIsOpaque(t *testing.T) {
	legacy := NewModerationScoreChangedV1(1, "legacy plaintext reason")
	if _, err := MarshalModerationEvent(legacy); err != ErrInvalidState { t.Fatalf("legacy reason accepted: %v", err) }
	valid := NewModerationScoreChangedV1(1, strings.Repeat("a", 64))
	if _, err := MarshalModerationEvent(valid); err != nil { t.Fatalf("digest rejected: %v", err) }
}

func TestTypedNilEventIsRejected(t *testing.T) {
	var event *PlayerNameChangedV1
	if _, err := ReducePlayer(PlayerState{}, event); err != ErrInvalidEvent { t.Fatalf("typed nil error = %v", err) }
}
func TestRepositoryValidatesReplayBeforeCommitWithoutProjector(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/validation.db"})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	repo := NewRepository(eventstore.NewStore(db))
	meta := eventstore.Metadata{EventID: "invalid", CommandID: "command", CorrelationID: "correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}
	if _, err := repo.AppendPlayerTyped(ctx, "dice-1", "group-1", "user-1", 0, meta, []PlayerEvent{NewPlayerNameChangedV1("name")}); err != ErrInvalidState { t.Fatalf("mutation before create = %v", err) }
	meta.EventID, meta.CommandID, meta.CorrelationID = "create", "create-command", "create-correlation"
	if _, err := repo.AppendPlayerTyped(ctx, "dice-1", "group-1", "user-1", 0, meta, []PlayerEvent{NewPlayerCreatedV1("dice-1", "group-1", "user-1", "name")}); err != nil { t.Fatal(err) }
	meta.EventID, meta.CommandID, meta.CorrelationID = "create-again", "create-again-command", "create-again-correlation"
	if _, err := repo.AppendPlayerTyped(ctx, "dice-1", "group-1", "user-1", 1, meta, []PlayerEvent{NewPlayerCreatedV1("dice-1", "group-1", "user-1", "again")}); err != ErrInvalidState { t.Fatalf("second create = %v", err) }
	meta.EventID, meta.CommandID, meta.CorrelationID = "delete", "delete-command", "delete-correlation"
	if _, err := repo.AppendPlayerTyped(ctx, "dice-1", "group-1", "user-1", 1, meta, []PlayerEvent{NewPlayerDeletedV1()}); err != nil { t.Fatal(err) }
	meta.EventID, meta.CommandID, meta.CorrelationID = "after-delete", "after-delete-command", "after-delete-correlation"
	if _, err := repo.AppendPlayerTyped(ctx, "dice-1", "group-1", "user-1", 2, meta, []PlayerEvent{NewPlayerNameChangedV1("again")}); err != ErrInvalidState { t.Fatalf("mutation after delete = %v", err) }
}

func TestStrictBoundsAndTypedNilAreRejected(t *testing.T) {
	if _, err := PlanDeleteForUser("dice-1", "group-1", strings.Repeat("u", MaxIdentityPartBytes+1), []Scope{ScopeCharacters}); err != ErrInvalidIdentity { t.Fatalf("oversized purge user = %v", err) }
	if _, err := PlanDelete("dice-1", "group-1", []Scope{"unknown"}); err != ErrInvalidCommand { t.Fatalf("unknown purge scope = %v", err) }
	if _, err := PlanDelete("dice-1", "group-1", []Scope{ScopeCharacters}); err != ErrInvalidIdentity { t.Fatalf("group-wide character purge = %v", err) }
	if _, err := PlanDeleteForUser("dice-1", "group-1", "user-1", []Scope{ScopeCharacters}); err != nil { t.Fatal(err) }
	if err := NewGroupUserAttrsBindingChangedV1(strings.Repeat("x", MaxIdentityPartBytes+1)).attrsValidate(); err != ErrInvalidIdentity { t.Fatalf("oversized binding = %v", err) }
	if err := NewCharacterCreatedV1("dice-1", "user-1", strings.Repeat("x", MaxIdentityPartBytes+1), "name", "coc7").characterValidate(); err != ErrInvalidIdentity { t.Fatalf("oversized character = %v", err) }
	if _, err := DecodePlayerEvent(EventPlayerNameChanged, bytes.Repeat([]byte("x"), eventstore.MaxEventPayloadBytes+1)); err == nil { t.Fatal("oversized decode accepted") }
	var nilEvent *PlayerNameChangedV1
	if _, err := NewEvent(nilEvent, eventstore.Metadata{EventID: "e", CommandID: "c", CorrelationID: "r", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}); err != eventstore.ErrInvalidEvent { t.Fatalf("typed nil NewEvent = %v", err) }
	if _, err := NewEventWithFactory(eventstore.EventFactory{}, nilEvent, eventstore.Metadata{OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}); err != eventstore.ErrInvalidEvent { t.Fatalf("typed nil factory event = %v", err) }
}

func TestReducersRejectVersionOverflow(t *testing.T) {
	overflow := ^uint64(0)
	if _, err := ReducePlayer(PlayerState{Version: overflow}, NewPlayerNameChangedV1("x")); err != ErrInvalidState { t.Fatalf("player overflow = %v", err) }
	if _, err := ReduceGroupUserAttrs(GroupUserAttrsState{Version: overflow}, NewGroupUserAttrsClearedV1()); err != ErrInvalidState { t.Fatalf("attrs overflow = %v", err) }
	if _, err := ReduceCharacter(CharacterState{Version: overflow}, NewCharacterRenamedV1("x")); err != ErrInvalidState { t.Fatalf("character overflow = %v", err) }
	if _, err := ReduceModeration(ModerationState{Version: overflow}, NewModerationRankChangedV1(0)); err != ErrInvalidState { t.Fatalf("moderation overflow = %v", err) }
}
func TestTerminalDeletionCannotRepeat(t *testing.T) {
	player, err := ReplayPlayer([]PlayerEvent{NewPlayerCreatedV1("dice-1", "group-1", "user-1", "name"), NewPlayerDeletedV1()}); if err != nil { t.Fatal(err) }
	if _, err = ReducePlayer(player, NewPlayerDeletedV1()); err != ErrInvalidState { t.Fatalf("repeat player delete = %v", err) }
	character, err := ReplayCharacters([]CharacterEvent{NewCharacterCreatedV1("dice-1", "user-1", "character-1", "name", "coc7"), NewCharacterDeletedV1()}); if err != nil { t.Fatal(err) }
	if _, err = ReduceCharacter(character, NewCharacterDeletedV1()); err != ErrInvalidState { t.Fatalf("repeat character delete = %v", err) }
	moderation, err := ReplayModeration([]ModerationEvent{NewModerationCreatedV1("dice-1", "group-1", "QQ:1", -1, 0), NewModerationDeletedV1()}); if err != nil { t.Fatal(err) }
	if _, err = ReduceModeration(moderation, NewModerationDeletedV1()); err != ErrInvalidState { t.Fatalf("repeat moderation delete = %v", err) }
	attrs := GroupUserAttrsState{Version: 1, Deleted: true}
	if _, err = ReduceGroupUserAttrs(attrs, NewGroupUserAttrsClearedV1()); err != ErrInvalidState { t.Fatalf("mutation on deleted attrs = %v", err) }
}
