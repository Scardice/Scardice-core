package dice

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/dice/service"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"

	ds "github.com/sealdice/dicescript"
)

// newCharacterServiceFixture builds a durable, event-sourced AttrsManager with
// a nil DBOperator, matching the production runtime where legacy SQL storage
// is unavailable. It returns the service plus a reopen function that rebuilds
// the manager from the same underlying store to prove persistence.
func newCharacterServiceFixture(t *testing.T) (*CharacterService, func() *CharacterService) {
	t.Helper()
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "character.db")
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err = store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "character-test", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.ValidateReadiness(ctx); err != nil {
		t.Fatal(err)
	}
	manager := &AttrsManager{}
	instance := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, Logger: zap.NewNop().Sugar(), AttrsManager: manager}
	if err = manager.InitDurable(instance); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.Stop()
		database.Close()
	})
	service := NewCharacterService(instance)
	reopen := func() *CharacterService {
		reopened := &AttrsManager{}
		reopenedInstance := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store, Logger: zap.NewNop().Sugar(), AttrsManager: reopened}
		if err := reopened.InitDurable(reopenedInstance); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(reopened.Stop)
		return NewCharacterService(reopenedInstance)
	}
	return service, reopen
}

func characterCall(t *testing.T, service *CharacterService, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	t.Helper()
	response, err := service.HandleCharacter(context.Background(), endpoint.FencedCharacterRequest{EndpointID: "sealchat-1", Generation: 1, DesiredVersion: 1, Request: request})
	if err != nil {
		t.Fatalf("handle character: %v", err)
	}
	return response
}

func characterWireAttributes(t *testing.T, response adapterapi.CharacterResponse) map[string]any {
	t.Helper()
	data, err := json.Marshal(sealChatCharacterResponsePayload(adapterapi.CharacterOperationGet, response))
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		t.Fatal(err)
	}
	return reply.Data
}

func TestCharacterServiceRunsNineOperationsOnDurableStore(t *testing.T) {
	service, reopen := newCharacterServiceFixture(t)

	// new: create and bind a character to the current group.
	created := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationNew,
		GroupID:   "channel-1", UserID: "user-1", Name: "Alice Smith", NameSet: true, SheetType: "coc7", SheetSet: true,
	})
	if !created.OK || created.ID == "" || created.BoundGroupID != "SEALCHAT-Group:channel-1" || created.Name != "Alice Smith" {
		t.Fatalf("new response = %#v", created)
	}
	charID := created.ID

	// list: the new character appears for the owner.
	listed := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationList, UserID: "user-1"})
	if !listed.OK || len(listed.List) != 1 || listed.List[0].ID != charID || listed.List[0].Name != "Alice Smith" {
		t.Fatalf("list response = %#v", listed)
	}

	// Loading a card preserves the current group binding.
	loaded := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationLoad, GroupID: "channel-1", UserID: "user-1", Character: charID})
	if !loaded.OK || loaded.ID != charID {
		t.Fatalf("load response = %#v", loaded)
	}

	// Write through the current binding.
	set := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "channel-1", UserID: "user-1",
		Attributes: map[string]any{"Close Combat": float64(60)}, AttrsSet: true,
	})
	if !set.OK {
		t.Fatalf("set response = %#v", set)
	}

	// get: read back the written attributes.
	got := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1"})
	if !got.OK || characterWireAttributes(t, got)["Close Combat"] != float64(60) {
		t.Fatalf("get response = %#v", got)
	}

	// Save a second character without changing the first.
	saved := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSave, GroupID: "channel-1", UserID: "user-1",
		Name: "Alice Copy", NameSet: true,
	})
	if !saved.OK || saved.Action != "created" || saved.ID == "" {
		t.Fatalf("save response = %#v", saved)
	}
	copyID := saved.ID

	// tag: bind the copied character, then unbind it.
	bound := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1", Character: copyID})
	if !bound.OK || bound.Action != "bind" || bound.ID != copyID {
		t.Fatalf("tag bind response = %#v", bound)
	}
	unbound := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1"})
	if !unbound.OK || unbound.Action != "unbind" || unbound.ID != copyID {
		t.Fatalf("tag unbind response = %#v", unbound)
	}

	// untagAll: remove remaining bindings for the copied character.
	untagged := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationUntagAll, UserID: "user-1", Character: copyID})
	if !untagged.OK || untagged.ID != copyID {
		t.Fatalf("untagAll response = %#v", untagged)
	}

	// delete: remove the copied character.
	deleted := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationDelete, UserID: "user-1", Character: copyID})
	if !deleted.OK || deleted.ID != copyID {
		t.Fatalf("delete response = %#v", deleted)
	}
	remaining := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationList, UserID: "user-1"})
	if !remaining.OK || len(remaining.List) != 1 || remaining.List[0].ID != charID {
		t.Fatalf("list after delete = %#v", remaining)
	}

	// The durable store must retain the surviving character across a reopen.
	reopened := reopen()
	persisted := characterCall(t, reopened, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationList, UserID: "user-1"})
	if !persisted.OK || len(persisted.List) != 1 || persisted.List[0].ID != charID || persisted.List[0].Name != "Alice Smith" {
		t.Fatalf("reopened list = %#v", persisted)
	}
	rebound := characterCall(t, reopened, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1", Character: charID})
	if !rebound.OK {
		t.Fatalf("rebind persisted character = %#v", rebound)
	}
	persistedGet := characterCall(t, reopened, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1"})
	if !persistedGet.OK || characterWireAttributes(t, persistedGet)["Close Combat"] != float64(60) {
		t.Fatalf("reopened get = %#v", persistedGet)
	}
}

func TestCharacterServiceRejectsForeignCharacterAndDoesNotClobberOnSelfLoad(t *testing.T) {
	service, _ := newCharacterServiceFixture(t)

	created := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationNew, GroupID: "channel-1", UserID: "user-1",
		Name: "Alice", NameSet: true, SheetType: "coc7", SheetSet: true,
	})
	if !created.OK {
		t.Fatalf("new response = %#v", created)
	}

	// Ownership: another user cannot address the character by explicit id.
	foreign := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationDelete, UserID: "user-2", Character: created.ID})
	if foreign.OK || foreign.Error == "" {
		t.Fatalf("foreign delete response = %#v", foreign)
	}

	// Self-load: the bound character is also the group's independent card, so
	// loading it must not clear its own attributes before copying.
	if set := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "channel-1", UserID: "user-1",
		Attributes: map[string]any{"HP": float64(10)}, AttrsSet: true,
	}); !set.OK {
		t.Fatalf("set response = %#v", set)
	}
	loaded := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationLoad, GroupID: "channel-1", UserID: "user-1", Character: created.ID})
	if !loaded.OK {
		t.Fatalf("self-load response = %#v", loaded)
	}
	got := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1"})
	if !got.OK || characterWireAttributes(t, got)["HP"] != float64(10) {
		t.Fatalf("self-load clobbered attributes: %#v", got)
	}

	foreignAttrs, err := service.attrs().Load("QQ-Group:999", "QQ:user-1")
	if err != nil {
		t.Fatal(err)
	}
	foreignAttrs.Store("HP", anyToVMValue(float64(10)))
	if err := service.commitAttributes(foreignAttrs); err != nil {
		t.Fatal(err)
	}
	isolated := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "QQ-Group:999", UserID: "QQ:user-1",
		Attributes: map[string]any{"HP": float64(1)}, AttrsSet: true,
	})
	if !isolated.OK || foreignAttrs.Load("HP").MustReadInt() != 10 {
		t.Fatalf("SealChat request modified a foreign platform card: %#v", isolated)
	}
}

// Saving a character snapshots the source before clearing it, so a save-over
// preserves the source attributes.
func TestCharacterServiceSaveOverPreservesSource(t *testing.T) {
	service, _ := newCharacterServiceFixture(t)
	if set := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "channel-1", UserID: "user-1",
		Attributes: map[string]any{"STR": float64(55)}, AttrsSet: true,
	}); !set.OK {
		t.Fatalf("set response = %#v", set)
	}
	saved := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSave, GroupID: "channel-1", UserID: "user-1", Name: "Snapshot", NameSet: true,
	})
	if !saved.OK || saved.ID == "" {
		t.Fatalf("save response = %#v", saved)
	}
	attrs, err := service.attrs().Load("SEALCHAT-Group:channel-1", "SEALCHAT:user-1")
	if err != nil || attrs.Load("STR") == nil || attrs.Load("STR").ToString() != "55" {
		t.Fatalf("source attributes = %#v err=%v", attrs.Load("STR"), err)
	}
}

func TestCharacterReadWaitsForCallbackFenceAndSeesCommittedAttributes(t *testing.T) {
	characterService, _ := newCharacterServiceFixture(t)
	manager := characterService.dice.AttrsManager
	ctx := context.Background()
	groupID := FormatDiceIDSealChatGroup("channel-race")
	userID := FormatDiceIDSealChat("user-race")
	attributeID := groupID + "-" + manager.UIDConvert(userID)
	values := &ds.ValueMap{}
	values.Store("hp", ds.NewIntVal(1))
	payload, err := ds.NewDictVal(values).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.durable.Save(ctx, attributestate.State{
		DiceID: manager.diceID, ID: attributeID, AttrsType: service.AttrsTypeGroupUser,
		SecretRef: attributestate.SecretRef(manager.diceID, attributeID), CreatedAt: 1, UpdatedAt: 1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Load(groupID, userID); err != nil {
		t.Fatal(err)
	}

	manager.callbackGate.Lock()
	released := false
	defer func() {
		if !released {
			manager.callbackGate.Unlock()
		}
	}()
	response := make(chan adapterapi.CharacterResponse, 1)
	go func() {
		result, _ := characterService.HandleCharacter(ctx, endpoint.FencedCharacterRequest{
			EndpointID: "endpoint-1", Generation: 1, DesiredVersion: 1,
			Request: adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationGet, GroupID: "channel-race", UserID: "user-race"},
		})
		response <- result
	}()
	select {
	case result := <-response:
		t.Fatalf("character read escaped callback fence: %#v", result)
	case <-time.After(30 * time.Millisecond):
	}

	values.Store("hp", ds.NewIntVal(2))
	updatedPayload, err := ds.NewDictVal(values).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.durable.Save(ctx, state, updatedPayload); err != nil {
		t.Fatal(err)
	}
	manager.DeleteCachedGroupData(groupID, true, true)
	manager.callbackGate.Unlock()
	released = true

	select {
	case result := <-response:
		if !result.OK || fmt.Sprint(result.Attributes["hp"]) != "2" {
			t.Fatalf("character read after callback commit = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("character read did not resume after callback fence release")
	}
}
