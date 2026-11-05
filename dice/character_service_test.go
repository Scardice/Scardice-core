package dice

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

func newCharacterServiceFixture(t *testing.T) (*CharacterService, func() *CharacterService) {
	t.Helper()
	instance, _ := newDomainExecutionFixture(t)
	manager := &AttrsManager{}
	instance.AttrsManager = manager
	if err := manager.InitDurable(instance); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Stop)
	service := NewCharacterService(instance)
	return service, func() *CharacterService {
		reopened := &AttrsManager{}
		instance.AttrsManager = reopened
		if err := reopened.InitDurable(instance); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(reopened.Stop)
		return NewCharacterService(instance)
	}
}

var characterRequestSequence atomic.Uint64

func characterCall(t *testing.T, service *CharacterService, request adapterapi.CharacterRequest) adapterapi.CharacterResponse {
	t.Helper()
	sequence := characterRequestSequence.Add(1)
	response, err := service.HandleCharacter(context.Background(), endpoint.FencedCharacterRequest{
		EndpointID: "sealchat-1", Generation: 1, DesiredVersion: sequence, Request: request,
	})
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
	if err = json.Unmarshal(data, &reply); err != nil {
		t.Fatal(err)
	}
	return reply.Data
}

func TestCharacterServiceRunsNineOperationsOnDurableStore(t *testing.T) {
	service, reopen := newCharacterServiceFixture(t)
	created := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationNew, GroupID: "channel-1", UserID: "user-1",
		Name: "Alice Smith", NameSet: true, SheetType: "coc7", SheetSet: true,
	})
	if !created.OK || created.ID == "" || created.BoundGroupID != "SEALCHAT-Group:channel-1" || created.Name != "Alice Smith" {
		t.Fatalf("new response = %#v", created)
	}
	characterID := created.ID
	listed := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationList, UserID: "user-1"})
	if !listed.OK || len(listed.List) != 1 || listed.List[0].ID != characterID || listed.List[0].Name != "Alice Smith" {
		t.Fatalf("list response = %#v", listed)
	}
	loaded := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationLoad, GroupID: "channel-1", UserID: "user-1", Character: characterID,
	})
	if !loaded.OK || loaded.ID != characterID {
		t.Fatalf("load response = %#v", loaded)
	}
	set := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "channel-1", UserID: "user-1",
		Attributes: map[string]any{"Close Combat": float64(60)}, AttrsSet: true,
	})
	if !set.OK {
		t.Fatalf("set response = %#v", set)
	}
	got := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1",
	})
	if !got.OK || characterWireAttributes(t, got)["Close Combat"] != float64(60) {
		t.Fatalf("get response = %#v", got)
	}
	saved := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSave, GroupID: "channel-1", UserID: "user-1",
		Name: "Alice Copy", NameSet: true,
	})
	if !saved.OK || saved.Action != "created" || saved.ID == "" {
		t.Fatalf("save response = %#v", saved)
	}
	copyID := saved.ID
	bound := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1", Character: copyID,
	})
	if !bound.OK || bound.Action != "bind" || bound.ID != copyID {
		t.Fatalf("tag bind response = %#v", bound)
	}
	unbound := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1",
	})
	if !unbound.OK || unbound.Action != "unbind" || unbound.ID != copyID {
		t.Fatalf("tag unbind response = %#v", unbound)
	}
	untagged := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationUntagAll, UserID: "user-1", Character: copyID,
	})
	if !untagged.OK || untagged.ID != copyID {
		t.Fatalf("untagAll response = %#v", untagged)
	}
	deleted := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationDelete, UserID: "user-1", Character: copyID,
	})
	if !deleted.OK || deleted.ID != copyID {
		t.Fatalf("delete response = %#v", deleted)
	}
	remaining := characterCall(t, service, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationList, UserID: "user-1"})
	if !remaining.OK || len(remaining.List) != 1 || remaining.List[0].ID != characterID {
		t.Fatalf("list after delete = %#v", remaining)
	}

	reopened := reopen()
	persisted := characterCall(t, reopened, adapterapi.CharacterRequest{Operation: adapterapi.CharacterOperationList, UserID: "user-1"})
	if !persisted.OK || len(persisted.List) != 1 || persisted.List[0].ID != characterID || persisted.List[0].Name != "Alice Smith" {
		t.Fatalf("reopened list = %#v", persisted)
	}
	rebound := characterCall(t, reopened, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1", Character: characterID,
	})
	if !rebound.OK {
		t.Fatalf("rebind persisted character = %#v", rebound)
	}
	persistedGet := characterCall(t, reopened, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1",
	})
	if !persistedGet.OK || characterWireAttributes(t, persistedGet)["Close Combat"] != float64(60) {
		t.Fatalf("reopened get = %#v", persistedGet)
	}
}

func TestCharacterServiceRejectsForeignCharacterAndPreservesSelfLoad(t *testing.T) {
	service, _ := newCharacterServiceFixture(t)
	created := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationNew, GroupID: "channel-1", UserID: "user-1",
		Name: "Alice", NameSet: true, SheetType: "coc7", SheetSet: true,
	})
	if !created.OK {
		t.Fatalf("new response = %#v", created)
	}
	foreign := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationDelete, UserID: "user-2", Character: created.ID,
	})
	if foreign.OK || foreign.Error == "" {
		t.Fatalf("foreign delete response = %#v", foreign)
	}
	set := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "channel-1", UserID: "user-1",
		Attributes: map[string]any{"HP": float64(10)}, AttrsSet: true,
	})
	if !set.OK {
		t.Fatalf("set response = %#v", set)
	}
	loaded := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationLoad, GroupID: "channel-1", UserID: "user-1", Character: created.ID,
	})
	if !loaded.OK {
		t.Fatalf("self-load response = %#v", loaded)
	}
	got := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1",
	})
	if !got.OK || characterWireAttributes(t, got)["HP"] != float64(10) {
		t.Fatalf("self-load clobbered attributes: %#v", got)
	}
}

func TestCharacterServiceSaveOverPreservesSource(t *testing.T) {
	service, _ := newCharacterServiceFixture(t)
	if set := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSet, GroupID: "channel-1", UserID: "user-1",
		Attributes: map[string]any{"STR": float64(55)}, AttrsSet: true,
	}); !set.OK {
		t.Fatalf("set response = %#v", set)
	}
	created := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSave, GroupID: "channel-1", UserID: "user-1", Name: "Snapshot", NameSet: true,
	})
	if !created.OK || created.ID == "" {
		t.Fatalf("save response = %#v", created)
	}
	updated := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationSave, GroupID: "channel-1", UserID: "user-1", Name: "Snapshot", NameSet: true,
	})
	if !updated.OK || updated.ID != created.ID || updated.Action != "updated" {
		t.Fatalf("save-over response = %#v", updated)
	}
	bound := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationTag, GroupID: "channel-1", UserID: "user-1", Character: created.ID,
	})
	if !bound.OK {
		t.Fatalf("bind saved character = %#v", bound)
	}
	got := characterCall(t, service, adapterapi.CharacterRequest{
		Operation: adapterapi.CharacterOperationGet, GroupID: "channel-1", UserID: "user-1",
	})
	if !got.OK || characterWireAttributes(t, got)["STR"] != float64(55) {
		t.Fatalf("save-over lost source values: %#v", got)
	}
}
