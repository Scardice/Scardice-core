package dice

import (
	"context"
	"testing"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/core/attributestate"
)

func TestAttributeRepositorySaveAdvancesCharacterCatalog(t *testing.T) {
	manager, store := newAttributeExecutionFixture(t)
	ctx := context.Background()
	const ownerID = "QQ:catalog-writer"
	const characterID = "catalog-card"
	catalogOwner := attributestate.CatalogOwner(manager.diceID, ownerID)
	before, err := store.ReadCatalogRevision(ctx, attributestate.CharacterCatalog, catalogOwner)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ds.NewDictVal(&ds.ValueMap{}).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.durable.Save(ctx, attributestate.State{
		DiceID: manager.diceID, ID: characterID, AttrsType: attributestate.AttrsTypeCharacter,
		OwnerID: ownerID, Name: "before", SheetType: "coc7", CreatedAt: 1, UpdatedAt: 1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	afterCreate, err := store.ReadCatalogRevision(ctx, attributestate.CharacterCatalog, catalogOwner)
	if err != nil {
		t.Fatal(err)
	}
	if afterCreate.Revision != before.Revision+1 {
		t.Fatalf("catalog revision after create = %d, want %d", afterCreate.Revision, before.Revision+1)
	}
	state.Name = "after"
	state.UpdatedAt = 2
	_, err = manager.durable.Save(ctx, state, payload)
	if err != nil {
		t.Fatal(err)
	}
	afterRename, err := store.ReadCatalogRevision(ctx, attributestate.CharacterCatalog, catalogOwner)
	if err != nil {
		t.Fatal(err)
	}
	if afterRename.Revision != afterCreate.Revision+1 {
		t.Fatalf("catalog revision after rename = %d, want %d", afterRename.Revision, afterCreate.Revision+1)
	}
	snapshot, err := attributestate.ListCatalogProjected(ctx, store, manager.diceID, attributestate.CharacterCatalog, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.States) != 1 || snapshot.States[0].ID != characterID || snapshot.States[0].Name != "after" {
		t.Fatalf("character catalog snapshot = %#v", snapshot.States)
	}
	if snapshot.Revision != afterRename.Revision {
		t.Fatalf("catalog snapshot revision = %d, want %d", snapshot.Revision, afterRename.Revision)
	}
	// A catalog read dependency is held together with a write. A current
	// snapshot must be accepted next to an unrelated attribute write.
	transaction, collector := newAttributeTransaction(t, store)
	if _, err = manager.GetCharacterListForTransaction(ctx, transaction, ownerID); err != nil {
		t.Fatal(err)
	}
	unrelated, err := manager.LoadByTransaction(ctx, transaction, "QQ-Group:catalog-dependency-QQ:catalog-dependency")
	if err != nil {
		t.Fatal(err)
	}
	if err = unrelated.Store("seen", ds.NewIntVal(1)); err != nil {
		t.Fatal(err)
	}
	if err = commitAttributeTransaction(t, store, transaction, collector); err != nil {
		t.Fatalf("current catalog dependency rejected: %v", err)
	}
}
