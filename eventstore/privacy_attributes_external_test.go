package eventstore_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"Scardice-core/core/attributestate"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

func openPrivacyAttributesFixture(t *testing.T) (*eventstore.GORMStore, *eventstore.Database, *attributestate.Repository) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "attributes.db"), DatabaseIdentity: "privacy-attributes"})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, projectionset.StoreOptions()...)
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	return store, db, repository
}
func savePrivacyAttribute(t *testing.T, repository *attributestate.Repository, state attributestate.State, payload string) attributestate.State {
	t.Helper()
	saved, err := repository.Save(context.Background(), state, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return saved
}
func privacyAttributeSecretRows(t *testing.T, db *eventstore.Database, ref string) int64 {
	t.Helper()
	var count int64
	if err := db.GORM().Table("adapter_secrets").Where("secret_ref = ?", []byte(ref)).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}
func deleteAttributeGroup(t *testing.T, store *eventstore.GORMStore, groupID, diceID string) eventstore.PrivacyDeleteResult {
	t.Helper()
	req := eventstore.PrivacyDryRunRequest{GroupID: groupID, DiceIDs: []string{diceID}, Scopes: []string{"attrs"}}
	scan, err := store.PrivacyDryRun(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.PrivacyDeleteGroup(context.Background(), eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestPrivacyAttributesDeletesWholeStreamsSecretsAndOnlySelectedOwners(t *testing.T) {
	ctx := context.Background()
	store, db, repository := openPrivacyAttributesFixture(t)
	defer db.Close()
	const dice = "dice-a"
	const groupID = "QQ-Group:100"
	group := savePrivacyAttribute(t, repository, attributestate.State{DiceID: dice, ID: groupID, AttrsType: "group", CreatedAt: 1, UpdatedAt: 1}, `{"revision":1}`)
	group.Name = "updated"
	group = savePrivacyAttribute(t, repository, group, `{"revision":2}`)
	user := savePrivacyAttribute(t, repository, attributestate.State{DiceID: dice, ID: groupID + "-QQ:200", AttrsType: "group_user", BindingSheetID: "character-1", CreatedAt: 1, UpdatedAt: 1}, `{"hp":2}`)
	misclassified := savePrivacyAttribute(t, repository, attributestate.State{DiceID: dice, ID: groupID + "-QQ:201", AttrsType: "character", CreatedAt: 1, UpdatedAt: 1}, `{"hp":3}`)
	survivors := []attributestate.State{
		{DiceID: dice, ID: "character-1", AttrsType: "character", OwnerID: "user-1", CreatedAt: 1, UpdatedAt: 1},
		{DiceID: dice, ID: "user-1", AttrsType: "user", CreatedAt: 1, UpdatedAt: 1},
		{DiceID: dice, ID: "QQ-Group:1000", AttrsType: "group", CreatedAt: 1, UpdatedAt: 1},
		{DiceID: dice, ID: "QQ-Group:1000-QQ:200", AttrsType: "group_user", CreatedAt: 1, UpdatedAt: 1},
		{DiceID: "dice-b", ID: groupID, AttrsType: "group", CreatedAt: 1, UpdatedAt: 1},
	}
	for i, state := range survivors {
		survivors[i] = savePrivacyAttribute(t, repository, state, `{"keep":true}`)
	}
	before, err := store.ReadCatalogRevision(ctx, attributestate.BindingCatalog, attributestate.CatalogOwner(dice, "character-1"))
	if err != nil {
		t.Fatal(err)
	}
	result := deleteAttributeGroup(t, store, groupID, dice)
	if result.Deleted.Attrs != 4 || result.Deleted.Secrets != 4 || result.Deleted.Projections != 3 {
		t.Fatalf("actual delete counts=%+v", result.Deleted)
	}
	for _, state := range []attributestate.State{group, user, misclassified} {
		events, err := store.Load(ctx, attributestate.Stream(state.DiceID, state.ID), 0)
		if err != nil || len(events) != 0 {
			t.Fatalf("stream survived %s: %d %v", state.ID, len(events), err)
		}
		if _, _, err := repository.Load(ctx, state.DiceID, state.ID); !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatalf("deleted attribute remained readable %s: %v", state.ID, err)
		}
		if count := privacyAttributeSecretRows(t, db, attributestate.SecretRef(state.DiceID, state.ID)); count != 0 {
			t.Fatalf("attribute secret survived %s: %d", state.ID, count)
		}
	}
	for _, state := range survivors {
		if _, _, err := repository.Load(ctx, state.DiceID, state.ID); err != nil {
			t.Fatalf("surviving owner %s/%s: %v", state.DiceID, state.ID, err)
		}
		if count := privacyAttributeSecretRows(t, db, attributestate.SecretRef(state.DiceID, state.ID)); count != 1 {
			t.Fatalf("surviving secret rows=%d", count)
		}
	}
	after, err := store.ReadCatalogRevision(ctx, before.Catalog, before.Owner)
	if err != nil || after.Revision <= before.Revision {
		t.Fatalf("binding catalog revision did not advance: before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestPrivacyAttributesDeletionKeepsCaseDistinctDiceOwners(t *testing.T) {
	ctx := context.Background()
	store, db, repository := openPrivacyAttributesFixture(t)
	defer db.Close()
	const groupID = "QQ-Group:100"
	ids := []string{groupID, groupID + "-QQ:200"}
	types := []string{"group", "group_user"}
	for i, id := range ids {
		savePrivacyAttribute(t, repository, attributestate.State{DiceID: "dice-a", ID: id, AttrsType: types[i], CreatedAt: 1, UpdatedAt: 1}, `{"delete":true}`)
		survivor := savePrivacyAttribute(t, repository, attributestate.State{DiceID: "Dice-a", ID: id, AttrsType: types[i], CreatedAt: 1, UpdatedAt: 1}, `{"keep":1}`)
		savePrivacyAttribute(t, repository, survivor, `{"keep":2}`)
	}
	req := eventstore.PrivacyDryRunRequest{GroupID: groupID, DiceIDs: []string{"dice-a"}, Scopes: []string{"attrs"}}
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil || scan.Counts.Attrs != 2 || scan.Counts.Secrets != 2 || scan.Counts.Projections != 2 {
		t.Fatalf("case-distinct dry run=%+v err=%v", scan, err)
	}
	deleted := deleteAttributeGroup(t, store, groupID, "dice-a")
	if deleted.Deleted.Attrs != 2 || deleted.Deleted.Secrets != 2 || deleted.Deleted.Projections != 2 {
		t.Fatalf("case-distinct deletion=%+v", deleted.Deleted)
	}
	for _, id := range ids {
		if _, _, err := repository.Load(ctx, "dice-a", id); !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatalf("selected attribute survived %s: %v", id, err)
		}
		state, payload, err := repository.Load(ctx, "Dice-a", id)
		if err != nil || state.DiceID != "Dice-a" || state.Version != 2 || string(payload) != `{"keep":2}` {
			t.Fatalf("case-distinct attribute changed %s: state=%+v payload=%q err=%v", id, state, payload, err)
		}
		events, err := store.Load(ctx, attributestate.Stream("Dice-a", id), 0)
		if err != nil || len(events) != 2 {
			t.Fatalf("case-distinct history changed %s: %d %v", id, len(events), err)
		}
		if count := privacyAttributeSecretRows(t, db, attributestate.SecretRef("Dice-a", id)); count != 2 {
			t.Fatalf("case-distinct secret history changed %s: %d", id, count)
		}
	}
}

func TestPrivacyOfficialQQChannelGroupUserIdentitiesRemainScoped(t *testing.T) {
	for _, tc := range []struct{ group, user, attrsType string }{
		{"PG-OpenQQCH:private-100", "OpenQQCH:private-100", "group_user"},
		{"OpenQQCH-Channel:guild-1-channel-1", "OpenQQCH:user-101", "group_user"},
		{"PG-OpenQQCH:legacy-200", "", "character"},
	} {
		t.Run(tc.group, func(t *testing.T) {
			store, db, repository := openPrivacyAttributesFixture(t)
			defer db.Close()
			id := tc.group
			if tc.user != "" {
				id += "-" + tc.user
			}
			savePrivacyAttribute(t, repository, attributestate.State{DiceID: "dice", ID: id, AttrsType: tc.attrsType, CreatedAt: 1, UpdatedAt: 1}, `{"score":7}`)
			result := deleteAttributeGroup(t, store, tc.group, "dice")
			if result.Deleted.Attrs != 1 || result.Deleted.Secrets != 1 {
				t.Fatalf("delete counts=%+v", result.Deleted)
			}
		})
	}
}
func TestPrivacyMalformedGroupUserFailsWithoutDeletingAnything(t *testing.T) {
	ctx := context.Background()
	store, db, repository := openPrivacyAttributesFixture(t)
	defer db.Close()
	const group = "QQ-Group:100"
	const malformed = "QQ-Group:100-QQ"
	savePrivacyAttribute(t, repository, attributestate.State{DiceID: "dice", ID: malformed, AttrsType: "group_user", CreatedAt: 1, UpdatedAt: 1}, `{"hp":5}`)
	neighbor, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: "QQ-Group:10", DiceIDs: []string{"dice"}, Scopes: []string{"attrs"}})
	if err != nil || neighbor.Counts.Attrs != 0 {
		t.Fatalf("loose-prefix selection: %+v %v", neighbor, err)
	}
	req := eventstore.PrivacyDryRunRequest{GroupID: group, DiceIDs: []string{"dice"}, Scopes: []string{"attrs"}}
	if _, err := store.PrivacyDryRun(ctx, req); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("ambiguous dry run=%v", err)
	}
	if _, err := store.PrivacyDeleteGroup(ctx, eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true}); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("ambiguous delete=%v", err)
	}
	if _, _, err := repository.Load(ctx, "dice", malformed); err != nil {
		t.Fatalf("ambiguous attribute was deleted: %v", err)
	}
}
