package eventstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/core/attributestate"
	"Scardice-core/eventstore"
)

func openPrivacyAttributesFixture(t *testing.T) (*eventstore.GORMStore, *eventstore.Database, *attributestate.Repository, eventstore.PrivacySubjectKeyResolver) {
	t.Helper()
	ctx := context.Background()
	source := fixedExternalKeySource{indexID: "privacy-attributes-index-v1", rootID: "privacy-attributes-root-v1"}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "privacy-attributes.db"), DatabaseIdentity: "privacy-attributes-db",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "privacy-attributes-db",
		IndexRootID: "privacy-attributes-index-v1", EncryptionRootIDs: []string{"privacy-attributes-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := store.RegisterProjection(attributestate.Projection()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	resolver, ok := any(store).(eventstore.PrivacySubjectKeyResolver)
	if !ok {
		db.Close()
		t.Fatal("GORMStore does not implement PrivacySubjectKeyResolver")
	}
	return store, db, repository, resolver
}

func savePrivacyAttribute(t *testing.T, ctx context.Context, repository *attributestate.Repository, state attributestate.State, subjectKey []byte, payload string) attributestate.State {
	t.Helper()
	state.PrivacySubjectKey = append([]byte(nil), subjectKey...)
	saved, err := repository.Save(ctx, state, []byte(payload))
	if err != nil {
		t.Fatalf("save attributes %s/%s: %v", state.DiceID, state.ID, err)
	}
	return saved
}

func privacyAttributeSecretRows(t *testing.T, db *eventstore.Database, secretRef string) int64 {
	t.Helper()
	var count int64
	if err := db.GORM().Table("adapter_secrets").Where("secret_ref = ?", secretRef).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func assertPrivacyPayloadOmitsSubjectKey(t *testing.T, payload []byte) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("decode persisted attribute JSON: %v", err)
	}
	for _, name := range []string{"privacySubjectKey", "subjectKey", "PrivacySubjectKey"} {
		if _, exists := fields[name]; exists {
			t.Fatalf("persisted attribute JSON contains %q", name)
		}
	}
}

func TestPrivacyAttributesRepositoryDryRunDeleteAndSecretIsolation(t *testing.T) {
	ctx := context.Background()
	store, db, repository, resolver := openPrivacyAttributesFixture(t)
	defer db.Close()

	const targetGroup = "QQ-Group:100"
	const targetGroupUser = "QQ-Group:100-QQ:201"
	const otherGroup = "QQ-Group:200"
	const otherGroupUser = "QQ-Group:200-QQ:202"
	const dice = "dice-a"
	targetKey, err := resolver.PrivacySubjectKey(ctx, targetGroup)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := resolver.PrivacySubjectKey(ctx, otherGroup)
	if err != nil {
		t.Fatal(err)
	}

	group := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: targetGroup, AttrsType: "group", Name: "target group", CreatedAt: 1, UpdatedAt: 1,
	}, targetKey, `{"revision":1}`)
	group.Name = "target group updated"
	group = savePrivacyAttribute(t, ctx, repository, group, targetKey, `{"revision":2}`)
	groupUser := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: targetGroupUser, AttrsType: "group_user", CreatedAt: 1, UpdatedAt: 1,
	}, targetKey, `{"revision":1}`)
	misclassified := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: "QQ-Group:100-QQ:203", AttrsType: "character", CreatedAt: 1, UpdatedAt: 1,
	}, nil, `{"revision":1}`)
	character := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: "character-1", AttrsType: "character", Name: "Alice", OwnerID: "user-1", CreatedAt: 1, UpdatedAt: 1,
	}, nil, `{"sheet":"character"}`)
	global := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: "user-global-1", AttrsType: "user", OwnerID: "user-1", CreatedAt: 1, UpdatedAt: 1,
	}, nil, `{"profile":"global"}`)
	other := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: otherGroup, AttrsType: "group", CreatedAt: 1, UpdatedAt: 1,
	}, otherKey, `{"revision":1}`)
	otherUser := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: otherGroupUser, AttrsType: "group_user", CreatedAt: 1, UpdatedAt: 1,
	}, otherKey, `{"revision":1}`)
	otherDice := savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: "dice-b", ID: targetGroup, AttrsType: "group", CreatedAt: 1, UpdatedAt: 1,
	}, targetKey, `{"revision":1}`)

	stateJSON, err := json.Marshal(group)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivacyPayloadOmitsSubjectKey(t, stateJSON)
	stream := attributestate.Stream(dice, targetGroup)
	events, err := store.Load(ctx, stream, 0)
	if err != nil || len(events) != 2 {
		t.Fatalf("target group events=%d err=%v", len(events), err)
	}
	if len(events[0].Metadata.SubjectKey) != 0 {
		t.Fatal("subject HMAC was persisted as event metadata")
	}
	assertPrivacyPayloadOmitsSubjectKey(t, events[0].Payload)
	projection, err := store.ReadProjectionRow(ctx, attributestate.ProjectionName, stream.AggregateID)
	if err != nil {
		t.Fatal(err)
	}
	var projected attributestate.State
	if err := json.Unmarshal(projection.Payload, &projected); err != nil {
		t.Fatal(err)
	}
	if len(projected.PrivacySubjectKey) != 0 {
		t.Fatal("subject HMAC was persisted in the attribute projection")
	}

	groupSecret := attributestate.SecretRef(dice, targetGroup)
	groupUserSecret := attributestate.SecretRef(dice, groupUser.ID)
	characterSecret := attributestate.SecretRef(dice, character.ID)
	otherSecret := attributestate.SecretRef(dice, otherGroup)
	globalSecret := attributestate.SecretRef(dice, global.ID)
	otherUserSecret := attributestate.SecretRef(dice, otherGroupUser)
	misclassifiedSecret := attributestate.SecretRef(dice, misclassified.ID)
	otherDiceSecret := attributestate.SecretRef("dice-b", targetGroup)
	if count := privacyAttributeSecretRows(t, db, groupSecret); count != 2 {
		t.Fatalf("target group secret versions before purge=%d, want 2", count)
	}

	scan, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: targetGroup, DiceIDs: []string{dice}, Scopes: []string{"attrs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if scan.Counts != (eventstore.PrivacyCounts{Attrs: 4}) {
		t.Fatalf("dry-run attributes count=%+v, want 4 selected group/group-user events", scan.Counts)
	}
	if err := store.PrivacyCreateOperation(ctx, "privacy-attributes-delete", scan.SubjectKey, eventstore.PrivacyOperationContext{
		GroupID: targetGroup, DiceIDs: []string{dice}, Scopes: []string{"attrs"}, Phase: "delete",
		Counts: scan.Counts, TargetHighWater: scan.TargetHighWater,
		ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrivacyFence(ctx, scan.SubjectKey, "group", "privacy-attributes-delete"); err != nil {
		t.Fatal(err)
	}

	var deleted int64
	cursor := ""
	for pageNumber := 0; ; pageNumber++ {
		batch, err := store.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{
			OperationID: "privacy-attributes-delete", GroupID: targetGroup, Phase: "delete",
			DiceIDs: []string{dice}, Scopes: []string{"attrs"}, Cursor: cursor, Limit: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		deleted += batch.Deleted.Attrs
		if pageNumber == 0 {
			if batch.Deleted.Attrs != 1 || batch.Done {
				t.Fatalf("first page=%+v, want one event and more pages", batch)
			}
			remaining, loadErr := store.Load(ctx, stream, 0)
			if loadErr != nil || len(remaining) != 1 {
				t.Fatalf("target group history after first page=%d err=%v", len(remaining), loadErr)
			}
			if count := privacyAttributeSecretRows(t, db, groupSecret); count != 2 {
				t.Fatalf("secret versions deleted while stream history remained: %d", count)
			}
		}
		if pageNumber == 1 {
			if batch.Deleted.Attrs != 1 {
				t.Fatalf("second page=%+v, want final event in target group stream", batch)
			}
			if count := privacyAttributeSecretRows(t, db, groupSecret); count != 0 {
				t.Fatalf("target group secret versions after final event=%d, want 0", count)
			}
		}
		if batch.Done && batch.Deleted.Attrs == 0 && batch.NextCursor == cursor {
			t.Fatalf("completion did not advance past nonmatching attribute rows from cursor %q", cursor)
		}
		if batch.Done {
			break
		}
		if batch.NextCursor == cursor {
			t.Fatalf("privacy batch cursor did not progress from %q", cursor)
		}
		cursor = batch.NextCursor
		view, private, err := store.PrivacyLoadOperation(ctx, "privacy-attributes-delete")
		if err != nil {
			t.Fatal(err)
		}
		private.Cursor = cursor
		if _, err := store.PrivacyUpdateOperation(ctx, view.OperationID, view.Version, private, "running"); err != nil {
			t.Fatal(err)
		}
	}
	if deleted != 4 {
		t.Fatalf("deleted attributes=%d, want 4", deleted)
	}
	for _, target := range []struct {
		stream eventstore.StreamID
		id     string
	}{{attributestate.Stream(dice, targetGroup), targetGroup}, {attributestate.Stream(dice, groupUser.ID), groupUser.ID}, {attributestate.Stream(dice, misclassified.ID), misclassified.ID}} {
		rows, err := store.Load(ctx, target.stream, 0)
		if err != nil || len(rows) != 0 {
			t.Fatalf("purged stream %s history=%d err=%v", target.id, len(rows), err)
		}
		if _, _, err := repository.Load(ctx, dice, target.id); !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatalf("purged projection/secret for %s: err=%v", target.id, err)
		}
	}
	for _, survivor := range []struct {
		diceID string
		id     string
		secret string
	}{{dice, character.ID, characterSecret}, {dice, global.ID, globalSecret}, {dice, other.ID, otherSecret}, {dice, otherUser.ID, otherUserSecret}, {"dice-b", otherDice.ID, otherDiceSecret}} {
		if _, _, err := repository.Load(ctx, survivor.diceID, survivor.id); err != nil {
			t.Fatalf("survivor %s/%s did not load: %v", survivor.diceID, survivor.id, err)
		}
		if count := privacyAttributeSecretRows(t, db, survivor.secret); count != 1 {
			t.Fatalf("survivor secret %s versions=%d, want 1", survivor.secret, count)
		}
	}
	if count := privacyAttributeSecretRows(t, db, groupUserSecret); count != 0 {
		t.Fatalf("target group-user secret versions=%d, want 0", count)
	}
	if count := privacyAttributeSecretRows(t, db, misclassifiedSecret); count != 0 {
		t.Fatalf("misclassified target group-user secret versions=%d, want 0", count)
	}
}

func TestPrivacyOfficialQQChannelGroupUserIdentitiesAreScopedAndPurgeable(t *testing.T) {
	tests := []struct {
		name      string
		groupID   string
		userID    string
		attrsType string
	}{
		{
			name: "private_group_user", groupID: "PG-OpenQQCH:private-100",
			userID: "OpenQQCH:private-100", attrsType: "group_user",
		},
		{
			name: "channel_group_user", groupID: "OpenQQCH-Channel:guild-1-channel-1",
			userID: "OpenQQCH:user-101", attrsType: "group_user",
		},
		{
			name: "legacy_private_group", groupID: "PG-OpenQQCH:legacy-200",
			attrsType: "character",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, db, repository, resolver := openPrivacyAttributesFixture(t)
			defer db.Close()
			const diceID = "dice-openqqch"
			attributeID := test.groupID
			var subjectKey []byte
			if test.userID != "" {
				attributeID += "-" + test.userID
				var err error
				subjectKey, err = resolver.PrivacySubjectKey(ctx, test.groupID)
				if err != nil {
					t.Fatal(err)
				}
			}
			savePrivacyAttribute(t, ctx, repository, attributestate.State{
				DiceID: diceID, ID: attributeID, AttrsType: test.attrsType, CreatedAt: 1, UpdatedAt: 1,
			}, subjectKey, `{"score":7}`)

			scan, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
				GroupID: test.groupID, DiceIDs: []string{diceID}, Scopes: []string{"attrs"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if scan.Counts.Attrs != 1 {
				t.Fatalf("dry-run attributes=%d, want 1 for %q", scan.Counts.Attrs, attributeID)
			}
			operationID := "privacy-" + test.name
			if err = store.PrivacyCreateOperation(ctx, operationID, scan.SubjectKey, eventstore.PrivacyOperationContext{
				GroupID: test.groupID, DiceIDs: []string{diceID}, Scopes: []string{"attrs"}, Phase: "delete",
				Counts: scan.Counts, TargetHighWater: scan.TargetHighWater,
				ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = store.PrivacyFence(ctx, scan.SubjectKey, "group", operationID); err != nil {
				t.Fatal(err)
			}
			batch, err := store.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{
				OperationID: operationID, GroupID: test.groupID, Phase: "delete",
				DiceIDs: []string{diceID}, Scopes: []string{"attrs"}, Limit: 10,
			})
			if err != nil {
				t.Fatal(err)
			}
			if batch.Deleted.Attrs != 1 || !batch.Done {
				t.Fatalf("purge batch = %+v, want one deleted attribute and completion", batch)
			}
			if _, _, err = repository.Load(ctx, diceID, attributeID); !errors.Is(err, eventstore.ErrNotFound) {
				t.Fatalf("purged attribute %q remains readable: %v", attributeID, err)
			}
			if count := privacyAttributeSecretRows(t, db, attributestate.SecretRef(diceID, attributeID)); count != 0 {
				t.Fatalf("purged secret %q still has %d versions", attributeID, count)
			}
		})
	}
}

func TestPrivacyMalformedGroupUserFailsClosedForPurge(t *testing.T) {
	ctx := context.Background()
	store, db, repository, resolver := openPrivacyAttributesFixture(t)
	defer db.Close()
	const targetGroup = "QQ-Group:100"
	const malformedID = "QQ-Group:100-QQ"
	const dice = "dice-a"

	savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: malformedID, AttrsType: "group_user", CreatedAt: 1, UpdatedAt: 1,
	}, nil, `{"hp":5}`)
	secretRef := attributestate.SecretRef(dice, malformedID)

	prefixNeighbor, err := store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: "QQ-Group:10", DiceIDs: []string{dice}, Scopes: []string{"attrs"},
	})
	if err != nil || prefixNeighbor.Counts.Attrs != 0 {
		t.Fatalf("prefix-neighbor dry-run = %+v, err=%v; malformed group-user data must not match by a loose prefix", prefixNeighbor, err)
	}
	savePrivacyAttribute(t, ctx, repository, attributestate.State{
		DiceID: dice, ID: targetGroup, AttrsType: "group_user", CreatedAt: 1, UpdatedAt: 1,
	}, nil, `{"hp":6}`)
	if _, err = store.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{
		GroupID: targetGroup, DiceIDs: []string{dice}, Scopes: []string{"attrs"},
	}); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("ambiguous malformed group-user dry-run err=%v, want ErrInvalidMetadata", err)
	}

	subjectKey, err := resolver.PrivacySubjectKey(ctx, targetGroup)
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "privacy-malformed-group-user"
	if err = store.PrivacyCreateOperation(ctx, operationID, subjectKey, eventstore.PrivacyOperationContext{
		GroupID: targetGroup, DiceIDs: []string{dice}, Scopes: []string{"attrs"}, Phase: "delete",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PrivacyFence(ctx, subjectKey, "group", operationID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{
		OperationID: operationID, GroupID: targetGroup, Phase: "delete",
		DiceIDs: []string{dice}, Scopes: []string{"attrs"}, Limit: 10,
	}); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("ambiguous malformed group-user delete err=%v, want ErrInvalidMetadata", err)
	}
	rows, err := store.Load(ctx, attributestate.Stream(dice, malformedID), 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("ambiguous malformed stream was deleted: history=%d err=%v", len(rows), err)
	}
	if _, _, err = repository.Load(ctx, dice, malformedID); err != nil {
		t.Fatalf("ambiguous malformed projection/secret was removed: %v", err)
	}
	if count := privacyAttributeSecretRows(t, db, secretRef); count != 1 {
		t.Fatalf("ambiguous malformed secret versions=%d, want 1", count)
	}
}

func TestPrivacyFenceAttributesUsesSubjectKeyAndFailsClosedWithoutOne(t *testing.T) {
	ctx := context.Background()
	store, db, repository, resolver := openPrivacyAttributesFixture(t)
	defer db.Close()
	const targetGroup = "QQ-Group:100"
	targetKey, err := resolver.PrivacySubjectKey(ctx, targetGroup)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PrivacyCreateOperation(ctx, "privacy-attributes-fence", targetKey, eventstore.PrivacyOperationContext{
		GroupID: targetGroup, DiceIDs: []string{"dice-a"}, Scopes: []string{"attrs"}, Phase: "delete",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrivacyFence(ctx, targetKey, "group", "privacy-attributes-fence"); err != nil {
		t.Fatal(err)
	}

	groupSave := func(id, diceID string, attrsType string, subjectKey []byte) error {
		_, err := repository.Save(ctx, attributestate.State{
			DiceID: diceID, ID: id, AttrsType: attrsType, CreatedAt: 1, UpdatedAt: 1,
			PrivacySubjectKey: append([]byte(nil), subjectKey...),
		}, []byte(fmt.Sprintf("secret:%s:%s", diceID, id)))
		return err
	}
	if err := groupSave(targetGroup, "dice-a", "group", targetKey); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("same-subject group write err=%v, want ErrInvalidTransition", err)
	}
	unrelatedKey, err := resolver.PrivacySubjectKey(ctx, "QQ-Group:200")
	if err != nil {
		t.Fatal(err)
	}
	if err := groupSave("QQ-Group:200", "dice-a", "group", unrelatedKey); err != nil {
		t.Fatalf("unrelated group with its own subject key was blocked: %v", err)
	}
	if err := groupSave(targetGroup, "dice-a", "group", unrelatedKey); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("target group write with another group's subject key err=%v, want ErrInvalidMetadata", err)
	}
	if err := groupSave("QQ-Group:300", "dice-a", "group", nil); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("missing-key group write err=%v, want ErrInvalidTransition", err)
	}
	if err := groupSave("QQ-Group:100-QQ:301", "dice-a", "group_user", nil); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("missing-key group-user write err=%v, want ErrInvalidTransition", err)
	}
	if err := groupSave("QQ-Group:100-QQ:302", "dice-a", "character", nil); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("mislabeled group-user write without a subject key err=%v, want ErrInvalidTransition", err)
	}
	if err := groupSave("QQ-Group:100-QQ:302", "dice-a", "character", targetKey); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("mislabeled group-user write with the fenced subject key err=%v, want ErrInvalidTransition", err)
	}
	if err := groupSave("QQ-Group:100-QQ", "dice-a", "group_user", nil); !errors.Is(err, eventstore.ErrInvalidTransition) {
		t.Fatalf("malformed group-user write without a subject key err=%v, want ErrInvalidTransition", err)
	}
	if err := groupSave("QQ-Group:100-QQ", "dice-a", "group_user", targetKey); !errors.Is(err, eventstore.ErrInvalidMetadata) {
		t.Fatalf("malformed group-user write with a subject key err=%v, want ErrInvalidMetadata", err)
	}
	if err := groupSave("character-1", "dice-a", "character", nil); err != nil {
		t.Fatalf("character write was blocked by group fence: %v", err)
	}
	if err := groupSave("user-global-1", "dice-a", "user", nil); err != nil {
		t.Fatalf("global attribute write was blocked by group fence: %v", err)
	}
}
