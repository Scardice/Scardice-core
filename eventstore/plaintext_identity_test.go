package eventstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPlainPluginIdentitiesPreserveCaseWhitespaceAndOpaqueBytes(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	extensions := []string{"CaseA", "casea", "CaseA ", "a\x00"}
	keys := []string{"Key", "key", "", " ", "trailing ", "\x00", string([]byte{255, 254})}
	for _, extension := range extensions {
		for i, key := range keys {
			value := []byte{byte(i), 0, 255}
			if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: extension, Key: key, Value: value}); err != nil {
				t.Fatalf("put %q/%q: %v", extension, key, err)
			}
		}
	}
	for _, extension := range extensions {
		items, err := store.ListPluginKV(ctx, PluginKVListRequest{ExtensionID: extension})
		if err != nil || len(items) != len(keys) {
			t.Fatalf("list %q: %d %v", extension, len(items), err)
		}
		for i, key := range keys {
			item, err := store.GetPluginKV(ctx, extension, key)
			if err != nil || item.Key != key || !bytes.Equal(item.Value, []byte{byte(i), 0, 255}) {
				t.Fatalf("get %q/%q: %+v %v", extension, key, item, err)
			}
		}
	}
	snapshot, err := store.LookupPluginKVSnapshot(ctx, "CaseA", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePluginKV(ctx, "CaseA", "", snapshot.Item.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "CaseA", Key: "", Value: []byte{}}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{PluginKVReads: []PluginKVReadExpectation{{Namespace: snapshot.Namespace, Key: snapshot.Key, ExpectedRevision: snapshot.KeyRevision, ExpectedExists: true}}, Operations: []OperationUpdate{{OperationID: "stale-plugin"}}})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("empty-key ABA accepted old revision: %v", err)
	}
}
func TestPlainSecretReferencesRemainExactAndReturnOwnedBytes(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	refs := []string{"vault:CaseA", "vault:casea", "vault:CaseA ", "vault:" + strings.Repeat("x", 300)}
	for i, ref := range refs {
		if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: ref, EndpointID: "Endpoint", AdapterID: "Adapter", Value: []byte{byte(i), 255}}); err != nil {
			t.Fatal(err)
		}
	}
	lookups := make([]SecretLookup, len(refs))
	for i, ref := range refs {
		lookups[i] = SecretLookup{SecretRef: ref, SecretVersion: 1}
	}
	values, err := store.ResolveSecrets(ctx, lookups)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range values {
		if value.SecretRef != refs[i] || !bytes.Equal(value.Value, []byte{byte(i), 255}) {
			t.Fatalf("batch identity folded: %+v", values)
		}
		value.Value[0] = 99
		again, err := store.ResolveSecret(ctx, refs[i], 1)
		if err != nil || again.Value[0] != byte(i) {
			t.Fatalf("secret result aliased storage: %+v %v", again, err)
		}
	}
	if _, err := store.ResolveSecretForOwner(ctx, "endpoint", "Adapter", refs[0], 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("secret owner case folded: %v", err)
	}
}
func TestLongPlainLanesSeekByCandidateAndKeepExactIdentity(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	base := strings.Repeat("x", 4095)
	encodedA, _ := json.Marshal([3]string{"endpoint", "group", base + "a"})
	encodedB, _ := json.Marshal([3]string{"endpoint", "group", base + "b"})
	laneA, laneB := string(encodedA), string(encodedB)
	first := newOutboxTestEffect("z-first", laneA)
	second := newOutboxTestEffect("a-second", laneA)
	if _, err := store.Commit(ctx, UnitOfWork{Effects: []NewEffect{first, second}}); err != nil {
		t.Fatal(err)
	}
	var headA laneHeadRow
	if err := laneQuery(db.GORM(), outboxLaneKind, laneA).Take(&headA).Error; err != nil {
		t.Fatal(err)
	}
	// Force a candidate collision in stored index metadata; no production hash
	// override is needed. Different raw identities must still receive distinct IDs.
	digestB := Digest("lane-lookup/v1", laneB)
	if err := db.GORM().Model(&laneHeadRow{}).Where("id = ?", headA.ID).UpdateColumn("lookup_digest", digestB).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptOutbox(ctx, newOutboxTestEffect("other-lane", laneB)); err != nil {
		t.Fatal(err)
	}
	var headB laneHeadRow
	if err := laneQuery(db.GORM(), outboxLaneKind, laneB).Take(&headB).Error; err != nil {
		t.Fatal(err)
	}
	if headA.ID == headB.ID || headB.Lane != laneB {
		t.Fatalf("candidate digest became lane identity: a=%+v b=%+v", headA, headB)
	}
	var candidates int64
	if err := db.GORM().Model(&laneHeadRow{}).Where("lookup_digest = ?", digestB).Count(&candidates).Error; err != nil || candidates != 2 {
		t.Fatalf("candidate collision not retained: %d %v", candidates, err)
	}
	if err := db.GORM().Model(&laneHeadRow{}).Where("id = ?", headA.ID).UpdateColumn("lookup_digest", Digest("lane-lookup/v1", laneA)).Error; err != nil {
		t.Fatal(err)
	}
	var rows []outboxEffectRow
	if err := db.GORM().Where("lane_id = ?", headA.ID).Order("ordering_sequence ASC").Find(&rows).Error; err != nil || len(rows) != 2 || rows[0].EffectID != "z-first" || rows[1].EffectID != "a-second" {
		t.Fatalf("emission FIFO changed: %+v %v", rows, err)
	}
	for _, row := range rows {
		if row.Lane != laneA {
			t.Fatal("raw lane was truncated")
		}
	}
}
func TestLargeProviderIdentifiersRemainDistinctAndDeduplicateExactly(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	endpoint := strings.Repeat("e", 4094) + "\x00E"
	prefix := strings.Repeat("p", 4094)
	subject := "g\x00raw"
	update := InboxUpdate{InboxID: "provider-a", EndpointID: endpoint, ProviderEventKey: prefix + "\x00A", Lane: "lane", Subject: subject, Payload: []byte{}}
	first, err := store.AcceptInbox(ctx, update)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.AcceptInbox(ctx, update)
	if err != nil || !repeated.Deduplicated || repeated.OrderingSequence != first.OrderingSequence {
		t.Fatalf("dedup=%+v %v", repeated, err)
	}
	update.InboxID = "provider-b"
	update.ProviderEventKey = prefix + "\x00a"
	if _, err := store.AcceptInbox(ctx, update); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.GORM().Model(&inboxMessageRow{}).Count(&count).Error; err != nil || count != 2 {
		t.Fatalf("provider case/prefix folded: %d %v", count, err)
	}
	if _, err := store.CreateStoryLog(ctx, "dice", subject, "archive"); err != nil {
		t.Fatal(err)
	}
	deleted := confirmGroupDelete(t, store, PrivacyDryRunRequest{GroupID: subject, DiceIDs: []string{"dice"}, Scopes: []string{"logs"}})
	if deleted.Deleted.Inbox != 2 || deleted.Deleted.LogSessions != 1 {
		t.Fatalf("raw NUL scope purge=%+v", deleted)
	}
}
func TestStoryLongScopeAndNameRoundTripThroughReadDependencyCommit(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	dice := strings.Repeat("D", 4096) + "\x00Dice "
	group := strings.Repeat("g", 4096) + "\x00Group "
	name := strings.Repeat("name", 1024)
	_, read, err := store.GetStoryLogStateSnapshot(ctx, dice, group)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Owner) <= 1024 {
		t.Fatal("fixture did not exceed the old scope bound")
	}
	if _, err := store.Commit(ctx, UnitOfWork{CatalogReads: []CatalogReadExpectation{read}, LogUpdates: []LogUpdate{NewStoryLogCreateSessionUpdate(dice, group, name), NewStoryLogStateUpdate(StoryLogState{DiceID: dice, GroupID: group, Name: name, On: true})}}); err != nil {
		t.Fatal(err)
	}
	state, current, err := store.GetStoryLogStateSnapshot(ctx, dice, group)
	if err != nil || state.Name != name || state.DiceID != dice || state.GroupID != group || state.SessionID == 0 {
		t.Fatalf("long state=%+v read=%+v err=%v", state, current, err)
	}
	listed, err := store.ListStoryLogsForDice(ctx, dice)
	if err != nil || len(listed) != 1 || listed[0].DiceID != dice {
		t.Fatalf("long dice list=%+v %v", listed, err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{CatalogReads: []CatalogReadExpectation{current}, Operations: []OperationUpdate{{OperationID: "long-story-read"}}}); err != nil {
		t.Fatalf("long scope read dependency rejected: %v", err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{CatalogReads: []CatalogReadExpectation{read}, Operations: []OperationUpdate{{OperationID: "old-long-story-read"}}}); !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("stale long scope read accepted: %v", err)
	}
	rawID := strings.Repeat("r", 4096) + "\x00raw"
	if err := store.AppendStoryLogEntry(ctx, StoryLogEntry{DiceID: dice, GroupID: group, LogName: name, RawMsgID: rawID, Message: "plain story"}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.GetStoryLogEntries(ctx, dice, group, name)
	if err != nil || len(entries) != 1 || entries[0].DiceID != dice || entries[0].GroupID != group || entries[0].RawMsgID != rawID {
		t.Fatalf("long entry=%+v %v", entries, err)
	}
	state.On = false
	if err := store.SetStoryLogState(ctx, state); err != nil {
		t.Fatal(err)
	}
	stateAfter, err := store.GetStoryLogState(ctx, dice, group)
	if err != nil || stateAfter.On || stateAfter.SessionID != state.SessionID {
		t.Fatalf("long scope state update=%+v %v", stateAfter, err)
	}
	source := strings.Repeat("source", 200) + "\x00id"
	record := StoryLogImportRecord{SourceID: source, Kind: StoryLogImportSession, DiceID: dice, GroupID: group, Session: &StoryLogSession{DiceID: dice, GroupID: group, Name: "imported", CreatedAt: 1, UpdatedAt: 1}}
	if _, err := store.ImportStoryLogBatch(ctx, []StoryLogImportRecord{record}); err != nil {
		t.Fatal(err)
	}
	receipts, err := store.ListStoryLogImports(ctx, strings.Repeat("source", 200), dice)
	if err != nil || len(receipts) != 1 || receipts[0].SourceID != source {
		t.Fatalf("long import receipts=%+v %v", receipts, err)
	}
}
func TestRevisionCandidatesCanCollideWithoutMergingRawResources(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	first, err := store.ReadCatalogRevision(ctx, "catalog", "owner-a")
	if err != nil {
		t.Fatal(err)
	}
	var row revisionHeadRow
	if err := revisionQuery(db.GORM(), revisionKindCatalog, first.Owner, first.Catalog).Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	digestB := Digest("revision-lookup/v1", revisionKindCatalog, "owner-b", "catalog")
	if err := db.GORM().Model(&revisionHeadRow{}).Where("id = ?", row.ID).UpdateColumn("lookup_digest", digestB).Error; err != nil {
		t.Fatal(err)
	}
	second, err := store.ReadCatalogRevision(ctx, "catalog", "owner-b")
	if err != nil || second.Owner != "owner-b" {
		t.Fatalf("raw owner merged: %+v %v", second, err)
	}
	var candidates int64
	if err := db.GORM().Model(&revisionHeadRow{}).Where("lookup_digest = ?", digestB).Count(&candidates).Error; err != nil || candidates != 2 {
		t.Fatalf("revision candidate digest is unique: %d %v", candidates, err)
	}
}

func TestSecretReferenceMaximumIsConsistentAcrossWriteAndBatchPaths(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	ref := strings.Repeat("r", MaxSecretRefBytes)
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: ref, EndpointID: "owner", AdapterID: "attributes", Value: []byte{}}); err != nil {
		t.Fatal(err)
	}
	values, err := store.ResolveSecrets(ctx, []SecretLookup{{SecretRef: ref, SecretVersion: 1}})
	if err != nil || len(values) != 1 || values[0].SecretRef != ref {
		t.Fatalf("maximum reference read=%+v %v", values, err)
	}
	tooLong := SecretPutRequest{SecretRef: ref + "x", EndpointID: "owner", AdapterID: "attributes", Value: []byte{}}
	if _, err := store.PutSecret(ctx, tooLong); err == nil {
		t.Fatal("standalone secret accepted oversized reference")
	}
	if _, err := store.PrepareSecretUpdate(ctx, tooLong); err == nil {
		t.Fatal("prepared secret accepted oversized reference")
	}
	if _, err := store.Commit(ctx, UnitOfWork{SecretUpdates: []SecretUpdate{{SecretRef: tooLong.SecretRef, EndpointID: tooLong.EndpointID, AdapterID: tooLong.AdapterID, SecretVersion: 1, ValueSet: true}}}); err == nil {
		t.Fatal("UOW secret accepted oversized reference")
	}
	if _, err := store.ResolveSecrets(ctx, []SecretLookup{{SecretRef: tooLong.SecretRef, SecretVersion: 1}}); err == nil {
		t.Fatal("batch secret accepted oversized reference")
	}
}
