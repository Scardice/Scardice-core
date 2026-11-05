package eventstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func privacyEvent(id string) NewEvent {
	return NewEvent{EventType: "test", SchemaVersion: 1, Payload: []byte(`{"ok":true}`), Metadata: Metadata{EventID: id, CommandID: id + "-cmd", CorrelationID: id + "-corr", Producer: "test", OccurredAt: time.Unix(1, 0).UTC()}}
}
func confirmGroupDelete(t *testing.T, store *GORMStore, req PrivacyDryRunRequest) PrivacyDeleteResult {
	t.Helper()
	scan, err := store.PrivacyDryRun(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.PrivacyDeleteGroup(context.Background(), PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestGroupPrivacyDeleteIsAtomicAndScopeIsolated(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	target := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "target")}
	other := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "other")}
	player := StreamID{AggregateType: "player", AggregateID: privacyCanonical("dice", "target", "user")}
	for i, stream := range []StreamID{target, other, player} {
		if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{privacyEvent(string(rune('a' + i)))}}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "target-in", EndpointID: "e", ProviderEventKey: "target", Lane: "shared", Subject: "target", Payload: []byte{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "other-in", EndpointID: "e", ProviderEventKey: "other", Lane: "shared", Subject: "other", Payload: []byte("keep")}); err != nil {
		t.Fatal(err)
	}
	req := PrivacyDryRunRequest{GroupID: "target", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}}
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").Take(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec("CREATE TRIGGER reject_privacy_delete BEFORE DELETE ON inbox_messages BEGIN SELECT RAISE(ABORT, 'injected'); END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrivacyDeleteGroup(ctx, PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version}); err == nil {
		t.Fatal("injected queue delete failure succeeded")
	}
	events, err := store.Load(ctx, target, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("partial stream deletion: %d %v", len(events), err)
	}
	var after projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").Take(&after).Error; err != nil || after.ActiveGeneration != before.ActiveGeneration {
		t.Fatalf("publication escaped rollback: before=%+v after=%+v err=%v", before, after, err)
	}
	if err := db.GORM().Exec("DROP TRIGGER reject_privacy_delete").Error; err != nil {
		t.Fatal(err)
	}
	deleted := confirmGroupDelete(t, store, req)
	if deleted.Deleted.GroupRecord != 1 || deleted.Deleted.Inbox != 1 || deleted.Deleted.Players != 0 {
		t.Fatalf("deleted=%+v", deleted.Deleted)
	}
	for _, stream := range []StreamID{other, player} {
		events, err := store.Load(ctx, stream, 0)
		if err != nil || len(events) != 1 {
			t.Fatalf("cross-scope delete %+v: %d %v", stream, len(events), err)
		}
	}
	var count int64
	if err := db.GORM().Model(&aggregateHeadRow{}).Where("aggregate_type = ? AND aggregate_id = ?", target.AggregateType, target.AggregateID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("head survived: %d %v", count, err)
	}
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "worker"})
	if err != nil || lease.Update.InboxID != "other-in" {
		t.Fatalf("shared lane cursor not advanced: %+v %v", lease, err)
	}
}
func TestGroupPrivacyConfirmationIncludesQueuesAndRejectsChangedContent(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	req := PrivacyDryRunRequest{GroupID: "g", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}}
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptInbox(ctx, InboxUpdate{InboxID: "new", EndpointID: "e", ProviderEventKey: "new", Lane: "lane", Subject: "g", Payload: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	result, err := store.PrivacyDeleteGroup(ctx, PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if !errors.Is(err, ErrPrivacyConfirmationMismatch) || result.Deleted != (PrivacyCounts{}) || result.Scan.Counts.Inbox != 1 {
		t.Fatalf("stale confirmation result=%+v err=%v", result, err)
	}
	var count int64
	if err := db.GORM().Model(&inboxMessageRow{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("rejected transaction deleted queue: %d %v", count, err)
	}
}
func TestGroupPrivacyDeleteInvalidatesOldGenerationAfterSameVersionRecreation(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(transactionTestProjection()); err != nil {
		t.Fatal(err)
	}
	stream := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "g")}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{transactionTestEvent("old", 1)}}}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadProjectionDependency(ctx, "counter", stream.AggregateID, stream)
	if err != nil {
		t.Fatal(err)
	}
	confirmGroupDelete(t, store, PrivacyDryRunRequest{GroupID: "g", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}})
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{transactionTestEvent("recreated", 2)}}}}); err != nil {
		t.Fatal(err)
	}
	_, err = store.Commit(ctx, UnitOfWork{StreamReads: []StreamReadExpectation{{Stream: stream, ExpectedVersion: snapshot.StreamVersion}}, ProjectionReads: []ProjectionReadExpectation{{Generation: snapshot.Snapshot.ProjectionGeneration}}, Operations: []OperationUpdate{{OperationID: "stale-result"}}})
	if !errors.Is(err, ErrParticipantConflict) {
		t.Fatalf("old read succeeded after ABA: %v", err)
	}
	if _, err := store.GetOperation(ctx, "stale-result"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale unit leaked participant: %v", err)
	}
}

func TestPrivacyProjectionNamespacesRemainScopeIsolated(t *testing.T) {
	for _, withAttrs := range []bool{false, true} {
		t.Run(strconv.FormatBool(withAttrs), func(t *testing.T) {
			ctx := context.Background()
			store, db := openPlainTestStore(t)
			defer db.Close()
			key := privacyCanonical("dice", "g")
			attrs := []byte(`{"diceId":"dice","id":"g","attrsType":"group","secretRef":""}`)
			attrEvent := privacyEvent("attrs")
			attrEvent.Payload = attrs
			work := UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "group", AggregateID: key}, Events: []NewEvent{privacyEvent("group")}}, {Stream: StreamID{AggregateType: "attributes", AggregateID: key}, Events: []NewEvent{attrEvent}}}}
			if _, err := store.Commit(ctx, work); err != nil {
				t.Fatal(err)
			}
			var control projectionControlRow
			if err := db.GORM().Where("singleton_id = ?", "default").Take(&control).Error; err != nil {
				t.Fatal(err)
			}
			for name, payload := range map[string][]byte{"group-record": []byte(`{"diceId":"dice","groupId":"g","active":false}`), "attributes": attrs, "moderation": []byte("moderation remains"), "character": []byte("global character remains")} {
				row := projectionReadModelRow{ProjectionGeneration: control.ActiveGeneration, ProjectionName: name, RowKey: key, Payload: payload, UpdatedAt: time.Unix(1, 0).UTC()}
				if err := db.GORM().Create(&row).Error; err != nil {
					t.Fatal(err)
				}
			}
			scopes := []string{"group_record"}
			want := int64(1)
			if withAttrs {
				scopes = append(scopes, "attrs")
				want = 2
			}
			result := confirmGroupDelete(t, store, PrivacyDryRunRequest{GroupID: "g", DiceIDs: []string{"dice"}, Scopes: scopes})
			if result.Deleted.Projections != want {
				t.Fatalf("projection delete=%+v want=%d", result.Deleted, want)
			}
			for _, name := range []string{"moderation", "character"} {
				if _, err := store.ReadProjectionRow(ctx, name, key); err != nil {
					t.Fatalf("cross-namespace delete %s: %v", name, err)
				}
			}
			row, err := store.ReadProjectionRow(ctx, "attributes", key)
			if withAttrs {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("attribute projection survived: %+v %v", row, err)
				}
			} else if err != nil || !bytes.Equal(row.Payload, attrs) {
				t.Fatalf("unselected attributes changed: %+v %v", row, err)
			}
		})
	}
}

func TestPrivacyPublicationFailureRollsBackHistoryAndGeneration(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	stream := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "g")}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{privacyEvent("publish")}}}}); err != nil {
		t.Fatal(err)
	}
	var before projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").Take(&before).Error; err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"diceId":"dice","groupId":"g","active":false}`)
	row := projectionReadModelRow{ProjectionGeneration: before.ActiveGeneration, ProjectionName: "group-record", RowKey: stream.AggregateID, Payload: payload, UpdatedAt: time.Unix(1, 0).UTC()}
	if err := db.GORM().Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	req := PrivacyDryRunRequest{GroupID: "g", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}}
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Exec("CREATE TRIGGER reject_privacy_publication AFTER UPDATE OF active_generation ON projection_control WHEN NEW.active_generation <> OLD.active_generation BEGIN SELECT RAISE(ABORT,'publication failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	result, err := store.PrivacyDeleteGroup(ctx, PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if err == nil || result.Deleted != (PrivacyCounts{}) {
		t.Fatalf("failed publication result=%+v err=%v", result, err)
	}
	var after projectionControlRow
	if err := db.GORM().Where("singleton_id = ?", "default").Take(&after).Error; err != nil || after.ActiveGeneration != before.ActiveGeneration {
		t.Fatalf("generation escaped rollback: %+v %v", after, err)
	}
	events, err := store.Load(ctx, stream, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("history escaped rollback: %d %v", len(events), err)
	}
	restored, err := store.ReadProjectionRow(ctx, "group-record", stream.AggregateID)
	if err != nil || !bytes.Equal(restored.Payload, payload) {
		t.Fatalf("projection escaped rollback: %+v %v", restored, err)
	}
}

func TestPrivacyDeletesAcrossFormerBatchAndByteLimitsAtomically(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	stream := StreamID{AggregateType: "group", AggregateID: privacyCanonical("dice", "large")}
	events := make([]NewEvent, privacyReadPageSize+101)
	payload := bytes.Repeat([]byte("raw"), 6*1024)
	for i := range events {
		events[i] = privacyEvent(fmt.Sprintf("large-%d", i))
		events[i].Payload = payload
	}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: events}}}); err != nil {
		t.Fatal(err)
	}
	req := PrivacyDryRunRequest{GroupID: "large", DiceIDs: []string{"dice"}, Scopes: []string{"group_record"}}
	scan, err := store.PrivacyDryRun(ctx, req)
	if err != nil || scan.Counts.GroupRecord != int64(len(events)) {
		t.Fatalf("scan=%+v err=%v", scan, err)
	}
	deleted, err := store.PrivacyDeleteGroup(ctx, PrivacyDeleteRequest{PrivacyDryRunRequest: req, AllowActive: true, ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version})
	if err != nil || deleted.Deleted.GroupRecord != int64(len(events)) {
		t.Fatalf("large delete=%+v err=%v", deleted, err)
	}
	if remaining, err := store.Load(ctx, stream, 0); err != nil || len(remaining) != 0 {
		t.Fatalf("partial deletion: %d %v", len(remaining), err)
	}
}
