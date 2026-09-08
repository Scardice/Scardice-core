package eventstore

import (
    "context"
    "errors"
    "testing"
    "time"
)

func privacyEvent(id string) NewEvent { return NewEvent{EventType: "test", SchemaVersion: 1, Payload: []byte(`{"ok":true}`), Metadata: Metadata{EventID: id, CommandID: id+"-cmd", CorrelationID: id+"-corr", Producer: "test", OccurredAt: time.Unix(1, 0).UTC()}} }

func TestPrivacyDryRunScopeIsolationAndDeleteBatch(t *testing.T) {
    store, db, _ := task6Store(t)
    defer db.Close()
    ctx := context.Background()
    streams := []StreamID{{AggregateType: "group", AggregateID: privacyCanonical("d1", "g")}, {AggregateType: "player", AggregateID: privacyCanonical("d1", "g", "u1")}, {AggregateType: "attrs/group", AggregateID: privacyCanonical("d1", "g")}, {AggregateType: "moderation/group", AggregateID: privacyCanonical("d1", "g")}}
    for i, stream := range streams { if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{privacyEvent(string(rune('a'+i)))}}}}); err != nil { t.Fatalf("stream %s/%s: %v", stream.AggregateType, stream.AggregateID, err) } }
    scan, err := store.PrivacyDryRun(ctx, PrivacyDryRunRequest{GroupID: "g", DiceIDs: []string{"d1"}, Scopes: []string{"group_record", "players", "attrs"}})
    if err != nil { t.Fatal(err) }
    if scan.Counts != (PrivacyCounts{GroupRecord: 1, Players: 1, Attrs: 1}) { t.Fatalf("counts=%+v", scan.Counts) }
    if scan.DigestKeyID == "" || len(scan.SubjectKey) != 32 || len(scan.Uncovered) == 0 { t.Fatalf("scan=%+v", scan) }
    subject, err := store.privacyHMAC(ctx, "privacy-subject/v1", "g")
    if err != nil { t.Fatal(err) }
    if err := store.PrivacyCreateOperation(ctx, "op", subject, PrivacyOperationContext{GroupID: "g", Phase: "delete", DiceIDs: []string{"d1"}, Scopes: []string{"players"}}); err != nil { t.Fatal(err) }
    if _, err := store.PrivacyFence(ctx, subject, "group", "op"); err != nil { t.Fatal(err) }
    batch, err := store.PrivacyDeleteBatch(ctx, PrivacyBatchRequest{OperationID: "op", GroupID: "g", Phase: "delete", DiceIDs: []string{"d1"}, Scopes: []string{"players"}, Limit: 500})
    if err != nil { t.Fatal(err) }
    if batch.Deleted.Players != 1 { t.Fatalf("deleted=%+v", batch.Deleted) }
    other, err := store.Load(ctx, streams[0], 1); if err != nil || len(other) != 1 { t.Fatalf("group preserved=%d err=%v", len(other), err) }
    if _, err := store.Load(ctx, streams[1], 1); err != nil && !errors.Is(err, ErrNotFound) { t.Fatal(err) }
}
