package eventstore

import (
	"context"
	"testing"
	"time"
)

func TestTask2A6OutboundParticipantUsesSplitKeyMetadata(t *testing.T) {
	store, db, source := task6Store(t)
	defer db.Close()
	ctx := context.Background()
	plaintext := []byte(`{"version":1,"payload":"segments"}`)
	ciphertext, nonce, keyID, err := a6Seal(ctx, source, "outbox/v1", "task2-effect", "endpoint-1", 1, plaintext)
	if err != nil { t.Fatal(err) }
	work := UnitOfWork{
		Operations: []OperationUpdate{{OperationID: "task2-operation", PrincipalID: "principal-a", ResourceID: "task2-effect", IdempotencyScope: "outbound", IdempotencyKey: "task2-command", RequestDigest: []byte("digest-a")}},
		Effects: []NewEffect{{EffectID: "task2-effect", EndpointID: "endpoint-1", LaneHMAC: []byte("lane-hmac"), EffectType: "message", RiskClass: RiskProviderIdempotent, Status: OutboxStatusPending, PayloadCiphertext: ciphertext, PayloadNonce: nonce, PayloadEncryptionKeyID: keyID, ContentDigest: []byte("digest-a"), ContentDigestKeyID: source.IndexID, PayloadExpiresAt: time.Now().UTC().Add(time.Minute)}},
	}
	if _, err := store.Commit(ctx, work); err != nil { t.Fatal(err) }
	view, err := store.GetOperationByIdempotency(ctx, "principal-a", "outbound", "task2-command")
	if err != nil || view.ResourceID != "task2-effect" { t.Fatalf("view=%#v err=%v", view, err) }
	plain, err := a6Open(ctx, source, "outbox/v1", "task2-effect", "endpoint-1", 1, keyID, ciphertext, nonce)
	if err != nil { t.Fatal(err) }
	if string(plain) != string(plaintext) { t.Fatalf("decrypted payload=%q", plain) }
	var beforeEvents,beforeOps,beforeEffects,beforeLanes int64
	for _,item:=range []struct{name string; value *int64}{{"domain_events",&beforeEvents},{"operations",&beforeOps},{"outbox_effects",&beforeEffects},{"lane_heads",&beforeLanes}} { if err:=db.GORM().Table(item.name).Count(item.value).Error; err!=nil{t.Fatal(err)} }
	rollbackWork:=UnitOfWork{
		Streams: []StreamAppend{{Stream:StreamID{AggregateType:"outbound-effect",AggregateID:"rollback-stream"},Events:[]NewEvent{{EventType:"rollback.requested",SchemaVersion:1,Payload:[]byte(`{"shape":1}`),Metadata:Metadata{EventID:"rollback-event",CommandID:"rollback-command",CorrelationID:"rollback-correlation",OccurredAt:time.Now().UTC()}}}}},
		Operations: []OperationUpdate{{OperationID:"rollback-operation",PrincipalID:"principal-a",ResourceID:"rollback-effect",IdempotencyScope:"outbound",IdempotencyKey:"rollback-command",RequestDigest:[]byte("rollback-digest")}},
		Effects: []NewEffect{{EffectID:"rollback-effect",EndpointID:"endpoint-1",LaneHMAC:[]byte("rollback-lane"),EffectType:"message",RiskClass:RiskProviderIdempotent,Status:OutboxStatusPending,PayloadCiphertext:ciphertext,PayloadNonce:nonce,PayloadEncryptionKeyID:keyID,ContentDigest:[]byte("rollback-digest"),ContentDigestKeyID:source.IndexID}},
		ArtifactUpdates: []ArtifactUpdate{{}},
	}
	if _,err:=store.Commit(ctx,rollbackWork); err==nil {t.Fatal("post-insert artifact failure unexpectedly committed")}
	var afterEvents,afterOps,afterEffects,afterLanes int64
	for _,item:=range []struct{name string; value *int64}{{"domain_events",&afterEvents},{"operations",&afterOps},{"outbox_effects",&afterEffects},{"lane_heads",&afterLanes}} { if err:=db.GORM().Table(item.name).Count(item.value).Error; err!=nil{t.Fatal(err)} }
	if beforeEvents!=afterEvents||beforeOps!=afterOps||beforeEffects!=afterEffects||beforeLanes!=afterLanes { t.Fatalf("rollback changed counts events=%d/%d ops=%d/%d effects=%d/%d lanes=%d/%d",beforeEvents,afterEvents,beforeOps,afterOps,beforeEffects,afterEffects,beforeLanes,afterLanes) }
}
