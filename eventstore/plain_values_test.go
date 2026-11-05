package eventstore

import (
	"bytes"
	"context"
	"testing"

	"gorm.io/gorm"
)

func TestSecretValuesPersistExactlyAndCanBeCleared(t *testing.T) {
	store, db := openPlainTestStore(t)
	defer db.Close()
	ctx := context.Background()
	ref := "plain-value"
	for i, value := range [][]byte{nil, {0, 1, 255, 0}, {}} {
		result, err := store.PutSecret(ctx, SecretPutRequest{
			SecretRef: ref, EndpointID: "owner", AdapterID: "attributes", Value: value,
		})
		if err != nil {
			t.Fatal(err)
		}
		var stored []byte
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM adapter_secrets WHERE secret_ref = ? AND secret_version = ?", []byte(ref), result.SecretVersion).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(stored, value) {
			t.Fatalf("version %d stored %x, want %x", i+1, stored, value)
		}
		resolved, err := store.ResolveSecret(ctx, ref, result.SecretVersion)
		if err != nil || !bytes.Equal(resolved.Value, value) {
			t.Fatalf("version %d resolved %x, err=%v", i+1, resolved.Value, err)
		}
	}
}

func TestRawRecordBodiesAcceptEmptyAndPersistUnwrappedBytes(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	if err := store.RegisterProjection(transactionTestProjection()); err != nil {
		t.Fatal(err)
	}
	for i, payload := range [][]byte{nil, {}, {0, 255, 0, 'r', 'a', 'w'}} {
		id := string(rune('a' + i))
		operationID := "raw-operation-" + id
		stream := StreamID{AggregateType: "raw", AggregateID: "raw-stream-" + id}
		event := privacyEvent("raw-event-" + id)
		event.Payload = payload
		work := UnitOfWork{
			Streams:         []StreamAppend{{Stream: stream, Events: []NewEvent{event}}},
			Operations:      []OperationUpdate{{OperationID: operationID, PrincipalID: "owner", PrivateContext: payload}},
			ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "raw-artifact-" + id, OperationID: operationID, OwnerPrincipalID: "owner", Data: payload}},
			InboxUpdates:    []InboxUpdate{{InboxID: "raw-inbox-" + id, EndpointID: "endpoint", ProviderEventKey: id, Lane: "raw-inbox-lane-" + id, Payload: payload}},
			Effects:         []NewEffect{{EffectID: "raw-effect-" + id, EndpointID: "endpoint", Lane: "raw-outbox-lane-" + id, EffectType: "message", RiskClass: RiskPreDispatchRetryable, Payload: payload, ContentDigest: []byte{1, 2, 3}}},
		}
		if _, err := store.Commit(ctx, work); err != nil {
			t.Fatalf("raw UOW %d: %v", i, err)
		}
		var operation operationRow
		var artifact operationArtifactRow
		var inbox inboxMessageRow
		var effect outboxEffectRow
		reads := []func() *gorm.DB{
			func() *gorm.DB { return db.GORM().Where("operation_id = ?", operationID).Take(&operation) },
			func() *gorm.DB { return db.GORM().Where("artifact_id = ?", "raw-artifact-"+id).Take(&artifact) },
			func() *gorm.DB { return db.GORM().Where("inbox_id = ?", "raw-inbox-"+id).Take(&inbox) },
			func() *gorm.DB { return db.GORM().Where("effect_id = ?", "raw-effect-"+id).Take(&effect) },
		}
		for _, read := range reads {
			if err := read().Error; err != nil {
				t.Fatal(err)
			}
		}
		for name, value := range map[string][]byte{"operation": operation.PrivateContext, "artifact": artifact.Data, "inbox": inbox.Payload, "outbox": effect.Payload} {
			if !bytes.Equal(value, payload) {
				t.Fatalf("%s transformed raw bytes: %x want %x", name, value, payload)
			}
		}
		if !bytes.Equal(effect.ContentDigest, []byte{1, 2, 3}) {
			t.Fatalf("effect request fingerprint changed: %x", effect.ContentDigest)
		}
		consumed, err := store.ConsumeArtifact(ctx, ArtifactConsumeRequest{ArtifactID: artifact.ArtifactID, OwnerPrincipalID: "owner"})
		if err != nil || !bytes.Equal(consumed.Plaintext, payload) {
			t.Fatalf("empty/raw artifact consume: %+v %v", consumed, err)
		}
		events, err := store.Load(ctx, stream, 0)
		if err != nil || len(events) != 1 || !bytes.Equal(events[0].Payload, payload) {
			t.Fatalf("event raw body: %+v %v", events, err)
		}
		projection, err := store.ReadProjectionRow(ctx, "counter", stream.AggregateID)
		if err != nil || !bytes.Equal(projection.Payload, payload) {
			t.Fatalf("projection raw body: %+v %v", projection, err)
		}
		if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "raw-plugin-" + id, Key: "", Value: payload}); err != nil {
			t.Fatal(err)
		}
		item, err := store.GetPluginKV(ctx, "raw-plugin-"+id, "")
		if err != nil || !bytes.Equal(item.Value, payload) {
			t.Fatalf("plugin empty/raw value: %+v %v", item, err)
		}
	}
}
func TestOperationPrivateContextCanBeExplicitlyCleared(t *testing.T) {
	ctx := context.Background()
	store, db := openPlainTestStore(t)
	defer db.Close()
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "clear-context", PrivateContext: []byte{0, 255}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, UnitOfWork{Operations: []OperationUpdate{{OperationID: "clear-context", ExpectedVersion: 1, PrivateContext: []byte{}}}}); err != nil {
		t.Fatal(err)
	}
	var row operationRow
	if err := db.GORM().Where("operation_id = ?", "clear-context").Take(&row).Error; err != nil || len(row.PrivateContext) != 0 {
		t.Fatalf("private context not cleared: %x %v", row.PrivateContext, err)
	}
}
