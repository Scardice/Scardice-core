package eventstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestVisitImportVerificationReadsEachPersistedKind(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	event := NewEvent{
		EventType: "profile.saved", SchemaVersion: 3, Payload: []byte(`{"name":"alice"}`),
		Metadata: Metadata{EventID: "event-1", CommandID: "command-1", CorrelationID: "correlation-1", Producer: "test", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true},
	}
	if _, err := store.Commit(ctx, UnitOfWork{Streams: []StreamAppend{{Stream: StreamID{AggregateType: "profile", AggregateID: "alice"}, Events: []NewEvent{event}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-1", EndpointID: "endpoint-1", AdapterID: "adapter-1", SecretVersion: 1, Plaintext: []byte("token")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPluginKV(ctx, PluginKVPutRequest{ExtensionID: "extension-1", Key: "", Value: []byte("value")}); err != nil {
		t.Fatal(err)
	}

	var events []ImportVerificationEvent
	var secrets []ImportVerificationSecret
	var plugins []PluginKVItem
	err := store.VisitImportVerification(ctx, ImportVerificationVisitor{
		Event: func(item ImportVerificationEvent) error {
			events = append(events, item)
			return nil
		},
		Secret: func(item ImportVerificationSecret) error {
			item.Plaintext = append([]byte(nil), item.Plaintext...)
			secrets = append(secrets, item)
			return nil
		},
		PluginKV: func(item PluginKVItem) error {
			item.Value = append([]byte(nil), item.Value...)
			plugins = append(plugins, item)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(event.Payload)
	if len(events) != 1 || events[0].Stream != (StreamID{AggregateType: "profile", AggregateID: "alice"}) || events[0].StreamVersion != 1 || events[0].EventType != event.EventType || events[0].SchemaVersion != event.SchemaVersion || events[0].PayloadSize != uint64(len(event.Payload)) || events[0].PayloadDigest != wantDigest {
		t.Fatalf("events = %#v", events)
	}
	if len(secrets) != 1 || secrets[0].SecretRef != "secret-1" || secrets[0].SecretVersion != 1 || !bytes.Equal(secrets[0].Plaintext, []byte("token")) {
		t.Fatalf("secrets = %#v", secrets)
	}
	if len(plugins) != 1 || plugins[0].ExtensionID != "extension-1" || plugins[0].Key != "" || plugins[0].Version != 1 || !bytes.Equal(plugins[0].Value, []byte("value")) {
		t.Fatalf("plugins = %#v", plugins)
	}
}

func TestVisitImportVerificationStopsOnVisitorError(t *testing.T) {
	store, db, _ := openEncryptedTestStore(t)
	defer db.Close()
	ctx := context.Background()
	if _, err := store.PutSecret(ctx, SecretPutRequest{SecretRef: "secret-1", EndpointID: "endpoint-1", AdapterID: "adapter-1", SecretVersion: 1, Plaintext: []byte("token")}); err != nil {
		t.Fatal(err)
	}
	visitorErr := errors.New("stop")
	err := store.VisitImportVerification(ctx, ImportVerificationVisitor{Secret: func(ImportVerificationSecret) error { return visitorErr }})
	if !errors.Is(err, visitorErr) {
		t.Fatalf("VisitImportVerification() err=%v, want visitor error", err)
	}
}
