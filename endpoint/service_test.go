package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type serviceDescriptor struct{ key adapterapi.AdapterKey }
func (d serviceDescriptor) Key() adapterapi.AdapterKey { return d.key }
func (d serviceDescriptor) ConfigVersion() uint16 { return 1 }
func (d serviceDescriptor) ValidateConfig(_ context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) { canonical, err := adapterapi.CanonicalizeJSON(raw); if err != nil { return adapterapi.ValidatedConfig{}, err }; return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical}, nil }
func (d serviceDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet { return 0 }
func (d serviceDescriptor) NewRuntime(adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) { return nil, errors.New("not used") }

type serviceRegistry map[adapterapi.AdapterKey]adapterapi.Descriptor
func (r serviceRegistry) Lookup(_ context.Context, key adapterapi.AdapterKey) (adapterapi.Descriptor, bool) { d, ok := r[key]; return d, ok }

func serviceStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "endpoint.db")})
	if err != nil { t.Fatal(err) }
	return eventstore.NewStore(db), db
}

func TestEndpointServiceCreateReplayAndProjection(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	key := adapterapi.AdapterKey("fake")
	registry := serviceRegistry{key: serviceDescriptor{key: key}}
	service := NewService(store, registry)
	id := adapterapi.EndpointID("endpoint-1")
	command := Command{Kind: CommandCreate, CommandID: "create-1", CorrelationID: "corr-1", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"channel":"test"}`), SecretRefs: []adapterapi.SecretRef{{Ref: "ref", Version: 1}}}}
	created, err := service.Execute(context.Background(), command)
	if err != nil { t.Fatal(err) }
	if created.State.Version != 1 || created.Operation.Status != "succeeded" || len(created.State.Config.SecretRefs) != 1 { t.Fatalf("create result = %#v", created) }
	row, err := store.ReadProjectionRow(context.Background(), EndpointProjectionName, string(id)); if err != nil { t.Fatal(err) }
	if string(row.Payload) == "" || !containsEndpointBytes(row.Payload, []byte("channel")) || containsEndpointBytes(row.Payload, []byte("password")) { t.Fatalf("endpoint projection = %s", row.Payload) }
	opRow, err := store.ReadProjectionRow(context.Background(), OperationProjectionName, created.State.OperationID); if err != nil { t.Fatal(err) }; if containsEndpointBytes(opRow.Payload, []byte("credential")) || containsEndpointBytes(opRow.Payload, []byte("artifact-bytes")) { t.Fatalf("operation projection leaked sensitive payload: %s", opRow.Payload) }
	replayed, err := service.Execute(context.Background(), command); if err != nil { t.Fatal(err) }
	if !replayed.Replay || replayed.Commit.Events != nil { t.Fatalf("replay result = %#v", replayed) }
	delete(registry, key)
	replayed, err = service.Execute(context.Background(), command); if err != nil { t.Fatal(err) }
	if !replayed.Replay { t.Fatalf("replay after registry removal = %#v", replayed) }
	var events int64; if err := db.GORM().Table("domain_events").Count(&events).Error; err != nil { t.Fatal(err) }; if events != 1 { t.Fatalf("replay appended %d events", events) }
}

func TestEndpointProjectionDoesNotExposeRuntimeOrPrivateFields(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("endpoint-safe")
	_, err := service.Create(context.Background(), Command{CommandID: "safe-create", CorrelationID: "safe-corr", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"token":"secret-ref-only"}`)}})
	if err != nil { t.Fatal(err) }
	row, err := store.ReadProjectionRow(context.Background(), EndpointProjectionName, string(id)); if err != nil { t.Fatal(err) }
	for _, forbidden := range [][]byte{[]byte("PrivateContext"), []byte("runtime"), []byte("artifact"), []byte("credential-bytes")} { if containsEndpointBytes(row.Payload, forbidden) { t.Fatalf("projection leaked %q: %s", forbidden, row.Payload) } }
}
func TestEndpointServiceRejectsUnknownAndInvalidWithoutWrites(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	key := adapterapi.AdapterKey("fake")
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("write-guard")
	_, err := svc.Create(context.Background(), Command{CommandID: "bad-unknown", CorrelationID: "bad-u", EndpointID: id, AdapterKey: adapterapi.AdapterKey("missing"), Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{}`)}})
	if err == nil || !errors.Is(err, ErrUnknownAdapter) { t.Fatalf("unknown adapter err=%v", err) }
	_, err = svc.Create(context.Background(), Command{CommandID: "bad-config", CorrelationID: "bad-c", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`not-json`)}})
	if err == nil || !errors.Is(err, ErrInvalidConfig) { t.Fatalf("invalid config err=%v", err) }
	var count int64
	if err := db.GORM().Table("domain_events").Count(&count).Error; err != nil { t.Fatal(err) }
	if count != 0 { t.Fatalf("rejected commands wrote %d events", count) }
}
func TestEndpointProjectionIgnoresForeignStreams(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	_ = NewService(store, serviceRegistry{})
	err := error(nil)
	_, err = store.Commit(context.Background(), eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: eventstore.StreamID{AggregateType: "other", AggregateID: "foreign"}, Events: []eventstore.NewEvent{{EventType: "other.event", SchemaVersion: 1, Payload: json.RawMessage(`{"private":"credential"}`), Metadata: eventstore.Metadata{EventID: "other-event", CommandID: "other-command", CorrelationID: "other-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}}}}})
	if err != nil { t.Fatal(err) }
	if _, err := store.ReadProjectionRow(context.Background(), EndpointProjectionName, "foreign"); !errors.Is(err, eventstore.ErrNotFound) { t.Fatalf("foreign stream projection err=%v", err) }
}
func TestEndpointProjectionRejectsInvalidEndpointIdentity(t *testing.T) {
	_, err := decodeProjectionEvent(eventstore.Envelope{
		Stream: eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: "invalid endpoint"},
		EventID: "event-1", EventType: string(EventEndpointCreated), StreamVersion: 1,
		Payload: json.RawMessage(`{"endpointId":"invalid endpoint"}`),
	})
	if err == nil || !errors.Is(err, ErrInvalidState) { t.Fatalf("invalid projection identity err=%v", err) }
}
func TestEndpointProjectionRejectsMissingEnvelopeIdentity(t *testing.T) {
	_, err := decodeProjectionEvent(eventstore.Envelope{
		Stream: eventstore.StreamID{AggregateType: EndpointAggregateType},
		Payload: json.RawMessage(`{}`),
	})
	if err == nil || !errors.Is(err, ErrInvalidState) { t.Fatalf("missing projection identity err=%v", err) }
}
func TestEndpointProjectionRejectsIncompleteEventPayload(t *testing.T) {
	_, err := decodeProjectionEvent(eventstore.Envelope{
		Stream: eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: "incomplete-endpoint"},
		StreamVersion: 1, EventID: "incomplete-event", EventType: string(EventEndpointCreated), SchemaVersion: 1,
		Payload: json.RawMessage(`{}`),
	})
	if err == nil || !errors.Is(err, ErrInvalidState) { t.Fatalf("incomplete projection payload err=%v", err) }
}
func TestEndpointProjectionRejectsPayloadIdentityOmission(t *testing.T) {
	_, err := decodeProjectionEvent(eventstore.Envelope{
		Stream: eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: "identity-endpoint"},
		StreamVersion: 1, EventID: "identity-event", EventType: string(EventEndpointCreated), SchemaVersion: 1,
		Payload: json.RawMessage(`{"commandID":"identity-command","correlationID":"identity-correlation","operationID":"identity-operation","desiredVersion":1,"desiredState":"disabled","observedState":1,"operationState":"idle"}`),
	})
	if err == nil || !errors.Is(err, ErrInvalidState) { t.Fatalf("payload identity omission err=%v", err) }
}
func TestEndpointServiceNilRegistryFailsClosed(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	svc := NewService(store, nil)
	_, err := svc.Create(context.Background(), Command{CommandID: "nil-registry", CorrelationID: "nil-registry-c", EndpointID: adapterapi.EndpointID("nil-registry-endpoint"), AdapterKey: adapterapi.AdapterKey("fake"), Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"password":"secret"}`)}})
	if err == nil || !errors.Is(err, ErrUnknownAdapter) { t.Fatalf("nil registry err=%v", err) }
	var count int64
	if err := db.GORM().Table("domain_events").Count(&count).Error; err != nil { t.Fatal(err) }
	if count != 0 { t.Fatalf("nil registry wrote %d events", count) }
}
func containsEndpointBytes(haystack, needle []byte) bool { for i := 0; i+len(needle) <= len(haystack); i++ { match := true; for j := range needle { if haystack[i+j] != needle[j] { match = false; break } }; if match { return true } }; return false }
