package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)
type lifecycleCodec struct {
	payload []byte
	domain string
	effectID string
	owner string
	version uint64
}
func (l *lifecycleCodec) EncryptBound(_ context.Context, domain, effectID, owner string, version uint64, plaintext []byte) ([]byte, []byte, string, error) {
	l.domain, l.effectID, l.owner, l.version = domain, effectID, owner, version
	l.payload = append(l.payload[:0], plaintext...)
	return []byte("ciphertext"), []byte("nonce"), "test-key", nil
}
type overflowOperationStore struct {
	eventstore.Store
	committed bool
}
func (s *overflowOperationStore) GetOperation(context.Context, string) (eventstore.OperationView, error) {
	return eventstore.OperationView{Version: ^uint64(0)}, nil
}
func (s *overflowOperationStore) Commit(context.Context, eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.committed = true
	return eventstore.CommitResult{}, nil
}
type invalidSchemaLoadStore struct{ eventstore.Store }
func (s *invalidSchemaLoadStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return []eventstore.Envelope{{
		Stream: eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: "schema-endpoint"},
		StreamVersion: 1, EventID: "schema-event", EventType: string(EventEndpointCreated), SchemaVersion: 0,
		Payload: json.RawMessage(`{}`),
	}}, nil
}
type endpointKeySource struct{}
func (*endpointKeySource) IndexRootID(context.Context) (string, error) { return "index-v1", nil }
func (*endpointKeySource) IndexRootMaterial(context.Context) ([]byte, error) { return []byte("01234567890123456789012345678901"), nil }
func (*endpointKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) { return eventstore.EncryptionRoot{ID: "root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil }
func (*endpointKeySource) EncryptionRoot(context.Context, string) ([]byte, error) { return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil }

func TestEndpointServiceLifecycleCompletionAndStaleConflict(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	key := adapterapi.AdapterKey("fake")
	codec := &lifecycleCodec{}
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}}, codec)
	id := adapterapi.EndpointID("lifecycle")
	if _, err := svc.Create(context.Background(), Command{CommandID: "lc-create", CorrelationID: "lc-c", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil { t.Fatal(err) }
	enabled, err := svc.Enable(context.Background(), Command{CommandID: "lc-enable", CorrelationID: "lc-e", EndpointID: id, ExpectedVersion: 1, ExpectedVersionSet: true}); if err != nil { t.Fatal(err) }
	if enabled.State.DesiredState != DesiredStateEnabled || enabled.Operation.Status != "pending" { t.Fatalf("enable = %#v", enabled) }
	var intent map[string]any
	if err := json.Unmarshal(codec.payload, &intent); err != nil { t.Fatal(err) }
	if string(codec.payload) == "{}" || intent["effectKind"] != string(EffectStart) || intent["endpointId"] != string(id) || intent["generation"] != float64(1) || intent["desiredVersion"] != float64(2) || intent["desiredState"] != string(DesiredStateEnabled) || intent["operationId"] != enabled.State.OperationID || intent["correlationId"] != "lc-e" || intent["commandId"] != "lc-enable" { t.Fatalf("effect intent = %s", codec.payload) }
	if codec.domain != "outbox/v1" || codec.owner != string(id) || codec.version != 1 || codec.effectID != enabled.State.ProcessedCommands["lc-enable"].EffectIDs[0] { t.Fatalf("effect binding = domain=%q effect=%q owner=%q version=%d", codec.domain, codec.effectID, codec.owner, codec.version) }
	if strings.Contains(string(codec.payload), "secret") || strings.Contains(string(codec.payload), "credential") || strings.Contains(string(codec.payload), "artifact") { t.Fatalf("effect intent leaked sensitive material: %s", codec.payload) }
	stale, err := svc.Disable(context.Background(), Command{CommandID: "lc-stale", CorrelationID: "lc-s", EndpointID: id, ExpectedVersion: 1, ExpectedVersionSet: true}); if err == nil || !errors.Is(err, ErrConflict) || stale.State.Version != 0 { t.Fatalf("stale conflict result=%#v err=%v", stale, err) }
	completeCommand := Command{CommandID: "lc-complete", CorrelationID: "lc-k", EndpointID: id, Generation: enabled.State.Generation, ObservedState: adapterapi.ObservedStateConnected, CompletionState: OperationStateSucceeded}
	completed, err := svc.Complete(context.Background(), completeCommand); if err != nil { t.Fatal(err) }
	if completed.State.OperationState != OperationStateSucceeded { t.Fatalf("complete = %#v", completed.State) }
	completeReplay, err := svc.Complete(context.Background(), completeCommand); if err != nil || !completeReplay.Replay || completeReplay.Operation.OperationID != completed.Operation.OperationID { t.Fatalf("complete replay result=%#v err=%v", completeReplay, err) }
	refreshed, err := svc.Complete(context.Background(), Command{CommandID: "lc-observed-failed", CorrelationID: "lc-observed-failed", EndpointID: id, Generation: completed.State.Generation, ObservedState: adapterapi.ObservedStateFailed, CompletionState: OperationStateSucceeded}); if err != nil { t.Fatal(err) }
	if refreshed.State.OperationState != OperationStateSucceeded || refreshed.State.OperationID != completed.State.OperationID || refreshed.State.ObservedState != adapterapi.ObservedStateFailed { t.Fatalf("observation refresh = %#v", refreshed.State) }
	if _, err := svc.Complete(context.Background(), Command{CommandID: "lc-stale-observation", CorrelationID: "lc-stale-observation", EndpointID: id, Generation: completed.State.Generation + 1, ObservedState: adapterapi.ObservedStateStopped, CompletionState: OperationStateSucceeded}); err == nil { t.Fatal("generation-mismatched observation refresh accepted") }
	disabled, err := svc.Disable(context.Background(), Command{CommandID: "lc-disable", CorrelationID: "lc-d", EndpointID: id}); if err != nil { t.Fatal(err) }
	_, err = svc.Complete(context.Background(), Command{CommandID: "lc-disable-complete", CorrelationID: "lc-dc", EndpointID: id, Generation: disabled.State.Generation, ObservedState: adapterapi.ObservedStateStopped, CompletionState: OperationStateSucceeded}); if err != nil { t.Fatal(err) }
	removed, err := svc.Remove(context.Background(), Command{CommandID: "lc-remove", CorrelationID: "lc-r", EndpointID: id}); if err != nil { t.Fatal(err) }
	resolvedCommand := Command{CommandID: "lc-resolve", CorrelationID: "lc-rs", EndpointID: id, Generation: removed.State.Generation, ObservedState: adapterapi.ObservedStateStopped}
	resolved, err := svc.Resolve(context.Background(), resolvedCommand); if err != nil { t.Fatal(err) }
	resolvedReplay, err := svc.Resolve(context.Background(), resolvedCommand); if err != nil || !resolvedReplay.Replay || resolvedReplay.Operation.OperationID != resolved.Operation.OperationID { t.Fatalf("resolve replay result=%#v err=%v", resolvedReplay, err) }
}
func TestEndpointRepositoryRejectsEffectDesiredStateMismatch(t *testing.T) {
	id := adapterapi.EndpointID("effect-mismatch")
	decision := Decision{
		Events: []Event{{EffectID: "effect-1", EffectKind: EffectStart, EndpointID: id, Generation: 1, DesiredState: DesiredStateEnabled, DesiredVersion: 2, OperationID: "op-1", CorrelationID: "corr-1", CommandID: "cmd-1"}},
		Effects: []LifecycleEffect{{ID: "effect-1", EffectID: "effect-1", Kind: EffectStart, EndpointID: id, Generation: 1, DesiredState: DesiredStateDisabled, DesiredVersion: 2, OperationID: "op-1", CorrelationID: "corr-1", CommandID: "cmd-1"}},
	}
	if err := validateDecisionEffects(decision); err == nil || !errors.Is(err, ErrInvalidState) { t.Fatalf("desired state mismatch err=%v", err) }
}
func TestEndpointRepositoryRejectsOperationVersionOverflowBeforeCommit(t *testing.T) {
	store := &overflowOperationStore{}
	repository := NewRepository(store)
	id := adapterapi.EndpointID("overflow-endpoint")
	decision, err := Decide(State{}, Command{Kind: CommandCreate, CommandID: "overflow-create", CorrelationID: "overflow-correlation", EndpointID: id, AdapterKey: adapterapi.AdapterKey("fake"), Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{}`)}})
	if err != nil { t.Fatal(err) }
	_, err = repository.Commit(context.Background(), State{}, decision)
	if !errors.Is(err, eventstore.ErrVersionExhausted) { t.Fatalf("operation version overflow err=%v", err) }
	if store.committed { t.Fatal("overflow commit reached Store.Commit") }
}
func TestEndpointRepositoryLifecycleWithoutCodecFailsClosed(t *testing.T) {
	store, db := serviceStore(t); defer db.Close()
	key := adapterapi.AdapterKey("fake")
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("no-codec")
	if _, err := svc.Create(context.Background(), Command{CommandID: "no-codec-create", CorrelationID: "no-codec-c", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{}`)}}); err != nil { t.Fatal(err) }
	if _, err := svc.Enable(context.Background(), Command{CommandID: "no-codec-enable", CorrelationID: "no-codec-e", EndpointID: id}); !errors.Is(err, eventstore.ErrEncryptionUnavailable) { t.Fatalf("missing codec err=%v", err) }
	var count int64; if err := db.GORM().Table("domain_events").Count(&count).Error; err != nil { t.Fatal(err) }; if count != 1 { t.Fatalf("failed lifecycle wrote %d events", count) }
}
func TestEndpointRepositoryRejectsZeroSchemaVersionOnLoad(t *testing.T) {
	repository := NewRepository(&invalidSchemaLoadStore{})
	_, err := repository.Load(context.Background(), adapterapi.EndpointID("schema-endpoint"))
	if err == nil || !errors.Is(err, ErrInvalidState) { t.Fatalf("zero schema load err=%v", err) }
}
func TestEndpointServiceKeyedLifecycleEffectRoundTrip(t *testing.T) {
	ctx := context.Background()
	source := &endpointKeySource{}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "keyed-endpoint.db"), KeySource: source, DatabaseIdentity: "endpoint-keyed"})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "endpoint-keyed", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil { t.Fatal(err) }
	key := adapterapi.AdapterKey("fake")
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("keyed-endpoint")
	if _, err := svc.Create(ctx, Command{CommandID: "keyed-create", CorrelationID: "keyed-c", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil { t.Fatal(err) }
	enabled, err := svc.Enable(ctx, Command{CommandID: "keyed-enable", CorrelationID: "keyed-e", EndpointID: id})
	if err != nil { t.Fatal(err) }
	lease, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "keyed-worker", LeaseDuration: time.Minute})
	if err != nil { t.Fatal(err) }
	plain, err := store.DecryptBound(ctx, "outbox/v1", lease.Effect.EffectID, lease.Effect.EndpointID, 1, lease.Effect.PayloadCiphertext, lease.Effect.PayloadNonce, lease.Effect.PayloadEncryptionKeyID)
	if err != nil { t.Fatal(err) }
	var intent map[string]any
	if err := json.Unmarshal(plain, &intent); err != nil { t.Fatal(err) }
	if intent["endpointId"] != string(id) || intent["desiredVersion"] != float64(enabled.State.DesiredVersion) || intent["desiredState"] != string(DesiredStateEnabled) || intent["effectKind"] != string(EffectStart) { t.Fatalf("keyed intent=%s", plain) }
	if string(plain) == "{}" || strings.Contains(string(plain), "secret") { t.Fatalf("invalid keyed intent=%s", plain) }
}
