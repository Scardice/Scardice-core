package endpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type lifecycleCodec struct{}

func (*lifecycleCodec) EncryptBound(context.Context, string, string, string, uint64, []byte) ([]byte, []byte, string, error) {
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
		Stream:        eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: "schema-endpoint"},
		StreamVersion: 1, EventID: "schema-event", EventType: string(EventEndpointCreated), SchemaVersion: 0,
		Payload: json.RawMessage(`{}`),
	}}, nil
}

type envelopeLoadStore struct {
	eventstore.Store
	envelopes []eventstore.Envelope
}

func (s *envelopeLoadStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return append([]eventstore.Envelope(nil), s.envelopes...), nil
}

type endpointKeySource struct{}

func (*endpointKeySource) IndexRootID(context.Context) (string, error) { return "index-v1", nil }
func (*endpointKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}
func (*endpointKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: "root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}
func (*endpointKeySource) EncryptionRoot(context.Context, string) ([]byte, error) {
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}

func TestEndpointServiceLifecycleCompletionAndStaleConflict(t *testing.T) {
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	codec := &lifecycleCodec{}
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}}, codec)
	id := adapterapi.EndpointID("lifecycle")
	if _, err := svc.Create(context.Background(), Command{CommandID: "lc-create", CorrelationID: "lc-c", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
		t.Fatal(err)
	}
	enabled, err := svc.Enable(context.Background(), Command{CommandID: "lc-enable", CorrelationID: "lc-e", EndpointID: id, ExpectedVersion: 1, ExpectedVersionSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if enabled.State.DesiredState != DesiredStateEnabled || enabled.Operation.Status != "pending" {
		t.Fatalf("enable = %#v", enabled)
	}
	stale, err := svc.Disable(context.Background(), Command{CommandID: "lc-stale", CorrelationID: "lc-s", EndpointID: id, ExpectedVersion: 1, ExpectedVersionSet: true})
	if err == nil || !errors.Is(err, ErrConflict) || stale.State.Version != 0 {
		t.Fatalf("stale conflict result=%#v err=%v", stale, err)
	}
	completeCommand := Command{CommandID: "lc-complete", CorrelationID: "lc-k", EndpointID: id, Generation: enabled.State.Generation, DesiredVersion: enabled.State.DesiredVersion, ObservedState: adapterapi.ObservedStateConnected, CompletionState: OperationStateSucceeded}
	completed, err := svc.Complete(context.Background(), completeCommand)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State.OperationState != OperationStateSucceeded {
		t.Fatalf("complete = %#v", completed.State)
	}
	completeReplay, err := svc.Complete(context.Background(), completeCommand)
	if err != nil || !completeReplay.Replay || completeReplay.Operation.OperationID != completed.Operation.OperationID {
		t.Fatalf("complete replay result=%#v err=%v", completeReplay, err)
	}
	refreshed, err := svc.Complete(context.Background(), Command{CommandID: "lc-observed-failed", CorrelationID: "lc-observed-failed", EndpointID: id, Generation: completed.State.Generation, DesiredVersion: completed.State.DesiredVersion, ObservedState: adapterapi.ObservedStateFailed, CompletionState: OperationStateSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.State.OperationState != OperationStateSucceeded || refreshed.State.OperationID != completed.State.OperationID || refreshed.State.ObservedState != adapterapi.ObservedStateFailed {
		t.Fatalf("observation refresh = %#v", refreshed.State)
	}
	if _, err := svc.Complete(context.Background(), Command{CommandID: "lc-stale-observation", CorrelationID: "lc-stale-observation", EndpointID: id, Generation: completed.State.Generation + 1, DesiredVersion: completed.State.DesiredVersion, ObservedState: adapterapi.ObservedStateStopped, CompletionState: OperationStateSucceeded}); err == nil {
		t.Fatal("generation-mismatched observation refresh accepted")
	}
	disabled, err := svc.Disable(context.Background(), Command{CommandID: "lc-disable", CorrelationID: "lc-d", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Complete(context.Background(), Command{CommandID: "lc-disable-complete", CorrelationID: "lc-dc", EndpointID: id, Generation: disabled.State.Generation, DesiredVersion: disabled.State.DesiredVersion, ObservedState: adapterapi.ObservedStateStopped, CompletionState: OperationStateSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := svc.Remove(context.Background(), Command{CommandID: "lc-remove", CorrelationID: "lc-r", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	resolvedCommand := Command{CommandID: "lc-resolve", CorrelationID: "lc-rs", EndpointID: id, Generation: removed.State.Generation, ObservedState: adapterapi.ObservedStateStopped}
	resolved, err := svc.Resolve(context.Background(), resolvedCommand)
	if err != nil {
		t.Fatal(err)
	}
	resolvedReplay, err := svc.Resolve(context.Background(), resolvedCommand)
	if err != nil || !resolvedReplay.Replay || resolvedReplay.Operation.OperationID != resolved.Operation.OperationID {
		t.Fatalf("resolve replay result=%#v err=%v", resolvedReplay, err)
	}
}
func TestEndpointRepositoryRejectsEffectDesiredStateMismatch(t *testing.T) {
	id := adapterapi.EndpointID("effect-mismatch")
	decision := Decision{
		Events:  []Event{{EffectID: "effect-1", EffectKind: EffectStart, EndpointID: id, Generation: 1, DesiredState: DesiredStateEnabled, DesiredVersion: 2, OperationID: "op-1", CorrelationID: "corr-1", CommandID: "cmd-1"}},
		Effects: []LifecycleEffect{{ID: "effect-1", EffectID: "effect-1", Kind: EffectStart, EndpointID: id, Generation: 1, DesiredState: DesiredStateDisabled, DesiredVersion: 2, OperationID: "op-1", CorrelationID: "corr-1", CommandID: "cmd-1"}},
	}
	if err := validateDecisionEffects(decision); err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("desired state mismatch err=%v", err)
	}
}
func TestEndpointRepositoryRejectsOperationVersionOverflowBeforeCommit(t *testing.T) {
	store := &overflowOperationStore{}
	repository := NewRepository(store)
	id := adapterapi.EndpointID("overflow-endpoint")
	decision, err := Decide(State{}, Command{Kind: CommandCreate, CommandID: "overflow-create", CorrelationID: "overflow-correlation", EndpointID: id, AdapterKey: adapterapi.AdapterKey("fake"), Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.Commit(context.Background(), State{}, decision)
	if !errors.Is(err, eventstore.ErrVersionExhausted) {
		t.Fatalf("operation version overflow err=%v", err)
	}
	if store.committed {
		t.Fatal("overflow commit reached Store.Commit")
	}
}
func TestEndpointRepositoryRejectsZeroSchemaVersionOnLoad(t *testing.T) {
	repository := NewRepository(&invalidSchemaLoadStore{})
	_, err := repository.Load(context.Background(), adapterapi.EndpointID("schema-endpoint"))
	if err == nil || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("zero schema load err=%v", err)
	}
}

func TestEndpointRepositoryAcceptsBoundedEarlyImporterEnvelopeMetadata(t *testing.T) {
	ctx := context.Background()
	id := adapterapi.EndpointID("legacy-envelope")
	decision, err := Decide(State{}, Command{
		Kind: CommandCreate, CommandID: "legacy-create-" + string(id),
		CorrelationID: "legacy-import-default", EndpointID: id, AdapterKey: "fake",
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"channel":"test"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := decision.Events[0]
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	envelope := eventstore.Envelope{
		Stream:        eventstore.StreamID{AggregateType: EndpointAggregateType, AggregateID: string(id)},
		StreamVersion: 1, EventID: event.ID, EventType: string(event.Type), SchemaVersion: 1, Payload: payload,
		Metadata: eventstore.Metadata{
			CommandID: event.ID + "-command", CorrelationID: event.ID + "-correlation", Producer: "eventsourcing-importer",
		},
	}
	repository := NewRepository(&envelopeLoadStore{envelopes: []eventstore.Envelope{envelope}})
	state, err := repository.Load(ctx, id)
	if err != nil || state.EndpointID != id || state.Version != 1 {
		t.Fatalf("early importer envelope state = %#v, %v", state, err)
	}

	envelope.Metadata.CommandID = "unrecognized-wrapper"
	repository = NewRepository(&envelopeLoadStore{envelopes: []eventstore.Envelope{envelope}})
	if _, err = repository.Load(ctx, id); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("arbitrary metadata mismatch error = %v, want invalid state", err)
	}
}
func TestEndpointServiceKeyedLifecycleEffectRoundTrip(t *testing.T) {
	ctx := context.Background()
	source := &endpointKeySource{}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "keyed-endpoint.db"), KeySource: source, DatabaseIdentity: "endpoint-keyed"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "endpoint-keyed", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	key := adapterapi.AdapterKey("fake")
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("keyed-endpoint")
	if _, err := svc.Create(ctx, Command{CommandID: "keyed-create", CorrelationID: "keyed-c", EndpointID: id, AdapterKey: key, Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)}}); err != nil {
		t.Fatal(err)
	}
	enabled, err := svc.Enable(ctx, Command{CommandID: "keyed-enable", CorrelationID: "keyed-e", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	replayed, err := restarted.Enable(ctx, Command{CommandID: "keyed-enable", CorrelationID: "keyed-e", EndpointID: id})
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replay || replayed.State.DesiredState != DesiredStateEnabled || len(replayed.Effects) != 1 || replayed.Effects[0].Kind != EffectStart || replayed.Effects[0].DesiredVersion != enabled.State.DesiredVersion {
		t.Fatalf("lifecycle intent was not recovered: %#v", replayed)
	}
	if _, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "outbound-worker", LeaseDuration: time.Minute}); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("lifecycle intent leaked into outbound dispatch: %v", err)
	}
}

func TestEndpointServiceRecordsFencedProviderIdentity(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	svc := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	id := adapterapi.EndpointID("identity-endpoint")
	created, err := svc.Create(ctx, Command{
		CommandID: "identity-create", CorrelationID: "identity-create", EndpointID: id, AdapterKey: key,
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := svc.RecordIdentity(ctx, Command{
		CommandID: "identity-observed", CorrelationID: "identity-observed", EndpointID: id,
		Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion, ProviderID: "discord:bot-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if recorded.State.ProviderID != "discord:bot-1" || recorded.State.DesiredVersion != created.State.DesiredVersion || recorded.State.Version != created.State.Version+1 {
		t.Fatalf("identity result = %#v", recorded.State)
	}
	view, err := svc.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if view.ProviderID != "discord:bot-1" {
		t.Fatalf("persisted provider identity = %#v", view)
	}
	if _, err := svc.RecordIdentity(ctx, Command{
		CommandID: "identity-stale", CorrelationID: "identity-stale", EndpointID: id,
		Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion - 1, ProviderID: "discord:bot-2",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale identity error = %v", err)
	}
}

func TestIdentityObservationDoesNotRewriteLifecycleOperation(t *testing.T) {
	ctx := context.Background()
	store, db := serviceStore(t)
	defer db.Close()
	key := adapterapi.AdapterKey("fake")
	service := NewService(store, serviceRegistry{key: serviceDescriptor{key: key}})
	endpointID := adapterapi.EndpointID("identity-operation-endpoint")

	created, err := service.Create(ctx, Command{
		CommandID: "identity-operation-create", CorrelationID: "identity-operation-correlation", EndpointID: endpointID, AdapterKey: key,
		Config: adapterapi.ValidatedConfig{Version: 1, Canonical: json.RawMessage(`{"x":1}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	operationID := created.Operation.OperationID
	before, err := store.GetOperation(ctx, operationID)
	if err != nil {
		t.Fatal(err)
	}
	projectionBefore, err := store.ReadProjectionRow(ctx, OperationProjectionName, operationID)
	if err != nil {
		t.Fatal(err)
	}

	identityResult, err := service.RecordIdentity(ctx, Command{
		CommandID: "identity-operation-observed", CorrelationID: "identity-observation", EndpointID: endpointID,
		Generation: created.State.Generation, DesiredVersion: created.State.DesiredVersion, ProviderID: "discord:bot-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if identityResult.State.OperationID != operationID || identityResult.State.CorrelationID != created.State.CorrelationID {
		t.Fatalf("identity observation changed lifecycle identity: operation=%q correlation=%q", identityResult.State.OperationID, identityResult.State.CorrelationID)
	}
	view, err := service.Get(ctx, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if view.CorrelationID != created.State.CorrelationID {
		t.Fatalf("identity observation rewrote endpoint projection correlation: got %q, want %q", view.CorrelationID, created.State.CorrelationID)
	}
	after, err := store.GetOperation(ctx, operationID)
	if err != nil {
		t.Fatal(err)
	}
	projectionAfter, err := store.ReadProjectionRow(ctx, OperationProjectionName, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(projectionAfter.Payload, projectionBefore.Payload) {
		t.Fatalf("identity observation rewrote operation projection:\nbefore: %s\nafter:  %s", projectionBefore.Payload, projectionAfter.Payload)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("identity observation rewrote operation metadata:\nbefore: %#v\nafter:  %#v", before, after)
	}
}
