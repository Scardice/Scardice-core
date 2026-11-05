package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type secretAtomicStore struct {
	work  eventstore.UnitOfWork
	calls int
	err   error
}

func (s *secretAtomicStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.calls++
	s.work = work
	s.work.SecretUpdates = append([]eventstore.SecretUpdate(nil), work.SecretUpdates...)
	for i := range s.work.SecretUpdates {
		s.work.SecretUpdates[i].Value = append([]byte(nil), work.SecretUpdates[i].Value...)
	}
	return eventstore.CommitResult{}, s.err
}
func (*secretAtomicStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, eventstore.ErrNotFound
}
func (*secretAtomicStore) Close() error { return nil }

type strictSecretDescriptor struct{}

func (strictSecretDescriptor) Key() adapterapi.AdapterKey { return adapterapi.AdapterKey("pureonebot") }
func (strictSecretDescriptor) ConfigVersion() uint16      { return 1 }
func (strictSecretDescriptor) ValidateConfig(_ context.Context, raw json.RawMessage) (adapterapi.ValidatedConfig, error) {
	canonical, err := adapterapi.CanonicalizeJSON(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: []adapterapi.SecretRef{{Ref: "token-a", Version: 1}}}, nil
}
func (strictSecretDescriptor) SupportedActions(adapterapi.ValidatedConfig) adapterapi.ActionSet {
	return 0
}
func (strictSecretDescriptor) Capabilities(adapterapi.ValidatedConfig) adapterapi.CapabilitySet {
	return adapterapi.CapabilityLifecycle
}
func (strictSecretDescriptor) NewRuntime(adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	return nil, errors.New("not used")
}

func TestEndpointCommandSecretInputSharesAtomicCommit(t *testing.T) {
	store := &secretAtomicStore{err: errors.New("rollback")}
	repository := NewRepository(store)
	configCanonical, err := adapterapi.CanonicalizeJSON([]byte(`{"mode":"server","listenAddress":"127.0.0.1:6700","reverseSuffix":"/ws","friendRequestPolicy":"accept","insecureSkipVerify":false,"token":{"secretRef":"token-ref","version":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	command := Command{
		Kind: CommandCreate, CommandID: "secret-create", CorrelationID: "secret-correlation",
		EndpointID: adapterapi.EndpointID("endpoint-secret"), AdapterKey: adapterapi.AdapterKey("pureonebot"),
		Config:      adapterapi.ValidatedConfig{Version: 1, Canonical: configCanonical, SecretRefs: []adapterapi.SecretRef{{Ref: "token-ref", Version: 1}}},
		SecretInput: &SecretInput{Ref: "token-ref", Version: 1, Plaintext: []byte("token-bytes")},
	}
	decision, err := Decide(State{}, command)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.CommitWithSecret(context.Background(), State{}, decision, command.SecretInput)
	if !errors.Is(err, store.err) {
		t.Fatalf("CommitWithSecret error = %v, want %v", err, store.err)
	}
	if store.calls != 1 {
		t.Fatalf("Store.Commit calls = %d, want 1", store.calls)
	}
	if len(store.work.Streams) != 1 || len(store.work.SecretUpdates) != 1 {
		t.Fatalf("atomic UoW = streams=%d secrets=%d", len(store.work.Streams), len(store.work.SecretUpdates))
	}
	if string(store.work.SecretUpdates[0].Value) != "token-bytes" {
		t.Fatalf("secret value in UoW = %q, want the raw value", store.work.SecretUpdates[0].Value)
	}
	if string(store.work.Streams[0].Events[0].Payload) == "" || string(store.work.Streams[0].Events[0].Payload) == "token-bytes" {
		t.Fatalf("event payload missing or leaked secret: %s", store.work.Streams[0].Events[0].Payload)
	}
	for index, value := range command.SecretInput.Plaintext {
		if value != 0 {
			t.Fatalf("transient plaintext byte %d was not cleared", index)
		}
	}
}
func TestEndpointServiceRejectsSecretReferenceAliasMismatch(t *testing.T) {
	descriptor := strictSecretDescriptor{}
	config, err := descriptor.ValidateConfig(context.Background(), []byte(`{"mode":"server","listenAddress":"127.0.0.1:6700","token":{"secretRef":"token-a","version":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	store := &secretAtomicStore{}
	service := &Service{
		Repository: NewRepository(store),
		Store:      store,
		Registry:   serviceRegistry{descriptor.Key(): descriptor},
	}
	command := Command{
		Kind: CommandCreate, CommandID: "alias-mismatch", CorrelationID: "alias-correlation",
		EndpointID: adapterapi.EndpointID("endpoint-alias"), AdapterKey: adapterapi.AdapterKey("pureonebot"),
		Config: config, SecretRefs: []adapterapi.SecretRef{{Ref: "token-b", Version: 1}},
		SecretInput: &SecretInput{Ref: "token-b", Version: 1, Plaintext: []byte("must-not-persist")},
	}
	if _, err := service.Execute(context.Background(), command); err == nil {
		t.Fatal("mismatched secret reference alias was accepted")
	}
	if store.calls != 0 {
		t.Fatalf("Store.Commit calls = %d, want 0 after validation rejection", store.calls)
	}
}
