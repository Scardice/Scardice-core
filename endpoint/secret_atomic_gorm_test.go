package endpoint

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func endpointA6Config(t *testing.T, ref string, version uint64) adapterapi.ValidatedConfig {
	t.Helper()
	raw := []byte(`{"mode":"server","listenAddress":"127.0.0.1:6700","reverseSuffix":"/ws","friendRequestPolicy":"accept","insecureSkipVerify":false,"token":{"secretRef":"` + ref + `","version":1}}`)
	canonical, err := adapterapi.CanonicalizeJSON(raw)
	if err != nil { t.Fatal(err) }
	return adapterapi.ValidatedConfig{Version: 1, Canonical: canonical, SecretRefs: []adapterapi.SecretRef{{Ref: ref, Version: version}}}
}
func TestCommitWithSecretUsesA6AADAndRollsBackEventAndSecret(t *testing.T) {
	ctx := context.Background()
	source := &endpointKeySource{}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "endpoint-secret.db"), KeySource: source})
	if err != nil { t.Fatal(err) }
	defer db.Close()
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "endpoint-secret", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil { t.Fatal(err) }
	repository := NewRepository(store)
	config := endpointA6Config(t, "token-a6", 1)
	create := Command{Kind: CommandCreate, CommandID: "a6-create", CorrelationID: "a6-correlation", EndpointID: adapterapi.EndpointID("endpoint-a6"), AdapterKey: adapterapi.AdapterKey("pureonebot"), Config: config}
	decision, err := Decide(State{}, create)
	if err != nil { t.Fatal(err) }
	input := &SecretInput{Ref: "token-a6", Version: 1, Plaintext: []byte("a6-token")}
	if _, err := repository.CommitWithSecret(ctx, State{}, decision, input); err != nil { t.Fatal(err) }
	resolved, err := store.ResolveSecret(ctx, "token-a6", 1)
	if err != nil || string(resolved.Plaintext) != "a6-token" { t.Fatalf("resolved secret=%q err=%v", resolved.Plaintext, err) }
	for _, value := range input.Plaintext { if value != 0 { t.Fatal("transient plaintext was not cleared") } }

	state, err := ApplyDecision(State{}, decision)
	if err != nil { t.Fatal(err) }
	updatedConfig := endpointA6Config(t, "token-a6-next", 1)
	update := Command{Kind: CommandUpdateConfig, CommandID: "a6-update", CorrelationID: "a6-update-correlation", EndpointID: state.EndpointID, AdapterKey: state.AdapterKey, Config: updatedConfig}
	updateDecision, err := Decide(state, update)
	if err != nil { t.Fatal(err) }
	rollbackInput := &SecretInput{Ref: "token-a6-next", Version: 1, ExpectedVersion: 99, Plaintext: []byte("next-token")}
	if _, err := repository.CommitWithSecret(ctx, state, updateDecision, rollbackInput); !errors.Is(err, eventstore.ErrParticipantConflict) {
		t.Fatalf("rollback commit error=%v, want participant conflict", err)
	}
	events, err := store.Load(ctx, endpointStream(state.EndpointID), 0)
	if err != nil { t.Fatal(err) }
	if len(events) != 1 { t.Fatalf("event count after rollback=%d, want 1", len(events)) }
	if _, err := store.ResolveSecret(ctx, "token-a6-next", 1); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("rolled-back secret resolve error=%v, want not found", err)
	}
}
