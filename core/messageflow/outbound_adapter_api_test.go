package messageflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func adapterAPIOutboundEffect(t *testing.T, root []byte, raw string) adapterapi.OutboundEffect {
	t.Helper()
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetRaw, Raw: "adapter-api"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-adapter-api", target, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	return adapterapi.OutboundEffect{
		Version:              adapterapi.EffectVersionOne,
		ID:                   "effect-adapter-api",
		EndpointID:           "endpoint-adapter-api",
		OperationID:          "operation-adapter-api",
		CorrelationID:        "correlation-adapter-api",
		CausationID:          "causation-adapter-api",
		Lane:                 lane,
		Deadline:             time.Now().Add(time.Minute).UTC(),
		Risk:                 adapterapi.EffectRiskNormal,
		RetryClass:           adapterapi.EffectRetryNonIdempotent,
		RequiredCapabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		RequiredAction:       adapterapi.ActionKindAdapterAPI,
		Kind:                 adapterapi.EffectKindAction,
		Payload: adapterapi.EffectPayload{
			Kind:        adapterapi.EffectPayloadAdapterAPI,
			Target:      target,
			RequestJSON: raw,
		},
	}
}

func TestAdapterAPIRequestEncryptedRoundTripPreservesExactJSONWithoutEventLeak(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/adapter-api.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := integrationKeySource{
		indexID: "index-adapter-api", index: []byte("01234567890123456789012345678901"),
		rootID: "root-adapter-api", root: []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-adapter-api", IndexRootID: source.indexID,
		EncryptionRootIDs: []string{source.rootID}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	raw := "{\n  \"action\": \"vendor.private_future_action\", \"params\": {\"snowflake\": 900719925474099312345, \"note\": \"secret spacing\"}\n}"
	effect := adapterAPIOutboundEffect(t, source.index, raw)
	resolver := testResolver{snap: EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
		IndexRootID:  source.indexID, IndexSigner: store,
	}}
	service, err := NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Submit(ctx, SubmitRequest{Effect: effect, CommandID: "adapter-api-command", PrincipalID: "plugin-principal"})
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: result.EffectID}, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if strings.Contains(string(events[0].Payload), "vendor.private_future_action") || strings.Contains(string(events[0].Payload), "secret spacing") {
		t.Fatal("immutable shape event leaked adapter request JSON")
	}

	var row struct {
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		EncryptionKeyID   string `gorm:"column:encryption_key_id"`
		RiskClass         string `gorm:"column:risk_class"`
	}
	if err := db.GORM().Table("outbox_effects").Where("effect_id = ?", result.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.RiskClass != eventstore.RiskNonIdempotentAfterDispatch {
		t.Fatalf("risk class = %q", row.RiskClass)
	}
	if strings.Contains(string(row.PayloadCiphertext), "vendor.private_future_action") || strings.Contains(string(row.PayloadCiphertext), "secret spacing") {
		t.Fatal("outbox stored plaintext adapter request")
	}
	plain, err := store.DecryptBound(ctx, "outbox/v1", result.EffectID, string(effect.EndpointID), 1, row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var wire effectWire
	if err := json.Unmarshal(plain, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.RawTarget != "adapter-api" || wire.Effect.Payload.RequestJSON != raw {
		t.Fatalf("decrypted wire changed request: target=%q request=%q", wire.RawTarget, wire.Effect.Payload.RequestJSON)
	}
}

func TestAdapterAPIUnsupportedCapabilityFailsBeforeEncryptionOrCommit(t *testing.T) {
	root := []byte(strings.Repeat("r", 32))
	effect := adapterAPIOutboundEffect(t, root, `{"action":"vendor.action","params":{}}`)
	base := EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
		IndexRootID:  "index-root-1", IndexSigner: testIndexSigner{root: root, id: "index-root-1"},
	}
	cases := map[string]EndpointSnapshot{
		"missing action capability": func() EndpointSnapshot {
			snapshot := base
			snapshot.Capabilities = adapterapi.CapabilityOutbound
			return snapshot
		}(),
		"missing abstract action": func() EndpointSnapshot {
			snapshot := base
			snapshot.Actions = 0
			return snapshot
		}(),
	}
	for name, snapshot := range cases {
		t.Run(name, func(t *testing.T) {
			store := &testStore{}
			encryptor := &testEncryptor{}
			service, err := NewOutboundService(store, testResolver{snap: snapshot}, encryptor, &testIDs{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Submit(context.Background(), SubmitRequest{Effect: effect, CommandID: "unsupported-" + name, PrincipalID: "plugin-principal"})
			if !errors.Is(err, ErrCapabilityDenied) {
				t.Fatalf("error = %v", err)
			}
			if store.calls != 0 || len(encryptor.plain) != 0 {
				t.Fatalf("unsupported adapter API reached persistence: commits=%d plaintext=%d", store.calls, len(encryptor.plain))
			}
		})
	}
}
