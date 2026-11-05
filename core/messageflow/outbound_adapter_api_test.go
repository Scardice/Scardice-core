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

func adapterAPIOutboundEffect(t *testing.T, raw string) adapterapi.OutboundEffect {
	t.Helper()
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetRaw, Raw: "adapter-api"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-adapter-api", target, 1)
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

func TestAdapterAPIRequestPlaintextRoundTripPreservesExactJSONWithoutEventLeak(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/adapter-api.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "db-adapter-api",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	raw := "{\n  \"action\": \"vendor.private_future_action\", \"params\": {\"snowflake\": 900719925474099312345, \"note\": \"secret spacing\"}\n}"
	effect := adapterAPIOutboundEffect(t, raw)
	resolver := testResolver{snap: EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
	}}
	service, err := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
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
		Payload   []byte
		Lane      string
		RiskClass string
	}
	if err := db.GORM().Table("outbox_effects").Where("effect_id = ?", result.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.RiskClass != eventstore.RiskNonIdempotentAfterDispatch {
		t.Fatalf("risk class = %q", row.RiskClass)
	}
	if row.Lane != `["endpoint-adapter-api","raw","adapter-api"]` {
		t.Fatalf("stored lane=%q", row.Lane)
	}
	var wire effectWire
	if err := json.Unmarshal(row.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.RawTarget != "adapter-api" || wire.Effect.Payload.RequestJSON != raw {
		t.Fatalf("plaintext wire changed request: target=%q request=%q", wire.RawTarget, wire.Effect.Payload.RequestJSON)
	}
}

func TestAdapterAPIUnsupportedCapabilityFailsBeforeCommit(t *testing.T) {
	effect := adapterAPIOutboundEffect(t, `{"action":"vendor.action","params":{}}`)
	base := EndpointSnapshot{
		EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
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
			service, err := NewOutboundService(store, testResolver{snap: snapshot}, &testIDs{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Submit(context.Background(), SubmitRequest{Effect: effect, CommandID: "unsupported-" + name, PrincipalID: "plugin-principal"})
			if !errors.Is(err, ErrCapabilityDenied) {
				t.Fatalf("error = %v", err)
			}
			if store.calls != 0 {
				t.Fatalf("unsupported adapter API reached persistence: commits=%d", store.calls)
			}
		})
	}
}
