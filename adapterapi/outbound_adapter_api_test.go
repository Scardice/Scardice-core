package adapterapi

import (
	"errors"
	"testing"
	"time"
)

func adapterAPIEffectForTest(t *testing.T, raw string) OutboundEffect {
	t.Helper()
	target := EffectTarget{Kind: TargetRaw, Raw: "adapter-api"}
	lane, err := NewLaneMetadata("endpoint-1", target, []byte("adapter-api-index-root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return OutboundEffect{
		Version:              EffectVersionOne,
		ID:                   "effect-adapter-api",
		EndpointID:           "endpoint-1",
		OperationID:          "operation-adapter-api",
		CorrelationID:        "correlation-adapter-api",
		CausationID:          "causation-adapter-api",
		Lane:                 lane,
		Deadline:             time.Now().Add(time.Minute).UTC(),
		Risk:                 EffectRiskNormal,
		RetryClass:           EffectRetryNonIdempotent,
		RequiredCapabilities: CapabilityOutbound | CapabilityActions,
		RequiredAction:       ActionKindAdapterAPI,
		Kind:                 EffectKindAction,
		Payload: EffectPayload{
			Kind:        EffectPayloadAdapterAPI,
			Target:      target,
			RequestJSON: raw,
		},
	}
}

func TestAdapterAPIEffectAcceptsUnknownProviderActionWithoutRewritingJSON(t *testing.T) {
	raw := "{\n  \"action\": \"vendor.future_action\", \"params\": {\"snowflake\": 900719925474099312345, \"enabled\": true}\n}"
	effect := adapterAPIEffectForTest(t, raw)
	if err := effect.Validate(); err != nil {
		t.Fatalf("unknown provider action rejected: %v", err)
	}
	if effect.Payload.RequestJSON != raw {
		t.Fatalf("request JSON changed: %q", effect.Payload.RequestJSON)
	}
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityActions, ActionSet(0).With(ActionKindAdapterAPI)); err != nil {
		t.Fatalf("adapter API capability rejected: %v", err)
	}
	if err := effect.ValidateForCapabilities(CapabilityOutbound|CapabilityActions, ActionSet(0)); !errors.Is(err, ErrUnsupportedAction) {
		t.Fatalf("missing abstract adapter API action error = %v", err)
	}
}

func TestAdapterAPIPayloadGuardsRawRequestAndLegacyVariants(t *testing.T) {
	raw := `{"action":"vendor.action","params":{}}`
	base := adapterAPIEffectForTest(t, raw)
	cases := map[string]func(*OutboundEffect){
		"wrong target": func(effect *OutboundEffect) {
			effect.Payload.Target = EffectTarget{Kind: TargetRaw, Raw: "other"}
		},
		"extra normalized field": func(effect *OutboundEffect) {
			effect.Payload.Text = "not allowed"
		},
		"malformed request": func(effect *OutboundEffect) {
			effect.Payload.RequestJSON = `{"action":`
		},
		"retry safe": func(effect *OutboundEffect) {
			effect.RetryClass = EffectRetryProviderIdempotent
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			effect := base
			mutate(&effect)
			if !errors.Is(effect.Validate(), ErrInvalidContract) {
				t.Fatalf("invalid adapter API effect accepted: %#v", effect)
			}
		})
	}

	text := EffectPayload{
		Kind:        EffectPayloadPersonText,
		Target:      EffectTarget{Kind: TargetPerson, Conversation: "person-1"},
		Text:        "hello",
		RequestJSON: raw,
	}
	if !errors.Is(text.Validate(), ErrInvalidContract) {
		t.Fatal("request JSON accepted on a non-adapter payload")
	}
	legacy := OutboundEffect{ID: "legacy-effect", Kind: EffectKindAction, Action: ActionKindSendMessage}
	legacy.Payload.RequestJSON = raw
	if !errors.Is(legacy.Validate(), ErrInvalidContract) {
		t.Fatal("request JSON accepted on a legacy effect")
	}
}

func TestAdapterAPIEnumsAppendWithoutRenumberingExistingWireValues(t *testing.T) {
	if ActionKindAnswerRequest != 15 || ActionKindAdapterAPI != 16 {
		t.Fatalf("action wire values changed: answer=%d adapterAPI=%d", ActionKindAnswerRequest, ActionKindAdapterAPI)
	}
	if EffectPayloadAnswerRequest != 12 || EffectPayloadAdapterAPI != 13 {
		t.Fatalf("payload wire values changed: answer=%d adapterAPI=%d", EffectPayloadAnswerRequest, EffectPayloadAdapterAPI)
	}
}
