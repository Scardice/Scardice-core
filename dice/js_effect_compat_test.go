package dice

import (
	"errors"
	"testing"

	"Scardice-core/eventstore"
)

func TestJSEffectRequiresPlaintextPayloadAndValidRisk(t *testing.T) {
	base := JSEffectRequest{EffectID: "effect", EndpointID: "endpoint", Lane: "lane", EffectType: "reply", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, Payload: []byte("payload")}
	if _, err := BuildJSEffect(base); err != nil {
		t.Fatalf("valid plaintext effect err=%v", err)
	}
	missingPayload := base
	missingPayload.Payload = nil
	if _, err := BuildJSEffect(missingPayload); err == nil {
		t.Fatal("missing payload accepted")
	}
	invalidRisk := base
	invalidRisk.RiskClass = "unknown"
	if _, err := BuildJSEffect(invalidRisk); err == nil {
		t.Fatal("invalid risk accepted")
	}
}

func TestBuildJSEffectRejectsCallerOwnedFields(t *testing.T) {
	base := JSEffectRequest{EffectID: "effect", EndpointID: "endpoint", Lane: "lane", EffectType: "reply", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, Payload: []byte("{}")}
	for name, mutate := range map[string]func(*JSEffectRequest){
		"expected version": func(r *JSEffectRequest) { r.ExpectedVersion = 1 },
		"subject":          func(r *JSEffectRequest) { r.Subject = "forged" },
		"principal":        func(r *JSEffectRequest) { r.PrincipalID = "forged" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := BuildJSEffect(request); !errors.Is(err, ErrJSEffect) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
