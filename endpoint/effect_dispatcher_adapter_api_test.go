package endpoint

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type adapterAPIRetryableExecutor struct {
	calls int
	raw   string
}

func (e *adapterAPIRetryableExecutor) ExecutePinned(_ context.Context, _ adapterapi.EndpointID, _ uint64, effect adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	e.calls++
	if effect.Payload.Target.ProviderRawTarget() == "adapter-api" {
		e.raw = effect.Payload.RequestJSON
	}
	return adapterapi.RetryableResult("provider-timeout", "outcome unknown"), nil
}

func TestAdapterAPIRetryableProviderResultSettlesAmbiguousWithoutRequeue(t *testing.T) {
	raw := "{\n\"action\":\"vendor.non_idempotent_action\",\"params\":{\"value\":900719925474099312345}\n}"
	target := adapterapi.EffectTarget{Kind: adapterapi.TargetRaw, Raw: "adapter-api"}
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", target, []byte("adapter-api-root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	effect := adapterapi.OutboundEffect{
		Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "op-1",
		CorrelationID: "correlation-1", CausationID: "cause-1", Lane: lane, Deadline: time.Now().Add(time.Hour).UTC(),
		Risk: adapterapi.EffectRiskNormal, RetryClass: adapterapi.EffectRetryNonIdempotent,
		RequiredCapabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		RequiredAction:       adapterapi.ActionKindAdapterAPI, Kind: adapterapi.EffectKindAction,
		Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadAdapterAPI, Target: target, RequestJSON: raw},
	}
	plain, err := json.Marshal(effectWire{Effect: effect, RawTarget: target.ProviderRawTarget()})
	if err != nil {
		t.Fatal(err)
	}
	store := &dispatcherTestStore{
		claimed: eventstore.OutboxLease{Effect: eventstore.NewEffect{
			EffectID: "effect-1", Version: 1, EndpointID: "endpoint-1", LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1",
			PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
			DeadlineAt: effect.Deadline, RiskClass: eventstore.RiskNonIdempotentAfterDispatch,
		}},
		marked: eventstore.OutboxLease{Effect: eventstore.NewEffect{
			EffectID: "effect-1", EndpointID: "endpoint-1", PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"),
			PayloadEncryptionKeyID: "key", RiskClass: eventstore.RiskNonIdempotentAfterDispatch,
		}},
	}
	executor := &adapterAPIRetryableExecutor{}
	dispatcher, err := NewEffectDispatcher(store, dispatcherTestDecrypt{plain: plain}, executor, "worker", WithDispatcherIDGenerator(&dispatcherTestIDs{}), WithDispatcherRandom(func(time.Duration) time.Duration { return 0 }))
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatcher.DispatchOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != adapterapi.EffectRetryable || executor.calls != 1 || executor.raw != raw {
		t.Fatalf("execution result=%#v calls=%d raw=%q", result, executor.calls, executor.raw)
	}
	for _, call := range store.calls {
		if call == "requeue" {
			t.Fatalf("non-idempotent adapter API was requeued: %v", store.calls)
		}
	}
	if len(store.work.Effects) != 1 || store.work.Effects[0].Status != eventstore.OutboxStatusAmbiguous {
		t.Fatalf("effect settlement = %#v", store.work.Effects)
	}
	if len(store.work.Operations) != 1 || store.work.Operations[0].Status != "ambiguous" {
		t.Fatalf("operation settlement = %#v", store.work.Operations)
	}
}
