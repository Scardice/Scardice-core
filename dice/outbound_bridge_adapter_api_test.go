package dice

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
)

type adapterAPIRecordingSubmitter struct {
	submitted []messageflow.SubmitRequest
	prepared  []messageflow.SubmitRequest
}

func (s *adapterAPIRecordingSubmitter) Submit(_ context.Context, request messageflow.SubmitRequest) (messageflow.SubmitResult, error) {
	s.submitted = append(s.submitted, request)
	return messageflow.SubmitResult{
		EffectID:    string(request.Effect.ID),
		OperationID: string(request.Effect.OperationID),
	}, nil
}

func (s *adapterAPIRecordingSubmitter) Prepare(_ context.Context, request messageflow.SubmitRequest) (messageflow.PreparedOutbound, error) {
	s.prepared = append(s.prepared, request)
	effectID := string(request.Effect.ID)
	operationID := string(request.Effect.OperationID)
	work := eventstore.UnitOfWork{
		Streams: []eventstore.StreamAppend{{
			Stream: eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: effectID},
			Events: []eventstore.NewEvent{{
				EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: []byte(`{}`),
				Metadata: eventstore.Metadata{EventID: "event-adapter-api", CommandID: request.CommandID, CorrelationID: string(request.Effect.CorrelationID)},
			}},
		}},
		Operations: []eventstore.OperationUpdate{{
			OperationID: operationID, Kind: "outbound-effect", Status: "pending",
			ResourceID: effectID, IdempotencyScope: "outbound", IdempotencyKey: request.CommandID,
		}},
		Effects: []eventstore.NewEffect{{
			EffectID: effectID, EndpointID: string(request.Effect.EndpointID),
			LaneHMAC: []byte("lane"), EffectType: "action", RiskClass: eventstore.RiskNonIdempotentAfterDispatch,
			Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key",
		}},
	}
	return messageflow.PreparedOutbound{
		Work: work,
		Result: messageflow.SubmitResult{
			EffectID: effectID, OperationID: operationID,
		},
	}, nil
}

type adapterAPIRecordingResolver struct {
	snapshot messageflow.EndpointSnapshot
	seen     []adapterapi.EndpointID
}

func (r *adapterAPIRecordingResolver) Resolve(_ context.Context, endpointID adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	r.seen = append(r.seen, endpointID)
	if endpointID != r.snapshot.EndpointID {
		return messageflow.EndpointSnapshot{}, messageflow.ErrEndpointUnavailable
	}
	return r.snapshot, nil
}

func newAdapterAPIBridgeTest(t *testing.T) (*MsgContext, *DurableOutboundBridge, *adapterAPIRecordingSubmitter, *adapterAPIRecordingResolver) {
	t.Helper()
	ctx, _, _ := bridgeTestContext(&bridgeTestSubmitter{})
	ctx.EndPoint.ID = "current-endpoint"
	submitter := &adapterAPIRecordingSubmitter{}
	resolver := &adapterAPIRecordingResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "target-endpoint", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
		IndexRootID:  "root-1",
		IndexSigner:  bridgeTestIndexSigner{root: []byte("01234567890123456789012345678901"), id: "root-1"},
	}}
	bridge := NewDurableOutboundBridge(submitter, resolver, eventstore.UUIDGenerator{})
	ctx.Dice.OutboundBridge = bridge
	return ctx, bridge, submitter, resolver
}

func TestEnqueueAdapterAPIUsesExplicitEndpointAndCommitsStandalonePendingOperation(t *testing.T) {
	ctx, bridge, submitter, resolver := newAdapterAPIBridgeTest(t)
	raw := "{\n \"action\":\"vendor.future_action\",\"params\":{\"id\":900719925474099312345}\n}"

	operation, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", raw)
	if err != nil {
		t.Fatal(err)
	}
	if operation.ID == "" || operation.Status != "pending" {
		t.Fatalf("operation = %#v", operation)
	}
	if len(submitter.submitted) != 1 || len(submitter.prepared) != 0 {
		t.Fatalf("submit calls=%d prepare calls=%d", len(submitter.submitted), len(submitter.prepared))
	}
	if len(resolver.seen) == 0 || resolver.seen[0] != "target-endpoint" || ctx.EndPoint.ID != "current-endpoint" {
		t.Fatalf("resolved=%v current endpoint=%q", resolver.seen, ctx.EndPoint.ID)
	}
	request := submitter.submitted[0]
	if request.Effect.EndpointID != "target-endpoint" || request.Effect.Payload.Target.ProviderRawTarget() != "adapter-api" || request.Effect.Payload.RequestJSON != raw {
		t.Fatalf("submitted request = %#v", request)
	}
	if request.Effect.RetryClass != adapterapi.EffectRetryNonIdempotent || request.Effect.RequiredAction != adapterapi.ActionKindAdapterAPI {
		t.Fatalf("unsafe adapter API classification = %#v", request.Effect)
	}
	bridge.mu.Lock()
	pendingNotifications := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingNotifications != 0 {
		t.Fatalf("raw enqueue registered send notification: %d", pendingNotifications)
	}
}

func TestEnqueueAdapterAPICallbackStagesOperationAndRollbackHasNoStandaloneEffects(t *testing.T) {
	ctx, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	ctx.callbackTransaction = &DurableCallbackTransaction{collector: collector}
	raw := `{"action":"vendor.callback_action","params":{"opaque":true}}`

	operation, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", raw)
	if err != nil {
		t.Fatal(err)
	}
	if operation.ID == "" || operation.Status != "staged" {
		t.Fatalf("operation = %#v", operation)
	}
	if len(submitter.prepared) != 1 || len(submitter.submitted) != 0 {
		t.Fatalf("prepare calls=%d submit calls=%d", len(submitter.prepared), len(submitter.submitted))
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 || work.Operations[0].OperationID != operation.ID {
		t.Fatalf("staged work = %#v", work)
	}
	if staged, ok := bridge.StagedAdapterAPIOperation(ctx, operation.ID); !ok || staged != operation {
		t.Fatalf("staged lookup = %#v, %t", staged, ok)
	}
	other := &MsgContext{
		callbackTransaction: &DurableCallbackTransaction{collector: messageflow.NewMutationCollector(eventstore.EventFactory{})},
	}
	if _, ok := bridge.StagedAdapterAPIOperation(other, operation.ID); ok {
		t.Fatal("staged operation leaked to another collector")
	}
	bridge.mu.Lock()
	pendingNotifications := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingNotifications != 0 || len(ctx.callbackTransaction.callbackAfterCommit) != 0 {
		t.Fatalf("raw enqueue registered send notification: pending=%d callbacks=%d", pendingNotifications, len(ctx.callbackTransaction.callbackAfterCommit))
	}
	// Dropping this collector models callback rollback: no Submit call or other
	// side effect has occurred, and the prepared work is owned only by the caller.
}

func TestEnqueueAdapterAPIRejectsReleasedCallbackScopeBeforeStaging(t *testing.T) {
	ctx, bridge, submitter, _ := newAdapterAPIBridgeTest(t)
	ctx.executionReleased.Store(true)
	_, err := bridge.EnqueueAdapterAPI(context.Background(), ctx, "target-endpoint", `{"action":"vendor.action"}`)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("released scope error = %v", err)
	}
	if len(submitter.prepared) != 0 || len(submitter.submitted) != 0 {
		t.Fatal("released scope reached durable submission")
	}
}
