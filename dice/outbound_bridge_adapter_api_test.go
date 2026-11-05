package dice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
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
			Lane: "lane", EffectType: "action", RiskClass: eventstore.RiskNonIdempotentAfterDispatch,
			Status: eventstore.OutboxStatusPending, Payload: []byte("payload"),
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
	ctx, _, _ := canonicalBridgeTestContext(t, &bridgeTestSubmitter{})
	ctx.EndPoint.ID = "current-endpoint"
	submitter := &adapterAPIRecordingSubmitter{}
	resolver := &adapterAPIRecordingResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "target-endpoint", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
	}}
	bridge := NewDurableOutboundBridge(submitter, resolver, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
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
	root := newCanonicalTestRoot(t, ctx.Dice, "adapter-api-callback")
	collector := root.Collector
	ctx.callbackTransaction = root.Transaction
	ctx.callbackMetadata = root.Metadata
	ctx.executionContext = root.Context
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
	otherRoot := newCanonicalTestRoot(t, ctx.Dice, "adapter-api-other-callback")
	other := &MsgContext{callbackTransaction: otherRoot.Transaction}
	if _, ok := bridge.StagedAdapterAPIOperation(other, operation.ID); ok {
		t.Fatal("staged operation leaked to another collector")
	}
	bridge.mu.Lock()
	pendingNotifications := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingNotifications != 0 || len(ctx.callbackTransaction.callbackPublication) != 0 || len(ctx.callbackTransaction.callbackAfterCommit) != 0 {
		t.Fatalf("raw enqueue registered send notification: pending=%d publication=%d callbacks=%d",
			pendingNotifications, len(ctx.callbackTransaction.callbackPublication), len(ctx.callbackTransaction.callbackAfterCommit))
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

type persistedAdapterAPIExecutor struct {
	effect adapterapi.OutboundEffect
	calls  int
}

func (e *persistedAdapterAPIExecutor) ExecutePinned(_ context.Context, _ adapterapi.EndpointID, _ uint64, effect adapterapi.OutboundEffect) (adapterapi.EffectResult, error) {
	e.effect = effect
	e.calls++
	return adapterapi.SucceededResult("provider-native-result"), nil
}

func TestEnqueueAdapterAPIExactRequestSurvivesReopenAndDispatch(t *testing.T) {
	ctx := context.Background()
	config := eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "adapter-request.db"), DatabaseIdentity: "adapter-request",
	}
	database, err := eventstore.OpenDatabase(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if database != nil {
			_ = database.Close()
		}
	})
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	d := &Dice{BaseConfig: BaseConfig{Name: "adapter-request-dice"}, DurableStore: store}
	seedCanonicalTestConfigBaseline(t, d)
	resolver := &adapterAPIRecordingResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: "target-endpoint", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindAdapterAPI),
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	bridge := NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
	raw := "{\n \"action\":\"vendor.future_action\",\"params\":{\"id\":900719925474099312345,\"text\":\"exact bytes\"}\n}"
	operation, err := bridge.EnqueueAdapterAPI(ctx, &MsgContext{Dice: d}, "target-endpoint", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = eventstore.OpenDatabase(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	store = eventstore.NewStore(database, projectionset.StoreOptions()...)
	var row struct {
		EffectID   string `gorm:"column:effect_id"`
		EndpointID string `gorm:"column:endpoint_id"`
		Lane       string `gorm:"column:lane"`
		Payload    []byte `gorm:"column:payload"`
	}
	if err := database.GORM().Table("outbox_effects").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Effect    adapterapi.OutboundEffect `json:"effect"`
		RawTarget string                    `json:"rawTarget"`
	}
	if err := json.Unmarshal(row.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	if row.EndpointID != "target-endpoint" || string(wire.Effect.ID) != row.EffectID || wire.Effect.Lane.Key != row.Lane ||
		wire.Effect.Payload.RequestJSON != raw || wire.RawTarget != "adapter-api" || string(wire.Effect.OperationID) != operation.ID {
		t.Fatalf("reopened adapter request changed: row=%#v wire=%#v", row, wire)
	}
	executor := &persistedAdapterAPIExecutor{}
	dispatcher, err := endpointcore.NewEffectDispatcher(store, executor, "adapter-request-worker", endpointcore.WithDispatcherTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatcher.DispatchOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != adapterapi.EffectSucceeded || executor.calls != 1 || executor.effect.Payload.RequestJSON != raw ||
		executor.effect.Payload.Target.ProviderRawTarget() != "adapter-api" {
		t.Fatalf("persisted adapter dispatch changed request: result=%#v calls=%d effect=%#v", result, executor.calls, executor.effect)
	}
	stored, err := store.GetOperation(ctx, operation.ID)
	if err != nil || stored.Status != "succeeded" {
		t.Fatalf("persisted adapter operation = %#v err=%v", stored, err)
	}
}
