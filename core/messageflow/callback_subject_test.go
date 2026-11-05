package messageflow

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// Hidden rolls and owner notices remain derived from the originating group,
// even when the destination conversation is different.
func TestCallbackOutboundInheritsTheMessageSubjectWhereverItIsAddressed(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/subject.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db)
	inbound, err := NewInboundService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbound.HandleInbound(ctx, endpoint.FencedInbound{
		EndpointID: "endpoint-1", Generation: 1, DesiredVersion: 1,
		Message: adapterapi.InboundMessage{ProviderEventID: "subject-message", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Sender: "user", Conversation: "group", Platform: "test", Text: "hidden roll"},
	}); err != nil {
		t.Fatal(err)
	}
	outbound, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{
		EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
	}}, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	targets := []adapterapi.EffectTarget{
		{Kind: adapterapi.TargetGroup, Conversation: "group"},
		{Kind: adapterapi.TargetPerson, Conversation: "person-1"},
		{Kind: adapterapi.TargetGroup, Conversation: "owner-group"},
	}
	host := &callbackTestHost{fn: func(ctx context.Context, _ CallbackRequest, _ *playerstate.LocalOverlay, collector *execution.MutationCollector) (CallbackResult, error) {
		for _, target := range targets {
			effect := testEffect()
			effect.ID = adapterapi.EffectID("derived-" + target.Conversation)
			effect.OperationID = adapterapi.OperationID("operation-" + target.Conversation)
			effect.Payload.Target = target
			if target.Kind == adapterapi.TargetGroup {
				effect.Payload.Kind = adapterapi.EffectPayloadGroupText
			}
			effect.Deadline = time.Now().Add(time.Minute).UTC()
			var err error
			effect.Lane, err = adapterapi.NewLaneMetadata(effect.EndpointID, target, 1)
			if err != nil {
				return CallbackResult{}, err
			}
			prepared, err := outbound.Prepare(ctx, SubmitRequest{Effect: effect, CommandID: "command-" + string(target.Conversation), PrincipalID: "principal"})
			if err != nil {
				return CallbackResult{}, err
			}
			if err := collector.AddPreparedOutbound(prepared.OwnedWork()); err != nil {
				return CallbackResult{}, err
			}
		}
		return CallbackResult{}, nil
	}}
	callback, err := NewCallbackService(CallbackConfig{Inbox: store, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callback.ProcessOne(ctx); err != nil {
		t.Fatal(err)
	}
	var effects []struct {
		EffectID string
		Subject  string
		Lane     string
		Payload  []byte
	}
	if err := db.GORM().Table("outbox_effects").Order("effect_id").Find(&effects).Error; err != nil {
		t.Fatal(err)
	}
	if len(effects) != len(targets) || host.calls != 1 {
		t.Fatalf("effects=%d host calls=%d", len(effects), host.calls)
	}
	for _, effect := range effects {
		var wire effectWire
		if err := json.Unmarshal(effect.Payload, &wire); err != nil {
			t.Fatal(err)
		}
		if effect.Subject != "group" || effect.Lane != wire.Effect.Lane.Key || wire.Effect.Payload.Text != "hello" {
			t.Fatalf("derived effect=%+v wire=%+v", effect, wire)
		}
		if err := wire.Effect.Validate(); err != nil {
			t.Fatalf("derived effect %s invalid: %v", effect.EffectID, err)
		}
	}
}
