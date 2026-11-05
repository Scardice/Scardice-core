package messageflow

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

func TestCallbackOutboxPreservesEmissionOrder(t *testing.T) {
	for _, collected := range []bool{false, true} {
		name := "direct-unit-of-work"
		if collected {
			name = "callback-collector"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/order.db"})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store := eventstore.NewStore(db)
			if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "db-1", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
				t.Fatal(err)
			}
			service, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)}}, eventstore.UUIDGenerator{})
			if err != nil {
				t.Fatal(err)
			}
			collector := execution.NewMutationCollector(eventstore.EventFactory{})
			work := eventstore.UnitOfWork{}
			ids := []string{"z-first", "m-second", "a-third"}
			for _, id := range ids {
				effect := testEffect()
				effect.ID, effect.OperationID, effect.Payload.Text = adapterapi.EffectID(id), adapterapi.OperationID("op-"+id), id
				effect.Deadline = time.Now().Add(time.Minute).UTC()
				effect.Lane, err = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, 1)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := service.Prepare(ctx, SubmitRequest{Effect: effect, CommandID: "command-" + id, PrincipalID: "principal"})
				if err != nil {
					t.Fatal(err)
				}
				if collected {
					if err := collector.AddPreparedOutbound(prepared.OwnedWork()); err != nil {
						t.Fatal(err)
					}
				} else {
					work.Streams = append(work.Streams, prepared.Work.Streams...)
					work.Operations = append(work.Operations, prepared.Work.Operations...)
					work.Effects = append(work.Effects, prepared.Work.Effects...)
				}
			}
			if collected {
				work, err = collector.UnitOfWork()
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Commit(ctx, work); err != nil {
				t.Fatal(err)
			}
			for _, id := range ids {
				lease, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "worker"})
				if err != nil {
					t.Fatal(err)
				}
				if lease.Effect.EffectID != id {
					t.Fatalf("emission order: claimed %q, want %q", lease.Effect.EffectID, id)
				}
				marked, err := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: id, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{EffectID: id, WorkerID: marked.Effect.LeaseOwner, LeaseEpoch: marked.Effect.LeaseEpoch, AttemptID: marked.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOutboundConversationLanePreservesMessageAndActionFIFO(t *testing.T) {
	for _, group := range []bool{false, true} {
		name, laneKind := "person", "person"
		if group {
			name, laneKind = "group-member-actions", "group"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/mixed-order.db"})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store := eventstore.NewStore(db)
			resolver := testResolver{snap: EndpointSnapshot{
				EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
				Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
				Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage).With(adapterapi.ActionKindEditMessage).With(adapterapi.ActionKindRecallMessage).With(adapterapi.ActionKindKick),
			}}
			service, err := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
			if err != nil {
				t.Fatal(err)
			}
			collector := execution.NewMutationCollector(eventstore.EventFactory{})
			ids := []string{"z-message", "m-action", "a-action"}
			for i, id := range ids {
				effect := testEffect()
				effect.ID, effect.OperationID = adapterapi.EffectID(id), adapterapi.OperationID("op-"+id)
				target := adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "destination"}
				if group {
					target.Kind = adapterapi.TargetGroup
					effect.Payload.Kind = adapterapi.EffectPayloadGroupText
				}
				effect.Payload.Target = target
				if i > 0 {
					effect.Kind = adapterapi.EffectKindAction
					effect.RequiredCapabilities |= adapterapi.CapabilityActions
					if group {
						effect.Payload = adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadKick, Target: target}
						effect.Payload.Target.Member = adapterapi.PrincipalID("member-" + id)
						effect.RequiredAction, effect.Risk = adapterapi.ActionKindKick, adapterapi.EffectRiskHigh
					} else {
						effect.Payload = adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: target, MessageID: "sent-message", Text: "edited"}
						effect.RequiredAction, effect.RetryClass = adapterapi.ActionKindEditMessage, adapterapi.EffectRetryProviderIdempotent
						if i == 2 {
							effect.Payload.Kind, effect.Payload.Text = adapterapi.EffectPayloadRecall, ""
							effect.RequiredAction = adapterapi.ActionKindRecallMessage
						}
					}
				}
				effect.Deadline = time.Now().Add(time.Minute).UTC()
				effect.Lane, err = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, uint64(i+1))
				if err != nil {
					t.Fatal(err)
				}
				if effect.Lane.Key != `["endpoint-1","`+laneKind+`","destination"]` {
					t.Fatalf("effect %s split the conversation lane: %q", id, effect.Lane.Key)
				}
				prepared, err := service.Prepare(ctx, SubmitRequest{Effect: effect, CommandID: "command-" + id, PrincipalID: "principal"})
				if err != nil {
					t.Fatal(err)
				}
				if err := collector.AddPreparedOutbound(prepared.OwnedWork()); err != nil {
					t.Fatal(err)
				}
			}
			work, err := collector.UnitOfWork()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Commit(ctx, work); err != nil {
				t.Fatal(err)
			}
			for i, id := range ids {
				lease, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "worker"})
				if err != nil {
					t.Fatal(err)
				}
				if lease.Effect.EffectID != id || lease.Effect.OrderingSequence != uint64(i+1) {
					t.Fatalf("mixed FIFO claim=%+v want=%q sequence=%d", lease.Effect, id, i+1)
				}
				marked, err := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: id, WorkerID: lease.Effect.LeaseOwner, LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{EffectID: id, WorkerID: marked.Effect.LeaseOwner, LeaseEpoch: marked.Effect.LeaseEpoch, AttemptID: marked.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
