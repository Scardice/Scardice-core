package messageflow

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
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
			source := defaultIntegrationKeySource()
			store := eventstore.NewStore(db, eventstore.WithKeySource(source))
			if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
				t.Fatal(err)
			}
			service, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-v1", IndexSigner: store}}, store, eventstore.UUIDGenerator{})
			if err != nil {
				t.Fatal(err)
			}
			collector := NewMutationCollector(eventstore.EventFactory{})
			work := eventstore.UnitOfWork{}
			ids := []string{"z-first", "m-second", "a-third"}
			root, _ := source.IndexRootMaterial(ctx)
			for _, id := range ids {
				effect := testEffect()
				effect.ID, effect.OperationID, effect.Payload.Text = adapterapi.EffectID(id), adapterapi.OperationID("op-"+id), id
				effect.Deadline = time.Now().Add(time.Minute).UTC()
				effect.Lane, err = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := service.Prepare(ctx, SubmitRequest{Effect: effect, CommandID: "command-" + id, PrincipalID: "principal"})
				if err != nil {
					t.Fatal(err)
				}
				if collected {
					if err := collector.AddPreparedOutbound(prepared); err != nil {
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
