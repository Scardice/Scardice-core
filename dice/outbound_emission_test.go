package dice

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

func repairTestStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite", DSN: t.TempDir() + "/repair.db",
		DatabaseIdentity: "repair",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	options := projectionset.StoreOptions()
	store := eventstore.NewStore(db, options...)
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "repair", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	return store, db
}

func TestDurableBridgeRepeatedTextIsTwoEmissions(t *testing.T) {
	for _, callback := range []bool{false, true} {
		name := "standalone"
		if callback {
			name = "callback"
		}
		t.Run(name, func(t *testing.T) {
			d, store := newCanonicalTestDice(t)
			endpoint := newCanonicalTestEndpoint(d, "QQ:100000")
			msg := &Message{
				MessageType: "private", Platform: "QQ",
				Sender: SenderBase{UserID: "QQ:1001", Nickname: "Sender"},
			}
			resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
				EndpointID: adapterapi.EndpointID(endpoint.ID), DesiredState: "enabled",
				ObservedState: adapterapi.ObservedStateConnected,
				Capabilities:  adapterapi.CapabilityOutbound,
				Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage),
			}}
			ids := &canonicalFixtureIDs{prefix: canonicalFixtureLabel(t, "repeated-outbound")}
			service, err := messageflow.NewOutboundService(store, resolver, ids)
			if err != nil {
				t.Fatal(err)
			}
			d.OutboundBridge = NewDurableOutboundBridge(service, resolver, ids, newBridgeTestNotificationOwner(t))
			submitTwice := func(ctx *MsgContext) error {
				for range 2 {
					if err := d.OutboundBridge.SubmitText(ctx, msg, "same reply", "", false); err != nil {
						return err
					}
				}
				return nil
			}
			if callback {
				withCanonicalTestMessageContext(t, d, endpoint, msg, "repeated-callback-outbound", submitTwice)
			} else {
				standalone := newCanonicalTestMessageContext(t, d, endpoint, msg, "repeated-standalone-outbound")
				standalone.callbackTransaction = nil
				if err := submitTwice(standalone); err != nil {
					t.Fatal(err)
				}
			}

			seen := map[string]struct{}{}
			for range 2 {
				lease, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{
					WorkerID: "repeated-outbound-worker", LeaseDuration: time.Minute,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, duplicate := seen[lease.Effect.EffectID]; duplicate {
					t.Fatalf("identical replies reused effect ID %q", lease.Effect.EffectID)
				}
				seen[lease.Effect.EffectID] = struct{}{}
				dispatched, err := store.MarkOutboxDispatched(context.Background(), eventstore.OutboxDispatchRequest{
					EffectID: lease.Effect.EffectID, WorkerID: lease.Effect.LeaseOwner,
					LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = store.CompleteOutbox(context.Background(), eventstore.OutboxCompletionRequest{
					EffectID: dispatched.Effect.EffectID, WorkerID: dispatched.Effect.LeaseOwner,
					LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID,
					Status: eventstore.OutboxStatusSucceeded, ResultCode: "success",
					ProviderMessageID: "provider-" + dispatched.Effect.EffectID,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if hasMore, err := store.HasOutboxWork(context.Background()); err != nil {
				t.Fatal(err)
			} else if hasMore {
				t.Fatal("identical reply invocations produced more than two effects")
			}
		})
	}
}
