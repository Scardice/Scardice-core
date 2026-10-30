package dice

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
)

func repairTestStore(t *testing.T) (*eventstore.GORMStore, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/repair.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := eventstore.NewStore(db, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "repair", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
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
			store, db := repairTestStore(t)
			ctx, msg, _ := bridgeTestContext(&bridgeTestSubmitter{})
			resolver := bridgeTestResolver{snapshot: messageflow.EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-v1", IndexSigner: store}}
			service, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
			if err != nil {
				t.Fatal(err)
			}
			ctx.Dice.OutboundBridge = NewDurableOutboundBridge(service, resolver, eventstore.UUIDGenerator{})
			collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
			if callback {
				ctx.callbackTransaction = &DurableCallbackTransaction{collector: collector}
			}
			for range 2 {
				if err := ctx.Dice.OutboundBridge.SubmitText(ctx, msg, "same reply", "", false); err != nil {
					t.Fatal(err)
				}
			}
			if callback {
				work, err := collector.UnitOfWork()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Commit(context.Background(), work); err != nil {
					t.Fatalf("two identical replies rolled back callback: %v", err)
				}
			}
			var count int64
			if err := db.GORM().Table("outbox_effects").Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatalf("identical reply invocations produced %d effects, want 2", count)
			}
		})
	}
}
