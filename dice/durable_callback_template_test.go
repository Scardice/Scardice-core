package dice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestDurableCallbackSNCOCTemplatePersistsAndDoesNotBlockNextMessage(t *testing.T) {
	ctx := context.Background()
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	keys := groupCardSQLiteKeySource{}
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type:             "sqlite",
		DSN:              filepath.Join(t.TempDir(), "durable-sn-template.db"),
		KeySource:        keys,
		DatabaseIdentity: "durable-sn-template-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "durable-sn-template-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d.DurableStore = store

	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(endpoint.ID), AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSetGroupCard),
		IndexRootID:  "card-index-v1", IndexSigner: groupCardSQLiteIndexSigner{},
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	d.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})

	const (
		groupID = "QQ-Group:2002"
		userID  = "QQ:1001"
	)
	seedMetadata := eventstore.Metadata{
		CommandID: "seed-durable-sn", CorrelationID: "seed-durable-sn",
		OccurredAt: time.Unix(2, 0).UTC(),
	}
	groupRepository := groupstate.NewRepository(store)
	if _, err := groupRepository.AppendTyped(ctx, d.BaseConfig.Name, groupID, 0, seedMetadata, []groupstate.TypedEvent{
		groupstate.NewGroupCreatedV1(d.BaseConfig.Name, groupID, "Template Test Group", 2),
		groupstate.NewGroupActivationChangedV1(endpoint.UserID, true, true),
		groupstate.NewGroupExtensionChangedV1("log", true),
		groupstate.NewGroupSystemChangedV1("coc7"),
	}); err != nil {
		t.Fatal(err)
	}
	playerRepository := playerstate.NewRepository(store)
	if _, err := playerRepository.AppendPlayerTyped(ctx, d.BaseConfig.Name, groupID, userID, 0, seedMetadata, []playerstate.PlayerEvent{
		playerstate.NewPlayerCreatedV1(d.BaseConfig.Name, groupID, userID, "Tester"),
	}); err != nil {
		t.Fatal(err)
	}

	inbound, err := messageflow.NewInboundService(store, store)
	if err != nil {
		t.Fatal(err)
	}
	callback, err := messageflow.NewCallbackService(messageflow.CallbackConfig{
		Inbox: store, Store: store, BoundCodec: store,
		Resolver: NewDurableCallbackScopeResolver(d),
		Group:    groupRepository, Player: playerRepository,
		Host: NewDurableCallbackHost(d), WorkerID: "durable-sn-template-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	accept := func(providerEventID, text string, occurredAt time.Time) adapterapi.IngressReceipt {
		t.Helper()
		receipt, acceptErr := inbound.HandleInbound(ctx, endpointcore.FencedInbound{
			EndpointID: adapterapi.EndpointID(endpoint.ID), Generation: 1, DesiredVersion: 1,
			Message: adapterapi.InboundMessage{
				ProviderEventID:  adapterapi.ProviderEventID(providerEventID),
				MessageID:        adapterapi.MessageID(providerEventID + "-message"),
				Kind:             adapterapi.InboundKindMessage,
				ConversationKind: adapterapi.ConversationKindGroup,
				Platform:         "QQ", Sender: adapterapi.PrincipalID(userID),
				Conversation: adapterapi.ConversationID(groupID), Target: endpoint.UserID,
				Text: text, OccurredAt: occurredAt,
			},
		})
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
			t.Fatalf("ingress receipt = %#v", receipt)
		}
		return receipt
	}
	assertConfirmed := func(inboxID string) {
		t.Helper()
		var row struct {
			Status string `gorm:"column:status"`
		}
		if err := database.GORM().Table("inbox_messages").Where("inbox_id = ?", inboxID).Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.Status != eventstore.InboxStatusConfirmedConsumed {
			t.Fatalf("inbox %q status = %q, want %q", inboxID, row.Status, eventstore.InboxStatusConfirmedConsumed)
		}
	}

	snReceipt := accept("provider-sn-coc", ".sn coc", time.Unix(3, 0).UTC())
	snSummary, err := callback.ProcessOne(ctx)
	if err != nil {
		t.Fatalf("process .sn coc: %v", err)
	}
	if snSummary.InboxID != snReceipt.InboxID || snSummary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf(".sn coc callback summary = %#v", snSummary)
	}
	assertConfirmed(snReceipt.InboxID)

	persistedPlayer, err := playerRepository.LoadPlayer(ctx, d.BaseConfig.Name, groupID, userID)
	if err != nil {
		t.Fatal(err)
	}
	const wantTemplate = "{$t玩家_RAW} SAN{理智} HP{生命值}/{生命值上限} DEX{敏捷}"
	if persistedPlayer.AutoSetNameTemplate != wantTemplate {
		t.Fatalf("persisted AutoSetNameTemplate = %q, want %q", persistedPlayer.AutoSetNameTemplate, wantTemplate)
	}

	rollReceipt := accept("provider-after-sn", ".r 1d1", time.Unix(4, 0).UTC())
	rollSummary, err := callback.ProcessOne(ctx)
	if err != nil {
		t.Fatalf("process command after .sn coc: %v", err)
	}
	if rollSummary.InboxID != rollReceipt.InboxID || rollSummary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("post-.sn callback summary = %#v", rollSummary)
	}
	assertConfirmed(rollReceipt.InboxID)
}
