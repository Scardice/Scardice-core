package dice

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestDurableCallbackSNCOCTemplatePersistsAndDoesNotBlockNextMessage(t *testing.T) {
	ctx := context.Background()
	fixture := newEventFixture(t)
	const (
		groupID = "QQ-Group:2002"
		userID  = "QQ:1001"
	)
	withCanonicalTestRoot(t, fixture.dice, "durable-sn-template-seed", func(transaction *DurableCallbackTransaction) error {
		group, err := transaction.Domain().Group(transaction.executionContext, fixture.dice.BaseConfig.Name, groupID)
		if err != nil {
			return err
		}
		for _, command := range []groupstate.Command{
			{Kind: groupstate.CommandCreate, DiceID: fixture.dice.BaseConfig.Name, GroupID: groupID, GroupName: "Template Test Group"},
			{Kind: groupstate.CommandActivation, DiceIDForActivation: fixture.endpoint.UserID, Active: true, Exists: true},
			{Kind: groupstate.CommandExtension, ExtensionID: "log", Enabled: true},
			{Kind: groupstate.CommandSystem, System: "coc7"},
		} {
			if err = group.Decide(command); err != nil {
				return err
			}
		}
		player, err := transaction.Domain().Player(transaction.executionContext, fixture.dice.BaseConfig.Name, groupID, userID)
		if err != nil {
			return err
		}
		return player.Decide(playerstate.PlayerCommand{
			Kind: playerstate.CommandPlayerCreate, DiceID: fixture.dice.BaseConfig.Name,
			GroupID: groupID, UserID: userID, Name: "Tester",
		})
	})

	accept := func(providerEventID, text string, occurredAt time.Time) adapterapi.IngressReceipt {
		t.Helper()
		receipt, err := fixture.enqueue(adapterapi.InboundMessage{
			ProviderEventID:  adapterapi.ProviderEventID(providerEventID),
			MessageID:        adapterapi.MessageID(providerEventID + "-message"),
			Kind:             adapterapi.InboundKindMessage,
			ConversationKind: adapterapi.ConversationKindGroup,
			Platform:         "QQ",
			Sender:           adapterapi.PrincipalID(userID),
			Conversation:     adapterapi.ConversationID(groupID),
			Target:           fixture.endpoint.UserID,
			Text:             text,
			OccurredAt:       occurredAt,
		}, groupstate.State{})
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
			t.Fatalf("ingress receipt = %#v", receipt)
		}
		return receipt
	}
	assertConfirmed := func(inboxID string) {
		t.Helper()
		statuses, err := fixture.store.InboxStatuses(ctx, []string{inboxID})
		if err != nil {
			t.Fatal(err)
		}
		if statuses[inboxID] != eventstore.InboxStatusConfirmedConsumed {
			t.Fatalf("inbox %q status = %q, want %q", inboxID, statuses[inboxID], eventstore.InboxStatusConfirmedConsumed)
		}
	}

	snReceipt := accept("provider-sn-coc", ".sn coc", time.Unix(3, 0).UTC())
	snSummary, err := fixture.callback.ProcessOne(ctx)
	if err != nil {
		t.Fatalf("process .sn coc: %v", err)
	}
	if snSummary.InboxID != snReceipt.InboxID || snSummary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf(".sn coc callback summary = %#v", snSummary)
	}
	assertConfirmed(snReceipt.InboxID)

	persistedPlayer, err := playerstate.ReadProjectedPlayer(ctx, fixture.store, fixture.dice.BaseConfig.Name, groupID, userID)
	if err != nil {
		t.Fatal(err)
	}
	const wantTemplate = "{$t玩家_RAW} SAN{理智} HP{生命值}/{生命值上限} DEX{敏捷}"
	if persistedPlayer.AutoSetNameTemplate != wantTemplate {
		t.Fatalf("persisted AutoSetNameTemplate = %q, want %q", persistedPlayer.AutoSetNameTemplate, wantTemplate)
	}

	rollReceipt := accept("provider-after-sn", ".r 1d1", time.Unix(4, 0).UTC())
	rollSummary, err := fixture.callback.ProcessOne(ctx)
	if err != nil {
		t.Fatalf("process command after .sn coc: %v", err)
	}
	if rollSummary.InboxID != rollReceipt.InboxID || rollSummary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("post-.sn callback summary = %#v", rollSummary)
	}
	assertConfirmed(rollReceipt.InboxID)
}
