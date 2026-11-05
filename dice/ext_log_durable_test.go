package dice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
)

type groupCardSQLiteResolver struct{ snapshot messageflow.EndpointSnapshot }

func (r groupCardSQLiteResolver) Resolve(context.Context, adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	return r.snapshot, nil
}

func newGroupCardCanonicalFixture(t *testing.T) (*Dice, *eventstore.GORMStore, *EndPointInfo, *Message) {
	t.Helper()
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	endpoint.ID = "endpoint-card-test"
	endpoint.Adapter = nil
	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(endpoint.ID), AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSetGroupCard),
	}}
	ids := &canonicalFixtureIDs{prefix: canonicalFixtureLabel(t, "group-card-outbound")}
	service, err := messageflow.NewOutboundService(store, resolver, ids)
	if err != nil {
		t.Fatal(err)
	}
	d.OutboundBridge = NewDurableOutboundBridge(service, resolver, ids, newBridgeTestNotificationOwner(t))
	msg := newGroupMsg("QQ-Group:2002", "QQ:1001", "")
	msg.Sender.Nickname = "Alice"
	return d, store, endpoint, msg
}

func groupCardSQLiteRowCounts(t *testing.T, db *eventstore.Database) (int64, int64, int64) {
	t.Helper()
	var events, operations, effects int64
	for _, item := range []struct {
		table string
		count *int64
	}{{"domain_events", &events}, {"operations", &operations}, {"outbox_effects", &effects}} {
		if err := db.GORM().Table(item.table).Count(item.count).Error; err != nil {
			t.Fatal(err)
		}
	}
	return events, operations, effects
}

func assertPersistedGroupCard(t *testing.T, store *eventstore.GORMStore, wantCard string) {
	t.Helper()
	lease, err := store.ClaimOutbox(context.Background(), eventstore.OutboxClaimRequest{
		WorkerID: "group-card-assertion", LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := lease.Effect
	var wire struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}
	if err := json.Unmarshal(pending.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	payload := wire.Effect.Payload
	if wire.Effect.Kind != adapterapi.EffectKindAction || payload.Kind != adapterapi.EffectPayloadSetGroupCard || payload.Target.Kind != adapterapi.TargetGroup || payload.Target.Conversation != "QQ-Group:2002" || payload.Target.Member != "QQ:1001" || payload.Card != wantCard {
		t.Fatalf("persisted card effect = %#v", wire.Effect)
	}
}

func TestSetPlayerGroupCardByTemplatePersistsDurableActionWithoutAdapter(t *testing.T) {
	for _, test := range []struct {
		name, template, card string
	}{
		{name: "evaluated card", template: "Card {1+1}", card: "Card 2"},
		{name: "clear card", template: "", card: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, store, endpoint, msg := newGroupCardCanonicalFixture(t)
			if endpoint.Adapter != nil {
				t.Fatal("fixture must model the adapter-free event-sourced endpoint")
			}
			var text string
			withCanonicalTestMessageContext(t, d, endpoint, msg, "persist-group-card", func(ctx *MsgContext) (err error) {
				ctx.SystemTemplate = &GameSystemTemplate{}
				text, err = SetPlayerGroupCardByTemplate(ctx, test.template)
				return err
			})
			if text != test.card {
				t.Fatalf("SetPlayerGroupCardByTemplate() = %q, want %q", text, test.card)
			}
			assertPersistedGroupCard(t, store, test.card)
		})
	}
}

func TestSetPlayerGroupCardByTemplateStagesCallbackActionWithoutPublishing(t *testing.T) {
	d, store, endpoint, msg := newGroupCardCanonicalFixture(t)
	ctx := newCanonicalTestMessageContext(t, d, endpoint, msg, "stage-group-card")
	ctx.SystemTemplate = &GameSystemTemplate{}
	text, err := SetPlayerGroupCardByTemplate(ctx, "Card {1+1}")
	if err != nil || text != "Card 2" {
		t.Fatalf("SetPlayerGroupCardByTemplate() = %q, %v", text, err)
	}
	if pending, lookupErr := store.HasOutboxWork(context.Background()); lookupErr != nil || pending {
		t.Fatalf("callback published before root commit: pending=%t err=%v", pending, lookupErr)
	}
	if err = ctx.callbackTransaction.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := ctx.callbackTransaction.collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 1 || len(work.Effects) != 1 {
		t.Fatalf("prepared callback action participants = operations:%d effects:%d", len(work.Operations), len(work.Effects))
	}
}

func TestSetPlayerGroupCardByTemplateUsesCardInCallbackIdentity(t *testing.T) {
	d, _, endpoint, msg := newGroupCardCanonicalFixture(t)
	ctx := newCanonicalTestMessageContext(t, d, endpoint, msg, "distinct-group-cards")
	ctx.SystemTemplate = &GameSystemTemplate{}
	for _, card := range []string{"First card", "Second card"} {
		if text, err := SetPlayerGroupCardByTemplate(ctx, card); err != nil || text != card {
			t.Fatalf("SetPlayerGroupCardByTemplate(%q) = %q, %v", card, text, err)
		}
	}
	if err := ctx.callbackTransaction.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
	work, err := ctx.callbackTransaction.collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 2 || len(work.Effects) != 2 ||
		work.Operations[0].OperationID == work.Operations[1].OperationID ||
		work.Effects[0].EffectID == work.Effects[1].EffectID {
		t.Fatalf("prepared callback actions = %#v", work)
	}
}

func TestSetPlayerGroupCardByTemplateCallbackFailureLeavesNoIntent(t *testing.T) {
	d, store, endpoint, msg := newGroupCardCanonicalFixture(t)
	failure := errors.New("reject group card callback")
	identity := d.DomainExecutionIdentity("test-fixture", canonicalFixtureLabel(t, "failed-group-card"))
	err := d.WithDomainExecution(context.Background(), identity, []byte("failed-group-card"), func(transaction *DurableCallbackTransaction) error {
		ctx, buildErr := NewDomainMsgContext(transaction, d, d.ImSession, endpoint, msg)
		if buildErr != nil {
			return buildErr
		}
		defer ctx.releaseExecutionState()
		ctx.SystemTemplate = &GameSystemTemplate{}
		if _, cardErr := SetPlayerGroupCardByTemplate(ctx, "Card {1+1}"); cardErr != nil {
			return cardErr
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("callback error = %v, want %v", err, failure)
	}
	if pending, lookupErr := store.HasOutboxWork(context.Background()); lookupErr != nil || pending {
		t.Fatalf("failed callback left durable outbound intent: pending=%t err=%v", pending, lookupErr)
	}
}

func TestSetPlayerGroupCardByTemplateRejectsInvalidAndOverlongBeforeSubmitting(t *testing.T) {
	for _, test := range []struct {
		name string
		tmpl string
	}{
		{name: "invalid template", tmpl: "{1 + }"},
		{name: "QQ card over limit", tmpl: strings.Repeat("x", 60)},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, store, endpoint, msg := newGroupCardCanonicalFixture(t)
			ctx := newCanonicalTestMessageContext(t, d, endpoint, msg, "reject-group-card")
			ctx.SystemTemplate = &GameSystemTemplate{}
			if _, err := SetPlayerGroupCardByTemplate(ctx, test.tmpl); err == nil {
				t.Fatal("invalid or overlong template unexpectedly succeeded")
			}
			if pending, lookupErr := store.HasOutboxWork(context.Background()); lookupErr != nil || pending {
				t.Fatalf("rejected template left durable outbound intent: pending=%t err=%v", pending, lookupErr)
			}
			work, err := ctx.callbackTransaction.collector.UnitOfWork()
			if err != nil {
				t.Fatal(err)
			}
			if len(work.Operations) != 0 || len(work.Effects) != 0 {
				t.Fatalf("rejected template staged outbound work: %#v", work)
			}
		})
	}
}
