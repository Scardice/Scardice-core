package messageflow

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/core/privacypurge"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestSQLiteMessageFlowThroughScopedPrivacyPurge(t *testing.T) {
	ctx := context.Background()
	db, databaseErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "privacy-purge-scenario.db"), DatabaseIdentity: "privacy-purge-scenario"})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithProjection(groupstate.GroupProjection()),
		eventstore.WithProjection(playerstate.PlayerProjection()),
		eventstore.WithProjection(playerstate.GroupUserAttrsProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "privacy-purge-scenario", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	inbound, databaseErr := NewInboundService(store, WithIngressClock(fixedIngressClock{now: now}))
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	message := adapterapi.InboundMessage{ProviderEventID: "provider-message-1", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "test", Sender: "user", Conversation: "group", Target: "group", Text: "hello group"}
	fenced := endpoint.FencedInbound{EndpointID: "endpoint-1", Generation: 1, DesiredVersion: 1, Message: message}
	first, databaseErr := inbound.HandleInbound(ctx, fenced)
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	duplicate, databaseErr := inbound.HandleInbound(ctx, fenced)
	if databaseErr != nil || duplicate.Outcome != adapterapi.IngressDuplicate || duplicate.InboxID != first.InboxID {
		t.Fatalf("duplicate=%+v err=%v", duplicate, databaseErr)
	}
	host := &callbackTestHost{fn: func(_ context.Context, request CallbackRequest, _ *playerstate.LocalOverlay, collector *execution.MutationCollector) (CallbackResult, error) {
		metadata := eventstore.Metadata{EventID: "scenario-group-created", CommandID: "scenario-command", CorrelationID: "scenario-correlation", OccurredAtUnixNanoUTC: 101, OccurredAtUnixNanoSet: true}
		if err := collector.AddGroupEvents(groupstate.GroupStream(request.Scope.DiceID, request.Scope.GroupID), 0, metadata, []groupstate.TypedEvent{
			groupstate.NewGroupCreatedV1(request.Scope.DiceID, request.Scope.GroupID, "Scenario Group", 101),
			groupstate.NewGroupActivationChangedV1(request.Scope.DiceID, true, true),
			groupstate.NewGroupExtensionChangedV1("extension-1", true),
		}); err != nil {
			return CallbackResult{}, err
		}
		playerMetadata := metadata
		playerMetadata.EventID = "scenario-player-created"
		if err := collector.AddPlayerEvents(playerstate.PlayerStream(request.Scope.DiceID, request.Scope.GroupID, request.Scope.UserID), 0, playerMetadata, []playerstate.PlayerEvent{
			playerstate.NewPlayerCreatedV1(request.Scope.DiceID, request.Scope.GroupID, request.Scope.UserID, "Player"),
			playerstate.NewPlayerNameChangedV1("Player One"),
		}); err != nil {
			return CallbackResult{}, err
		}
		attrsMetadata := metadata
		attrsMetadata.EventID = "scenario-attrs-created"
		if err := collector.AddGroupUserAttrsEvents(playerstate.GroupUserAttrsStream(request.Scope.DiceID, request.Scope.GroupID, request.Scope.UserID), 0, attrsMetadata, []playerstate.GroupUserAttrsEvent{
			playerstate.NewGroupUserAttrsCreatedV1(request.Scope.DiceID, request.Scope.GroupID, request.Scope.UserID),
			playerstate.NewGroupUserAttrsSetV1("role", []byte("plain-role-value")),
		}); err != nil {
			return CallbackResult{}, err
		}
		return CallbackResult{}, nil
	}}
	callback, databaseErr := NewCallbackService(CallbackConfig{Inbox: store, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "scenario-worker", Clock: fixedIngressClock{now: now}})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if summary, err := callback.ProcessOne(ctx); err != nil || summary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("callback summary=%+v err=%v", summary, err)
	}

	group, databaseErr := groupstate.ReadProjected(ctx, store, "dice", "group")
	if databaseErr != nil || !group.Active || !group.DiceIDExists["dice"] || len(group.ActivatedExtensions) != 1 || group.ActivatedExtensions[0] != "extension-1" {
		t.Fatalf("group=%+v err=%v", group, databaseErr)
	}
	player, databaseErr := playerstate.ReadProjectedPlayer(ctx, store, "dice", "group", "user")
	if databaseErr != nil || player.Name != "Player One" {
		t.Fatalf("player=%+v err=%v", player, databaseErr)
	}
	attrs, databaseErr := playerstate.ReadProjectedGroupUserAttrs(ctx, store, "dice", "group", "user")
	if databaseErr != nil || len(attrs.Values) != 1 || string(attrs.Values["role"]) != "plain-role-value" {
		t.Fatalf("attrs=%+v err=%v", attrs, databaseErr)
	}
	var inboxBody struct {
		Payload []byte
		Subject string
		Status  string
	}
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", first.InboxID).First(&inboxBody).Error; err != nil {
		t.Fatal(err)
	}
	var retained ingressPayload
	if err := json.Unmarshal(inboxBody.Payload, &retained); err != nil || retained.Message.Text != "hello group" || inboxBody.Subject != "group" || inboxBody.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("terminal callback lost its plaintext body or subject: row=%+v payload=%+v err=%v", inboxBody, retained, err)
	}

	resolver := testResolver{snap: EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages | adapterapi.CapabilityArtifacts, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)}}
	outbound, databaseErr := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	for i := range 2 {
		effect := testEffect()
		effect.ID = adapterapi.EffectID("scenario-effect-" + string(rune('1'+i)))
		effect.OperationID = adapterapi.OperationID("scenario-operation-" + string(rune('1'+i)))
		effect.CorrelationID = adapterapi.CorrelationID("scenario-correlation-" + string(rune('1'+i)))
		effect.CausationID = adapterapi.CausationID("scenario-causation-" + string(rune('1'+i)))
		effect.Deadline = time.Now().Add(time.Minute).UTC()
		effect.Lane, databaseErr = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, uint64(i+1))
		if databaseErr != nil {
			t.Fatal(databaseErr)
		}
		result, err := outbound.Submit(ctx, SubmitRequest{Effect: effect, CommandID: "scenario-command-" + string(rune('1'+i)), PrincipalID: "scenario-principal"})
		if err != nil || result.EffectID != string(effect.ID) {
			t.Fatalf("ordered submit=%+v err=%v", result, err)
		}
		if i == 0 {
			lease, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "scenario-dispatcher", LeaseDuration: time.Minute})
			if err != nil || lease.Effect.EffectID != string(effect.ID) || lease.Effect.OrderingSequence != 1 {
				t.Fatalf("first ordered claim=%+v err=%v", lease, err)
			}
			dispatched, err := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: string(effect.ID), WorkerID: "scenario-dispatcher", LeaseEpoch: lease.Effect.LeaseEpoch, AttemptID: lease.Effect.AttemptID})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{EffectID: string(effect.ID), WorkerID: "scenario-dispatcher", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded, ResultCode: "sent"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	second, databaseErr := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "scenario-dispatcher", LeaseDuration: time.Minute})
	if databaseErr != nil || second.Effect.OrderingSequence != 2 {
		t.Fatalf("second ordered claim=%+v err=%v", second, databaseErr)
	}
	dispatched, databaseErr := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: second.Effect.EffectID, WorkerID: "scenario-dispatcher", LeaseEpoch: second.Effect.LeaseEpoch, AttemptID: second.Effect.AttemptID})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{EffectID: second.Effect.EffectID, WorkerID: "scenario-dispatcher", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded, ResultCode: "sent"}); err != nil {
		t.Fatal(err)
	}

	// Both retained terminal and still-pending ingress rows belong to the group.
	// A different group's plaintext queue must survive the same transaction.
	groupPending := fenced
	groupPending.Message.ProviderEventID = "provider-group-pending"
	if _, err := inbound.HandleInbound(ctx, groupPending); err != nil {
		t.Fatal(err)
	}
	unrelatedPending := fenced
	unrelatedPending.Message.ProviderEventID = "provider-unrelated-pending"
	unrelatedPending.Message.Conversation = "other-group"
	unrelatedPending.Message.Target = "other-group"
	if _, err := inbound.HandleInbound(ctx, unrelatedPending); err != nil {
		t.Fatal(err)
	}
	groupEffect := testEffect()
	groupEffect.ID, groupEffect.OperationID = "scenario-group-pending", "scenario-group-operation"
	groupEffect.Deadline = time.Now().Add(time.Minute).UTC()
	groupEffect.Payload.Kind = adapterapi.EffectPayloadGroupText
	groupEffect.Payload.Target = adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "group"}
	groupEffect.Lane, databaseErr = adapterapi.NewLaneMetadata(groupEffect.EndpointID, groupEffect.Payload.Target, 1)
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if _, err := outbound.Submit(ctx, SubmitRequest{Effect: groupEffect, CommandID: "scenario-group-pending", PrincipalID: "scenario-principal"}); err != nil {
		t.Fatal(err)
	}

	var beforeControl struct {
		ActiveGeneration string `gorm:"column:active_generation"`
	}
	if err := db.GORM().Table("projection_control").Where("singleton_id = ?", "default").First(&beforeControl).Error; err != nil {
		t.Fatal(err)
	}
	beforeDigest, databaseErr := store.DigestProjection(ctx, beforeControl.ActiveGeneration)
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	rebuilt, databaseErr := store.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: "v1"})
	if databaseErr != nil || rebuilt.Digest != beforeDigest {
		t.Fatalf("rebuild=%+v err=%v before=%s", rebuilt, databaseErr, beforeDigest)
	}

	purge := privacypurge.NewService(store)
	dry, databaseErr := purge.DryRun(ctx, privacypurge.Request{GroupID: "group", DiceIDs: []string{"dice"}, Scopes: []string{"group_record", "players", "attrs"}, ActiveDiceIDs: []string{"dice"}, AllowActive: true})
	if databaseErr != nil {
		t.Fatal(databaseErr)
	}
	if dry.Counts.Inbox != 2 || dry.Counts.Outbox != 1 {
		t.Fatalf("dry-run queue counts=%+v", dry.Counts)
	}
	result, databaseErr := purge.Confirm(ctx, privacypurge.Request{GroupID: "group", DiceIDs: []string{"dice"}, Scopes: []string{"group_record", "players", "attrs"}, ActiveDiceIDs: []string{"dice"}, AllowActive: true, ConfirmationDigest: dry.ConfirmationDigest, ConfirmationVersion: dry.ConfirmationVersion})
	if !errors.Is(databaseErr, privacypurge.ErrUncoveredData) || !result.Completed || result.Deleted.GroupRecord != 3 || result.Deleted.Players != 2 || result.Deleted.Attrs != 2 || result.Deleted.Inbox != 2 || result.Deleted.Outbox != 1 {
		t.Fatalf("purge result=%+v err=%v", result, databaseErr)
	}
	var unrelatedEffects []struct {
		EffectID   string
		Status     string
		Subject    string
		ResultCode string
		Payload    []byte
	}
	effectIDs := []string{"scenario-effect-1", "scenario-effect-2"}
	if err := db.GORM().Table("outbox_effects").Where("effect_id IN ?", effectIDs).Find(&unrelatedEffects).Error; err != nil {
		t.Fatal(err)
	}
	if len(unrelatedEffects) != 2 {
		t.Fatalf("unrelated effects=%d want=2", len(unrelatedEffects))
	}
	for _, effect := range unrelatedEffects {
		if effect.Status != eventstore.OutboxStatusSucceeded || effect.ResultCode != "sent" || effect.Subject != "person-1" {
			t.Fatalf("unrelated effect was purged or changed: %+v", effect)
		}
		var wire effectWire
		if err := json.Unmarshal(effect.Payload, &wire); err != nil || wire.Effect.Payload.Text != "hello" {
			t.Fatalf("terminal unrelated effect lost its plaintext payload: %s err=%v", effect.EffectID, err)
		}
	}
	var unrelatedOutbox, unrelatedInbox int64
	if err := db.GORM().Table("outbox_effects").Where("subject <> ?", "group").Count(&unrelatedOutbox).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Table("inbox_messages").Where("subject <> ?", "group").Count(&unrelatedInbox).Error; err != nil {
		t.Fatal(err)
	}
	if unrelatedOutbox != 2 || unrelatedInbox != 1 {
		t.Fatalf("unrelated scope counts outbox=%d inbox=%d", unrelatedOutbox, unrelatedInbox)
	}
	for _, table := range []string{"inbox_messages", "outbox_effects"} {
		var remaining int64
		if err := db.GORM().Table(table).Where("subject = ?", "group").Count(&remaining).Error; err != nil {
			t.Fatal(err)
		}
		if remaining != 0 {
			t.Fatalf("%s still contains %d group rows after completed purge", table, remaining)
		}
	}
	if _, err := groupstate.ReadProjected(ctx, store, "dice", "group"); err == nil {
		t.Fatal("purged group remained readable")
	}
	rowKeys := []string{groupstate.GroupStream("dice", "group").AggregateID, playerstate.PlayerStream("dice", "group", "user").AggregateID, playerstate.GroupUserAttrsStream("dice", "group", "user").AggregateID}
	var heads, projections int64
	if err := db.GORM().Table("aggregate_heads").Where("aggregate_id IN ?", rowKeys).Count(&heads).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Table("projection_read_models").Where("row_key IN ?", rowKeys).Count(&projections).Error; err != nil {
		t.Fatal(err)
	}
	if heads != 0 || projections != 0 {
		t.Fatalf("raw purge rows heads=%d projections=%d", heads, projections)
	}
	if _, err := playerstate.ReadProjectedPlayer(ctx, store, "dice", "group", "user"); err == nil {
		t.Fatal("purged player remained readable")
	}
	if _, err := playerstate.ReadProjectedGroupUserAttrs(ctx, store, "dice", "group", "user"); err == nil {
		t.Fatal("purged attrs remained readable")
	}
}
