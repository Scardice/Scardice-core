package messageflow

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/core/privacypurge"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestTask7SQLiteMessageFlowScenarioThroughScopedPurge(t *testing.T) {
	ctx := context.Background()
	source := integrationKeySource{indexID: "task7-index", index: []byte("01234567890123456789012345678901"), rootID: "task7-root", root: []byte("abcdefghijklmnopqrstuvwxyz123456")}
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task7-scenario.db"), KeySource: source, DatabaseIdentity: "task7-scenario"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := eventstore.NewStore(db,
		eventstore.WithProjection(groupstate.GroupProjection()),
		eventstore.WithProjection(playerstate.PlayerProjection()),
		eventstore.WithProjection(playerstate.GroupUserAttrsProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "task7-scenario", IndexRootID: source.indexID, EncryptionRootIDs: []string{source.rootID}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	inbound, err := NewInboundService(store, store, WithIngressClock(fixedIngressClock{now: now}))
	if err != nil {
		t.Fatal(err)
	}
	message := adapterapi.InboundMessage{ProviderEventID: "provider-message-1", Kind: adapterapi.InboundKindMessage, Platform: "test", Sender: "user", Conversation: "group", Target: "group", Text: "hello group"}
	fenced := endpoint.FencedInbound{EndpointID: "endpoint-1", Generation: 1, DesiredVersion: 1, Message: message}
	first, err := inbound.HandleInbound(ctx, fenced)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := inbound.HandleInbound(ctx, fenced)
	if err != nil || duplicate.Outcome != adapterapi.IngressDuplicate || duplicate.InboxID != first.InboxID {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	host := &callbackTestHost{fn: func(_ context.Context, request CallbackRequest, _ *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
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
			playerstate.NewGroupUserAttrsSetV1("role", []byte("encrypted-role"), source.rootID),
		}); err != nil {
			return CallbackResult{}, err
		}
		return CallbackResult{}, nil
	}}
	callback, err := NewCallbackService(CallbackConfig{Inbox: store, Store: store, BoundCodec: store, Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{}, Host: host, WorkerID: "scenario-worker", Clock: fixedIngressClock{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := callback.ProcessOne(ctx); err != nil || summary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("callback summary=%+v err=%v", summary, err)
	}

	group, err := groupstate.ReadProjected(ctx, store, "dice", "group")
	if err != nil || !group.Active || !group.DiceIDExists["dice"] || len(group.ActivatedExtensions) != 1 || group.ActivatedExtensions[0] != "extension-1" {
		t.Fatalf("group=%+v err=%v", group, err)
	}
	player, err := playerstate.ReadProjectedPlayer(ctx, store, "dice", "group", "user")
	if err != nil || player.Name != "Player One" {
		t.Fatalf("player=%+v err=%v", player, err)
	}
	attrs, err := playerstate.ReadProjectedGroupUserAttrs(ctx, store, "dice", "group", "user")
	if err != nil || len(attrs.Values) != 1 || string(attrs.Values["role"].Ciphertext) != "encrypted-role" {
		t.Fatalf("attrs=%+v err=%v", attrs, err)
	}
	var inboxBody struct {
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		SubjectKey        []byte `gorm:"column:subject_key"`
	}
	if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", first.InboxID).First(&inboxBody).Error; err != nil {
		t.Fatal(err)
	}
	groupSubjectKey := append([]byte(nil), inboxBody.SubjectKey...)
	if len(inboxBody.PayloadCiphertext) != 0 || len(inboxBody.PayloadNonce) != 0 {
		t.Fatal("terminal callback retained encrypted body")
	}

	resolver := testResolver{snap: EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages | adapterapi.CapabilityArtifacts, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: source.indexID, IndexSigner: store}}
	outbound, err := NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		effect := testEffect()
		effect.ID = adapterapi.EffectID("scenario-effect-" + string(rune('1'+i)))
		effect.OperationID = adapterapi.OperationID("scenario-operation-" + string(rune('1'+i)))
		effect.CorrelationID = adapterapi.CorrelationID("scenario-correlation-" + string(rune('1'+i)))
		effect.CausationID = adapterapi.CausationID("scenario-causation-" + string(rune('1'+i)))
		effect.Deadline = time.Now().Add(time.Minute).UTC()
		effect.Lane, err = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, source.index, uint64(i+1))
		if err != nil {
			t.Fatal(err)
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
	second, err := store.ClaimOutbox(ctx, eventstore.OutboxClaimRequest{WorkerID: "scenario-dispatcher", LeaseDuration: time.Minute})
	if err != nil || second.Effect.OrderingSequence != 2 {
		t.Fatalf("second ordered claim=%+v err=%v", second, err)
	}
	dispatched, err := store.MarkOutboxDispatched(ctx, eventstore.OutboxDispatchRequest{EffectID: second.Effect.EffectID, WorkerID: "scenario-dispatcher", LeaseEpoch: second.Effect.LeaseEpoch, AttemptID: second.Effect.AttemptID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteOutbox(ctx, eventstore.OutboxCompletionRequest{EffectID: second.Effect.EffectID, WorkerID: "scenario-dispatcher", LeaseEpoch: dispatched.Effect.LeaseEpoch, AttemptID: dispatched.Effect.AttemptID, Status: eventstore.OutboxStatusSucceeded, ResultCode: "sent"}); err != nil {
		t.Fatal(err)
	}

	var beforeControl struct {
		ActiveGeneration string `gorm:"column:active_generation"`
	}
	if err := db.GORM().Table("projection_control").Where("singleton_id = ?", "default").First(&beforeControl).Error; err != nil {
		t.Fatal(err)
	}
	beforeDigest, err := store.DigestProjection(ctx, beforeControl.ActiveGeneration)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := store.Rebuild(ctx, eventstore.RebuildRequest{ProjectorVersion: "v1"})
	if err != nil || rebuilt.Digest != beforeDigest {
		t.Fatalf("rebuild=%+v err=%v before=%s", rebuilt, err, beforeDigest)
	}

	purge := privacypurge.NewService(store)
	dry, err := purge.DryRun(ctx, privacypurge.Request{GroupID: "group", DiceIDs: []string{"dice"}, Scopes: []string{"group_record", "players", "attrs"}, ActiveDiceIDs: []string{"dice"}, AllowActive: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := purge.Confirm(ctx, privacypurge.Request{GroupID: "group", DiceIDs: []string{"dice"}, Scopes: []string{"group_record", "players", "attrs"}, ActiveDiceIDs: []string{"dice"}, AllowActive: true, ConfirmationDigest: dry.ConfirmationDigest, ConfirmationVersion: dry.ConfirmationVersion})
	if !errors.Is(err, privacypurge.ErrUncoveredData) || !result.Completed || result.Deleted.GroupRecord != 3 || result.Deleted.Players != 2 || result.Deleted.Attrs != 2 {
		t.Fatalf("purge result=%+v err=%v", result, err)
	}
	var unrelatedEffects []struct {
		EffectID          string
		Status            string
		SubjectKey        []byte
		ResultCode        string
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
	}
	effectIDs := []string{"scenario-effect-1", "scenario-effect-2"}
	if err := db.GORM().Table("outbox_effects").Where("effect_id IN ?", effectIDs).Find(&unrelatedEffects).Error; err != nil {
		t.Fatal(err)
	}
	if len(unrelatedEffects) != 2 {
		t.Fatalf("unrelated effects=%d want=2", len(unrelatedEffects))
	}
	for _, effect := range unrelatedEffects {
		if effect.Status != eventstore.OutboxStatusSucceeded || effect.ResultCode != "sent" || string(effect.SubjectKey) == string(groupSubjectKey) {
			t.Fatalf("unrelated effect was purged or changed: %+v", effect)
		}
		if len(effect.PayloadCiphertext) != 0 || len(effect.PayloadNonce) != 0 {
			t.Fatalf("terminal unrelated effect retained encrypted payload: %s", effect.EffectID)
		}
	}
	var unrelatedOutbox, unrelatedInbox int64
	if err := db.GORM().Table("outbox_effects").Where("subject_key <> ?", groupSubjectKey).Count(&unrelatedOutbox).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.GORM().Table("inbox_messages").Where("subject_key <> ?", groupSubjectKey).Count(&unrelatedInbox).Error; err != nil {
		t.Fatal(err)
	}
	if unrelatedOutbox != 2 || unrelatedInbox != 0 {
		t.Fatalf("unrelated scope counts outbox=%d inbox=%d", unrelatedOutbox, unrelatedInbox)
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
