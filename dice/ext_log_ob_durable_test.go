package dice

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/message"
)

const (
	obTestGroupID = "QQ-Group:2002"
	obTestUserID  = "QQ:1001"
)

type durableOBHarness struct {
	t        *testing.T
	ctx      context.Context
	dice     *Dice
	endpoint *EndPointInfo
	keys     groupCardSQLiteKeySource
	dsn      string
	database *eventstore.Database
	store    *eventstore.GORMStore
	inbound  *messageflow.InboundService
	callback *messageflow.CallbackService
	sequence int
}

func newDurableOBHarness(t *testing.T) *durableOBHarness {
	t.Helper()
	ctx := context.Background()
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(cleanup)

	harness := &durableOBHarness{
		t: t, ctx: ctx, dice: d, endpoint: endpoint,
		keys: groupCardSQLiteKeySource{},
		dsn:  filepath.Join(t.TempDir(), "durable-ob.db"),
	}
	harness.database = harness.openDatabase()
	t.Cleanup(func() {
		if harness.database != nil {
			_ = harness.database.Close()
		}
	})
	harness.store = eventstore.NewStore(harness.database, eventstore.WithKeySource(harness.keys))
	if err := harness.store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "durable-ob-test",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d.DurableStore = harness.store

	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(endpoint.ID), AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions: adapterapi.ActionSet(0).With(
			adapterapi.ActionKindSendMessage,
			adapterapi.ActionKindSetGroupCard,
		),
		IndexRootID: "card-index-v1", IndexSigner: groupCardSQLiteIndexSigner{},
	}}
	outbound, err := messageflow.NewOutboundService(harness.store, resolver, harness.store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	d.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})

	metadata := eventstore.Metadata{
		CommandID: "seed-durable-ob", CorrelationID: "seed-durable-ob",
		OccurredAt: time.Unix(2, 0).UTC(),
	}
	groupRepository := groupstate.NewRepository(harness.store)
	if _, err := groupRepository.AppendTyped(ctx, d.BaseConfig.Name, obTestGroupID, 0, metadata, []groupstate.TypedEvent{
		groupstate.NewGroupCreatedV1(d.BaseConfig.Name, obTestGroupID, "Observer Test Group", 2),
		groupstate.NewGroupActivationChangedV1(endpoint.UserID, true, true),
		groupstate.NewGroupExtensionChangedV1("log", true),
	}); err != nil {
		t.Fatal(err)
	}
	playerRepository := playerstate.NewRepository(harness.store)
	if _, err := playerRepository.AppendPlayerTyped(ctx, d.BaseConfig.Name, obTestGroupID, obTestUserID, 0, metadata, []playerstate.PlayerEvent{
		playerstate.NewPlayerCreatedV1(d.BaseConfig.Name, obTestGroupID, obTestUserID, "Tester"),
	}); err != nil {
		t.Fatal(err)
	}

	harness.inbound, err = messageflow.NewInboundService(harness.store, harness.store)
	if err != nil {
		t.Fatal(err)
	}
	harness.callback, err = messageflow.NewCallbackService(messageflow.CallbackConfig{
		Inbox: harness.store, Store: harness.store, BoundCodec: harness.store,
		Resolver: NewDurableCallbackScopeResolver(d),
		Group:    groupRepository, Player: playerRepository,
		Host: NewDurableCallbackHost(d), WorkerID: "durable-ob-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

func (h *durableOBHarness) openDatabase() *eventstore.Database {
	h.t.Helper()
	database, err := eventstore.OpenDatabase(h.ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: h.dsn, KeySource: h.keys, DatabaseIdentity: "durable-ob-test",
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return database
}

func (h *durableOBHarness) process(command string) {
	h.processInbound(command, "", nil)
}

func (h *durableOBHarness) processInbound(command, senderRole string, segments []adapterapi.InboundSegment) {
	h.t.Helper()
	h.sequence++
	providerEventID := fmt.Sprintf("provider-ob-%d", h.sequence)
	receipt, err := h.inbound.HandleInbound(h.ctx, endpointcore.FencedInbound{
		EndpointID: adapterapi.EndpointID(h.endpoint.ID), Generation: 1, DesiredVersion: 1,
		Message: adapterapi.InboundMessage{
			ProviderEventID:  adapterapi.ProviderEventID(providerEventID),
			MessageID:        adapterapi.MessageID(providerEventID + "-message"),
			Kind:             adapterapi.InboundKindMessage,
			ConversationKind: adapterapi.ConversationKindGroup,
			Platform:         "QQ", Sender: adapterapi.PrincipalID(obTestUserID), SenderRole: senderRole,
			Conversation: adapterapi.ConversationID(obTestGroupID), Target: h.endpoint.UserID,
			Text: command, Segments: segments, OccurredAt: time.Unix(int64(2+h.sequence), 0).UTC(),
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
		h.t.Fatalf("ingress receipt = %#v", receipt)
	}
	summary, err := h.callback.ProcessOne(h.ctx)
	if err != nil {
		h.t.Fatalf("process %q: %v", command, err)
	}
	if summary.InboxID != receipt.InboxID || summary.Status != eventstore.InboxStatusConfirmedConsumed {
		h.t.Fatalf("%q callback summary = %#v", command, summary)
	}
}

func (h *durableOBHarness) player() playerstate.PlayerState {
	return h.playerByID(obTestUserID)
}

func (h *durableOBHarness) playerByID(userID string) playerstate.PlayerState {
	h.t.Helper()
	state, err := playerstate.NewRepository(h.store).LoadPlayer(h.ctx, h.dice.BaseConfig.Name, obTestGroupID, userID)
	if err != nil {
		h.t.Fatal(err)
	}
	return state
}

func (h *durableOBHarness) reopen() {
	h.t.Helper()
	database := h.database
	h.database = nil
	if err := database.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.database = h.openDatabase()
	h.store = eventstore.NewStore(h.database, eventstore.WithKeySource(h.keys))
	if err := h.store.ValidateReadiness(h.ctx); err != nil {
		h.t.Fatalf("validate reopened durable store: %v", err)
	}
	h.dice.DurableStore = h.store
}

func (h *durableOBHarness) outboundEffects() []adapterapi.OutboundEffect {
	h.t.Helper()
	var rows []struct {
		EffectID          string `gorm:"column:effect_id"`
		EndpointID        string `gorm:"column:endpoint_id"`
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		EncryptionKeyID   string `gorm:"column:encryption_key_id"`
	}
	if err := h.database.GORM().Table("outbox_effects").Order("effect_id").Find(&rows).Error; err != nil {
		h.t.Fatal(err)
	}
	effects := make([]adapterapi.OutboundEffect, 0, len(rows))
	for _, row := range rows {
		plain, err := h.store.DecryptBound(h.ctx, "outbox/v1", row.EffectID, row.EndpointID, 1, row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID)
		if err != nil {
			h.t.Fatalf("decrypt outbound effect %q after reopen: %v", row.EffectID, err)
		}
		var wire struct {
			Effect adapterapi.OutboundEffect `json:"effect"`
		}
		if err := json.Unmarshal(plain, &wire); err != nil {
			h.t.Fatal(err)
		}
		effects = append(effects, wire.Effect)
	}
	return effects
}

func TestDurableCallbackOBEnterAndExitPersistCardReplyAndPlayerAcrossRestart(t *testing.T) {
	harness := newDurableOBHarness(t)

	harness.process(".ob")
	if got := harness.player().Name; got != "obTester" {
		t.Fatalf("player name after .ob = %q, want %q", got, "obTester")
	}

	harness.process(".ob exit")
	if got := harness.player().Name; got != "Tester" {
		t.Fatalf("player name after .ob exit = %q, want %q", got, "Tester")
	}

	harness.reopen()
	if got := harness.player().Name; got != "Tester" {
		t.Fatalf("player name after restart = %q, want %q", got, "Tester")
	}

	cards := map[string]int{}
	replies := map[string]int{}
	effects := harness.outboundEffects()
	for _, effect := range effects {
		payload := effect.Payload
		switch payload.Kind {
		case adapterapi.EffectPayloadSetGroupCard:
			if effect.Kind != adapterapi.EffectKindAction || payload.Target.Kind != adapterapi.TargetGroup ||
				payload.Target.Conversation != adapterapi.ConversationID(obTestGroupID) || payload.Target.Member != adapterapi.PrincipalID(obTestUserID) {
				t.Fatalf("invalid observer card effect = %#v", effect)
			}
			cards[payload.Card]++
		case adapterapi.EffectPayloadGroupText:
			if effect.Kind != adapterapi.EffectKindMessage || payload.Target.Kind != adapterapi.TargetGroup ||
				payload.Target.Conversation != adapterapi.ConversationID(obTestGroupID) {
				t.Fatalf("invalid observer reply effect = %#v", effect)
			}
			replies[payload.Text]++
		default:
			t.Fatalf("unexpected observer outbound effect = %#v", effect)
		}
	}
	wantCards := map[string]int{"obTester": 1, "Tester": 1}
	if !reflect.DeepEqual(cards, wantCards) {
		t.Fatalf("observer card effects = %#v, want %#v (all effects: %#v)", cards, wantCards, effects)
	}
	wantReplies := map[string]int{
		"你将成为观众（自动修改昵称和群名片[如有权限]，并不会给观众发送暗骰结果）。": 1,
		"你不再是观众了（自动修改昵称和群名片[如有权限]）。":             1,
	}
	if !reflect.DeepEqual(replies, wantReplies) {
		t.Fatalf("observer reply effects = %#v, want %#v (all effects: %#v)", replies, wantReplies, effects)
	}
	if len(effects) != 4 {
		t.Fatalf("observer outbound effect count = %d, want 4: %#v", len(effects), effects)
	}
}

func TestDurableCallbackOBDelegateLoadsAndPersistsTargetPlayerAcrossRestart(t *testing.T) {
	harness := newDurableOBHarness(t)
	const targetUserID = "QQ:2002"
	targetRepository := playerstate.NewRepository(harness.store)
	if _, err := targetRepository.AppendPlayerTyped(
		harness.ctx,
		harness.dice.BaseConfig.Name,
		obTestGroupID,
		targetUserID,
		0,
		eventstore.Metadata{
			CommandID: "seed-durable-ob-target", CorrelationID: "seed-durable-ob-target",
			OccurredAt: time.Unix(2, 0).UTC(),
		},
		[]playerstate.PlayerEvent{
			playerstate.NewPlayerCreatedV1(harness.dice.BaseConfig.Name, obTestGroupID, targetUserID, "Target"),
		},
	); err != nil {
		t.Fatal(err)
	}
	if group, exists := harness.dice.ImSession.ServiceAtNew.Load(obTestGroupID); exists && group.Players.Exists(targetUserID) {
		t.Fatal("durable target player unexpectedly preloaded into compatibility cache")
	}

	delegated := func(command string) {
		harness.processInbound(command, "admin", []adapterapi.InboundSegment{
			{Kind: "text", Text: command + " "},
			{Kind: "mention", ProviderID: targetUserID},
		})
	}
	delegated(".ob")
	targetAfterEnter := harness.playerByID(targetUserID).Name
	senderAfterEnter := harness.player().Name
	delegated(".ob exit")
	targetAfterExit := harness.playerByID(targetUserID).Name
	senderAfterExit := harness.player().Name

	if targetAfterEnter != "obTarget" {
		t.Fatalf("delegated target after .ob = %q, want %q", targetAfterEnter, "obTarget")
	}
	if targetAfterExit != "Target" {
		t.Fatalf("delegated target after .ob exit = %q, want %q", targetAfterExit, "Target")
	}
	if senderAfterEnter != "Tester" || senderAfterExit != "Tester" {
		t.Fatalf("delegated .ob changed sender name: enter=%q exit=%q", senderAfterEnter, senderAfterExit)
	}

	harness.reopen()
	if got := harness.playerByID(targetUserID).Name; got != "Target" {
		t.Fatalf("delegated target after restart = %q, want %q", got, "Target")
	}
	if got := harness.player().Name; got != "Tester" {
		t.Fatalf("delegated sender after restart = %q, want %q", got, "Tester")
	}

	cards := map[string]int{}
	replies := map[string]int{}
	effects := harness.outboundEffects()
	for _, effect := range effects {
		payload := effect.Payload
		switch payload.Kind {
		case adapterapi.EffectPayloadSetGroupCard:
			if payload.Target.Member != adapterapi.PrincipalID(targetUserID) {
				t.Fatalf("delegated card targeted wrong player: %#v", effect)
			}
			cards[payload.Card]++
		case adapterapi.EffectPayloadGroupText:
			replies[payload.Text]++
		default:
			t.Fatalf("unexpected delegated observer effect: %#v", effect)
		}
	}
	wantCards := map[string]int{"obTarget": 1, "Target": 1}
	if !reflect.DeepEqual(cards, wantCards) {
		t.Fatalf("delegated card effects = %#v, want %#v (all effects: %#v)", cards, wantCards, effects)
	}
	wantReplies := map[string]int{
		"由<Tester>操作:\n你将成为观众（自动修改昵称和群名片[如有权限]，并不会给观众发送暗骰结果）。": 1,
		"由<Tester>操作:\n你不再是观众了（自动修改昵称和群名片[如有权限]）。":             1,
	}
	if !reflect.DeepEqual(replies, wantReplies) {
		t.Fatalf("delegated reply effects = %#v, want %#v (all effects: %#v)", replies, wantReplies, effects)
	}
	if len(effects) != 4 {
		t.Fatalf("delegated outbound effect count = %d, want 4: %#v", len(effects), effects)
	}
}

func TestDurableOBDelegateStagesTargetCardInCallbackCollector(t *testing.T) {
	harness := newDurableOBHarness(t)
	const targetUserID = "QQ:2002"
	if _, err := playerstate.NewRepository(harness.store).AppendPlayerTyped(
		harness.ctx,
		harness.dice.BaseConfig.Name,
		obTestGroupID,
		targetUserID,
		0,
		eventstore.Metadata{
			CommandID: "seed-durable-ob-conflict-target", CorrelationID: "seed-durable-ob-conflict-target",
			OccurredAt: time.Unix(2, 0).UTC(),
		},
		[]playerstate.PlayerEvent{
			playerstate.NewPlayerCreatedV1(harness.dice.BaseConfig.Name, obTestGroupID, targetUserID, "Target"),
		},
	); err != nil {
		t.Fatal(err)
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	transaction, err := NewDurableCallbackTransaction(harness.store, collector)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := compatibilityCallbackEndpoint(harness.dice.ImSession, messageflow.CallbackRequest{
		EndpointID: harness.endpoint.ID,
		Message: adapterapi.InboundMessage{
			Platform: "QQ",
			Target:   harness.endpoint.UserID,
		},
	})
	if endpoint.Adapter != nil {
		t.Fatal("delegated callback fixture unexpectedly has a legacy adapter")
	}

	sender := &GroupPlayerInfo{UserID: obTestUserID, Name: "Admin"}
	target := &GroupPlayerInfo{UserID: targetUserID, Name: "Target"}
	group := &GroupInfo{GroupID: obTestGroupID, Players: new(SyncMap[string, *GroupPlayerInfo])}
	group.Players.Store(sender.UserID, sender)
	group.Players.Store(target.UserID, target)
	ctx := &MsgContext{
		Dice: harness.dice, Session: harness.dice.ImSession, EndPoint: endpoint,
		Group: group, Player: sender, MessageType: "group", PrivilegeLevel: 50,
		callbackTransaction: transaction,
		callbackMetadata: eventstore.Metadata{
			CommandID: "durable-ob-delegate", CorrelationID: "durable-ob-delegate",
			OccurredAt: time.Unix(10, 0).UTC(),
		},
	}
	msg := &Message{
		Platform: "QQ", MessageType: "group", GroupID: obTestGroupID,
		Sender:  SenderBase{UserID: sender.UserID, Nickname: sender.Name},
		Message: ".ob [CQ:at,qq=2002]",
	}
	extension := harness.dice.ExtFind("log", false)
	if extension == nil || extension.GetCmdMap()["ob"] == nil {
		t.Fatal("built-in observer command is unavailable")
	}
	result := extension.GetCmdMap()["ob"].Solve(ctx, msg, &CmdArgs{At: []*AtInfo{{UserID: target.UserID}}})
	if !result.Matched || !result.Solved {
		t.Fatalf("delegated .ob result = %#v", result)
	}
	if target.Name != "obTarget" {
		t.Fatalf("delegated player name = %q, want %q", target.Name, "obTarget")
	}
	if _, operations, effects := groupCardSQLiteRowCounts(t, harness.database); operations != 0 || effects != 0 {
		t.Fatalf("delegated .ob persisted outside callback collector: operations=%d effects=%d", operations, effects)
	}
	if err := transaction.Finalize(harness.ctx); err != nil {
		t.Fatal(err)
	}

	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 2 || len(work.Effects) != 2 {
		t.Fatalf("delegated callback effects = operations:%d effects:%d, want card and reply", len(work.Operations), len(work.Effects))
	}
	var cardEffects int
	for _, pending := range work.Effects {
		plain, err := harness.store.DecryptBound(
			harness.ctx, "outbox/v1", pending.EffectID, pending.EndpointID, 1,
			pending.PayloadCiphertext, pending.PayloadNonce, pending.PayloadEncryptionKeyID,
		)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Effect adapterapi.OutboundEffect `json:"effect"`
		}
		if err := json.Unmarshal(plain, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Effect.Payload.Kind != adapterapi.EffectPayloadSetGroupCard {
			continue
		}
		cardEffects++
		payload := wire.Effect.Payload
		if payload.Card != "obTarget" || payload.Target.Conversation != adapterapi.ConversationID(obTestGroupID) ||
			payload.Target.Member != adapterapi.PrincipalID(target.UserID) {
			t.Fatalf("delegated observer card effect = %#v", wire.Effect)
		}
	}
	if cardEffects != 1 {
		t.Fatalf("delegated observer card effect count = %d, want 1", cardEffects)
	}
	targetStream := playerstate.PlayerStream(harness.dice.BaseConfig.Name, obTestGroupID, targetUserID)
	targetStaged := false
	for index := range work.Streams {
		if work.Streams[index].Stream == targetStream && work.Streams[index].ExpectedVersion != 1 {
			t.Fatalf("delegated target expected version = %d, want 1", work.Streams[index].ExpectedVersion)
		}
		if work.Streams[index].Stream == targetStream {
			work.Streams[index].ExpectedVersion++
			targetStaged = true
			break
		}
	}
	if !targetStaged {
		t.Fatal("delegated callback did not stage the target player stream")
	}
	if _, err := harness.store.Commit(harness.ctx, work); err == nil {
		t.Fatal("delegated callback conflict unexpectedly committed")
	}
	if _, operations, effects := groupCardSQLiteRowCounts(t, harness.database); operations != 0 || effects != 0 {
		t.Fatalf("failed delegated callback left durable outbound rows: operations=%d effects=%d", operations, effects)
	}
	if state := harness.playerByID(targetUserID); state.Name != "Target" || state.Version != 1 {
		t.Fatalf("failed delegated callback changed target player: %#v", state)
	}
	if state := harness.player(); state.Name != "Tester" || state.Version != 1 {
		t.Fatalf("failed delegated callback changed sender player: %#v", state)
	}
	bridge := harness.dice.OutboundBridge.(*DurableOutboundBridge)
	bridge.mu.Lock()
	pendingNotifications := len(bridge.pending)
	bridge.mu.Unlock()
	if pendingNotifications != 0 {
		t.Fatalf("failed delegated callback registered %d outbound notifications", pendingNotifications)
	}
}

type obCardUpdate struct {
	userID string
	name   string
}

type obCardCaptureAdapter struct {
	*mockPlatformAdapter
	updates []obCardUpdate
}

func (a *obCardCaptureAdapter) SetGroupCardName(ctx *MsgContext, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updates = append(a.updates, obCardUpdate{userID: ctx.Player.UserID, name: name})
}

func (a *obCardCaptureAdapter) cardUpdates() []obCardUpdate {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]obCardUpdate(nil), a.updates...)
}

func TestLegacyOBEnterAndExitUsesAdapterCardUpdates(t *testing.T) {
	d, endpoint, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	capture := &obCardCaptureAdapter{mockPlatformAdapter: adapter}
	endpoint.Adapter = capture

	d.ImSession.ExecuteNew(endpoint, newGroupMsg("QQ-Group:legacy-ob", "QQ:1001", ".ob"))
	if reply, ok := capture.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for .ob reply")
	} else if reply != "你将成为观众（自动修改昵称和群名片[如有权限]，并不会给观众发送暗骰结果）。" {
		t.Fatalf(".ob reply = %q", reply)
	}

	d.ImSession.ExecuteNew(endpoint, newGroupMsg("QQ-Group:legacy-ob", "QQ:1001", ".ob exit"))
	if reply, ok := capture.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for .ob exit reply")
	} else if reply != "你不再是观众了（自动修改昵称和群名片[如有权限]）。" {
		t.Fatalf(".ob exit reply = %q", reply)
	}

	if updates, want := capture.cardUpdates(), []obCardUpdate{{userID: "QQ:1001", name: "obTester"}, {userID: "QQ:1001", name: "Tester"}}; !reflect.DeepEqual(updates, want) {
		t.Fatalf("legacy observer card updates = %#v, want %#v", updates, want)
	}
}

func TestLegacyOBDelegateUsesTargetPlayerContextForCardUpdate(t *testing.T) {
	d, endpoint, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	capture := &obCardCaptureAdapter{mockPlatformAdapter: adapter}
	endpoint.Adapter = capture

	const groupID = "QQ-Group:legacy-ob-delegate"
	targetMessage := newGroupMsg(groupID, "QQ:2002", ".r 1d1")
	targetMessage.Sender.Nickname = "Target"
	d.ImSession.ExecuteNew(endpoint, targetMessage)
	if _, ok := capture.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout seeding delegated observer player")
	}

	delegated := newGroupMsg(groupID, "QQ:1001", ".ob [CQ:at,qq=2002]")
	delegated.Sender.Nickname = "Admin"
	delegated.Sender.GroupRole = "admin"
	delegated.Segment = []message.IMessageElement{
		&message.TextElement{Content: ".ob "},
		&message.AtElement{Target: "2002"},
	}
	d.ImSession.ExecuteNew(endpoint, delegated)
	if _, ok := capture.waitForMsg(2 * time.Second); !ok {
		t.Fatal("timeout waiting for delegated .ob reply")
	}

	if updates, want := capture.cardUpdates(), []obCardUpdate{{userID: "QQ:2002", name: "obTarget"}}; !reflect.DeepEqual(updates, want) {
		t.Fatalf("delegated observer card updates = %#v, want %#v", updates, want)
	}
}
