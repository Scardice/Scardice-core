package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/configstate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	endpointcore "Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
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
	dsn      string
	database *eventstore.Database
	store    *eventstore.GORMStore
	inbound  *messageflow.InboundService
	callback *messageflow.CallbackService
	fence    endpointcore.State
	baseline struct{ operations, effects int64 }
	sequence int
}

func newDurableOBHarness(t *testing.T) *durableOBHarness {
	t.Helper()
	ctx := context.Background()
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(cleanup)

	harness := &durableOBHarness{
		t: t, ctx: ctx, dice: d, endpoint: endpoint,
		dsn: filepath.Join(t.TempDir(), "durable-ob.db"),
	}
	harness.database = harness.openDatabase()
	t.Cleanup(func() {
		if harness.database != nil {
			_ = harness.database.Close()
		}
	})
	options := projectionset.StoreOptions()
	harness.store = eventstore.NewStore(harness.database, options...)
	if err := harness.store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 2, DatabaseIdentity: "durable-ob-test",
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	d.DurableStore = harness.store
	baseline := configstate.Baseline{
		DiceID: d.BaseConfig.Name, ConfigVersion: 1, CommandPrefix: []string{"."},
	}
	if _, err := configstate.NewRepository(harness.store).DecideAndAppend(
		ctx, configstate.State{}, 0, eventstore.Metadata{},
		configstate.Command{Kind: configstate.CommandImportBaseline, Baseline: &baseline},
	); err != nil {
		t.Fatal(err)
	}
	if err := d.ReloadConfigView(ctx); err != nil {
		t.Fatal(err)
	}
	d.AttrsManager.Stop()
	d.AttrsManager = &AttrsManager{}
	if err := d.AttrsManager.InitDurable(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.AttrsManager.Stop)

	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: adapterapi.EndpointID(endpoint.ID), AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions: adapterapi.ActionSet(0).With(
			adapterapi.ActionKindSendMessage,
			adapterapi.ActionKindSetGroupCard,
		),
	}}
	ids := &canonicalFixtureIDs{prefix: canonicalFixtureLabel(t, "durable-ob-outbound")}
	outbound, err := messageflow.NewOutboundService(harness.store, resolver, ids)
	if err != nil {
		t.Fatal(err)
	}
	d.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, ids, newBridgeTestNotificationOwner(t))
	harness.fence = projectCallbackTestEndpoint(t, d, harness.store, endpoint).state
	_, harness.baseline.operations, harness.baseline.effects = groupCardSQLiteRowCounts(t, harness.database)

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

	harness.inbound, err = messageflow.NewInboundService(harness.store)
	if err != nil {
		t.Fatal(err)
	}
	harness.callback, err = messageflow.NewCallbackService(messageflow.CallbackConfig{
		Inbox: harness.store, Store: harness.store,
		Resolver: NewDurableCallbackScopeResolver(d),
		Host:     NewDurableCallbackHost(d), WorkerID: "durable-ob-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

func (h *durableOBHarness) openDatabase() *eventstore.Database {
	h.t.Helper()
	database, err := eventstore.OpenDatabase(h.ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: h.dsn, DatabaseIdentity: "durable-ob-test",
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
		EndpointID: h.fence.EndpointID, Generation: h.fence.Generation, DesiredVersion: h.fence.DesiredVersion,
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

// outboundRowsSinceSeed reports operation/effect rows added after the fixture
// projected its endpoint (endpoint lifecycle operations are fixture setup).
func (h *durableOBHarness) outboundRowsSinceSeed() (operations, effects int64) {
	h.t.Helper()
	_, operations, effects = groupCardSQLiteRowCounts(h.t, h.database)
	return operations - h.baseline.operations, effects - h.baseline.effects
}

func (h *durableOBHarness) reopen() {
	h.t.Helper()
	database := h.database
	h.database = nil
	if err := database.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.database = h.openDatabase()
	options := projectionset.StoreOptions()
	h.store = eventstore.NewStore(h.database, options...)
	if _, err := h.store.GetReadiness(h.ctx); err != nil {
		h.t.Fatalf("validate reopened durable store: %v", err)
	}
	h.dice.DurableStore = h.store
}

func (h *durableOBHarness) outboundEffects() []adapterapi.OutboundEffect {
	h.t.Helper()
	var rows []struct {
		EffectID   string `gorm:"column:effect_id"`
		EndpointID string `gorm:"column:endpoint_id"`
		Subject    string `gorm:"column:subject"`
		Payload    []byte `gorm:"column:payload"`
	}
	if err := h.database.GORM().Table("outbox_effects").Order("effect_id").Find(&rows).Error; err != nil {
		h.t.Fatal(err)
	}
	effects := make([]adapterapi.OutboundEffect, 0, len(rows))
	for _, row := range rows {
		var wire struct {
			Effect adapterapi.OutboundEffect `json:"effect"`
		}
		if err := json.Unmarshal(row.Payload, &wire); err != nil {
			h.t.Fatal(err)
		}
		// Every harness callback originates in obTestGroupID, even when it
		// sends a private reply or targets another group.
		if string(wire.Effect.ID) != row.EffectID || string(wire.Effect.EndpointID) != row.EndpointID || row.Subject != obTestGroupID {
			h.t.Fatalf("persisted observer effect identity mismatch: row=%#v effect=%#v", row, wire.Effect)
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
	endpointValue := *harness.endpoint
	endpointValue.Adapter = nil
	endpointValue.Session = harness.dice.ImSession
	endpoint := &endpointValue
	root := newCanonicalTestRoot(t, harness.dice, "durable-ob-delegate")
	msg := newGroupMsg(obTestGroupID, obTestUserID, ".ob [CQ:at,qq=2002]")
	msg.Sender.Nickname = "Admin"
	msg.Sender.GroupRole = "admin"
	ctx, err := NewDomainMsgContext(root.Transaction, harness.dice, harness.dice.ImSession, endpoint, msg)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.releaseExecutionState()
	ctx.PrivilegeLevel = 50
	extension := harness.dice.ExtFind("log", false)
	if extension == nil || extension.GetCmdMap()["ob"] == nil {
		t.Fatal("built-in observer command is unavailable")
	}
	result := extension.GetCmdMap()["ob"].Solve(ctx, msg, &CmdArgs{At: []*AtInfo{{UserID: targetUserID}}})
	if !result.Matched || !result.Solved {
		t.Fatalf("delegated .ob result = %#v", result)
	}
	target, err := root.Transaction.Domain().Player(harness.ctx, harness.dice.BaseConfig.Name, obTestGroupID, targetUserID)
	if err != nil {
		t.Fatal(err)
	}
	if target.Name() != "obTarget" {
		t.Fatalf("delegated player name = %q, want %q", target.Name(), "obTarget")
	}
	if operations, effects := harness.outboundRowsSinceSeed(); operations != 0 || effects != 0 {
		t.Fatalf("delegated .ob persisted outside callback collector: operations=%d effects=%d", operations, effects)
	}
	if err := root.Transaction.Finalize(harness.ctx); err != nil {
		t.Fatal(err)
	}
	work, err := root.Collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Operations) != 2 || len(work.Effects) != 2 {
		t.Fatalf("delegated callback effects = operations:%d effects:%d, want card and reply", len(work.Operations), len(work.Effects))
	}
	var cardEffects int
	for _, pending := range work.Effects {
		var wire struct {
			Effect adapterapi.OutboundEffect `json:"effect"`
		}
		if err := json.Unmarshal(pending.Payload, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Effect.Payload.Kind != adapterapi.EffectPayloadSetGroupCard {
			continue
		}
		cardEffects++
		payload := wire.Effect.Payload
		if payload.Card != "obTarget" || payload.Target.Conversation != adapterapi.ConversationID(obTestGroupID) ||
			payload.Target.Member != adapterapi.PrincipalID(targetUserID) {
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
	if _, err := harness.store.Commit(harness.ctx, work); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("delegated callback conflict error = %v, want conflict", err)
	}
	if operations, effects := harness.outboundRowsSinceSeed(); operations != 0 || effects != 0 {
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
