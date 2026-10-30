package dice

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"

	ds "github.com/sealdice/dicescript"
)

func TestDurableCallbackScopeResolverMapsGroupAndPrivateMessages(t *testing.T) {
	manager := &DiceManager{EventSourcedMode: true}
	instance := &Dice{BaseConfig: BaseConfig{Name: "default"}, Parent: manager}
	manager.Dice = []*Dice{instance}
	resolver := NewDurableCallbackScopeResolver(instance)

	group, err := resolver.Resolve(context.Background(), "endpoint-1", adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
		Sender: "QQ:1001", Conversation: "QQ-Group:2002",
	})
	if err != nil {
		t.Fatal(err)
	}
	if group.DiceID != "default" || group.GroupID != "QQ-Group:2002" || group.UserID != "QQ:1001" {
		t.Fatalf("group scope = %#v", group)
	}

	private, err := resolver.Resolve(context.Background(), "endpoint-1", adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindDirect,
		Sender: "QQ:1001", Conversation: "QQ:1001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if private.DiceID != "default" || private.GroupID != "PG-QQ:1001" || private.UserID != "QQ:1001" {
		t.Fatalf("private scope = %#v", private)
	}
}

func TestDurableCallbackUsesExplicitConversationKind(t *testing.T) {
	direct := adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindDirect,
		Sender: "DISCORD:user-1", Conversation: "DISCORD-DM:channel-1", Platform: "DISCORD",
	}
	message := compatibilityCallbackMessage(messageflow.CallbackRequest{Message: direct, Scope: messageflow.CallbackScope{UserID: "DISCORD:user-1"}})
	if message.MessageType != "private" || message.GroupID != "" {
		t.Fatalf("direct compatibility message = %#v", message)
	}

	group := adapterapi.InboundMessage{
		Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
		Sender: "DISCORD:user-1", Conversation: "DISCORD-CH-Group:channel-1", Platform: "DISCORD",
	}
	message = compatibilityCallbackMessage(messageflow.CallbackRequest{Message: group, Scope: messageflow.CallbackScope{UserID: "DISCORD:user-1"}})
	if message.MessageType != "group" || message.GroupID != "DISCORD-CH-Group:channel-1" {
		t.Fatalf("group compatibility message = %#v", message)
	}
}

func TestDurableCallbackRejectsUnhandledInboundKind(t *testing.T) {
	session := &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	dice := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, ImSession: session}
	host := NewDurableCallbackHost(dice)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	_, err := host.HandleCallback(context.Background(), messageflow.CallbackRequest{
		Scope:   messageflow.CallbackScope{DiceID: "dice-1", GroupID: "QQ-Group:1", UserID: "QQ:2"},
		Message: adapterapi.InboundMessage{Kind: adapterapi.InboundKindRequest},
	}, nil, collector)
	if !errors.Is(err, ErrUnsupportedDurableInboundKind) {
		t.Fatalf("unhandled inbound kind error = %v", err)
	}
}

func TestCompatibilityGroupFromZeroVersionStateSeedsScopedPlayer(t *testing.T) {
	scope := messageflow.CallbackScope{DiceID: "test", GroupID: "QQ-Group:2002", UserID: "QQ:1001"}
	group := compatibilityGroupFromState(&Dice{}, groupstate.State{}, playerstate.PlayerState{}, scope)
	if group.GroupID != scope.GroupID {
		t.Fatalf("group ID = %q, want %q", group.GroupID, scope.GroupID)
	}
	player := group.PlayerGet(nil, scope.UserID)
	if player == nil || player.UserID != scope.UserID || player.ValueMapTemp == nil {
		t.Fatalf("zero-version player = %#v", player)
	}
}

func TestGroupPlayerGetWithNilDatabaseDoesNotFallback(t *testing.T) {
	group := &GroupInfo{GroupID: "QQ-Group:2002", Players: new(SyncMap[string, *GroupPlayerInfo])}
	if player := group.PlayerGet(nil, "QQ:1001"); player != nil {
		t.Fatalf("nil database lookup returned %#v", player)
	}
}

func TestDurableCallbackHostInvalidatesCompatibilityGroup(t *testing.T) {
	session := &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	session.ServiceAtNew.Store("QQ-Group:2002", &GroupInfo{GroupID: "QQ-Group:2002"})
	host := NewDurableCallbackHost(&Dice{ImSession: session})
	if err := host.InvalidateGroup(context.Background(), "QQ-Group:2002"); err != nil {
		t.Fatal(err)
	}
	if _, ok := session.ServiceAtNew.Load("QQ-Group:2002"); ok {
		t.Fatal("privacy invalidation retained compatibility group")
	}
}

func TestPrivacyGroupInvalidationEvictsCachedBindingState(t *testing.T) {
	characterService, _ := newCharacterServiceFixture(t)
	manager := characterService.dice.AttrsManager
	ctx := context.Background()
	groupID := FormatDiceIDSealChatGroup("channel-cache")
	userID := FormatDiceIDSealChat("user-cache")
	groupUserID := groupID + "-" + manager.UIDConvert(userID)
	const sheetID = "sheet-cache"

	groupValues := &ds.ValueMap{}
	groupValues.Store("hp", ds.NewIntVal(1))
	groupPayload, err := ds.NewDictVal(groupValues).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	groupState, err := manager.durable.Save(ctx, attributestate.State{
		DiceID: manager.diceID, ID: groupUserID, AttrsType: service.AttrsTypeGroupUser,
		SecretRef: attributestate.SecretRef(manager.diceID, groupUserID), CreatedAt: 1, UpdatedAt: 1,
	}, groupPayload)
	if err != nil {
		t.Fatal(err)
	}
	sheetValues := &ds.ValueMap{}
	sheetValues.Store("hp", ds.NewIntVal(99))
	sheetPayload, err := ds.NewDictVal(sheetValues).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	sheetState, err := manager.durable.Save(ctx, attributestate.State{
		DiceID: manager.diceID, ID: sheetID, AttrsType: service.AttrsTypeCharacter, OwnerID: userID,
		SecretRef: attributestate.SecretRef(manager.diceID, sheetID), CreatedAt: 1, UpdatedAt: 1,
	}, sheetPayload)
	if err != nil {
		t.Fatal(err)
	}

	staleBoundState := groupState
	staleBoundState.BindingSheetID = sheetID
	manager.states.Store(groupUserID, staleBoundState)
	manager.m.Store(groupUserID, manager.itemFromState(staleBoundState, groupValues))
	manager.states.Store(sheetID, sheetState)
	manager.m.Store(sheetID, manager.itemFromState(sheetState, sheetValues))
	session := &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	characterService.dice.ImSession = session
	host := NewDurableCallbackHost(characterService.dice)
	if err := host.InvalidateGroup(ctx, groupID); err != nil {
		t.Fatal(err)
	}

	item, err := manager.Load(groupID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if got := item.Load("hp").ToString(); got != "1" {
		t.Fatalf("reloaded group attributes hp = %s, want unbound group value 1", got)
	}
	state, ok := manager.states.Load(groupUserID)
	if !ok || state.BindingSheetID != "" {
		t.Fatalf("reloaded binding state = %#v, exists=%v", state, ok)
	}
}

func TestDurableCallbackHostCapturesCreatedGroupAndPlayer(t *testing.T) {
	instance, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	host := NewDurableCallbackHost(instance)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	request := messageflow.CallbackRequest{
		InboxID: "inbox-1", EndpointID: "endpoint-1",
		Message: adapterapi.InboundMessage{
			ProviderEventID: "provider-1", Kind: adapterapi.InboundKindMessage,
			ConversationKind: adapterapi.ConversationKindGroup,
			Platform:         "QQ", Sender: "QQ:1001", Conversation: "QQ-Group:2002", Text: ".r 1d1",
		},
		Scope: messageflow.CallbackScope{DiceID: "test", GroupID: "QQ-Group:2002", UserID: "QQ:1001"},
	}
	result, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != nil {
		result.Release()
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 2 {
		t.Fatalf("captured streams = %#v", work.Streams)
	}
	types := map[string]bool{}
	for _, stream := range work.Streams {
		types[stream.Stream.AggregateType] = true
	}
	if !types["group"] || !types["player"] {
		t.Fatalf("captured aggregate types = %#v", types)
	}
}

func TestDurableCallbackHostProvidesTransactionToMessageExtension(t *testing.T) {
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/callback-host.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithKeySource(compatKeySource{}))
	if err := store.SetReadiness(context.Background(), eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "callback-host-db", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	instance.DurableStore = store
	observed := make(chan bool, 1)
	extension := &ExtInfo{Name: "callback-transaction-test", OnMessageReceived: func(ctx *MsgContext, _ *Message) {
		observed <- ctx.callbackTransaction != nil && ctx.callbackMetadata.CommandID == "inbox-transaction" && ctx.callbackMetadata.CorrelationID == "inbox-transaction"
	}}
	instance.RegisterExtension(extension)
	host := NewDurableCallbackHost(instance)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	request := messageflow.CallbackRequest{
		InboxID: "inbox-transaction", EndpointID: endpoint.ID,
		Message: adapterapi.InboundMessage{ProviderEventID: "provider-transaction", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: "QQ:1001", Conversation: "QQ-Group:2002", Text: ".r 1d1"},
		Scope:   messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:2002", UserID: "QQ:1001"},
		Group: groupstate.State{Version: 1, DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:2002", Active: true,
			DiceIDActive: map[string]bool{endpoint.ID: true}, DiceIDExists: map[string]bool{endpoint.ID: true}, ActivatedExtensions: []string{extension.Name}}.CompatibilityView(),
	}
	result, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != nil {
		result.Release()
	}
	select {
	case value := <-observed:
		if !value {
			t.Fatal("message extension did not receive callback transaction")
		}
	default:
		t.Fatal("message extension was not invoked")
	}
}

func TestDurableCallbackAfterCommitInvalidatesAttributeCache(t *testing.T) {
	instance, endpointInfo, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	legacyManager := instance.AttrsManager
	legacyManager.Stop()
	characterService, _ := newCharacterServiceFixture(t)
	manager := characterService.dice.AttrsManager
	instance.AttrsManager = manager
	instance.DurableStore = characterService.dice.DurableStore
	instance.ImSession.Parent = instance

	ctx := context.Background()
	groupID := "QQ-Group:2002"
	userID := "QQ:1001"
	attributeID := groupID + "-" + manager.UIDConvert(userID)
	values := &ds.ValueMap{}
	values.Store("hp", ds.NewIntVal(1))
	payload, err := ds.NewDictVal(values).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.durable.Save(ctx, attributestate.State{
		DiceID: manager.diceID, ID: attributeID, AttrsType: service.AttrsTypeGroupUser,
		SecretRef: attributestate.SecretRef(manager.diceID, attributeID), CreatedAt: 1, UpdatedAt: 1,
	}, payload); err != nil {
		t.Fatal(err)
	}
	if item, err := manager.Load(groupID, userID); err != nil || item.Load("hp").ToString() != "1" {
		t.Fatalf("preloaded attributes = %v, err=%v", item, err)
	}

	executed := false
	instance.CmdMap["callbackcacheprobe"] = &CmdItemInfo{Name: "callbackcacheprobe", Raw: true,
		Solve: func(messageCtx *MsgContext, _ *Message, _ *CmdArgs) CmdExecuteResult {
			executed = true
			item, loadErr := messageCtx.Dice.AttrsManager.LoadByCtx(messageCtx)
			if loadErr != nil {
				t.Errorf("load callback attributes: %v", loadErr)
			} else {
				item.Store("hp", ds.NewIntVal(2))
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	host := NewDurableCallbackHost(instance)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	request := messageflow.CallbackRequest{
		InboxID: "inbox-cache-update", EndpointID: endpointInfo.ID,
		Message: adapterapi.InboundMessage{
			ProviderEventID: "provider-cache-update",
			Kind:            adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
			Platform: "QQ", Sender: adapterapi.PrincipalID(userID), Conversation: adapterapi.ConversationID(groupID), Target: endpointInfo.UserID, Text: ".callbackcacheprobe",
		},
		Scope: messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: groupID, UserID: userID},
		Group: groupstate.State{
			DiceID: instance.BaseConfig.Name, GroupID: groupID, Active: true,
			DiceIDActive: map[string]bool{endpointInfo.UserID: true}, DiceIDExists: map[string]bool{endpointInfo.UserID: true},
		}.CompatibilityView(),
	}
	result, err := host.HandleCallback(ctx, request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != nil {
		defer result.Release()
	}
	if !executed {
		t.Fatal("cache-update command was not executed")
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	commitErr := func() error {
		if result.CommitFence != nil {
			if !result.CommitFence.TryLock() {
				return errors.New("callback commit fence is busy")
			}
			defer result.CommitFence.Unlock()
		}
		if _, commitErr := instance.DurableStore.Commit(ctx, work); commitErr != nil {
			return commitErr
		}
		if result.AfterCommit != nil {
			result.AfterCommit()
		}
		return nil
	}()
	if commitErr != nil {
		t.Fatal(commitErr)
	}
	item, err := manager.Load(groupID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if got := item.Load("hp").ToString(); got != "2" {
		t.Fatalf("attribute cache after callback commit = %s, want 2", got)
	}
}

func TestDurableCallbackExecutesCommandsAndPreservesSenderRole(t *testing.T) {
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	host := NewDurableCallbackHost(instance)
	for _, tc := range []struct {
		name     string
		text     string
		segments []adapterapi.InboundSegment
		role     string
		level    int
	}{
		{name: "plain text", text: ".callbackprobe value"},
		{name: "structured mention", text: ".callbackprobe value", segments: []adapterapi.InboundSegment{
			{Kind: "mention", ProviderID: endpoint.UserID}, {Kind: "text", Text: " .callbackprobe value"},
		}, role: "admin", level: 50},
		{name: "raw mention", text: "[CQ:at,qq=100000] .callbackprobe value", role: "owner", level: 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executed := false
			instance.CmdMap["callbackprobe"] = &CmdItemInfo{Name: "callbackprobe", Raw: true,
				Solve: func(ctx *MsgContext, _ *Message, args *CmdArgs) CmdExecuteResult {
					executed = true
					if args.GetArgN(1) != "value" || ctx.GroupRoleLevel != tc.level {
						t.Errorf("argument=%q, role level=%d; want value, %d", args.GetArgN(1), ctx.GroupRoleLevel, tc.level)
					}
					return CmdExecuteResult{Matched: true, Solved: true}
				},
			}
			request := messageflow.CallbackRequest{
				InboxID: "callback-command", EndpointID: endpoint.ID,
				Message: adapterapi.InboundMessage{
					Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
					Platform: "QQ", Sender: "QQ:1001", SenderRole: tc.role, Conversation: "QQ-Group:2002",
					Target: endpoint.UserID, Text: tc.text, Segments: tc.segments,
				},
				Scope: messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:2002", UserID: "QQ:1001"},
				Group: groupstate.State{Version: 1, DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:2002", Active: true,
					DiceIDActive: map[string]bool{endpoint.UserID: true}, DiceIDExists: map[string]bool{endpoint.UserID: true}}.CompatibilityView(),
			}
			result, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), messageflow.NewMutationCollector(eventstore.EventFactory{}))
			if err != nil {
				t.Fatal(err)
			}
			if result.Release != nil {
				result.Release()
			}
			if !executed {
				t.Fatal("durable inbound command was not executed")
			}
		})
	}
}

// A group with no recorded state is activated by its first message, as the
// session always did, so the bot answers in groups it was just added to.
func TestDurableCallbackActivatesAGroupWithNoRecordedState(t *testing.T) {
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	host := NewDurableCallbackHost(instance)
	executed := false
	instance.CmdMap["callbackprobe"] = &CmdItemInfo{Name: "callbackprobe", Raw: true,
		Solve: func(*MsgContext, *Message, *CmdArgs) CmdExecuteResult {
			executed = true
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	request := messageflow.CallbackRequest{
		InboxID: "callback-new-group", EndpointID: endpoint.ID,
		Message: adapterapi.InboundMessage{
			Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
			Platform: "QQ", Sender: "QQ:1001", Conversation: "QQ-Group:3003", Target: endpoint.UserID, Text: ".callbackprobe",
		},
		Scope: messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:3003", UserID: "QQ:1001"},
		Group: groupstate.State{}.CompatibilityView(),
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	result, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != nil {
		result.Release()
	}
	if !executed {
		t.Fatal("the first command in a new group was ignored")
	}
	group, ok := instance.ImSession.ServiceAtNew.Load("QQ-Group:3003")
	if !ok || !group.Active {
		t.Fatalf("new group active = %v (found %v)", ok && group.Active, ok)
	}
	if active, _ := group.DiceIDActiveMap.Load(endpoint.UserID); !active {
		t.Fatal("the bot is not active in the new group")
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, stream := range work.Streams {
		recorded = recorded || stream.Stream.AggregateType == "group"
	}
	if !recorded {
		t.Fatal("the activation was not recorded")
	}
}

// A group switched on from the WebUI must stay on: durable callbacks rebuild
// the group from recorded state for every message.
func TestRecordGroupActivationSurvivesTheNextMessage(t *testing.T) {
	ctx := context.Background()
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	keys := groupCardSQLiteKeySource{}
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "group-activation.db"),
		KeySource: keys, DatabaseIdentity: "group-activation-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	d.DurableStore = store

	const groupID = "QQ-Group:4004"
	repository := groupstate.NewRepository(store)
	// Recorded, but never switched on: how first messages created groups.
	if _, err := repository.AppendTyped(ctx, d.BaseConfig.Name, groupID, 0, eventstore.Metadata{
		CommandID: "seed", CorrelationID: "seed", OccurredAt: time.Unix(2, 0).UTC(),
	}, []groupstate.TypedEvent{groupstate.NewGroupCreatedV1(d.BaseConfig.Name, groupID, "Recorded Off", 0)}); err != nil {
		t.Fatal(err)
	}
	load := func() groupstate.State {
		t.Helper()
		state, err := repository.Load(ctx, d.BaseConfig.Name, groupID)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}

	if err := d.RecordGroupActivation(ctx, groupID, []string{endpoint.UserID}, true); err != nil {
		t.Fatal(err)
	}
	on := load()
	if !on.Active || !on.DiceIDActive[endpoint.UserID] {
		t.Fatalf("switched-on state = %#v", on)
	}
	if err := d.RecordGroupActivation(ctx, groupID, []string{endpoint.UserID}, true); err != nil {
		t.Fatal(err)
	}
	if again := load(); again.Version != on.Version {
		t.Fatalf("switching on twice appended events: version %d, want %d", again.Version, on.Version)
	}

	executed := false
	d.CmdMap["activationprobe"] = &CmdItemInfo{Name: "activationprobe", Raw: true,
		Solve: func(*MsgContext, *Message, *CmdArgs) CmdExecuteResult {
			executed = true
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	request := messageflow.CallbackRequest{
		InboxID: "activation-probe", EndpointID: endpoint.ID,
		Message: adapterapi.InboundMessage{
			Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
			Platform: "QQ", Sender: "QQ:1001", Conversation: groupID, Target: endpoint.UserID, Text: ".activationprobe",
		},
		Scope: messageflow.CallbackScope{DiceID: d.BaseConfig.Name, GroupID: groupID, UserID: "QQ:1001"},
		Group: on.CompatibilityView(),
	}
	result, err := NewDurableCallbackHost(d).HandleCallback(ctx, request, playerstate.NewLocalOverlay(), messageflow.NewMutationCollector(eventstore.EventFactory{}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != nil {
		result.Release()
	}
	if !executed {
		t.Fatal("a command in the switched-on group was ignored")
	}

	if err := d.RecordGroupActivation(ctx, groupID, []string{endpoint.UserID}, false); err != nil {
		t.Fatal(err)
	}
	if off := load(); off.Active || off.DiceIDActive[endpoint.UserID] {
		t.Fatalf("switched-off state = %#v", off)
	}
}

func TestRecordGroupActivationIgnoresUnrecordedGroups(t *testing.T) {
	ctx := context.Background()
	d, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	keys := groupCardSQLiteKeySource{}
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "group-activation-missing.db"),
		KeySource: keys, DatabaseIdentity: "group-activation-missing-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	d.DurableStore = eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err := d.RecordGroupActivation(ctx, "QQ-Group:5005", []string{endpoint.UserID}, true); err != nil {
		t.Fatal(err)
	}
	state, err := groupstate.NewRepository(d.DurableStore).Load(ctx, d.BaseConfig.Name, "QQ-Group:5005")
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 0 {
		t.Fatalf("an unrecorded group was created: %#v", state)
	}
}

func TestDurableCallbackDispatchesMessageMutationsWithoutExecutingCommands(t *testing.T) {
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	edited, deleted := 0, 0
	extension := &ExtInfo{Name: "callback-mutations",
		OnMessageEdit:    func(_ *MsgContext, _ *Message) { edited++ },
		OnMessageDeleted: func(_ *MsgContext, _ *Message) { deleted++ },
	}
	instance.RegisterExtension(extension)
	instance.CmdMap["callbackprobe"] = &CmdItemInfo{Name: "callbackprobe", Raw: true,
		Solve: func(_ *MsgContext, _ *Message, _ *CmdArgs) CmdExecuteResult {
			t.Error("message mutation must not execute its text as a command")
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	host := NewDurableCallbackHost(instance)
	for _, kind := range []adapterapi.InboundKind{adapterapi.InboundKindMessageUpdated, adapterapi.InboundKindMessageDeleted} {
		request := messageflow.CallbackRequest{
			InboxID: "callback-mutation", EndpointID: endpoint.ID,
			Message: adapterapi.InboundMessage{Kind: kind, MessageID: "original-message",
				ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: "QQ:1001",
				Conversation: "QQ-Group:2002", Target: endpoint.UserID, Text: ".callbackprobe"},
			Scope: messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:2002", UserID: "QQ:1001"},
			Group: groupstate.State{Version: 1, DiceID: instance.BaseConfig.Name, GroupID: "QQ-Group:2002", Active: true,
				DiceIDActive: map[string]bool{endpoint.UserID: true}, ActivatedExtensions: []string{extension.Name}}.CompatibilityView(),
		}
		result, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), messageflow.NewMutationCollector(eventstore.EventFactory{}))
		if err != nil {
			t.Fatal(err)
		}
		if result.Release != nil {
			result.Release()
		}
	}
	if edited != 1 || deleted != 1 {
		t.Fatalf("mutation hooks: edited=%d deleted=%d, want one of each", edited, deleted)
	}
}
