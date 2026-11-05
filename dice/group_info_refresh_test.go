package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestDurableCallbackStagesCooledGroupInfoRefreshWithInboundMutation(t *testing.T) {
	testDurableCallbackStagesCooledGroupInfoRefresh(t, false)
}

func TestDurableJSCallbackStagesGroupInfoRefreshAfterClosingScript(t *testing.T) {
	testDurableCallbackStagesCooledGroupInfoRefresh(t, true)
}

func testDurableCallbackStagesCooledGroupInfoRefresh(t *testing.T, script bool) {
	instance, runtimeEndpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx := context.Background()
	store, ok := instance.DurableStore.(*eventstore.GORMStore)
	if !ok {
		t.Fatal("callback group refresh requires the canonical GORM EventStore")
	}
	projected := projectCallbackTestEndpoint(t, instance, store, runtimeEndpoint)
	endpoint := projected.info
	endpointID := adapterapi.EndpointID(endpoint.ID)
	resolver := groupInfoRefreshResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID:    endpointID,
		AdapterKey:    OnebotAdapterKey,
		DesiredState:  "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindGroupInfoRefresh),
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	instance.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
	host := NewDurableCallbackHost(instance)
	groupID := "QQ-Group:2002"
	seedGroupInfoRefreshCallbackConversation(t, instance, endpoint, groupID, "QQ:1001", "callback-refresh-source")
	request := messageflow.CallbackRequest{
		InboxID: "inbox-group-refresh-1", EndpointID: endpoint.ID,
		Generation: projected.state.Generation, DesiredVersion: projected.state.DesiredVersion,
		Message: adapterapi.InboundMessage{
			ProviderEventID:  "provider-group-refresh-1",
			MessageID:        "message-group-refresh-1",
			Kind:             adapterapi.InboundKindMessage,
			ConversationKind: adapterapi.ConversationKindGroup,
			Platform:         "QQ",
			Sender:           "QQ:1001",
			Conversation:     adapterapi.ConversationID(groupID),
			Target:           endpoint.UserID,
			Text:             "hello",
		},
		Scope: messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: groupID, UserID: "QQ:1001"},
	}
	if script {
		loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
		instance.ExtLoopManager = NewJsLoopManager()
		generation := instance.ExtLoopManager.SetLoop(loop)
		instance.CmdMap["refreshprobe"] = &CmdItemInfo{
			Name: "refreshprobe", Raw: true, JSLoopVersion: generation,
			SolveEngine: func(rt jsengine.Runtime, _ *MsgContext, _ *Message, _ *CmdArgs) (jsengine.Value, error) {
				return rt.RunString("refresh.js", "({matched:true, solved:true})")
			},
		}
		request.Message.Text = ".refreshprobe"
	}
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	callbackResult, err := host.HandleCallback(ctx, request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Effects) != 1 || len(work.Operations) != 1 {
		t.Fatalf("callback refresh participants = effects:%d operations:%d", len(work.Effects), len(work.Operations))
	}
	persisted := work.Effects[0]
	var wire struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}
	if err := json.Unmarshal(persisted.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Effect.Payload.Kind != adapterapi.EffectPayloadGroupInfoRefresh ||
		wire.Effect.Payload.Target.Conversation != adapterapi.ConversationID(groupID) {
		t.Fatalf("callback refresh effect = %#v", wire.Effect)
	}
	hasOutboxWork, err := store.HasOutboxWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hasOutboxWork {
		t.Fatal("callback refresh committed outside its collector")
	}
	commitGroupInfoRefreshCallbackWork(t, store, work, callbackResult)

	request.InboxID = "inbox-group-refresh-2"
	request.Message.ProviderEventID = "provider-group-refresh-2"
	request.Message.MessageID = "message-group-refresh-2"
	// A first-time sender makes the second callback mutate durable state while
	// the group refresh cooldown still suppresses a duplicate effect.
	request.Message.Sender = "QQ:1002"
	request.Scope.UserID = "QQ:1002"
	secondCollector := execution.NewMutationCollector(eventstore.EventFactory{})
	secondResult, err := host.HandleCallback(ctx, request, playerstate.NewLocalOverlay(), secondCollector)
	if err != nil {
		t.Fatal(err)
	}
	secondWork, err := secondCollector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(secondWork.Effects) != 0 {
		t.Fatalf("cooldown staged duplicate refresh effects: %d", len(secondWork.Effects))
	}
	commitGroupInfoRefreshCallbackWork(t, store, secondWork, secondResult)
}

func seedGroupInfoRefreshCallbackConversation(
	t *testing.T,
	d *Dice,
	endpoint *EndPointInfo,
	groupID, userID, label string,
) {
	t.Helper()
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		Platform: "QQ", MessageType: "group", GroupID: groupID,
		Sender: SenderBase{UserID: userID, Nickname: "Refresh Source"},
	}, label, func(ctx *MsgContext) error {
		return ctx.Group.SetActivation(endpoint.UserID, true, true)
	})
}

func commitGroupInfoRefreshCallbackWork(
	t *testing.T,
	store *eventstore.GORMStore,
	work eventstore.UnitOfWork,
	result messageflow.CallbackResult,
) {
	t.Helper()
	locked := false
	if result.CommitFence != nil {
		if !result.CommitFence.TryLock() {
			t.Fatal("callback commit fence is busy")
		}
		locked = true
	}
	_, err := store.Commit(context.Background(), work)
	if err == nil && result.PublishCommitted != nil {
		result.PublishCommitted()
	}
	if locked {
		result.CommitFence.Unlock()
	}
	if err != nil {
		if result.Release != nil {
			result.Release()
		}
		t.Fatalf("commit callback work: %v", err)
	}
	if result.AfterCommit != nil {
		result.AfterCommit()
	}
	if result.Release != nil {
		result.Release()
	}
}

func TestDurableCallbackDoesNotRestageCommittedGroupInfoObservation(t *testing.T) {
	instance, runtimeEndpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	store, ok := instance.DurableStore.(*eventstore.GORMStore)
	if !ok {
		t.Fatal("observed-name callback requires the canonical GORM EventStore")
	}
	projected := projectCallbackTestEndpoint(t, instance, store, runtimeEndpoint)
	endpoint := projected.info
	groupID := "QQ-Group:2002"
	seedGroupInfoRefreshCallbackConversation(t, instance, endpoint, groupID, "QQ:1001", "observed-name-source")
	observation := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation: adapterapi.ConversationID(groupID),
		Name:         "Observed Group",
	})
	NewGroupInfoRefreshSuccessNotifier(instance).
		NotifyOutboundEffectSucceeded(context.Background(), groupInfoRefreshEffect(t, groupID), observation)
	repository := groupstate.NewRepository(store)
	persisted, err := repository.Load(context.Background(), instance.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.GroupName != "Observed Group" {
		t.Fatalf("provider observation was not persisted before callback: %q", persisted.GroupName)
	}
	cached, ok := instance.Parent.GroupNameCache.Load(groupID)
	if !ok || cached == nil || cached.Name != "Observed Group" {
		t.Fatalf("provider observation was not published after persistence: %#v, exists=%t", cached, ok)
	}
	host := NewDurableCallbackHost(instance)
	collector := execution.NewMutationCollector(eventstore.EventFactory{})
	request := messageflow.CallbackRequest{
		InboxID: "inbox-observed-group-name", EndpointID: endpoint.ID,
		Generation: projected.state.Generation, DesiredVersion: projected.state.DesiredVersion,
		Message: adapterapi.InboundMessage{
			ProviderEventID:  "provider-observed-group-name",
			MessageID:        "message-observed-group-name",
			Kind:             adapterapi.InboundKindMessage,
			ConversationKind: adapterapi.ConversationKindGroup,
			Platform:         "QQ",
			Sender:           "QQ:1001",
			Conversation:     adapterapi.ConversationID(groupID),
			Target:           endpoint.UserID,
			Text:             "hello",
		},
		Scope: messageflow.CallbackScope{DiceID: instance.BaseConfig.Name, GroupID: groupID, UserID: "QQ:1001"},
	}
	callbackResult, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	foundNameDiff := false
	for _, stream := range work.Streams {
		for _, event := range stream.Events {
			if event.EventType == string(groupstate.EventGroupNameChanged) {
				foundNameDiff = true
			}
		}
	}
	if foundNameDiff {
		t.Fatalf("callback restaged an already committed provider observation: %#v", work.Streams)
	}
	commitGroupInfoRefreshCallbackWork(t, store, work, callbackResult)
	persisted, err = repository.Load(context.Background(), instance.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.GroupName != "Observed Group" {
		t.Fatalf("persisted observed group name = %q", persisted.GroupName)
	}
}

func TestGroupInfoRefreshObserverPersistsBeforeCacheAndPreservesKnownCounts(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Old Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-observed-group", func(ctx *MsgContext) error {
		return ctx.Group.SetGroupName("Old Group")
	})
	d.Parent.GroupNameCache.Store(groupID, &GroupNameCacheItem{
		Name: "Old Group", MemberCount: 40, MaxMemberCount: 500,
		MemberCountKnown: true, MaxMemberCountKnown: true,
	})
	notifier := NewGroupInfoRefreshSuccessNotifier(d)
	effect := groupInfoRefreshEffect(t, groupID)
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation: adapterapi.ConversationID(groupID), Name: "Observed Group",
		MemberCount: 45, MemberCountKnown: true,
	})

	notifier.NotifyOutboundEffectSucceeded(context.Background(), effect, result)

	persisted, err := groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.GroupName != "Observed Group" {
		t.Fatalf("persisted group name = %q, want Observed Group", persisted.GroupName)
	}
	cached, ok := d.Parent.GroupNameCache.Load(groupID)
	if !ok || cached == nil || cached.Name != "Observed Group" ||
		cached.MemberCount != 45 || !cached.MemberCountKnown ||
		cached.MaxMemberCount != 500 || !cached.MaxMemberCountKnown {
		t.Fatalf("cached group observation = %#v, exists=%t", cached, ok)
	}

	version := persisted.Version
	notifier.NotifyOutboundEffectSucceeded(context.Background(), effect, result)
	persisted, err = groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Version != version {
		t.Fatalf("duplicate observation advanced group version from %d to %d", version, persisted.Version)
	}
}

func groupInfoRefreshEffect(t *testing.T, groupID string) adapterapi.OutboundEffect {
	t.Helper()
	return outboundEffectForTest(t, adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadGroupInfoRefresh,
		Target: adapterapi.EffectTarget{
			Kind:         adapterapi.TargetGroup,
			Conversation: adapterapi.ConversationID(groupID),
		},
	}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindGroupInfoRefresh)
}

func TestOnebotGroupInfoRefreshReturnsTypedProviderObservation(t *testing.T) {
	outbound := &onebotOutboundFake{
		rawResponse: []byte(`{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"Renamed Group","member_count":12,"max_member_count":500}}`),
	}

	result := (&onebotRuntime{outbound: outbound}).Execute(context.Background(), groupInfoRefreshEffect(t, "QQ-Group:2002"))

	if result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
		t.Fatalf("group refresh result = %#v", result)
	}
	got := result.GroupInfo
	if got.Conversation != "QQ-Group:2002" || got.Name != "Renamed Group" ||
		got.MemberCount != 12 || got.MaxMemberCount != 500 ||
		!got.MemberCountKnown || !got.MaxMemberCountKnown {
		t.Fatalf("group observation = %#v", got)
	}
	if outbound.rawAction != "get_group_info" {
		t.Fatalf("group refresh action = %q", outbound.rawAction)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("typed group refresh result is invalid: %v", err)
	}
}

func TestOnebotGroupInfoRefreshRejectsMismatchedProviderGroup(t *testing.T) {
	outbound := &onebotOutboundFake{
		rawResponse: []byte(`{"status":"ok","retcode":0,"data":{"group_id":9999,"group_name":"Wrong Group","member_count":1,"max_member_count":500}}`),
	}

	result := (&onebotRuntime{outbound: outbound}).Execute(context.Background(), groupInfoRefreshEffect(t, "QQ-Group:2002"))

	if result.Outcome == adapterapi.EffectSucceeded || result.GroupInfo != nil {
		t.Fatalf("mismatched provider group reported success: %#v", result)
	}
}

func TestOnebotGroupInfoRefreshMissingCountsRemainUnknown(t *testing.T) {
	outbound := &onebotOutboundFake{
		rawResponse: []byte(`{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"Countless Group"}}`),
	}

	result := (&onebotRuntime{outbound: outbound}).Execute(context.Background(), groupInfoRefreshEffect(t, "QQ-Group:2002"))

	if result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
		t.Fatalf("group refresh result = %#v", result)
	}
	if result.GroupInfo.MemberCountKnown || result.GroupInfo.MaxMemberCountKnown {
		t.Fatalf("missing provider counts reported as known: %#v", result.GroupInfo)
	}
}

func TestMilkyGroupInfoRefreshReturnsTypedProviderObservation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/get_group_info" {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer runtime-token" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			GroupID int64 `json:"group_id"`
			NoCache bool  `json:"no_cache"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.GroupID != 2002 || !body.NoCache {
			http.Error(writer, "bad group refresh request", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"Milky Group","member_count":23,"max_member_count":1000}}`))
	}))
	defer server.Close()

	runtime := &milkyRuntime{
		config:     milkyCanonicalConfig{RESTGateway: server.URL},
		httpClient: server.Client(),
		token:      "runtime-token",
		selfID:     9001,
	}
	result := runtime.Execute(context.Background(), groupInfoRefreshEffect(t, "QQ-Group:2002"))

	if result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
		t.Fatalf("group refresh result = %#v", result)
	}
	got := result.GroupInfo
	if got.Conversation != "QQ-Group:2002" || got.Name != "Milky Group" ||
		got.MemberCount != 23 || got.MaxMemberCount != 1000 ||
		!got.MemberCountKnown || !got.MaxMemberCountKnown {
		t.Fatalf("group observation = %#v", got)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("typed group refresh result is invalid: %v", err)
	}
}

func TestMilkyGroupInfoRefreshMissingMaxDoesNotImplyDeparture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"Milky Group","member_count":23}}`))
	}))
	defer server.Close()

	runtime := &milkyRuntime{
		config:     milkyCanonicalConfig{RESTGateway: server.URL},
		httpClient: server.Client(),
		token:      "runtime-token",
		selfID:     9001,
	}
	effect := groupInfoRefreshEffect(t, "QQ-Group:2002")
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
		t.Fatalf("group refresh result = %#v", result)
	}
	if result.GroupInfo.MaxMemberCountKnown || result.GroupInfo.MaxMemberCount != 0 {
		t.Fatalf("missing maximum was reported as known: %#v", result.GroupInfo)
	}

	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Old Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-milky-observation", func(ctx *MsgContext) error {
		return ctx.Group.SetActivation(endpoint.UserID, true, true)
	})

	NewGroupInfoRefreshSuccessNotifier(d).NotifyOutboundEffectSucceeded(context.Background(), effect, result)

	cached, ok := d.Parent.GroupNameCache.Load(groupID)
	if !ok || cached == nil || cached.Name != "Milky Group" ||
		!cached.MemberCountKnown || cached.MemberCount != 23 || cached.MaxMemberCountKnown {
		t.Fatalf("canonical Milky group cache = %#v, exists=%t", cached, ok)
	}
	persisted, err := groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.DiceIDExists[endpoint.UserID] {
		t.Fatal("unknown maximum count removed known endpoint membership")
	}
}

func TestMilkyGroupInfoRefreshRejectsInvalidProviderResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","retcode":0,"data":{"group_id":9999,"group_name":"Wrong Group","member_count":-1,"max_member_count":1000}}`))
	}))
	defer server.Close()

	runtime := &milkyRuntime{
		config:     milkyCanonicalConfig{RESTGateway: server.URL},
		httpClient: server.Client(),
		token:      "runtime-token",
		selfID:     9001,
	}
	result := runtime.Execute(context.Background(), groupInfoRefreshEffect(t, "QQ-Group:2002"))

	if result.Outcome == adapterapi.EffectSucceeded || result.GroupInfo != nil {
		t.Fatalf("invalid provider group info reported success: %#v", result)
	}
}

func TestMilkyGroupInfoRefreshProviderFailureIsRetryable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "temporary failure", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	runtime := &milkyRuntime{
		config:     milkyCanonicalConfig{RESTGateway: server.URL},
		httpClient: server.Client(),
		token:      "runtime-token",
		selfID:     9001,
	}
	result := runtime.Execute(context.Background(), groupInfoRefreshEffect(t, "QQ-Group:2002"))

	if result.Outcome != adapterapi.EffectRetryable {
		t.Fatalf("idempotent refresh failure outcome = %q, want retryable", result.Outcome)
	}
}

func TestOnebotGroupInfoRefreshProviderResponseUpdatesCanonicalState(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Old Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-provider-observation", func(*MsgContext) error { return nil })
	effect := groupInfoRefreshEffect(t, groupID)
	outbound := &onebotOutboundFake{
		rawResponse: []byte(`{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"Canonical Group","member_count":45,"max_member_count":500}}`),
	}
	result := (&onebotRuntime{outbound: outbound}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("provider result = %#v", result)
	}

	NewGroupInfoRefreshSuccessNotifier(d).NotifyOutboundEffectSucceeded(context.Background(), effect, result)

	persisted, err := groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.GroupName != "Canonical Group" {
		t.Fatalf("persisted group name = %q", persisted.GroupName)
	}
	cached, ok := d.Parent.GroupNameCache.Load(groupID)
	if !ok || cached == nil || cached.Name != "Canonical Group" ||
		cached.MemberCount != 45 || cached.MaxMemberCount != 500 ||
		!cached.MemberCountKnown || !cached.MaxMemberCountKnown {
		t.Fatalf("canonical group cache = %#v, exists=%t", cached, ok)
	}
}

func TestGroupInfoRefreshSuccessNotifierRejectsMismatchedObservation(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Original Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-mismatch-observation", func(ctx *MsgContext) error { return ctx.Group.SetGroupName("Original Group") })
	notifier := NewGroupInfoRefreshSuccessNotifier(d)
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation: "QQ-Group:9999", Name: "Wrong Group",
		MemberCount: 1, MaxMemberCount: 500,
		MemberCountKnown: true, MaxMemberCountKnown: true,
	})

	notifier.NotifyOutboundEffectSucceeded(context.Background(), groupInfoRefreshEffect(t, groupID), result)

	if _, ok := d.Parent.GroupNameCache.Load(groupID); ok {
		t.Fatal("mismatched observation updated the canonical cache")
	}
	persisted, err := groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.GroupName != "Original Group" {
		t.Fatalf("mismatched observation changed canonical group to %q", persisted.GroupName)
	}
}

func TestGroupInfoRefreshSuccessNotifierDoesNotCacheFailedPersistence(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	store.RegisterParticipant(func(_ context.Context, tx *gorm.DB, _ eventstore.UnitOfWork) error {
		return tx.Exec(`
			CREATE TRIGGER IF NOT EXISTS reject_group_info_write
			BEFORE INSERT ON domain_events
			WHEN NEW.aggregate_type = 'group' AND NEW.event_type = 'group.name_changed'
			BEGIN SELECT RAISE(ABORT, 'rejected_group_info_write'); END
		`).Error
	})
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Original Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-group-before-rejected-observation", func(ctx *MsgContext) error {
		return ctx.Group.SetGroupName("Original Group")
	})
	d.Parent.GroupNameCache.Store(groupID, &GroupNameCacheItem{Name: "Original Group"})
	core, observed := observer.New(zapcore.ErrorLevel)
	d.Logger = zap.New(core).Sugar()
	notifier := NewGroupInfoRefreshSuccessNotifier(d)
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation: adapterapi.ConversationID(groupID), Name: "Uncommitted Group",
	})

	notifier.NotifyOutboundEffectSucceeded(context.Background(), groupInfoRefreshEffect(t, groupID), result)

	persisted, err := groupstate.ReadProjected(context.Background(), store, d.BaseConfig.Name, groupID)
	if err != nil || persisted.GroupName != "Original Group" {
		t.Fatalf("rejected observation changed committed group: %#v, err=%v", persisted, err)
	}
	if cached, ok := d.Parent.GroupNameCache.Load(groupID); !ok || cached.Name != "Original Group" {
		t.Fatalf("failed persistence published cache authority: %#v, exists=%t", cached, ok)
	}
	if observed.FilterMessageSnippet("eventstore: insert domain events failed").Len() == 0 {
		t.Error("group observation did not report the rejected SQLite insert")
	}
}

func TestGroupInfoRefreshSuccessNotifierRespectsCanceledOwner(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Original Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-group-before-canceled-observation", func(ctx *MsgContext) error {
		return ctx.Group.SetGroupName("Original Group")
	})
	d.Parent.GroupNameCache.Store(groupID, &GroupNameCacheItem{Name: "Original Group"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation: adapterapi.ConversationID(groupID), Name: "Canceled Group",
	})

	NewGroupInfoRefreshSuccessNotifier(d).NotifyOutboundEffectSucceeded(ctx, groupInfoRefreshEffect(t, groupID), result)

	persisted, err := groupstate.ReadProjected(context.Background(), store, d.BaseConfig.Name, groupID)
	if err != nil || persisted.GroupName != "Original Group" {
		t.Fatalf("canceled notification changed committed group: %#v, err=%v", persisted, err)
	}
	if cached, ok := d.Parent.GroupNameCache.Load(groupID); !ok || cached.Name != "Original Group" {
		t.Fatalf("canceled notification changed cache: %#v, exists=%t", cached, ok)
	}
}

func TestGroupInfoRefreshSuccessNotifierIgnoresStaleObservation(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	endpoint := newCanonicalTestEndpoint(d, "QQ:9001")
	groupID := "QQ-Group:2002"
	withCanonicalTestMessageContext(t, d, endpoint, &Message{
		MessageType: "group", GroupID: groupID, GroupName: "Fresh Group",
		Sender: SenderBase{UserID: "QQ:1001", Nickname: "Alice"},
	}, "seed-fresh-observation", func(ctx *MsgContext) error { return ctx.Group.SetGroupName("Fresh Group") })
	d.Parent.GroupNameCache.Store(groupID, &GroupNameCacheItem{Name: "Fresh Group", time: time.Now().Unix()})
	effect := groupInfoRefreshEffect(t, groupID)
	effect.Deadline = time.Now().Add(-time.Hour)
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation: adapterapi.ConversationID(groupID), Name: "Stale Group",
	})

	NewGroupInfoRefreshSuccessNotifier(d).NotifyOutboundEffectSucceeded(context.Background(), effect, result)

	persisted, err := groupstate.NewRepository(store).Load(context.Background(), d.BaseConfig.Name, groupID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.GroupName != "Fresh Group" {
		t.Fatalf("stale observation changed canonical name to %q", persisted.GroupName)
	}
	cached, _ := d.Parent.GroupNameCache.Load(groupID)
	if cached == nil || cached.Name != "Fresh Group" {
		t.Fatalf("stale observation changed display cache: %#v", cached)
	}
}

type groupInfoRefreshResolver struct {
	snapshot messageflow.EndpointSnapshot
}

func (r groupInfoRefreshResolver) Resolve(context.Context, adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	return r.snapshot, nil
}

type groupInfoRefreshLegacyAdapter struct {
	PlatformAdapter
	groupIDs []string
}

func (a *groupInfoRefreshLegacyAdapter) GetGroupInfoAsync(groupID string) {
	a.groupIDs = append(a.groupIDs, groupID)
}

func TestEndPointGetGroupInfoAsyncPersistsDurableRefreshWithoutAdapter(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  t.TempDir() + "/group-info-refresh.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	store := eventstore.NewStore(database)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode:             "import",
		SchemaVersion:    2,
		DatabaseIdentity: "group-info-refresh-test-db",
		CompletedAt:      time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	endpointID := adapterapi.EndpointID("endpoint-group-refresh")
	resolver := groupInfoRefreshResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID:    endpointID,
		AdapterKey:    OnebotAdapterKey,
		DesiredState:  "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindGroupInfoRefresh),
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}

	d := &Dice{Logger: zap.NewNop().Sugar(), DurableStore: store}
	session := &IMSession{Parent: d}
	d.ImSession = session
	d.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{}, newBridgeTestNotificationOwner(t))
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID:           string(endpointID),
		UserID:       "QQ:9001",
		Platform:     "QQ",
		ProtocolType: string(OnebotAdapterKey),
		Enable:       true,
		State:        StateConnected,
		Session:      session,
	}}
	if endpoint.Adapter != nil {
		t.Fatal("durable endpoint unexpectedly has a legacy adapter")
	}

	endpoint.GetGroupInfoAsync("QQ-Group:2002")

	var counts struct {
		Events     int64
		Operations int64
		Effects    int64
	}
	if err := database.GORM().Table("domain_events").Count(&counts.Events).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.GORM().Table("operations").Count(&counts.Operations).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.GORM().Table("outbox_effects").Count(&counts.Effects).Error; err != nil {
		t.Fatal(err)
	}
	if counts.Events != 1 || counts.Operations != 1 || counts.Effects != 1 {
		t.Fatalf("durable participants = events:%d operations:%d effects:%d", counts.Events, counts.Operations, counts.Effects)
	}

	var row struct {
		EffectID   string `gorm:"column:effect_id"`
		EndpointID string `gorm:"column:endpoint_id"`
		Subject    string `gorm:"column:subject"`
		Payload    []byte `gorm:"column:payload"`
	}
	if err := database.GORM().Table("outbox_effects").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}
	if err := json.Unmarshal(row.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	if err := wire.Effect.Validate(); err != nil {
		t.Fatalf("persisted refresh effect is invalid: %v", err)
	}
	if string(wire.Effect.ID) != row.EffectID || string(wire.Effect.EndpointID) != row.EndpointID || row.Subject != "QQ-Group:2002" {
		t.Fatalf("persisted refresh effect identity mismatch: row=%#v effect=%#v", row, wire.Effect)
	}
	payload := wire.Effect.Payload
	if wire.Effect.Kind != adapterapi.EffectKindAction ||
		wire.Effect.RequiredCapabilities != adapterapi.CapabilityOutbound|adapterapi.CapabilityActions ||
		wire.Effect.RequiredAction != adapterapi.ActionKindGroupInfoRefresh ||
		wire.Effect.RetryClass != adapterapi.EffectRetryProviderIdempotent ||
		wire.Effect.Risk != adapterapi.EffectRiskNormal ||
		payload.Kind != adapterapi.EffectPayloadGroupInfoRefresh ||
		payload.Target.Kind != adapterapi.TargetGroup ||
		payload.Target.Conversation != "QQ-Group:2002" {
		t.Fatalf("persisted refresh effect = %#v", wire.Effect)
	}

	endpoint.GetGroupInfoAsync("QQ-Group:2002")
	var repeatedEffects int64
	if err := database.GORM().Table("outbox_effects").Count(&repeatedEffects).Error; err != nil {
		t.Fatal(err)
	}
	if repeatedEffects != 2 {
		t.Fatalf("distinct refresh requests persisted effects = %d, want 2", repeatedEffects)
	}
}

func TestEndPointGetGroupInfoAsyncPreservesLegacyAdapterPath(t *testing.T) {
	adapter := &groupInfoRefreshLegacyAdapter{}
	d := &Dice{Logger: zap.NewNop().Sugar()}
	session := &IMSession{Parent: d}
	endpoint := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID: "legacy-endpoint", Enable: true, State: StateConnected, Session: session,
		},
		Adapter: adapter,
	}

	endpoint.GetGroupInfoAsync("legacy-group")

	if len(adapter.groupIDs) != 1 || adapter.groupIDs[0] != "legacy-group" {
		t.Fatalf("legacy refresh calls = %#v", adapter.groupIDs)
	}
}

func TestEndPointGetGroupInfoAsyncFailsClosedWhenDurableActionUnsupported(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	adapter := &groupInfoRefreshLegacyAdapter{}
	d := &Dice{
		Logger:         zap.New(core).Sugar(),
		OutboundBridge: NewFailClosedOutboundBridge(),
	}
	session := &IMSession{Parent: d}
	endpoint := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID: "durable-startup-endpoint", Enable: true, State: StateConnected, Session: session,
		},
		Adapter: adapter,
	}

	endpoint.GetGroupInfoAsync("QQ-Group:2002")

	if len(adapter.groupIDs) != 0 {
		t.Fatalf("unsupported durable refresh fell back to legacy adapter: %#v", adapter.groupIDs)
	}
	if logs.Len() == 0 {
		t.Fatal("unsupported durable refresh was not reported")
	}
}

func TestEndPointGetGroupInfoAsyncRejectsDisabledEndpoint(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	adapter := &groupInfoRefreshLegacyAdapter{}
	d := &Dice{Logger: zap.New(core).Sugar()}
	endpoint := &EndPointInfo{
		EndPointInfoBase: EndPointInfoBase{
			ID: "disabled-endpoint", Enable: false, State: StateDisconnected,
			Session: &IMSession{Parent: d},
		},
		Adapter: adapter,
	}

	endpoint.GetGroupInfoAsync("QQ-Group:2002")

	if len(adapter.groupIDs) != 0 {
		t.Fatalf("disabled endpoint refreshed through legacy adapter: %#v", adapter.groupIDs)
	}
	if logs.Len() == 0 {
		t.Fatal("disabled endpoint refresh was not reported")
	}
}
