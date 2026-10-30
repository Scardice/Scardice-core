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

	"Scardice-core/adapterapi"
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
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  t.TempDir() + "/callback-group-refresh.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys := groupInfoRefreshKeySource{}
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode:                 "import",
		SchemaVersion:        1,
		DatabaseIdentity:     "callback-group-refresh-db",
		IndexRootID:          "group-refresh-index-v1",
		EncryptionRootIDs:    []string{"group-refresh-root-v1"},
		SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32),
		CompletedAt:          time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	endpointID := adapterapi.EndpointID(endpoint.ID)
	resolver := groupInfoRefreshResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID:    endpointID,
		AdapterKey:    OnebotAdapterKey,
		DesiredState:  "enabled",
		ObservedState: adapterapi.ObservedStateConnected,
		Capabilities:  adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:       adapterapi.ActionSet(0).With(adapterapi.ActionKindGroupInfoRefresh),
		IndexRootID:   "group-refresh-index-v1",
		IndexSigner:   store,
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	instance.DurableStore = store
	instance.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})
	host := NewDurableCallbackHost(instance)
	groupID := "QQ-Group:2002"
	request := messageflow.CallbackRequest{
		InboxID:    "inbox-group-refresh-1",
		EndpointID: endpoint.ID,
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
		Group: groupstate.State{
			Version:      1,
			DiceID:       instance.BaseConfig.Name,
			GroupID:      groupID,
			Active:       true,
			DiceIDActive: map[string]bool{endpoint.UserID: true},
			DiceIDExists: map[string]bool{endpoint.UserID: true},
		}.CompatibilityView(),
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
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	callbackResult, err := host.HandleCallback(ctx, request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if callbackResult.Release != nil {
		callbackResult.Release()
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Effects) != 1 || len(work.Operations) != 1 {
		t.Fatalf("callback refresh participants = effects:%d operations:%d", len(work.Effects), len(work.Operations))
	}
	persisted := work.Effects[0]
	plain, err := store.DecryptBound(ctx, "outbox/v1", persisted.EffectID, persisted.EndpointID, 1, persisted.PayloadCiphertext, persisted.PayloadNonce, persisted.PayloadEncryptionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}
	if err := json.Unmarshal(plain, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Effect.Payload.Kind != adapterapi.EffectPayloadGroupInfoRefresh ||
		wire.Effect.Payload.Target.Conversation != adapterapi.ConversationID(groupID) {
		t.Fatalf("callback refresh effect = %#v", wire.Effect)
	}
	var storedEffects int64
	if err := database.GORM().Table("outbox_effects").Count(&storedEffects).Error; err != nil {
		t.Fatal(err)
	}
	if storedEffects != 0 {
		t.Fatalf("callback refresh committed outside collector: %d", storedEffects)
	}

	request.InboxID = "inbox-group-refresh-2"
	request.Message.ProviderEventID = "provider-group-refresh-2"
	request.Message.MessageID = "message-group-refresh-2"
	secondCollector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	secondResult, err := host.HandleCallback(ctx, request, playerstate.NewLocalOverlay(), secondCollector)
	if err != nil {
		t.Fatal(err)
	}
	if secondResult.Release != nil {
		secondResult.Release()
	}
	secondWork, err := secondCollector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(secondWork.Effects) != 0 {
		t.Fatalf("cooldown staged duplicate refresh effects: %d", len(secondWork.Effects))
	}
}

func TestDurableCallbackMergesObservedGroupNameAndStagesTypedDiff(t *testing.T) {
	instance, endpoint, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	groupID := "QQ-Group:2002"
	instance.Parent.GroupNameCache.Store(groupID, &GroupNameCacheItem{
		Name: "Observed Group",
		time: time.Now().Unix(),
	})
	host := NewDurableCallbackHost(instance)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	request := messageflow.CallbackRequest{
		InboxID:    "inbox-observed-group-name",
		EndpointID: endpoint.ID,
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
		Group: groupstate.State{
			Version:      1,
			DiceID:       instance.BaseConfig.Name,
			GroupID:      groupID,
			Active:       true,
			DiceIDActive: map[string]bool{endpoint.UserID: true},
			DiceIDExists: map[string]bool{endpoint.UserID: true},
		}.CompatibilityView(),
	}
	callbackResult, err := host.HandleCallback(context.Background(), request, playerstate.NewLocalOverlay(), collector)
	if err != nil {
		t.Fatal(err)
	}
	if callbackResult.Release != nil {
		callbackResult.Release()
	}
	group, ok := instance.ImSession.ServiceAtNew.Load(groupID)
	if !ok || group == nil || group.GroupName != "Observed Group" {
		t.Fatalf("compatibility group after callback = %#v, exists=%t", group, ok)
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
	if !foundNameDiff {
		t.Fatalf("observed group name was not staged as typed group diff: %#v", work.Streams)
	}
}

func TestGroupInfoRefreshObserverBusyHostCachesAndPreservesKnownCounts(t *testing.T) {
	manager := &DiceManager{}
	d := &Dice{
		Parent:      manager,
		Logger:      zap.NewNop().Sugar(),
		DirtyGroups: new(SyncMap[string, int64]),
	}
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	groupID := "QQ-Group:2002"
	group := &GroupInfo{GroupID: groupID, GroupName: "Old Group"}
	d.ImSession.ServiceAtNew.Store(groupID, group)
	manager.GroupNameCache.Store(groupID, &GroupNameCacheItem{
		Name:                "Old Group",
		MemberCount:         40,
		MaxMemberCount:      500,
		MemberCountKnown:    true,
		MaxMemberCountKnown: true,
	})
	host := NewDurableCallbackHost(d)
	notifier := NewGroupInfoRefreshSuccessNotifier(d, host)
	effect := groupInfoRefreshEffect(t, groupID)
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation:     adapterapi.ConversationID(groupID),
		Name:             "Observed Group",
		MemberCount:      45,
		MemberCountKnown: true,
	})

	host.mu.Lock()
	done := make(chan struct{})
	go func() {
		notifier.NotifyOutboundEffectSucceeded(context.Background(), effect, result)
		close(done)
	}()
	select {
	case <-done:
		host.mu.Unlock()
	case <-time.After(time.Second):
		host.mu.Unlock()
		<-done
		t.Fatal("busy callback host blocked the success notifier")
	}

	cached, ok := manager.GroupNameCache.Load(groupID)
	if !ok || cached == nil || cached.Name != "Observed Group" ||
		cached.MemberCount != 45 || !cached.MemberCountKnown ||
		cached.MaxMemberCount != 500 || !cached.MaxMemberCountKnown {
		t.Fatalf("cached group observation = %#v, exists=%t", cached, ok)
	}
	if group.GroupName != "Old Group" {
		t.Fatalf("busy observer mutated compatibility group to %q", group.GroupName)
	}
	if _, dirty := d.DirtyGroups.Load(groupID); dirty {
		t.Fatal("busy observer marked compatibility state dirty")
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

	manager := &DiceManager{}
	d := &Dice{Parent: manager, Logger: zap.NewNop().Sugar(), DirtyGroups: new(SyncMap[string, int64])}
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	membership := new(SyncMap[string, bool])
	membership.Store("QQ:9001", true)
	group := &GroupInfo{
		GroupID:         "QQ-Group:2002",
		GroupName:       "Old Group",
		DiceIDExistsMap: membership,
	}
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)

	NewGroupInfoRefreshSuccessNotifier(d, NewDurableCallbackHost(d)).NotifyOutboundEffectSucceeded(context.Background(), effect, result)

	cached, ok := manager.GroupNameCache.Load(group.GroupID)
	if !ok || cached == nil || cached.Name != "Milky Group" ||
		!cached.MemberCountKnown || cached.MemberCount != 23 || cached.MaxMemberCountKnown {
		t.Fatalf("canonical Milky group cache = %#v, exists=%t", cached, ok)
	}
	if exists, ok := membership.Load("QQ:9001"); !ok || !exists {
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

func TestOnebotGroupInfoRefreshProviderResponseUpdatesCanonicalCache(t *testing.T) {
	manager := &DiceManager{}
	d := &Dice{
		Parent:      manager,
		Logger:      zap.NewNop().Sugar(),
		DirtyGroups: new(SyncMap[string, int64]),
	}
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	group := &GroupInfo{GroupID: "QQ-Group:2002", GroupName: "Old Group"}
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)
	effect := groupInfoRefreshEffect(t, group.GroupID)
	outbound := &onebotOutboundFake{
		rawResponse: []byte(`{"status":"ok","retcode":0,"data":{"group_id":2002,"group_name":"Canonical Group","member_count":45,"max_member_count":500}}`),
	}
	result := (&onebotRuntime{outbound: outbound}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("provider result = %#v", result)
	}

	NewGroupInfoRefreshSuccessNotifier(d, NewDurableCallbackHost(d)).NotifyOutboundEffectSucceeded(context.Background(), effect, result)

	cached, ok := manager.GroupNameCache.Load(group.GroupID)
	if !ok || cached == nil || cached.Name != "Canonical Group" ||
		cached.MemberCount != 45 || cached.MaxMemberCount != 500 ||
		!cached.MemberCountKnown || !cached.MaxMemberCountKnown {
		t.Fatalf("canonical group cache = %#v, exists=%t", cached, ok)
	}
	if group.GroupName != "Canonical Group" {
		t.Fatalf("compatibility group name = %q", group.GroupName)
	}
	if _, dirty := d.DirtyGroups.Load(group.GroupID); !dirty {
		t.Fatal("compatibility group update was not marked dirty")
	}
}

func TestGroupInfoRefreshSuccessNotifierRejectsMismatchedObservation(t *testing.T) {
	manager := &DiceManager{}
	d := &Dice{Parent: manager, Logger: zap.NewNop().Sugar(), DirtyGroups: new(SyncMap[string, int64])}
	d.ImSession = &IMSession{Parent: d, ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	group := &GroupInfo{GroupID: "QQ-Group:2002", GroupName: "Original Group"}
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)
	notifier := NewGroupInfoRefreshSuccessNotifier(d, NewDurableCallbackHost(d))
	result := adapterapi.SucceededGroupInfoResult(adapterapi.GroupInfoResult{
		Conversation:        "QQ-Group:9999",
		Name:                "Wrong Group",
		MemberCount:         1,
		MaxMemberCount:      500,
		MemberCountKnown:    true,
		MaxMemberCountKnown: true,
	})

	notifier.NotifyOutboundEffectSucceeded(context.Background(), groupInfoRefreshEffect(t, group.GroupID), result)

	if _, ok := manager.GroupNameCache.Load(group.GroupID); ok {
		t.Fatal("mismatched observation updated the canonical cache")
	}
	if group.GroupName != "Original Group" {
		t.Fatalf("mismatched observation changed compatibility group to %q", group.GroupName)
	}
}

type groupInfoRefreshKeySource struct{}

func (groupInfoRefreshKeySource) IndexRootID(context.Context) (string, error) {
	return "group-refresh-index-v1", nil
}

func (groupInfoRefreshKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}

func (groupInfoRefreshKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{
		ID:       "group-refresh-root-v1",
		Material: []byte("abcdefghijklmnopqrstuvwxyz123456"),
	}, nil
}

func (groupInfoRefreshKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != "group-refresh-root-v1" {
		return nil, eventstore.ErrKeyUnavailable
	}
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
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

	keys := groupInfoRefreshKeySource{}
	store := eventstore.NewStore(database, eventstore.WithKeySource(keys))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode:                 "import",
		SchemaVersion:        1,
		DatabaseIdentity:     "group-info-refresh-test-db",
		IndexRootID:          "group-refresh-index-v1",
		EncryptionRootIDs:    []string{"group-refresh-root-v1"},
		SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32),
		CompletedAt:          time.Unix(1, 0).UTC(),
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
		IndexRootID:   "group-refresh-index-v1",
		IndexSigner:   store,
	}}
	outbound, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}

	d := &Dice{Logger: zap.NewNop().Sugar(), DurableStore: store}
	session := &IMSession{Parent: d}
	d.ImSession = session
	d.OutboundBridge = NewDurableOutboundBridge(outbound, resolver, eventstore.UUIDGenerator{})
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
		EffectID          string `gorm:"column:effect_id"`
		EndpointID        string `gorm:"column:endpoint_id"`
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		EncryptionKeyID   string `gorm:"column:encryption_key_id"`
	}
	if err := database.GORM().Table("outbox_effects").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	plain, err := store.DecryptBound(ctx, "outbox/v1", row.EffectID, row.EndpointID, 1, row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}
	if err := json.Unmarshal(plain, &wire); err != nil {
		t.Fatal(err)
	}
	if err := wire.Effect.Validate(); err != nil {
		t.Fatalf("persisted refresh effect is invalid: %v", err)
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
