package dice

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/message"
)

// ErrUnsupportedDurableInboundKind reports callback kinds without a legacy handler.
var ErrUnsupportedDurableInboundKind = errors.New("dice: unsupported durable inbound kind")

// DurableCallbackScopeResolver maps provider-neutral ingress onto the single
// Core instance selected by main. Private conversations use the same synthetic
// group identity as the legacy command engine.
type DurableCallbackScopeResolver struct {
	dice *Dice
}

func NewDurableCallbackScopeResolver(instance *Dice) *DurableCallbackScopeResolver {
	return &DurableCallbackScopeResolver{dice: instance}
}

func (r *DurableCallbackScopeResolver) Resolve(_ context.Context, endpointID string, message adapterapi.InboundMessage) (messageflow.CallbackScope, error) {
	if r == nil || r.dice == nil || r.dice.BaseConfig.Name == "" {
		return messageflow.CallbackScope{}, messageflow.ErrCallbackScope
	}
	userID := string(message.Sender)
	if userID == "" {
		userID = "system:" + endpointID
	}
	var groupID string
	switch message.ConversationKind {
	case adapterapi.ConversationKindDirect:
		groupID = "PG-" + userID
	case adapterapi.ConversationKindGroup:
		groupID = string(message.Conversation)
		if groupID == "" {
			return messageflow.CallbackScope{}, messageflow.ErrCallbackScope
		}
	default:
		return messageflow.CallbackScope{}, messageflow.ErrCallbackScope
	}
	if groupstate.ValidatePlayerIdentity(r.dice.BaseConfig.Name, groupID, userID) != nil {
		return messageflow.CallbackScope{}, messageflow.ErrCallbackScope
	}
	return messageflow.CallbackScope{DiceID: r.dice.BaseConfig.Name, GroupID: groupID, UserID: userID}, nil
}

// DurableCallbackHost serializes the complete snapshot→execution→commit cycle
// across endpoint lanes; mu separately protects direct legacy cache access.
type DurableCallbackHost struct {
	dice      *Dice
	mu        sync.Mutex
	admission sync.Mutex
}

func NewDurableCallbackHost(instance *Dice) *DurableCallbackHost {
	return &DurableCallbackHost{dice: instance}
}

func (h *DurableCallbackHost) BeginCallback(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	if h.admission.TryLock() {
		return ctx, h.admission.Unlock, nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx, nil, ctx.Err()
		case <-ticker.C:
			if h.admission.TryLock() {
				return ctx, h.admission.Unlock, nil
			}
		}
	}
}

// InvalidateGroup removes the legacy compatibility view while the privacy
// service owns the subject fence. The mutex excludes an in-flight callback.
func (h *DurableCallbackHost) InvalidateGroup(_ context.Context, groupID string) error {
	if h == nil || h.dice == nil || h.dice.ImSession == nil || groupID == "" {
		return messageflow.ErrCallbackUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if manager := h.dice.AttrsManager; manager != nil {
		manager.callbackGate.Lock()
		defer manager.callbackGate.Unlock()
		manager.DeleteCachedGroupData(groupID, true, true)
	}
	h.dice.ImSession.ServiceAtNew.Delete(groupID)
	return nil
}

func (h *DurableCallbackHost) HandleCallback(ctx context.Context, request messageflow.CallbackRequest, _ *playerstate.LocalOverlay, collector *messageflow.MutationCollector) (messageflow.CallbackResult, error) {
	if h == nil || h.dice == nil || h.dice.ImSession == nil || collector == nil {
		return messageflow.CallbackResult{}, messageflow.ErrCallbackUnavailable
	}
	if err := ctx.Err(); err != nil {
		return messageflow.CallbackResult{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	manager := h.dice.AttrsManager
	gateLocked := false
	if manager != nil {
		manager.callbackGate.Lock()
		gateLocked = true
	}
	defer func() {
		if gateLocked {
			manager.callbackGate.Unlock()
		}
	}()
	if err := ctx.Err(); err != nil {
		return messageflow.CallbackResult{}, err
	}
	if request.Scope.DiceID != h.dice.BaseConfig.Name {
		return messageflow.CallbackResult{}, messageflow.ErrCallbackScope
	}
	if request.Message.History != adapterapi.InboundHistoryNone {
		state, eligible, err := h.historyLogState(request)
		if err != nil || !eligible {
			return messageflow.CallbackResult{}, err
		}
		if request.Message.History == adapterapi.InboundHistoryRecordOnly {
			return h.recordHistoryMessage(request, state, collector)
		}
	}
	session := h.dice.ImSession
	var transaction *DurableCallbackTransaction
	if h.dice.DurableStore != nil {
		var err error
		transaction, err = NewDurableCallbackTransaction(h.dice.DurableStore, collector)
		if err != nil {
			return messageflow.CallbackResult{}, err
		}
		transaction.executionContext = ctx
	}
	metadata := callbackMetadata(request)
	// Names are remembered first so the group projected below already carries its name.
	h.rememberNames(request.Message)
	if request.Group.Version == 0 && request.Message.Kind == adapterapi.InboundKindMessage && request.Message.ConversationKind == adapterapi.ConversationKindGroup {
		// A group with no recorded state is left to the session, which
		// activates it on its first message as it always has; the difference
		// against the empty state is recorded below like any other change.
		session.ServiceAtNew.Delete(request.Scope.GroupID)
	} else {
		session.ServiceAtNew.Store(request.Scope.GroupID, compatibilityGroupFromState(h.dice, request.Group.State, request.Player.PlayerState, request.Scope))
	}
	endpoint := compatibilityCallbackEndpoint(session, request)
	message := compatibilityCallbackMessage(request)
	var execution messageExecutionResult
	refreshGroupInfo := true
	switch request.Message.Kind {
	case adapterapi.InboundKindMessage:
		execution = session.executeMessage(endpoint, message, messageExecutionOptions{parser: messageParserSegments, runInSync: true, callbackTransaction: transaction, callbackMetadata: metadata})
	case adapterapi.InboundKindMessageUpdated, adapterapi.InboundKindMessageDeleted:
		mctx := &MsgContext{
			Dice: h.dice, Session: session, EndPoint: endpoint,
			MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
			callbackTransaction: transaction, callbackMetadata: metadata,
		}
		mctx.Group, mctx.Player = GetPlayerInfoBySender(mctx, message)
		mctx.fillPrivilege(message)
		if request.Message.Kind == adapterapi.InboundKindMessageUpdated {
			session.OnMessageEdit(mctx, message)
		} else {
			session.OnMessageDeleted(mctx, message)
		}
		execution.context = mctx
	case adapterapi.InboundKindNotice, adapterapi.InboundKindRequest:
		var err error
		execution.context, refreshGroupInfo, err = h.handleInboundEvent(request, session, endpoint, message, transaction, metadata)
		if err != nil {
			return messageflow.CallbackResult{}, err
		}
	case adapterapi.InboundKindAdapterEvent:
		if request.Message.AdapterEvent == nil {
			return messageflow.CallbackResult{}, adapterapi.ErrInvalidContract
		}
		mctx := &MsgContext{
			Dice: h.dice, Session: session, EndPoint: endpoint,
			MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
			callbackTransaction: transaction, callbackMetadata: metadata,
		}
		execution.context = mctx
		refreshGroupInfo = false
	default:
		return messageflow.CallbackResult{}, ErrUnsupportedDurableInboundKind
	}
	if execution.context != nil {
		defer execution.context.releaseExecutionState()
		if request.Message.AdapterEvent != nil {
			h.bindAdapterEventConversation(execution.context, request.Scope)
			execution.context.fillPrivilege(message)
			if err := h.dice.dispatchAdapterEvent(execution.context, execution.context, *request.Message.AdapterEvent, endpoint); err != nil {
				return messageflow.CallbackResult{}, err
			}
		}
		if err := execution.context.stopJSExecution(); err != nil {
			return messageflow.CallbackResult{}, err
		}
	}

	if refreshGroupInfo {
		h.stageGroupInfoRefresh(ctx, request, execution.context)
	}

	group, ok := session.ServiceAtNew.Load(request.Scope.GroupID)
	if !ok || group == nil {
		return messageflow.CallbackResult{}, errors.New("dice: callback did not produce group state")
	}
	groupEvents := compatibilityGroupEvents(request.Group.State, request.Scope, group)
	if len(groupEvents) > 0 {
		stream := groupstate.GroupStream(request.Scope.DiceID, request.Scope.GroupID)
		if transaction != nil {
			if err := transaction.stageGroupEvents(stream, request.Group.Version, metadata, groupEvents); err != nil {
				return messageflow.CallbackResult{}, err
			}
		} else if err := collector.AddGroupEvents(stream, request.Group.Version, metadata, groupEvents); err != nil {
			return messageflow.CallbackResult{}, err
		}
	}
	player, _ := group.Players.Load(request.Scope.UserID)
	playerEvents := compatibilityPlayerEvents(request.Player.PlayerState, request.Scope, player)
	if len(playerEvents) > 0 {
		if err := collector.AddPlayerEvents(playerstate.PlayerStream(request.Scope.DiceID, request.Scope.GroupID, request.Scope.UserID), request.Player.Version, metadata, playerEvents); err != nil {
			return messageflow.CallbackResult{}, err
		}
	}
	if transaction != nil {
		if err := transaction.Finalize(ctx); err != nil {
			return messageflow.CallbackResult{}, err
		}
	}
	var (
		callbacks           []func()
		commitFence         callbackCommitFence
		changedAttributeIDs []string
	)
	if transaction != nil {
		callbacks = append(callbacks, transaction.callbackAfterCommit...)
		commitFence = transaction.callbackCommitFence
		changedAttributeIDs = transaction.ChangedAttributeIDs()
	}
	result := messageflow.CallbackResult{
		CommitFence: commitFence,
		AfterCommit: func() {
			for _, callback := range callbacks {
				callback()
			}
			if manager != nil {
				manager.InvalidateCachedAttributes(changedAttributeIDs)
			}
		},
	}
	if gateLocked {
		gateLocked = false
		result.Release = manager.callbackGate.Unlock
	}
	return result, nil
}

func (h *DurableCallbackHost) stageGroupInfoRefresh(ctx context.Context, request messageflow.CallbackRequest, mctx *MsgContext) {
	if h == nil || h.dice == nil || h.dice.Parent == nil ||
		request.Message.ConversationKind != adapterapi.ConversationKindGroup ||
		mctx == nil || mctx.EndPoint == nil || !mctx.EndPoint.Enable ||
		mctx.callbackTransaction == nil {
		return
	}
	bridge, ok := h.dice.OutboundBridge.(*DurableOutboundBridge)
	if !ok || bridge == nil {
		return
	}
	groupID := strings.TrimSpace(request.Scope.GroupID)
	if groupID == "" || !h.dice.Parent.ShouldRefreshGroupInfo(groupID) {
		return
	}
	target := adapterapi.EffectTarget{
		Kind:         adapterapi.TargetGroup,
		Conversation: adapterapi.ConversationID(groupID),
	}
	if err := target.Validate(); err != nil {
		log := h.dice.Logger
		if log == nil {
			log = logger.M()
		}
		log.Errorf("群信息刷新失败：callback 群组目标无效: %v", err)
		return
	}
	// Host 扫尾仍加入原事务，但不能复用已撤销的脚本执行权限。
	finalizationContext := &MsgContext{
		Dice: h.dice, EndPoint: mctx.EndPoint,
		callbackTransaction: mctx.callbackTransaction, callbackMetadata: mctx.callbackMetadata,
	}
	if err := bridge.submitAction(ctx, finalizationContext, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupInfoRefresh,
		Target: target,
	}, nil); err != nil {
		log := h.dice.Logger
		if log == nil {
			log = logger.M()
		}
		log.Errorf("群信息刷新失败：callback durable 动作提交失败: %v", err)
	}
}

func compatibilityCallbackEndpoint(session *IMSession, request messageflow.CallbackRequest) *EndPointInfo {
	for _, endpoint := range session.EndPointsReadOnly() {
		if endpoint != nil && endpoint.ID == request.EndpointID {
			endpoint.Session = session
			return endpoint
		}
	}
	userID := request.Message.Target
	if userID == "" {
		userID = request.EndpointID
	}
	return &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID: request.EndpointID, UserID: userID, Platform: request.Message.Platform,
		Enable: true, State: StateConnected, Session: session,
	}}
}

func compatibilityCallbackMessage(request messageflow.CallbackRequest) *Message {
	messageType := "private"
	groupID := ""
	if request.Message.ConversationKind == adapterapi.ConversationKindGroup {
		messageType = "group"
		groupID = string(request.Message.Conversation)
	}
	occurredAt := request.Message.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return &Message{
		Time: occurredAt.Unix(), MessageType: messageType, GroupID: groupID,
		Sender: SenderBase{UserID: request.Scope.UserID, Nickname: request.Message.SenderName, GroupRole: request.Message.SenderRole}, Message: request.Message.Text,
		Segment: compatibilityCallbackSegments(request.Message),
		RawID:   string(request.Message.MessageID), Platform: request.Message.Platform,
		Seq:       request.Message.Sequence,
		recovered: request.Message.History != adapterapi.InboundHistoryNone,
	}
}

func compatibilityCallbackSegments(inbound adapterapi.InboundMessage) []message.IMessageElement {
	if len(inbound.Segments) == 0 {
		return appendCallbackTextSegments(nil, inbound.Text, inbound.Platform)
	}
	segments := make([]message.IMessageElement, 0, len(inbound.Segments))
	for _, segment := range inbound.Segments {
		switch segment.Kind {
		case "text":
			segments = appendCallbackTextSegments(segments, segment.Text, inbound.Platform)
		case "at", "mention":
			target := strings.TrimPrefix(segment.ProviderID, inbound.Platform+":")
			segments = append(segments, &message.AtElement{Target: target, IsRobot: inbound.Platform == "QQ" && isQQBotUserID("QQ:"+target)})
		case "mention_all":
			segments = append(segments, &message.AtElement{Target: "all"})
		case "reply":
			segments = append(segments, &message.ReplyElement{ReplySeq: segment.ProviderID})
		case "image":
			segments = append(segments, &message.ImageElement{URL: segment.URL, File: &message.FileElement{URL: segment.URL, File: segment.ProviderID}})
		case "file":
			segments = append(segments, &message.FileElement{URL: segment.URL, File: segment.ProviderID})
		case "record", "audio":
			segments = append(segments, &message.RecordElement{File: &message.FileElement{URL: segment.URL, File: segment.ProviderID}})
		default:
			payload, _ := json.Marshal(segment)
			segments = append(segments, &message.DefaultElement{RawType: segment.Kind, Data: payload})
		}
	}
	return segments
}

// 入站文本只解析提及标记，不调用可能读取本地文件或下载资源的出站 CQ 转换器。
func appendCallbackTextSegments(segments []message.IMessageElement, text, platform string) []message.IMessageElement {
	for text != "" {
		match := normalizedAtPattern.FindStringSubmatchIndex(text)
		cqMatch := qqAtPattern.FindStringSubmatchIndex(text)
		if cqMatch != nil && (match == nil || cqMatch[0] < match[0]) {
			match = cqMatch
		}
		if match == nil {
			return append(segments, &message.TextElement{Content: text})
		}
		if match[0] > 0 {
			segments = append(segments, &message.TextElement{Content: text[:match[0]]})
		}
		target := text[match[2]:match[3]]
		segments = append(segments, &message.AtElement{Target: target, IsRobot: platform == "QQ" && isQQBotUserID("QQ:"+target)})
		text = text[match[1]:]
	}
	return segments
}

func compatibilityGroupFromState(d *Dice, state groupstate.State, player playerstate.PlayerState, scope messageflow.CallbackScope) *GroupInfo {
	if state.GroupID == "" {
		state.GroupID = scope.GroupID
	}
	if player.UserID == "" {
		player.UserID = scope.UserID
	}
	group := &GroupInfo{
		Active: state.Active, Players: new(SyncMap[string, *GroupPlayerInfo]),
		InactivatedExtSet: StringSet{}, GroupID: state.GroupID, GuildID: state.GuildID,
		ChannelID: state.ChannelID, GroupName: state.GroupName,
		DiceIDActiveMap: new(SyncMap[string, bool]), DiceIDExistsMap: new(SyncMap[string, bool]),
		BotList: new(SyncMap[string, bool]), DiceSideNum: state.DiceSideNum,
		DiceSideExpr: state.DiceSideExpr, System: state.System, RollShaperMode: state.RollShaperMode,
		HelpPackages: append([]string(nil), state.HelpPackages...), CocRuleIndex: state.CocRuleIndex,
		ShowGroupWelcome: state.ShowGroupWelcome, GroupWelcomeMessage: state.GroupWelcomeMessage,
		EnteredTime: state.EnteredAt, InviteUserID: state.InviteUserID,
		DefaultHelpGroup: state.DefaultHelpGroup, PlayerGroups: new(SyncMap[string, []string]),
	}
	if d != nil && d.ImSession != nil && d.ImSession.ServiceAtNew != nil {
		if previous, ok := d.ImSession.ServiceAtNew.Load(scope.GroupID); ok && previous != nil {
			group.logRuntime = previous.logSequence()
		}
	}
	if d != nil && d.Parent != nil {
		if cached, exists := d.Parent.GroupNameCache.Load(scope.GroupID); exists && cached != nil && cached.Name != "" {
			group.GroupName = cached.Name
		}
	}
	for id, active := range state.DiceIDActive {
		if active {
			group.DiceIDActiveMap.Store(id, true)
		}
	}
	for id, exists := range state.DiceIDExists {
		if exists {
			group.DiceIDExistsMap.Store(id, true)
		}
	}
	for id, bot := range state.BotList {
		if bot {
			group.BotList.Store(id, true)
		}
	}
	for id, inactive := range state.InactivatedExtensions {
		if inactive {
			group.InactivatedExtSet[id] = struct{}{}
		}
	}
	activated := make([]*ExtInfo, 0, len(state.ActivatedExtensions))
	for _, name := range state.ActivatedExtensions {
		extension := d.ExtFind(name, false)
		if extension == nil {
			extension = extNamePlaceholder(name)
		}
		activated = append(activated, extension)
	}
	group.SetActivatedExtList(activated, d)
	group.Players.Store(player.UserID, compatibilityPlayerFromState(player))
	return group
}
func compatibilityPlayerFromState(player playerstate.PlayerState) *GroupPlayerInfo {
	return &GroupPlayerInfo{
		Name: player.Name, UserID: player.UserID, AutoSetNameTemplate: player.AutoSetNameTemplate,
		LastCommandTime: player.LastCommandAt, DiceSideNum: int(player.DiceSideNum), InGroup: true,
		ValueMapTemp: &ds.ValueMap{},
	}
}

func callbackMetadata(request messageflow.CallbackRequest) eventstore.Metadata {
	occurredAt := request.Message.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return eventstore.Metadata{
		CommandID: request.InboxID, CorrelationID: request.InboxID,
		CausationID: string(request.Message.ProviderEventID), PrincipalID: request.Scope.UserID,
		Producer: "dice/durable-callback", OccurredAt: occurredAt.UTC(),
	}
}

func compatibilityGroupEvents(before groupstate.State, scope messageflow.CallbackScope, after *GroupInfo) []groupstate.TypedEvent {
	if after == nil {
		return nil
	}
	events := make([]groupstate.TypedEvent, 0, 12)
	base := before
	if before.Version == 0 {
		events = append(events, groupstate.NewGroupCreatedWithInviteV1(scope.DiceID, after.GroupID, after.GroupName, after.InviteUserID, after.EnteredTime))
		base = groupstate.State{DiceID: scope.DiceID, GroupID: after.GroupID, GroupName: after.GroupName, InviteUserID: after.InviteUserID, EnteredAt: after.EnteredTime}
	}
	active := syncBoolMap(after.DiceIDActiveMap)
	exists := syncBoolMap(after.DiceIDExistsMap)
	for _, id := range sortedUnionBoolKeys(base.DiceIDActive, base.DiceIDExists, active, exists) {
		if base.DiceIDActive[id] != active[id] || base.DiceIDExists[id] != exists[id] {
			events = append(events, groupstate.NewGroupActivationChangedV1(id, active[id], exists[id]))
		}
	}
	if before.Version > 0 && (base.GroupName != after.GroupName) {
		events = append(events, groupstate.NewGroupNameChangedV1(after.GroupName))
	}
	if base.GuildID != after.GuildID || base.ChannelID != after.ChannelID {
		events = append(events, groupstate.NewGroupIdentityChangedV1(after.GuildID, after.ChannelID))
	}
	if base.System != after.System {
		events = append(events, groupstate.NewGroupSystemChangedV1(after.System))
	}
	if base.DiceSideNum != after.DiceSideNum || base.DiceSideExpr != after.DiceSideExpr || base.RollShaperMode != after.RollShaperMode || base.CocRuleIndex != after.CocRuleIndex {
		events = append(events, groupstate.NewGroupTemplateWithCocRuleV1(after.DiceSideNum, after.DiceSideExpr, after.RollShaperMode, after.CocRuleIndex))
	}
	if !equalStrings(base.HelpPackages, after.HelpPackages) || base.DefaultHelpGroup != after.DefaultHelpGroup {
		events = append(events, groupstate.NewGroupHelpChangedV1(after.DefaultHelpGroup, after.HelpPackages))
	}
	if base.ShowGroupWelcome != after.ShowGroupWelcome || base.GroupWelcomeMessage != after.GroupWelcomeMessage {
		events = append(events, groupstate.NewGroupWelcomeChangedV1(after.ShowGroupWelcome, after.GroupWelcomeMessage))
	}
	afterExtensions := map[string]bool{}
	for _, extension := range after.GetActivatedExtListRaw() {
		if extension != nil && extension.Name != "" {
			afterExtensions[extension.Name] = true
		}
	}
	beforeExtensions := extensionSet(base.ActivatedExtensions)
	afterInactiveSet := mapStringSet(after.InactivatedExtSet)
	for _, name := range sortedUnionStringKeys(beforeExtensions, base.InactivatedExtensions, afterExtensions, afterInactiveSet) {
		beforeEnabled, afterEnabled := beforeExtensions[name], afterExtensions[name]
		beforeInactive, afterInactive := base.InactivatedExtensions[name], afterInactiveSet[name]
		if beforeInactive != afterInactive || beforeEnabled != afterEnabled {
			events = append(events, groupstate.NewGroupExtensionChangedV1(name, afterEnabled))
		}
	}
	afterBots := syncBoolMap(after.BotList)
	for _, id := range sortedUnionBoolKeys(base.BotList, afterBots) {
		if base.BotList[id] != afterBots[id] {
			events = append(events, groupstate.NewGroupBotListChangedV1(id, afterBots[id]))
		}
	}
	return events
}

func compatibilityPlayerEvents(before playerstate.PlayerState, scope messageflow.CallbackScope, after *GroupPlayerInfo) []playerstate.PlayerEvent {
	if after == nil {
		return nil
	}
	events := make([]playerstate.PlayerEvent, 0, 5)
	base := before
	if before.Version == 0 {
		events = append(events, playerstate.NewPlayerCreatedV1(scope.DiceID, scope.GroupID, scope.UserID, after.Name))
		base = playerstate.PlayerState{DiceID: scope.DiceID, GroupID: scope.GroupID, UserID: scope.UserID, Name: after.Name}
	}
	if before.Version > 0 && base.Name != after.Name {
		events = append(events, playerstate.NewPlayerNameChangedV1(after.Name))
	}
	if base.AutoSetNameTemplate != after.AutoSetNameTemplate {
		events = append(events, playerstate.NewPlayerAutoSetNameTemplateChangedV1(after.AutoSetNameTemplate))
	}
	if base.LastCommandAt != after.LastCommandTime {
		events = append(events, playerstate.NewPlayerLastCommandChangedV1(after.LastCommandTime))
	}
	if base.DiceSideNum != int64(after.DiceSideNum) {
		events = append(events, playerstate.NewPlayerDiceSideChangedV1(int64(after.DiceSideNum)))
	}
	return events
}

func syncBoolMap(source *SyncMap[string, bool]) map[string]bool {
	values := map[string]bool{}
	if source != nil {
		source.Range(func(key string, value bool) bool {
			if value {
				values[key] = true
			}
			return true
		})
	}
	return values
}

func mapStringSet(source StringSet) map[string]bool {
	values := make(map[string]bool, len(source))
	for key := range source {
		values[key] = true
	}
	return values
}

func extensionSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func sortedUnionBoolKeys(inputs ...map[string]bool) []string {
	keys := map[string]struct{}{}
	for _, input := range inputs {
		for key := range input {
			keys[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedUnionStringKeys(inputs ...map[string]bool) []string {
	return sortedUnionBoolKeys(inputs...)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
