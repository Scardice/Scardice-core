package dice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
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
		// The account's own private message belongs to the conversation with its
		// recipient; the sender stays the account.
		peer := userID
		if message.Kind == adapterapi.InboundKindSelfMessage && message.Conversation != "" {
			peer = string(message.Conversation)
		}
		groupID = "PG-" + peer
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

// DurableCallbackHost executes against one invocation-owned DomainTx. Shared
// runtime resources do not own or publish durable group/player state.
type DurableCallbackHost struct {
	dice *Dice
}

func NewDurableCallbackHost(instance *Dice) *DurableCallbackHost {
	return &DurableCallbackHost{dice: instance}
}

func (h *DurableCallbackHost) InvalidateGroup(ctx context.Context, groupID string) error {
	if h == nil || h.dice == nil || h.dice.ImSession == nil || groupID == "" {
		return messageflow.ErrCallbackUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.dice.ImSession.InvalidateGroupRuntime(groupID)
	return nil
}

func (h *DurableCallbackHost) HandleCallback(ctx context.Context, request messageflow.CallbackRequest, _ *playerstate.LocalOverlay, collector *execution.MutationCollector) (result messageflow.CallbackResult, err error) {
	if h == nil || h.dice == nil || h.dice.ImSession == nil || collector == nil {
		return result, messageflow.ErrCallbackUnavailable
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if request.Scope.DiceID != h.dice.BaseConfig.Name {
		return result, messageflow.ErrCallbackScope
	}
	if request.Message.History != adapterapi.InboundHistoryNone && request.Message.Kind != adapterapi.InboundKindSelfMessage {
		state, eligible, historyErr := h.historyLogState(ctx, request, collector)
		if historyErr != nil || !eligible {
			return result, historyErr
		}
		if request.Message.History == adapterapi.InboundHistoryRecordOnly {
			return h.recordHistoryMessage(request, state, collector)
		}
	}
	metadata := callbackMetadata(request)
	transaction, err := NewDurableCallbackTransaction(ctx, h.dice.DurableStore, collector, metadata)
	if err != nil {
		return result, err
	}
	finalized := false
	defer func() {
		if !finalized {
			transaction.Domain().Abort()
		}
	}()
	if err = h.dice.ContributeConfigView(ctx, transaction.Domain()); err != nil {
		return result, err
	}
	if err = transaction.checkEndpointFence(ctx, adapterapi.EndpointID(request.EndpointID), request.Generation, request.DesiredVersion); err != nil {
		return result, err
	}
	h.rememberNames(request.Message)
	session := h.dice.ImSession
	endpoint := compatibilityCallbackEndpoint(session, request)
	message := compatibilityCallbackMessage(request)
	var executed messageExecutionResult
	refreshGroupInfo := true
	switch request.Message.Kind {
	case adapterapi.InboundKindMessage:
		executed = session.executeMessage(endpoint, message, messageExecutionOptions{parser: messageParserSegments, runInSync: true, callbackTransaction: transaction, callbackMetadata: metadata})
	case adapterapi.InboundKindMessageUpdated, adapterapi.InboundKindMessageDeleted:
		mctx := &MsgContext{
			Dice: h.dice, Session: session, EndPoint: endpoint,
			MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
			callbackTransaction: transaction, callbackMetadata: metadata,
		}
		if request.Message.Kind == adapterapi.InboundKindMessageUpdated {
			session.OnMessageEdit(mctx, message)
		} else {
			session.OnMessageDeleted(mctx, message)
		}
		executed.context = mctx
	case adapterapi.InboundKindNotice, adapterapi.InboundKindRequest:
		executed.context, refreshGroupInfo, err = h.handleInboundEvent(request, session, endpoint, message, transaction, metadata)
		if err != nil {
			return result, err
		}
	case adapterapi.InboundKindAdapterEvent:
		if request.Message.AdapterEvent == nil {
			return result, adapterapi.ErrInvalidContract
		}
		executed.context = &MsgContext{
			Dice: h.dice, Session: session, EndPoint: endpoint,
			MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
			callbackTransaction: transaction, callbackMetadata: metadata,
		}
		refreshGroupInfo = false
	case adapterapi.InboundKindSelfMessage:
		executed.context, err = h.handleSelfMessage(request, session, endpoint, message, transaction, metadata)
		if err != nil {
			return result, err
		}
		refreshGroupInfo = false
	default:
		return result, ErrUnsupportedDurableInboundKind
	}
	if executed.err != nil {
		return result, executed.err
	}
	if executed.context != nil {
		defer executed.context.releaseExecutionState()
		if request.Message.AdapterEvent != nil {
			if request.Message.Kind != adapterapi.InboundKindSelfMessage {
				if err = h.bindAdapterEventConversation(executed.context, request.Scope); err != nil {
					return result, err
				}
			}
			executed.context.fillPrivilege(message)
			if err = h.dice.dispatchAdapterEvent(executed.context, executed.context, *request.Message.AdapterEvent, endpoint); err != nil {
				return result, err
			}
		}
		if err = executed.context.getExecutionError(); err != nil {
			return result, err
		}
		if err = executed.context.stopJSExecution(); err != nil {
			return result, err
		}
		if err = executed.context.getExecutionError(); err != nil {
			return result, err
		}
	}
	if refreshGroupInfo {
		h.stageGroupInfoRefresh(ctx, request, executed.context)
	}
	if err = transaction.Finalize(ctx); err != nil {
		return result, err
	}
	finalized = true
	return messageflow.CallbackResult{
		PublishCommitted: func() { publishDomainCommit(transaction) },
		CommitFence:      transaction.callbackCommitFence,
		AfterCommit:      func() { notifyDomainCommit(transaction) },
	}, nil
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
