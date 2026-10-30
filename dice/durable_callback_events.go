package dice

import (
	"fmt"
	"math"
	"strings"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/dice/events"
	"Scardice-core/eventstore"
)

// Delays that stand in for the pauses the legacy handlers slept through. They
// are applied to the outbound effect instead of blocking the callback lease.
const (
	botJoinedWelcomeDelay   = 4 * time.Second
	friendAddedWelcomeDelay = 5 * time.Second
)

// handleInboundEvent runs the Core side of a Notice or Request inbound inside
// the callback transaction. Every reply and provider answer is staged in the
// same transaction as the state change it belongs to. The boolean reports
// whether the group's provider info should be refreshed afterwards.
func (h *DurableCallbackHost) handleInboundEvent(
	request messageflow.CallbackRequest,
	session *IMSession,
	endpoint *EndPointInfo,
	message *Message,
	transaction *DurableCallbackTransaction,
	metadata eventstore.Metadata,
) (*MsgContext, bool, error) {
	inbound := request.Message
	mctx := &MsgContext{
		Dice: h.dice, Session: session, EndPoint: endpoint,
		MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
		callbackTransaction: transaction, callbackMetadata: metadata,
	}
	sender := string(inbound.Sender)
	subject := string(inbound.Subject)
	groupID := ""
	if inbound.ConversationKind == adapterapi.ConversationKindGroup {
		groupID = string(inbound.Conversation)
	}
	log := h.dice.Logger

	// bindPlayer loads the acting member's state. Requests and departures are
	// answered without it, so strangers do not acquire player state.
	bindPlayer := func() {
		mctx.Group, mctx.Player = GetPlayerInfoBySender(mctx, message)
		if mctx.Player != nil && mctx.Player.Name == "" {
			mctx.Player.Name = message.Sender.Nickname
			if mctx.Player.Name == "" {
				mctx.Player.Name = message.Sender.UserID
			}
			if mctx.Group != nil {
				mctx.Group.MarkDirty(mctx.Dice)
			}
		}
		mctx.fillPrivilege(message)
	}

	switch inbound.Event {
	case adapterapi.InboundEventPoke:
		bindPlayer()
		session.OnPoke(mctx, &events.PokeEvent{GroupID: groupID, SenderID: sender, TargetID: subject, IsPrivate: mctx.IsPrivate})
	case adapterapi.InboundEventMemberJoined:
		message.Sender.UserID = subject
		if inbound.SubjectName != "" {
			message.Sender.Nickname = inbound.SubjectName
		}
		bindPlayer()
		session.OnGroupMemberJoined(mctx, message)
	case adapterapi.InboundEventSelfJoined:
		// The unified join handler expects the inviter in Sender.
		message.Sender.UserID = sender
		bindPlayer()
		mctx.Group = SetBotOnAtGroup(mctx, groupID)
		session.OnGroupJoined(mctx, message)
	case adapterapi.InboundEventSelfRemoved:
		session.OnGroupLeave(mctx, &events.GroupLeaveEvent{GroupID: groupID, UserID: subject, OperatorID: string(inbound.Operator)})
		return mctx, false, nil
	case adapterapi.InboundEventSelfLeft:
		h.handleSelfLeft(mctx, session, endpoint, groupID)
		return mctx, false, nil
	case adapterapi.InboundEventSelfMuted:
		operator := string(inbound.Operator)
		if operator == "" {
			operator = sender
		}
		groupName := h.dice.Parent.TryGetGroupName(groupID)
		userName := h.dice.Parent.TryGetUserName(operator)
		h.dice.Config.BanList.AddScoreByGroupMuted(operator, groupID, mctx)
		duration := fmt.Sprintf("%d秒", inbound.DurationSeconds)
		if inbound.DurationSeconds == math.MaxUint32 {
			duration = "永久"
		}
		txt := fmt.Sprintf("被禁言: 在群组<%s>(%s)中被禁言，时长%s，操作者:<%s>(%s)", groupName, groupID, duration, userName, operator)
		log.Info(txt)
		mctx.Notice(txt)
	case adapterapi.InboundEventFriendAdded:
		bindPlayer()
		message.MessageType, message.Platform = "private", "QQ"
		welcome := DiceFormatTmpl(mctx, "核心:骰子成为好友")
		log.Infof("与 %s 成为好友，发送好友致辞: %s", sender, welcome)
		mctx.setOutboundDelay(friendAddedWelcomeDelay)
		ReplyPerson(mctx, message, welcome)
		mctx.setOutboundDelay(0)
		if mctx.Group != nil {
			for _, wrapper := range mctx.Group.GetActivatedExtList(mctx.Dice) {
				wrapper.CallOnBecomeFriend(mctx.Dice, mctx, message)
			}
		}
	case adapterapi.InboundEventFriendRequest:
		h.handleFriendRequest(mctx, inbound, sender)
		return mctx, false, nil
	case adapterapi.InboundEventGroupInvite:
		h.handleGroupInvite(mctx, inbound, sender, groupID)
		return mctx, false, nil
	default:
		return nil, false, ErrUnsupportedDurableInboundKind
	}
	return mctx, true, nil
}

// handleSelfLeft removes the bot from the group's roster after it left, was
// removed, or the group was disbanded.
func (h *DurableCallbackHost) handleSelfLeft(mctx *MsgContext, session *IMSession, endpoint *EndPointInfo, groupID string) {
	log := h.dice.Logger
	pendingQuit := session.ConsumePendingQuit(groupID, endpoint.UserID)
	groupName := h.dice.Parent.TryGetGroupName(groupID)
	quietAutoQuit := pendingQuit != nil && pendingQuit.Origin == QuitOriginAutoInactive && h.dice.Config.QuitInactiveNoticeSummaryMode
	group, exists := session.ServiceAtNew.Load(groupID)
	if !exists {
		txt := fmt.Sprintf("离开群组或群解散，删除对应群聊信息失败: <%s>(%s)", groupName, groupID)
		log.Error(txt)
		if !quietAutoQuit {
			mctx.Notice(txt)
		}
		return
	}
	group.DiceIDExistsMap.Delete(endpoint.UserID)
	group.MarkDirty(h.dice)
	txt := fmt.Sprintf("离开群组或群解散: <%s>(%s)", groupName, groupID)
	log.Info(txt)
	if !quietAutoQuit {
		mctx.Notice(txt)
	}
}

// handleFriendRequest applies the endpoint's friend request policy and the
// operator's verification question and blacklist, then stages the provider
// answer in the same transaction as the report.
func (h *DurableCallbackHost) handleFriendRequest(mctx *MsgContext, inbound adapterapi.InboundMessage, userID string) {
	d := h.dice
	comment := normalizeOnebotFriendRequestComment(inbound.Text)
	toMatch := strings.TrimSpace(d.Config.FriendAddComment)
	passQuestion := toMatch == "" || comment == DiceFormat(mctx, toMatch) || checkMultiFriendAddVerify(comment, toMatch)
	blacklist := checkBlackList(userID, "user", "", mctx)

	approve := blacklist.Passed && passQuestion
	extra := "。回答正确"
	if !passQuestion {
		extra = "。回答错误"
	}
	if !blacklist.Passed {
		extra += "。（被禁止用户），原因：" + blacklist.Reason
	}
	answer := true
	switch inbound.RequestPolicy {
	case "ignore", "manual":
		// The operator handles the request; Core only reports it.
		answer = false
		extra += "。由于设置了忽略邀请，此信息仅为通报"
	case "deny":
		approve = false
		extra += "。由于设置了拒绝策略，已自动拒绝"
	}
	shown := "(无)"
	if comment != "" {
		shown = formatOnebotFriendRequestCommentForLog(comment)
	}
	txt := fmt.Sprintf("收到QQ好友邀请: 邀请人:%s, 验证信息: %s, 是否自动同意: %t%s", strings.TrimPrefix(userID, "QQ:"), shown, answer && approve, extra)
	d.Logger.Info(txt)
	mctx.Notice(txt, NoticeTypeInvite)
	if !answer {
		return
	}
	h.answerRequest(mctx, adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: adapterapi.ConversationID(userID)}, inbound.RequestID, approve, "")
}

// handleGroupInvite decides whether to join a group the bot was invited into.
func (h *DurableCallbackHost) handleGroupInvite(mctx *MsgContext, inbound adapterapi.InboundMessage, inviter, groupID string) {
	d := h.dice
	txt := fmt.Sprintf("收到QQ加群邀请: 群组<%s>(%s) 邀请人:<%s>(%s)", d.Parent.TryGetGroupName(groupID), groupID, d.Parent.TryGetUserName(inviter), inviter)
	d.Logger.Info(txt)
	mctx.Notice(txt, NoticeTypeInvite)

	approve, reason := checkPassBlackListGroup(inviter, groupID, mctx)
	if !approve {
		d.Logger.Infof("群组 %s 加群请求被拒绝，原因为 %s", groupID, reason)
	}
	h.answerRequest(mctx, adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: adapterapi.ConversationID(groupID)}, inbound.RequestID, approve, reason)
}

// answerRequest stages the provider answer. A failure to stage is logged
// rather than returned: the report has already been made and the callback must
// still commit its state.
func (h *DurableCallbackHost) answerRequest(mctx *MsgContext, target adapterapi.EffectTarget, requestID string, approve bool, reason string) {
	port, ok := h.dice.OutboundBridge.(durableOutboundActionPort)
	if !ok {
		h.dice.Logger.Errorf("无法应答请求 %s: 出站桥接不可用", requestID)
		return
	}
	err := port.SubmitAction(mctx, adapterapi.EffectPayload{
		Kind: adapterapi.EffectPayloadAnswerRequest, Target: target,
		RequestID: requestID, Approve: approve, Reason: reason,
	})
	if err != nil {
		h.dice.Logger.Errorf("应答请求 %s 失败: %v", requestID, err)
	}
}

// rememberNames records the display names the provider supplied with an
// inbound, so every later lookup by id (reports, welcomes, group lists) shows a
// name instead of a placeholder. An empty name never overwrites a known one,
// and a renamed group keeps the member counts already cached for it.
func (h *DurableCallbackHost) rememberNames(inbound adapterapi.InboundMessage) {
	if h == nil || h.dice == nil || h.dice.Parent == nil {
		return
	}
	dm := h.dice.Parent
	now := time.Now().Unix()
	user := func(id adapterapi.PrincipalID, name string) {
		if id != "" && name != "" {
			dm.UserNameCache.Store(string(id), &GroupNameCacheItem{Name: name, time: now})
		}
	}
	user(inbound.Sender, inbound.SenderName)
	user(inbound.Subject, inbound.SubjectName)
	if inbound.ConversationKind != adapterapi.ConversationKindGroup || inbound.Conversation == "" || inbound.ConversationName == "" {
		return
	}
	dm.groupNameCacheMu.Lock()
	defer dm.groupNameCacheMu.Unlock()
	next := GroupNameCacheItem{}
	if current, exists := dm.GroupNameCache.Load(string(inbound.Conversation)); exists && current != nil {
		next = *current
	}
	next.Name, next.time = inbound.ConversationName, now
	dm.GroupNameCache.Store(string(inbound.Conversation), &next)
}
