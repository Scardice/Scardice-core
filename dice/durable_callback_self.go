package dice

import (
	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/model"
)

// handleSelfMessage processes a message the endpoint's own account sent. It
// never reaches the command engine, custom replies, message hooks, rate
// limiting or player creation: the conversation is bound only to facts that
// already exist, exactly as for an adapter event, and the only effects are the
// group's log position, the log entry of a hand-typed message, and the raw
// adapter event that subscribed plugins still receive.
func (h *DurableCallbackHost) handleSelfMessage(
	request messageflow.CallbackRequest,
	session *IMSession,
	endpoint *EndPointInfo,
	message *Message,
	transaction *DurableCallbackTransaction,
	metadata eventstore.Metadata,
) (*MsgContext, error) {
	mctx := &MsgContext{
		Dice: h.dice, Session: session, EndPoint: endpoint,
		MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
		callbackTransaction: transaction, callbackMetadata: metadata,
	}
	if err := h.bindAdapterEventConversation(mctx, request.Scope); err != nil {
		return nil, err
	}
	if request.Message.ConversationKind == adapterapi.ConversationKindGroup && mctx.Group != nil {
		h.recordSelfMessage(request, mctx, message)
	}
	// The account's own message belongs to no player: hooks must not attribute
	// it to, or moderate it as, a player of the table.
	mctx.Player = nil
	return mctx, nil
}

// recordSelfMessage places an own group message in the group's log position
// and, unless Core itself issued it, archives it as the dice's speech.
//
// A message Core sent is archived by Core's own outbound state when the send
// reaches its terminal outcome (with the provider message id), so the report
// only settles the sequence accounting. A message typed by hand has no other
// record: it is appended under the provider message id, and the archive keeps
// one entry per provider message id however the report and Core's own commit
// interleave (see eventstore.NewStoryLogAppendOnceUpdate).
func (h *DurableCallbackHost) recordSelfMessage(request messageflow.CallbackRequest, mctx *MsgContext, msg *Message) {
	if !logCallbackStorageAvailable(mctx) {
		return
	}
	logger := h.dice.Logger
	state, err := loadGroupLogState(mctx, mctx.Group)
	if err != nil {
		logger.Warnf("日志状态读取失败: group=%s err=%v", mctx.Group.GroupID(), err)
		return
	}
	if !state.On || state.Name == "" {
		return
	}
	inbound := request.Message
	if inbound.Sequence > 0 && inbound.Sequence <= state.BaselineSeq {
		return
	}
	issuedByCore := inbound.SelfOrigin == adapterapi.SelfMessageIssuedByCore
	if inbound.Sequence > 0 && inbound.History == adapterapi.InboundHistoryNone {
		span := detectSelfLogGap(mctx.Group.runtime, state, inbound.Sequence, msg.RawID, issuedByCore, logStoredSeqReader(mctx, state))
		if span.missing > 0 && !startLogGapFill(mctx, state, span) {
			return
		}
	}
	if issuedByCore {
		return
	}
	repository := logRepositoryForDice(h.dice)
	ensureMessageTextFromSegments(msg)
	item := &model.LogOneItem{
		Nickname: mctx.EndPoint.Nickname, IMUserID: UserIDExtract(mctx.EndPoint.UserID), UniformID: mctx.EndPoint.UserID,
		Time: msg.Time, Seq: ptrInt64(msg.Seq), Message: msg.Message, IsDice: true, RawMsgID: msg.RawID,
	}
	entry, err := storyLogEntry(repository.DiceID(), mctx.Group.GroupID(), state.Name, item)
	if err != nil {
		logger.Warnf("账号自身消息转换日志条目失败: group=%s err=%v", mctx.Group.GroupID(), err)
		return
	}
	if err := mctx.callbackTransaction.AddLogUpdate(eventstore.NewStoryLogAppendOnceUpdate(entry)); err != nil {
		mctx.setExecutionError(err)
	}
}
