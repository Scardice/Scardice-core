package dice

import (
	"time"

	"Scardice-core/core/messageflow"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
)

func (h *DurableCallbackHost) historyLogState(request messageflow.CallbackRequest) (service.LogState, bool, error) {
	repository, ok := logRepositoryForDice(h.dice).(service.LogStateRepository)
	if !ok {
		return service.LogState{}, false, service.ErrLogRepositoryUnavailable
	}
	state, err := repository.GetState(request.Scope.GroupID)
	eligible := state.On && state.Name != "" && request.Message.Sequence > state.BaselineSeq
	return state, eligible, err
}

// History-only delivery participates in the inbox transaction without entering
// the command engine, creating players, invoking plugins or emitting reminders.
func (h *DurableCallbackHost) recordHistoryMessage(request messageflow.CallbackRequest, state service.LogState, collector *messageflow.MutationCollector) (messageflow.CallbackResult, error) {
	msg := compatibilityCallbackMessage(request)
	ensureMessageTextFromSegments(msg)
	item := receivedLogItem(msg, msg.Sender.Nickname, msg.Sender.UserID, 0)
	entry, err := storyLogEntry(h.dice.BaseConfig.Name, request.Scope.GroupID, state.Name, item)
	if err != nil {
		return messageflow.CallbackResult{}, err
	}
	if err := collector.AddLogUpdate(eventstore.NewStoryLogAppendUpdate(entry)); err != nil {
		return messageflow.CallbackResult{}, err
	}
	return messageflow.CallbackResult{}, nil
}

func (ctx *MsgContext) replyLogTime(now time.Time) int64 {
	if ctx.logReplyTime > 0 {
		return ctx.logReplyTime
	}
	return now.Unix()
}
