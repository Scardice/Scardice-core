package dice

import (
	"context"
	"time"

	"Scardice-core/core/execution"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
)

func (h *DurableCallbackHost) historyLogState(ctx context.Context, request messageflow.CallbackRequest, collector *execution.MutationCollector) (eventstore.StoryLogState, bool, error) {
	repository, ok := h.dice.DurableStore.(storyLogSnapshotRepository)
	if !ok {
		return eventstore.StoryLogState{}, false, ErrDomainExecutionUnavailable
	}
	state, expectation, err := repository.GetStoryLogStateSnapshot(ctx, request.Scope.DiceID, request.Scope.GroupID)
	if err != nil {
		return eventstore.StoryLogState{}, false, err
	}
	if err := collector.AddUnitOfWork(eventstore.UnitOfWork{CatalogReads: []eventstore.CatalogReadExpectation{expectation}}); err != nil {
		return eventstore.StoryLogState{}, false, err
	}
	eligible := state.On && state.Name != "" && request.Message.Sequence > state.BaselineSeq
	return state, eligible, nil
}

// History-only delivery participates in the inbox transaction without entering
// the command engine, creating players, invoking plugins or emitting reminders.
func (h *DurableCallbackHost) recordHistoryMessage(request messageflow.CallbackRequest, state eventstore.StoryLogState, collector *execution.MutationCollector) (messageflow.CallbackResult, error) {
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
