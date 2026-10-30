package dice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
)

// StartLogGapCheck is the authenticated management entry point. Chat commands
// must use newLogGapCheck with their actual sender privilege instead.
func (d *Dice) StartLogGapCheck(endpointID, groupID string, after, before int64) error {
	if d == nil || d.ImSession == nil || d.ImSession.ServiceAtNew == nil {
		return errors.New("运行时尚未就绪")
	}
	for _, ep := range d.ImSession.EndPointsReadOnly() {
		if ep == nil || ep.ID != endpointID || !ep.Enable {
			continue
		}
		group, ok := d.ImSession.ServiceAtNew.Load(groupID)
		if !ok || group == nil {
			if d.DurableStore == nil {
				return service.ErrLogRepositoryUnavailable
			}
			state, err := groupstate.NewRepository(d.DurableStore).Load(context.Background(), d.BaseConfig.Name, groupID)
			if err != nil {
				return err
			}
			scope := messageflow.CallbackScope{DiceID: d.BaseConfig.Name, GroupID: groupID, UserID: ep.UserID}
			group = compatibilityGroupFromState(d, state, playerstate.PlayerState{}, scope)
			group, _ = d.ImSession.ServiceAtNew.LoadOrStore(groupID, group)
		}
		task, err := newLogGapCheck(&MsgContext{Dice: d, EndPoint: ep, Group: group, PrivilegeLevel: 100}, after, before)
		if err != nil {
			return err
		}
		task.start()
		return nil
	}
	return errors.New("目标连接不可用")
}

func newLogGapCheck(ctx *MsgContext, after, before int64) (logGapFillTask, error) {
	if ctx == nil || ctx.PrivilegeLevel < 100 {
		return logGapFillTask{}, errors.New("仅骰主可手动检查日志断层")
	}
	if ctx.IsPrivate || ctx.Group == nil || ctx.Dice == nil || ctx.EndPoint == nil {
		return logGapFillTask{}, errors.New("请在目标群执行日志检查")
	}
	if after < 0 || before <= after || before-after <= 1 || before-after-1 > adapterapi.MaxHistoryQueryMessages {
		return logGapFillTask{}, errors.New("请指定递增的 seq 边界，区间内须为 1 至 1000 条消息")
	}
	if ctx.Dice.ProviderQuery == nil || ctx.Dice.InboundReplay == nil {
		return logGapFillTask{}, errors.New("当前连接不支持日志补全")
	}
	state, err := loadGroupLogState(ctx, ctx.Group)
	if err != nil {
		return logGapFillTask{}, err
	}
	if !state.On || state.Name == "" || state.ID == 0 {
		return logGapFillTask{}, errors.New("当前群没有正在记录的日志")
	}
	if after < state.BaselineSeq {
		return logGapFillTask{}, errors.New("检查区间不能早于本次开启日志的 seq 基线")
	}
	return logGapFillTask{
		dice: ctx.Dice, endpoint: ctx.EndPoint, group: ctx.Group,
		logID: state.ID, logName: state.Name, fromSeq: after, toSeq: before,
		gap: before - after - 1, manualCheck: true,
	}, nil
}

func (t logGapFillTask) start() { go t.run() }

func (t logGapFillTask) run() {
	defer func() {
		if value := recover(); value != nil {
			t.dice.Logger.Errorf("日志补全异常: 群=%s err=%v", t.group.GroupID, value)
		}
	}()
	if t.dice.ProviderQuery == nil || t.dice.InboundReplay == nil {
		return
	}
	lock := &t.group.logSequence().fillMu
	if !lock.TryLock() {
		return
	}
	defer lock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), logGapFillTimeout)
	defer cancel()
	t.dice.Logger.Infof("检测到日志seq断层: 群=%s 上条seq=%d 本条seq=%d 缺失=%d", t.group.GroupID, t.fromSeq, t.toSeq, t.gap)
	request := adapterapi.QueryRequest{EndpointID: adapterapi.EndpointID(t.endpoint.ID), Kind: adapterapi.QueryKindGroupHistory, Group: adapterapi.ConversationID(t.group.GroupID), AfterSequence: t.fromSeq, BeforeSequence: t.toSeq, Limit: adapterapi.MaxHistoryQueryMessages}
	result, err := t.dice.ProviderQuery.Query(ctx, request)
	if err == nil {
		err = result.Validate(request)
	}
	if err != nil {
		t.dice.Logger.Warnf("日志补全拉取失败: 群=%s err=%v", t.group.GroupID, err)
		return
	}
	missing := t.filterHistory(result.History)
	archived := 0
	if t.manualCheck {
		entries, readErr := logRepositoryForDice(t.dice).Entries(t.group.GroupID, t.logName)
		if readErr != nil {
			t.dice.Logger.Warnf("日志补全比对失败: 群=%s err=%v", t.group.GroupID, readErr)
			return
		}
		known := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			if entry.RawMsgID != nil {
				known[fmt.Sprint(entry.RawMsgID)] = struct{}{}
			}
		}
		filtered := missing[:0]
		for _, message := range missing {
			if _, exists := known[string(message.MessageID)]; exists {
				archived++
				continue
			}
			filtered = append(filtered, message)
		}
		missing = filtered
	}
	if len(missing) == 0 && !t.manualCheck {
		return
	}
	if t.toSeq-t.fromSeq-1 > adapterapi.MaxHistoryQueryMessages {
		t.dice.Logger.Warnf("日志补全区间超过上限，仅检查最近 %d 条: 群=%s", adapterapi.MaxHistoryQueryMessages, t.group.GroupID)
	}
	mode := adapterapi.InboundHistoryExecute
	if len(missing) > logGapFillSilentThreshold {
		mode = adapterapi.InboundHistoryRecordOnly
	}
	pending := make(map[string]adapterapi.InboundMessage, len(missing))
	duplicates := make(map[string]bool)
	confirmed, failed, existing := 0, 0, archived
	for i, m := range missing {
		if err := ctx.Err(); err != nil {
			failed += len(missing) - i
			break
		}
		if !t.currentLog() {
			t.dice.Logger.Infof("日志补全停止: 日志已暂停或切换，群=%s", t.group.GroupID)
			return
		}
		m.History = mode
		receipt, err := t.submitHistory(ctx, m)
		if errors.Is(err, eventstore.ErrConflict) {
			existing++
			continue
		}
		if err != nil || receipt.Outcome == adapterapi.IngressRejected || receipt.InboxID == "" {
			failed++
			continue
		}
		if receipt.Outcome == adapterapi.IngressDuplicate {
			duplicates[receipt.InboxID] = true
		}
		pending[receipt.InboxID] = m
	}
	stats := map[string]map[string]int{}
	names := map[string]string{}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	ids := make([]string, 0, len(pending))
	for len(pending) > 0 && ctx.Err() == nil {
		ids = ids[:0]
		for id := range pending {
			ids = append(ids, id)
		}
		statuses, err := t.dice.InboundReplay.InboxStatuses(ctx, ids)
		if err == nil {
			for id, m := range pending {
				switch statuses[id] {
				case eventstore.InboxStatusConfirmedConsumed:
					if duplicates[id] {
						existing++
					} else {
						confirmed++
						if mode == adapterapi.InboundHistoryRecordOnly {
							t.countHistoryCommand(m, stats, names)
						}
					}
					delete(pending, id)
				case eventstore.InboxStatusFailed, eventstore.InboxStatusAmbiguous, eventstore.InboxStatusSkipped, "":
					failed++
					delete(pending, id)
				}
			}
		}
		if len(pending) > 0 {
			select {
			case <-ctx.Done():
			case <-ticker.C:
			}
		}
	}
	t.dice.Logger.Infof("日志补全处理结束: 群=%s 成功=%d 失败=%d 待处理=%d 已存在=%d", t.group.GroupID, confirmed, failed, len(pending), existing)
	if (!t.manualCheck && mode != adapterapi.InboundHistoryRecordOnly) || !t.currentLog() {
		return
	}
	msg := &Message{MessageType: "group", GroupID: t.group.GroupID, Platform: t.endpoint.Platform, Sender: SenderBase{UserID: t.endpoint.UserID}}
	report := CreateTempCtx(t.endpoint, msg)
	_ = report.runStandaloneMessageScope(func() {
		ReplyToSenderRaw(report, msg, t.buildNotice(confirmed, failed, len(pending), existing, stats, names), "skip")
	})
}

func (t logGapFillTask) currentLog() bool {
	repository, ok := logRepositoryForDice(t.dice).(service.LogStateRepository)
	if !ok {
		return false
	}
	state, err := repository.GetState(t.group.GroupID)
	return err == nil && state.On && state.ID == t.logID && state.Name == t.logName && state.BaselineSeq <= t.fromSeq
}

func (t logGapFillTask) filterHistory(messages []adapterapi.InboundMessage) []adapterapi.InboundMessage {
	out := messages[:0]
	for _, m := range messages {
		if m.Sequence <= t.fromSeq || m.Sequence >= t.toSeq || m.Sender == adapterapi.PrincipalID(t.endpoint.UserID) || m.OccurredAt.IsZero() || m.MessageID == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (t logGapFillTask) submitHistory(ctx context.Context, m adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	var err error
	for attempt := range 4 {
		var receipt adapterapi.IngressReceipt
		receipt, err = t.dice.InboundReplay.SubmitInbound(ctx, adapterapi.EndpointID(t.endpoint.ID), m)
		if err == nil || !isRetryableInboundError(err) {
			return receipt, err
		}
		if attempt == 3 {
			break
		}
		timer := time.NewTimer(time.Duration(1<<attempt) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return adapterapi.IngressReceipt{}, ctx.Err()
		case <-timer.C:
		}
	}
	return adapterapi.IngressReceipt{}, fmt.Errorf("history ingress retries exhausted: %w", err)
}

func (t logGapFillTask) countHistoryCommand(m adapterapi.InboundMessage, stats map[string]map[string]int, names map[string]string) {
	msg := compatibilityCallbackMessageForHistory(m)
	cmd := extractCommandName(t.dice.CommandPrefix, msg.Platform, msg.Message)
	if cmd == "" {
		return
	}
	uid := string(m.Sender)
	if stats[uid] == nil {
		stats[uid] = map[string]int{}
	}
	stats[uid][cmd]++
	names[uid] = m.SenderName
}

func compatibilityCallbackMessageForHistory(m adapterapi.InboundMessage) *Message {
	msg := &Message{Platform: m.Platform, Message: m.Text, Segment: compatibilityCallbackSegments(m)}
	ensureMessageTextFromSegments(msg)
	return msg
}
