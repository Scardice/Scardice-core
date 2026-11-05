package dice

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

// GroupInfoRefreshSuccessNotifier commits validated provider observations to
// the canonical group stream before publishing the derived display cache.
type GroupInfoRefreshSuccessNotifier struct {
	dice *Dice
}

func NewGroupInfoRefreshSuccessNotifier(d *Dice) *GroupInfoRefreshSuccessNotifier {
	return &GroupInfoRefreshSuccessNotifier{dice: d}
}

func (notifier *GroupInfoRefreshSuccessNotifier) NotifyOutboundEffectSucceeded(ctx context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
	if effect.Payload.Kind != adapterapi.EffectPayloadGroupInfoRefresh {
		return
	}
	if notifier == nil || notifier.dice == nil {
		logger.M().Error("忽略群信息刷新结果：骰子实例不可用")
		return
	}
	d := notifier.dice
	log := d.Logger
	if log == nil {
		log = logger.M()
	}
	if d.DurableStore == nil ||
		effect.Payload.Target.Kind != adapterapi.TargetGroup ||
		result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
		log.Error("忽略无效的群信息刷新结果")
		return
	}
	if err := effect.Validate(); err != nil {
		log.Errorf("忽略无效的群信息刷新效果: %v", err)
		return
	}
	if err := result.Validate(); err != nil {
		log.Errorf("忽略无效的群信息刷新结果: %v", err)
		return
	}
	info := *result.GroupInfo
	if err := info.ValidateForTarget(effect.Payload.Target); err != nil {
		log.Errorf("忽略目标不匹配的群信息刷新结果: %v", err)
		return
	}
	requestedAt := effect.Deadline.Add(-5 * time.Minute).Unix()
	var current *GroupNameCacheItem
	var exists bool
	if d.Parent != nil {
		d.Parent.groupNameCacheMu.Lock()
		current, exists = d.Parent.GroupNameCache.Load(info.Conversation.String())
		stale := exists && current != nil && current.time > requestedAt
		d.Parent.groupNameCacheMu.Unlock()
		if stale {
			return
		}
	}
	groupID := info.Conversation.String()
	canonical, err := json.Marshal(struct {
		EffectID  adapterapi.EffectID        `json:"effectId"`
		Endpoint  adapterapi.EndpointID      `json:"endpointId"`
		Target    adapterapi.EffectTarget    `json:"target"`
		GroupInfo adapterapi.GroupInfoResult `json:"groupInfo"`
	}{
		EffectID: effect.ID, Endpoint: effect.EndpointID,
		Target: effect.Payload.Target, GroupInfo: info,
	})
	if err != nil {
		log.Errorf("构造群信息观察事务失败: %v", err)
		return
	}
	identity := d.DomainExecutionIdentity("group-info-observation", string(effect.ID))
	err = d.WithDomainExecution(ctx, identity, canonical, func(transaction *DurableCallbackTransaction) error {
		group, loadErr := transaction.Domain().Group(transaction.executionContext, d.BaseConfig.Name, groupID)
		if loadErr != nil {
			return loadErr
		}
		if group.Version() == 0 || group.Deleted() {
			return errors.Join(eventstore.ErrNotFound, groupstate.ErrInvalidState)
		}
		return group.Decide(groupstate.Command{Kind: groupstate.CommandName, GroupName: info.Name})
	})
	if err != nil {
		log.Errorf("提交群信息观察失败: %v", err)
		return
	}
	if d.Parent == nil {
		return
	}

	d.Parent.groupNameCacheMu.Lock()
	defer d.Parent.groupNameCacheMu.Unlock()
	current, exists = d.Parent.GroupNameCache.Load(groupID)
	if exists && current != nil && current.time > requestedAt {
		return
	}
	next := GroupNameCacheItem{Name: info.Name, time: time.Now().Unix()}
	if exists && current != nil {
		next.MemberCount = current.MemberCount
		next.MaxMemberCount = current.MaxMemberCount
		next.MemberCountKnown = current.MemberCountKnown
		next.MaxMemberCountKnown = current.MaxMemberCountKnown
	}
	if info.MemberCountKnown {
		next.MemberCount, next.MemberCountKnown = info.MemberCount, true
	}
	if info.MaxMemberCountKnown {
		next.MaxMemberCount, next.MaxMemberCountKnown = info.MaxMemberCount, true
	}
	d.Parent.GroupNameCache.Store(groupID, &next)
}
