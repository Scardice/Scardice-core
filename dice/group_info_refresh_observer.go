package dice

import (
	"context"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/logger"
)

// GroupInfoRefreshSuccessNotifier projects validated provider observations into
// the compatibility caches. It deliberately performs no event-store or SQL IO.
type GroupInfoRefreshSuccessNotifier struct {
	dice *Dice
	host *DurableCallbackHost
}

func NewGroupInfoRefreshSuccessNotifier(d *Dice, host *DurableCallbackHost) *GroupInfoRefreshSuccessNotifier {
	return &GroupInfoRefreshSuccessNotifier{dice: d, host: host}
}

func (notifier *GroupInfoRefreshSuccessNotifier) NotifyOutboundEffectSucceeded(_ context.Context, effect adapterapi.OutboundEffect, result adapterapi.EffectResult) {
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
	if effect.Payload.Target.Kind != adapterapi.TargetGroup || result.Outcome != adapterapi.EffectSucceeded || result.GroupInfo == nil {
		log.Error("忽略无效的群信息刷新结果")
		return
	}
	if err := result.Validate(); err != nil {
		log.Errorf("忽略无效的群信息刷新结果: %v", err)
		return
	}
	info := result.GroupInfo
	if err := info.ValidateForTarget(effect.Payload.Target); err != nil {
		log.Errorf("忽略目标不匹配的群信息刷新结果: %v", err)
		return
	}

	if d.Parent != nil {
		d.Parent.groupNameCacheMu.Lock()
		now := time.Now().Unix()
		next := GroupNameCacheItem{Name: info.Name, time: now}
		if current, exists := d.Parent.GroupNameCache.Load(info.Conversation.String()); exists && current != nil {
			next = *current
			next.Name = info.Name
			next.time = now
		}
		if info.MemberCountKnown {
			next.MemberCount = info.MemberCount
			next.MemberCountKnown = true
		}
		if info.MaxMemberCountKnown {
			next.MaxMemberCount = info.MaxMemberCount
			next.MaxMemberCountKnown = true
		}
		d.Parent.GroupNameCache.Store(info.Conversation.String(), &next)
		d.Parent.groupNameCacheMu.Unlock()
	}

	host := notifier.host
	if host == nil || host.dice != d || !host.mu.TryLock() {
		return
	}
	defer host.mu.Unlock()
	if d.ImSession == nil || d.ImSession.ServiceAtNew == nil {
		return
	}
	group, exists := d.ImSession.ServiceAtNew.Load(info.Conversation.String())
	if !exists || group == nil || group.GroupName == info.Name {
		return
	}
	group.GroupName = info.Name
	group.MarkDirty(d)
}
