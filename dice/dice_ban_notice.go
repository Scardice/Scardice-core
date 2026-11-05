package dice

import "time"

const defaultBlacklistedUserNoticeCooldown = 20 * time.Minute

type blacklistedUserNoticeKey struct {
	GroupID string
	UserID  string
}

func (i *BanListInfo) BlacklistedUserNoticeCooldown() time.Duration {
	if i.BanNotifyIntervalMinutes == 0 {
		return defaultBlacklistedUserNoticeCooldown
	}
	return time.Duration(i.BanNotifyIntervalMinutes) * time.Minute
}

func (i *BanListInfo) cleanupBlacklistedUserNoticeAtLocked(now time.Time, cooldown time.Duration) {
	for key, noticeAt := range i.runtime.noticeAt {
		if now.Sub(noticeAt) >= cooldown {
			delete(i.runtime.noticeAt, key)
		}
	}
}

func (i *BanListInfo) cleanupBlacklistedUserNotices(now time.Time) {
	cooldown := i.BlacklistedUserNoticeCooldown()
	if cooldown < 0 {
		return
	}
	if i.runtime == nil {
		i.runtime = &banListRuntime{noticeAt: map[blacklistedUserNoticeKey]time.Time{}}
	}
	i.runtime.noticeMu.Lock()
	defer i.runtime.noticeMu.Unlock()
	i.cleanupBlacklistedUserNoticeAtLocked(now, cooldown)
}

func (i *BanListInfo) CanNotifyBlacklistedUser(groupID string, userID string, now time.Time) bool {
	cooldown := i.BlacklistedUserNoticeCooldown()
	if cooldown < 0 {
		return true
	}
	if i.runtime == nil {
		i.runtime = &banListRuntime{noticeAt: map[blacklistedUserNoticeKey]time.Time{}}
	}
	i.runtime.noticeMu.Lock()
	defer i.runtime.noticeMu.Unlock()
	if i.runtime.noticeAt == nil {
		i.runtime.noticeAt = map[blacklistedUserNoticeKey]time.Time{}
	}
	key := blacklistedUserNoticeKey{GroupID: groupID, UserID: userID}
	if lastNoticeAt, ok := i.runtime.noticeAt[key]; ok && now.Sub(lastNoticeAt) < cooldown {
		return false
	}
	i.runtime.noticeAt[key] = now
	return true
}
