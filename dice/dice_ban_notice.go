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
	for key, noticeAt := range i.banNoticeAt {
		if now.Sub(noticeAt) >= cooldown {
			delete(i.banNoticeAt, key)
		}
	}
}

func (i *BanListInfo) cleanupBlacklistedUserNotices(now time.Time) {
	cooldown := i.BlacklistedUserNoticeCooldown()
	if cooldown < 0 {
		return
	}
	i.banNoticeMu.Lock()
	defer i.banNoticeMu.Unlock()
	i.cleanupBlacklistedUserNoticeAtLocked(now, cooldown)
}

func (i *BanListInfo) CanNotifyBlacklistedUser(groupID string, userID string, now time.Time) bool {
	cooldown := i.BlacklistedUserNoticeCooldown()
	if cooldown < 0 {
		return true
	}

	i.banNoticeMu.Lock()
	defer i.banNoticeMu.Unlock()
	if i.banNoticeAt == nil {
		i.banNoticeAt = map[blacklistedUserNoticeKey]time.Time{}
	}

	key := blacklistedUserNoticeKey{GroupID: groupID, UserID: userID}
	if lastNoticeAt, ok := i.banNoticeAt[key]; ok && now.Sub(lastNoticeAt) < cooldown {
		return false
	}
	i.banNoticeAt[key] = now
	return true
}
