package dice

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	officialQQC2CBotLimit      = 10
	officialQQC2CBotPeriod     = time.Second
	officialQQGroupBotLimit    = 60
	officialQQGroupBotPeriod   = time.Minute
	officialQQRelationLimit    = 20
	officialQQRelationPeriod   = time.Minute
	officialQQDailyLimit       = 1000
	officialQQMaxQueueDelay    = 5 * time.Minute
	officialQQRelationMapLimit = 2048
)

var officialQQTimeZone = time.FixedZone("CST", 8*60*60)

type OfficialQQSendQuota struct {
	mu         sync.Mutex
	botLimit   int
	botPeriod  time.Duration
	botStamps  []time.Time
	relStamps  map[string][]time.Time
	dailyDay   string
	dailyCount map[string]int
	now        func() time.Time
}

func newOfficialQQSendQuota(botLimit int, botPeriod time.Duration) *OfficialQQSendQuota {
	return &OfficialQQSendQuota{
		botLimit:   botLimit,
		botPeriod:  botPeriod,
		relStamps:  make(map[string][]time.Time),
		dailyCount: make(map[string]int),
		now:        time.Now,
	}
}

func (q *OfficialQQSendQuota) reserve(targetID string) (time.Time, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := q.now().In(officialQQTimeZone)
	day := now.Format("2006-01-02")
	if day != q.dailyDay {
		q.dailyDay = day
		q.dailyCount = make(map[string]int)
	}
	if q.dailyCount[targetID] >= officialQQDailyLimit {
		return time.Time{}, fmt.Errorf("对 %s 的主动消息已达当日上限(%d条)", targetID, officialQQDailyLimit)
	}

	reserved := now
	relationStamps := q.relStamps[targetID]
	if len(relationStamps) >= officialQQRelationLimit {
		candidate := relationStamps[len(relationStamps)-officialQQRelationLimit].Add(officialQQRelationPeriod)
		if candidate.After(reserved) {
			reserved = candidate
		}
	}
	if len(q.botStamps) >= q.botLimit {
		candidate := q.botStamps[len(q.botStamps)-q.botLimit].Add(q.botPeriod)
		if candidate.After(reserved) {
			reserved = candidate
		}
	}
	if reserved.Sub(now) > officialQQMaxQueueDelay {
		return time.Time{}, fmt.Errorf("对 %s 的主动消息排队等待超过 %v，放弃发送", targetID, officialQQMaxQueueDelay)
	}

	relationStamps = append(relationStamps, reserved)
	if len(relationStamps) > officialQQRelationLimit {
		relationStamps = relationStamps[len(relationStamps)-officialQQRelationLimit:]
	}
	q.relStamps[targetID] = relationStamps
	q.botStamps = append(q.botStamps, reserved)
	if len(q.botStamps) > q.botLimit {
		q.botStamps = q.botStamps[len(q.botStamps)-q.botLimit:]
	}
	q.dailyCount[targetID]++
	if len(q.relStamps) > officialQQRelationMapLimit {
		for target, stamps := range q.relStamps {
			if len(stamps) == 0 || now.Sub(stamps[len(stamps)-1]) > officialQQRelationPeriod {
				delete(q.relStamps, target)
			}
		}
	}
	return reserved, nil
}

func (q *OfficialQQSendQuota) acquire(ctx context.Context, targetID string) error {
	reserved, err := q.reserve(targetID)
	if err != nil {
		return err
	}
	delay := time.Until(reserved)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (pa *PlatformAdapterOfficialQQ) initSendQuota() {
	pa.sendQuotaOnce.Do(func() {
		pa.c2cSendQuota = newOfficialQQSendQuota(officialQQC2CBotLimit, officialQQC2CBotPeriod)
		pa.groupSendQuota = newOfficialQQSendQuota(officialQQGroupBotLimit, officialQQGroupBotPeriod)
	})
}

func (pa *PlatformAdapterOfficialQQ) waitC2CActiveQuota(ctx context.Context, userOpenID string) error {
	pa.initSendQuota()
	return pa.c2cSendQuota.acquire(ctx, userOpenID)
}

func (pa *PlatformAdapterOfficialQQ) waitGroupActiveQuota(ctx context.Context, groupOpenID string) error {
	pa.initSendQuota()
	return pa.groupSendQuota.acquire(ctx, groupOpenID)
}
