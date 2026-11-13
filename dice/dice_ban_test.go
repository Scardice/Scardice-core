package dice_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/dice"
)

func TestCanNotifyBlacklistedUserUsesIndependentGroupAndUserCooldowns(t *testing.T) {
	// Given
	var banList dice.BanListInfo
	banList.Init()
	banList.BanNotifyIntervalMinutes = 10
	base := time.Unix(1_700_000_000, 0)

	// When / Then
	if !banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2001", base) {
		t.Fatal("first notice should be allowed")
	}
	if banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2001", base.Add(5*time.Minute)) {
		t.Fatal("same user in the same group should be throttled")
	}
	if !banList.CanNotifyBlacklistedUser("QQ-Group:1002", "QQ:2001", base.Add(5*time.Minute)) {
		t.Fatal("the same user in another group should have an independent cooldown")
	}
	if !banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2002", base.Add(5*time.Minute)) {
		t.Fatal("another user in the same group should have an independent cooldown")
	}
	if !banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2001", base.Add(11*time.Minute)) {
		t.Fatal("notice should be allowed after cooldown elapsed")
	}
}

func TestCanNotifyBlacklistedUserAllowsEveryNoticeWhenCooldownDisabled(t *testing.T) {
	// Given
	var banList dice.BanListInfo
	banList.Init()
	banList.BanNotifyIntervalMinutes = -1
	now := time.Unix(1_700_000_000, 0)

	// When / Then
	if !banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2001", now) {
		t.Fatal("first notice should be allowed")
	}
	if !banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2001", now) {
		t.Fatal("every notice should be allowed when cooldown is disabled")
	}
}

func TestCanNotifyBlacklistedUserAllowsOneConcurrentNotice(t *testing.T) {
	// Given
	var banList dice.BanListInfo
	banList.Init()
	const goroutines = 32
	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	now := time.Unix(1_700_000_000, 0)

	// When
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if banList.CanNotifyBlacklistedUser("QQ-Group:1001", "QQ:2001", now) {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// Then
	if got := allowed.Load(); got != 1 {
		t.Fatalf("concurrent notices allowed = %d, want 1", got)
	}
}
