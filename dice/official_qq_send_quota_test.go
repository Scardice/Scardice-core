package dice

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOfficialQQSendQuota_reservesBotWindowInOrder(t *testing.T) {
	// Given
	now := time.Date(2026, 8, 2, 10, 0, 0, 0, officialQQTimeZone)
	quota := newOfficialQQSendQuota(2, time.Minute)
	quota.now = func() time.Time { return now }

	// When
	first, err := quota.reserve("group-a")
	if err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	second, err := quota.reserve("group-b")
	if err != nil {
		t.Fatalf("reserve second: %v", err)
	}
	third, err := quota.reserve("group-c")
	if err != nil {
		t.Fatalf("reserve third: %v", err)
	}

	// Then
	if !first.Equal(now) || !second.Equal(now) || !third.Equal(now.Add(time.Minute)) {
		t.Fatalf("reservations = %s, %s, %s", first, second, third)
	}
}

func TestOfficialQQSendQuota_resetsDailyLimitInCST(t *testing.T) {
	// Given
	now := time.Date(2026, 8, 2, 23, 59, 0, 0, officialQQTimeZone)
	quota := newOfficialQQSendQuota(officialQQDailyLimit+1, time.Minute)
	quota.now = func() time.Time { return now }
	quota.dailyDay = now.Format("2006-01-02")
	quota.dailyCount["group-a"] = officialQQDailyLimit

	// When
	_, err := quota.reserve("group-a")
	now = now.Add(time.Minute)
	reserved, resetErr := quota.reserve("group-a")

	// Then
	if err == nil {
		t.Fatal("reserve at daily limit succeeded")
	}
	if resetErr != nil || !reserved.Equal(now) {
		t.Fatalf("reserve after CST reset = %s, %v", reserved, resetErr)
	}
}

func TestOfficialQQSendQuota_acquireHonorsCancellation(t *testing.T) {
	// Given
	now := time.Now().In(officialQQTimeZone)
	quota := newOfficialQQSendQuota(1, time.Minute)
	quota.now = func() time.Time { return now }
	if _, err := quota.reserve("first"); err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// When
	err := quota.acquire(ctx, "second")

	// Then
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire() error = %v, want context cancellation", err)
	}
}
