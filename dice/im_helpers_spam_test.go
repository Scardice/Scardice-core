//lint:file-ignore testpackage Tests need access to unexported helpers
package dice //nolint:testpackage // tests rely on unexported helpers

import (
	"math"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func almostEqualRateLimit(a, b rate.Limit) bool {
	const eps = 1e-9
	return math.Abs(float64(a-b)) < eps
}

func TestCalcSpamRecoveryMultiplier_BasicProgressionAndReset(t *testing.T) {
	now := time.Now().Unix()

	cmd, at, count, mul := calcSpamRecoveryMultiplier("", 0, 0, "ra", now, 30, 5)
	if cmd != "ra" || at != now || count != 1 || mul != 1 {
		t.Fatalf("unexpected first result: cmd=%q at=%d count=%d mul=%d", cmd, at, count, mul)
	}

	cmd, at, count, mul = calcSpamRecoveryMultiplier(cmd, at, count, "ra", now+3, 30, 5)
	if count != 2 || mul != 2 {
		t.Fatalf("expected same command to increase count/multiplier, got count=%d mul=%d", count, mul)
	}

	cmd, at, count, mul = calcSpamRecoveryMultiplier(cmd, at, count, "rb", now+5, 30, 5)
	if cmd != "rb" || count != 1 || mul != 1 {
		t.Fatalf("expected different command to reset count, got cmd=%q count=%d mul=%d", cmd, count, mul)
	}

	cmd, at, count, mul = calcSpamRecoveryMultiplier(cmd, at, count, "rb", now+40, 30, 5)
	if count != 1 || mul != 1 {
		t.Fatalf("expected timeout to reset count, got count=%d mul=%d", count, mul)
	}
}

func TestCalcSpamRecoveryMultiplier_MaxAndDefaults(t *testing.T) {
	now := time.Now().Unix()

	_, at, count, mul := calcSpamRecoveryMultiplier("ra", now-1, 20, "ra", now, 30, 3)
	if count != 21 || mul != 3 {
		t.Fatalf("expected multiplier capped to 3, got count=%d mul=%d", count, mul)
	}
	if at != now {
		t.Fatalf("expected updated timestamp %d, got %d", now, at)
	}

	_, _, _, mul = calcSpamRecoveryMultiplier("ra", now-1, 50, "ra", now, 0, 0)
	if mul != int(DefaultConfig.SpamRecoveryMultiplierMax) {
		t.Fatalf("expected default max multiplier %d, got %d", DefaultConfig.SpamRecoveryMultiplierMax, mul)
	}
}

func TestApplyRateLimiterPenalty(t *testing.T) {
	base := rate.Every(3 * time.Second)
	limiter := rate.NewLimiter(base, 3)

	applyRateLimiterPenalty(limiter, base, 1)
	if !almostEqualRateLimit(limiter.Limit(), base) {
		t.Fatalf("expected unchanged limit %v, got %v", base, limiter.Limit())
	}

	applyRateLimiterPenalty(limiter, base, 5)
	expected := base / 5
	if !almostEqualRateLimit(limiter.Limit(), expected) {
		t.Fatalf("expected limited rate %v, got %v", expected, limiter.Limit())
	}
}
