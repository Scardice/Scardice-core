package dice

import (
	"testing"
	"time"
)

func TestPrunePendingQuitsPreservesValidOriginsAndExpiryBoundary(t *testing.T) {
	now := time.Now()
	session := &IMSession{PendingQuits: new(SyncMap[string, *PendingQuitInfo])}
	expiredKey := makePendingQuitKey("expired", "endpoint")
	boundaryKey := makePendingQuitKey("boundary", "endpoint")
	validKey := makePendingQuitKey("valid", "endpoint")
	expired := &PendingQuitInfo{Origin: QuitOriginAutoInactive, ExpireAt: now.Add(-time.Second)}
	boundary := &PendingQuitInfo{Origin: QuitOriginAutoInactive, ExpireAt: now}
	valid := &PendingQuitInfo{Origin: QuitOriginAutoInactive, ExpireAt: now.Add(time.Hour)}
	session.PendingQuits.Store(expiredKey, expired)
	session.PendingQuits.Store(boundaryKey, boundary)
	session.PendingQuits.Store(validKey, valid)
	session.pruneExpiredPendingQuits(now)
	if _, exists := session.PendingQuits.Load(expiredKey); exists {
		t.Fatal("expired unacknowledged quit marker was retained")
	}
	if got, exists := session.PendingQuits.Load(boundaryKey); !exists || got != boundary {
		t.Fatal("marker at its exact expiry boundary was removed early")
	}
	if got := session.ConsumePendingQuit("valid", "endpoint"); got != valid || got.Origin != QuitOriginAutoInactive {
		t.Fatalf("valid automatic quit lost its origin: %v", got)
	}
	if got := session.ConsumePendingQuit("valid", "endpoint"); got != nil {
		t.Fatal("quit marker was consumed twice")
	}
	session.MarkPendingQuit("expired", "endpoint", QuitOriginAutoInactive, time.Hour)
	session.pruneExpiredPendingQuits(now)
	if got := session.ConsumePendingQuit("expired", "endpoint"); got == nil || got == expired {
		t.Fatal("replacement quit marker was lost")
	}
}
