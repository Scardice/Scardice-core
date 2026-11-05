package eventstore

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type queueTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *queueTestClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *queueTestClock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func openQueueTestStore(t *testing.T) (*GORMStore, *Database, *queueTestClock) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task5.db")})
	if err != nil {
		t.Fatal(err)
	}
	clock := &queueTestClock{now: time.Unix(100, 0).UTC()}
	return NewStore(db, WithClock(clock)), db, clock
}
func newInboxTestUpdate(id, provider, lane string) InboxUpdate {
	return InboxUpdate{InboxID: id, EndpointID: "endpoint", ProviderEventKey: provider, Lane: lane, Status: InboxStatusPending, Payload: []byte("inbound-payload")}
}

func newOutboxTestEffect(id, lane string) NewEffect {
	return NewEffect{EffectID: id, EndpointID: "endpoint", Lane: lane, EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, Payload: []byte("outbound-payload")}
}
