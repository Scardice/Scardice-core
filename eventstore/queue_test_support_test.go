package eventstore

import (
	"context"
	"errors"
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

type queueTestCodec struct{}

func (queueTestCodec) Encrypt(_ context.Context, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "test-key", nil
}
func (queueTestCodec) Decrypt(_ context.Context, ciphertext, _ []byte, _ string) ([]byte, error) {
	const prefix = "sealed:"
	if len(ciphertext) < len(prefix) || string(ciphertext[:len(prefix)]) != prefix {
		return nil, errors.New("bad ciphertext")
	}
	return append([]byte(nil), ciphertext[len(prefix):]...), nil
}

type corruptQueueTestCodec struct {
	plaintext []byte
}

func (corruptQueueTestCodec) Encrypt(_ context.Context, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "test-key", nil
}
func (c corruptQueueTestCodec) Decrypt(_ context.Context, _ []byte, _ []byte, _ string) ([]byte, error) {
	return append([]byte(nil), c.plaintext...), nil
}

func openQueueTestStore(t *testing.T) (*GORMStore, *Database, *queueTestClock) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "task5.db")})
	if err != nil {
		t.Fatal(err)
	}
	clock := &queueTestClock{now: time.Unix(100, 0).UTC()}
	return NewStore(db, WithClock(clock), WithPayloadCodec(queueTestCodec{})), db, clock
}
func newInboxTestUpdate(id, provider, lane string) InboxUpdate {
	return InboxUpdate{InboxID: id, EndpointID: "endpoint", ProviderEventKey: provider, LaneHMAC: []byte(lane), Status: InboxStatusPending, PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "digest-key"}
}

func newOutboxTestEffect(id, lane string) NewEffect {
	return NewEffect{EffectID: id, EndpointID: "endpoint", LaneHMAC: []byte(lane), EffectType: "send", RiskClass: RiskPreDispatchRetryable, Status: OutboxStatusPending, PayloadCiphertext: []byte("ciphertext"), PayloadNonce: []byte("nonce"), DigestKeyID: "digest-key"}
}
