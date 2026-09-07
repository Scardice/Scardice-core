package messageflow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

type ingressRepoStub struct {
	mu      sync.Mutex
	updates []eventstore.InboxUpdate
	block   <-chan struct{}
}

func (r *ingressRepoStub) AcceptInbox(ctx context.Context, update eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	if r.block != nil {
		select {
		case <-r.block:
		case <-ctx.Done():
			return eventstore.CommitResult{}, ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, prior := range r.updates {
		if prior.EndpointID == update.EndpointID && prior.ProviderEventKey == update.ProviderEventKey {
			if string(prior.ContentDigest) == string(update.ContentDigest) {
				return eventstore.CommitResult{InboxIDs: []string{prior.InboxID}, OrderingSequence: prior.OrderingSequence, Version: 1, Deduplicated: true}, nil
			}
			return eventstore.CommitResult{}, eventstore.ErrConflict
		}
	}
	update.OrderingSequence = uint64(len(r.updates) + 1)
	r.updates = append(r.updates, update)
	return eventstore.CommitResult{InboxIDs: []string{update.InboxID}, OrderingSequence: update.OrderingSequence, Version: 1}, nil
}
func (r *ingressRepoStub) ClaimInbox(context.Context, eventstore.InboxClaimRequest) (eventstore.InboxLease, error) {
	return eventstore.InboxLease{}, eventstore.ErrNotFound
}
func (r *ingressRepoStub) UpdateInbox(context.Context, eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrNotFound
}
func (r *ingressRepoStub) ResolveInbox(context.Context, eventstore.InboxResolutionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrNotFound
}

type ingressCryptoStub struct{}
func (ingressCryptoStub) EncryptBound(_ context.Context, _, _, _ string, _ uint64, plaintext []byte) ([]byte, []byte, string, error) {
	return append([]byte("sealed:"), plaintext...), []byte("nonce"), "key-1", nil
}
func (ingressCryptoStub) KeyedDigest(_ context.Context, domain string, parts ...string) ([]byte, string, error) {
	return []byte(domain + ":" + stringsJoin(parts)), "index-1", nil
}
func stringsJoin(parts []string) string {
	var out string
	for _, p := range parts { out += "|" + p }
	return out
}

func testFencedMessage(id adapterapi.ProviderEventID, text string) endpoint.FencedInbound {
	return endpoint.FencedInbound{EndpointID: "ep-1", Generation: 2, DesiredVersion: 3, Message: adapterapi.InboundMessage{ProviderEventID: id, Kind: adapterapi.InboundKindMessage, Platform: "QQ", Sender: "QQ:42", Conversation: "QQ:group:9", Target: "QQ:group:9", Text: text, OccurredAt: time.Unix(100, 0).UTC()}}
}

func TestInboundServiceStableDuplicateReturnsPriorReceiptAndStoresEncryptedBody(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo, ingressCryptoStub{}, WithIngressCapacity(2))
	if err != nil { t.Fatal(err) }
	first, err := svc.HandleInbound(context.Background(), testFencedMessage("stable-1", "secret body"))
	if err != nil { t.Fatal(err) }
	second, err := svc.HandleInbound(context.Background(), testFencedMessage("stable-1", "secret body"))
	if err != nil { t.Fatal(err) }
	if first.Outcome != adapterapi.IngressAccepted || second.Outcome != adapterapi.IngressDuplicate || second.InboxID != first.InboxID { t.Fatalf("receipts = %#v %#v", first, second) }
	repo.mu.Lock(); defer repo.mu.Unlock()
	if len(repo.updates) != 1 || string(repo.updates[0].PayloadCiphertext) == "secret body" { t.Fatalf("updates = %#v", repo.updates) }
	if repo.updates[0].OrderingSequence != 1 { t.Fatalf("ordering = %d", repo.updates[0].OrderingSequence) }
}

func TestInboundServiceFallbackDuplicateAndCollision(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo, ingressCryptoStub{})
	if err != nil { t.Fatal(err) }
	noID := testFencedMessage("", "body")
	first, err := svc.HandleInbound(context.Background(), noID)
	if err != nil { t.Fatal(err) }
	second, err := svc.HandleInbound(context.Background(), noID)
	if err != nil { t.Fatal(err) }
	if first.InboxID != second.InboxID || second.Outcome != adapterapi.IngressDuplicate { t.Fatalf("fallback receipts = %#v %#v", first, second) }
	collision := noID
	collision.Message.Text = "changed"
	if _, err := svc.HandleInbound(context.Background(), collision); !errors.Is(err, eventstore.ErrConflict) { t.Fatalf("fallback collision = %v", err) }
	if svc.CollisionCount() == 0 { t.Fatal("fallback collision telemetry was not recorded") }
}

func TestInboundServiceRejectsWhenBoundedAdmissionIsFull(t *testing.T) {
	release := make(chan struct{})
	repo := &ingressRepoStub{block: release}
	svc, err := NewInboundService(repo, ingressCryptoStub{}, WithIngressCapacity(1))
	if err != nil { t.Fatal(err) }
	firstDone := make(chan error, 1)
	go func() { _, err := svc.HandleInbound(context.Background(), testFencedMessage("one", "one")); firstDone <- err }()
	deadline := time.After(time.Second)
	for {
		if svc.InFlight() == 1 { break }
		select { case <-deadline: t.Fatal("first ingress did not acquire capacity"); default: time.Sleep(time.Millisecond) }
	}
	if _, err := svc.HandleInbound(context.Background(), testFencedMessage("two", "two")); !errors.Is(err, ErrIngressBackpressure) { t.Fatalf("backpressure = %v", err) }
	close(release)
	if err := <-firstDone; err != nil { t.Fatal(err) }
}

type fixedIngressClock struct{ now time.Time }
func (c fixedIngressClock) Now() time.Time { return c.now }

func TestInboundServiceAssignsLaneOrderAndSevenDayPayloadTTL(t *testing.T) {
	repo := &ingressRepoStub{}
	now := time.Unix(200, 0).UTC()
	svc, err := NewInboundService(repo, ingressCryptoStub{}, WithIngressClock(fixedIngressClock{now: now}))
	if err != nil { t.Fatal(err) }
	first, err := svc.HandleInbound(context.Background(), testFencedMessage("ordered-1", "one"))
	if err != nil { t.Fatal(err) }
	second, err := svc.HandleInbound(context.Background(), testFencedMessage("ordered-2", "two"))
	if err != nil { t.Fatal(err) }
	if first.Outcome != adapterapi.IngressAccepted || second.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("outcomes = %#v %#v", first, second)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.updates) != 2 || repo.updates[0].OrderingSequence != 1 || repo.updates[1].OrderingSequence != 2 {
		t.Fatalf("ordered updates = %#v", repo.updates)
	}
	if string(repo.updates[0].LaneHMAC) != string(repo.updates[1].LaneHMAC) {
		t.Fatalf("same conversation split lanes: %q %q", repo.updates[0].LaneHMAC, repo.updates[1].LaneHMAC)
	}
	if got := repo.updates[0].PayloadExpiresAt.Sub(now); got != IngressPayloadTTL {
		t.Fatalf("payload ttl = %s", got)
	}
}
