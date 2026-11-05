package messageflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
func (r *ingressRepoStub) RenewInbox(context.Context, eventstore.InboxRenewRequest) (eventstore.InboxLease, error) {
	return eventstore.InboxLease{}, eventstore.ErrNotFound
}
func (r *ingressRepoStub) UpdateInbox(context.Context, eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrNotFound
}
func (r *ingressRepoStub) ResolveInbox(context.Context, eventstore.InboxResolutionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, eventstore.ErrNotFound
}

func testFencedMessage(id adapterapi.ProviderEventID, text string) endpoint.FencedInbound {
	return endpoint.FencedInbound{EndpointID: "ep-1", Generation: 2, DesiredVersion: 3, Message: adapterapi.InboundMessage{ProviderEventID: id, Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup, Platform: "QQ", Sender: "QQ:42", Conversation: "QQ:group:9", Target: "QQ:group:9", Text: text, OccurredAt: time.Unix(100, 0).UTC()}}
}

func TestInboundServiceStableDuplicateReturnsPriorReceiptAndStoresPlaintextBody(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo, WithIngressCapacity(2))
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.HandleInbound(context.Background(), testFencedMessage("stable-1", "secret body"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.HandleInbound(context.Background(), testFencedMessage("stable-1", "secret body"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != adapterapi.IngressAccepted || second.Outcome != adapterapi.IngressDuplicate || second.InboxID != first.InboxID {
		t.Fatalf("receipts = %#v %#v", first, second)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.updates) != 1 {
		t.Fatalf("updates = %#v", repo.updates)
	}
	if repo.updates[0].OrderingSequence != 1 {
		t.Fatalf("ordering = %d", repo.updates[0].OrderingSequence)
	}
	if repo.updates[0].Subject != "QQ:group:9" || repo.updates[0].Lane != `["ep-1","group","QQ:group:9","live"]` {
		t.Fatalf("plaintext identity subject=%q lane=%q", repo.updates[0].Subject, repo.updates[0].Lane)
	}
	var stored ingressPayload
	if err := json.Unmarshal(repo.updates[0].Payload, &stored); err != nil || stored.Message.Text != "secret body" {
		t.Fatalf("stored ingress=%+v err=%v", stored, err)
	}
}

func TestInboundServiceFallbackDuplicateAndCollision(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	noID := testFencedMessage("", "body")
	first, err := svc.HandleInbound(context.Background(), noID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.HandleInbound(context.Background(), noID)
	if err != nil {
		t.Fatal(err)
	}
	if first.InboxID != second.InboxID || second.Outcome != adapterapi.IngressDuplicate {
		t.Fatalf("fallback receipts = %#v %#v", first, second)
	}
	collision := noID
	collision.Message.Text = "changed"
	if _, err := svc.HandleInbound(context.Background(), collision); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("fallback collision = %v", err)
	}
	if svc.CollisionCount() == 0 {
		t.Fatal("fallback collision telemetry was not recorded")
	}
}

func TestInboundServiceNoIDNoTimeUsesContentDigestIdentity(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	message := testFencedMessage("", "body")
	message.Message.OccurredAt = time.Time{}
	first, err := svc.HandleInbound(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := svc.HandleInbound(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Outcome != adapterapi.IngressDuplicate || duplicate.InboxID != first.InboxID {
		t.Fatalf("no-time duplicate = %#v, first = %#v", duplicate, first)
	}
	message.Message.Text = "changed"
	changed, err := svc.HandleInbound(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Outcome != adapterapi.IngressAccepted || changed.InboxID == first.InboxID {
		t.Fatalf("no-time content identity = %#v, first = %#v", changed, first)
	}
}

func TestInboundServiceRejectsAggregatePayloadBeforeMarshal(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("x", 150*1024)
	message := testFencedMessage("aggregate", "body")
	message.Message.Segments = []adapterapi.InboundSegment{
		{Kind: "text", Text: large},
		{Kind: "text", Text: large},
	}
	if _, err := svc.HandleInbound(context.Background(), message); !errors.Is(err, ErrIngressPayload) {
		t.Fatalf("aggregate payload error = %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.updates) != 0 {
		t.Fatalf("oversized aggregate admitted %d updates", len(repo.updates))
	}
}

func TestInboundServiceRejectsEscapeHeavyAggregateBeforeMarshal(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	segments := make([]adapterapi.InboundSegment, adapterapi.MaxInboundSegments)
	for i := range segments {
		segments[i] = adapterapi.InboundSegment{Kind: "text", Text: strings.Repeat("\x00", 160)}
	}
	message := testFencedMessage("escape-heavy", "body")
	message.Message.Segments = segments
	if _, err := svc.HandleInbound(context.Background(), message); !errors.Is(err, ErrIngressPayload) {
		t.Fatalf("escape-heavy aggregate error = %v", err)
	}
}

func TestInboundServiceRejectsEnvelopeAggregateBeforePayloadMarshal(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	message := testFencedMessage("envelope", strings.Repeat("x", 232*1024))
	message.EndpointID = adapterapi.EndpointID(strings.Repeat("e", adapterapi.MaxIdentifierBytes))
	if _, err := svc.HandleInbound(context.Background(), message); !errors.Is(err, ErrIngressPayload) {
		t.Fatalf("envelope aggregate error = %v", err)
	}
}

func TestInboundPayloadUpperBoundAllowsNormal100KiBMessage(t *testing.T) {
	message := testFencedMessage("normal-bound", strings.Repeat("x", 100*1024))
	messageBound := inboundJSONUpperBound(message.Message)
	if got := ingressPayloadJSONUpperBound(message.EndpointID, messageBound, 32); got > eventstore.MaxEventPayloadBytes {
		t.Fatalf("normal 100 KiB envelope bound = %d, want <= %d", got, eventstore.MaxEventPayloadBytes)
	}
}

func TestInboundJSONEscapedLenCoversUnicodeLineSeparators(t *testing.T) {
	value := "\u2028\u2029"
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inboundJSONEscapedLen(value), len(encoded)-2; got != want {
		t.Fatalf("escaped length = %d, want %d", got, want)
	}
}

func TestInboundJSONEscapedLenCoversInvalidUTF8Replacement(t *testing.T) {
	value := string([]byte{0xff})
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inboundJSONEscapedLen(value), len(encoded)-2; got < want {
		t.Fatalf("escaped length = %d, want at least %d", got, want)
	}
}
func TestInboundServiceStableIDChangedBodyIsCollision(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	first := testFencedMessage("stable-envelope", "before")
	if _, err := svc.HandleInbound(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	first.Message.Text = "after"
	if _, err := svc.HandleInbound(context.Background(), first); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stable envelope collision = %v", err)
	}
}

func TestInboundServiceConversationLaneIgnoresDifferentTarget(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	first := testFencedMessage("lane-1", "one")
	second := testFencedMessage("lane-2", "two")
	second.Message.Target = "QQ:another-target"
	if _, err := svc.HandleInbound(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.HandleInbound(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.updates[0].Lane != repo.updates[1].Lane {
		t.Fatalf("conversation split lanes: %q %q", repo.updates[0].Lane, repo.updates[1].Lane)
	}
}

func TestInboundServiceSeparatesEndpointAndConversationKinds(t *testing.T) {
	repo := &ingressRepoStub{}
	service, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	group := testFencedMessage("group", "group")
	direct := testFencedMessage("direct", "direct")
	direct.Message.ConversationKind = adapterapi.ConversationKindDirect
	otherEndpoint := testFencedMessage("other-endpoint", "other")
	otherEndpoint.EndpointID = "ep-2"
	for _, message := range []endpoint.FencedInbound{group, direct, otherEndpoint} {
		if _, err := service.HandleInbound(context.Background(), message); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		`["ep-1","group","QQ:group:9","live"]`,
		`["ep-1","person","QQ:group:9","live"]`,
		`["ep-2","group","QQ:group:9","live"]`,
	}
	for i, update := range repo.updates {
		if update.Lane != want[i] {
			t.Fatalf("lane[%d]=%q want=%q", i, update.Lane, want[i])
		}
	}
}

func TestInboundServiceRejectsWhenBoundedAdmissionIsFull(t *testing.T) {
	release := make(chan struct{})
	repo := &ingressRepoStub{block: release}
	svc, err := NewInboundService(repo, WithIngressCapacity(1))
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := svc.HandleInbound(context.Background(), testFencedMessage("one", "one"))
		firstDone <- err
	}()
	deadline := time.After(time.Second)
	for svc.InFlight() != 1 {
		select {
		case <-deadline:
			t.Fatal("first ingress did not acquire capacity")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := svc.HandleInbound(context.Background(), testFencedMessage("two", "two")); !errors.Is(err, ErrIngressBackpressure) {
		t.Fatalf("backpressure = %v", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

type fixedIngressClock struct{ now time.Time }

func (c fixedIngressClock) Now() time.Time { return c.now }

func TestInboundServiceAssignsLaneOrder(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.HandleInbound(context.Background(), testFencedMessage("ordered-1", "one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.HandleInbound(context.Background(), testFencedMessage("ordered-2", "two"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != adapterapi.IngressAccepted || second.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("outcomes = %#v %#v", first, second)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.updates) != 2 || repo.updates[0].OrderingSequence != 1 || repo.updates[1].OrderingSequence != 2 {
		t.Fatalf("ordered updates = %#v", repo.updates)
	}
	if repo.updates[0].Lane != repo.updates[1].Lane {
		t.Fatalf("same conversation split lanes: %q %q", repo.updates[0].Lane, repo.updates[1].Lane)
	}
}
