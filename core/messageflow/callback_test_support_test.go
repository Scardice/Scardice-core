package messageflow

import (
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/execution"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func callbackEvent(eventType, payload string) eventstore.NewEvent {
	return eventstore.NewEvent{EventType: eventType, SchemaVersion: 1, Payload: []byte(payload), Metadata: eventstore.Metadata{EventID: eventType + "-event", CommandID: eventType + "-command", CorrelationID: eventType + "-correlation", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true}}
}

func newCallbackTestInbox() *callbackTestInbox {
	payload := []byte(`{"endpointId":"endpoint","generation":1,"desiredVersion":1,"message":{"kind":1,"conversationKind":2,"sender":"user","conversation":"group","platform":"test"},"contentDigest":"AQ==","status":"pending"}`)
	return &callbackTestInbox{lease: eventstore.InboxLease{Update: eventstore.InboxUpdate{InboxID: "inbox-1", EndpointID: "endpoint", Subject: "group", Status: eventstore.InboxStatusLeased, Version: 1, LeaseOwner: "worker", LeaseEpoch: 1, AttemptID: "attempt-1", Payload: payload, ContentDigest: []byte{1}}}}
}

func callbackPendingTestInbox(id, provider, lane string) eventstore.InboxUpdate {
	fixture := newCallbackTestInbox().lease.Update
	return eventstore.InboxUpdate{
		InboxID: id, EndpointID: fixture.EndpointID, ProviderEventKey: provider,
		Lane: lane, Subject: fixture.Subject, Status: eventstore.InboxStatusPending,
		Payload: fixture.Payload, ContentDigest: fixture.ContentDigest,
	}
}
func newCallbackTestService(t *testing.T, inbox *callbackTestInbox, store *callbackTestStore, host *callbackTestHost) *CallbackService {
	t.Helper()
	service, err := NewCallbackService(CallbackConfig{Inbox: inbox, Store: store, Resolver: callbackTestResolver{}, Host: host, WorkerID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type callbackTestInbox struct {
	lease           eventstore.InboxLease
	updates         []eventstore.InboxUpdate
	claims          int
	renewals        int
	renewed         chan struct{}
	renewErr        error
	markerConflicts int
}

func (f *callbackTestInbox) AcceptInbox(context.Context, eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}
func (f *callbackTestInbox) ClaimInbox(context.Context, eventstore.InboxClaimRequest) (eventstore.InboxLease, error) {
	f.claims++
	if f.lease.Update.Status != eventstore.InboxStatusLeased {
		return eventstore.InboxLease{}, eventstore.ErrNotFound
	}
	return f.lease, nil
}
func (f *callbackTestInbox) RenewInbox(_ context.Context, request eventstore.InboxRenewRequest) (eventstore.InboxLease, error) {
	f.renewals++
	if f.renewErr != nil {
		return eventstore.InboxLease{}, f.renewErr
	}
	f.lease.Update.Version++
	f.lease.Update.LeaseExpiresAt = time.Now().UTC().Add(request.LeaseDuration)
	if f.renewed != nil {
		select {
		case f.renewed <- struct{}{}:
		default:
		}
	}
	return f.lease, nil
}

func (f *callbackTestInbox) UpdateInbox(_ context.Context, update eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	if update.Status == eventstore.InboxStatusCallbackStarted && f.markerConflicts > 0 {
		f.markerConflicts--
		return eventstore.CommitResult{}, eventstore.ErrConflict
	}
	f.updates = append(f.updates, update)
	f.lease.Update.Status = update.Status
	f.lease.Update.Version++
	return eventstore.CommitResult{Version: f.lease.Update.Version}, nil
}
func (f *callbackTestInbox) ResolveInbox(context.Context, eventstore.InboxResolutionRequest) (eventstore.CommitResult, error) {
	return eventstore.CommitResult{}, nil
}

type callbackTestStore struct {
	commits   []eventstore.UnitOfWork
	commitErr error
	onCommit  func()
}

func (f *callbackTestStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if f.onCommit != nil {
		f.onCommit()
	}
	if f.commitErr != nil {
		return eventstore.CommitResult{}, f.commitErr
	}
	f.commits = append(f.commits, work)
	return eventstore.CommitResult{}, nil
}
func (*callbackTestStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}
func (*callbackTestStore) Close() error { return nil }

type callbackTestFence struct {
	locked      bool
	lockCalls   int
	unlockCalls int
}

func (f *callbackTestFence) TryLock() bool {
	if f.locked {
		return false
	}
	f.locked = true
	f.lockCalls++
	return true
}

func (f *callbackTestFence) Unlock() {
	f.locked = false
	f.unlockCalls++
}

type callbackTestResolver struct{}

func (callbackTestResolver) Resolve(context.Context, string, adapterapi.InboundMessage) (CallbackScope, error) {
	return CallbackScope{DiceID: "dice", GroupID: "group", UserID: "user"}, nil
}

type callbackTestHost struct {
	inbox          *callbackTestInbox
	called         bool
	markerObserved bool
	panic          bool
	calls          int
	fn             func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *execution.MutationCollector) (CallbackResult, error)
}

func (h *callbackTestHost) HandleCallback(ctx context.Context, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *execution.MutationCollector) (CallbackResult, error) {
	h.called = true
	h.calls++
	if h.inbox != nil {
		for _, update := range h.inbox.updates {
			if update.Status == eventstore.InboxStatusCallbackStarted {
				h.markerObserved = true
			}
		}
	}
	if h.panic {
		panic("host panic")
	}
	if h.fn != nil {
		return h.fn(ctx, request, overlay, collector)
	}
	return CallbackResult{}, nil
}

type callbackFixedClock struct {
	now time.Time
}

func (c *callbackFixedClock) Now() time.Time { return c.now }

type eventstoreInboxRowForTest struct {
	Status  string
	Payload []byte
}
