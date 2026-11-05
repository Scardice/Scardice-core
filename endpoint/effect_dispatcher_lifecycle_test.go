package endpoint

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

type dispatcherTestNotificationOwner struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	workers  sync.WaitGroup
	stopOnce sync.Once
	done     chan struct{}
}

func newDispatcherTestNotificationOwner(t *testing.T) *dispatcherTestNotificationOwner {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	owner := &dispatcherTestNotificationOwner{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	t.Cleanup(func() {
		owner.stop()
		select {
		case <-owner.done:
		case <-time.After(3 * time.Second):
			t.Error("dispatcher notifications did not join")
		}
	})
	return owner
}

func (owner *dispatcherTestNotificationOwner) Go(run func(context.Context)) bool {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || run == nil {
		return false
	}
	owner.workers.Add(1)
	go func() {
		defer owner.workers.Done()
		run(owner.ctx)
	}()
	return true
}

func (owner *dispatcherTestNotificationOwner) stop() {
	owner.stopOnce.Do(func() {
		owner.mu.Lock()
		owner.closed = true
		owner.cancel()
		owner.mu.Unlock()
		go func() {
			owner.workers.Wait()
			close(owner.done)
		}()
	})
}

type dispatcherLifetimeNotifier struct {
	started  chan context.Context
	canceled chan struct{}
	release  <-chan struct{}
}

func (notifier dispatcherLifetimeNotifier) run(ctx context.Context) {
	notifier.started <- ctx
	select {
	case <-ctx.Done():
		notifier.canceled <- struct{}{}
	case <-notifier.release:
		return
	}
	<-notifier.release
}

func (notifier dispatcherLifetimeNotifier) NotifyOutboundEffectResult(ctx context.Context, _ adapterapi.OutboundEffect, _ adapterapi.EffectResult) {
	notifier.run(ctx)
}

func (notifier dispatcherLifetimeNotifier) NotifyOutboundEffectSucceeded(ctx context.Context, _ adapterapi.OutboundEffect, _ adapterapi.EffectResult) {
	notifier.run(ctx)
}

func TestDispatcherCompletionNotificationsFollowOwnerLifetime(t *testing.T) {
	ctx := t.Context()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: filepath.Join(t.TempDir(), "notifications.db"), DatabaseIdentity: "notifications",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database)
	if err = store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "notifications", CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	effect := dispatcherRecoveryEffect(t, "owned-notification", "owned-notification-operation", adapterapi.EffectRetryNonIdempotent)
	effect.Deadline = time.Now().Add(time.Minute)
	payload, err := json.Marshal(struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}{Effect: effect})
	if err != nil {
		t.Fatal(err)
	}
	sourcePayload, err := json.Marshal(map[string]string{
		"effectId": string(effect.ID), "operationId": string(effect.OperationID), "endpointId": string(effect.EndpointID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Commit(ctx, eventstore.UnitOfWork{
		Streams: []eventstore.StreamAppend{{
			Stream: eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: string(effect.ID)},
			Events: []eventstore.NewEvent{{
				EventType: "OutboundEffectRequestedV1", SchemaVersion: 1, Payload: sourcePayload,
				Metadata: eventstore.Metadata{
					EventID: "owned-notification-request", CommandID: "owned-notification-command",
					CorrelationID: "owned-notification-command", OccurredAt: time.Now().UTC(),
				},
			}},
		}},
		Operations: []eventstore.OperationUpdate{{
			OperationID: string(effect.OperationID), Version: 1, Kind: "outbound-effect", Status: "pending",
			PrincipalID: "notification-owner", ResourceID: string(effect.ID),
		}},
		Effects: []eventstore.NewEffect{{
			EffectID: string(effect.ID), Version: 1, EndpointID: string(effect.EndpointID), Lane: effect.Lane.Key,
			EffectType: "message", RiskClass: eventstore.RiskNonIdempotentAfterDispatch, Status: eventstore.OutboxStatusPending,
			Payload: payload, ContentDigest: eventstore.DigestBytes("effect-content/v1", payload), DeadlineAt: effect.Deadline,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	owner := newDispatcherTestNotificationOwner(t)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseNotifiers := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseNotifiers)
	notifier := dispatcherLifetimeNotifier{started: make(chan context.Context, 2), canceled: make(chan struct{}, 2), release: release}
	dispatcher, err := NewEffectDispatcher(store, dispatcherTestExecutor{}, "owned-notification-worker",
		WithEffectResultNotifier(notifier), WithEffectSuccessNotifier(notifier),
		WithDispatcherNotificationOwner(owner),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := dispatcher.DispatchOnce(ctx)
	if err != nil || result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("dispatch result = %#v, err = %v", result, err)
	}
	for range 2 {
		select {
		case notificationCtx := <-notifier.started:
			if deadline, bounded := notificationCtx.Deadline(); !bounded || time.Until(deadline) > 30*time.Second {
				t.Error("committed completion notification has no bounded lifetime")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("committed completion notification did not start")
		}
	}
	owner.stop()
	for range 2 {
		select {
		case <-notifier.canceled:
		case <-time.After(3 * time.Second):
			t.Error("notification did not observe owner cancellation")
		}
	}
	select {
	case <-owner.done:
		t.Error("owner joined before its admitted completion notifications returned")
	default:
	}
	releaseNotifiers()
	select {
	case <-owner.done:
	case <-time.After(3 * time.Second):
		t.Fatal("completion notifications did not join after release")
	}
	operation, err := store.GetOperation(ctx, string(effect.OperationID))
	if err != nil || operation.Status != "succeeded" {
		t.Fatalf("notification cancellation changed committed provider success: %#v, %v", operation, err)
	}
}
