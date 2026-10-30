package messageflow

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestCallbackCancelsInFlightRenewalBeforeJoiningHeartbeat(t *testing.T) {
	inbox := &callbackBlockingRenewInbox{
		callbackTestInbox: newCallbackTestInbox(),
		started:           make(chan struct{}),
		canceled:          make(chan struct{}),
	}
	var afterCommit atomic.Bool
	releasedAfterCommit := make(chan bool, 1)
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		<-inbox.started
		return CallbackResult{
			AfterCommit: func() { afterCommit.Store(true) },
			Release:     func() { releasedAfterCommit <- afterCommit.Load() },
		}, nil
	}}
	store := &callbackTestStore{}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{},
		Host: host, WorkerID: "worker", LeaseDuration: callbackMinimumLeaseDuration,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type processResult struct {
		err error
	}
	done := make(chan processResult, 1)
	go func() {
		_, processErr := service.ProcessOne(ctx)
		done <- processResult{err: processErr}
	}()

	var result processResult
	select {
	case result = <-done:
	case <-time.After(time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("ProcessOne remained blocked after test cancellation")
		}
		t.Fatal("ProcessOne did not return after canceling the in-flight renewal")
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("ProcessOne error = %v, want canceled renewal error", result.err)
	}
	select {
	case <-inbox.canceled:
	default:
		t.Fatal("ProcessOne returned before the in-flight renewal observed cancellation")
	}
	select {
	case ranAfterCommit := <-releasedAfterCommit:
		if ranAfterCommit {
			t.Fatal("AfterCommit ran despite the uncertain canceled renewal")
		}
	default:
		t.Fatal("callback result was not released when ProcessOne returned")
	}
	if len(store.commits) != 0 {
		t.Fatalf("committed callback with uncertain lease version: %#v", store.commits)
	}
	if len(inbox.updates) != 2 || inbox.updates[1].Status != eventstore.InboxStatusAmbiguous || inbox.updates[1].ExpectedVersion != 2 {
		t.Fatalf("canceled renewal was not failed closed at the last known lease version: %#v", inbox.updates)
	}
}

type callbackBlockingRenewInbox struct {
	*callbackTestInbox
	started  chan struct{}
	canceled chan struct{}
}

func (f *callbackBlockingRenewInbox) RenewInbox(ctx context.Context, _ eventstore.InboxRenewRequest) (eventstore.InboxLease, error) {
	close(f.started)
	<-ctx.Done()
	close(f.canceled)
	return eventstore.InboxLease{}, ctx.Err()
}
