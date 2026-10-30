package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestEventWorkerGroupShutdownWaitsForWorkers(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	group.Go(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		<-release
	})
	<-started

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- group.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before worker exit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
}

func TestEventWorkerGroupShutdownHonorsDeadline(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	group.Go(func(context.Context) {
		close(started)
		<-release
	})
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := group.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", err)
	}
	close(release)
}

func TestStartEventWorkerPoolStartsExactlyConfiguredWorkers(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	started := make(chan int, 4)
	release := make(chan struct{})
	err := startEventWorkerPool(group, 3, func(index int) (func(context.Context), error) {
		return func(ctx context.Context) {
			started <- index
			select {
			case <-ctx.Done():
			case <-release:
			}
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for range 3 {
		select {
		case index := <-started:
			seen[index] = true
		case <-time.After(time.Second):
			t.Fatal("configured worker did not start")
		}
	}
	select {
	case index := <-started:
		t.Fatalf("unexpected extra worker %d", index)
	case <-time.After(20 * time.Millisecond):
	}
	if len(seen) != 3 {
		t.Fatalf("started worker indexes = %v", seen)
	}
	close(release)
	if err := group.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNextEventWorkerIdleDelayBacksOffAndCaps(t *testing.T) {
	delay := time.Duration(0)
	want := []time.Duration{
		eventCallbackIdleDelay,
		2 * eventCallbackIdleDelay,
		4 * eventCallbackIdleDelay,
		8 * eventCallbackIdleDelay,
		eventWorkerMaximumIdleDelay,
	}
	for i, expected := range want {
		delay = nextEventWorkerIdleDelay(delay, eventCallbackIdleDelay)
		if delay != expected {
			t.Fatalf("step %d delay = %s, want %s", i, delay, expected)
		}
	}
	if delay = nextEventWorkerIdleDelay(delay, eventCallbackIdleDelay); delay != eventWorkerMaximumIdleDelay {
		t.Fatalf("capped delay = %s, want %s", delay, eventWorkerMaximumIdleDelay)
	}
}

func TestWaitEventWorkerWakesForCommittedWork(t *testing.T) {
	work := make(chan struct{}, 1)
	work <- struct{}{}
	if !waitEventWorker(context.Background(), time.Hour, work) {
		t.Fatal("worker stopped instead of waking for committed work")
	}
}

func TestStartEventWorkerPoolRejectsAdmissionAfterShutdown(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	if err := group.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	var factoryCalled atomic.Bool
	err := startEventWorkerPool(group, 1, func(int) (func(context.Context), error) {
		factoryCalled.Store(true)
		return func(context.Context) {}, nil
	})
	if err == nil {
		t.Fatal("worker pool admitted work after shutdown")
	}
	if factoryCalled.Load() {
		t.Fatal("worker factory ran after shutdown closed admission")
	}
}

type eventQueueProbeResult struct {
	available bool
	err       error
}

func receiveEventQueueProbe(t *testing.T, requests <-chan chan eventQueueProbeResult) chan eventQueueProbeResult {
	t.Helper()
	select {
	case response := <-requests:
		return response
	case <-time.After(time.Second):
		t.Fatal("queue coordinator did not issue the expected probe")
		return nil
	}
}

func waitEventTestClosed(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestEventQueueCoordinatorCoalescesPersistentProbeErrorsUntilSuccess(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := group.Shutdown(ctx); err != nil {
			t.Errorf("shutdown queue coordinator: %v", err)
		}
	})

	requests := make(chan chan eventQueueProbeResult)
	work := make(chan struct{}, 1)
	queue := newEventQueueCoordinator(group, 2*time.Millisecond, work, func(ctx context.Context) (bool, error) {
		response := make(chan eventQueueProbeResult, 1)
		select {
		case requests <- response:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		select {
		case result := <-response:
			return result.available, result.err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	})

	wake := queue.signal()
	permanentErr := errors.New("probe unavailable")
	first := receiveEventQueueProbe(t, requests)
	first <- eventQueueProbeResult{err: permanentErr}
	second := receiveEventQueueProbe(t, requests)
	select {
	case <-wake:
		t.Fatal("first failed advisory probe woke every worker")
	default:
	}

	second <- eventQueueProbeResult{err: permanentErr}
	third := receiveEventQueueProbe(t, requests)
	select {
	case <-wake:
		t.Fatal("repeated failed advisory probe created another worker wake generation")
	default:
	}

	third <- eventQueueProbeResult{available: true}
	waitEventTestClosed(t, wake, "worker wake after a successful availability probe")
}

func TestEventQueueCoordinatorNewWorkWakesAfterProbeError(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := group.Shutdown(ctx); err != nil {
			t.Errorf("shutdown queue coordinator: %v", err)
		}
	})

	requests := make(chan chan eventQueueProbeResult)
	work := make(chan struct{}, 1)
	queue := newEventQueueCoordinator(group, 2*time.Millisecond, work, func(ctx context.Context) (bool, error) {
		response := make(chan eventQueueProbeResult, 1)
		select {
		case requests <- response:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		select {
		case result := <-response:
			return result.available, result.err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	})

	wake := queue.signal()
	first := receiveEventQueueProbe(t, requests)
	first <- eventQueueProbeResult{err: errors.New("probe unavailable")}
	second := receiveEventQueueProbe(t, requests)
	select {
	case <-wake:
		t.Fatal("failed advisory probe woke workers before new work arrived")
	default:
	}

	work <- struct{}{}
	second <- eventQueueProbeResult{err: errors.New("probe still unavailable")}
	waitEventTestClosed(t, wake, "worker wake after committed work")
}

func TestEventQueueCoordinatorStopsWhenWorkSignalCloses(t *testing.T) {
	const helperEnv = "SCARDICE_TEST_CLOSED_EVENT_WORK_SIGNAL"
	if os.Getenv(helperEnv) == "1" {
		group := newEventWorkerGroup(context.Background())
		work := make(chan struct{}, 1)
		queue := newEventQueueCoordinator(group, time.Hour, work, func(context.Context) (bool, error) {
			return false, nil
		})
		wake := queue.signal()
		work <- struct{}{}
		waitEventTestClosed(t, wake, "initial work notification")
		close(work)
		time.Sleep(10 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := group.Shutdown(ctx); err != nil {
			t.Fatalf("coordinator did not stop after its work signal closed: %v", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEventQueueCoordinatorStopsWhenWorkSignalCloses$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("closed work signal regression failed: %v\n%s", err, output)
	}
}

type crossingOutboxStore struct {
	*eventstore.GORMStore
	calls        atomic.Int64
	firstEntered chan struct{}
	firstRelease chan struct{}
	second       chan struct{}
}

func (s *crossingOutboxStore) ClaimOutbox(ctx context.Context, _ eventstore.OutboxClaimRequest) (eventstore.OutboxLease, error) {
	switch s.calls.Add(1) {
	case 1:
		close(s.firstEntered)
		select {
		case <-s.firstRelease:
		case <-ctx.Done():
			return eventstore.OutboxLease{}, ctx.Err()
		}
	case 2:
		close(s.second)
	}
	return eventstore.OutboxLease{}, eventstore.ErrNotFound
}

type crossingNoOpEffectExecutor struct{}

func (crossingNoOpEffectExecutor) ExecutePinned(
	context.Context,
	adapterapi.EndpointID,
	uint64,
	adapterapi.OutboundEffect,
) (adapterapi.EffectResult, error) {
	return adapterapi.EffectResult{Outcome: adapterapi.EffectSucceeded}, nil
}

func TestEventQueueNotificationCrossingClaimWakesCapturedGeneration(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	work := make(chan struct{}, 1)
	queue := newEventQueueCoordinator(group, time.Hour, work, func(context.Context) (bool, error) {
		return false, nil
	})
	store := &crossingOutboxStore{
		GORMStore:    eventstore.NewStore(nil),
		firstEntered: make(chan struct{}),
		firstRelease: make(chan struct{}),
		second:       make(chan struct{}),
	}
	dispatcher, err := endpoint.NewEffectDispatcher(store, store, crossingNoOpEffectExecutor{}, "crossing-notification")
	if err != nil {
		t.Fatal(err)
	}
	group.Go(func(ctx context.Context) {
		runEventEffectDispatcher(ctx, dispatcher, queue.signal)
	})

	waitEventTestClosed(t, store.firstEntered, "first blocked claim")
	observedWake := queue.signal()
	work <- struct{}{}
	waitEventTestClosed(t, observedWake, "notification crossing the blocked claim")
	close(store.firstRelease)
	waitEventTestClosed(t, store.second, "claim following the crossing notification")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := group.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestQueueNotificationDuringEmptyProbeWakesEverySubscriber(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	defer func() {
		if err := group.Shutdown(context.Background()); err != nil {
			t.Errorf("stop queue workers: %v", err)
		}
	}()
	work := make(chan struct{}, 4)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	queue := newEventQueueCoordinator(group, eventCallbackIdleDelay, work, func(ctx context.Context) (bool, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return false, nil
	})
	wakes := []<-chan struct{}{queue.signal(), queue.signal(), queue.signal(), queue.signal()}
	<-started
	work <- struct{}{}
	close(release)
	for _, wake := range wakes {
		select {
		case <-wake:
		case <-time.After(time.Second):
			t.Fatal("commit crossing an empty probe was lost")
		}
	}
}

func TestQueueProbeDiscoversExternalWorkWithoutNotification(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	defer func() {
		if err := group.Shutdown(context.Background()); err != nil {
			t.Errorf("stop queue workers: %v", err)
		}
	}()
	var available atomic.Bool
	first := make(chan struct{})
	var calls atomic.Int32
	queue := newEventQueueCoordinator(group, eventEffectIdleDelay, nil, func(context.Context) (bool, error) {
		value := available.Load()
		if calls.Add(1) == 1 {
			close(first)
		}
		return value, nil
	})
	wake := queue.signal()
	<-first
	available.Store(true)
	select {
	case <-wake:
	case <-time.After(time.Second):
		t.Fatal("cross-process or due work was not discovered")
	}
}

func TestWaitEventQueueStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{})
	cancel()
	if waitEventQueue(ctx, wake) {
		t.Fatal("canceled idle worker resumed processing")
	}
}
