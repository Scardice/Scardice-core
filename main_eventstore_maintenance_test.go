package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type eventInboxMaintenanceProbe struct {
	requests           chan chan error
	cancelled          chan struct{}
	releaseAfterCancel chan struct{}
}

func (p *eventInboxMaintenanceProbe) DeleteExpiredTerminalInbox(ctx context.Context) (int64, error) {
	response := make(chan error)
	select {
	case p.requests <- response:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case err := <-response:
		return 1, err
	case <-ctx.Done():
		if p.cancelled != nil {
			close(p.cancelled)
		}
		if p.releaseAfterCancel != nil {
			<-p.releaseAfterCancel
		}
		return 0, ctx.Err()
	}
}

func receiveInboxMaintenanceSweep(t *testing.T, requests <-chan chan error) chan error {
	t.Helper()
	select {
	case response := <-requests:
		return response
	case <-time.After(time.Second):
		t.Fatal("inbox maintenance did not sweep")
		return nil
	}
}

func TestInboxMaintenanceCompletesStartupSweepBeforeAdmission(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	defer func() {
		if err := group.Shutdown(context.Background()); err != nil {
			t.Errorf("stop inbox maintenance: %v", err)
		}
	}()
	probe := &eventInboxMaintenanceProbe{requests: make(chan chan error)}
	started := make(chan error, 1)
	go func() { started <- startEventInboxMaintenance(group, probe) }()
	response := receiveInboxMaintenanceSweep(t, probe.requests)
	select {
	case err := <-started:
		t.Fatalf("startup admitted workers before sweep completed: %v", err)
	default:
	}
	response <- nil
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if err := group.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := startEventInboxMaintenance(group, probe); !errors.Is(err, errEventWorkerGroupClosed) {
		t.Fatalf("maintenance admitted after shutdown: %v", err)
	}
}

func TestInboxMaintenanceTicksAndShutdownJoinsInflightCleanup(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	probe := &eventInboxMaintenanceProbe{requests: make(chan chan error), cancelled: make(chan struct{}), releaseAfterCancel: make(chan struct{})}
	ticks := make(chan time.Time)
	t.Cleanup(func() {
		group.beginShutdown()
		select {
		case <-probe.releaseAfterCancel:
		default:
			close(probe.releaseAfterCancel)
		}
		if err := group.Shutdown(context.Background()); err != nil {
			t.Errorf("stop inbox maintenance: %v", err)
		}
	})
	if !group.Go(func(ctx context.Context) { runEventInboxMaintenance(ctx, probe, ticks) }) {
		t.Fatal("worker rejected")
	}
	ticks <- time.Now()
	response := receiveInboxMaintenanceSweep(t, probe.requests)
	response <- nil
	ticks <- time.Now()
	_ = receiveInboxMaintenanceSweep(t, probe.requests)
	shutdown := make(chan error, 1)
	go func() { shutdown <- group.Shutdown(context.Background()) }()
	waitEventTestClosed(t, probe.cancelled, "inflight housekeeping cancellation")
	select {
	case err := <-shutdown:
		t.Fatalf("shutdown did not join cleanup: %v", err)
	default:
	}
	close(probe.releaseAfterCancel)
	if err := <-shutdown; err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe.requests:
		t.Fatal("cleanup continued after joined shutdown")
	default:
	}
}

func TestInboxMaintenanceStartupErrorIsReturned(t *testing.T) {
	group := newEventWorkerGroup(context.Background())
	defer func() {
		if err := group.Shutdown(context.Background()); err != nil {
			t.Errorf("stop inbox maintenance: %v", err)
		}
	}()
	probe := &eventInboxMaintenanceProbe{requests: make(chan chan error)}
	started := make(chan error, 1)
	go func() { started <- startEventInboxMaintenance(group, probe) }()
	failure := errors.New("terminal inbox delete transaction failed")
	response := receiveInboxMaintenanceSweep(t, probe.requests)
	response <- failure
	if err := <-started; !errors.Is(err, failure) {
		t.Fatalf("initial failure was hidden: %v", err)
	}
}
