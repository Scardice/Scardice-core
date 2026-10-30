package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robfig/cron/v3"

	"Scardice-core/dice"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

func TestCleanupStopsJSBeforeEventRuntime(t *testing.T) {
	instance := &dice.Dice{ExtLoopManager: dice.NewJsLoopManager()}
	manager := &dice.DiceManager{Dice: []*dice.Dice{instance}}

	jsStopped := false
	instance.ExtLoopManager.SetShutdownHook(func() {
		jsStopped = true
	})
	eventRuntimeObservedJSStopped := false

	cleanupCreate(manager, func(context.Context, bool) error {
		eventRuntimeObservedJSStopped = jsStopped
		return nil
	})()

	if !eventRuntimeObservedJSStopped {
		t.Fatal("event runtime stopped before the JS runtime")
	}
}

type cleanupOneShotSchedule struct {
	mu    sync.Mutex
	fired bool
}

func (s *cleanupOneShotSchedule) Next(now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.fired {
		s.fired = true
		return now.Add(time.Millisecond)
	}
	return now.Add(time.Hour)
}

func startBlockingCleanupCron(t *testing.T) (*cron.Cron, <-chan struct{}, func()) {
	t.Helper()
	scheduler := cron.New()
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	var releaseOnce sync.Once
	scheduler.Schedule(&cleanupOneShotSchedule{}, cron.FuncJob(func() {
		startedOnce.Do(func() { close(started) })
		<-release
	}))
	scheduler.Start()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("ordinary cron job did not start")
	}
	return scheduler, started, func() {
		releaseOnce.Do(func() { close(release) })
	}
}

func TestCleanupWaitsForOrdinaryCronJobsBeforeEventRuntime(t *testing.T) {
	for _, scope := range []string{"instance", "manager"} {
		t.Run(scope, func(t *testing.T) {
			scheduler, _, release := startBlockingCleanupCron(t)
			defer func() {
				release()
				<-scheduler.Stop().Done()
			}()

			instance := &dice.Dice{}
			manager := &dice.DiceManager{}
			if scope == "instance" {
				instance.Cron = scheduler
				manager.Dice = []*dice.Dice{instance}
			} else {
				manager.Cron = scheduler
			}

			eventRuntimeCleanup := make(chan struct{})
			cleanupDone := make(chan struct{})
			go func() {
				cleanupCreate(manager, func(context.Context, bool) error {
					close(eventRuntimeCleanup)
					return nil
				})()
				close(cleanupDone)
			}()

			reachedCleanupEarly := false
			select {
			case <-eventRuntimeCleanup:
				reachedCleanupEarly = true
			case <-time.After(20 * time.Millisecond):
			}
			release()
			select {
			case <-cleanupDone:
			case <-time.After(time.Second):
				t.Fatal("cleanup did not finish after the ordinary cron job returned")
			}
			if reachedCleanupEarly {
				t.Fatal("event runtime cleanup began while an ordinary cron job was still running")
			}
		})
	}
}

type cleanupBlockingJSLoop struct {
	closeStarted  chan struct{}
	closeRelease  chan struct{}
	closeFinished chan struct{}
	closeCalls    atomic.Int64
}

func (l *cleanupBlockingJSLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *cleanupBlockingJSLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineGoja}
}

func (l *cleanupBlockingJSLoop) Run(run func(jsengine.Runtime) error) error {
	return run(nil)
}

func (l *cleanupBlockingJSLoop) LoadEntry(jsengine.Entry) error { return nil }

func (l *cleanupBlockingJSLoop) Close() error {
	l.closeCalls.Add(1)
	close(l.closeStarted)
	<-l.closeRelease
	close(l.closeFinished)
	return nil
}

func TestShutdownEventRuntimeDeadlineBoundsJSStop(t *testing.T) {
	loop := &cleanupBlockingJSLoop{
		closeStarted:  make(chan struct{}),
		closeRelease:  make(chan struct{}),
		closeFinished: make(chan struct{}),
	}
	instance := &dice.Dice{ExtLoopManager: dice.NewJsLoopManager()}
	instance.ExtLoopManager.SetLoop(loop)

	const shutdownBudget = 20 * time.Millisecond
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		shutdownDone <- shutdownEventRuntime(ctx, func(ctx context.Context) error {
			return instance.StopJSRuntime(ctx)
		})
	}()
	select {
	case <-loop.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("JS runtime stop did not begin")
	}

	var shutdownErr error
	returnedWithinDeadline := true
	select {
	case shutdownErr = <-shutdownDone:
	case <-time.After(4 * shutdownBudget):
		returnedWithinDeadline = false
	}
	close(loop.closeRelease)
	if !returnedWithinDeadline {
		shutdownErr = <-shutdownDone
	}
	select {
	case <-loop.closeFinished:
	case <-time.After(time.Second):
		t.Fatal("blocked JS close did not finish after release")
	}
	if err := instance.StopJSRuntime(context.Background()); err != nil {
		t.Fatalf("join completed JS stop: %v", err)
	}

	if !returnedWithinDeadline {
		t.Fatalf("JS runtime stop ignored the total shutdown deadline: %v", shutdownErr)
	}
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", shutdownErr)
	}
	if calls := loop.closeCalls.Load(); calls != 1 {
		t.Fatalf("JS loop close calls = %d, want 1", calls)
	}
}

type cleanupDatabaseUsingLoop struct {
	database *eventstore.Database
	started  chan struct{}
	release  chan struct{}
	access   chan error
}

func (l *cleanupDatabaseUsingLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *cleanupDatabaseUsingLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineGoja}
}

func (l *cleanupDatabaseUsingLoop) Run(run func(jsengine.Runtime) error) error {
	return run(nil)
}

func (l *cleanupDatabaseUsingLoop) LoadEntry(jsengine.Entry) error { return nil }

func (l *cleanupDatabaseUsingLoop) Close() error {
	close(l.started)
	<-l.release
	err := l.database.SQLDB().PingContext(context.Background())
	l.access <- err
	return err
}

func TestSignalCleanupAndDeferredCleanupJoinBeforeDatabaseClose(t *testing.T) {
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(t.TempDir(), "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	loop := &cleanupDatabaseUsingLoop{
		database: database,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		access:   make(chan error, 1),
	}
	instance := &dice.Dice{ExtLoopManager: dice.NewJsLoopManager()}
	instance.ExtLoopManager.SetLoop(loop)
	manager := &dice.DiceManager{Dice: []*dice.Dice{instance}}
	cleanup := cleanupCreate(manager, nil)

	signalCleanupDone := make(chan struct{})
	go func() {
		cleanup()
		close(signalCleanupDone)
	}()
	select {
	case <-loop.started:
	case <-time.After(time.Second):
		t.Fatal("signal cleanup did not begin JS runtime shutdown")
	}

	startupReturnDone := make(chan struct{})
	go func() {
		// This models main returning from startup while signal cleanup is still
		// running: its deferred cleanup must join before the database owner closes.
		cleanup()
		_ = database.Close()
		close(startupReturnDone)
	}()

	returnedBeforeRuntimeStopped := false
	select {
	case <-startupReturnDone:
		returnedBeforeRuntimeStopped = true
	case <-time.After(20 * time.Millisecond):
	}
	close(loop.release)

	select {
	case <-signalCleanupDone:
	case <-time.After(time.Second):
		t.Fatal("signal cleanup did not finish after releasing the JS runtime")
	}
	select {
	case <-startupReturnDone:
	case <-time.After(time.Second):
		t.Fatal("deferred cleanup did not join the signal cleanup")
	}
	accessErr := <-loop.access
	if returnedBeforeRuntimeStopped {
		t.Fatal("deferred cleanup returned while signal cleanup still owned a running JS callback")
	}
	if accessErr != nil {
		t.Fatalf("JS runtime lost database access before it stopped: %v", accessErr)
	}
}

func TestShutdownOwnedEventRuntimeLeavesDatabaseOpenAfterJSDeadline(t *testing.T) {
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(t.TempDir(), "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
	release := make(chan struct{})
	var releaseOnce sync.Once
	loop := &cleanupBlockingJSLoop{
		closeStarted:  make(chan struct{}),
		closeRelease:  release,
		closeFinished: make(chan struct{}),
	}
	instance := &dice.Dice{ExtLoopManager: dice.NewJsLoopManager()}
	instance.ExtLoopManager.SetLoop(loop)
	defer func() {
		releaseOnce.Do(func() { close(release) })
		_ = instance.StopJSRuntime(context.Background())
		_ = database.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	stopResult := make(chan error, 1)
	go func() {
		stopResult <- instance.StopJSRuntime(ctx)
	}()
	select {
	case <-loop.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("JS runtime close did not reach the controlled gate")
	}
	var stopErr error
	select {
	case stopErr = <-stopResult:
	case <-time.After(time.Second):
		t.Fatal("JS stop did not return at its deadline")
	}
	if !errors.Is(stopErr, context.DeadlineExceeded) {
		t.Fatalf("JS stop error = %v, want deadline exceeded", stopErr)
	}
	group := newEventWorkerGroup(context.Background())
	_ = shutdownOwnedEventRuntime(ctx, false, group, nil, store)

	if pingErr := database.SQLDB().PingContext(context.Background()); pingErr != nil {
		t.Fatalf("event database closed while the timed-out JS runtime could still access it: %v", pingErr)
	}
	releaseOnce.Do(func() { close(release) })
	if stopErr = instance.StopJSRuntime(context.Background()); stopErr != nil {
		t.Fatalf("join JS stop after release: %v", stopErr)
	}
}

func TestShutdownOwnedEventRuntimeClosesDatabaseAfterQuiescence(t *testing.T) {
	database, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{
		Type: "sqlite",
		DSN:  filepath.Join(t.TempDir(), "events.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(database)
	group := newEventWorkerGroup(context.Background())

	if shutdownErr := shutdownOwnedEventRuntime(context.Background(), true, group, nil, store); shutdownErr != nil {
		t.Fatal(shutdownErr)
	}
	if pingErr := database.SQLDB().PingContext(context.Background()); pingErr == nil {
		t.Fatal("event database remained open after every runtime resource quiesced")
	}
}

func TestShutdownEventRuntimeUsesOneTotalDeadline(t *testing.T) {
	firstErr := errors.New("worker shutdown failed")
	secondCalled := false
	var secondContextErr error
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := shutdownEventRuntime(ctx,
		func(ctx context.Context) error {
			<-ctx.Done()
			return errors.Join(firstErr, ctx.Err())
		},
		func(ctx context.Context) error {
			secondCalled = true
			secondContextErr = ctx.Err()
			return nil
		},
	)

	if !secondCalled {
		t.Fatal("endpoint shutdown was skipped after worker failure")
	}
	if !errors.Is(secondContextErr, context.DeadlineExceeded) {
		t.Fatalf("endpoint shutdown context error = %v, want shared deadline exceeded", secondContextErr)
	}
	if !errors.Is(err, firstErr) {
		t.Fatalf("shutdown error = %v, want worker failure", err)
	}
}

func TestShutdownEventRuntimeContinuesAfterImmediateFailure(t *testing.T) {
	firstErr := errors.New("worker shutdown failed")
	secondCalled := false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := shutdownEventRuntime(ctx,
		func(context.Context) error { return firstErr },
		func(ctx context.Context) error {
			secondCalled = true
			if err := ctx.Err(); err != nil {
				t.Fatalf("shared shutdown context expired early: %v", err)
			}
			return nil
		},
	)
	if !secondCalled {
		t.Fatal("endpoint shutdown was skipped after worker failure")
	}
	if !errors.Is(err, firstErr) {
		t.Fatalf("shutdown error = %v, want worker failure", err)
	}
}
