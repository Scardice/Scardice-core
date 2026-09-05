//go:build cgo

package native

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

// The worker owns the task channel, so a callback queued from inside a running
// task must not be handed to that channel or the worker would wait on itself.
func TestNativeScheduleFromOwnerThreadDoesNotBlock(t *testing.T) {
	loop := openEcho(t)
	defer func() {
		if err := loop.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	nested := make(chan struct{})
	if err := loop.Run(func(jsengine.Runtime) error {
		return jsengine.Schedule(loop, func(jsengine.Runtime) error {
			close(nested)
			return nil
		})
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	select {
	case <-nested:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled callback never ran")
	}
}

func TestNativeScheduleFromForeignGoroutineRuns(t *testing.T) {
	loop := openEcho(t)
	defer func() {
		if err := loop.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	ran := make(chan struct{})
	if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
		close(ran)
		return nil
	}); err != nil {
		t.Fatalf("Schedule() error = %v", err)
	}
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled callback never ran")
	}
}

func TestNativeScheduleAfterCloseIsRejected(t *testing.T) {
	loop := openEcho(t)
	if err := loop.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	ran := false
	if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
		ran = true
		return nil
	}); !errors.Is(err, ErrNativeClosed) {
		t.Fatalf("Schedule() after Close error = %v, want ErrNativeClosed", err)
	}
	if ran {
		t.Fatal("scheduled callback ran after Close")
	}
}

// Queued callbacks must never reach the provider after it has been stopped.
func TestNativeCloseDiscardsQueuedCallbacks(t *testing.T) {
	loop := openEcho(t)
	native, ok := loop.(*nativeLoop)
	if !ok {
		t.Fatalf("loop type = %T, want *nativeLoop", loop)
	}
	parked := make(chan struct{})
	release := make(chan struct{})
	if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
		close(parked)
		<-release
		return nil
	}); err != nil {
		t.Fatalf("Schedule() error = %v", err)
	}
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("first scheduled callback never ran")
	}
	var ran atomic.Int32
	for i := 0; i < 4; i++ {
		if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
			ran.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("Schedule(%d) error = %v", i, err)
		}
	}
	closed := make(chan error, 1)
	go func() {
		closed <- loop.Close()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !native.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Close did not mark the loop closed")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish while callbacks were queued")
	}
	if got := ran.Load(); got != 0 {
		t.Fatalf("queued callbacks executed after close = %d, want 0", got)
	}
	native.scheduledMu.Lock()
	remaining := len(native.scheduled)
	native.scheduledMu.Unlock()
	if remaining != 0 {
		t.Fatalf("queued callbacks retained = %d, want 0", remaining)
	}
	native.contextMu.RLock()
	contexts := len(native.contexts)
	native.contextMu.RUnlock()
	if contexts != 0 {
		t.Fatalf("retained execution contexts = %d, want 0", contexts)
	}
}
