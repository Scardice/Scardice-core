//go:build cgo

package native

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

func TestNativeCanceledScheduleDoesNotRetainCallback(t *testing.T) {
	loop := newContextLoop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := loop.ScheduleWithContext(&invocationTestContext{Context: ctx, id: 1}, func(jsengine.Runtime) error { t.Error("expired callback executed"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expired schedule admitted: %v", err)
	}
	if len(loop.takeScheduled()) != 0 {
		t.Fatal("expired callback retained")
	}
}

func TestNativeAdmissionDeadlineWhileShutdownOwnsGate(t *testing.T) {
	loop := newContextLoop()
	loop.runMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- loop.RunWithContext(&invocationTestContext{Context: ctx, id: 2}, func(jsengine.Runtime) error { t.Error("expired admission executed"); return nil })
	}()
	select {
	case err := <-done:
		loop.runMu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("admission error=%v", err)
		}
	case <-time.After(300 * time.Millisecond):
		loop.closed.Store(true)
		loop.runMu.Unlock()
		err := <-done
		t.Fatalf("admission deadline waited for shutdown gate: %v", err)
	}
}
