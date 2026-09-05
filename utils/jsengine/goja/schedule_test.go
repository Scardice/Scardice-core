package goja

import (
	"testing"
	"time"

	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
)

func startedTestLoop(t *testing.T) jsengine.Loop {
	t.Helper()
	raw := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	loop := WrapEventLoop(raw)
	go func() {
		_ = StartInForeground(loop)
	}()
	if err := WaitUntilStarted(loop); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = loop.Close()
	})
	return loop
}

// A blocking entry from inside a loop callback waits for a job the busy owner
// goroutine can never dequeue. Scheduling must return before the callback runs.
func TestScheduleFromInsideLoopCallbackDoesNotBlock(t *testing.T) {
	loop := startedTestLoop(t)
	nested := make(chan any, 1)
	outerReturned := false
	if err := jsengine.RunWithContext(loop, "outer", func(jsengine.Runtime) error {
		if err := jsengine.ScheduleWithContext(loop, "inner", func(jsengine.Runtime) error {
			nested <- jsengine.CurrentContext(loop)
			return nil
		}); err != nil {
			return err
		}
		outerReturned = true
		return nil
	}); err != nil {
		t.Fatalf("RunWithContext() error = %v", err)
	}
	if !outerReturned {
		t.Fatal("outer callback did not complete")
	}
	select {
	case context := <-nested:
		if context != "inner" {
			t.Fatalf("scheduled context = %#v, want inner", context)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled callback never ran")
	}
}

func TestScheduleWithoutContextUsesCurrentContext(t *testing.T) {
	loop := startedTestLoop(t)
	seen := make(chan any, 1)
	if err := jsengine.RunWithContext(loop, "plugin-a", func(jsengine.Runtime) error {
		return jsengine.Schedule(loop, func(jsengine.Runtime) error {
			seen <- jsengine.CurrentContext(loop)
			return nil
		})
	}); err != nil {
		t.Fatalf("RunWithContext() error = %v", err)
	}
	select {
	case context := <-seen:
		if context != "plugin-a" {
			t.Fatalf("scheduled context = %#v, want plugin-a", context)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled callback never ran")
	}
}

func TestScheduleAfterCloseIsRejected(t *testing.T) {
	loop := startedTestLoop(t)
	if err := loop.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	ran := false
	if err := jsengine.ScheduleWithContext(loop, "late", func(jsengine.Runtime) error {
		ran = true
		return nil
	}); err == nil {
		t.Fatal("ScheduleWithContext() after Close returned nil error")
	}
	if ran {
		t.Fatal("scheduled callback ran after Close")
	}
}

// A scheduled callback has no caller to receive its failure, so a panic must
// stay inside the adapter instead of reaching the event loop.
func TestScheduledCallbackPanicDoesNotStopTheLoop(t *testing.T) {
	loop := startedTestLoop(t)
	if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
		panic("scheduled callback panic")
	}); err != nil {
		t.Fatalf("Schedule() error = %v", err)
	}
	survived := make(chan struct{})
	if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
		close(survived)
		return nil
	}); err != nil {
		t.Fatalf("Schedule() error = %v", err)
	}
	select {
	case <-survived:
	case <-time.After(2 * time.Second):
		t.Fatal("event loop stopped accepting callbacks after a panic")
	}
}

func TestScheduleOnIsolatedRealmRunsInline(t *testing.T) {
	loop := New()
	t.Cleanup(func() {
		_ = loop.Close()
	})
	ran := false
	if err := jsengine.ScheduleWithContext(loop, "isolated", func(jsengine.Runtime) error {
		ran = true
		if context := jsengine.CurrentContext(loop); context != "isolated" {
			t.Fatalf("scheduled context = %#v, want isolated", context)
		}
		return nil
	}); err != nil {
		t.Fatalf("ScheduleWithContext() error = %v", err)
	}
	if !ran {
		t.Fatal("isolated realm did not run the scheduled callback")
	}
}
