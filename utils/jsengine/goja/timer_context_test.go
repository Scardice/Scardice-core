package goja

import (
	"context"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
)

type persistentTimerPromotionScope struct {
	context.Context
	loop     jsengine.Loop
	promoted any
}

func (s *persistentTimerPromotionScope) ExecutionContext() context.Context { return s.Context }

func (s *persistentTimerPromotionScope) PromotePersistentAsync(run func() (jsengine.Value, error)) error {
	return jsengine.ScheduleWithContext(s.loop, s.promoted, func(jsengine.Runtime) error {
		_, err := run()
		return err
	})
}

func TestContextPropagationPreservesTimerKindsDelaysAndCancellation(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	type timerEvent struct {
		kind    string
		arg     string
		elapsed time.Duration
		context any
	}
	events := make(chan timerEvent, 8)
	var started time.Time
	if err := jsengine.RunWithContext(loop, "timer-plugin", func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("captureTimer", func(kind, arg string) {
			events <- timerEvent{kind: kind, arg: arg, elapsed: time.Since(started), context: jsengine.CurrentContext(loop)}
		}); err != nil {
			return err
		}
		started = time.Now()
		_, err := runtime.RunString("timer-semantics.js", `
			var longTimer = setTimeout(function(arg) { captureTimer("long", arg); }, 5000, "long-value");
			var cancelled = setTimeout(function(arg) { captureTimer("cancelled", arg); }, 40, "cancelled-value");
			clearTimeout(cancelled);
			var interval = setInterval(function(arg) {
				clearInterval(interval);
				captureTimer("interval", arg);
			}, 180, "interval-value");
			setTimeout(function(arg) { captureTimer("timeout", arg); }, 120, "timeout-value");
			setImmediate(function(arg) { captureTimer("immediate", arg); }, "immediate-value");
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, 3)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for len(seen) < 3 {
		select {
		case event := <-events:
			if event.kind == "long" || event.kind == "cancelled" {
				t.Fatalf("unexpected %s timer fired after %s", event.kind, event.elapsed)
			}
			if seen[event.kind] {
				t.Fatalf("timer %s fired more than once", event.kind)
			}
			if event.arg != event.kind+"-value" || event.context != "timer-plugin" {
				t.Fatalf("timer %s delivered arg=%q context=%v", event.kind, event.arg, event.context)
			}
			minimum := map[string]time.Duration{"timeout": 110 * time.Millisecond, "interval": 170 * time.Millisecond}[event.kind]
			if event.elapsed < minimum {
				t.Fatalf("timer %s fired after %s, before minimum %s", event.kind, event.elapsed, minimum)
			}
			seen[event.kind] = true
		case <-deadline.C:
			t.Fatalf("timers did not complete: %v", seen)
		}
	}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		_, err := runtime.RunString("cancel-long-timer.js", `clearTimeout(longTimer);`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentAsyncPromotionRunsTimerUnderFreshContext(t *testing.T) {
	loop := startedTestLoop(t)
	if err := InstallContextPropagation(loop); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.InstallPersistentAsyncPromotion(loop); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.InstallPersistentAsyncPromotion(loop); err != nil {
		t.Fatal(err)
	}
	promoted := &struct{ name string }{name: "fresh"}
	scope := &persistentTimerPromotionScope{
		Context:  context.Background(),
		loop:     loop,
		promoted: promoted,
	}
	seen := make(chan any, 1)
	if err := jsengine.RunWithContext(loop, scope, func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("capturePromotedTimer", func(argument string) {
			if argument == "argument" {
				seen <- jsengine.CurrentContext(loop)
			}
		}); err != nil {
			return err
		}
		_, err := runtime.RunString("persistent-timer.js", `
			setTimeout(function (argument) {
				capturePromotedTimer(argument);
			}, 0, "argument");
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case context := <-seen:
		if context != promoted {
			t.Fatalf("timer context = %v, want promoted context", context)
		}
	case <-time.After(time.Second):
		t.Fatal("promoted timer did not run")
	}
}
