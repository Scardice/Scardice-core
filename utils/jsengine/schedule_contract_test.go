package jsengine_test

import (
	"errors"
	"testing"

	"Scardice-core/utils/jsengine"
)

// unschedulableLoop implements only the base Loop contract.
type unschedulableLoop struct {
	ran int
}

func (l *unschedulableLoop) Engine() jsengine.EngineID { return jsengine.EngineID("stub") }

func (l *unschedulableLoop) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{ID: jsengine.EngineID("stub")}
}

func (l *unschedulableLoop) Run(run func(jsengine.Runtime) error) error {
	l.ran++
	return run(nil)
}

func (l *unschedulableLoop) LoadEntry(jsengine.Entry) error { return nil }
func (l *unschedulableLoop) Close() error                   { return nil }

// Falling back to Loop.Run would reintroduce a blocking realm entry, so an
// unschedulable loop must report the missing capability instead.
func TestScheduleRejectsLoopWithoutSchedulingSupport(t *testing.T) {
	loop := new(unschedulableLoop)
	if err := jsengine.Schedule(loop, func(jsengine.Runtime) error {
		return nil
	}); !errors.Is(err, jsengine.ErrScheduleUnsupported) {
		t.Fatalf("Schedule() error = %v, want ErrScheduleUnsupported", err)
	}
	if err := jsengine.ScheduleWithContext(loop, "context", func(jsengine.Runtime) error {
		return nil
	}); !errors.Is(err, jsengine.ErrScheduleUnsupported) {
		t.Fatalf("ScheduleWithContext() error = %v, want ErrScheduleUnsupported", err)
	}
	if loop.ran != 0 {
		t.Fatalf("Loop.Run calls = %d, want 0", loop.ran)
	}
}
