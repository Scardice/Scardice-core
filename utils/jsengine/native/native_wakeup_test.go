//go:build cgo

package native

import (
	"testing"
	"time"
)

func TestNativeTickScheduleBacksOffWhileIdleAndWakesAtLowLatency(t *testing.T) {
	schedule := newNativeTickSchedule()
	got := make([]time.Duration, 0, 6)
	for range 6 {
		got = append(got, schedule.nextDelay())
		schedule.onIdle()
	}
	want := []time.Duration{
		time.Millisecond,
		2 * time.Millisecond,
		4 * time.Millisecond,
		8 * time.Millisecond,
		16 * time.Millisecond,
		16 * time.Millisecond,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idle delay[%d] = %s, want %s (delays=%v)", i, got[i], want[i], got)
		}
	}
	schedule.onWake()
	if got := schedule.nextDelay(); got != time.Millisecond {
		t.Fatalf("wake delay = %s, want %s", got, time.Millisecond)
	}
}
