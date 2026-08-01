package dice

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestOfficialQQEventQueue_executesEventsInFIFOOrder(t *testing.T) {
	// Given
	queue := newOfficialQQEventQueue()
	order := make([]int, 0, 3)
	started := make(chan struct{})
	release := make(chan struct{})
	firstAccepted := make(chan bool, 1)
	go func() {
		firstAccepted <- queue.Enqueue(func() {
			order = append(order, 1)
			close(started)
			<-release
		})
	}()
	<-started
	for eventID := 2; eventID <= 3; eventID++ {
		if !queue.Enqueue(func() { order = append(order, eventID) }) {
			t.Fatalf("Enqueue(%d) rejected an open queue", eventID)
		}
	}

	// When
	close(release)
	if !<-firstAccepted {
		t.Fatal("Enqueue(1) rejected an open queue")
	}
	queue.Close()

	// Then
	if !slices.Equal(order, []int{1, 2, 3}) {
		t.Fatalf("event order = %v, want [1 2 3]", order)
	}
}

func TestOfficialQQEventQueue_rejectsEventsAfterSafeCloseWithoutRunningPayload(t *testing.T) {
	// Given
	queue := newOfficialQQEventQueue()
	queue.Close()
	queue.Close()
	exposed := ""

	// When
	accepted := queue.Enqueue(func() {
		exposed = "credential-shaped payload"
	})

	// Then
	if accepted {
		t.Fatal("Enqueue() accepted an event after close")
	}
	if exposed != "" {
		t.Fatalf("closed queue ran rejected payload %q", exposed)
	}
}

func TestOfficialQQEventQueue_closeFromCallbackDrainsAcceptedEvents(t *testing.T) {
	// Given
	queue := newOfficialQQEventQueue()
	order := make([]int, 0, 2)
	callbackStarted := make(chan struct{})
	allowClose := make(chan struct{})
	enqueueFinished := make(chan bool, 1)
	go func() {
		enqueueFinished <- queue.Enqueue(func() {
			order = append(order, 1)
			close(callbackStarted)
			<-allowClose
			queue.Close()
		})
	}()
	<-callbackStarted
	if !queue.Enqueue(func() { order = append(order, 2) }) {
		t.Fatal("Enqueue(2) rejected before callback close")
	}

	// When
	close(allowClose)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	select {
	case accepted := <-enqueueFinished:
		if !accepted {
			t.Fatal("Enqueue(1) rejected an open queue")
		}
	case <-ctx.Done():
		t.Fatal("Close() deadlocked inside event callback")
	}

	// Then
	if !slices.Equal(order, []int{1, 2}) {
		t.Fatalf("event order = %v, want [1 2]", order)
	}
	if queue.Enqueue(func() { order = append(order, 3) }) {
		t.Fatal("Enqueue(3) accepted after callback close")
	}
}

func TestOfficialQQEventQueue_externalAdapterCloseWaitsForAcceptedEvents(t *testing.T) {
	// Given
	adapter := new(PlatformAdapterOfficialQQ)
	adapter.startOfficialQQEventQueue()
	order := make([]int, 0, 2)
	callbackStarted := make(chan struct{})
	release := make(chan struct{})
	enqueueFinished := make(chan bool, 1)
	go func() {
		enqueueFinished <- adapter.enqueueOfficialQQEvent(func() {
			order = append(order, 1)
			close(callbackStarted)
			<-release
		})
	}()
	<-callbackStarted
	if !adapter.enqueueOfficialQQEvent(func() { order = append(order, 2) }) {
		t.Fatal("second event rejected before external close")
	}
	closeReturned := make(chan struct{})
	go func() {
		adapter.closeOfficialQQEventQueue()
		close(closeReturned)
	}()

	// When
	select {
	case <-closeReturned:
		t.Fatal("external close returned before accepted events drained")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	select {
	case <-closeReturned:
	case <-ctx.Done():
		t.Fatal("external close did not return after accepted events drained")
	}
	if !<-enqueueFinished {
		t.Fatal("first event was not accepted")
	}

	// Then
	if !slices.Equal(order, []int{1, 2}) {
		t.Fatalf("event order = %v, want [1 2]", order)
	}
	if adapter.enqueueOfficialQQEvent(func() { order = append(order, 3) }) {
		t.Fatal("event accepted after external close")
	}
}
