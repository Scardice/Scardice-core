package kook

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestSnPersistHandlerRunsOnSnAdvance(t *testing.T) {
	s := New("token", nopLogger{})
	var calls int32
	s.SetSnPersistHandler(func() {
		atomic.AddInt32(&calls, 1)
	})

	s.finishEvent(0, 1, true)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("persist calls after first sn = %d, want 1", got)
	}
	s.finishEvent(0, 1, true)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("persist calls after duplicate sn = %d, want 1", got)
	}
	s.skipEvent(0, 2, "test skip")
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("persist calls after skipped sn = %d, want 2", got)
	}
}

func TestHandlerSerializesAcrossDispatchers(t *testing.T) {
	s := New("token", nopLogger{})
	old, had := registeredEventHandler["251"]
	registeredEventHandler["251"] = &dispatchTestProvider{}
	t.Cleanup(func() {
		if had {
			registeredEventHandler["251"] = old
		} else {
			delete(registeredEventHandler, "251")
		}
	})

	started := make(chan struct{}, 2)
	block := make(chan struct{})
	s.addEventHandler(&dispatchTestHandler{started: started, block: block})

	event := &Event{Signal: EventSignalEvent, SequenceNumber: 1}
	data := &EventData{EventDataGeneral: &EventDataGeneral{Type: 251}, Extra: []byte(`{}`)}
	firstDone := make(chan bool, 1)
	secondDone := make(chan bool, 1)
	go func() { firstDone <- s.runEventHandler(event, data) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first handler did not start")
	}

	go func() { secondDone <- s.runEventHandler(event, data) }()
	select {
	case <-started:
		t.Fatal("second handler ran concurrently with the first")
	case <-time.After(50 * time.Millisecond):
	}

	close(block)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("second handler did not start after the first finished")
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first handler did not finish")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second handler did not finish")
	}
}
