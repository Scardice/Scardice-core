//go:build cgo

package native

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/utils/jsengine"
	jsservices "Scardice-core/utils/jsengine/services"
)

type nativeServiceTestPromoter struct {
	enabled   bool
	immediate bool
	err       error
	calls     int
	pending   []func() (jsengine.Value, error)
	requests  []uint64
	terminals []bool
}

func (p *nativeServiceTestPromoter) PersistentAsyncPromotionEnabled() bool { return p.enabled }

func (p *nativeServiceTestPromoter) PromotePersistentAsync(run func() (jsengine.Value, error)) error {
	p.calls++
	if p.err != nil {
		return p.err
	}
	if p.immediate {
		_, err := run()
		return err
	}
	p.pending = append(p.pending, run)
	return nil
}

func (p *nativeServiceTestPromoter) PromotePersistentAsyncRequest(request uint64, terminal bool, run func() (jsengine.Value, error)) error {
	p.requests = append(p.requests, request)
	p.terminals = append(p.terminals, terminal)
	return p.PromotePersistentAsync(run)
}

func TestNativeServiceSinkPromotesWithinRequestOwnership(t *testing.T) {
	loop := &nativeLoop{}
	promoter := &nativeServiceTestPromoter{enabled: true}
	sink := nativeServiceSink{loop: loop, context: promoter}
	if err := sink.Event(7, jsservices.Response{}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Complete(8, jsservices.Response{}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(7, jsservices.Response{}); err != nil {
		t.Fatal(err)
	}
	if len(promoter.requests) != 3 || len(promoter.terminals) != 3 {
		t.Fatalf("request-owned promotions = %d, want 3", len(promoter.requests))
	}
	for index, want := range []struct {
		request  uint64
		terminal bool
	}{{7, false}, {8, true}, {7, true}} {
		if promoter.requests[index] != want.request || promoter.terminals[index] != want.terminal {
			t.Fatalf("promotion %d = request %d terminal %v, want request %d terminal %v", index, promoter.requests[index], promoter.terminals[index], want.request, want.terminal)
		}
	}
	if len(loop.serviceEvents) != 0 {
		t.Fatal("persistent service events escaped their request-owned promotion")
	}
}

func TestNativeLoopRejectsServiceEventsAfterClose(t *testing.T) {
	loop := &nativeLoop{}
	loop.closed.Store(true)
	err := loop.enqueueServiceEvent(nativeServiceEvent{
		kind:     jsservices.EventData,
		request:  1,
		response: jsservices.Response{String: "late"},
	})
	if !errors.Is(err, ErrNativeClosed) {
		t.Fatalf("enqueueServiceEvent() error = %v, want ErrNativeClosed", err)
	}
}

func TestNativeServiceSinkReroutesPersistentCompletions(t *testing.T) {
	loop := &nativeLoop{}
	promoter := &nativeServiceTestPromoter{enabled: true}
	var delivered []nativeServiceEvent
	sink := nativeServiceSink{
		loop:    loop,
		context: promoter,
		deliver: func(event nativeServiceEvent) error {
			delivered = append(delivered, event)
			return nil
		},
	}
	payload := []byte{1, 2, 3}
	if err := sink.Event(7, jsservices.Response{String: "ready", Bytes: payload}); err != nil {
		t.Fatal(err)
	}
	payload[0] = 9
	if promoter.calls != 1 || len(promoter.pending) != 1 {
		t.Fatalf("promotion calls=%d pending=%d", promoter.calls, len(promoter.pending))
	}
	if len(loop.serviceEvents) != 0 || len(delivered) != 0 {
		t.Fatal("persistent completion escaped into the context-free event queue")
	}
	if _, err := promoter.pending[0](); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 1 {
		t.Fatalf("delivered events = %d, want 1", len(delivered))
	}
	event := delivered[0]
	if event.kind != jsservices.EventData || event.request != 7 || event.response.String != "ready" {
		t.Fatalf("delivered event = %#v", event)
	}
	if len(event.response.Bytes) != 3 || event.response.Bytes[0] != 1 {
		t.Fatalf("promoted event did not retain its response snapshot: %v", event.response.Bytes)
	}
}

func TestNativeServiceSinkDoesNotPromoteFloatedMessageContext(t *testing.T) {
	loop := &nativeLoop{}
	promoter := &nativeServiceTestPromoter{enabled: false, immediate: true}
	delivered := 0
	sink := nativeServiceSink{
		loop:    loop,
		context: promoter,
		deliver: func(nativeServiceEvent) error {
			delivered++
			return nil
		},
	}
	if err := sink.Complete(8, jsservices.Response{Status: jsservices.StatusOK}); err != nil {
		t.Fatal(err)
	}
	if promoter.calls != 0 || delivered != 0 {
		t.Fatalf("message completion promoted: calls=%d delivered=%d", promoter.calls, delivered)
	}
	if len(loop.serviceEvents) != 1 || loop.serviceEvents[0].kind != jsservices.EventComplete {
		t.Fatalf("queued events = %#v", loop.serviceEvents)
	}
}

func TestNativeServiceSinkPromotionFailuresNeverFallBack(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "failure", err: errors.New("promotion failed")},
		{name: "cancel", err: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			loop := &nativeLoop{}
			promoter := &nativeServiceTestPromoter{enabled: true, err: test.err}
			delivered := 0
			sink := nativeServiceSink{
				loop:    loop,
				context: promoter,
				deliver: func(nativeServiceEvent) error {
					delivered++
					return nil
				},
			}
			err := sink.Close(9, jsservices.Response{Status: jsservices.StatusClosed})
			if !errors.Is(err, test.err) {
				t.Fatalf("Close() error = %v, want %v", err, test.err)
			}
			if delivered != 0 || len(loop.serviceEvents) != 0 {
				t.Fatal("failed promotion fell back to context-free delivery")
			}
		})
	}
}

func TestNativeServiceSinkDeliveryFailureDoesNotPoisonNextPromotion(t *testing.T) {
	loop := &nativeLoop{}
	promoter := &nativeServiceTestPromoter{enabled: true, immediate: true}
	deliveryFailure := errors.New("delivery failed")
	deliveries := 0
	sink := nativeServiceSink{
		loop:    loop,
		context: promoter,
		deliver: func(nativeServiceEvent) error {
			deliveries++
			if deliveries == 1 {
				return deliveryFailure
			}
			return nil
		},
	}
	if err := sink.Event(10, jsservices.Response{}); !errors.Is(err, deliveryFailure) {
		t.Fatalf("first Event() error = %v, want %v", err, deliveryFailure)
	}
	if err := sink.Event(10, jsservices.Response{}); err != nil {
		t.Fatalf("second Event() error = %v", err)
	}
	if promoter.calls != 2 || deliveries != 2 {
		t.Fatalf("promotion calls=%d deliveries=%d", promoter.calls, deliveries)
	}
	if len(loop.serviceEvents) != 0 {
		t.Fatal("delivery failure poisoned the queue with a fallback event")
	}
}

type nativeCompletionTestScope struct{ delivered int }

func (s *nativeCompletionTestScope) DeliverHostCompletion(deliver func() error) error {
	s.delivered++
	return deliver()
}

func TestNativeLoopDispatchesServiceEventThroughCompletionScope(t *testing.T) {
	loop := &nativeLoop{}
	scope := &nativeCompletionTestScope{}
	err := loop.dispatchServiceEvent(nativeServiceEvent{kind: jsservices.EventComplete, request: 1, context: scope})
	if !errors.Is(err, ErrNativeClosed) || scope.delivered != 1 {
		t.Fatalf("scoped dispatch = (%v, deliveries=%d), want ErrNativeClosed through the scope once", err, scope.delivered)
	}
	err = loop.dispatchServiceEvent(nativeServiceEvent{kind: jsservices.EventComplete, request: 2, context: struct{}{}})
	if !errors.Is(err, ErrNativeClosed) || scope.delivered != 1 {
		t.Fatalf("unscoped dispatch = (%v, deliveries=%d), want direct delivery", err, scope.delivered)
	}
}
