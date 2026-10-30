package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

type capturedAdapterEvents struct {
	mu    sync.Mutex
	items []FencedAdapterEvent
}

func (capture *capturedAdapterEvents) sink() AdapterEventSink {
	return AdapterEventSinkFunc(func(_ context.Context, event FencedAdapterEvent) (adapterapi.IngressReceipt, error) {
		capture.mu.Lock()
		capture.items = append(capture.items, event)
		capture.mu.Unlock()
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
	})
}

func (capture *capturedAdapterEvents) all() []FencedAdapterEvent {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]FencedAdapterEvent(nil), capture.items...)
}

func startAdapterEventEndpoint(t *testing.T, sink AdapterEventSink) (*Supervisor, *fakeRuntime) {
	t.Helper()
	id := adapterapi.EndpointID("adapter-event-endpoint")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	options := []SupervisorOption{WithLifecycleSink(&fakeLifecycleSink{})}
	if sink != nil {
		options = append(options, WithAdapterEventSink(sink))
	}
	supervisor := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, options...)
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := supervisor.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select {
	case <-runtime.runStarted:
	case <-time.After(time.Second):
		t.Fatal("runtime did not start")
	}
	return supervisor, runtime
}

func testGlobalAdapterEvent() adapterapi.AdapterEvent {
	return adapterapi.AdapterEvent{
		Protocol: "onebot11",
		Type:     "meta_event",
		RawJSON:  `{"post_type":"meta_event","meta_event_type":"heartbeat"}`,
	}
}

func TestSupervisorAdapterEventUsesActiveGenerationFence(t *testing.T) {
	capture := &capturedAdapterEvents{}
	_, runtime := startAdapterEventEndpoint(t, capture.sink())
	port, ok := runtime.port().(adapterapi.AdapterEventCorePort)
	if !ok {
		t.Fatal("generation core port does not expose optional adapter event port")
	}
	receipt, err := port.HandleAdapterEvent(context.Background(), testGlobalAdapterEvent())
	if err != nil || receipt.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("HandleAdapterEvent() = %#v, %v", receipt, err)
	}
	items := capture.all()
	if len(items) != 1 || items[0].EndpointID != "adapter-event-endpoint" || items[0].Generation == 0 || items[0].DesiredVersion != 2 || items[0].Event.RawJSON != testGlobalAdapterEvent().RawJSON {
		t.Fatalf("fenced event = %#v", items)
	}
}

func TestSupervisorAdapterEventRejectsAfterShutdownFence(t *testing.T) {
	capture := &capturedAdapterEvents{}
	supervisor, runtime := startAdapterEventEndpoint(t, capture.sink())
	port := runtime.port().(adapterapi.AdapterEventCorePort)
	supervisor.BeginShutdown()
	if _, err := port.HandleAdapterEvent(context.Background(), testGlobalAdapterEvent()); !errors.Is(err, ErrSupervisorClosed) {
		t.Fatalf("shutdown delivery error = %v", err)
	}
	if len(capture.all()) != 0 {
		t.Fatal("shutdown event reached sink")
	}
}

func TestSupervisorAdapterEventPortIsOptionalWithoutSink(t *testing.T) {
	_, runtime := startAdapterEventEndpoint(t, nil)
	port := runtime.port().(adapterapi.AdapterEventCorePort)
	receipt, err := port.HandleAdapterEvent(context.Background(), testGlobalAdapterEvent())
	if err != nil || receipt.Outcome != adapterapi.IngressRejected {
		t.Fatalf("optional sink receipt = %#v, %v", receipt, err)
	}
}

func TestBootstrapConfiguresAdapterEventSink(t *testing.T) {
	capture := &capturedAdapterEvents{}
	bootstrap := &Bootstrap{Supervisor: NewSupervisor(nil)}
	if err := bootstrap.SetAdapterEventSink(capture.sink()); err != nil {
		t.Fatal(err)
	}
	if bootstrap.AdapterEventSink() == nil {
		t.Fatal("adapter event sink was not retained")
	}
	if err := bootstrap.SetAdapterEventSink(nil); !errors.Is(err, ErrSupervisorNoAdapterEventSink) {
		t.Fatalf("nil sink error = %v", err)
	}
}
