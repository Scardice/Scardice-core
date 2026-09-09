package endpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

func TestSupervisorInboundWithoutSinkFailsClosed(t *testing.T) {
	id := adapterapi.EndpointID("inbound-no-sink")
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	supervisor := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := supervisor.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil { t.Fatal(err) }
	runtime := descriptor.Runtime(0)
	runtime.allowStart()
	select { case <-runtime.runStarted: case <-time.After(time.Second): t.Fatal("runtime did not start") }
	_, err := runtime.port().HandleInbound(context.Background(), adapterapi.InboundMessage{ProviderEventID: "event-1", Kind: adapterapi.InboundKindMessage})
	if !errors.Is(err, ErrSupervisorNoInboundSink) { t.Fatalf("nil inbound sink error = %v", err) }
}
