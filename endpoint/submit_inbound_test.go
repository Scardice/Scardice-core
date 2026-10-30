package endpoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

type capturedInbound struct {
	mu    sync.Mutex
	items []FencedInbound
}

func (c *capturedInbound) sink() InboundSink {
	return InboundSinkFunc(func(_ context.Context, inbound FencedInbound) (adapterapi.IngressReceipt, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.items = append(c.items, inbound)
		return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted, InboxID: "inbox-1"}, nil
	})
}

func (c *capturedInbound) all() []FencedInbound {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]FencedInbound(nil), c.items...)
}

func startedEndpoint(t *testing.T, id adapterapi.EndpointID, sink InboundSink) (*Supervisor, *fakeRuntime) {
	t.Helper()
	key := adapterapi.AdapterKey("fake")
	descriptor := &fakeDescriptor{key: key}
	supervisor := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}), WithInboundSink(sink))
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

func historyGroupMessage(history adapterapi.InboundHistory) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		ProviderEventID: "onebot-message-7", Kind: adapterapi.InboundKindMessage, ConversationKind: adapterapi.ConversationKindGroup,
		Conversation: "QQ-Group:1", Sender: "QQ:2", Text: "hello", Sequence: 41, History: history,
	}
}

// Core's own inbound must reach ingress under the same generation and desired
// version fence a provider's delivery would get; Core never makes one up.
func TestSubmitInboundCarriesTheActiveGenerationFence(t *testing.T) {
	id := adapterapi.EndpointID("submit-fence")
	captured := &capturedInbound{}
	supervisor, runtime := startedEndpoint(t, id, captured.sink())

	live := historyGroupMessage(adapterapi.InboundHistoryNone)
	live.ProviderEventID = "onebot-message-6"
	if _, err := runtime.port().HandleInbound(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	receipt, err := supervisor.SubmitInbound(context.Background(), id, historyGroupMessage(adapterapi.InboundHistoryRecordOnly))
	if err != nil || receipt.Outcome != adapterapi.IngressAccepted {
		t.Fatalf("SubmitInbound = %+v, %v", receipt, err)
	}

	got := captured.all()
	if len(got) != 2 {
		t.Fatalf("sink saw %d inbounds, want 2", len(got))
	}
	fromProvider, fromCore := got[0], got[1]
	if fromCore.EndpointID != id || fromCore.Generation != fromProvider.Generation || fromCore.DesiredVersion != fromProvider.DesiredVersion || fromCore.Generation == 0 {
		t.Fatalf("fence differs: provider %+v, core %+v", fromProvider, fromCore)
	}
	if fromCore.Message.History != adapterapi.InboundHistoryRecordOnly || fromCore.Message.Sequence != 41 {
		t.Fatalf("message was altered on the way: %+v", fromCore.Message)
	}
}

// A provider's delivery is always live. If it could mark a message as history,
// a provider could make Core record messages without acting on their commands.
func TestProviderCannotDeliverHistory(t *testing.T) {
	id := adapterapi.EndpointID("provider-history")
	captured := &capturedInbound{}
	_, runtime := startedEndpoint(t, id, captured.sink())

	for _, history := range []adapterapi.InboundHistory{adapterapi.InboundHistoryExecute, adapterapi.InboundHistoryRecordOnly} {
		if _, err := runtime.port().HandleInbound(context.Background(), historyGroupMessage(history)); !errors.Is(err, adapterapi.ErrInvalidContract) {
			t.Fatalf("history %d from a provider: %v", history, err)
		}
	}
	if n := len(captured.all()); n != 0 {
		t.Fatalf("%d provider-marked history messages reached ingress", n)
	}
}

func TestSubmitInboundNeedsARunningEndpointAndAValidMessage(t *testing.T) {
	id := adapterapi.EndpointID("submit-unknown")
	captured := &capturedInbound{}
	supervisor, _ := startedEndpoint(t, id, captured.sink())

	if _, err := supervisor.SubmitInbound(context.Background(), "nobody", historyGroupMessage(adapterapi.InboundHistoryRecordOnly)); !errors.Is(err, ErrSupervisorClosed) {
		t.Fatalf("unknown endpoint: %v", err)
	}
	direct := historyGroupMessage(adapterapi.InboundHistoryRecordOnly)
	direct.ConversationKind = adapterapi.ConversationKindDirect
	if _, err := supervisor.SubmitInbound(context.Background(), id, direct); !errors.Is(err, adapterapi.ErrInvalidContract) {
		t.Fatalf("history on a direct message: %v", err)
	}
	if n := len(captured.all()); n != 0 {
		t.Fatalf("%d rejected submissions reached ingress", n)
	}
	if _, err := (*Supervisor)(nil).SubmitInbound(context.Background(), id, historyGroupMessage(adapterapi.InboundHistoryRecordOnly)); !errors.Is(err, ErrSupervisorClosed) {
		t.Fatalf("nil supervisor: %v", err)
	}
}
