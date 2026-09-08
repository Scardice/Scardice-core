package dice

import (
	"context"
	"testing"

	"Scardice-core/adapterapi"
)

type pureOnebotDurableStub struct {
	received chan adapterapi.InboundMessage
	receipt  adapterapi.IngressReceipt
}

func (s *pureOnebotDurableStub) HandleInbound(_ context.Context, message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	s.received <- message
	return s.receipt, nil
}

func (s *pureOnebotDurableStub) ReportObservation(context.Context, adapterapi.LifecycleObservation) error {
	return nil
}

func TestExecutePureOnebotInboundRequiresDurableExecutor(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	id := adapterapi.EndpointID("pureonebot-inbound-no-executor")
	ep := NewPureOnebotReadEndpoint(id, adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700","accountHint":"QQ:10001"}`)})
	_, err := d.ImSession.ExecutePureOnebotInbound(context.Background(), ep, adapterapi.InboundMessage{
		ProviderEventID: "provider-event-no-executor",
		Kind:            adapterapi.InboundKindMessage,
		Text:            ".r 1d1",
	})
	if err != ErrPureOnebotInboundUnavailable {
		t.Fatalf("err = %v, want durable executor unavailable", err)
	}
}
func TestExecutePureOnebotInboundUsesInjectedDurableExecutor(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	core := &pureOnebotDurableStub{
		received: make(chan adapterapi.InboundMessage, 1),
		receipt:  adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted, InboxID: "inbox-1"},
	}
	d.ImSession.PureOnebotInboundExecutor = core
	id := adapterapi.EndpointID("pureonebot-inbound-test")
	ep := NewPureOnebotReadEndpoint(id, adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700","accountHint":"QQ:10001"}`)})
	eventID := adapterapi.ProviderEventID("provider-event-1")
	receipt, err := d.ImSession.ExecutePureOnebotInbound(context.Background(), ep, adapterapi.InboundMessage{ProviderEventID: eventID, Kind: adapterapi.InboundKindMessage, Text: ".r 1d1"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID != "inbox-1" {
		t.Fatalf("receipt = %#v", receipt)
	}
	select {
	case got := <-core.received:
		if got.ProviderEventID != eventID || got.Text != ".r 1d1" {
			t.Fatalf("durable executor input = %#v", got)
		}
	default:
		t.Fatal("durable executor did not receive inbound message")
	}
	if len(d.ImSession.EndPoints) != 1 {
		t.Fatalf("read view mutated legacy endpoint slice: %d", len(d.ImSession.EndPoints))
	}
}

func TestExecutePureOnebotInboundAllowsProviderEventIDFallback(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	core := &pureOnebotDurableStub{
		received: make(chan adapterapi.InboundMessage, 1),
		receipt:  adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted, InboxID: "inbox-fallback"},
	}
	d.ImSession.PureOnebotInboundExecutor = core
	ep := NewPureOnebotReadEndpoint(adapterapi.EndpointID("pureonebot-inbound-fallback"), adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700"}`)})
	receipt, err := d.ImSession.ExecutePureOnebotInbound(context.Background(), ep, adapterapi.InboundMessage{Kind: adapterapi.InboundKindMessage, Text: "plain"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID != "inbox-fallback" {
		t.Fatalf("receipt = %#v", receipt)
	}
}
func TestExecutePureOnebotInboundRejectedReceiptHasNoSyntheticInboxID(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	id := adapterapi.EndpointID("pureonebot-inbound-rejected")
	ep := NewPureOnebotReadEndpoint(id, adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700"}`)})
	receipt, err := d.ImSession.ExecutePureOnebotInbound(context.Background(), ep, adapterapi.InboundMessage{
		ProviderEventID: "provider-event-rejected",
		Kind:            adapterapi.InboundKindNotice,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressRejected || receipt.InboxID != "" {
		t.Fatalf("receipt = %#v, want rejected receipt without synthetic inbox id", receipt)
	}
}
func TestExecutePureOnebotInboundRejectsMissingDurableInboxID(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	d.ImSession.PureOnebotInboundExecutor = &pureOnebotDurableStub{
		received: make(chan adapterapi.InboundMessage, 1),
		receipt:  adapterapi.IngressReceipt{Outcome: adapterapi.IngressDuplicate},
	}
	ep := NewPureOnebotReadEndpoint(adapterapi.EndpointID("pureonebot-inbound-missing-inbox"), adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700"}`)})
	_, err := d.ImSession.ExecutePureOnebotInbound(context.Background(), ep, adapterapi.InboundMessage{Kind: adapterapi.InboundKindMessage, Text: "duplicate"})
	if err == nil {
		t.Fatal("missing durable inbox id was accepted")
	}
}
