package dice

import (
	"context"
	"testing"

	"Scardice-core/adapterapi"
)

func TestPureOnebotInboundConversationRouting(t *testing.T) {
	ep := NewPureOnebotReadEndpoint(adapterapi.EndpointID("pureonebot-routing"), adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700"}`)})
	private := pureOnebotCoreMessage(ep, adapterapi.InboundMessage{ProviderEventID: "private-event", Kind: adapterapi.InboundKindMessage, Sender: "QQ:10001", Conversation: "QQ:10001"})
	if private.MessageType != "private" || private.GroupID != "" {
		t.Fatalf("private message = %#v", private)
	}
	group := pureOnebotCoreMessage(ep, adapterapi.InboundMessage{ProviderEventID: "group-event", Kind: adapterapi.InboundKindMessage, Conversation: "QQ:group:20002"})
	if group.MessageType != "group" || group.GroupID != "QQ-Group:20002" {
		t.Fatalf("group message = %#v", group)
	}
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
	core := &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 1)}
	d.ImSession.PureOnebotInboundExecutor = core
	id := adapterapi.EndpointID("pureonebot-inbound-test")
	ep := NewPureOnebotReadEndpoint(id, adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"client","url":"ws://127.0.0.1:6700","accountHint":"QQ:10001"}`)})
	eventID := adapterapi.ProviderEventID("provider-event-1")
	receipt, err := d.ImSession.ExecutePureOnebotInbound(context.Background(), ep, adapterapi.InboundMessage{ProviderEventID: eventID, Kind: adapterapi.InboundKindMessage, Text: ".r 1d1"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID != string(eventID) {
		t.Fatalf("receipt = %#v", receipt)
	}
	select {
	case got := <-core.inboundCh:
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
