package dice

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

const onebotGlobalEventTestTimeout = 3 * time.Second

type onebotPassthroughCore struct {
	*onebotRuntimeCore
	adapterEvents  chan adapterapi.AdapterEvent
	adapterErr     error
	adapterOutcome adapterapi.IngressOutcome
}

func newOnebotPassthroughRuntime(t *testing.T) (*onebotRuntime, *onebotPassthroughCore) {
	t.Helper()
	core := &onebotPassthroughCore{
		onebotRuntimeCore: &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 8)},
		adapterEvents:     make(chan adapterapi.AdapterEvent, 8),
	}
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	runtime.core = core
	runtime.startGlobalOnebotEventDelivery(context.Background(), core)
	t.Cleanup(func() {
		runtime.stopGlobalOnebotEventDelivery()
		runtime.waitGlobalOnebotEventDelivery()
	})
	return runtime, core
}

func (core *onebotPassthroughCore) HandleAdapterEvent(_ context.Context, event adapterapi.AdapterEvent) (adapterapi.IngressReceipt, error) {
	core.adapterEvents <- event
	if core.adapterErr != nil {
		return adapterapi.IngressReceipt{}, core.adapterErr
	}
	if core.adapterOutcome != adapterapi.IngressOutcomeInvalid {
		return adapterapi.IngressReceipt{Outcome: core.adapterOutcome}, nil
	}
	return adapterapi.IngressReceipt{Outcome: adapterapi.IngressAccepted}, nil
}

func TestOnebotUnknownConversationNoticesReachCoreWithExactRawJSON(t *testing.T) {
	for name, raw := range map[string]string{
		"emoji": " {\n \"post_type\" : \"notice\", \"notice_type\":\"group_msg_emoji_like\",\"group_id\":2002,\"user_id\":1001,\"emoji_id\":900719925474099312345,\"time\":1700000000\n} ",
		"admin": `{"post_type":"notice","notice_type":"group_admin","sub_type":"set","group_id":2002,"user_id":1001,"time":1700000000}`,
		"title": `{"post_type":"notice","notice_type":"group_title","group_id":2002,"user_id":1001,"title":"helper","time":1700000000}`,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, core := newOnebotPassthroughRuntime(t)
			if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
				t.Fatal(err)
			}
			select {
			case message := <-core.inboundCh:
				if message.Kind != adapterapi.InboundKindAdapterEvent || message.ConversationKind != adapterapi.ConversationKindGroup || message.Conversation != "QQ-Group:2002" || message.Target != "QQ-Group:2002" || message.Sender != "QQ:1001" {
					t.Fatalf("normalized opaque inbound = %#v", message)
				}
				if message.AdapterEvent == nil || message.AdapterEvent.Protocol != "onebot11" || message.AdapterEvent.Type != "notice" || message.AdapterEvent.RawJSON != raw {
					t.Fatalf("adapter event = %#v", message.AdapterEvent)
				}
			default:
				t.Fatal("opaque conversation event did not reach durable ingress")
			}
			select {
			case event := <-core.adapterEvents:
				t.Fatalf("conversation event also used global port: %#v", event)
			default:
			}
		})
	}
}

func TestOnebotKnownMessageAndPokeAttachRawEventWithoutDuplicateIngress(t *testing.T) {
	for name, raw := range map[string]string{
		"message": `{"post_type":"message","message_type":"group","message_id":77,"group_id":2002,"user_id":1001,"message":"hello","time":1700000000}`,
		"poke":    `{"post_type":"notice","notice_type":"notify","sub_type":"poke","group_id":2002,"user_id":1001,"target_id":3003,"self_id":3003,"time":1700000000}`,
	} {
		t.Run(name, func(t *testing.T) {
			runtime, core := newOnebotPassthroughRuntime(t)
			if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
				t.Fatal(err)
			}
			message := <-core.inboundCh
			if message.AdapterEvent == nil || message.AdapterEvent.RawJSON != raw {
				t.Fatalf("known inbound lost raw event: %#v", message)
			}
			if name == "message" && message.Kind != adapterapi.InboundKindMessage {
				t.Fatalf("message kind = %v", message.Kind)
			}
			if name == "poke" && (message.Kind != adapterapi.InboundKindNotice || message.Event != adapterapi.InboundEventPoke) {
				t.Fatalf("poke = %#v", message)
			}
			select {
			case duplicate := <-core.inboundCh:
				t.Fatalf("known event entered ingress twice: %#v", duplicate)
			default:
			}
		})
	}
}

func TestOnebotIgnoredKnownNoticeIsRetainedAsOpaqueConversationEvent(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	raw := `{"post_type":"notice","notice_type":"group_decrease","sub_type":"leave","group_id":2002,"user_id":4004,"operator_id":4004,"self_id":3003,"time":1700000000}`
	if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if message := <-core.inboundCh; message.Kind != adapterapi.InboundKindAdapterEvent || message.AdapterEvent == nil || message.AdapterEvent.RawJSON != raw {
		t.Fatalf("ignored known notice = %#v", message)
	}
}

func TestOnebotMalformedKnownFrameRemainsRejected(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	raw := []byte(`{"post_type":"message","message_type":"group","group_id":2002,"user_id":1001,"message":"missing id"}`)
	if err := runtime.handleProtocolInbound(context.Background(), raw); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
		t.Fatalf("malformed known frame error = %v", err)
	}
	select {
	case message := <-core.inboundCh:
		t.Fatalf("malformed frame reached ingress: %#v", message)
	default:
	}
	select {
	case event := <-core.adapterEvents:
		t.Fatalf("malformed frame reached global hook: %#v", event)
	default:
	}
}

func TestOnebotMetadataWithoutConversationUsesOptionalGlobalPortAndContainsFailure(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	core.adapterErr = errors.New("plugin rejected metadata")
	raw := `{"time":1700000000,"post_type":"meta_event","meta_event_type":"heartbeat","status":{"online":true},"interval":5000}`
	if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
		t.Fatalf("global callback failure escaped protocol runtime: %v", err)
	}
	select {
	case event := <-core.adapterEvents:
		if event.Protocol != "onebot11" || event.Type != "meta_event" || event.RawJSON != raw {
			t.Fatalf("global adapter event = %#v", event)
		}
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("global adapter event was not delivered")
	}
	select {
	case message := <-core.inboundCh:
		t.Fatalf("metadata fabricated a durable conversation: %#v", message)
	default:
	}
	if got := runtime.inboundRejected.Load(); got != 0 {
		t.Fatalf("heartbeat rejection count = %d, want 0", got)
	}
}

func TestOnebotGlobalEventLanePreservesOrderAndExactRawJSON(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	rawEvents := []string{
		" {\n \"post_type\":\"meta_event\",\"meta_event_type\":\"lifecycle\",\"sequence\":900719925474099312345\n} ",
		`{"post_type":"notice","notice_type":"vendor_status","sequence":2}`,
		`{"post_type":"request","request_type":"vendor_authorization","sequence":3}`,
	}
	for _, raw := range rawEvents {
		if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for index, raw := range rawEvents {
		select {
		case event := <-core.adapterEvents:
			if event.RawJSON != raw {
				t.Fatalf("global event %d raw JSON = %q, want %q", index, event.RawJSON, raw)
			}
		case <-time.After(onebotGlobalEventTestTimeout):
			t.Fatalf("global event %d was not delivered", index)
		}
	}
	if got := runtime.globalEventAccepted.Load(); got < uint64(len(rawEvents)-1) {
		t.Fatalf("accepted global event receipts = %d, want at least %d", got, len(rawEvents)-1)
	}
}

func TestOnebotGlobalEventLaneClassifiesRejectedReceipts(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	core.adapterOutcome = adapterapi.IngressRejected
	rawEvents := []string{
		`{"post_type":"meta_event","meta_event_type":"heartbeat","sequence":1}`,
		`{"post_type":"meta_event","meta_event_type":"heartbeat","sequence":2}`,
		`{"post_type":"meta_event","meta_event_type":"heartbeat","sequence":3}`,
	}
	for _, raw := range rawEvents {
		if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for range rawEvents {
		select {
		case <-core.adapterEvents:
		case <-time.After(onebotGlobalEventTestTimeout):
			t.Fatal("rejected receipt stalled the global event lane")
		}
	}
	if got := runtime.globalEventRejected.Load(); got < uint64(len(rawEvents)-1) {
		t.Fatalf("rejected global event receipts = %d, want at least %d", got, len(rawEvents)-1)
	}
	if got := runtime.globalEventAccepted.Load(); got != 0 {
		t.Fatalf("rejected receipts counted as accepted: %d", got)
	}
}

func TestOnebotGlobalEventFailureIsNotRetriedAndDoesNotStallNextEvent(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	core.adapterErr = errors.New("plugin callback failed")
	rawEvents := []string{
		`{"post_type":"meta_event","meta_event_type":"heartbeat","sequence":1}`,
		`{"post_type":"notice","notice_type":"vendor_status","sequence":2}`,
	}
	for _, raw := range rawEvents {
		if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for index, raw := range rawEvents {
		select {
		case event := <-core.adapterEvents:
			if event.RawJSON != raw {
				t.Fatalf("global callback %d raw JSON = %q, want %q", index, event.RawJSON, raw)
			}
		case <-time.After(onebotGlobalEventTestTimeout):
			t.Fatalf("global callback %d was stalled", index)
		}
	}
	if got := runtime.globalEventFailed.Load(); got == 0 {
		t.Fatal("failed global event delivery was not diagnosed")
	}
}

func TestOnebotAPIResponseFrameNeverBecomesAdapterEvent(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	raw := []byte(`{"status":"ok","retcode":0,"data":{"message_id":77},"echo":"adapter-owned"}`)
	if err := runtime.handleProtocolInbound(context.Background(), raw); !errors.Is(err, ErrOnebotUnsupportedInboundEvent) {
		t.Fatalf("API response error = %v", err)
	}
	select {
	case message := <-core.inboundCh:
		t.Fatalf("API response reached durable ingress: %#v", message)
	default:
	}
	select {
	case event := <-core.adapterEvents:
		t.Fatalf("API response reached global adapter hook: %#v", event)
	default:
	}
}

func TestOnebotOpaqueIdentityIncludesRawDigestAtSameSecond(t *testing.T) {
	runtime, core := newOnebotPassthroughRuntime(t)
	for _, noticeType := range []string{"group_admin", "group_title"} {
		raw := `{"post_type":"notice","notice_type":"` + noticeType + `","group_id":2002,"user_id":1001,"time":1700000000}`
		if err := runtime.handleProtocolInbound(context.Background(), []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-core.inboundCh, <-core.inboundCh
	if first.ProviderEventID == "" || second.ProviderEventID == "" || first.ProviderEventID == second.ProviderEventID {
		t.Fatalf("opaque provider identities collapsed: %q and %q", first.ProviderEventID, second.ProviderEventID)
	}
}

type blockingOnebotPassthroughCore struct {
	*onebotPassthroughCore
	started      chan struct{}
	canceled     chan struct{}
	startedOnce  sync.Once
	canceledOnce sync.Once
}

func newBlockingOnebotPassthroughRuntime(t *testing.T) (*onebotRuntime, *blockingOnebotPassthroughCore) {
	t.Helper()
	core := &blockingOnebotPassthroughCore{
		onebotPassthroughCore: &onebotPassthroughCore{
			onebotRuntimeCore: &onebotRuntimeCore{inboundCh: make(chan adapterapi.InboundMessage, 8)},
			adapterEvents:     make(chan adapterapi.AdapterEvent, 8),
		},
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	runtime.core = core
	runtime.startGlobalOnebotEventDelivery(context.Background(), core)
	t.Cleanup(func() {
		runtime.stopGlobalOnebotEventDelivery()
		runtime.waitGlobalOnebotEventDelivery()
	})
	return runtime, core
}

func (core *blockingOnebotPassthroughCore) HandleAdapterEvent(ctx context.Context, event adapterapi.AdapterEvent) (adapterapi.IngressReceipt, error) {
	core.adapterEvents <- event
	core.startedOnce.Do(func() { close(core.started) })
	<-ctx.Done()
	core.canceledOnce.Do(func() { close(core.canceled) })
	return adapterapi.IngressReceipt{}, ctx.Err()
}

func TestOnebotOutstandingGlobalCallbackDoesNotBlockConversationIngress(t *testing.T) {
	runtime, core := newBlockingOnebotPassthroughRuntime(t)
	globalRaw := []byte(`{"post_type":"meta_event","meta_event_type":"heartbeat","time":1700000000}`)
	messageRaw := []byte(`{"post_type":"message","message_type":"group","message_id":78,"group_id":2002,"user_id":1001,"message":"still delivered","time":1700000001}`)

	eventLoopDone := make(chan error, 1)
	go func() {
		if err := runtime.handleProtocolInbound(context.Background(), globalRaw); err != nil {
			eventLoopDone <- err
			return
		}
		eventLoopDone <- runtime.handleProtocolInbound(context.Background(), messageRaw)
	}()

	select {
	case <-core.started:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("global callback did not start")
	}
	select {
	case message := <-core.inboundCh:
		if message.AdapterEvent == nil || message.AdapterEvent.RawJSON != string(messageRaw) {
			t.Fatalf("conversation ingress = %#v", message)
		}
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("conversation ingress was stalled behind the global callback")
	}
	select {
	case err := <-eventLoopDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("protocol event loop remained blocked")
	}
}

func TestOnebotRunLoopContinuesPastOutstandingGlobalCallback(t *testing.T) {
	config, _ := onebotRuntimeServerConfig(t)
	resolver := &onebotRuntimeResolver{bytes: []byte("runtime-token"), calls: make(chan struct{}, 1)}
	core := &blockingOnebotPassthroughCore{
		onebotPassthroughCore: &onebotPassthroughCore{
			onebotRuntimeCore: &onebotRuntimeCore{
				ch:        make(chan adapterapi.LifecycleObservation, 16),
				inboundCh: make(chan adapterapi.InboundMessage, 1),
			},
			adapterEvents: make(chan adapterapi.AdapterEvent, 1),
		},
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	runtime := newOnebotRuntime(config, resolver)
	runDone := make(chan error, 1)
	go func() {
		runDone <- runtime.Run(context.Background(), core)
	}()
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), onebotGlobalEventTestTimeout)
		defer cancel()
		_ = runtime.Stop(stopCtx)
	})
	core.waitState(t, adapterapi.ObservedStateStarting)
	select {
	case <-resolver.calls:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("runtime did not resolve its token")
	}

	globalRaw := []byte(`{"post_type":"meta_event","meta_event_type":"heartbeat","time":1700000000}`)
	messageRaw := []byte(`{"post_type":"message","message_type":"group","message_id":79,"group_id":2002,"user_id":1001,"message":"run loop continued","time":1700000001}`)
	if !runtime.enqueue(onebotRuntimeEvent{kind: "inbound", raw: globalRaw}) {
		t.Fatal("global event was not admitted to the runtime loop")
	}
	if !runtime.enqueue(onebotRuntimeEvent{kind: "inbound", raw: messageRaw}) {
		t.Fatal("conversation event was not admitted to the runtime loop")
	}
	select {
	case <-core.started:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("Run did not start the global event worker")
	}
	select {
	case message := <-core.inboundCh:
		if message.AdapterEvent == nil || message.AdapterEvent.RawJSON != string(messageRaw) {
			t.Fatalf("conversation ingress = %#v", message)
		}
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("Run loop stalled behind the global callback")
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), onebotGlobalEventTestTimeout)
	defer cancel()
	if err := runtime.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run after Stop = %v", err)
		}
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("Run did not release the global event worker")
	}
}

func TestOnebotGlobalEventLaneReportsBackpressureWithSingleWorker(t *testing.T) {
	runtime, core := newBlockingOnebotPassthroughRuntime(t)
	raw := []byte(`{"post_type":"meta_event","meta_event_type":"heartbeat","time":1700000000}`)
	if err := runtime.handleProtocolInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	select {
	case <-core.started:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("global callback did not start")
	}

	for range maxOnebotGlobalEventQueue {
		if err := runtime.handleProtocolInbound(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.handleProtocolInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if got := runtime.globalEventBackpressure.Load(); got != 1 {
		t.Fatalf("global event backpressure = %d, want 1", got)
	}
	if got := runtime.globalEventEnqueued.Load(); got != maxOnebotGlobalEventQueue+1 {
		t.Fatalf("global event queue admissions = %d, want %d", got, maxOnebotGlobalEventQueue+1)
	}
	if got := len(core.adapterEvents); got != 1 {
		t.Fatalf("global callback attempts = %d, want one outstanding non-retried callback", got)
	}

	found := false
	for _, entry := range runtime.Diagnostics(context.Background()).Entries {
		if entry.Code == "adapter_event.backpressure" {
			found = true
		}
	}
	if !found {
		t.Fatal("global event backpressure diagnostic is missing")
	}
}

func TestOnebotCleanupCancelsGlobalEventWorker(t *testing.T) {
	runtime, core := newBlockingOnebotPassthroughRuntime(t)
	raw := []byte(`{"post_type":"notice","notice_type":"vendor_status","time":1700000000}`)
	if err := runtime.handleProtocolInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	select {
	case <-core.started:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("global callback did not start")
	}

	cleanupDone := make(chan struct{})
	go func() {
		runtime.cleanup()
		close(cleanupDone)
	}()
	select {
	case <-core.canceled:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("cleanup did not cancel the outstanding global callback")
	}
	select {
	case <-cleanupDone:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("cleanup did not release the owned global event worker")
	}
}

func TestOnebotStopCancelsGlobalEventWorker(t *testing.T) {
	runtime, core := newBlockingOnebotPassthroughRuntime(t)
	raw := []byte(`{"post_type":"meta_event","meta_event_type":"heartbeat","time":1700000000}`)
	if err := runtime.handleProtocolInbound(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	select {
	case <-core.started:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("global callback did not start")
	}

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- runtime.Stop(context.Background())
	}()
	select {
	case <-core.canceled:
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("Stop did not cancel the outstanding global callback")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(onebotGlobalEventTestTimeout):
		t.Fatal("Stop returned without releasing the owned global event worker")
	}
}
