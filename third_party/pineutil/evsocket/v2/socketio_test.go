package socketio

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lxzan/gws"
)

func TestShutdownWaitDrainsQueuedWrapperEvents(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	manager.registerWrapper(wrapper)
	close(wrapper.connectReady)

	entered := make(chan struct{})
	release := make(chan struct{})
	manager.On(EventDisconnect, func(*EventPayload) {
		close(entered)
		<-release
	})
	wrapper.dispatchEvent(EventDisconnect, nil, nil)

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- manager.ShutdownWait(ctx)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("disconnect callback did not start")
	}
	select {
	case err := <-shutdownDone:
		t.Fatalf("ShutdownWait returned before queued callback drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("ShutdownWait returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ShutdownWait did not drain queued callback")
	}
}


func TestWrapperEventQueueIsBounded(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	close(wrapper.connectReady)
	entered := make(chan struct{})
	release := make(chan struct{})
	disconnected := make(chan struct{})
	connected := make(chan struct{})
	manager.On(EventMessage, func(*EventPayload) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
	})
	manager.On(EventDisconnect, func(*EventPayload) {
		close(disconnected)
	})
	manager.On(EventConnect, func(*EventPayload) {
		close(connected)
	})
	wrapper.dispatchMessage(1, []byte("first"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("message callback did not start")
	}
	for range maxWrapperEventQueue {
		wrapper.dispatchMessage(1, []byte("queued"))
	}
	wrapper.dispatchEvent(EventDisconnect, nil, nil)
	wrapper.dispatchEvent(EventConnect, nil, nil)
	if wrapper.DroppedEventCount() != 2 {
		t.Fatalf("dropped events after lifecycle admission = %d", wrapper.DroppedEventCount())
	}
	wrapper.dispatchMessage(1, []byte("overflow"))
	if wrapper.DroppedEventCount() != 3 {
		t.Fatalf("dropped events after overflow = %d", wrapper.DroppedEventCount())
	}
	close(release)
	if err := wrapper.WaitEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("terminal disconnect event was dropped")
	}
	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("terminal connect event was dropped")
	}
}

func TestTransportMessageIsBoundBeforeCopy(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	handler := &transportHandler{wrapper: wrapper}
	message := &gws.Message{
		Opcode: gws.OpcodeText,
		Data:   bytes.NewBuffer(make([]byte, maxWrapperMessageBytes+1)),
	}
	handler.OnMessage(nil, message)
	if wrapper.DroppedEventCount() != 1 {
		t.Fatalf("dropped events = %d", wrapper.DroppedEventCount())
	}
	if len(wrapper.eventQueue) != 0 {
		t.Fatalf("oversized message entered queue: %d", len(wrapper.eventQueue))
	}
}

func TestConnectReadySignalIsIdempotentAcrossReconnects(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	wrapper.markConnectedReady()
	wrapper.markConnectedReady()
	select {
	case <-wrapper.connectReady:
	default:
		t.Fatal("connect readiness was not signaled")
	}
}

func TestServerWrapperRegistryUnregistersChurn(t *testing.T) {
	manager := NewSocketInstance()
	for range 128 {
		wrapper := newServerWrapper(manager)
		manager.registerWrapper(wrapper)
		manager.unregisterWrapper(wrapper)
	}
	manager.wrappersMu.Lock()
	defer manager.wrappersMu.Unlock()
	if len(manager.wrappers) != 0 {
		t.Fatalf("registered wrappers after churn = %d", len(manager.wrappers))
	}
}

func TestServerWrapperUnregistersAfterTerminalCallbacksDrain(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newServerWrapper(manager)
	manager.registerWrapper(wrapper)
	close(wrapper.connectReady)
	manager.On(EventDisconnect, func(*EventPayload) {})
	wrapper.serverClosed.Store(true)
	wrapper.serverTerminalPending.Store(1)
	wrapper.dispatchEvent(EventDisconnect, nil, nil)
	if err := wrapper.WaitEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.wrappersMu.Lock()
	defer manager.wrappersMu.Unlock()
	if _, ok := manager.wrappers[wrapper]; ok {
		t.Fatal("server wrapper unregistered before terminal callback drain")
	}
}

func TestTransportDropBaselineCapturesPreConnectDrops(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newServerWrapper(manager)
	wrapper.droppedEvents.Store(3)
	(&transportHandler{wrapper: wrapper}).OnOpen(nil)
	if got := wrapper.TransportDropBaseline(); got != 3 {
		t.Fatalf("transport drop baseline = %d, want 3", got)
	}
}

func TestSafePoolDeleteIfPreservesReplacement(t *testing.T) {
	pool := safePool{}
	oldWrapper := &WebsocketWrapper{UUID: "same"}
	newWrapper := &WebsocketWrapper{UUID: "same"}
	pool.set(oldWrapper)
	pool.set(newWrapper)
	pool.deleteIf("same", oldWrapper)
	got, err := pool.get("same")
	if err != nil || got != newWrapper {
		t.Fatalf("replacement wrapper was deleted: got=%p err=%v", got, err)
	}
}

func TestDisconnectEvictsQueuedConnectWhenTerminalQueueIsFull(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	close(wrapper.connectReady)
	entered := make(chan struct{})
	release := make(chan struct{})
	disconnected := make(chan struct{})
	manager.On(EventMessage, func(*EventPayload) {
		close(entered)
		<-release
	})
	manager.On(EventConnect, func(*EventPayload) {})
	manager.On(EventDisconnect, func(*EventPayload) { close(disconnected) })
	wrapper.dispatchMessage(1, []byte("first"))
	<-entered
	for range maxWrapperEventQueue {
		wrapper.dispatchEvent(EventConnect, nil, nil)
	}
	wrapper.dispatchEvent(EventDisconnect, nil, nil)
	close(release)
	if err := wrapper.WaitEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("disconnect was dropped behind queued connect events")
	}
}

func TestDuplicateDisconnectCoalescesWhenTerminalQueueIsFull(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	close(wrapper.connectReady)
	entered := make(chan struct{})
	release := make(chan struct{})
	manager.On(EventMessage, func(*EventPayload) {
		close(entered)
		<-release
	})
	manager.On(EventDisconnect, func(*EventPayload) {})
	wrapper.dispatchMessage(1, []byte("first"))
	<-entered
	for range maxWrapperEventQueue {
		wrapper.dispatchEvent(EventDisconnect, nil, nil)
	}
	before := wrapper.DroppedEventCount()
	wrapper.dispatchEvent(EventDisconnect, nil, nil)
	if wrapper.DroppedEventCount() != before+1 {
		t.Fatalf("duplicate disconnect drop count = %d, want %d", wrapper.DroppedEventCount(), before+1)
	}
	close(release)
	if err := wrapper.WaitEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateConnectCoalescesBeforeEvictingOrdinaryQueue(t *testing.T) {
	manager := NewSocketInstance()
	wrapper := newClientWrapper(manager, "ws://127.0.0.1", ClientOptions{})
	close(wrapper.connectReady)
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	manager.On(EventMessage, func(*EventPayload) {
		enteredOnce.Do(func() { close(entered) })
		<-release
	})
	manager.On(EventConnect, func(*EventPayload) {})
	wrapper.dispatchMessage(1, []byte("first"))
	<-entered
	for range maxWrapperEventQueue - 1 {
		wrapper.dispatchMessage(1, []byte("queued"))
	}
	wrapper.dispatchEvent(EventConnect, nil, nil)
	before := wrapper.DroppedEventCount()
	wrapper.dispatchEvent(EventConnect, nil, nil)
	if wrapper.DroppedEventCount() != before+1 {
		t.Fatalf("duplicate connect drop count = %d, want %d", wrapper.DroppedEventCount(), before+1)
	}
	close(release)
	if err := wrapper.WaitEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
}