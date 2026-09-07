package socketio

import (
	"context"
	"testing"
	"time"
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
	manager.On(EventMessage, func(*EventPayload) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
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
	wrapper.dispatchMessage(1, []byte("overflow"))
	if wrapper.DroppedEventCount() != 1 {
		t.Fatalf("dropped events = %d", wrapper.DroppedEventCount())
	}
	close(release)
	if err := wrapper.WaitEvents(context.Background()); err != nil {
		t.Fatal(err)
	}
}