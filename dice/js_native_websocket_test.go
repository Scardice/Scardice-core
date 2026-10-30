package dice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/utils/jsengine/services"
)

type nativeWebSocketTestEvent struct {
	kind     services.EventKind
	response services.Response
}

type nativeWebSocketTestSink struct {
	events chan nativeWebSocketTestEvent
}

func (s *nativeWebSocketTestSink) Event(_ services.RequestID, response services.Response) error {
	s.events <- nativeWebSocketTestEvent{kind: services.EventData, response: response}
	return nil
}

func (s *nativeWebSocketTestSink) Complete(_ services.RequestID, response services.Response) error {
	s.events <- nativeWebSocketTestEvent{kind: services.EventComplete, response: response}
	return nil
}

func (s *nativeWebSocketTestSink) Close(_ services.RequestID, response services.Response) error {
	s.events <- nativeWebSocketTestEvent{kind: services.EventClose, response: response}
	return nil
}

func TestNativeWebSocketServiceConnectSendAndClose(t *testing.T) {
	upgrader := websocket.Upgrader{Subprotocols: []string{"chat"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		for {
			messageType, payload, readErr := connection.ReadMessage()
			if readErr != nil {
				return
			}
			if writeErr := connection.WriteMessage(messageType, payload); writeErr != nil {
				return
			}
		}
	}))
	defer server.Close()

	var service services.Service
	for _, factory := range nativeServiceFactories {
		if factory.name == services.WebSocket {
			service = factory.newService(&Dice{}, nil)
			break
		}
	}
	if service == nil {
		t.Fatal("native WebSocket service is not registered")
	}
	asyncService, ok := service.(services.AsyncService)
	if !ok {
		t.Fatal("native WebSocket service is not asynchronous")
	}

	sink := &nativeWebSocketTestSink{events: make(chan nativeWebSocketTestEvent, 8)}
	const requestID services.RequestID = 41
	if err := asyncService.Start(services.AsyncCall{
		ID: requestID,
		Call: services.Call{Request: services.Request{
			Service:   services.WebSocket,
			Operation: services.OpWebSocketConnect,
			String:    "ws" + strings.TrimPrefix(server.URL, "http"),
			Bytes:     []byte(`["chat"]`),
		}},
		Sink: sink,
	}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = asyncService.Cancel(requestID) }()

	open := waitNativeWebSocketTestEvent(t, sink.events)
	if open.kind != services.EventData || !strings.Contains(open.response.String, `"type":"open"`) ||
		!strings.Contains(open.response.String, `"protocol":"chat"`) {
		t.Fatalf("open event = %#v", open)
	}

	response, err := service.Invoke(services.Call{Request: services.Request{
		Service: services.WebSocket, Operation: services.OpWebSocketSend,
		String: "text", Bytes: []byte("ping"), Uint64: uint64(requestID),
	}})
	if err != nil || response.Status != services.StatusOK {
		t.Fatalf("send = %#v, %v", response, err)
	}
	message := waitNativeWebSocketTestEvent(t, sink.events)
	if message.kind != services.EventData || !strings.Contains(message.response.String, `"type":"message"`) ||
		string(message.response.Bytes) != "ping" {
		t.Fatalf("message event = %#v", message)
	}

	response, err = service.Invoke(services.Call{Request: services.Request{
		Service: services.WebSocket, Operation: services.OpWebSocketClose,
		String: `{"code":1000,"reason":"done"}`, Uint64: uint64(requestID),
	}})
	if err != nil || response.Status != services.StatusOK {
		t.Fatalf("close = %#v, %v", response, err)
	}
	closed := waitNativeWebSocketTestEvent(t, sink.events)
	if closed.kind != services.EventClose ||
		!strings.Contains(closed.response.String, `"type":"close"`) ||
		!strings.Contains(closed.response.String, `"code":1000`) ||
		!strings.Contains(closed.response.String, `"reason":"done"`) ||
		!strings.Contains(closed.response.String, `"wasClean":true`) {
		t.Fatalf("close event = %#v", closed)
	}
}

func waitNativeWebSocketTestEvent(t *testing.T, events <-chan nativeWebSocketTestEvent) nativeWebSocketTestEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for native WebSocket event")
		return nativeWebSocketTestEvent{}
	}
}
