package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/utils/jsengine/services"
)

type nativeWebSocketService struct {
	maxConnections  uint64
	maxMessageBytes uint64
	dialer          websocket.Dialer

	mu          sync.Mutex
	connections map[services.RequestID]*nativeWebSocketConnection
}

type nativeWebSocketConnection struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu             sync.Mutex
	writeMu        sync.Mutex
	conn           *websocket.Conn
	requestedClose *nativeWebSocketCloseRequest
	close          sync.Once
}

type nativeWebSocketEvent struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol,omitempty"`
	Binary   bool   `json:"binary,omitempty"`
	Code     int    `json:"code,omitempty"`
	Reason   string `json:"reason,omitempty"`
	WasClean bool   `json:"wasClean,omitempty"`
	Message  string `json:"message,omitempty"`
}

type nativeWebSocketCloseRequest struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}

func newNativeWebSocketService(d *Dice) *nativeWebSocketService {
	service := &nativeWebSocketService{dialer: *websocket.DefaultDialer}
	if d != nil {
		service.maxConnections = d.Config.QuickJSMaxWebSocketConnections
		if d.Config.QuickJSMaxWebSocketMessageMiB <= ^uint64(0)/(1024*1024) {
			service.maxMessageBytes = d.Config.QuickJSMaxWebSocketMessageMiB * 1024 * 1024
		}
	}
	return service
}

func (s *nativeWebSocketService) Definition() services.Definition {
	return services.Definition{
		Name:       services.WebSocket,
		Operations: []services.OperationID{services.OpWebSocketSend, services.OpWebSocketClose},
		AsyncOperations: []services.OperationID{
			services.OpWebSocketConnect,
		},
	}
}

func (s *nativeWebSocketService) Invoke(call services.Call) (services.Response, error) {
	if s == nil {
		return services.Response{Status: services.StatusInternal}, errors.New("native WebSocket service is unavailable")
	}
	request := call.Request
	connection, err := s.connection(services.RequestID(request.Uint64))
	if err != nil {
		return services.Response{Status: services.StatusInvalid}, err
	}
	switch request.Operation {
	case services.OpWebSocketSend:
		if s.maxMessageBytes != 0 && uint64(len(request.Bytes)) > s.maxMessageBytes {
			return services.Response{Status: services.StatusInvalid}, errors.New("WebSocket message exceeds configured limit")
		}
		messageType := websocket.TextMessage
		if request.String == "binary" {
			messageType = websocket.BinaryMessage
		} else if request.String != "text" {
			return services.Response{Status: services.StatusInvalid}, errors.New("WebSocket message type is invalid")
		}
		if err := connection.write(messageType, request.Bytes); err != nil {
			return services.Response{Status: services.StatusInternal}, err
		}
		return services.Response{Status: services.StatusOK}, nil
	case services.OpWebSocketClose:
		var closeRequest nativeWebSocketCloseRequest
		if err := json.Unmarshal([]byte(request.String), &closeRequest); err != nil {
			return services.Response{Status: services.StatusInvalid}, fmt.Errorf("decode WebSocket close metadata: %w", err)
		}
		if closeRequest.Code == 0 {
			closeRequest.Code = websocket.CloseNormalClosure
		}
		if len(closeRequest.Reason) > 123 {
			return services.Response{Status: services.StatusInvalid}, errors.New("WebSocket close reason exceeds 123 bytes")
		}
		if err := connection.writeClose(closeRequest.Code, closeRequest.Reason); err != nil {
			return services.Response{Status: services.StatusInternal}, err
		}
		return services.Response{Status: services.StatusOK}, nil
	default:
		return services.Response{Status: services.StatusUnsupported}, fmt.Errorf("unsupported WebSocket operation %d", request.Operation)
	}
}

func (s *nativeWebSocketService) Start(call services.AsyncCall) error {
	if s == nil || call.Sink == nil {
		return errors.New("native WebSocket service is unavailable")
	}
	if call.Call.Request.Operation != services.OpWebSocketConnect || call.ID == 0 || call.Call.Request.String == "" {
		return errors.New("invalid WebSocket connect request")
	}
	var protocols []string
	if len(call.Call.Request.Bytes) != 0 {
		if err := json.Unmarshal(call.Call.Request.Bytes, &protocols); err != nil {
			return fmt.Errorf("decode WebSocket protocols: %w", err)
		}
	}
	for _, protocol := range protocols {
		if protocol == "" {
			return errors.New("WebSocket protocol must not be empty")
		}
	}

	runContext, cancel := context.WithCancel(context.Background())
	connection := &nativeWebSocketConnection{cancel: cancel, done: make(chan struct{})}
	s.mu.Lock()
	if s.connections == nil {
		s.connections = make(map[services.RequestID]*nativeWebSocketConnection)
	}
	if _, exists := s.connections[call.ID]; exists {
		s.mu.Unlock()
		cancel()
		return errors.New("WebSocket request already exists")
	}
	if s.maxConnections != 0 && uint64(len(s.connections)) >= s.maxConnections {
		s.mu.Unlock()
		cancel()
		return errors.New("WebSocket connection limit reached")
	}
	s.connections[call.ID] = connection
	s.mu.Unlock()

	go s.run(runContext, call, connection, protocols)
	return nil
}

func (s *nativeWebSocketService) Cancel(id services.RequestID) error {
	if s == nil || id == 0 {
		return nil
	}
	s.mu.Lock()
	connection := s.connections[id]
	delete(s.connections, id)
	s.mu.Unlock()
	if connection != nil {
		connection.shutdown()
	}
	return nil
}

func (s *nativeWebSocketService) run(ctx context.Context, call services.AsyncCall, state *nativeWebSocketConnection, protocols []string) {
	defer func() {
		s.remove(call.ID, state)
		state.shutdown()
	}()

	dialer := s.dialer
	dialer.Subprotocols = append([]string(nil), protocols...)
	connection, response, err := dialer.DialContext(ctx, call.Call.Request.String, http.Header{})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		_ = call.Sink.Close(call.ID, services.Response{
			Status: services.StatusInternal,
			String: nativeWebSocketEventJSON(nativeWebSocketEvent{Type: "error", Message: err.Error()}),
		})
		return
	}
	state.mu.Lock()
	state.conn = connection
	state.mu.Unlock()
	if s.maxMessageBytes != 0 {
		connection.SetReadLimit(int64(s.maxMessageBytes))
	}

	go func() {
		select {
		case <-ctx.Done():
			state.shutdown()
		case <-call.Call.Cancellation:
			state.shutdown()
		case <-state.done:
		}
	}()

	if err := call.Sink.Event(call.ID, services.Response{
		Status: services.StatusOK,
		String: nativeWebSocketEventJSON(nativeWebSocketEvent{Type: "open", Protocol: connection.Subprotocol()}),
	}); err != nil {
		return
	}

	for {
		messageType, payload, readErr := connection.ReadMessage()
		if readErr != nil {
			code := websocket.CloseAbnormalClosure
			reason := readErr.Error()
			wasClean := false
			if requestedCode, requestedReason, ok := state.localClose(); ok {
				code = requestedCode
				reason = requestedReason
				wasClean = true
			} else {
				var closeError *websocket.CloseError
				if errors.As(readErr, &closeError) {
					code = closeError.Code
					reason = closeError.Text
					wasClean = code == websocket.CloseNormalClosure || code == websocket.CloseGoingAway
				}
			}
			_ = call.Sink.Close(call.ID, services.Response{
				Status: services.StatusOK,
				String: nativeWebSocketEventJSON(nativeWebSocketEvent{
					Type: "close", Code: code, Reason: reason, WasClean: wasClean,
				}),
			})
			return
		}
		if s.maxMessageBytes != 0 && uint64(len(payload)) > s.maxMessageBytes {
			_ = connection.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseMessageTooBig, "message too large"), time.Now().Add(time.Second))
			_ = call.Sink.Close(call.ID, services.Response{
				Status: services.StatusInvalid,
				String: nativeWebSocketEventJSON(nativeWebSocketEvent{
					Type: "close", Code: websocket.CloseMessageTooBig, Reason: "message too large",
				}),
			})
			return
		}
		if err := call.Sink.Event(call.ID, services.Response{
			Status: services.StatusOK,
			String: nativeWebSocketEventJSON(nativeWebSocketEvent{
				Type: "message", Binary: messageType == websocket.BinaryMessage,
			}),
			Bytes: payload,
		}); err != nil {
			return
		}
	}
}

func (s *nativeWebSocketService) connection(id services.RequestID) (*nativeWebSocketConnection, error) {
	if id == 0 {
		return nil, errors.New("invalid WebSocket request id")
	}
	s.mu.Lock()
	connection := s.connections[id]
	s.mu.Unlock()
	if connection == nil {
		return nil, errors.New("WebSocket connection is unavailable")
	}
	connection.mu.Lock()
	ready := connection.conn != nil
	connection.mu.Unlock()
	if !ready {
		return nil, errors.New("WebSocket connection is not open")
	}
	return connection, nil
}

func (s *nativeWebSocketService) remove(id services.RequestID, connection *nativeWebSocketConnection) {
	s.mu.Lock()
	if s.connections[id] == connection {
		delete(s.connections, id)
	}
	s.mu.Unlock()
}

func (c *nativeWebSocketConnection) write(messageType int, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	connection := c.conn
	c.mu.Unlock()
	if connection == nil {
		return errors.New("WebSocket connection is not open")
	}
	return connection.WriteMessage(messageType, payload)
}

func (c *nativeWebSocketConnection) writeClose(code int, reason string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	connection := c.conn
	c.requestedClose = &nativeWebSocketCloseRequest{Code: code, Reason: reason}
	c.mu.Unlock()
	if connection == nil {
		return errors.New("WebSocket connection is not open")
	}
	if err := connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second)); err != nil {
		return err
	}
	return connection.Close()
}

func (c *nativeWebSocketConnection) localClose() (int, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requestedClose == nil {
		return 0, "", false
	}
	return c.requestedClose.Code, c.requestedClose.Reason, true
}

func (c *nativeWebSocketConnection) shutdown() {
	if c == nil {
		return
	}
	c.close.Do(func() {
		c.cancel()
		c.mu.Lock()
		connection := c.conn
		c.mu.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		close(c.done)
	})
}

func nativeWebSocketEventJSON(event nativeWebSocketEvent) string {
	encoded, err := json.Marshal(event)
	if err != nil {
		return `{"type":"error","message":"encode WebSocket event"}`
	}
	return string(encoded)
}
