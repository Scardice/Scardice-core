package dice

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
	nativejs "Scardice-core/utils/jsengine/native"
	"Scardice-core/utils/jsengine/services"
)

// Gorilla clears the network deadline after validating the successful upgrade,
// immediately before returning the connection. Holding that exact boundary
// makes Cancel win before the service publishes the already-open socket.
type webSocketPublishGateConn struct {
	net.Conn
	handshake chan struct{}
	resume    chan struct{}
	closed    chan struct{}
	gateOnce  sync.Once
	closeOnce sync.Once
}

func (c *webSocketPublishGateConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.gateOnce.Do(func() {
			close(c.handshake)
			<-c.resume
		})
	}
	return c.Conn.SetDeadline(deadline)
}

func (c *webSocketPublishGateConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestNativeWebSocketCancellationBeforeDialPublishClosesSocket(t *testing.T) {
	serverClosed := make(chan struct{})
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		defer close(serverClosed)
		_, _, _ = connection.ReadMessage()
	}))
	defer server.Close()

	service := newNativeWebSocketService(nil)
	connected := make(chan *webSocketPublishGateConn, 1)
	service.dialer.Proxy = nil
	service.dialer.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		gate := &webSocketPublishGateConn{
			Conn: connection, handshake: make(chan struct{}), resume: make(chan struct{}), closed: make(chan struct{}),
		}
		connected <- gate
		return gate, nil
	}
	sink := &nativeWebSocketTestSink{events: make(chan nativeWebSocketTestEvent, 8)}
	const requestID services.RequestID = 812
	if err := service.Start(services.AsyncCall{
		ID: requestID,
		Call: services.Call{Request: services.Request{
			Service: services.WebSocket, Operation: services.OpWebSocketConnect,
			String: "ws" + strings.TrimPrefix(server.URL, "http"),
		}},
		Sink: sink,
	}); err != nil {
		t.Fatal(err)
	}
	gate := awaitPersistentLifecycle(t, connected, "real WebSocket TCP dial")
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.resume) }) }
	t.Cleanup(func() {
		release()
		_ = gate.Close()
	})
	awaitPersistentLifecycle(t, gate.handshake, "successful WebSocket handshake before publication")
	if err := service.Cancel(requestID); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-gate.closed:
	case event := <-sink.events:
		t.Fatalf("cancelled socket was published after shutdown: %#v", event)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled socket was neither closed nor retired")
	}
	awaitPersistentLifecycle(t, serverClosed, "cancelled peer socket to close")
	service.mu.Lock()
	remaining := len(service.connections)
	service.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("cancelled native WebSocket connections = %d, want zero", remaining)
	}
}

func TestNativePersistentWebSocketRetiresWithBinding(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		d, _, script := persistentLifecycleFixture(t, runtimeID)
		serverClosed := make(chan struct{})
		upgrader := websocket.Upgrader{}
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			connection, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			defer close(serverClosed)
			_, _, _ = connection.ReadMessage()
		}))
		defer server.Close()
		service := newNativeWebSocketService(d)
		sink := &nativeWebSocketTestSink{events: make(chan nativeWebSocketTestEvent, 8)}
		binding := script.currentPersistentBinding()
		const requestID services.RequestID = 813
		if err := service.Start(services.AsyncCall{
			ID: requestID,
			Call: services.Call{
				Context: &jsExecutionContext{Dice: d, Script: script, PersistentBinding: true, binding: binding},
				Request: services.Request{
					Service: services.WebSocket, Operation: services.OpWebSocketConnect,
					String: "ws" + strings.TrimPrefix(server.URL, "http"),
				},
			},
			Sink: sink,
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = service.Cancel(requestID) })
		event := waitNativeWebSocketTestEvent(t, sink.events)
		if !strings.Contains(event.response.String, `"type":"open"`) {
			t.Fatalf("WebSocket did not open: %#v", event)
		}
		binding.retire()
		awaitPersistentLifecycle(t, serverClosed, "retired binding to close its persistent WebSocket")
	})
}

type persistentFirstAdmissionGate struct {
	*eventstore.GORMStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *persistentFirstAdmissionGate) ExecutionRequestDigest(ctx context.Context, canonical []byte) ([]byte, error) {
	if bytes.HasPrefix(canonical, []byte("js-persistent-async\x00")) {
		first := false
		s.once.Do(func() { first = true })
		if first {
			close(s.entered)
			<-s.release
		}
	}
	return s.GORMStore.ExecutionRequestDigest(ctx, canonical)
}

type observedWebSocketService struct {
	*nativeWebSocketService
	terminalQueued chan struct{}
}

func (s *observedWebSocketService) Start(call services.AsyncCall) error {
	call.Sink = observedWebSocketSink{AsyncSink: call.Sink, terminalQueued: s.terminalQueued}
	return s.nativeWebSocketService.Start(call)
}

type observedWebSocketSink struct {
	services.AsyncSink
	terminalQueued chan struct{}
}

func (s observedWebSocketSink) Close(id services.RequestID, response services.Response) error {
	err := s.AsyncSink.Close(id, response)
	close(s.terminalQueued)
	return err
}

func TestNativePersistentWebSocketEventsStayFIFOAcrossRootAdmission(t *testing.T) {
	if os.Getenv("SCARDICE_RUNTIME_ROOT") == "" && os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("native QuickJS package is not configured")
	}
	d, loop, loaded := persistentLifecycleFixture(t, "quickjs")
	sendFrames := make(chan struct{})
	var sendOnce sync.Once
	allowFrames := func() { sendOnce.Do(func() { close(sendFrames) }) }
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		<-sendFrames
		for _, message := range []string{"first", "second"} {
			if err := connection.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
				return
			}
		}
		_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"), time.Now().Add(time.Second))
	}))
	t.Cleanup(func() {
		allowFrames()
		server.Close()
	})

	// Only the sink is observed. TCP, upgrade, read loop, service request
	// validation, native provider delivery and JS handlers are all real.
	observed := &observedWebSocketService{nativeWebSocketService: newNativeWebSocketService(d), terminalQueued: make(chan struct{})}
	registry := services.NewRegistry()
	registry.SetPolicyProvider(func(call services.Call) services.Policy {
		return services.Policy{Authorizer: nativeServiceAuthorizer{dice: d, context: jsOpaqueExecutionContext(call.Context)}}
	})
	for _, factory := range nativeServiceFactories {
		service := factory.newService(d, loop)
		if factory.name == services.WebSocket {
			service = observed
		}
		if err := registry.Register(service); err != nil {
			t.Fatal(err)
		}
	}
	if err := nativejs.InstallServiceRegistry(loop, registry); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	store, ok := d.DurableStore.(*eventstore.GORMStore)
	if !ok {
		t.Fatalf("durable store = %T, want real GORM store", d.DurableStore)
	}
	admission := &persistentFirstAdmissionGate{GORMStore: store, entered: make(chan struct{}), release: make(chan struct{})}
	d.DurableStore = admission
	var releaseOnce sync.Once
	releaseOpen := func() { releaseOnce.Do(func() { close(admission.release) }) }
	t.Cleanup(releaseOpen)
	closed := make(chan string, 1)
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		return runtime.Bind("__persistentWebSocketClosed", func(sequence string) { closed <- sequence })
	}); err != nil {
		t.Fatal(err)
	}
	const extensionName = "Persistent WebSocket FIFO"
	script := &JsScriptInfo{Name: extensionName, Enable: true, runtimeGeneration: jsContextGeneration(&jsExecutionContext{Script: loaded})}
	source := fmt.Sprintf(`
var fifoExt = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(fifoExt);
var fifoSequence = [];
var fifoSocket = new WebSocket(%q);
function recordFIFO(value) {
  fifoSequence.push(value);
  fifoExt.storageSet("sequence", fifoSequence.join(","));
}
fifoSocket.onopen = function () { recordFIFO("open"); };
fifoSocket.onmessage = function (event) { recordFIFO("message:" + event.data); };
fifoSocket.onclose = function () {
  recordFIFO("close");
  __persistentWebSocketClosed(fifoSequence.join(","));
};
`, extensionName, "ws"+strings.TrimPrefix(server.URL, "http"))
	if err := d.loadJSScriptInRoot(loop, script, "websocket-fifo.js", []byte(source)); err != nil {
		t.Fatal(err)
	}
	awaitPersistentLifecycle(t, admission.entered, "open event root to reach held repository admission")
	allowFrames()
	awaitPersistentLifecycle(t, observed.terminalQueued, "real WebSocket data and close to enter native sink")

	// Every frame has arrived while open is held in repository admission.
	// Releasing it must preserve the observable WebSocket event order.
	releaseOpen()
	sequence := awaitPersistentLifecycle(t, closed, "ordered WebSocket close handler")
	if sequence != "open,message:first,message:second,close" {
		t.Fatalf("WebSocket event order = %q", sequence)
	}
	waitPluginKV(t, d, extensionName, "sequence", "open,message:first,message:second,close")
	binding := script.currentPersistentBinding()
	binding.retire()
	binding.mu.RLock()
	remaining := len(binding.requests)
	binding.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("terminal WebSocket request pumps = %d, want zero", remaining)
	}
}
