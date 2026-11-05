package dice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine/services"
)

// Every held operation delegates to the actual SQLite repository after release.
// Cancellation must reach it before shutdown can report the task as drained.
type finalTaskRepositoryGate struct {
	*eventstore.GORMStore
	phase   string
	entered chan context.Context
	release chan struct{}
	once    sync.Once
}

func (s *finalTaskRepositoryGate) hold(ctx context.Context) {
	s.entered <- ctx
	<-s.release
}

func (s *finalTaskRepositoryGate) open() { s.once.Do(func() { close(s.release) }) }

func (s *finalTaskRepositoryGate) ExecutionRequestDigest(ctx context.Context, canonical []byte) ([]byte, error) {
	if s.phase == "digest" && bytes.HasPrefix(canonical, []byte("js-task\x00")) {
		s.hold(ctx)
	}
	return s.GORMStore.ExecutionRequestDigest(ctx, canonical)
}

func (s *finalTaskRepositoryGate) AdmitExecution(ctx context.Context, request eventstore.ExecutionAdmissionRequest) (eventstore.ExecutionReceipt, error) {
	if s.phase == "admission" {
		s.hold(ctx)
	}
	return s.GORMStore.AdmitExecution(ctx, request)
}

func (s *finalTaskRepositoryGate) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if s.phase == "commit" && work.Execution != nil {
		s.hold(ctx)
	}
	return s.GORMStore.Commit(ctx, work)
}

func TestJSScheduledTaskShutdownCancelsAndJoinsRepository(t *testing.T) {
	forEachHostIORuntime(t, func(t *testing.T, runtimeID string) {
		for _, phase := range []string{"digest", "admission", "commit"} {
			t.Run(phase, func(t *testing.T) {
				// A broken shutdown must fail this one child, not hang integration
				// or the runtime fixture's cleanup while joining an admitted task.
				const childEnvironment = "SCARDICE_TEST_FINAL_TASK_REPOSITORY_CHILD"
				childKey := runtimeID + "/" + phase
				if os.Getenv(childEnvironment) != childKey {
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					childContext, cancelChild := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancelChild()
					command := exec.CommandContext(childContext, executable,
						"-test.run=^TestJSScheduledTaskShutdownCancelsAndJoinsRepository$/^"+regexp.QuoteMeta(runtimeID)+"$/^"+phase+"$",
						"-test.timeout=12s")
					command.Env = append(os.Environ(), childEnvironment+"="+childKey)
					output, err := command.CombinedOutput()
					if err != nil {
						t.Fatalf("task %s cancellation/join failed in isolated runtime: %v\n%s", childKey, err, output)
					}
					return
				}

				extensionName := "Final task repository " + childKey
				source := fmt.Sprintf(`// ==UserScript==
// @runtime %s:Scardice
// ==/UserScript==
var ext = seal.ext.new(%q, "test", "1.0.0");
seal.ext.register(ext);
seal.ext.registerTask(ext, "once", "3600000", function () {
  ext.storageSet("cancelled-task", "must-not-commit");
}, "", "", "");
`, runtimeID, extensionName)
				d, _, _, _, _ := preparePublicPreprocessRuntime(t, runtimeID, "", extensionName, source)
				extension, ok := d.JsExtRegistry.Load(extensionName)
				if !ok || extension == nil || len(extension.taskList) != 1 {
					t.Fatal("actual script did not register its once task")
				}
				store, ok := d.DurableStore.(*eventstore.GORMStore)
				if !ok {
					t.Fatalf("durable store = %T, want actual SQLite store", d.DurableStore)
				}
				gate := &finalTaskRepositoryGate{
					GORMStore: store, phase: phase, entered: make(chan context.Context, 1), release: make(chan struct{}),
				}
				d.DurableStore = gate
				t.Cleanup(gate.open)
				taskDone := make(chan struct{})
				go func() {
					extension.taskList[0].run()
					close(taskDone)
				}()
				repositoryContext := awaitPersistentLifecycle(t, gate.entered, "task's actual repository "+phase)
				if deadline, bounded := repositoryContext.Deadline(); !bounded || time.Until(deadline) > jsSolveAwaitTimeout+time.Second {
					t.Errorf("task repository %s has no existing invocation deadline: deadline=%v bounded=%t", phase, deadline, bounded)
				}
				stopped := make(chan error, 1)
				go func() { stopped <- d.StopJSRuntime(context.Background()) }()
				cancelled := false
				select {
				case <-repositoryContext.Done():
					cancelled = true
				case err := <-stopped:
					t.Errorf("shutdown returned before cancelling held task repository %s: %v", phase, err)
				case <-time.After(2 * time.Second):
					t.Errorf("shutdown did not cancel held task repository %s", phase)
				}
				if cancelled {
					select {
					case err := <-stopped:
						t.Errorf("shutdown reported quiescence before held repository %s returned: %v", phase, err)
					default:
					}
				}
				gate.open()
				awaitPersistentLifecycle(t, taskDone, "cancelled task repository call to return")
				if err := d.StopJSRuntime(t.Context()); err != nil {
					t.Fatalf("shutdown did not join the released task: %v", err)
				}
				if _, err := store.GetPluginKV(context.Background(), extensionName, "cancelled-task"); !errors.Is(err, eventstore.ErrPluginKVNotFound) {
					t.Fatalf("cancelled task committed its SQLite mutation: %v", err)
				}
			})
		}
	})
}

type finalRegistryWebSocketService struct {
	*nativeWebSocketService
	terminalReturned chan struct{}
}

func (s *finalRegistryWebSocketService) Start(call services.AsyncCall) error {
	call.Sink = finalRegistryWebSocketSink{AsyncSink: call.Sink, terminalReturned: s.terminalReturned}
	return s.nativeWebSocketService.Start(call)
}

type finalRegistryWebSocketSink struct {
	services.AsyncSink
	terminalReturned chan struct{}
}

func (s finalRegistryWebSocketSink) Close(id services.RequestID, response services.Response) error {
	err := s.AsyncSink.Close(id, response)
	close(s.terminalReturned)
	return err
}

func TestNativeWebSocketFailedRootBeforePublishRetiresRegistryRequest(t *testing.T) {
	d, _, script := persistentLifecycleFixture(t, "goja")
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

	service := &finalRegistryWebSocketService{
		nativeWebSocketService: newNativeWebSocketService(d), terminalReturned: make(chan struct{}),
	}
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
	registry := services.NewRegistry()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	realm := jsContextForRoot(t.Context(), d, nil, script, nil, false)
	realm.PersistentAsync = true
	failRoot := make(chan struct{})
	requestStarted := make(chan services.RequestID, 1)
	rootDone := make(chan error, 1)
	sink := &nativeWebSocketTestSink{events: make(chan nativeWebSocketTestEvent, 8)}
	rootFailure := errors.New("promoted root failed after successful WebSocket handshake")
	go func() {
		rootDone <- runJSExecutionRoot(realm, func() error {
			id, err := registry.StartNative(services.Call{
				Context: realm,
				Request: services.Request{
					Service: services.WebSocket, Operation: services.OpWebSocketConnect,
					String: "ws" + strings.TrimPrefix(server.URL, "http"),
				},
			}, sink)
			if err != nil {
				return err
			}
			requestStarted <- id
			<-failRoot
			return rootFailure
		})
	}()
	id := awaitPersistentLifecycle(t, requestStarted, "actual registry WebSocket request")
	gate := awaitPersistentLifecycle(t, connected, "real WebSocket TCP connection")
	var releaseOnce, failOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.resume) }) }
	fail := func() { failOnce.Do(func() { close(failRoot) }) }
	t.Cleanup(func() {
		fail()
		release()
		_ = gate.Close()
	})
	awaitPersistentLifecycle(t, gate.handshake, "successful handshake before DialContext publishes")
	service.mu.Lock()
	state := service.connections[id]
	service.mu.Unlock()
	if state == nil {
		t.Fatal("registry request did not own its connecting socket")
	}
	fail()
	if err := awaitPersistentLifecycle(t, rootDone, "failed promoted root"); !errors.Is(err, rootFailure) {
		t.Fatalf("root failure = %v", err)
	}
	awaitPersistentLifecycle(t, state.done, "AsyncWorkContext cancellation to seal the unpublished socket")
	release()
	awaitPersistentLifecycle(t, gate.closed, "unpublished successful connection to close")
	awaitPersistentLifecycle(t, serverClosed, "unpublished peer socket to close")
	select {
	case <-service.terminalReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("closed unpublished socket retained its active Registry request; no terminal sink delivery")
	}
	if active := reflect.ValueOf(registry).Elem().FieldByName("requests").Len(); active != 0 {
		t.Fatalf("Registry retains %d full active requests after discarded dial", active)
	}
	if err := registry.Deliver(id, services.EventData, services.Response{Status: services.StatusOK}); !errors.Is(err, services.ErrCancelled) {
		t.Fatalf("discarded dial terminal evidence = %v, want cancellation", err)
	}
	event := waitNativeWebSocketTestEvent(t, sink.events)
	if event.kind != services.EventClose || event.response.Status != services.StatusCancelled {
		t.Fatalf("discarded dial published %#v, want only terminal cancellation", event)
	}
	select {
	case event := <-sink.events:
		t.Fatalf("discarded dial published an extra Open/Data/terminal event: %#v", event)
	default:
	}
}
