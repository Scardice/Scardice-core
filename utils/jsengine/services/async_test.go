package services_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"Scardice-core/utils/jsengine/services"
)

const asyncTestServiceName services.Name = "async-test"

const asyncTestOperation services.OperationID = 1

type asyncTestService struct {
	definition   services.Definition
	started      chan services.AsyncCall
	cancelled    chan services.RequestID
	startGate    <-chan struct{}
	startEntered chan<- struct{}
}

func newAsyncTestService() *asyncTestService {
	return &asyncTestService{
		definition: services.Definition{
			Name:            asyncTestServiceName,
			Operations:      []services.OperationID{services.OperationID(2)},
			AsyncOperations: []services.OperationID{asyncTestOperation},
		},
		started:   make(chan services.AsyncCall, 4),
		cancelled: make(chan services.RequestID, 4),
	}
}

func (s *asyncTestService) Definition() services.Definition { return s.definition }
func (s *asyncTestService) Invoke(services.Call) (services.Response, error) {
	return services.Response{Status: services.StatusUnsupported}, services.ErrUnsupported
}
func (s *asyncTestService) Start(call services.AsyncCall) error {
	if s.startEntered != nil {
		s.startEntered <- struct{}{}
	}
	if s.startGate != nil {
		<-s.startGate
	}
	s.started <- call
	return nil
}
func (s *asyncTestService) Cancel(id services.RequestID) error {
	s.cancelled <- id
	return nil
}

type recordedEvent struct {
	kind     string
	response services.Response
}

type recordingSink struct {
	mu     sync.Mutex
	events []recordedEvent
}

func (s *recordingSink) Event(_ services.RequestID, response services.Response) error {
	s.record("event", response)
	return nil
}
func (s *recordingSink) Complete(_ services.RequestID, response services.Response) error {
	s.record("complete", response)
	return nil
}
func (s *recordingSink) Close(_ services.RequestID, response services.Response) error {
	s.record("close", response)
	return nil
}
func (s *recordingSink) record(kind string, response services.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	response.Bytes = append([]byte(nil), response.Bytes...)
	s.events = append(s.events, recordedEvent{kind: kind, response: response})
}
func (s *recordingSink) snapshot() []recordedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedEvent, len(s.events))
	copy(out, s.events)
	return out
}

func TestRegistryStartsAsyncServiceAndCopiesRequestBytes(t *testing.T) {
	registry := services.NewRegistry()
	service := newAsyncTestService()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	sink := new(recordingSink)
	requestBytes := []byte("before")
	id, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: asyncTestOperation,
		Bytes:     requestBytes,
	}}, sink)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if id == 0 {
		t.Fatal("Start() returned zero request ID")
	}
	call := <-service.started
	requestBytes[0] = 'a'
	if err := call.Sink.Event(id, services.Response{Bytes: call.Call.Request.Bytes}); err != nil {
		t.Fatalf("Event() error = %v", err)
	}
	if err := call.Sink.Complete(id, services.Response{Status: services.StatusOK}); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if err := call.Sink.Complete(id, services.Response{Status: services.StatusOK}); err != nil {
		t.Fatalf("idempotent Complete() error = %v", err)
	}
	events := sink.snapshot()
	if len(events) != 2 || events[0].kind != "event" || events[1].kind != "complete" {
		t.Fatalf("events = %#v, want event then complete", events)
	}
	if string(events[0].response.Bytes) != "before" {
		t.Fatalf("event bytes = %q, want copied request bytes", events[0].response.Bytes)
	}
	if err := registry.Deliver(id, services.EventData, services.Response{}); !errors.Is(err, services.ErrRequestCompleted) {
		t.Fatalf("late Event() error = %v, want ErrRequestCompleted", err)
	}
}

func TestRegistryDeliversEventsByRequestID(t *testing.T) {
	registry := services.NewRegistry()
	service := newAsyncTestService()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	sink := new(recordingSink)
	id, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: asyncTestOperation,
	}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Deliver(id, services.EventData, services.Response{String: "chunk"}); err != nil {
		t.Fatalf("Deliver(data) error = %v", err)
	}
	if err := registry.Deliver(id, services.EventComplete, services.Response{Status: services.StatusOK}); err != nil {
		t.Fatalf("Deliver(complete) error = %v", err)
	}
	events := sink.snapshot()
	if len(events) != 2 || events[0].kind != "event" || events[1].kind != "complete" {
		t.Fatalf("events = %#v, want event then complete", events)
	}
}

func TestRegistryCancellationClosesAsyncRequestAndRejectsLateEvents(t *testing.T) {
	registry := services.NewRegistry()
	service := newAsyncTestService()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	sink := new(recordingSink)
	id, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: asyncTestOperation,
	}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Cancel(id); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if got := <-service.cancelled; got != id {
		t.Fatalf("Cancel() sent ID %d, want %d", got, id)
	}
	if err := registry.Cancel(id); err != nil {
		t.Fatalf("idempotent Cancel() error = %v", err)
	}
	events := sink.snapshot()
	if len(events) != 1 || events[0].kind != "close" || events[0].response.Status != services.StatusCancelled {
		t.Fatalf("events = %#v, want cancelled close", events)
	}
	if err := registry.Deliver(id, services.EventData, services.Response{}); !errors.Is(err, services.ErrCancelled) {
		t.Fatalf("late event error = %v, want ErrCancelled", err)
	}
}

func TestRegistryRejectsAsyncStartPreconditions(t *testing.T) {
	registry := services.NewRegistry()
	service := newAsyncTestService()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Start(services.Call{Request: services.Request{
		Service:   "missing",
		Operation: asyncTestOperation,
	}}, new(recordingSink)); !errors.Is(err, services.ErrServiceNotFound) {
		t.Fatalf("unknown service error = %v", err)
	}
	if _, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: services.OperationID(2),
	}}, new(recordingSink)); !errors.Is(err, services.ErrUnsupported) {
		t.Fatalf("sync-only operation error = %v, want ErrUnsupported", err)
	}
	deadline := time.Now().Add(-time.Second)
	if _, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: asyncTestOperation,
	}, Deadline: deadline}, new(recordingSink)); !errors.Is(err, services.ErrDeadlineExceeded) {
		t.Fatalf("expired deadline error = %v", err)
	}
	cancel := make(chan struct{})
	close(cancel)
	if _, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: asyncTestOperation,
	}, Cancellation: cancel}, new(recordingSink)); !errors.Is(err, services.ErrCancelled) {
		t.Fatalf("pre-cancelled error = %v", err)
	}
}

func TestRegistryClosesPendingAsyncRequests(t *testing.T) {
	registry := services.NewRegistry()
	service := newAsyncTestService()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	sink := new(recordingSink)
	id, err := registry.Start(services.Call{Request: services.Request{
		Service:   asyncTestServiceName,
		Operation: asyncTestOperation,
	}}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := <-service.cancelled; got != id {
		t.Fatalf("Close() sent ID %d, want %d", got, id)
	}
	events := sink.snapshot()
	if len(events) != 1 || events[0].kind != "close" || events[0].response.Status != services.StatusClosed {
		t.Fatalf("events = %#v, want closed request", events)
	}
	if err := registry.Deliver(id, services.EventData, services.Response{}); !errors.Is(err, services.ErrRegistryClosed) {
		t.Fatalf("late event after registry close = %v, want ErrRegistryClosed", err)
	}
}

func TestDefinitionRejectsDuplicateSyncAndAsyncOperations(t *testing.T) {
	registry := services.NewRegistry()
	service := &asyncTestService{definition: services.Definition{
		Name:            asyncTestServiceName,
		Operations:      []services.OperationID{asyncTestOperation},
		AsyncOperations: []services.OperationID{asyncTestOperation},
	}}
	if err := registry.Register(service); !errors.Is(err, services.ErrInvalidService) {
		t.Fatalf("Register(duplicate operation) error = %v, want ErrInvalidService", err)
	}
}

type denyingAuthorizer struct{}

func (denyingAuthorizer) Authorize(services.Name, services.OperationID, string) error {
	return errors.New("denied")
}

func TestRegistryNativeStartAppliesPolicy(t *testing.T) {
	registry := services.NewRegistry()
	service := &asyncTestService{
		definition: services.Definition{
			Name:            services.Filesystem,
			AsyncOperations: []services.OperationID{services.OpFilesystemReadFile},
		},
		started:   make(chan services.AsyncCall, 1),
		cancelled: make(chan services.RequestID, 1),
	}
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	call := services.Call{
		Request: services.Request{
			Service:   services.Filesystem,
			Operation: services.OpFilesystemReadFile,
			String:    "data://fixture.txt",
		},
		Policy: services.Policy{Authorizer: denyingAuthorizer{}},
	}
	if _, err := registry.Start(call, new(recordingSink)); !errors.Is(err, services.ErrPermissionDenied) {
		t.Fatalf("Start() error = %v, want permission denial", err)
	}
	if _, err := registry.StartNative(call, new(recordingSink)); !errors.Is(err, services.ErrPermissionDenied) {
		t.Fatalf("StartNative() error = %v, want permission denial", err)
	}
}

type targetRecordingAuthorizer struct{ target string }

func (a *targetRecordingAuthorizer) Authorize(_ services.Name, _ services.OperationID, target string) error {
	a.target = target
	return nil
}

func TestRegistryUsesStructuredRequestTargetForPolicy(t *testing.T) {
	registry := services.NewRegistry()
	service := newAsyncTestService()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	authorizer := new(targetRecordingAuthorizer)
	_, err := registry.Start(services.Call{
		Request: services.Request{Service: asyncTestServiceName, Operation: asyncTestOperation, String: `{"url":"https://example.test"}`, Target: "https://example.test"},
		Policy:  services.Policy{Authorizer: authorizer},
	}, new(recordingSink))
	if err != nil {
		t.Fatal(err)
	}
	if authorizer.target != "https://example.test" {
		t.Fatalf("policy target = %q, want URL", authorizer.target)
	}
}
func TestRegistryCloseWaitsForAsyncStart(t *testing.T) {
	registry := services.NewRegistry()
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	service := newAsyncTestService()
	service.startGate = gate
	service.startEntered = entered
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() {
		_, err := registry.Start(services.Call{Request: services.Request{Service: asyncTestServiceName, Operation: asyncTestOperation}}, new(recordingSink))
		started <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- registry.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close completed before Start: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(gate)
	if err := <-started; err != nil {
		t.Fatalf("Start error = %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close error = %v", err)
	}
}
