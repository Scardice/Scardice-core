package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lifetimeFilesystemService executes real file reads. Its gates control when
// that work and its cancellation finish; terminal delivery still goes through
// the registry's actual AsyncSink wrapper.
type lifetimeFilesystemService struct {
	synchronous   bool
	readGate      <-chan struct{}
	cancelGate    <-chan struct{}
	cancelEntered chan RequestID
	finished      chan RequestID
	startErr      error
	cancelErr     error
	cancelCalls   atomic.Int32

	mu      sync.Mutex
	pending map[RequestID]context.CancelFunc
}

func newLifetimeFilesystemService() *lifetimeFilesystemService {
	return &lifetimeFilesystemService{
		cancelEntered: make(chan RequestID, 128),
		finished:      make(chan RequestID, 4096),
		pending:       make(map[RequestID]context.CancelFunc),
	}
}

func (*lifetimeFilesystemService) Definition() Definition {
	return Definition{Name: Filesystem, AsyncOperations: []OperationID{OpFilesystemReadFile}}
}

func (*lifetimeFilesystemService) Invoke(Call) (Response, error) {
	return Response{Status: StatusUnsupported}, ErrUnsupported
}

func (s *lifetimeFilesystemService) Start(call AsyncCall) error {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.pending[call.ID] = cancel
	s.mu.Unlock()
	read := func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.pending, call.ID)
			s.mu.Unlock()
			s.finished <- call.ID
		}()
		if call.Call.Request.Bool && s.readGate != nil {
			select {
			case <-s.readGate:
			case <-ctx.Done():
				_ = call.Sink.Close(call.ID, Response{Status: StatusCancelled})
				return
			}
		}
		data, err := os.ReadFile(call.Call.Request.String)
		if err != nil {
			_ = call.Sink.Complete(call.ID, Response{Status: StatusInternal, String: err.Error()})
			return
		}
		_ = call.Sink.Complete(call.ID, Response{Status: StatusOK, Bytes: data})
	}
	if s.synchronous {
		read()
	} else {
		go read()
	}
	return s.startErr
}

func (s *lifetimeFilesystemService) Cancel(id RequestID) error {
	s.cancelCalls.Add(1)
	s.cancelEntered <- id
	if s.cancelGate != nil {
		<-s.cancelGate
	}
	s.mu.Lock()
	cancel := s.pending[id]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return s.cancelErr
}

type lifetimeResultSink struct {
	terminal chan Response
	calls    atomic.Int32
	err      error
}

func newLifetimeResultSink() *lifetimeResultSink {
	return &lifetimeResultSink{terminal: make(chan Response, 2)}
}

func (*lifetimeResultSink) Event(RequestID, Response) error { return nil }

func (s *lifetimeResultSink) Complete(_ RequestID, response Response) error {
	s.calls.Add(1)
	s.terminal <- response
	return s.err
}

func (s *lifetimeResultSink) Close(_ RequestID, response Response) error {
	s.calls.Add(1)
	s.terminal <- response
	return s.err
}

func lifetimeReadCall(path string, gated bool) Call {
	return Call{Request: Request{Service: Filesystem, Operation: OpFilesystemReadFile, String: path, Bool: gated}}
}

func lifetimeFixture(t *testing.T, service *lifetimeFilesystemService) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(path, []byte("real request payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if err := registry.Register(service); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return registry, path
}

func awaitLifetimeValue[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("service request did not finish")
		var zero T
		return zero
	}
}

func assertLifetimeActiveRequests(t *testing.T, registry *Registry, want int) {
	t.Helper()
	registry.mu.RLock()
	active := len(registry.requests)
	retained := len(registry.completed)
	order := len(registry.completedOrder)
	registry.mu.RUnlock()
	if active != want {
		t.Fatalf("active requests = %d, want %d; completed operations must release full requests", active, want)
	}
	if retained > 1024 || order > 1024 {
		t.Fatalf("completed evidence retains %d entries and %d order slots, want at most 1024", retained, order)
	}
}

func TestRegistryCompactsActualFilesystemTerminalHistory(t *testing.T) {
	for _, test := range []struct {
		name   string
		status Status
	}{
		{name: "success", status: StatusOK},
		{name: "read failure", status: StatusInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newLifetimeFilesystemService()
			service.synchronous = true
			registry, path := lifetimeFixture(t, service)
			if test.status != StatusOK {
				path += ".missing"
			}
			const requests = 2*1024 + 17
			ids := make([]RequestID, 0, requests)
			for range requests {
				sink := newLifetimeResultSink()
				id, err := registry.StartNative(lifetimeReadCall(path, false), sink)
				if err != nil {
					t.Fatal(err)
				}
				if len(ids) != 0 && id <= ids[len(ids)-1] {
					t.Fatalf("request IDs are not increasing: %d follows %d", id, ids[len(ids)-1])
				}
				ids = append(ids, id)
				if got := awaitLifetimeValue(t, service.finished); got != id {
					t.Fatalf("finished request = %d, want %d", got, id)
				}
				response := awaitLifetimeValue(t, sink.terminal)
				if response.Status != test.status {
					t.Fatalf("terminal status = %v, want %v", response.Status, test.status)
				}
				if test.status == StatusOK && string(response.Bytes) != "real request payload" {
					t.Fatalf("file read = %q", response.Bytes)
				}
			}
			assertLifetimeActiveRequests(t, registry, 0)
			expired := ids[len(ids)-1025]
			if err := registry.Deliver(expired, EventComplete, Response{}); !errors.Is(err, ErrRequestNotFound) {
				t.Fatalf("expired Complete() error = %v, want ErrRequestNotFound", err)
			}
			if err := registry.Cancel(expired); !errors.Is(err, ErrRequestNotFound) {
				t.Fatalf("expired Cancel() error = %v, want ErrRequestNotFound", err)
			}
			for _, id := range ids[len(ids)-1024:] {
				if err := registry.Deliver(id, EventComplete, Response{}); err != nil {
					t.Fatalf("retained duplicate Complete(%d) = %v", id, err)
				}
				if err := registry.Cancel(id); err != nil {
					t.Fatalf("retained Cancel(%d) = %v", id, err)
				}
				var callErr *CallError
				if err := registry.Deliver(id, EventData, Response{}); !errors.As(err, &callErr) || callErr.Status != test.status {
					t.Fatalf("retained late Event(%d) = %v, want status %v", id, err, test.status)
				}
			}
			if service.cancelCalls.Load() != 0 {
				t.Fatal("completed requests were cancelled again")
			}
		})
	}
}

func TestRegistryCompletedEvidenceExpiresByCompletionNotDuplicateAccess(t *testing.T) {
	service := newLifetimeFilesystemService()
	service.synchronous = true
	registry, path := lifetimeFixture(t, service)
	var first RequestID
	for range 1024 {
		id, err := registry.StartNative(lifetimeReadCall(path, false), nil)
		if err != nil {
			t.Fatal(err)
		}
		awaitLifetimeValue(t, service.finished)
		if first == 0 {
			first = id
		}
	}
	for range 8 {
		if err := registry.Deliver(first, EventComplete, Response{}); err != nil {
			t.Fatal(err)
		}
		if err := registry.Cancel(first); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := registry.StartNative(lifetimeReadCall(path, false), nil); err != nil {
		t.Fatal(err)
	}
	awaitLifetimeValue(t, service.finished)
	if err := registry.Deliver(first, EventData, Response{}); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("oldest completed request after window advances = %v, want ErrRequestNotFound", err)
	}
	assertLifetimeActiveRequests(t, registry, 0)
}

func TestRegistryCancelReleasesRequestWhileProviderCancellationIsInFlight(t *testing.T) {
	service := newLifetimeFilesystemService()
	readGate := make(chan struct{})
	cancelGate := make(chan struct{})
	service.readGate = readGate
	service.cancelGate = cancelGate
	registry, path := lifetimeFixture(t, service)
	var releaseCancel sync.Once
	t.Cleanup(func() { releaseCancel.Do(func() { close(cancelGate) }) })
	sink := newLifetimeResultSink()
	id, err := registry.StartNative(lifetimeReadCall(path, true), sink)
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.RLock()
	request := registry.requests[id]
	registry.mu.RUnlock()
	cancelled := make(chan error, 1)
	go func() { cancelled <- registry.Cancel(id) }()
	if got := awaitLifetimeValue(t, service.cancelEntered); got != id {
		t.Fatalf("provider Cancel ID = %d, want %d", got, id)
	}
	assertLifetimeActiveRequests(t, registry, 0)
	request.mu.Lock()
	retainsService := request.service != nil
	retainsRegistry := request.registry != nil
	_, discardedSink := request.sink.(discardAsyncSink)
	request.mu.Unlock()
	if retainsService || retainsRegistry || !discardedSink {
		t.Fatalf("terminal request retains service=%v registry=%v discardedSink=%v", retainsService, retainsRegistry, discardedSink)
	}
	if err := registry.Cancel(id); err != nil {
		t.Fatalf("duplicate Cancel during provider call = %v", err)
	}
	if err := registry.Deliver(id, EventClose, Response{}); err != nil {
		t.Fatalf("duplicate Close during provider call = %v", err)
	}
	if err := registry.Deliver(id, EventComplete, Response{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("late Complete during provider call = %v, want ErrCancelled", err)
	}
	for range 1024 {
		if _, err := registry.StartNative(lifetimeReadCall(path, false), nil); err != nil {
			t.Fatal(err)
		}
		awaitLifetimeValue(t, service.finished)
	}
	if err := registry.Cancel(id); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("expired Cancel during original provider call = %v, want ErrRequestNotFound", err)
	}
	releaseCancel.Do(func() { close(cancelGate) })
	if err := awaitLifetimeValue(t, cancelled); err != nil {
		t.Fatalf("original Cancel() error = %v", err)
	}
	if got := awaitLifetimeValue(t, service.finished); got != id {
		t.Fatalf("cancelled operation finished ID = %d, want %d", got, id)
	}
	if response := awaitLifetimeValue(t, sink.terminal); response.Status != StatusCancelled {
		t.Fatalf("cancel terminal status = %v", response.Status)
	}
	if sink.calls.Load() != 1 || service.cancelCalls.Load() != 1 {
		t.Fatalf("sink terminals=%d provider cancellations=%d, want one each", sink.calls.Load(), service.cancelCalls.Load())
	}
}

func TestRegistryTerminalSinkErrorsStillReleaseRequest(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "complete"
		if cancelled {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			service := newLifetimeFilesystemService()
			gate := make(chan struct{})
			service.readGate = gate
			service.synchronous = !cancelled
			registry, path := lifetimeFixture(t, service)
			sinkErr := errors.New("terminal sink rejected delivery")
			sink := newLifetimeResultSink()
			sink.err = sinkErr
			id, err := registry.StartNative(lifetimeReadCall(path, cancelled), sink)
			if err != nil {
				t.Fatal(err)
			}
			if cancelled {
				if err := registry.Cancel(id); !errors.Is(err, sinkErr) {
					t.Fatalf("Cancel() error = %v, want terminal sink error", err)
				}
			}
			awaitLifetimeValue(t, service.finished)
			awaitLifetimeValue(t, sink.terminal)
			assertLifetimeActiveRequests(t, registry, 0)
			if err := registry.Cancel(id); err != nil {
				t.Fatalf("duplicate Cancel() error = %v", err)
			}
			want := ErrRequestCompleted
			if cancelled {
				want = ErrCancelled
			}
			if err := registry.Deliver(id, EventData, Response{}); !errors.Is(err, want) {
				t.Fatalf("late Event() error = %v, want %v", err, want)
			}
		})
	}
}

func TestRegistryStartFailureRemovesSynchronousCompletionEvidence(t *testing.T) {
	service := newLifetimeFilesystemService()
	service.synchronous = true
	service.startErr = errors.New("provider failed after synchronous completion")
	registry, path := lifetimeFixture(t, service)
	sink := newLifetimeResultSink()
	id, err := registry.StartNative(lifetimeReadCall(path, false), sink)
	if id != 0 || !errors.Is(err, service.startErr) {
		t.Fatalf("StartNative() = (%d, %v), want failed start", id, err)
	}
	completedID := awaitLifetimeValue(t, service.finished)
	if response := awaitLifetimeValue(t, sink.terminal); response.Status != StatusOK {
		t.Fatalf("synchronous read status = %v", response.Status)
	}
	assertLifetimeActiveRequests(t, registry, 0)
	if err := registry.Cancel(completedID); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("Cancel(failed Start ID) = %v, want ErrRequestNotFound", err)
	}
	if err := registry.Deliver(completedID, EventComplete, Response{}); !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("Deliver(failed Start ID) = %v, want ErrRequestNotFound", err)
	}
	service.startErr = nil
	nextID, err := registry.StartNative(lifetimeReadCall(path, false), nil)
	if err != nil || nextID <= completedID {
		t.Fatalf("next StartNative() = (%d, %v), want ID after %d", nextID, err, completedID)
	}
	awaitLifetimeValue(t, service.finished)
}

func TestRegistryCloseRacesActualFilesystemTerminalDelivery(t *testing.T) {
	service := newLifetimeFilesystemService()
	gate := make(chan struct{})
	service.readGate = gate
	registry, path := lifetimeFixture(t, service)
	const requests = 64
	sinks := make([]*lifetimeResultSink, requests)
	for i := range requests {
		sinks[i] = newLifetimeResultSink()
		if _, err := registry.StartNative(lifetimeReadCall(path, true), sinks[i]); err != nil {
			t.Fatal(err)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- registry.Close() }()
	close(gate)
	if err := awaitLifetimeValue(t, closed); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	for range requests {
		awaitLifetimeValue(t, service.finished)
	}
	for _, sink := range sinks {
		response := awaitLifetimeValue(t, sink.terminal)
		if response.Status != StatusOK && response.Status != StatusClosed {
			t.Fatalf("racing terminal status = %v, want success or registry closed", response.Status)
		}
		if sink.calls.Load() != 1 {
			t.Fatalf("racing terminal calls = %d, want one", sink.calls.Load())
		}
	}
	assertLifetimeActiveRequests(t, registry, 0)
	if err := registry.Cancel(1); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("Cancel after Close = %v, want ErrRegistryClosed", err)
	}
}

func TestRegistryRequestIDsNeverWrapToPreviouslyUsedIDs(t *testing.T) {
	service := newLifetimeFilesystemService()
	service.synchronous = true
	registry, path := lifetimeFixture(t, service)
	registry.nextRequest = ^RequestID(0) - 1
	id, err := registry.StartNative(lifetimeReadCall(path, false), nil)
	if err != nil || id != ^RequestID(0) {
		t.Fatalf("last request ID = (%d, %v)", id, err)
	}
	awaitLifetimeValue(t, service.finished)
	if wrapped, err := registry.StartNative(lifetimeReadCall(path, false), nil); err == nil || wrapped != 0 {
		t.Fatalf("exhausted request IDs = (%d, %v), must fail rather than reuse ID 1", wrapped, err)
	}
	assertLifetimeActiveRequests(t, registry, 0)
}

func TestRegistryCompletedEvidencePreservesTerminalClassification(t *testing.T) {
	for _, kind := range []EventKind{EventComplete, EventClose} {
		for _, test := range []struct {
			name   string
			status Status
			cause  error
		}{
			{name: "ok", status: StatusOK, cause: ErrRequestCompleted},
			{name: "cancelled", status: StatusCancelled, cause: ErrCancelled},
			{name: "deadline", status: StatusDeadlineExceeded, cause: ErrDeadlineExceeded},
			{name: "permission", status: StatusPermissionDenied, cause: ErrPermissionDenied},
			{name: "unsupported", status: StatusUnsupported, cause: ErrUnsupported},
			{name: "closed", status: StatusClosed, cause: ErrRegistryClosed},
			{name: "invalid", status: StatusInvalid},
			{name: "internal", status: StatusInternal},
		} {
			name := "complete/"
			if kind == EventClose {
				name = "close/"
			}
			t.Run(name+test.name, func(t *testing.T) {
				service := newLifetimeFilesystemService()
				gate := make(chan struct{})
				service.readGate = gate
				registry, path := lifetimeFixture(t, service)
				var release sync.Once
				t.Cleanup(func() { release.Do(func() { close(gate) }) })
				sink := newLifetimeResultSink()
				id, err := registry.StartNative(lifetimeReadCall(path, true), sink)
				if err != nil {
					t.Fatal(err)
				}
				if err := registry.Deliver(id, kind, Response{Status: test.status}); err != nil {
					t.Fatal(err)
				}
				assertLifetimeActiveRequests(t, registry, 0)
				if err := registry.Deliver(id, kind, Response{}); err != nil {
					t.Fatalf("same terminal kind = %v, want idempotent success", err)
				}
				if err := registry.Cancel(id); err != nil {
					t.Fatalf("Cancel completed request = %v", err)
				}
				otherKind := EventClose
				if kind == EventClose {
					otherKind = EventComplete
				}
				for _, lateKind := range []EventKind{EventData, otherKind} {
					err := registry.Deliver(id, lateKind, Response{})
					var callErr *CallError
					if !errors.As(err, &callErr) || callErr.Status != test.status || callErr.Service != Filesystem || callErr.Operation != OpFilesystemReadFile {
						t.Fatalf("late kind %d = %v, want original status and operation", lateKind, err)
					}
					if test.cause != nil && !errors.Is(err, test.cause) {
						t.Fatalf("late kind %d cause = %v, want %v", lateKind, err, test.cause)
					}
				}
				if err := registry.Deliver(id, EventKind(99), Response{}); !errors.Is(err, ErrInvalidService) {
					t.Fatalf("invalid late kind = %v, want ErrInvalidService", err)
				}
				release.Do(func() { close(gate) })
				awaitLifetimeValue(t, service.finished)
				awaitLifetimeValue(t, sink.terminal)
				if sink.calls.Load() != 1 {
					t.Fatalf("terminal callbacks = %d, want one", sink.calls.Load())
				}
			})
		}
	}
}

func TestRegistryCancelProviderErrorDoesNotRetainTerminalRequest(t *testing.T) {
	service := newLifetimeFilesystemService()
	service.readGate = make(chan struct{})
	service.cancelErr = errors.New("provider cancellation failed")
	registry, path := lifetimeFixture(t, service)
	sink := newLifetimeResultSink()
	id, err := registry.StartNative(lifetimeReadCall(path, true), sink)
	if err != nil {
		t.Fatal(err)
	}
	var callErr *CallError
	if err := registry.Cancel(id); !errors.As(err, &callErr) || callErr.Status != StatusInternal || !errors.Is(err, service.cancelErr) {
		t.Fatalf("provider cancellation error = %v, want wrapped provider error", err)
	}
	awaitLifetimeValue(t, service.finished)
	awaitLifetimeValue(t, sink.terminal)
	assertLifetimeActiveRequests(t, registry, 0)
	if err := registry.Cancel(id); err != nil {
		t.Fatalf("duplicate failed Cancel = %v, want nil", err)
	}
	if err := registry.Deliver(id, EventData, Response{}); !errors.Is(err, ErrCancelled) {
		t.Fatalf("late Event after provider cancellation error = %v, want ErrCancelled", err)
	}
}
