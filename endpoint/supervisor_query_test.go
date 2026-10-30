package endpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

// querylessDescriptor hands out runtimes that expose only the mandatory
// AdapterRuntime surface, like a provider that has not adopted queries.
type querylessDescriptor struct{ *fakeDescriptor }

type querylessRuntime struct{ adapterapi.AdapterRuntime }

func (d querylessDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	runtime, err := d.fakeDescriptor.NewRuntime(init)
	if err != nil {
		return nil, err
	}
	return querylessRuntime{runtime}, nil
}

func startQueryWorker(t *testing.T, descriptor adapterapi.Descriptor, fake func() *fakeRuntime, id adapterapi.EndpointID) *Supervisor {
	t.Helper()
	key := descriptor.Key()
	sup := NewSupervisor(fakeDescriptorRegistry{key: descriptor}, WithLifecycleSink(&fakeLifecycleSink{}), WithStopTimeout(time.Second))
	state := validFakeState(t, id, key, DesiredStateEnabled, 1, 2)
	if err := sup.Reconcile(context.Background(), state, fakeEffect(id, EffectStart, 1, 2, DesiredStateEnabled)); err != nil {
		t.Fatal(err)
	}
	if runtime := fake(); runtime != nil {
		runtime.allowStart()
	}
	return sup
}

func memberRole(id adapterapi.EndpointID) adapterapi.QueryRequest {
	return adapterapi.QueryRequest{EndpointID: id, Kind: adapterapi.QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003", Fresh: true}
}

func TestSupervisorQueryReachesTheActiveGenerationAndReturnsAValidatedAnswer(t *testing.T) {
	id := adapterapi.EndpointID("sup-query")
	descriptor := &fakeDescriptor{key: "fake"}
	sup := startQueryWorker(t, descriptor, func() *fakeRuntime { return descriptor.Runtime(0) }, id)
	seen := make(chan adapterapi.QueryRequest, 1)
	descriptor.Runtime(0).queryFn = func(_ context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
		seen <- request
		return adapterapi.QueryResult{Role: "admin"}, nil
	}

	result, err := sup.Query(context.Background(), memberRole(id))
	if err != nil || result.Role != "admin" {
		t.Fatalf("Query = %#v, %v", result, err)
	}
	got := <-seen
	if got.Generation != 1 || got.Group != "QQ-Group:2002" || got.Member != "QQ:3003" || !got.Fresh {
		t.Fatalf("runtime saw %#v; a zero generation must be pinned to the active one", got)
	}
}

func TestSupervisorQueryRejectsWhatItMustNotForward(t *testing.T) {
	id := adapterapi.EndpointID("sup-query-reject")
	descriptor := &fakeDescriptor{key: "fake"}
	sup := startQueryWorker(t, descriptor, func() *fakeRuntime { return descriptor.Runtime(0) }, id)
	runtime := descriptor.Runtime(0)
	called := false
	runtime.queryFn = func(context.Context, adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
		called = true
		return adapterapi.QueryResult{Role: "admin"}, nil
	}

	if _, err := sup.Query(context.Background(), adapterapi.QueryRequest{EndpointID: id, Kind: adapterapi.QueryKindMemberRole}); !errors.Is(err, adapterapi.ErrInvalidContract) {
		t.Fatalf("malformed query err = %v", err)
	}
	stale := memberRole(id)
	stale.Generation = 9
	if _, err := sup.Query(context.Background(), stale); !errors.Is(err, ErrSupervisorAmbiguous) {
		t.Fatalf("stale generation err = %v", err)
	}
	if _, err := sup.Query(context.Background(), memberRole("never-started")); !errors.Is(err, ErrSupervisorClosed) {
		t.Fatalf("unknown endpoint err = %v", err)
	}
	if called {
		t.Fatal("a rejected query reached the runtime")
	}
}

func TestSupervisorQueryHandlesRuntimesThatMisbehave(t *testing.T) {
	id := adapterapi.EndpointID("sup-query-misbehave")
	descriptor := &fakeDescriptor{key: "fake"}
	sup := startQueryWorker(t, descriptor, func() *fakeRuntime { return descriptor.Runtime(0) }, id)
	runtime := descriptor.Runtime(0)

	runtime.queryFn = func(context.Context, adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
		return adapterapi.QueryResult{Role: "supreme-leader"}, nil
	}
	if _, err := sup.Query(context.Background(), memberRole(id)); !errors.Is(err, adapterapi.ErrInvalidContract) {
		t.Fatalf("an answer outside the role vocabulary must be rejected, got %v", err)
	}

	runtime.queryFn = func(context.Context, adapterapi.QueryRequest) (adapterapi.QueryResult, error) { panic("boom") }
	if _, err := sup.Query(context.Background(), memberRole(id)); err == nil {
		t.Fatal("a panicking runtime must surface as an error")
	}

	runtime.queryFn = func(ctx context.Context, _ adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
		<-ctx.Done()
		return adapterapi.QueryResult{}, ctx.Err()
	}
	deadline, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := sup.Query(deadline, memberRole(id)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a slow provider must be bounded by the caller's deadline, got %v", err)
	}
}

func TestSupervisorQueryReportsRuntimesWithoutQuerySupport(t *testing.T) {
	id := adapterapi.EndpointID("sup-query-unsupported")
	inner := &fakeDescriptor{key: "fake"}
	sup := startQueryWorker(t, querylessDescriptor{inner}, func() *fakeRuntime { return inner.Runtime(0) }, id)
	if _, err := sup.Query(context.Background(), memberRole(id)); !errors.Is(err, adapterapi.ErrUnsupportedAction) {
		t.Fatalf("err = %v, want unsupported", err)
	}
}

func TestSupervisorQueryIsRefusedOnceTheEndpointIsStopping(t *testing.T) {
	id := adapterapi.EndpointID("sup-query-stopped")
	descriptor := &fakeDescriptor{key: "fake"}
	sup := startQueryWorker(t, descriptor, func() *fakeRuntime { return descriptor.Runtime(0) }, id)
	runtime := descriptor.Runtime(0)
	runtime.queryFn = func(context.Context, adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
		return adapterapi.QueryResult{Role: "owner"}, nil
	}
	runtime.allowStopNow()
	if err := sup.Stop(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := sup.Query(context.Background(), memberRole(id)); err == nil {
		t.Fatal("a stopped endpoint answered a query")
	}
}
