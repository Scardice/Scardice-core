package endpoint

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
)

type protocolCallDescriptor struct {
	*fakeDescriptor
	call func(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error)
}

type protocolCallRuntime struct {
	adapterapi.AdapterRuntime
	call func(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error)
}

func (d protocolCallDescriptor) NewRuntime(init adapterapi.RuntimeInit) (adapterapi.AdapterRuntime, error) {
	runtime, err := d.fakeDescriptor.NewRuntime(init)
	if err != nil {
		return nil, err
	}
	return protocolCallRuntime{runtime, d.call}, nil
}

func (r protocolCallRuntime) CallAPI(ctx context.Context, request adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
	return r.call(ctx, request)
}

func TestSupervisorAdapterCallRejectsRequestsBeforeProviderIO(t *testing.T) {
	id := adapterapi.EndpointID("protocol-admission")
	inner := &fakeDescriptor{key: "fake"}
	descriptor := protocolCallDescriptor{fakeDescriptor: inner, call: func(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
		t.Error("refused request reached the provider")
		return adapterapi.AdapterCallResult{}, nil
	}}
	sup := startQueryWorker(t, descriptor, func() *fakeRuntime { return inner.Runtime(0) }, id)
	t.Cleanup(func() { inner.Runtime(0).allowStopNow(); _ = sup.Stop(context.Background(), id) })
	for _, test := range []struct {
		request adapterapi.AdapterCallRequest
		want    error
	}{
		{adapterapi.AdapterCallRequest{EndpointID: id, RawJSON: `[]`}, adapterapi.ErrInvalidContract},
		{adapterapi.AdapterCallRequest{EndpointID: id, Generation: 9, RawJSON: `{"action":"send"}`}, ErrSupervisorAmbiguous},
		{adapterapi.AdapterCallRequest{EndpointID: "absent", RawJSON: `{"action":"send"}`}, ErrSupervisorClosed},
	} {
		if _, err := sup.CallAPI(t.Context(), test.request); !errors.Is(err, test.want) {
			t.Fatalf("CallAPI(%#v) error = %v, want %v", test.request, err, test.want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := sup.CallAPI(ctx, adapterapi.AdapterCallRequest{EndpointID: id, RawJSON: `{"action":"send"}`}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request error = %v", err)
	}
}

func TestSupervisorAdapterCallDiscardsSuccessAfterCallerCancellation(t *testing.T) {
	id := adapterapi.EndpointID("protocol-late-success")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	inner := &fakeDescriptor{key: "fake"}
	descriptor := protocolCallDescriptor{fakeDescriptor: inner, call: func(context.Context, adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
		cancel()
		return adapterapi.AdapterCallResult{RawJSON: `{"status":"ok"}`}, nil
	}}
	sup := startQueryWorker(t, descriptor, func() *fakeRuntime { return inner.Runtime(0) }, id)
	t.Cleanup(func() { inner.Runtime(0).allowStopNow(); _ = sup.Stop(context.Background(), id) })
	result, err := sup.CallAPI(ctx, adapterapi.AdapterCallRequest{EndpointID: id, RawJSON: `{"action":"send"}`})
	if !errors.Is(err, context.Canceled) || result.RawJSON != "" {
		t.Fatalf("late success escaped cancellation: %#v, %v", result, err)
	}
}
