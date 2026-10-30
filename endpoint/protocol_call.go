package endpoint

import (
	"context"
	"fmt"

	"Scardice-core/adapterapi"
)

// CallAPI pins an immediate native protocol request to one active runtime.
// Unlike Query it may mutate provider state; unlike ExecutePinned it is not an
// outbox operation and must never be retried by the supervisor.
func (s *Supervisor) CallAPI(ctx context.Context, request adapterapi.AdapterCallRequest) (result adapterapi.AdapterCallResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = request.Validate(); err != nil {
		return result, err
	}
	if s == nil {
		return result, ErrSupervisorClosed
	}
	s.mu.Lock()
	worker := s.active[request.EndpointID]
	if worker == nil || !beginWorkerCallback(worker) {
		s.mu.Unlock()
		return result, ErrSupervisorClosed
	}
	s.mu.Unlock()
	defer endWorkerCallback(worker)
	worker.mu.Lock()
	valid := (request.Generation == 0 || request.Generation == worker.generation) && !worker.exited && !worker.stopping && !worker.ambiguous
	request.Generation = worker.generation
	runtime := worker.runtime
	worker.mu.Unlock()
	if !valid || runtime == nil {
		return result, ErrSupervisorAmbiguous
	}
	caller, ok := runtime.(adapterapi.AdapterCallRuntime)
	if !ok {
		return result, adapterapi.ErrUnsupportedAction
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result = adapterapi.AdapterCallResult{}
			err = fmt.Errorf("endpoint supervisor: protocol call panic: %v", recovered)
		}
	}()
	if err = ctx.Err(); err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	result, err = caller.CallAPI(ctx, request)
	if err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	if err = ctx.Err(); err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	s.mu.Lock()
	current := s.active[request.EndpointID] == worker
	s.mu.Unlock()
	worker.mu.Lock()
	valid = current && !worker.exited && !worker.stopping && !worker.ambiguous
	worker.mu.Unlock()
	if !valid {
		return adapterapi.AdapterCallResult{}, ErrSupervisorAmbiguous
	}
	if err = result.Validate(); err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	return result, nil
}
