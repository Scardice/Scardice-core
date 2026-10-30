package dice

import (
	"context"

	"Scardice-core/adapterapi"
)

// CallAPI uses the same owned OneBot transport as durable effects. The outer
// supervisor and the transport retain their generation/connection fences.
func (runtime *builtinProcessRuntime) CallAPI(ctx context.Context, request adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
	if runtime == nil {
		return adapterapi.AdapterCallResult{}, ErrOnebotRuntimeStopped
	}
	runtime.mu.Lock()
	transport := runtime.transport
	runtime.mu.Unlock()
	if transport == nil {
		return adapterapi.AdapterCallResult{}, ErrOnebotRuntimeStopped
	}
	caller, ok := transport.(adapterapi.AdapterCallRuntime)
	if !ok {
		return adapterapi.AdapterCallResult{}, adapterapi.ErrUnsupportedAction
	}
	return caller.CallAPI(ctx, request)
}

var _ adapterapi.AdapterCallRuntime = (*builtinProcessRuntime)(nil)
