package dice

import (
	"context"
	"errors"

	"Scardice-core/adapterapi"
)

func (r *onebotRuntime) CallAPI(ctx context.Context, request adapterapi.AdapterCallRequest) (adapterapi.AdapterCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := request.Validate(); err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	if r.fenced.Load() || r.stopReq.Load() {
		return adapterapi.AdapterCallResult{}, ErrOnebotRuntimeStopped
	}
	r.mu.Lock()
	current := r.emitter
	r.mu.Unlock()
	if current == nil {
		return adapterapi.AdapterCallResult{}, errors.New("onebot: protocol connection unavailable")
	}
	raw, err := current.RawJSON(ctx, []byte(request.RawJSON))
	if err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	r.mu.Lock()
	unchanged := r.emitter == current
	r.mu.Unlock()
	if !unchanged || r.fenced.Load() || r.stopReq.Load() {
		return adapterapi.AdapterCallResult{}, errors.New("onebot: protocol connection changed during call")
	}
	result := adapterapi.AdapterCallResult{RawJSON: string(raw)}
	if err := result.Validate(); err != nil {
		return adapterapi.AdapterCallResult{}, err
	}
	return result, nil
}

var _ adapterapi.AdapterCallRuntime = (*onebotRuntime)(nil)
