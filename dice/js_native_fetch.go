package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/services"
)

type nativeFetchRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}

type nativeFetchResponse struct {
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
}
type nativeFetchService struct {
	dice      *Dice
	loop      jsengine.Loop
	client    *http.Client
	semaphore chan struct{}

	mu      sync.Mutex
	pending map[services.RequestID]context.CancelFunc
}

func newNativeFetchService(d *Dice, loop jsengine.Loop) *nativeFetchService {
	service := &nativeFetchService{dice: d, loop: loop}
	service.client = &http.Client{
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request == nil || request.URL == nil {
				return errors.New("invalid fetch redirect")
			}
			return jsNetworkAuthorizeWithContext(d, jsOpaqueExecutionContext(request.Context().Value(jsExecutionContextKey{})), request.URL.String())
		},
	}
	if d != nil && d.Config.JsConfig.QuickJSMaxFetchConcurrent != 0 {
		service.semaphore = make(chan struct{}, d.Config.JsConfig.QuickJSMaxFetchConcurrent)
	}
	return service
}

func (s *nativeFetchService) Definition() services.Definition {
	return services.Definition{
		Name:            services.Fetch,
		AsyncOperations: []services.OperationID{services.OpFetchRequest},
	}
}

func decodeNativeFetchRequest(raw string) (nativeFetchRequest, error) {
	var request nativeFetchRequest
	if strings.TrimSpace(raw) == "" {
		return request, errors.New("fetch request metadata is empty")
	}
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		return request, fmt.Errorf("decode fetch request: %w", err)
	}
	request.URL = strings.TrimSpace(request.URL)
	if request.URL == "" {
		return request, errors.New("fetch URL is empty")
	}
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	if request.Method == "" {
		request.Method = http.MethodGet
	}
	return request, nil
}

func (s *nativeFetchService) Invoke(services.Call) (services.Response, error) {
	return services.Response{}, fmt.Errorf("%w: fetch is asynchronous", services.ErrUnsupported)
}

func (s *nativeFetchService) Start(call services.AsyncCall) error {
	if s == nil || s.dice == nil || call.Sink == nil {
		return errors.New("native fetch service is unavailable")
	}
	if call.Call.Request.Operation != services.OpFetchRequest {
		return fmt.Errorf("%w: fetch operation %d", services.ErrUnsupported, call.Call.Request.Operation)
	}
	request, err := decodeNativeFetchRequest(call.Call.Request.String)
	if err != nil {
		return err
	}
	executionContext := jsOpaqueExecutionContext(call.Call.Context)
	if err := jsNetworkAuthorizeWithContext(s.dice, executionContext, request.URL); err != nil {
		return err
	}
	requestContext := context.WithValue(context.Background(), jsExecutionContextKey{}, executionContext)
	var cancel context.CancelFunc
	ctx := requestContext
	if !call.Call.Deadline.IsZero() {
		ctx, cancel = context.WithDeadline(requestContext, call.Call.Deadline)
	} else {
		ctx, cancel = context.WithCancel(requestContext)
	}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[services.RequestID]context.CancelFunc)
	}
	s.pending[call.ID] = cancel
	s.mu.Unlock()
	done := make(chan struct{})
	if call.Call.Cancellation != nil {
		go func() {
			select {
			case <-call.Call.Cancellation:
				cancel()
			case <-done:
			}
		}()
	}
	go func() {
		defer close(done)
		defer cancel()
		defer s.removePending(call.ID)
		response := s.execute(ctx, request, call.Call.Request.Bytes)
		_ = call.Sink.Complete(call.ID, response)
	}()
	return nil
}

func (s *nativeFetchService) removePending(id services.RequestID) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

func (s *nativeFetchService) Cancel(id services.RequestID) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancel := s.pending[id]
	delete(s.pending, id)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (s *nativeFetchService) acquire(ctx context.Context) error {
	if s.semaphore == nil {
		return nil
	}
	select {
	case s.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *nativeFetchService) release() {
	if s.semaphore != nil {
		<-s.semaphore
	}
}

func (s *nativeFetchService) execute(ctx context.Context, request nativeFetchRequest, body []byte) services.Response {
	if err := s.acquire(ctx); err != nil {
		return nativeFetchErrorResponse(ctx, err)
	}
	defer s.release()
	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(body))
	if err != nil {
		return nativeFetchErrorResponse(ctx, err)
	}
	for key, value := range request.Headers {
		httpRequest.Header.Set(key, value)
	}
	response, err := s.client.Do(httpRequest)
	if err != nil {
		return nativeFetchErrorResponse(ctx, err)
	}
	defer response.Body.Close()
	data, err := readNativeFetchBody(response.Body, s.dice.Config.JsConfig.QuickJSMaxFetchResponseMiB)
	if err != nil {
		return nativeFetchErrorResponse(ctx, err)
	}
	headers := make(map[string]string, len(response.Header))
	for key, values := range response.Header {
		headers[key] = strings.Join(values, ", ")
	}
	metadata, err := json.Marshal(nativeFetchResponse{
		Status:     response.StatusCode,
		StatusText: response.Status,
		Headers:    headers,
	})
	if err != nil {
		return nativeFetchErrorResponse(ctx, err)
	}
	return services.Response{Status: services.StatusOK, String: string(metadata), Bytes: data, Int64: int64(response.StatusCode)}
}

func readNativeFetchBody(body io.Reader, limitMiB uint64) ([]byte, error) {
	limit, err := quickJSPolicyMiBBytes(limitMiB)
	if err != nil {
		return nil, err
	}
	if limit == 0 {
		return io.ReadAll(body)
	}
	const maxInt = uint64(^uint(0) >> 1)
	if limit >= maxInt {
		return nil, errors.New("fetch response limit exceeds platform size")
	}
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > limit {
		return nil, fmt.Errorf("fetch response exceeds %d MiB", limit/(1024*1024))
	}
	return data, nil
}

func nativeFetchErrorResponse(ctx context.Context, err error) services.Response {
	status := services.StatusInternal
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		status = services.StatusCancelled
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		status = services.StatusDeadlineExceeded
	}
	return services.Response{Status: status, String: err.Error()}
}
