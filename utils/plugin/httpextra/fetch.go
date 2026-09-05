package sealhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
)

type fetchRequestData struct {
	url     string
	method  string
	headers *headersData
	body    []byte
	ctx     context.Context
	cancel  context.CancelFunc
	abort   *fetchAbortState
}

type fetchAbortState struct {
	mu     sync.Mutex
	reason goja.Value
}

// FetchLifecycle tracks adapter-owned requests so runtime shutdown can cancel
// them before the event loop is released. It never starts a goroutine.
type FetchLifecycle struct {
	mu     sync.Mutex
	active map[*fetchRequestData]struct{}
	closed bool
}

// AsyncContextHooks let the owning adapter restore an opaque execution
// context before a fetch completion resolves its Promise.
//
// ScheduleOnLoop MUST NOT wait for the callback: it runs on the JS owner
// thread, which may already be executing the goroutine's own caller. Its error
// reports only whether the callback was accepted.
type AsyncContextHooks struct {
	CurrentContext func() any
	ScheduleOnLoop func(any, func(*goja.Runtime) error) error
}

func NewFetchLifecycle() *FetchLifecycle {
	return &FetchLifecycle{active: make(map[*fetchRequestData]struct{})}
}

func (l *FetchLifecycle) Start(request *fetchRequestData) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("fetch lifecycle is closed")
	}
	l.active[request] = struct{}{}
	return nil
}

func (l *FetchLifecycle) Done(request *fetchRequestData) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.active, request)
	l.mu.Unlock()
}

func (l *FetchLifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	active := make([]*fetchRequestData, 0, len(l.active))
	for request := range l.active {
		active = append(active, request)
	}
	l.active = make(map[*fetchRequestData]struct{})
	l.mu.Unlock()
	for _, request := range active {
		if request != nil && request.cancel != nil {
			request.cancel()
		}
	}
	return nil
}

func (s *fetchAbortState) set(reason goja.Value) {
	s.mu.Lock()
	s.reason = reason
	s.mu.Unlock()
}

func (s *fetchAbortState) get() goja.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// EnableFetch installs fetch without an authorization hook for direct Goja
// callers.
func EnableFetch(rt *goja.Runtime, loop *eventloop.EventLoop, proxy http.Handler) error {
	return EnableFetchWithPolicyAndLifecycleAndContext(rt, loop, proxy, nil, nil, AsyncContextHooks{})
}

// EnableFetchWithPolicy installs fetch with an adapter-owned policy check.
func EnableFetchWithPolicy(rt *goja.Runtime, loop *eventloop.EventLoop, proxy http.Handler, authorize func(string) error) error {
	return EnableFetchWithPolicyAndLifecycleAndContext(rt, loop, proxy, authorize, nil, AsyncContextHooks{})
}

// EnableFetchWithPolicyAndLifecycle additionally attaches requests to a
// lifecycle owner, allowing shutdown to cancel in-flight network work.
func EnableFetchWithPolicyAndLifecycle(rt *goja.Runtime, loop *eventloop.EventLoop, proxy http.Handler, authorize func(string) error, lifecycle *FetchLifecycle) error {
	return EnableFetchWithPolicyAndLifecycleAndContext(rt, loop, proxy, authorize, lifecycle, AsyncContextHooks{})
}

// EnableFetchWithPolicyAndLifecycleAndContext installs fetch and restores the
// opaque context captured at request creation before resolving its Promise.
func EnableFetchWithPolicyAndLifecycleAndContext(rt *goja.Runtime, loop *eventloop.EventLoop, proxy http.Handler, authorize func(string) error, lifecycle *FetchLifecycle, hooks AsyncContextHooks) error {
	if loop == nil {
		return errors.New("JS event loop is required for fetch")
	}
	if proxy == nil {
		return errors.New("proxy handler cannot be nil")
	}
	return rt.Set("fetch", newFetchFn(rt, loop, proxy, authorize, lifecycle, hooks))
}
func newFetchFn(rt *goja.Runtime, loop *eventloop.EventLoop, proxy http.Handler, authorize func(string) error, lifecycle *FetchLifecycle, hooks AsyncContextHooks) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		promise, resolve, reject := rt.NewPromise()

		requestData, err := parseFetchRequest(rt, call.Argument(0), call.Argument(1))
		if err != nil {
			_ = reject(rt.NewTypeError(err.Error()))
			return rt.ToValue(promise)
		}
		if authorize != nil {
			if err := authorize(requestData.url); err != nil {
				_ = reject(rt.NewGoError(err))
				return rt.ToValue(promise)
			}
		}
		if lifecycle != nil {
			if err := lifecycle.Start(requestData); err != nil {
				_ = reject(rt.NewGoError(err))
				return rt.ToValue(promise)
			}
		}
		var executionContext any
		if hooks.CurrentContext != nil {
			executionContext = hooks.CurrentContext()
		}
		go func() {
			if lifecycle != nil {
				defer lifecycle.Done(requestData)
			}
			responseData, err := doFetchRequest(requestData, proxy)
			complete := func(loopRT *goja.Runtime) {
				if requestData.ctx != nil && requestData.ctx.Err() != nil {
					reason := requestData.abort.get()
					if reason == nil || goja.IsUndefined(reason) || goja.IsNull(reason) {
						reason = loopRT.NewTypeError("The operation was aborted")
					}
					_ = reject(reason)
					return
				}
				if err != nil {
					_ = reject(loopRT.NewTypeError(err.Error()))
					return
				}
				response := loopRT.NewObject()
				bindResponse(loopRT, response, responseData)
				_ = resolve(response)
			}
			if hooks.ScheduleOnLoop != nil {
				_ = hooks.ScheduleOnLoop(executionContext, func(loopRT *goja.Runtime) error {
					complete(loopRT)
					return nil
				})
				return
			}
			loop.RunOnLoop(complete)
		}()

		return rt.ToValue(promise)
	}
}

func parseFetchRequest(rt *goja.Runtime, input goja.Value, init goja.Value) (*fetchRequestData, error) {
	if goja.IsUndefined(input) || goja.IsNull(input) || strings.TrimSpace(input.String()) == "" {
		return nil, errors.New("url parameter missing")
	}

	data := &fetchRequestData{
		url:     input.String(),
		method:  http.MethodGet,
		headers: newHeadersData(),
		abort:   &fetchAbortState{},
	}
	data.ctx, data.cancel = context.WithCancel(context.Background())

	if obj, ok := input.(*goja.Object); ok {
		if urlValue := obj.Get("url"); urlValue != nil && !goja.IsUndefined(urlValue) && !goja.IsNull(urlValue) {
			data.url = urlValue.String()
		}
		if err := applyFetchInit(rt, data, obj); err != nil {
			return nil, err
		}
	}

	if !goja.IsUndefined(init) && !goja.IsNull(init) {
		if obj, ok := init.(*goja.Object); ok {
			if err := applyFetchInit(rt, data, obj); err != nil {
				return nil, err
			}
		}
	}
	applyDefaultFetchHeaders(data.headers)

	encodedURL, err := encodeFetchURL(data.url)
	if err != nil {
		return nil, err
	}
	data.url = encodedURL
	return data, nil
}

func applyDefaultFetchHeaders(headers *headersData) {
	if !headers.has("user-agent") {
		headers.set("user-agent", "Scardice-core-fetch/1.0")
	}
	if !headers.has("connection") {
		headers.set("connection", "close")
	}
	if !headers.has("accept") {
		headers.set("accept", "*/*")
	}
}

func applyFetchInit(rt *goja.Runtime, data *fetchRequestData, obj *goja.Object) error {
	if method := obj.Get("method"); method != nil && !goja.IsUndefined(method) && !goja.IsNull(method) {
		data.method = strings.ToUpper(method.String())
	}
	if headers := obj.Get("headers"); headers != nil && !goja.IsUndefined(headers) && !goja.IsNull(headers) {
		fillHeaders(rt, data.headers, headers)
	}
	if body := obj.Get("body"); body != nil && !goja.IsUndefined(body) && !goja.IsNull(body) {
		bodyBytes, err := bytesFromBodyValue(data.headers, body)
		if err != nil {
			return err
		}
		data.body = bodyBytes
	}
	if signal := obj.Get("signal"); signal != nil && !goja.IsUndefined(signal) && !goja.IsNull(signal) {
		attachFetchAbortSignal(rt, data, signal)
	}
	return nil
}

func attachFetchAbortSignal(rt *goja.Runtime, data *fetchRequestData, signal goja.Value) {
	signalObj, ok := signal.(*goja.Object)
	if !ok {
		signalObj = signal.ToObject(rt)
	}
	if signalObj == nil {
		return
	}
	addEventListener, ok := goja.AssertFunction(signalObj.Get("addEventListener"))
	if !ok {
		return
	}
	cancelFn := rt.ToValue(func(call goja.FunctionCall) goja.Value {
		if eventObj, ok := call.Argument(0).(*goja.Object); ok {
			data.abort.set(eventObj.Get("reason"))
		} else {
			data.abort.set(call.Argument(0))
		}
		data.cancel()
		return goja.Undefined()
	})
	_, _ = addEventListener(signalObj, rt.ToValue("abort"), cancelFn)
}

func bytesFromBodyValue(headers *headersData, body goja.Value) ([]byte, error) {
	if obj, ok := body.(*goja.Object); ok {
		if formData := formDataFromObject(obj); formData != nil {
			return encodeMultipartFormData(headers, formData)
		}
		if isURLSearchParams(obj) {
			if !headers.has("content-type") {
				headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8")
			}
			toString, ok := goja.AssertFunction(obj.Get("toString"))
			if !ok {
				return nil, errors.New("URLSearchParams body cannot be serialized")
			}
			encoded, err := toString(obj)
			if err != nil {
				return nil, err
			}
			return []byte(encoded.String()), nil
		}
	}
	return bytesFromValue(body), nil
}

func formDataFromObject(obj *goja.Object) *formDataData {
	internal := obj.Get(sealFormDataDataKey)
	if internal == nil || goja.IsUndefined(internal) || goja.IsNull(internal) {
		return nil
	}
	data, _ := internal.Export().(*formDataData)
	return data
}

func encodeMultipartFormData(headers *headersData, formData *formDataData) ([]byte, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for _, entry := range formData.entries {
		var part io.Writer
		var err error
		if entry.isFile {
			part, err = writer.CreateFormFile(entry.name, entry.filename)
		} else {
			part, err = writer.CreateFormField(entry.name)
		}
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(part, entry.value); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if !headers.has("content-type") {
		headers.set("content-type", writer.FormDataContentType())
	}
	return buf.Bytes(), nil
}

func isURLSearchParams(obj *goja.Object) bool {
	ctor := obj.Get("constructor")
	if ctorObj, ok := ctor.(*goja.Object); ok {
		if name := ctorObj.Get("name"); name != nil && name.String() == "URLSearchParams" {
			return true
		}
	}
	for _, method := range []string{"append", "delete", "get", "getAll", "has", "set", "sort", "toString"} {
		value := obj.Get(method)
		if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
			return false
		}
	}
	return obj.String() != "[object Object]"
}

func encodeFetchURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String(), nil
}

func doFetchRequest(data *fetchRequestData, proxy http.Handler) (*responseData, error) {
	var body io.Reader
	if data.body != nil {
		body = bytes.NewReader(data.body)
	}

	ctx := data.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := http.NewRequestWithContext(ctx, data.method, data.url, body)
	if err != nil {
		return nil, err
	}

	request.Header = data.headers.toHTTPHeader()
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)

	status := recorder.Code
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = recorder.Result().Status
	}

	return &responseData{
		status:     status,
		statusText: statusText,
		headers:    newHeadersDataFromHTTPHeader(recorder.Header()),
		bodyBytes:  append([]byte(nil), recorder.Body.Bytes()...),
		url:        data.url,
		method:     data.method,
	}, nil
}

func newHeadersDataFromHTTPHeader(header http.Header) *headersData {
	data := newHeadersData()
	for key, values := range header {
		data.store[strings.ToLower(key)] = append([]string(nil), values...)
	}
	return data
}

func (h *headersData) toHTTPHeader() http.Header {
	header := make(http.Header)
	for key, values := range h.store {
		header[textproto.CanonicalMIMEHeaderKey(key)] = append([]string(nil), values...)
	}
	return header
}
