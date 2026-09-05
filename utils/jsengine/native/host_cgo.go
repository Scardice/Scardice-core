//go:build cgo

package native

/*
#include "bridge.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"runtime/cgo"
	"sync"
	"unsafe"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
	jsservices "Scardice-core/utils/jsengine/services"
)

type nativeHostState struct {
	loop            *nativeLoop
	session         *hostbridge.Session
	serviceRegistry *jsservices.Registry
	mu              sync.Mutex
	lastErr         string
	callbacks       map[uint64]uint64
	nextCallback    uint64
	closed          bool
}
type nativeServiceSink struct {
	loop *nativeLoop
}

func (s nativeServiceSink) enqueue(kind jsservices.EventKind, id jsservices.RequestID, response jsservices.Response) error {
	if s.loop == nil {
		return ErrNativeClosed
	}
	return s.loop.enqueueServiceEvent(nativeServiceEvent{
		kind:     kind,
		request:  id,
		response: response,
	})
}

func (s nativeServiceSink) Event(id jsservices.RequestID, response jsservices.Response) error {
	return s.enqueue(jsservices.EventData, id, response)
}

func (s nativeServiceSink) Complete(id jsservices.RequestID, response jsservices.Response) error {
	return s.enqueue(jsservices.EventComplete, id, response)
}

func (s nativeServiceSink) Close(id jsservices.RequestID, response jsservices.Response) error {
	return s.enqueue(jsservices.EventClose, id, response)
}

func newNativeHostState(loop *nativeLoop) *nativeHostState {
	return &nativeHostState{
		loop: loop, session: hostbridge.NewSession(), callbacks: make(map[uint64]uint64),
	}
}

func (s *nativeHostState) setError(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
}

func (s *nativeHostState) errorText() string {
	if s == nil {
		return "native host callback failed"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr == "" {
		return "native host callback failed"
	}
	return s.lastErr
}
func (s *nativeHostState) setServiceRegistry(registry *jsservices.Registry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.serviceRegistry = registry
	s.mu.Unlock()
}

func hostStateFromContext(ctx C.sc_host_ctx_t) (state *nativeHostState, err error) {
	if ctx == 0 {
		return nil, errors.New("native host context is empty")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid native host context: %v", recovered)
		}
	}()
	value := cgo.Handle(uintptr(ctx)).Value()
	state, ok := value.(*nativeHostState)
	if !ok || state == nil {
		return nil, errors.New("invalid native host context")
	}
	return state, nil
}
func (s *nativeHostState) registerCallback(runtimeHandle, valueHandle uint64) (hostbridge.CallbackRef, error) {
	if s == nil || s.loop == nil || s.loop.closed.Load() {
		return 0, ErrNativeClosed
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, hostbridge.ErrStaleRuntimeCallback
	}
	if s.nextCallback == 0 {
		s.nextCallback = 1
	}
	token := s.nextCallback
	s.nextCallback++
	s.mu.Unlock()
	errorBuffer := make([]byte, 512)
	status := C.sc_native_value_retain(
		C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(valueHandle),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)),
	)
	if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
		return 0, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		C.sc_native_value_release(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(valueHandle))
		return 0, hostbridge.ErrStaleRuntimeCallback
	}
	s.callbacks[token] = valueHandle
	s.mu.Unlock()
	return hostbridge.CallbackRef(token), nil
}

func (s *nativeHostState) callbackHandle(token hostbridge.CallbackRef) (uint64, error) {
	if s == nil || s.loop == nil || s.loop.closed.Load() {
		return 0, ErrNativeClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, hostbridge.ErrStaleRuntimeCallback
	}
	handle, ok := s.callbacks[uint64(token)]
	if !ok {
		return 0, hostbridge.ErrStaleRuntimeCallback
	}
	return handle, nil
}

func (s *nativeHostState) closeCallbacks() {
	if s == nil || s.loop == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	handles := make([]uint64, 0, len(s.callbacks))
	for _, handle := range s.callbacks {
		handles = append(handles, handle)
	}
	s.callbacks = nil
	s.mu.Unlock()
	for _, handle := range handles {
		C.sc_native_value_release(C.uint64_t(s.loop.provider.library), C.uint64_t(s.loop.runtime), C.uint64_t(handle))
	}
}

func withHostState(ctx C.sc_host_ctx_t, fn func(*nativeHostState) C.sc_status_t) (status C.sc_status_t) {
	state, err := hostStateFromContext(ctx)
	if err != nil {
		return C.sc_status_t(-20)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err := fmt.Errorf("native host callback panic: %v", recovered)
			state.setError(err)
			status = C.sc_status_t(-20)
		}
	}()
	return fn(state)
}

func hostString(view C.sc_string_view) (string, error) {
	if view.len == 0 {
		return "", nil
	}
	if view.data == nil || uint64(view.len) > uint64(^uint(0)>>1) {
		return "", errors.New("invalid native string view")
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(view.data)), int(view.len))), nil
}

func copyHostBytes(buffer *C.char, capacity C.uint64_t, data []byte) C.sc_status_t {
	return copyServiceBuffer(unsafe.Pointer(buffer), capacity, data)
}

func copyServiceBuffer(buffer unsafe.Pointer, capacity C.uint64_t, data []byte) C.sc_status_t {
	if uint64(capacity) > uint64(^uint(0)>>1) || uint64(capacity) < uint64(len(data)) {
		return C.sc_status_t(-1)
	}
	if len(data) != 0 {
		if buffer == nil {
			return C.sc_status_t(-1)
		}
		copy(unsafe.Slice((*byte)(buffer), int(capacity)), data)
	}
	return C.SC_OK
}

func (s *nativeHostState) checkRuntime(runtimeHandle C.sc_runtime_t) error {
	if s == nil || s.loop == nil || s.loop.closed.Load() {
		return ErrNativeClosed
	}
	if uint64(runtimeHandle) != s.loop.runtime {
		return ErrNativeStaleValue
	}
	return nil
}

func decodeNativeServiceRequest(service C.sc_string_view, request *C.sc_host_service_request_v1) (jsservices.Name, jsservices.Request, error) {
	if request == nil || request.struct_size < C.uint32_t(unsafe.Sizeof(*request)) {
		return "", jsservices.Request{}, errors.New("invalid native host service request")
	}
	serviceName, err := hostString(service)
	if err != nil {
		return "", jsservices.Request{}, err
	}
	requestString, err := hostString(request.string)
	if err != nil {
		return "", jsservices.Request{}, err
	}
	if uint64(request.bytes_len) > uint64(^uint(0)>>1) ||
		(request.bytes_len != 0 && request.bytes == nil) {
		return "", jsservices.Request{}, errors.New("invalid native host service byte buffer")
	}
	requestBytes := make([]byte, int(request.bytes_len))
	if len(requestBytes) != 0 {
		copy(requestBytes, unsafe.Slice((*byte)(unsafe.Pointer(request.bytes)), len(requestBytes)))
	}
	serviceID := jsservices.NormalizeName(jsservices.Name(serviceName))
	requestValue := jsservices.Request{
		Service:   serviceID,
		Operation: jsservices.OperationID(request.operation),
		String:    requestString,
		Bytes:     requestBytes,
		Bool:      request.bool_value != 0,
		Int64:     int64(request.int64_value),
		Uint64:    uint64(request.uint64_value),
		Float64:   float64(request.float64_value),
	}
	if serviceID == jsservices.Fetch && requestValue.Operation == jsservices.OpFetchRequest {
		var metadata struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(requestString), &metadata) == nil {
			requestValue.Target = metadata.URL
		}
	}
	return serviceID, requestValue, nil
}

func nativeHostServiceStatus(err error) C.sc_status_t {
	switch {
	case errors.Is(err, jsservices.ErrRegistryClosed):
		return C.SC_ECLOSED
	case errors.Is(err, jsservices.ErrDeadlineExceeded):
		return C.SC_ETIMEOUT
	case errors.Is(err, jsservices.ErrCancelled):
		return C.SC_ESTATE
	case errors.Is(err, jsservices.ErrPermissionDenied),
		errors.Is(err, jsservices.ErrUnsupported),
		errors.Is(err, jsservices.ErrServiceNotFound):
		return C.SC_ENOTSUP
	default:
		return C.SC_EHOST
	}
}

//export sc_native_go_host_get
func sc_native_go_host_get(ctx C.sc_host_ctx_t, runtimeHandle C.sc_runtime_t, ref C.sc_host_ref_t, key C.sc_string_view, out *C.sc_value_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if err := state.checkRuntime(runtimeHandle); err != nil || out == nil {
			if err == nil {
				err = errors.New("host_get output is nil")
			}
			state.setError(err)
			return C.sc_status_t(-20)
		}
		name, err := hostString(key)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		value, err := state.session.Get(hostbridge.HostRef(ref), name)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		handle, err := state.encodeValue(uint64(runtimeHandle), value)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		*out = C.sc_value_t(handle)
		return C.SC_OK
	})
}

//export sc_native_go_host_set
func sc_native_go_host_set(ctx C.sc_host_ctx_t, runtimeHandle C.sc_runtime_t, ref C.sc_host_ref_t, key C.sc_string_view, input C.sc_value_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if err := state.checkRuntime(runtimeHandle); err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		name, err := hostString(key)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		value, err := state.decodeValue(uint64(runtimeHandle), uint64(input))
		if err == nil {
			err = state.session.SetWithCodec(hostbridge.HostRef(ref), name, value, nativeCodec{state: state, runtime: uint64(runtimeHandle)})
		}
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		return C.SC_OK
	})
}

//export sc_native_go_host_has
func sc_native_go_host_has(ctx C.sc_host_ctx_t, ref C.sc_host_ref_t, key C.sc_string_view, out *C.uint32_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if out == nil {
			state.setError(errors.New("host_has output is nil"))
			return C.sc_status_t(-20)
		}
		name, err := hostString(key)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		present, err := state.session.Has(hostbridge.HostRef(ref), name)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		if present {
			*out = 1
		} else {
			*out = 0
		}
		return C.SC_OK
	})
}

//export sc_native_go_host_delete
func sc_native_go_host_delete(ctx C.sc_host_ctx_t, ref C.sc_host_ref_t, key C.sc_string_view, out *C.uint32_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if out == nil {
			state.setError(errors.New("host_delete output is nil"))
			return C.sc_status_t(-20)
		}
		name, err := hostString(key)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		deleted, err := state.session.Delete(hostbridge.HostRef(ref), name)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		if deleted {
			*out = 1
		} else {
			*out = 0
		}
		return C.SC_OK
	})
}

//export sc_native_go_host_keys
func sc_native_go_host_keys(ctx C.sc_host_ctx_t, ref C.sc_host_ref_t, buffer *C.char, capacity C.uint64_t, required *C.uint64_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if required == nil {
			state.setError(errors.New("host_keys output is nil"))
			return C.sc_status_t(-20)
		}
		keys, err := state.session.Keys(hostbridge.HostRef(ref))
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		data, err := json.Marshal(keys)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		*required = C.uint64_t(len(data))
		if buffer == nil || capacity < C.uint64_t(len(data)) {
			return C.sc_status_t(-1)
		}
		return copyHostBytes(buffer, capacity, data)
	})
}

//export sc_native_go_host_call
func sc_native_go_host_call(ctx C.sc_host_ctx_t, runtimeHandle C.sc_runtime_t, function C.sc_host_func_t, thisValue C.sc_value_t, argv *C.sc_value_t, argc C.uint64_t, out *C.sc_value_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if err := state.checkRuntime(runtimeHandle); err != nil || out == nil {
			if err == nil {
				err = errors.New("host_call output is nil")
			}
			state.setError(err)
			return C.sc_status_t(-20)
		}
		if uint64(argc) > uint64(^uint(0)>>1) || (argc > 0 && argv == nil) {
			state.setError(errors.New("invalid host_call argument array"))
			return C.sc_status_t(-20)
		}
		args := make([]hostbridge.Value, int(argc))
		for i := range args {
			value, err := state.decodeValue(uint64(runtimeHandle), uint64(unsafe.Slice(argv, int(argc))[i]))
			if err != nil {
				state.setError(err)
				return C.sc_status_t(-20)
			}
			args[i] = value
		}
		_ = thisValue
		value, err := state.session.CallFunctionWithCodec(hostbridge.HostFuncRef(function), args, nativeCodec{state: state, runtime: uint64(runtimeHandle)})
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		handle, err := state.encodeValue(uint64(runtimeHandle), value)
		if err != nil {
			state.setError(err)
			return C.sc_status_t(-20)
		}
		*out = C.sc_value_t(handle)
		return C.SC_OK
	})
}

//export sc_native_go_host_service_call
func sc_native_go_host_service_call(ctx C.sc_host_ctx_t, runtimeHandle C.sc_runtime_t, service C.sc_string_view, request *C.sc_host_service_request_v1, response *C.sc_host_service_response_v1) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if err := state.checkRuntime(runtimeHandle); err != nil {
			state.setError(err)
			return C.SC_ECLOSED
		}
		if request == nil || response == nil ||
			request.struct_size < C.uint32_t(unsafe.Sizeof(*request)) ||
			response.struct_size < C.uint32_t(unsafe.Sizeof(*response)) {
			err := errors.New("invalid native host service request")
			state.setError(err)
			return C.SC_EINVAL
		}
		serviceName, err := hostString(service)
		if err != nil {
			state.setError(err)
			return C.SC_EINVAL
		}
		requestString, err := hostString(request.string)
		if err != nil {
			state.setError(err)
			return C.SC_EINVAL
		}
		if uint64(request.bytes_len) > uint64(^uint(0)>>1) ||
			(request.bytes_len != 0 && request.bytes == nil) {
			err := errors.New("invalid native host service byte buffer")
			state.setError(err)
			return C.SC_EINVAL
		}
		requestBytes := make([]byte, int(request.bytes_len))
		if len(requestBytes) != 0 {
			copy(requestBytes, unsafe.Slice((*byte)(unsafe.Pointer(request.bytes)), len(requestBytes)))
		}

		state.mu.Lock()
		registry := state.serviceRegistry
		state.mu.Unlock()
		if registry == nil {
			response.status = C.SC_SERVICE_UNSUPPORTED
			state.setError(errors.New("native host service registry is unavailable"))
			return C.SC_OK
		}
		result, invokeErr := registry.InvokeNative(jsservices.Call{
			Request: jsservices.Request{
				Service:   jsservices.Name(serviceName),
				Operation: jsservices.OperationID(request.operation),
				String:    requestString,
				Bytes:     requestBytes,
				Bool:      request.bool_value != 0,
				Int64:     int64(request.int64_value),
				Uint64:    uint64(request.uint64_value),
				Float64:   float64(request.float64_value),
			},
			Context: state.loop.CurrentContext(),
		})
		response.status = C.uint32_t(result.Status)
		response.bool_value = 0
		if result.Bool {
			response.bool_value = 1
		}
		response.int64_value = C.int64_t(result.Int64)
		response.uint64_value = C.uint64_t(result.Uint64)
		response.float64_value = C.double(result.Float64)
		response.string_required = C.uint64_t(len(result.String))
		response.bytes_required = C.uint64_t(len(result.Bytes))
		if status := copyServiceBuffer(unsafe.Pointer(response.string_buffer), response.string_capacity, []byte(result.String)); status != C.SC_OK {
			state.setError(errors.New("native host service string output buffer is too small"))
			return status
		}
		if status := copyServiceBuffer(unsafe.Pointer(response.bytes_buffer), response.bytes_capacity, result.Bytes); status != C.SC_OK {
			state.setError(errors.New("native host service byte output buffer is too small"))
			return status
		}
		if invokeErr != nil {
			state.setError(invokeErr)
		}
		return C.SC_OK
	})
}

//export sc_native_go_host_service_start
func sc_native_go_host_service_start(ctx C.sc_host_ctx_t, runtimeHandle C.sc_runtime_t, service C.sc_string_view, request *C.sc_host_service_request_v1, outRequest *C.sc_service_request_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if err := state.checkRuntime(runtimeHandle); err != nil {
			state.setError(err)
			return C.SC_ECLOSED
		}
		if outRequest == nil {
			err := errors.New("native host service start output is nil")
			state.setError(err)
			return C.SC_EINVAL
		}
		*outRequest = 0
		_, requestValue, err := decodeNativeServiceRequest(service, request)
		if err != nil {
			state.setError(err)
			return C.SC_EINVAL
		}
		state.mu.Lock()
		registry := state.serviceRegistry
		state.mu.Unlock()
		if registry == nil {
			err := errors.New("native host service registry is unavailable")
			state.setError(err)
			return C.SC_ENOTSUP
		}
		id, err := registry.StartNative(jsservices.Call{Request: requestValue, Context: state.loop.CurrentContext()}, nativeServiceSink{loop: state.loop})
		if err != nil {
			state.setError(err)
			return nativeHostServiceStatus(err)
		}
		*outRequest = C.sc_service_request_t(id)
		return C.SC_OK
	})
}

//export sc_native_go_host_service_cancel
func sc_native_go_host_service_cancel(ctx C.sc_host_ctx_t, runtimeHandle C.sc_runtime_t, request C.sc_service_request_t) C.sc_status_t {
	return withHostState(ctx, func(state *nativeHostState) C.sc_status_t {
		if err := state.checkRuntime(runtimeHandle); err != nil {
			state.setError(err)
			return C.SC_ECLOSED
		}
		if request == 0 {
			err := errors.New("native host service cancel request is empty")
			state.setError(err)
			return C.SC_EINVAL
		}
		state.mu.Lock()
		registry := state.serviceRegistry
		state.mu.Unlock()
		if registry == nil {
			err := errors.New("native host service registry is unavailable")
			state.setError(err)
			return C.SC_ENOTSUP
		}
		if err := registry.Cancel(jsservices.RequestID(request)); err != nil {
			state.setError(err)
			return nativeHostServiceStatus(err)
		}
		return C.SC_OK
	})
}

//export sc_native_go_host_last
func sc_native_go_host_last(ctx C.sc_host_ctx_t, buffer *C.char, capacity C.uint64_t, required *C.uint64_t) C.sc_status_t {
	state, err := hostStateFromContext(ctx)
	if err != nil || required == nil {
		return C.sc_status_t(-20)
	}
	data := []byte(state.errorText())
	*required = C.uint64_t(len(data))
	if buffer == nil || capacity < C.uint64_t(len(data)) {
		return C.sc_status_t(-1)
	}
	return copyHostBytes(buffer, capacity, data)
}

type nativeCodec struct {
	state   *nativeHostState
	runtime uint64
}

func (c nativeCodec) Decode(value hostbridge.Value, target reflect.Type) (reflect.Value, error) {
	if target == nil {
		return reflect.Value{}, errors.New("native codec callback target is nil")
	}
	if target.Kind() != reflect.Func {
		return reflect.Value{}, fmt.Errorf("native codec callback target must be a function")
	}
	if value.Kind != hostbridge.KindCallback {
		return reflect.Value{}, errors.New("expected JavaScript callback value")
	}
	token := hostbridge.CallbackRef(value.Callback)
	if _, err := c.state.callbackHandle(token); err != nil {
		return reflect.Value{}, err
	}
	return reflect.MakeFunc(target, func(inputs []reflect.Value) []reflect.Value {
		var (
			outputs []reflect.Value
			err     error
		)
		if c.state.loop.onOwnerThread() {
			outputs, err = c.callCallback(token, target, inputs)
		} else {
			err = c.state.loop.Run(func(jsengine.Runtime) error {
				outputs, err = c.callCallback(token, target, inputs)
				return err
			})
		}
		if err != nil {
			results := make([]reflect.Value, target.NumOut())
			for i := range results {
				results[i] = reflect.Zero(target.Out(i))
			}
			if len(results) > 0 && target.Out(len(results)-1) == reflect.TypeOf((*error)(nil)).Elem() {
				results[len(results)-1] = reflect.ValueOf(err)
				return results
			}
			panic(err)
		}
		return outputs
	}), nil
}

func (c nativeCodec) callCallback(token hostbridge.CallbackRef, target reflect.Type, inputs []reflect.Value) ([]reflect.Value, error) {
	handle, err := c.state.callbackHandle(token)
	if err != nil {
		return nil, err
	}
	arguments := make([]uint64, len(inputs))
	for i, input := range inputs {
		value, err := c.state.reflectValue(input)
		if err != nil {
			return nil, err
		}
		arguments[i], err = c.state.encodeValue(c.runtime, value)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		for _, argument := range arguments {
			if argument != 0 {
				C.sc_native_value_release(C.uint64_t(c.state.loop.provider.library), C.uint64_t(c.runtime), C.uint64_t(argument))
			}
		}
	}()
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_function_call(
		C.uint64_t(c.state.loop.provider.library), C.uint64_t(c.runtime), C.uint64_t(handle), 0,
		pointerToUint64(arguments), C.uint64_t(len(arguments)), &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)),
	)
	if err := c.state.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil, err
	}
	if output == 0 {
		return nil, errors.New("native callback returned an empty value")
	}
	defer C.sc_native_value_release(C.uint64_t(c.state.loop.provider.library), C.uint64_t(c.runtime), output)
	value, err := c.state.decodeValue(c.runtime, uint64(output))
	if err != nil {
		return nil, err
	}
	resultCount := target.NumOut()
	hasError := resultCount > 0 && target.Out(resultCount-1) == reflect.TypeOf((*error)(nil)).Elem()
	if hasError {
		resultCount--
	}
	if resultCount > 1 {
		return nil, errors.New("native callback supports one result plus error")
	}
	results := make([]reflect.Value, target.NumOut())
	if resultCount == 1 {
		results[0], err = c.state.session.DecodeValue(value, target.Out(0), c)
		if err != nil {
			return nil, err
		}
	}
	if hasError {
		results[len(results)-1] = reflect.Zero(target.Out(len(results) - 1))
	}
	return results, nil
}

func pointerToUint64(values []uint64) *C.uint64_t {
	if len(values) == 0 {
		return nil
	}
	return (*C.uint64_t)(unsafe.Pointer(&values[0]))
}

func (c nativeCodec) Encode(value reflect.Value) (hostbridge.Value, error) {
	return c.state.reflectValue(value)
}

func (c nativeCodec) CallCallback(hostbridge.Value, []hostbridge.Value) (hostbridge.Value, error) {
	return hostbridge.UndefinedValue(), errors.New("native runtime callback invocation is unsupported")
}

func (s *nativeHostState) decodeValue(runtimeHandle, handle uint64) (hostbridge.Value, error) {
	if handle == 0 {
		return hostbridge.UndefinedValue(), errors.New("invalid native value handle")
	}
	var typ C.uint32_t
	errorBuffer := make([]byte, 256)
	status := C.sc_native_value_type(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), &typ,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
		return hostbridge.UndefinedValue(), err
	}
	switch uint32(typ) {
	case nativeTypeUndefined:
		return hostbridge.UndefinedValue(), nil
	case nativeTypeNull:
		return hostbridge.NullValue(), nil
	case nativeTypeBool:
		var raw C.uint32_t
		errorBuffer = make([]byte, 256)
		status = C.sc_native_value_to_bool(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), &raw, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.BoolValue(raw != 0), nil
	case nativeTypeI64:
		var raw C.int64_t
		errorBuffer = make([]byte, 256)
		status = C.sc_native_value_to_i64(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), &raw, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.IntValue(int64(raw)), nil
	case nativeTypeU64:
		var raw C.uint64_t
		errorBuffer = make([]byte, 256)
		status = C.sc_native_value_to_u64(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), &raw, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.UintValue(uint64(raw)), nil
	case nativeTypeF64:
		var raw C.double
		errorBuffer = make([]byte, 256)
		status = C.sc_native_value_to_f64(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), &raw, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.FloatValue(float64(raw)), nil
	case nativeTypeString:
		var required C.uint64_t
		errorBuffer = make([]byte, 256)
		status = C.sc_native_value_to_utf8_copy(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), nil, 0, &required, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if required == 0 && status != C.SC_NATIVE_OK {
			return hostbridge.UndefinedValue(), s.loop.operation(status, cError(errorBuffer))
		}
		buffer := make([]byte, int(required))
		if len(buffer) > 0 {
			status = C.sc_native_value_to_utf8_copy(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), (*C.char)(unsafe.Pointer(&buffer[0])), C.uint64_t(len(buffer)), &required, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
			if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
				return hostbridge.UndefinedValue(), err
			}
			if buffer[len(buffer)-1] == 0 {
				buffer = buffer[:len(buffer)-1]
			}
		}
		return hostbridge.StringValue(string(buffer)), nil
	case nativeTypeHostObject, nativeTypeHostFunction:
		var ref C.uint64_t
		var kind C.uint32_t
		errorBuffer = make([]byte, 256)
		status = C.sc_native_value_get_host_ref(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(handle), &ref, &kind, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
			return hostbridge.UndefinedValue(), err
		}
		if uint32(typ) == nativeTypeHostFunction || uint32(kind) == uint32(hostbridge.KindHostFunction) {
			return hostbridge.HostFunctionValue(hostbridge.HostFuncRef(ref)), nil
		}
		return hostbridge.HostObjectValue(hostbridge.HostRef(ref)), nil
	case nativeTypeFunction:
		token, err := s.registerCallback(runtimeHandle, handle)
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.CallbackValue(token), nil
	default:
		return hostbridge.UndefinedValue(), fmt.Errorf("unsupported native value type %d", typ)
	}
}

func (s *nativeHostState) reflectValue(value reflect.Value) (hostbridge.Value, error) {
	if !value.IsValid() {
		return hostbridge.UndefinedValue(), nil
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return hostbridge.NullValue(), nil
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Bool:
		return hostbridge.BoolValue(value.Bool()), nil
	case reflect.String:
		return hostbridge.StringValue(value.String()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return hostbridge.IntValue(value.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return hostbridge.UintValue(value.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return hostbridge.FloatValue(value.Float()), nil
	case reflect.Pointer, reflect.Struct, reflect.Map, reflect.Slice:
		if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Map || value.Kind() == reflect.Slice) && value.IsNil() {
			return hostbridge.NullValue(), nil
		}
		ref, err := s.session.BindObject(value.Interface())
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.HostObjectValue(ref), nil
	case reflect.Func:
		ref, err := s.session.RegisterFunction(value.Interface())
		if err != nil {
			return hostbridge.UndefinedValue(), err
		}
		return hostbridge.HostFunctionValue(ref), nil
	default:
		return hostbridge.UndefinedValue(), fmt.Errorf("unsupported native host result %s", value.Type())
	}
}

func (s *nativeHostState) encodeValue(runtimeHandle uint64, value hostbridge.Value) (uint64, error) {
	call := func(fn func(*C.uint64_t, *C.char, C.uint64_t) C.int) (uint64, error) {
		var output C.uint64_t
		errorBuffer := make([]byte, 512)
		status := fn(&output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
		if err := s.loop.operation(status, cError(errorBuffer)); err != nil {
			return 0, err
		}
		return uint64(output), nil
	}
	switch value.Kind {
	case hostbridge.KindUndefined:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_undefined(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), out, err, cap)
		})
	case hostbridge.KindNull:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_null(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), out, err, cap)
		})
	case hostbridge.KindBool:
		raw := C.uint32_t(0)
		if value.Bool {
			raw = 1
		}
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_bool(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), raw, out, err, cap)
		})
	case hostbridge.KindString:
		data := []byte(value.String)
		var ptr *C.char
		if len(data) == 0 {
			data = []byte{0}
		}
		ptr = (*C.char)(unsafe.Pointer(&data[0]))
		output, err := call(func(out *C.uint64_t, e *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_string(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), ptr, C.uint64_t(len(value.String)), out, e, cap)
		})
		runtime.KeepAlive(data)
		return output, err
	case hostbridge.KindInt:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_i64(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.int64_t(value.Int), out, err, cap)
		})
	case hostbridge.KindUint:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_u64(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(value.Uint), out, err, cap)
		})
	case hostbridge.KindFloat:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_value_new_f64(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.double(value.Float), out, err, cap)
		})
	case hostbridge.KindHostObject:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_host_object_new(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(value.Host), C.uint32_t(hostbridge.KindHostObject), out, err, cap)
		})
	case hostbridge.KindHostFunction:
		return call(func(out *C.uint64_t, err *C.char, cap C.uint64_t) C.int {
			return C.sc_native_host_function_new(C.uint64_t(s.loop.provider.library), C.uint64_t(runtimeHandle), C.uint64_t(value.Function), out, err, cap)
		})
	default:
		return 0, fmt.Errorf("unsupported HostBridge value kind %d", value.Kind)
	}
}

var _ = runtime.KeepAlive
