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

	"Scardice-core/utils/jsengine/hostbridge"
)

type nativeHostState struct {
	loop    *nativeLoop
	session *hostbridge.Session
	mu      sync.Mutex
	lastErr string
}

func newNativeHostState(loop *nativeLoop) *nativeHostState {
	return &nativeHostState{loop: loop, session: hostbridge.NewSession()}
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
	if uint64(view.len) > uint64(^uint(0)>>1) {
		return "", errors.New("invalid native string view")
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(view.data)), int(view.len))), nil
}

func copyHostBytes(buffer *C.char, capacity C.uint64_t, data []byte) C.sc_status_t {
	if uint64(capacity) < uint64(len(data)) {
		return C.sc_status_t(-1)
	}
	if len(data) != 0 {
		if buffer == nil {
			return C.sc_status_t(-1)
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(capacity)), data)
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
	if target.Kind() != reflect.Func {
		return reflect.Value{}, fmt.Errorf("native codec callback target must be a function")
	}
	return reflect.Value{}, errors.New("native runtime cannot decode a JavaScript callback without a callback value ABI")
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
