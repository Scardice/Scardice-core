//go:build cgo

package native

/*
#cgo linux LDFLAGS: -ldl
#cgo freebsd LDFLAGS: -ldl
#include <stdlib.h>
#include <string.h>
#include "bridge.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"unsafe"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
)

const (
	hostABIMajor    = 1
	hostABIMinor    = 0
	runtimeABIMajor = 1
	runtimeABIMinor = 0

	nativeTypeUndefined    = 0
	nativeTypeNull         = 1
	nativeTypeBool         = 2
	nativeTypeI64          = 3
	nativeTypeU64          = 4
	nativeTypeF64          = 5
	nativeTypeString       = 6
	nativeTypeObject       = 7
	nativeTypeHostObject   = 8
	nativeTypeHostFunction = 9
	nativeTypeFunction     = 10
)

type Provider struct {
	candidate  Candidate
	descriptor jsengine.Descriptor
	library    uint64
}

type LoadedProvider = Provider

func Load(candidate Candidate) (*Provider, error) { return candidate.Load() }

func loadNative(candidate Candidate) (*Provider, error) {
	absolutePath, err := filepathAbs(candidate.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMissingLibrary, candidate.LibraryPath, err)
	}
	candidate.LibraryPath = absolutePath
	path := C.CString(absolutePath)
	defer C.free(unsafe.Pointer(path))
	errorBuffer := make([]byte, 512)
	var library C.uint64_t
	status := C.sc_native_open(path, &library, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if status != C.SC_NATIVE_OK {
		return nil, wrapNativeError(status, candidate.LibraryPath, cError(errorBuffer))
	}
	var raw C.sc_native_descriptor
	status = C.sc_native_query(library, runtimeABIMajor, runtimeABIMinor, hostABIMajor, hostABIMinor,
		&raw, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if status != C.SC_NATIVE_OK {
		return nil, wrapNativeError(status, candidate.LibraryPath, cError(errorBuffer))
	}
	descriptor := jsengine.Descriptor{
		ID:           jsengine.NormalizeEngineID(C.GoString(&raw.id[0])),
		Name:         C.GoString(&raw.name[0]),
		Version:      C.GoString(&raw.version[0]),
		Language:     C.GoString(&raw.language[0]),
		ABIMajor:     uint32(raw.abi_major),
		ABIMinor:     uint32(raw.abi_minor),
		HostABIMajor: uint32(raw.host_abi_major),
		HostABIMinor: uint32(raw.host_abi_minor),
		Capabilities: jsengine.CapabilitySet(raw.capabilities),
		Path:         candidate.LibraryPath,
	}
	if jsengine.NormalizeEngineID(candidate.Manifest.ID) != descriptor.ID || candidate.Manifest.Version != descriptor.Version {
		return nil, fmt.Errorf("%w: %w: manifest id/version %q/%q, descriptor %q/%q", ErrManifestMismatch, ErrDescriptorMismatch,
			candidate.Manifest.ID, candidate.Manifest.Version, descriptor.ID, descriptor.Version)
	}
	if candidate.Manifest.RuntimeABI.Major != descriptor.ABIMajor || candidate.Manifest.RuntimeABI.MinMinor > descriptor.ABIMinor {
		return nil, fmt.Errorf("%w: manifest runtime ABI %d.%d, descriptor %d.%d", ErrManifestMismatch,
			candidate.Manifest.RuntimeABI.Major, candidate.Manifest.RuntimeABI.MinMinor, descriptor.ABIMajor, descriptor.ABIMinor)
	}
	if candidate.Manifest.HostABI.Major != descriptor.HostABIMajor || candidate.Manifest.HostABI.MinMinor > descriptor.HostABIMinor {
		return nil, fmt.Errorf("%w: manifest host ABI %d.%d, descriptor %d.%d", ErrManifestMismatch,
			candidate.Manifest.HostABI.Major, candidate.Manifest.HostABI.MinMinor, descriptor.HostABIMajor, descriptor.HostABIMinor)
	}
	candidate.loaded = true
	return &Provider{candidate: candidate, descriptor: descriptor, library: uint64(library)}, nil
}

func cError(buffer []byte) string {
	for i, b := range buffer {
		if b == 0 {
			return string(buffer[:i])
		}
	}
	return string(buffer)
}

func wrapNativeError(status C.int, path, detail string) error {
	var sentinel error
	switch status {
	case C.SC_NATIVE_MISSING_LIBRARY:
		sentinel = ErrMissingLibrary
	case C.SC_NATIVE_MISSING_SYMBOL:
		sentinel = ErrMissingQuerySymbol
	case C.SC_NATIVE_RUNTIME_ABI:
		sentinel = ErrRuntimeABIMismatch
	case C.SC_NATIVE_HOST_ABI:
		sentinel = ErrHostABIMismatch
	case C.SC_NATIVE_CREATE:
		sentinel = ErrPluginCreateFailure
	case C.SC_NATIVE_CORRUPT_VTABLE:
		sentinel = ErrCorruptVTable
	case C.SC_NATIVE_TOO_SMALL:
		sentinel = ErrTooSmallStruct
	default:
		sentinel = ErrNativeUnavailable
	}
	return fmt.Errorf("%w: %s (%s)", sentinel, path, detail)
}

func wrapOperationError(status C.int, path, detail string) error {
	var sentinel error
	switch int(status) {
	case -3:
		sentinel = ErrNativeUnavailable
	case -5:
		sentinel = ErrNativeClosed
	case -10:
		sentinel = ErrNativeException
	case -12:
		sentinel = ErrNativeTimeout
	case -20:
		sentinel = ErrNativeHost
	default:
		sentinel = errors.New("native runtime operation failed")
	}
	if detail == "" {
		return fmt.Errorf("%w: %s (status %d)", sentinel, path, int(status))
	}
	return fmt.Errorf("%w: %s (%s)", sentinel, path, detail)
}
func (p *Provider) Descriptor() jsengine.Descriptor { return p.descriptor }

func (p *Provider) Open(ctx context.Context, options jsengine.RuntimeOptions) (jsengine.Loop, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	loop := &nativeLoop{
		provider:   p,
		tasks:      make(chan nativeTask),
		done:       make(chan struct{}),
		persistent: make(map[uint64]uint32),
	}
	ready := make(chan error, 1)
	go loop.worker(options, ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = loop.Close()
		return nil, err
	}
	return loop, nil
}

type nativeTask struct {
	fn   func(*nativeRuntime) error
	done chan error
	stop bool
}

type nativeLoop struct {
	provider *Provider
	runtime  uint64

	tasks  chan nativeTask
	done   chan struct{}
	closed atomic.Bool
	once   sync.Once

	closeMu  sync.Mutex
	closeErr error

	host       *nativeHostState
	hostHandle cgo.Handle

	persistentMu sync.Mutex
	persistent   map[uint64]uint32
}

func (l *nativeLoop) Engine() jsengine.EngineID       { return l.provider.descriptor.ID }
func (l *nativeLoop) Descriptor() jsengine.Descriptor { return l.provider.descriptor }

func (l *nativeLoop) worker(options jsengine.RuntimeOptions, ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	host := newNativeHostState(l)
	l.host = host
	l.hostHandle = cgo.NewHandle(host)
	payload := options.OptionsJSON
	var optionsPtr *C.char
	if len(payload) > 0 {
		optionsPtr = (*C.char)(C.CBytes(payload))
		defer C.free(unsafe.Pointer(optionsPtr))
	}
	errorBuffer := make([]byte, 512)
	var runtimeHandle C.uint64_t
	status := C.sc_native_create(
		C.uint64_t(l.provider.library),
		C.uint64_t(l.hostHandle),
		optionsPtr,
		C.uint64_t(len(payload)),
		&runtimeHandle,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])),
		C.uint64_t(len(errorBuffer)),
	)
	if status != C.SC_NATIVE_OK {
		l.hostHandle.Delete()
		close(l.done)
		ready <- wrapNativeError(status, l.provider.candidate.LibraryPath, cError(errorBuffer))
		return
	}
	l.runtime = uint64(runtimeHandle)
	status = C.sc_native_start(
		C.uint64_t(l.provider.library), runtimeHandle,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)),
	)
	if status != C.SC_NATIVE_OK {
		C.sc_native_destroy(C.uint64_t(l.provider.library), runtimeHandle, nil, 0)
		l.hostHandle.Delete()
		close(l.done)
		ready <- wrapOperationError(status, l.provider.candidate.LibraryPath, cError(errorBuffer))
		return
	}
	ready <- nil

	for task := range l.tasks {
		if task.stop {
			err := l.shutdown()
			task.done <- err
			return
		}
		rt := &nativeRuntime{loop: l, scope: newNativeScope(l)}
		err := runNativeTask(rt, task.fn)
		rt.scope.release()
		task.done <- err
	}
}

func runNativeTask(rt *nativeRuntime, fn func(*nativeRuntime) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("native runtime callback panic: %v", recovered)
		}
	}()
	return fn(rt)
}

func (l *nativeLoop) Run(run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("native runtime callback is nil")
	}
	if l.closed.Load() {
		return ErrNativeClosed
	}
	task := nativeTask{done: make(chan error, 1), fn: func(rt *nativeRuntime) error { return run(rt) }}
	select {
	case l.tasks <- task:
	case <-l.done:
		return ErrNativeClosed
	}
	return <-task.done
}

func (l *nativeLoop) LoadEntry(entry jsengine.Entry) error {
	return l.Run(func(rt jsengine.Runtime) error {
		native, ok := rt.(*nativeRuntime)
		if !ok {
			return errors.New("native runtime type assertion failed")
		}
		_, err := native.loadEntry(entry)
		return err
	})
}

func (l *nativeLoop) Close() error {
	l.once.Do(func() {
		l.closed.Store(true)
		closeTask := nativeTask{stop: true, done: make(chan error, 1)}
		select {
		case l.tasks <- closeTask:
			err := <-closeTask.done
			l.closeMu.Lock()
			l.closeErr = err
			l.closeMu.Unlock()
		case <-l.done:
		}
	})
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	return l.closeErr
}

func (l *nativeLoop) shutdown() error {
	errorBuffer := make([]byte, 512)
	var first error
	if status := C.sc_native_stop(C.uint64_t(l.provider.library), C.uint64_t(l.runtime),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer))); status != C.SC_NATIVE_OK {
		first = wrapOperationError(status, l.provider.candidate.LibraryPath, cError(errorBuffer))
	}
	l.persistentMu.Lock()
	for handle, count := range l.persistent {
		for i := uint32(0); i < count; i++ {
			C.sc_native_value_release(C.uint64_t(l.provider.library), C.uint64_t(l.runtime), C.uint64_t(handle))
		}
	}
	l.persistent = make(map[uint64]uint32)
	l.persistentMu.Unlock()
	if l.host != nil {
		l.host.closeCallbacks()
		l.host.session.Teardown()
	}
	if status := C.sc_native_destroy(C.uint64_t(l.provider.library), C.uint64_t(l.runtime),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer))); status != C.SC_NATIVE_OK && first == nil {
		first = wrapOperationError(status, l.provider.candidate.LibraryPath, cError(errorBuffer))
	}
	l.hostHandle.Delete()
	close(l.done)
	l.closeMu.Lock()
	l.closeErr = first
	l.closeMu.Unlock()
	return first
}

func (l *nativeLoop) registerPersistent(handle uint64) {
	l.persistentMu.Lock()
	l.persistent[handle]++
	l.persistentMu.Unlock()
}

func (l *nativeLoop) unregisterPersistent(handle uint64) {
	l.persistentMu.Lock()
	defer l.persistentMu.Unlock()
	if l.persistent[handle] <= 1 {
		delete(l.persistent, handle)
	} else {
		l.persistent[handle]--
	}
}

func (l *nativeLoop) operation(status C.int, detail string) error {
	if status == C.SC_NATIVE_OK {
		return nil
	}
	return wrapOperationError(status, l.provider.candidate.LibraryPath, detail)
}

type nativeScope struct {
	loop     *nativeLoop
	values   []*nativeValue
	released atomic.Bool
}

func newNativeScope(loop *nativeLoop) *nativeScope { return &nativeScope{loop: loop} }

func (s *nativeScope) value(handle uint64) *nativeValue {
	if s == nil || s.released.Load() || handle == 0 {
		return nil
	}
	v := &nativeValue{loop: s.loop, runtime: s.loop.runtime, handle: handle, scope: s}
	s.values = append(s.values, v)
	return v
}

func (s *nativeScope) release() {
	if s == nil || s.released.Swap(true) {
		return
	}
	for i := len(s.values) - 1; i >= 0; i-- {
		v := s.values[i]
		if !v.persistent.Load() && !v.gone.Swap(true) {
			C.sc_native_value_release(C.uint64_t(s.loop.provider.library), C.uint64_t(s.loop.runtime), C.uint64_t(v.handle))
		}
	}
	s.values = nil
}

type nativeRuntime struct {
	loop  *nativeLoop
	scope *nativeScope
}

func (r *nativeRuntime) Engine() jsengine.EngineID { return r.loop.Engine() }

func (r *nativeRuntime) RunString(filename, source string) (jsengine.Value, error) {
	return r.eval(jsengine.Entry{Filename: filename, Source: source, Kind: jsengine.EntryScript})
}
func (r *nativeRuntime) LoadCommonJS(filename, source string) (jsengine.Value, error) {
	return r.loadEntry(jsengine.Entry{Filename: filename, Source: source, Kind: jsengine.EntryCommonJS})
}
func (r *nativeRuntime) eval(entry jsengine.Entry) (jsengine.Value, error) {
	filename := []byte(entry.Filename)
	source := []byte(entry.Source)
	var filenamePtr *C.char
	var sourcePtr *C.char
	if len(filename) > 0 {
		filenamePtr = (*C.char)(unsafe.Pointer(&filename[0]))
	}
	if len(source) > 0 {
		sourcePtr = (*C.char)(unsafe.Pointer(&source[0]))
	}
	var output C.uint64_t
	var errorBuffer = make([]byte, 512)
	var status C.int
	if entry.Kind == jsengine.EntryScript {
		status = C.sc_native_eval(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime),
			filenamePtr, C.uint64_t(len(filename)), sourcePtr, C.uint64_t(len(source)), &output,
			(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	} else {
		status = C.sc_native_load_entry(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime),
			C.uint32_t(entry.Kind), filenamePtr, C.uint64_t(len(filename)), sourcePtr,
			C.uint64_t(len(source)), &output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	}
	runtime.KeepAlive(filename)
	runtime.KeepAlive(source)
	if err := r.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil, err
	}
	return r.scope.value(uint64(output)), nil
}

func (r *nativeRuntime) loadEntry(entry jsengine.Entry) (jsengine.Value, error) {
	if entry.Kind > jsengine.EntryExtension {
		return nil, fmt.Errorf("native runtime: unknown entry kind %d", entry.Kind)
	}
	return r.eval(entry)
}
func (r *nativeRuntime) LoadEntry(entry jsengine.Entry) (jsengine.Value, error) {
	return r.loadEntry(entry)
}

func (r *nativeRuntime) NewObject() jsengine.Object {
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_object_new(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if err := r.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil
	}
	value := r.scope.value(uint64(output))
	if value == nil {
		return nil
	}
	return value.Object()
}

func (r *nativeRuntime) Get(name string) jsengine.Value {
	value, err := r.getGlobal(name)
	if err == nil {
		return value
	}
	return r.undefined()
}

func (r *nativeRuntime) Set(name string, raw interface{}) error {
	value, err := r.coerce(raw)
	if err != nil {
		return err
	}
	return r.setGlobal(name, value)
}

func (r *nativeRuntime) Bind(name string, raw interface{}) error { return r.Set(name, raw) }
// ExposeDangerous mirrors the explicit seal.inst escape hatch for native runtimes.
func ExposeDangerous(engine jsengine.Runtime, target interface{}) (jsengine.Value, error) {
	r, ok := engine.(*nativeRuntime)
	if !ok || r == nil || r.loop == nil || r.loop.host == nil {
		return nil, errors.New("native runtime is required")
	}
	ref, err := r.loop.host.session.ExposeDangerous(target)
	if err != nil {
		return nil, err
	}
	return r.newHostObject(ref, uint32(hostbridge.KindHostObject))
}

func (r *nativeRuntime) getGlobal(name string) (jsengine.Value, error) {
	nameBytes := []byte(name)
	var namePtr *C.char
	if len(nameBytes) > 0 {
		namePtr = (*C.char)(unsafe.Pointer(&nameBytes[0]))
	}
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_global_get(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime),
		namePtr, C.uint64_t(len(nameBytes)), &output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(nameBytes)
	if err := r.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil, err
	}
	return r.scope.value(uint64(output)), nil
}

func (r *nativeRuntime) setGlobal(name string, value *nativeValue) error {
	nameBytes := []byte(name)
	var namePtr *C.char
	if len(nameBytes) > 0 {
		namePtr = (*C.char)(unsafe.Pointer(&nameBytes[0]))
	}
	errorBuffer := make([]byte, 512)
	status := C.sc_native_global_set(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime),
		namePtr, C.uint64_t(len(nameBytes)), C.uint64_t(value.handle),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(nameBytes)
	return r.loop.operation(status, cError(errorBuffer))
}

func (r *nativeRuntime) undefined() jsengine.Value {
	var output C.uint64_t
	errorBuffer := make([]byte, 256)
	status := C.sc_native_value_new_undefined(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if err := r.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil
	}
	return r.scope.value(uint64(output))
}

func (r *nativeRuntime) coerce(raw interface{}) (*nativeValue, error) {
	if raw == nil {
		return r.newNull()
	}
	if value, ok := raw.(*nativeValue); ok {
		return r.sameValue(value)
	}
	if value, ok := raw.(nativeValue); ok {
		return r.sameValue(&value)
	}
	if value, ok := raw.(jsengine.Value); ok {
		if native, ok := value.(*nativeValue); ok {
			return r.sameValue(native)
		}
		return nil, errors.New("native runtime cannot consume a value from another engine")
	}
	if value, ok := raw.(hostbridge.Value); ok {
		return r.coerceHostBridgeValue(value)
	}
	return r.coerceReflect(reflect.ValueOf(raw))
}

func (r *nativeRuntime) sameValue(value *nativeValue) (*nativeValue, error) {
	if value == nil || r == nil || r.loop == nil || r.loop.closed.Load() ||
		value.loop != r.loop || value.runtime != r.loop.runtime || value.released() {
		return nil, errors.New("native value belongs to another or closed runtime")
	}
	return value, nil
}

func (r *nativeRuntime) coerceHostBridgeValue(value hostbridge.Value) (*nativeValue, error) {
	switch value.Kind {
	case hostbridge.KindUndefined:
		return r.undefinedValue()
	case hostbridge.KindNull:
		return r.newNull()
	case hostbridge.KindBool:
		return r.newBool(value.Bool)
	case hostbridge.KindString:
		return r.newString(value.String)
	case hostbridge.KindInt:
		return r.newInt(value.Int)
	case hostbridge.KindUint:
		return r.newUint(value.Uint)
	case hostbridge.KindFloat:
		return r.newFloat(value.Float)
	case hostbridge.KindHostObject:
		return r.newHostObject(value.Host, uint32(hostbridge.KindHostObject))
	case hostbridge.KindHostFunction:
		return r.newHostFunction(hostbridge.HostFuncRef(value.Function))
	default:
		return nil, fmt.Errorf("unsupported HostBridge value kind %d", value.Kind)
	}
}

func (r *nativeRuntime) coerceReflect(value reflect.Value) (*nativeValue, error) {
	if !value.IsValid() {
		return r.newNull()
	}
	for value.Kind() == reflect.Interface {
		if value.IsNil() {
			return r.newNull()
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Bool:
		return r.newBool(value.Bool())
	case reflect.String:
		return r.newString(value.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return r.newInt(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return r.newUint(value.Uint())
	case reflect.Float32, reflect.Float64:
		return r.newFloat(value.Float())
	case reflect.Func:
		if value.IsNil() {
			return r.newNull()
		}
		ref, err := r.loop.host.session.RegisterFunction(value.Interface())
		if err != nil {
			return nil, err
		}
		return r.newHostFunction(ref)
	case reflect.Pointer, reflect.Struct, reflect.Map, reflect.Slice:
		if value.Kind() == reflect.Pointer && value.IsNil() {
			return r.newNull()
		}
		if (value.Kind() == reflect.Map || value.Kind() == reflect.Slice) && value.IsNil() {
			return r.newNull()
		}
		ref, err := r.loop.host.session.BindObject(value.Interface())
		if err != nil {
			return nil, err
		}
		return r.newHostObject(ref, uint32(hostbridge.KindHostObject))
	default:
		return nil, fmt.Errorf("unsupported native binding type %s", value.Type())
	}
}

func (r *nativeRuntime) newNull() (*nativeValue, error) {
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_new_null(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) undefinedValue() (*nativeValue, error) {
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_new_undefined(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) newBool(value bool) (*nativeValue, error) {
	var raw C.uint32_t
	if value {
		raw = 1
	}
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_new_bool(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), raw, output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) newInt(value int64) (*nativeValue, error) {
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_new_i64(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.int64_t(value), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) newUint(value uint64) (*nativeValue, error) {
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_new_u64(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.uint64_t(value), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) newFloat(value float64) (*nativeValue, error) {
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_new_f64(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.double(value), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) newString(value string) (*nativeValue, error) {
	data := []byte(value)
	if len(data) == 0 {
		data = []byte{0}
	}
	ptr := (*C.char)(unsafe.Pointer(&data[0]))
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_value_new_string(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), ptr, C.uint64_t(len(value)), &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(data)
	if err := r.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil, err
	}
	return r.scope.value(uint64(output)), nil
}
func (r *nativeRuntime) newHostObject(ref hostbridge.HostRef, kind uint32) (*nativeValue, error) {
	if ref == 0 {
		return nil, errors.New("invalid HostRef 0")
	}
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_host_object_new(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.uint64_t(ref), C.uint32_t(kind), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) newHostFunction(ref hostbridge.HostFuncRef) (*nativeValue, error) {
	if ref == 0 {
		return nil, errors.New("invalid HostFuncRef 0")
	}
	return r.makeValue(func(output *C.uint64_t, errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_host_function_new(C.uint64_t(r.loop.provider.library), C.uint64_t(r.loop.runtime), C.uint64_t(ref), output, errorBuffer, capacity)
	})
}
func (r *nativeRuntime) makeValue(call func(*C.uint64_t, *C.char, C.uint64_t) C.int) (*nativeValue, error) {
	if r == nil || r.loop == nil || r.scope == nil || r.scope.released.Load() {
		return nil, ErrNativeClosed
	}
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	status := call(&output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if err := r.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil, err
	}
	return r.scope.value(uint64(output)), nil
}

type nativeValue struct {
	loop       *nativeLoop
	runtime    uint64
	handle     uint64
	scope      *nativeScope
	gone       atomic.Bool
	persistent atomic.Bool
}

func (v *nativeValue) released() bool {
	return v == nil || v.gone.Load() || v.scope == nil || (v.scope.released.Load() && !v.persistent.Load())
}

func (v *nativeValue) usable() bool {
	return v != nil && v.loop != nil && !v.released() && !v.loop.closed.Load()
}

func (v *nativeValue) Export() interface{} {
	if !v.usable() {
		return nil
	}
	typ, err := v.typeOf()
	if err != nil {
		return nil
	}
	switch typ {
	case nativeTypeUndefined, nativeTypeNull:
		return nil
	case nativeTypeBool:
		var output C.uint32_t
		if err := v.valueCallBool(&output); err != nil {
			return nil
		}
		return output != 0
	case nativeTypeI64:
		var output C.int64_t
		if err := v.valueCallI64(&output); err != nil {
			return nil
		}
		return int64(output)
	case nativeTypeU64:
		var output C.uint64_t
		if err := v.valueCallU64(&output); err != nil {
			return nil
		}
		return uint64(output)
	case nativeTypeF64:
		var output C.double
		if err := v.valueCallF64(&output); err != nil {
			return nil
		}
		return float64(output)
	case nativeTypeString:
		text, _ := v.stringValue()
		return text
	case nativeTypeObject, nativeTypeHostObject:
		return &nativeObject{loop: v.loop, runtime: v.runtime, handle: v.handle, scope: v.scope}
	case nativeTypeHostFunction:
		return &nativeFunction{value: v}
	default:
		return nil
	}
}

func (v *nativeValue) ExportPrimitive() (any, error) {
	if !v.usable() {
		return nil, ErrNativeStaleValue
	}
	typ, err := v.typeOf()
	if err != nil {
		return nil, err
	}
	switch typ {
	case nativeTypeUndefined, nativeTypeNull:
		return nil, nil
	case nativeTypeBool:
		var output C.uint32_t
		if err := v.valueCallBool(&output); err != nil {
			return nil, err
		}
		return output != 0, nil
	case nativeTypeI64:
		var output C.int64_t
		if err := v.valueCallI64(&output); err != nil {
			return nil, err
		}
		return int64(output), nil
	case nativeTypeU64:
		var output C.uint64_t
		if err := v.valueCallU64(&output); err != nil {
			return nil, err
		}
		return uint64(output), nil
	case nativeTypeF64:
		var output C.double
		if err := v.valueCallF64(&output); err != nil {
			return nil, err
		}
		return float64(output), nil
	case nativeTypeString:
		return v.stringValue()
	case nativeTypeObject:
		return nil, fmt.Errorf("%w: object", jsengine.ErrPrimitiveExportUnsupported)
	case nativeTypeHostObject:
		return nil, fmt.Errorf("%w: host object", jsengine.ErrPrimitiveExportUnsupported)
	case nativeTypeHostFunction:
		return nil, fmt.Errorf("%w: host function", jsengine.ErrPrimitiveExportUnsupported)
	default:
		return nil, fmt.Errorf("%w: native type %d", jsengine.ErrPrimitiveExportUnsupported, typ)
	}
}

func (v *nativeValue) ToBoolean() bool {
	if !v.usable() {
		return false
	}
	var output C.uint32_t
	return v.valueCallBool(&output) == nil && output != 0
}

func (v *nativeValue) Object() jsengine.Object {
	if !v.usable() {
		return nil
	}
	typ, err := v.typeOf()
	if err != nil || (typ != nativeTypeObject && typ != nativeTypeHostObject) {
		return nil
	}
	return &nativeObject{loop: v.loop, runtime: v.runtime, handle: v.handle, scope: v.scope}
}

func (v *nativeValue) typeOf() (uint32, error) {
	var output C.uint32_t
	errorBuffer := make([]byte, 256)
	status := C.sc_native_value_type(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle), &output,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	return uint32(output), v.loop.operation(status, cError(errorBuffer))
}
func (v *nativeValue) valueCallBool(output *C.uint32_t) error {
	return v.callConversion(func(errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_to_bool(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle), output, errorBuffer, capacity)
	})
}
func (v *nativeValue) valueCallI64(output *C.int64_t) error {
	return v.callConversion(func(errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_to_i64(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle), output, errorBuffer, capacity)
	})
}
func (v *nativeValue) valueCallU64(output *C.uint64_t) error {
	return v.callConversion(func(errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_to_u64(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle), output, errorBuffer, capacity)
	})
}
func (v *nativeValue) valueCallF64(output *C.double) error {
	return v.callConversion(func(errorBuffer *C.char, capacity C.uint64_t) C.int {
		return C.sc_native_value_to_f64(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle), output, errorBuffer, capacity)
	})
}
func (v *nativeValue) callConversion(call func(*C.char, C.uint64_t) C.int) error {
	errorBuffer := make([]byte, 512)
	return v.loop.operation(call((*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer))), cError(errorBuffer))
}
func (v *nativeValue) stringValue() (string, error) {
	var required C.uint64_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_value_to_utf8_copy(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle), nil, 0, &required,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if status != C.SC_NATIVE_OK && required == 0 {
		return "", v.loop.operation(status, cError(errorBuffer))
	}
	if required == 0 {
		return "", nil
	}
	if uint64(required) > uint64(^uint(0)>>1) {
		return "", errors.New("native string is too large")
	}
	buffer := make([]byte, int(required))
	status = C.sc_native_value_to_utf8_copy(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle),
		(*C.char)(unsafe.Pointer(&buffer[0])), C.uint64_t(len(buffer)), &required,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if err := v.loop.operation(status, cError(errorBuffer)); err != nil {
		return "", err
	}
	if uint64(required) < uint64(len(buffer)) {
		buffer = buffer[:int(required)]
	}
	if len(buffer) > 0 && buffer[len(buffer)-1] == 0 {
		buffer = buffer[:len(buffer)-1]
	}
	return string(buffer), nil
}
func (v *nativeValue) retain() error {
	if !v.usable() {
		return ErrNativeClosed
	}
	if v.persistent.Load() {
		return nil
	}
	errorBuffer := make([]byte, 256)
	status := C.sc_native_value_retain(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if err := v.loop.operation(status, cError(errorBuffer)); err != nil {
		return err
	}
	v.persistent.Store(true)
	v.loop.registerPersistent(v.handle)
	return nil
}

func (v *nativeValue) releasePersistent() error {
	if v == nil || v.loop == nil || v.scope == nil || v.loop.closed.Load() || !v.persistent.Swap(false) {
		return ErrNativeClosed
	}
	v.loop.unregisterPersistent(v.handle)
	C.sc_native_value_release(C.uint64_t(v.loop.provider.library), C.uint64_t(v.runtime), C.uint64_t(v.handle))
	if v.scope.released.Load() {
		v.gone.Store(true)
	}
	return nil
}

type nativeObject struct {
	loop    *nativeLoop
	runtime uint64
	handle  uint64
	scope   *nativeScope
}

func (o *nativeObject) usable() bool {
	return o != nil && o.loop != nil && !o.loop.closed.Load() &&
		o.scope != nil && !o.scope.released.Load() && o.handle != 0
}

func (o *nativeObject) Set(name string, raw interface{}) error {
	if !o.usable() {
		return ErrNativeClosed
	}
	value, err := (&nativeRuntime{loop: o.loop, scope: o.scope}).coerce(raw)
	if err != nil {
		return err
	}
	key := []byte(name)
	var keyPtr *C.char
	if len(key) > 0 {
		keyPtr = (*C.char)(unsafe.Pointer(&key[0]))
	}
	errorBuffer := make([]byte, 512)
	status := C.sc_native_object_set(C.uint64_t(o.loop.provider.library), C.uint64_t(o.runtime), C.uint64_t(o.handle),
		keyPtr, C.uint64_t(len(key)), C.uint64_t(value.handle), (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(key)
	return o.loop.operation(status, cError(errorBuffer))
}

func (o *nativeObject) Get(name string) jsengine.Value {
	if !o.usable() {
		return nil
	}
	key := []byte(name)
	var keyPtr *C.char
	if len(key) > 0 {
		keyPtr = (*C.char)(unsafe.Pointer(&key[0]))
	}
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_object_get(C.uint64_t(o.loop.provider.library), C.uint64_t(o.runtime), C.uint64_t(o.handle),
		keyPtr, C.uint64_t(len(key)), &output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(key)
	if status != C.SC_NATIVE_OK {
		return (&nativeRuntime{loop: o.loop, scope: o.scope}).undefined()
	}
	return o.scope.value(uint64(output))
}

func (o *nativeObject) Has(name string) bool {
	if !o.usable() {
		return false
	}
	key := []byte(name)
	var keyPtr *C.char
	if len(key) > 0 {
		keyPtr = (*C.char)(unsafe.Pointer(&key[0]))
	}
	var output C.uint32_t
	errorBuffer := make([]byte, 512)
	status := C.sc_native_object_has(C.uint64_t(o.loop.provider.library), C.uint64_t(o.runtime), C.uint64_t(o.handle),
		keyPtr, C.uint64_t(len(key)), &output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(key)
	return status == C.SC_NATIVE_OK && output != 0
}

type nativeFunction struct{ value *nativeValue }

func (f *nativeFunction) Call(thisValue jsengine.Value, args ...interface{}) (jsengine.Value, error) {
	if f == nil || f.value == nil || !f.value.usable() || f.value.scope == nil || f.value.scope.released.Load() {
		return nil, ErrNativeStaleValue
	}
	rt := &nativeRuntime{loop: f.value.loop, scope: f.value.scope}
	var thisHandle uint64
	if thisValue != nil {
		v, ok := thisValue.(*nativeValue)
		if !ok {
			return nil, errors.New("native function this value belongs to another engine")
		}
		if _, err := rt.sameValue(v); err != nil {
			return nil, err
		}
		thisHandle = v.handle
	}
	handles := make([]C.uint64_t, len(args))
	for i, arg := range args {
		v, err := rt.coerce(arg)
		if err != nil {
			return nil, fmt.Errorf("argument %d: %w", i+1, err)
		}
		handles[i] = C.uint64_t(v.handle)
	}
	var output C.uint64_t
	errorBuffer := make([]byte, 512)
	var argv *C.uint64_t
	if len(handles) != 0 {
		argv = &handles[0]
	}
	status := C.sc_native_function_call(C.uint64_t(f.value.loop.provider.library), C.uint64_t(f.value.runtime), C.uint64_t(f.value.handle), C.uint64_t(thisHandle), argv, C.uint64_t(len(handles)), &output, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	runtime.KeepAlive(handles)
	if err := f.value.loop.operation(status, cError(errorBuffer)); err != nil {
		return nil, err
	}
	return f.value.scope.value(uint64(output)), nil
}

func filepathAbs(path string) (string, error) {
	return filepath.Abs(path)
}

func ResidentLibraryCount() uint64 {
	return uint64(C.sc_native_resident_count())
}

var _ jsengine.Loop = (*nativeLoop)(nil)
var _ jsengine.Runtime = (*nativeRuntime)(nil)
var _ jsengine.Value = (*nativeValue)(nil)
var _ jsengine.Object = (*nativeObject)(nil)
