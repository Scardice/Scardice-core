//go:build cgo

package native

/*
#cgo linux LDFLAGS: -ldl
#cgo freebsd LDFLAGS: -ldl
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
static uint64_t sc_native_thread_id(void) { return (uint64_t)GetCurrentThreadId(); }
#else
#include <pthread.h>
static uint64_t sc_native_thread_id(void) { return (uint64_t)(uintptr_t)pthread_self(); }
#endif
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
	"time"
	"unsafe"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostbridge"
	jsservices "Scardice-core/utils/jsengine/services"
)

const (
	hostABIMajor    = 1
	hostABIMinor    = 1
	runtimeABIMajor = 1
	runtimeABIMinor = 0

	nativeTypeUndefined    = C.SC_VALUE_TYPE_UNDEFINED
	nativeTypeNull         = C.SC_VALUE_TYPE_NULL
	nativeTypeBool         = C.SC_VALUE_TYPE_BOOL
	nativeTypeI64          = C.SC_VALUE_TYPE_I64
	nativeTypeU64          = C.SC_VALUE_TYPE_U64
	nativeTypeF64          = C.SC_VALUE_TYPE_F64
	nativeTypeString       = C.SC_VALUE_TYPE_STRING
	nativeTypeObject       = C.SC_VALUE_TYPE_OBJECT
	nativeTypeHostObject   = C.SC_VALUE_TYPE_HOST_OBJECT
	nativeTypeHostFunction = C.SC_VALUE_TYPE_HOST_FUNCTION
	nativeTypeFunction     = C.SC_VALUE_TYPE_FUNCTION
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
		Author:       candidate.Manifest.Author,
		ABIMajor:     uint32(raw.abi_major),
		ABIMinor:     uint32(raw.abi_minor),
		HostABIMajor: uint32(raw.host_abi_major),
		HostABIMinor: uint32(raw.host_abi_minor),
		Capabilities: jsengine.CapabilitySet(raw.capabilities),
		Services:     append([]string(nil), candidate.Manifest.Services...),
		Extensions:   append([]string(nil), candidate.Manifest.Extensions...),
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
	case int(C.SC_NATIVE_UNSUPPORTED):
		sentinel = ErrNativeContextUnsupported
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
		provider:      p,
		tasks:         make(chan nativeTask),
		done:          make(chan struct{}),
		eventWake:     make(chan struct{}, 1),
		persistent:    make(map[uint64]uint32),
		contexts:      make(map[uint64]any),
		contextTokens: make(map[any]uint64),
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
type nativeServiceEvent struct {
	kind     jsservices.EventKind
	request  jsservices.RequestID
	response jsservices.Response
}

// nativeScheduledCall carries a callback queued for the owner thread. The token
// keeps its execution context alive until the callback has run.
type nativeScheduledCall struct {
	token   uint64
	context any
	fn      func(*nativeRuntime) error
}

type nativeLoop struct {
	provider    *Provider
	runtime     uint64
	ownerThread atomic.Uint64

	tasks     chan nativeTask
	done      chan struct{}
	eventWake chan struct{}
	closed    atomic.Bool
	once      sync.Once

	// runMu closes the admission window before shutdown enqueues its stop
	// task. Calls already admitted finish before provider.stop runs.
	runMu sync.RWMutex

	closeMu  sync.Mutex
	closeErr error

	host       *nativeHostState
	hostHandle cgo.Handle

	serviceEventMu  sync.Mutex
	serviceEvents   []nativeServiceEvent
	tickErrorBuffer [512]byte

	scheduledMu sync.Mutex
	scheduled   []nativeScheduledCall

	persistentMu sync.Mutex
	persistent   map[uint64]uint32

	contextMu      sync.RWMutex
	contexts       map[uint64]any
	contextTokens  map[any]uint64
	currentContext any
	currentToken   uint64
	nextToken      uint64
}

func (l *nativeLoop) Engine() jsengine.EngineID { return l.provider.descriptor.ID }
func (l *nativeLoop) onOwnerThread() bool {
	if l == nil {
		return false
	}
	owner := l.ownerThread.Load()
	return owner != 0 && owner == uint64(C.sc_native_thread_id())
}

// registerContext returns the provider token that identifies context.
//
// Tokens are interned and outlive the call that introduced them: the provider
// stores them on timers, pending Promises, and outstanding service requests, so
// a token released when its first callback returned would leave later
// asynchronous callbacks without a context. Interning keeps the table bounded by
// the number of distinct contexts instead of the number of realm entries, and
// shutdown clears it.
func (l *nativeLoop) registerContext(context any) uint64 {
	if context == nil {
		return 0
	}
	key, keyed := nativeContextKey(context)
	l.contextMu.Lock()
	defer l.contextMu.Unlock()
	if keyed {
		if token, ok := l.contextTokens[key]; ok {
			l.contexts[token] = context
			return token
		}
	}
	l.nextToken++
	if l.nextToken == 0 {
		l.nextToken++
	}
	token := l.nextToken
	l.contexts[token] = context
	if keyed {
		l.contextTokens[key] = token
	}
	return token
}

// nativeContextKey resolves the interning identity of a context. A context that
// declares no identity and is not comparable cannot be interned.
func nativeContextKey(context any) (any, bool) {
	if keyer, ok := context.(jsengine.ContextKeyer); ok {
		key := keyer.ContextKey()
		if key != nil && reflect.TypeOf(key).Comparable() {
			return key, true
		}
		return nil, false
	}
	if reflect.TypeOf(context).Comparable() {
		return context, true
	}
	return nil, false
}

func (l *nativeLoop) currentNativeToken() uint64 {
	if l != nil && l.onOwnerThread() && l.runtime != 0 {
		return uint64(C.sc_native_current_context(
			C.uint64_t(l.provider.library), C.uint64_t(l.runtime)))
	}
	l.contextMu.RLock()
	defer l.contextMu.RUnlock()
	return l.currentToken
}

func (l *nativeLoop) CurrentContext() any {
	if l == nil {
		return nil
	}
	token := l.currentNativeToken()
	l.contextMu.RLock()
	defer l.contextMu.RUnlock()
	if token != 0 {
		return l.contexts[token]
	}
	return l.currentContext
}

func (l *nativeLoop) setNativeToken(token uint64) error {
	errorBuffer := make([]byte, 256)
	status := C.sc_native_set_context(
		C.uint64_t(l.provider.library), C.uint64_t(l.runtime), C.uint64_t(token),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if status == C.SC_NATIVE_UNSUPPORTED && token == 0 {
		return nil
	}
	return l.operation(status, cError(errorBuffer))
}

func (l *nativeLoop) enterContext(token uint64, context any) (uint64, any, error) {
	previousToken := l.currentNativeToken()
	l.contextMu.Lock()
	previousContext := l.currentContext
	l.currentToken = token
	l.currentContext = context
	l.contextMu.Unlock()
	if err := l.setNativeToken(token); err != nil {
		l.contextMu.Lock()
		l.currentToken = previousToken
		l.currentContext = previousContext
		l.contextMu.Unlock()
		return 0, nil, err
	}
	return previousToken, previousContext, nil
}

func (l *nativeLoop) leaveContext(previousToken uint64, previousContext any) error {
	err := l.setNativeToken(previousToken)
	l.contextMu.Lock()
	l.currentToken = previousToken
	l.currentContext = previousContext
	l.contextMu.Unlock()
	return err
}

func (l *nativeLoop) Descriptor() jsengine.Descriptor { return l.provider.descriptor }
func (l *nativeLoop) enqueueServiceEvent(event nativeServiceEvent) error {
	if l == nil || l.closed.Load() {
		return ErrNativeClosed
	}
	event.response.Bytes = append([]byte(nil), event.response.Bytes...)
	l.serviceEventMu.Lock()
	if l.closed.Load() {
		l.serviceEventMu.Unlock()
		return ErrNativeClosed
	}
	l.serviceEvents = append(l.serviceEvents, event)
	l.serviceEventMu.Unlock()
	select {
	case l.eventWake <- struct{}{}:
	default:
	}
	return nil
}

func (l *nativeLoop) takeServiceEvents() []nativeServiceEvent {
	l.serviceEventMu.Lock()
	defer l.serviceEventMu.Unlock()
	events := l.serviceEvents
	l.serviceEvents = nil
	return events
}

func (l *nativeLoop) discardServiceEvents() {
	l.serviceEventMu.Lock()
	l.serviceEvents = nil
	l.serviceEventMu.Unlock()
}

func (l *nativeLoop) drainServiceEvents() {
	for _, event := range l.takeServiceEvents() {
		if err := l.deliverServiceEvent(event); err != nil && l.host != nil {
			l.host.setError(err)
		}
	}
}

func (l *nativeLoop) deliverServiceEvent(event nativeServiceEvent) error {
	if l == nil || l.provider == nil || l.closed.Load() {
		return ErrNativeClosed
	}
	stringBytes := []byte(event.response.String)
	var stringPtr *C.char
	if len(stringBytes) != 0 {
		stringPtr = (*C.char)(unsafe.Pointer(&stringBytes[0]))
	}
	bytes := event.response.Bytes
	var bytesPtr *C.uint8_t
	if len(bytes) != 0 {
		bytesPtr = (*C.uint8_t)(unsafe.Pointer(&bytes[0]))
	}
	errorBuffer := make([]byte, 512)
	boolValue := C.uint32_t(0)
	if event.response.Bool {
		boolValue = 1
	}
	status := C.sc_native_service_event(
		C.uint64_t(l.provider.library),
		C.uint64_t(l.runtime),
		C.uint32_t(event.kind),
		C.uint32_t(event.response.Status),
		C.uint64_t(event.request),
		stringPtr,
		C.uint64_t(len(stringBytes)),
		bytesPtr,
		C.uint64_t(len(bytes)),
		boolValue,
		C.int64_t(event.response.Int64),
		C.uint64_t(event.response.Uint64),
		C.double(event.response.Float64),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])),
		C.uint64_t(len(errorBuffer)),
	)
	runtime.KeepAlive(stringBytes)
	runtime.KeepAlive(bytes)
	return l.operation(status, cError(errorBuffer))
}

// InstallServiceRegistry attaches the engine-neutral service registry to a
// native loop before JavaScript invokes a provider-installed host service.
func InstallServiceRegistry(loop jsengine.Loop, registry *jsservices.Registry) error {
	if loop == nil {
		return errors.New("native service registry loop is nil")
	}
	if registry == nil {
		return errors.New("native service registry is nil")
	}
	nativeLoop, ok := loop.(*nativeLoop)
	if !ok {
		return fmt.Errorf("loop %q is not a native runtime", loop.Engine())
	}
	return nativeLoop.Run(func(runtime jsengine.Runtime) error {
		nativeRuntime, ok := runtime.(*nativeRuntime)
		if !ok || nativeRuntime.loop == nil || nativeRuntime.loop.host == nil {
			return errors.New("native host state is unavailable")
		}
		nativeRuntime.loop.host.setServiceRegistry(registry)
		return nil
	})
}

const nativeTickInterval = time.Millisecond

func (l *nativeLoop) tick() {
	if l == nil || l.closed.Load() || l.runtime == 0 {
		return
	}
	status := C.sc_native_tick(
		C.uint64_t(l.provider.library), C.uint64_t(l.runtime),
		(*C.char)(unsafe.Pointer(&l.tickErrorBuffer[0])), C.uint64_t(len(l.tickErrorBuffer)),
	)
	if err := l.operation(status, cError(l.tickErrorBuffer[:])); err != nil && l.host != nil {
		l.host.setError(err)
	}
}

func (l *nativeLoop) worker(options jsengine.RuntimeOptions, ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.ownerThread.Store(uint64(C.sc_native_thread_id()))

	host := newNativeHostState(l)
	l.host = host
	l.hostHandle = cgo.NewHandle(host)
	payload := options.PayloadFor(l.provider.descriptor.ID)
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

	ticker := time.NewTicker(nativeTickInterval)
	defer ticker.Stop()
	for {
		select {
		case task := <-l.tasks:
			if task.stop {
				err := l.shutdown()
				task.done <- err
				return
			}
			rt := &nativeRuntime{loop: l, scope: newNativeScope(l)}
			err := runNativeTask(rt, task.fn)
			rt.scope.release()
			task.done <- err
		case <-l.eventWake:
			l.drainServiceEvents()
			l.drainScheduled()
			l.tick()
		case <-ticker.C:
			l.drainScheduled()
			l.tick()
		}
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
	return l.RunWithContext(l.CurrentContext(), run)
}

func (l *nativeLoop) RunWithContext(context any, run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("native runtime callback is nil")
	}
	l.runMu.RLock()
	defer l.runMu.RUnlock()
	if l.closed.Load() {
		return ErrNativeClosed
	}
	token := l.registerContext(context)
	runTask := func(rt *nativeRuntime) (callbackErr error) {
		previousToken, previousContext, err := l.enterContext(token, context)
		if err != nil {
			return err
		}
		defer func() {
			if restoreErr := l.leaveContext(previousToken, previousContext); callbackErr == nil {
				callbackErr = restoreErr
			}
		}()
		return run(rt)
	}
	if l.onOwnerThread() {
		rt := &nativeRuntime{loop: l, scope: newNativeScope(l)}
		err := runNativeTask(rt, runTask)
		rt.scope.release()
		return err
	}
	task := nativeTask{done: make(chan error, 1), fn: runTask}
	select {
	case l.tasks <- task:
	case <-l.done:
		return ErrNativeClosed
	}
	return <-task.done
}

// Schedule queues a callback for the owner thread without waiting for it.
func (l *nativeLoop) Schedule(run func(jsengine.Runtime) error) error {
	return l.ScheduleWithContext(l.CurrentContext(), run)
}

// ScheduleWithContext queues a context-aware callback for the owner thread.
// It never waits, so it is safe from inside a native callback, a provider
// timer, or a host service completion.
func (l *nativeLoop) ScheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("native runtime callback is nil")
	}
	l.runMu.RLock()
	defer l.runMu.RUnlock()
	if l.closed.Load() {
		return ErrNativeClosed
	}
	token := l.registerContext(context)
	call := nativeScheduledCall{token: token, context: context, fn: func(rt *nativeRuntime) error {
		return run(rt)
	}}
	l.scheduledMu.Lock()
	if l.closed.Load() {
		l.scheduledMu.Unlock()
		return ErrNativeClosed
	}
	l.scheduled = append(l.scheduled, call)
	l.scheduledMu.Unlock()
	select {
	case l.eventWake <- struct{}{}:
	default:
	}
	return nil
}

func (l *nativeLoop) takeScheduled() []nativeScheduledCall {
	l.scheduledMu.Lock()
	defer l.scheduledMu.Unlock()
	calls := l.scheduled
	l.scheduled = nil
	return calls
}

// discardScheduled drops queued callbacks. Queued work must never run after the
// provider has been stopped.
func (l *nativeLoop) discardScheduled() {
	l.scheduledMu.Lock()
	l.scheduled = nil
	l.scheduledMu.Unlock()
}

func (l *nativeLoop) drainScheduled() {
	for _, call := range l.takeScheduled() {
		l.runScheduled(call)
	}
}

func (l *nativeLoop) runScheduled(call nativeScheduledCall) {
	if l.closed.Load() {
		return
	}
	previousToken, previousContext, err := l.enterContext(call.token, call.context)
	if err != nil {
		if l.host != nil {
			l.host.setError(err)
		}
		return
	}
	rt := &nativeRuntime{loop: l, scope: newNativeScope(l)}
	callbackErr := runNativeTask(rt, call.fn)
	rt.scope.release()
	if restoreErr := l.leaveContext(previousToken, previousContext); callbackErr == nil {
		callbackErr = restoreErr
	}
	if callbackErr != nil && l.host != nil {
		l.host.setError(callbackErr)
	}
}

func (l *nativeLoop) LoadEntry(entry jsengine.Entry) error {
	return l.LoadEntryWithContext(l.CurrentContext(), entry)
}

func (l *nativeLoop) LoadEntryWithContext(context any, entry jsengine.Entry) error {
	return l.RunWithContext(context, func(rt jsengine.Runtime) error {
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
		l.runMu.Lock()
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
		l.runMu.Unlock()
	})
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	return l.closeErr
}

func (l *nativeLoop) shutdown() error {
	errorBuffer := make([]byte, 512)
	var first error
	l.discardServiceEvents()
	l.discardScheduled()

	// provider.stop must run while the runtime and all persistent values are
	// still valid. Host callbacks are then released before provider.destroy.
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
	}
	l.contextMu.Lock()
	l.contexts = make(map[uint64]any)
	l.contextTokens = make(map[any]uint64)
	l.currentContext = nil
	l.currentToken = 0
	l.contextMu.Unlock()
	if status := C.sc_native_destroy(C.uint64_t(l.provider.library), C.uint64_t(l.runtime),
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer))); status != C.SC_NATIVE_OK && first == nil {
		first = wrapOperationError(status, l.provider.candidate.LibraryPath, cError(errorBuffer))
	}
	if l.host != nil {
		// HostRef/HostFunc registries are invalid after provider.destroy. The
		// teardown also advances the generation used by stale callbacks.
		l.host.session.Teardown()
	}
	l.runtime = 0
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

// ExposeDangerous implements the optional engine-neutral dangerous exposure
// capability. It is only reachable when the caller explicitly enables
// seal.inst.
func (r *nativeRuntime) ExposeDangerous(target interface{}) (jsengine.Value, error) {
	if r == nil || r.loop == nil || r.loop.host == nil {
		return nil, errors.New("native runtime is required")
	}
	ref, err := r.loop.host.session.ExposeDangerous(target)
	if err != nil {
		return nil, err
	}
	return r.newHostObject(ref, uint32(hostbridge.KindHostObject))
}

// ExposeDangerous is retained as a compatibility helper for native callers;
// core execution uses the engine-neutral runtime capability above.
func ExposeDangerous(engine jsengine.Runtime, target interface{}) (jsengine.Value, error) {
	exposer, ok := engine.(jsengine.DangerousExposer)
	if !ok {
		return nil, errors.New("native runtime is required")
	}
	return exposer.ExposeDangerous(target)
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
	if object, ok := raw.(*nativeObject); ok {
		return r.objectValue(object)
	}
	if object, ok := raw.(jsengine.Object); ok {
		nativeObject, ok := object.(*nativeObject)
		if !ok {
			return nil, errors.New("native runtime cannot consume an object from another engine")
		}
		return r.objectValue(nativeObject)
	}
	if value, ok := raw.(*nativeValue); ok {
		return r.sameValue(value)
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
func (r *nativeRuntime) objectValue(object *nativeObject) (*nativeValue, error) {
	if object == nil || r == nil || r.loop == nil || r.loop.closed.Load() ||
		object.loop != r.loop || object.runtime != r.loop.runtime ||
		object.scope == nil || object.scope.released.Load() || object.handle == 0 {
		return nil, errors.New("native object belongs to another or closed runtime")
	}
	return &nativeValue{
		loop:    r.loop,
		runtime: r.loop.runtime,
		handle:  object.handle,
		scope:   object.scope,
	}, nil
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
