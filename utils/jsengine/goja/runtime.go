// Package goja adapts Goja to the engine-neutral runtime contract.
package goja

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"

	"Scardice-core/utils/jsengine"
)

var realms sync.Map

var (
	errJSONParseUnavailable = errors.New("Goja JSON.parse intrinsic is unavailable")
	errGojaStaleValue       = errors.New("Goja value belongs to an expired runtime callback")
)

type fieldNameMapper struct {
	fallback goja.FieldNameMapper
	legacy   goja.FieldNameMapper
}

// FieldNameMapper prefers provider-specific legacy tags where a shared public
// property still needs the Goja ABI, while hiding the neutral field alias in
// Goja. Other jsbind names retain the normal mapper behavior.
func FieldNameMapper() goja.FieldNameMapper {
	return fieldNameMapper{
		fallback: goja.TagFieldNameMapper("jsbind", true),
		legacy:   goja.TagFieldNameMapper("jsbindgoja", true),
	}
}

func (m fieldNameMapper) FieldName(t reflect.Type, field reflect.StructField) string {
	if _, ok := field.Tag.Lookup("jsbindgoja"); ok {
		return m.legacy.FieldName(t, field)
	}
	name := m.fallback.FieldName(t, field)
	if name == "" {
		return ""
	}
	for typ := t; typ.Kind() == reflect.Pointer; typ = typ.Elem() {
		t = typ
	}
	if t.Kind() != reflect.Struct {
		return name
	}
	for index := range t.NumField() {
		candidate := t.Field(index)
		if _, ok := candidate.Tag.Lookup("jsbindgoja"); ok && m.legacy.FieldName(t, candidate) == name {
			return ""
		}
	}
	return name
}

func (m fieldNameMapper) MethodName(t reflect.Type, method reflect.Method) string {
	return m.fallback.MethodName(t, method)
}

var eventRealms sync.Map

type contextState struct {
	mu      sync.RWMutex
	current any
}

func (s *contextState) currentContext() any {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *contextState) replaceContext(context any) (previous any) {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	previous = s.current
	s.current = context
	s.mu.Unlock()
	return previous
}

func (s *contextState) with(context any, run func() error) (err error) {
	if s == nil {
		return run()
	}
	leave, err := jsengine.EnterExecution(context, s.currentContext())
	if err != nil {
		return err
	}
	defer leave()
	s.mu.Lock()
	previous := s.current
	s.current = context
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.current = previous
		s.mu.Unlock()
	}()
	return run()
}

type realm struct {
	vm          *goja.Runtime
	state       *contextState
	tracker     *asyncContextTracker
	promiseThen goja.Callable
	jsonParse   goja.Callable
	jsonMu      sync.RWMutex
	closed      atomic.Bool

	promiseMu     sync.Mutex
	promises      map[*promiseObservation]struct{}
	promiseClosed bool
}

func newRealm() *realm {
	state := &contextState{}
	return &realm{
		state:   state,
		tracker: &asyncContextTracker{state: state},
	}
}

func (r *realm) attach(vm *goja.Runtime) {
	if r == nil || vm == nil || r.vm == vm {
		return
	}
	r.vm = vm
	r.tracker.vm = vm
	r.promiseThen = nil
	var jsonParse goja.Callable
	_ = vm.Try(func() {
		if jsonObject, ok := vm.Get("JSON").(*goja.Object); ok {
			jsonParse, _ = goja.AssertFunction(jsonObject.Get("parse"))
		}
		if promise, ok := vm.Get("Promise").(*goja.Object); ok {
			if prototype, ok := promise.Get("prototype").(*goja.Object); ok {
				r.promiseThen, _ = goja.AssertFunction(prototype.Get("then"))
			}
		}
	})
	r.jsonMu.Lock()
	r.jsonParse = jsonParse
	r.jsonMu.Unlock()
	vm.SetAsyncContextTracker(r.tracker)
}

func (r *realm) close() {
	if r == nil || r.closed.Swap(true) {
		return
	}
	r.jsonMu.Lock()
	r.jsonParse = nil
	r.jsonMu.Unlock()
	r.closePromiseObservations()
	if r.tracker != nil {
		r.tracker.close()
	}
}

func publishRealm(vm *goja.Runtime, candidate *realm) *realm {
	if existing, ok := realms.Load(vm); ok {
		realm := existing.(*realm)
		realm.attach(vm)
		return realm
	}
	actual, _ := realms.LoadOrStore(vm, candidate)
	realm := actual.(*realm)
	realm.attach(vm)
	return realm
}

func realmFor(vm *goja.Runtime) *realm {
	if vm == nil {
		return newRealm()
	}
	if existing, ok := realms.Load(vm); ok {
		realm := existing.(*realm)
		realm.attach(vm)
		return realm
	}
	return publishRealm(vm, newRealm())
}

type runtime struct {
	vm    *goja.Runtime
	realm *realm

	nextValueScope   atomic.Uint64
	activeValueScope atomic.Uint64
}

type eventLoop struct {
	loop      *eventloop.EventLoop
	realm     atomic.Pointer[realm]
	closed    atomic.Bool
	running   atomic.Bool
	once      sync.Once
	context   atomic.Bool
	observer  atomic.Pointer[observerBox]
	depth     atomic.Int32
	ownerGID  atomic.Uint64
	started   chan struct{}
	startOnce sync.Once
	vm        atomic.Pointer[goja.Runtime]
}

func currentGoroutineID() uint64 {
	var buffer [64]byte
	n := goruntime.Stack(buffer[:], false)
	fields := bytes.Fields(buffer[:n])
	if len(fields) < 2 {
		return 0
	}
	id, _ := strconv.ParseUint(string(fields[1]), 10, 64)
	return id
}

type value struct {
	value goja.Value
	realm *realm
	owner *runtime
	scope uint64
}

type object struct {
	value *goja.Object
	realm *realm
	owner *runtime
	scope uint64
}

func (r *runtime) enterValueScope() uint64 {
	previous := r.activeValueScope.Load()
	next := r.nextValueScope.Add(1)
	if next == 0 {
		next = r.nextValueScope.Add(1)
	}
	r.activeValueScope.Store(next)
	return previous
}

func (r *runtime) leaveValueScope(previous uint64) {
	r.activeValueScope.Store(previous)
}

func (r *runtime) valueScope() (*runtime, uint64) {
	if r == nil {
		return nil, 0
	}
	scope := r.activeValueScope.Load()
	if scope == 0 {
		return nil, 0
	}
	return r, scope
}

func (r *runtime) ownsValueScope(scope uint64) bool {
	return r != nil && scope != 0 && r.activeValueScope.Load() == scope
}

// New creates an isolated Goja realm.
func New() jsengine.Loop {
	vm := goja.New()
	vm.SetFieldNameMapper(FieldNameMapper())
	return &runtime{vm: vm, realm: realmFor(vm)}
}

// Wrap adapts an existing Goja runtime for shared Host API installers.
// The caller retains ownership of the runtime and its event loop.
func Wrap(vm *goja.Runtime) jsengine.Runtime {
	return &runtime{vm: vm, realm: realmFor(vm)}
}

// WrapEventLoop adapts the legacy Goja event loop to jsengine.Loop.
// The event loop remains owned by the caller until Close is invoked.
func WrapEventLoop(loop *eventloop.EventLoop) jsengine.Loop {
	if existing, ok := eventRealms.Load(loop); ok {
		return existing.(*eventLoop)
	}
	created := &eventLoop{
		loop:    loop,
		started: make(chan struct{}),
	}
	created.realm.Store(newRealm())
	actual, _ := eventRealms.LoadOrStore(loop, created)
	return actual.(*eventLoop)
}

func (l *eventLoop) currentRealm() *realm {
	if l == nil {
		return nil
	}
	return l.realm.Load()
}

func (l *eventLoop) attachRealm(vm *goja.Runtime) *realm {
	candidate := l.currentRealm()
	if candidate == nil {
		candidate = newRealm()
	}
	realm := publishRealm(vm, candidate)
	l.realm.Store(realm)
	return realm
}

// signalStarted releases callers waiting for StartInForeground to claim the
// adapter. It is separate from running so Open can close its setup/start race.
func (l *eventLoop) signalStarted() {
	if l == nil || l.started == nil {
		return
	}
	l.startOnce.Do(func() { close(l.started) })
}

// StartInForeground runs a wrapped event loop until it is closed.
func StartInForeground(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.closed.Load() {
		adapter.signalStarted()
		return errors.New("goja event loop is closed")
	}
	if !adapter.running.CompareAndSwap(false, true) {
		adapter.signalStarted()
		return errors.New("goja event loop is already running")
	}
	adapter.signalStarted()
	owner := currentGoroutineID()
	previousOwner := adapter.ownerGID.Load()
	if owner != 0 {
		adapter.ownerGID.Store(owner)
		defer adapter.ownerGID.Store(previousOwner)
	}
	defer adapter.running.Store(false)
	var runErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				runErr = fmt.Errorf("goja event loop panic: %v", recovered)
			}
		}()
		adapter.loop.StartInForeground()
	}()
	return runErr
}

func (l *eventLoop) Engine() jsengine.EngineID { return jsengine.EngineGoja }

func (l *eventLoop) Descriptor() jsengine.Descriptor {
	return (&runtime{}).Descriptor()
}

// WaitUntilStarted waits until StartInForeground has claimed loop ownership.
func WaitUntilStarted(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.started == nil {
		return errors.New("goja event loop start signal is unavailable")
	}
	<-adapter.started
	return nil
}

// observerBox lets a nil-able interface live behind an atomic pointer.
type observerBox struct{ jsengine.InvocationObserver }

// SetInvocationObserver implements jsengine.ObservableLoop.
func (l *eventLoop) SetInvocationObserver(observer jsengine.InvocationObserver) {
	if l == nil {
		return
	}
	if observer == nil {
		l.observer.Store(nil)
		return
	}
	l.observer.Store(&observerBox{observer})
}

// observe reports the outermost invocation on this loop to the observer. Work
// that runs nested inside a reported invocation belongs to its window.
func (l *eventLoop) observe(context any, phase jsengine.InvocationPhase, run func() error) error {
	box := l.observer.Load()
	if box == nil {
		return run()
	}
	defer l.depth.Add(-1)
	if l.depth.Add(1) != 1 {
		return run()
	}
	return box.ObserveInvocation(context, phase, run)
}

func (l *eventLoop) invoke(context any, phase jsengine.InvocationPhase, run func(jsengine.Runtime) error, vm *goja.Runtime) error {
	l.vm.Store(vm)
	realm := l.attachRealm(vm)
	rootBoundary := realm.tracker.enterBoundary()
	defer realm.tracker.exitBoundary(rootBoundary)
	owner := currentGoroutineID()
	previousOwner := l.ownerGID.Load()
	if owner != 0 && previousOwner != owner {
		l.ownerGID.Store(owner)
		defer l.ownerGID.Store(previousOwner)
	}
	return realm.state.with(context, func() error {
		return runWithExecutionContext(jsengine.ContextForExecution(context), vm, func() error {
			// Allocate the runtime handle before the window opens so the
			// observer measures the callback and not the adapter.
			rt := &runtime{vm: vm, realm: realm}
			previousScope := rt.enterValueScope()
			defer rt.leaveValueScope(previousScope)
			return l.observe(context, phase, func() error { return run(rt) })
		})
	})
}

func (l *eventLoop) runWithContext(context any, phase jsengine.InvocationPhase, run func(jsengine.Runtime) error) (err error) {
	if run == nil {
		return errors.New("goja runtime callback is nil")
	}
	if l == nil || l.loop == nil || l.closed.Load() {
		return errors.New("goja event loop is closed")
	}
	execution := jsengine.ContextForExecution(context)
	if err := execution.Err(); err != nil {
		return err
	}
	if l.running.Load() {
		done := make(chan error, 1)
		var state atomic.Int32 // queued=0, running=1, canceled=2
		if !l.loop.RunOnLoop(func(vm *goja.Runtime) {
			if !state.CompareAndSwap(0, 1) {
				done <- execution.Err()
				return
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					done <- fmt.Errorf("goja runtime callback panic: %v", recovered)
				}
			}()
			done <- l.invoke(context, phase, run, vm)
		}) {
			return errors.New("goja event loop is closed")
		}
		select {
		case err := <-done:
			return err
		case <-execution.Done():
			if state.CompareAndSwap(0, 2) {
				return execution.Err()
			}
			<-done //nolint:errcheck // Join the callback; cancellation takes precedence over its result.
			return execution.Err()
		}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("goja runtime callback panic: %v", recovered)
		}
	}()
	l.loop.Run(func(vm *goja.Runtime) {
		err = l.invoke(context, phase, run, vm)
	})
	return err
}

// scheduleWithContext queues a context-aware callback without waiting for it.
// Nothing observes the callback result, so a failure is contained instead of
// escaping into the event loop's panic accounting.
func (l *eventLoop) scheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("goja runtime callback is nil")
	}
	if l == nil || l.loop == nil || l.closed.Load() {
		return errors.New("goja event loop is closed")
	}
	if !l.loop.RunOnLoop(func(vm *goja.Runtime) {
		defer func() {
			_ = recover()
		}()
		_ = l.invoke(context, jsengine.InvocationSchedule, run, vm)
	}) {
		return errors.New("goja event loop is closed")
	}
	return nil
}

// ScheduleWithContext queues a context-aware callback on the owning event
// loop. It never waits for the callback, so it is the only entry point that is
// safe from inside a loop callback, a timer, a Promise continuation, or a host
// service completion.
func ScheduleWithContext(loop jsengine.Loop, context any, run func(jsengine.Runtime) error) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	return adapter.scheduleWithContext(context, run)
}

// ScheduleOnExistingEventLoop queues a raw Goja callback through an adapter
// that already owns loop. It never creates or retains an adapter for legacy
// raw-only loops; false tells the caller to use its original RunOnLoop path.
func ScheduleOnExistingEventLoop(loop *eventloop.EventLoop, context any, run func(*goja.Runtime) error) (bool, error) {
	if loop == nil {
		return false, errors.New("goja event loop is required")
	}
	existing, ok := eventRealms.Load(loop)
	if !ok {
		return false, nil
	}
	if run == nil {
		return true, errors.New("goja runtime callback is nil")
	}
	adapter := existing.(*eventLoop)
	err := adapter.scheduleWithContext(context, func(engine jsengine.Runtime) error {
		runtime, ok := engine.(*runtime)
		if !ok {
			return errors.New("goja runtime is required")
		}
		return run(runtime.vm)
	})
	return true, err
}

func (l *eventLoop) contextForDefaultEntry() any {
	if !l.InOwner() {
		return nil
	}
	return l.CurrentContext()
}

func (l *eventLoop) Run(run func(jsengine.Runtime) error) error {
	return l.runWithContext(l.contextForDefaultEntry(), jsengine.InvocationRun, run)
}

func (l *eventLoop) RunWithContext(context any, run func(jsengine.Runtime) error) error {
	return l.runWithContext(context, jsengine.InvocationRun, run)
}

func (l *eventLoop) Schedule(run func(jsengine.Runtime) error) error {
	return l.scheduleWithContext(l.contextForDefaultEntry(), run)
}

func (l *eventLoop) ScheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	return l.scheduleWithContext(context, run)
}

func (l *eventLoop) CurrentContext() any {
	realm := l.currentRealm()
	if realm == nil {
		return nil
	}
	return realm.state.currentContext()
}

func (l *eventLoop) InOwner() bool {
	return l != nil && l.ownerGID.Load() != 0 && l.ownerGID.Load() == currentGoroutineID()
}

func gojaLoadEntry(runtime jsengine.Runtime, entry jsengine.Entry) error {
	switch entry.Kind {
	case jsengine.EntryScript:
		_, err := runtime.RunString(entry.Filename, entry.Source)
		return err
	case jsengine.EntryCommonJS, jsengine.EntryExtension:
		_, err := runtime.LoadCommonJS(entry.Filename, entry.Source)
		return err
	case jsengine.EntryESModule:
		return errors.New("goja: ESM entries are unsupported")
	default:
		return errors.New("goja: unknown entry kind")
	}
}

func (l *eventLoop) LoadEntry(entry jsengine.Entry) error {
	return l.LoadEntryWithContext(l.contextForDefaultEntry(), entry)
}

func (l *eventLoop) LoadEntryWithContext(context any, entry jsengine.Entry) error {
	return l.runWithContext(context, jsengine.InvocationLoad, func(runtime jsengine.Runtime) error {
		return gojaLoadEntry(runtime, entry)
	})
}

func (l *eventLoop) Close() error {
	if l == nil || l.loop == nil {
		return nil
	}
	l.once.Do(func() {
		l.closed.Store(true)
		realm := l.currentRealm()
		if realm != nil {
			realm.close()
		}
		if vm := l.vm.Load(); vm != nil {
			vm.Interrupt(errors.New("goja event loop is closed"))
			if realm != nil {
				realms.CompareAndDelete(vm, realm)
			}
		}
		eventRealms.Delete(l.loop)
		l.loop.Terminate()
	})
	return nil
}

func (r *runtime) Engine() jsengine.EngineID {
	return jsengine.EngineGoja
}

func (r *runtime) Run(run func(jsengine.Runtime) error) error {
	return r.RunWithContext(r.CurrentContext(), run)
}

func (r *runtime) RunWithContext(context any, run func(jsengine.Runtime) error) error {
	if run == nil {
		return errors.New("goja runtime callback is nil")
	}
	rootBoundary := r.realm.tracker.enterBoundary()
	defer r.realm.tracker.exitBoundary(rootBoundary)
	previousScope := r.enterValueScope()
	defer r.leaveValueScope(previousScope)
	return r.realm.state.with(context, func() error {
		return runWithExecutionContext(jsengine.ContextForExecution(context), r.vm, func() error { return run(r) })
	})
}

// Schedule runs the callback inline. An isolated realm has no job queue and no
// owner goroutine to block, so immediate execution is the deferred execution.
func (r *runtime) Schedule(run func(jsengine.Runtime) error) error {
	return r.ScheduleWithContext(r.CurrentContext(), run)
}

func (r *runtime) ScheduleWithContext(context any, run func(jsengine.Runtime) error) error {
	return r.RunWithContext(context, run)
}

func (r *runtime) CurrentContext() any {
	if r == nil || r.realm == nil {
		return nil
	}
	return r.realm.state.currentContext()
}

func (r *runtime) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{
		ID:           jsengine.EngineGoja,
		Name:         "Goja",
		Version:      "builtin",
		Language:     "Go",
		Author:       "Scardice",
		Extensions:   []string{".js", ".ts"},
		Capabilities: jsengine.CapabilityScript.With(jsengine.CapabilityCommonJS, jsengine.CapabilityHostObject, jsengine.CapabilityHostFunction, jsengine.CapabilityContextPropagation),
		Builtin:      true,
	}
}

func (r *runtime) LoadEntry(entry jsengine.Entry) error {
	return r.LoadEntryWithContext(r.CurrentContext(), entry)
}

func (r *runtime) LoadEntryWithContext(context any, entry jsengine.Entry) error {
	return r.RunWithContext(context, func(runtime jsengine.Runtime) error {
		return gojaLoadEntry(runtime, entry)
	})
}

// Raw returns the underlying Goja runtime for legacy Goja-only integrations.
func Raw(engine jsengine.Runtime) (*goja.Runtime, bool) {
	runtime, ok := engine.(*runtime)
	if !ok {
		return nil, false
	}
	return runtime.vm, true
}

// WrapValue adapts a raw Goja value for engine-neutral Host installation.
func WrapValue(vm *goja.Runtime, raw goja.Value) jsengine.Value {
	return value{value: raw, realm: realmFor(vm)}
}

// WrapValueForRuntime adapts a raw Goja value for the realm owned by runtime.
// The raw value must have been created by the same Goja runtime.
func WrapValueForRuntime(engine jsengine.Runtime, raw goja.Value) (jsengine.Value, error) {
	adapter, ok := engine.(*runtime)
	if !ok || adapter == nil || adapter.vm == nil {
		return nil, errors.New("goja runtime is required")
	}
	owner, scope := adapter.valueScope()
	return value{value: raw, realm: adapter.realm, owner: owner, scope: scope}, nil
}

// UnwrapValueForRuntime returns the raw Goja value only when it belongs to the
// supplied runtime's realm and current callback scope. It is intended for
// legacy Goja callback slots that consume an engine-neutral value immediately.
func UnwrapValueForRuntime(engine jsengine.Runtime, adapted jsengine.Value) (goja.Value, error) {
	owner, ok := engine.(*runtime)
	if !ok || owner == nil || owner.vm == nil || owner.realm == nil || owner.realm.closed.Load() {
		return nil, errors.New("Goja runtime is required")
	}
	wrapped, ok := adapted.(value)
	if !ok || wrapped.realm == nil || wrapped.value == nil {
		return nil, errors.New("Goja value is required")
	}
	if wrapped.realm != owner.realm || owner.realm.vm != owner.vm {
		return nil, errors.New("Goja value belongs to another realm")
	}
	_, ownerScope := owner.valueScope()
	if err := validateValueScope(wrapped.owner, wrapped.scope, owner, ownerScope); err != nil {
		return nil, err
	}
	return wrapped.value, nil
}

func (r *runtime) RunString(filename, source string) (jsengine.Value, error) {
	program, err := goja.Compile(filename, source, false)
	if err != nil {
		return nil, err
	}

	result, err := r.vm.RunProgram(program)
	if err != nil {
		return nil, err
	}
	owner, scope := r.valueScope()
	return value{value: result, realm: r.realm, owner: owner, scope: scope}, nil
}

func (r *runtime) ParseJSON(raw string) (jsengine.Value, error) {
	if r == nil || r.vm == nil || r.realm == nil || r.realm.vm != r.vm {
		return nil, errors.New("Goja runtime is closed")
	}
	owner, scope := r.valueScope()
	if owner == nil {
		return nil, errGojaStaleValue
	}
	r.realm.jsonMu.RLock()
	defer r.realm.jsonMu.RUnlock()
	if r.realm.closed.Load() {
		return nil, errors.New("Goja runtime is closed")
	}
	if r.realm.jsonParse == nil {
		return nil, errJSONParseUnavailable
	}
	parsed, err := r.realm.jsonParse(goja.Undefined(), r.vm.ToValue(raw))
	if err != nil {
		return nil, err
	}
	return value{value: parsed, realm: r.realm, owner: owner, scope: scope}, nil
}

func (r *runtime) LoadCommonJS(filename, source string) (jsengine.Value, error) {
	return r.RunString(filename, jsengine.CommonJSProgram(filename, source))
}

func (r *runtime) NewObject() jsengine.Object {
	owner, scope := r.valueScope()
	return object{value: r.vm.NewObject(), realm: r.realm, owner: owner, scope: scope}
}

func (r *runtime) Get(name string) jsengine.Value {
	owner, scope := r.valueScope()
	return value{value: r.vm.Get(name), realm: r.realm, owner: owner, scope: scope}
}

func (r *runtime) Set(name string, raw interface{}) error {
	owner, scope := r.valueScope()
	value, err := unwrapObject(raw, r.realm, owner, scope)
	if err != nil {
		return err
	}
	return r.vm.Set(name, value)
}

func (o object) Set(name string, raw interface{}) error {
	if !o.usable() {
		return errGojaStaleValue
	}
	value, err := unwrapObject(raw, o.realm, o.owner, o.scope)
	if err != nil {
		return err
	}
	return o.value.Set(name, value)
}

func (o object) Get(name string) jsengine.Value {
	if !o.usable() {
		return value{value: goja.Undefined(), realm: o.realm}
	}
	return value{value: o.value.Get(name), realm: o.realm, owner: o.owner, scope: o.scope}
}

func (o object) Has(name string) bool {
	if !o.usable() {
		return false
	}
	for _, property := range o.value.GetOwnPropertyNames() {
		if property == name {
			return true
		}
	}
	return false
}

func (o object) usable() bool {
	return o.value != nil && o.realm != nil && !o.realm.closed.Load() &&
		(o.owner == nil || o.owner.ownsValueScope(o.scope))
}

func validateValueScope(valueOwner *runtime, valueScope uint64, owner *runtime, ownerScope uint64) error {
	if valueOwner == nil {
		return nil
	}
	if !valueOwner.ownsValueScope(valueScope) {
		return errGojaStaleValue
	}
	if valueOwner != owner || valueScope != ownerScope {
		return errors.New("Goja value belongs to another runtime callback")
	}
	return nil
}

func unwrapObject(raw interface{}, realm *realm, owner *runtime, scope uint64) (interface{}, error) {
	switch value := raw.(type) {
	case object:
		if value.realm != realm {
			return nil, errors.New("goja object belongs to another realm")
		}
		if !value.usable() {
			return nil, errGojaStaleValue
		}
		if err := validateValueScope(value.owner, value.scope, owner, scope); err != nil {
			return nil, err
		}
		return value.value, nil
	case value:
		if value.realm != realm {
			return nil, errors.New("goja value belongs to another realm")
		}
		if !value.usable() {
			return nil, errGojaStaleValue
		}
		if err := validateValueScope(value.owner, value.scope, owner, scope); err != nil {
			return nil, err
		}
		return value.value, nil
	default:
		return raw, nil
	}
}

func (r *runtime) Bind(name string, raw interface{}) error {
	owner, scope := r.valueScope()
	value, err := unwrapObject(raw, r.realm, owner, scope)
	if err != nil {
		return err
	}
	return r.vm.Set(name, value)
}

func (r *runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.realm != nil {
		r.realm.close()
	}
	if r.vm != nil && r.realm != nil {
		realms.CompareAndDelete(r.vm, r.realm)
	}
	return nil
}

func (v value) usable() bool {
	return v.value != nil && v.realm != nil && !v.realm.closed.Load() &&
		(v.owner == nil || v.owner.ownsValueScope(v.scope))
}

// primitiveExportable reports whether Export can detach the value without
// entering its Goja realm. Goja primitives are immutable; objects, functions,
// and their engine-owned graphs remain fenced to the callback scope.
func (v value) primitiveExportable() bool {
	if v.value == nil || v.realm == nil || v.realm.closed.Load() {
		return false
	}
	_, isObject := v.value.(*goja.Object)
	return !isObject
}

func (v value) Export() interface{} {
	if !v.usable() && !v.primitiveExportable() {
		return nil
	}
	return v.value.Export()
}

func (v value) ExportPrimitive() (any, error) {
	if !v.usable() && !v.primitiveExportable() {
		return nil, errGojaStaleValue
	}
	if goja.IsUndefined(v.value) || goja.IsNull(v.value) {
		return nil, jsengine.ErrNoPrimitiveValue
	}
	if _, ok := v.value.(*goja.Object); ok {
		return nil, fmt.Errorf("%w: object", jsengine.ErrPrimitiveExportUnsupported)
	}
	switch exported := v.value.Export().(type) {
	case bool, string, int64, uint64, float64:
		return exported, nil
	default:
		return nil, fmt.Errorf("%w: %T", jsengine.ErrPrimitiveExportUnsupported, exported)
	}
}

func (v value) ToBoolean() bool {
	return v.usable() && v.value.ToBoolean()
}

func (v value) Object() jsengine.Object {
	if !v.usable() {
		return nil
	}
	if rawObject, ok := v.value.(*goja.Object); ok {
		return object{value: rawObject, realm: v.realm, owner: v.owner, scope: v.scope}
	}
	return nil
}

// InstallContextPropagation makes timers and queueMicrotask restore the
// registration context. Promise reactions use Goja's native tracker, which is
// installed when the realm is attached to its runtime.
func InstallContextPropagation(loop jsengine.Loop) error {
	adapter, ok := loop.(*eventLoop)
	if !ok || adapter.loop == nil {
		return errors.New("goja event loop is required")
	}
	if adapter.context.Load() {
		return nil
	}
	if err := adapter.Run(func(runtime jsengine.Runtime) error {
		vm, ok := Raw(runtime)
		if !ok {
			return errors.New("goja runtime is required")
		}
		realm := adapter.currentRealm()
		if realm == nil {
			return errors.New("goja realm is required")
		}
		if err := vm.Set("__scardiceWrapAsync", func(call goja.FunctionCall) goja.Value {
			callback, ok := goja.AssertFunction(call.Argument(0))
			if !ok {
				return call.Argument(0)
			}
			context := adapter.CurrentContext()
			return vm.ToValue(func(callbackCall goja.FunctionCall) goja.Value {
				rootBoundary := realm.tracker.enterBoundary()
				defer realm.tracker.exitBoundary(rootBoundary)
				var result goja.Value
				if jsengine.ContextForExecution(context).Err() != nil {
					return goja.Undefined()
				}
				if err := realm.state.with(context, func() error {
					return runWithExecutionContext(jsengine.ContextForExecution(context), vm, func() error {
						return adapter.observe(context, jsengine.InvocationReaction, func() error {
							var err error
							result, err = callback(callbackCall.This, callbackCall.Arguments...)
							return err
						})
					})
				}); err != nil {
					if jsengine.ContextForExecution(context).Err() != nil {
						return goja.Undefined()
					}
					panic(err)
				}
				return result
			})
		}); err != nil {
			return err
		}
		if _, err := vm.RunString(`(function () {
			var wrap = globalThis.__scardiceWrapAsync;
			for (const name of ["setTimeout", "setInterval", "setImmediate"]) {
				const original = globalThis[name];
				if (typeof original !== "function") continue;
				globalThis[name] = function (callback) {
					var args = Array.prototype.slice.call(arguments, 1);
					args.unshift(wrap(callback));
					return original.apply(this, args);
				};
			}
			if (typeof globalThis.queueMicrotask === "function") {
				var originalQueueMicrotask = globalThis.queueMicrotask;
				globalThis.queueMicrotask = function (callback) {
					return originalQueueMicrotask.call(this, wrap(callback));
				};
			}
		})();`); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	adapter.context.Store(true)
	return nil
}

var _ jsengine.ContextAwareLoop = (*eventLoop)(nil)
var _ jsengine.ContextAwareLoop = (*runtime)(nil)
var _ jsengine.Runtime = (*runtime)(nil)
var _ jsengine.JSONParser = (*runtime)(nil)
var _ jsengine.Value = value{}
var _ jsengine.Object = object{}
