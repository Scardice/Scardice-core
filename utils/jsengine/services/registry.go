// Package services defines the engine-neutral host-service boundary.
//
// Services are deliberately separate from hostbridge: hostbridge exposes
// reflected objects, while this package names policy-governed operations that
// may be implemented by an engine adapter. The request and response unions
// contain only scalar values and byte buffers; adapter packages are responsible
// for converting engine values at their boundary.
package services

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"Scardice-core/utils/jsengine"
)

// Name is the stable service identifier used by the registry.
type Name string

const (
	Console         Name = "console"
	Crypto          Name = "crypto"
	Fetch           Name = "fetch"
	HTTP            Name = "http"
	WebSocket       Name = "websocket"
	Filesystem      Name = "filesystem"
	Abort           Name = "abort"
	StructuredClone Name = "structuredclone"
	UtilInspect     Name = "util.inspect"

	// Service-prefixed aliases make call sites self-documenting without
	// creating another spelling of the wire-level names.
	ServiceConsole         = Console
	ServiceCrypto          = Crypto
	ServiceFetch           = Fetch
	ServiceHTTP            = HTTP
	ServiceWebSocket       = WebSocket
	ServiceFilesystem      = Filesystem
	ServiceAbort           = Abort
	ServiceStructuredClone = StructuredClone
	ServiceUtilInspect     = UtilInspect
)

// NormalizeName applies the registry's canonical spelling.
func NormalizeName(name Name) Name { return Name(strings.ToLower(strings.TrimSpace(string(name)))) }

// OperationID is a stable numeric operation identifier. Values are grouped by
// service so an adapter can validate the operation without parsing JSON.
type OperationID uint32

// RequestID identifies one asynchronous service operation.
type RequestID uint64

// EventKind identifies the lifecycle phase delivered to an AsyncSink.
type EventKind uint32

const (
	EventData EventKind = iota + 1
	EventComplete
	EventClose
)

const (
	OpConsoleLog   OperationID = 0x0101
	OpConsoleInfo  OperationID = 0x0102
	OpConsoleWarn  OperationID = 0x0103
	OpConsoleError OperationID = 0x0104

	OpCryptoDigest      OperationID = 0x0201
	OpCryptoRandomBytes OperationID = 0x0202

	OpFetchRequest OperationID = 0x0301
	OpHTTPRequest  OperationID = 0x0401

	OpWebSocketConnect OperationID = 0x0501
	OpWebSocketSend    OperationID = 0x0502
	OpWebSocketClose   OperationID = 0x0503

	OpFilesystemReadFile      OperationID = 0x0601
	OpFilesystemWriteFile     OperationID = 0x0602
	OpFilesystemStat          OperationID = 0x0603
	OpFilesystemReadDir       OperationID = 0x0604
	OpFilesystemMkdir         OperationID = 0x0605
	OpFilesystemRemove        OperationID = 0x0606
	OpFilesystemReadFileSync  OperationID = 0x0607
	OpFilesystemWriteFileSync OperationID = 0x0608

	OpAbortCreate OperationID = 0x0701
	OpAbortCancel OperationID = 0x0702

	OpStructuredClone OperationID = 0x0801
	OpUtilInspect     OperationID = 0x0901
)

// Status is the typed result status for a service call.
type Status uint32

const (
	StatusOK Status = iota
	StatusInvalid
	StatusPermissionDenied
	StatusCancelled
	StatusDeadlineExceeded
	StatusUnsupported
	StatusClosed
	StatusInternal
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusInvalid:
		return "invalid"
	case StatusPermissionDenied:
		return "permission-denied"
	case StatusCancelled:
		return "cancelled"
	case StatusDeadlineExceeded:
		return "deadline-exceeded"
	case StatusUnsupported:
		return "unsupported"
	case StatusClosed:
		return "closed"
	case StatusInternal:
		return "internal"
	default:
		return "unknown"
	}
}

var (
	ErrDuplicateService = errors.New("duplicate service")
	ErrDuplicateOwner   = errors.New("duplicate service owner")
	ErrInvalidService   = errors.New("invalid service")
	ErrServiceNotFound  = errors.New("service not found")
	ErrPermissionDenied = errors.New("service permission denied")
	ErrCancelled        = errors.New("service call cancelled")
	ErrDeadlineExceeded = errors.New("service call deadline exceeded")
	ErrUnsupported      = errors.New("service unsupported")
	ErrRegistryClosed   = errors.New("service registry closed")
	ErrRequestNotFound  = errors.New("service request not found")
	ErrRequestCompleted = errors.New("service request completed")
)

// Request is the scalar/bytes request union. The operation determines which
// field is meaningful; adapters must reject a malformed field combination
// rather than interpreting it as an implicit JSON payload.
type Request struct {
	Service   Name
	Operation OperationID
	String    string
	Target    string // policy target; empty falls back to String
	Bytes     []byte
	Bool      bool
	Int64     int64
	Uint64    uint64
	Float64   float64
}

// Response is the scalar/bytes response union. StatusOK with an unused value
// field represents an operation that has no return value.
type Response struct {
	Status  Status
	String  string
	Bytes   []byte
	Bool    bool
	Int64   int64
	Uint64  uint64
	Float64 float64
}

// Authorizer evaluates one policy-governed service operation. It intentionally
// accepts only engine-neutral metadata; the owner may attach any execution
// context through a Registry PolicyProvider.
type Authorizer interface {
	Authorize(service Name, operation OperationID, target string) error
}

// Policy is the authorization context supplied for one service operation.
// A zero Policy permits services that do not install an authorizer.
type Policy struct {
	Authorizer Authorizer
}

// PolicyError keeps service and operation information while retaining
// errors.Is(err, ErrPermissionDenied) behavior.
type PolicyError struct {
	Service   Name
	Operation OperationID
	Target    string
	Cause     error
}

func (e *PolicyError) Error() string {
	if e == nil {
		return ErrPermissionDenied.Error()
	}
	if e.Cause == nil {
		return fmt.Sprintf("service %q operation %d denied", e.Service, e.Operation)
	}
	return fmt.Sprintf("service %q operation %d denied: %v", e.Service, e.Operation, e.Cause)
}
func (e *PolicyError) Unwrap() error { return ErrPermissionDenied }

func (p Policy) Authorize(service Name, operation OperationID, target string) error {
	if p.Authorizer == nil {
		return nil
	}
	service = NormalizeName(service)
	if err := p.Authorizer.Authorize(service, operation, target); err != nil {
		return &PolicyError{Service: service, Operation: operation, Target: target, Cause: err}
	}
	return nil
}

// Call carries cancellation/deadline/policy metadata without exposing an
// engine value or reflection object. Context is opaque to this package and is
// copied by the adapter boundary before asynchronous work starts.
type Call struct {
	Request      Request
	Policy       Policy
	Context      any
	Deadline     time.Time
	Cancellation <-chan struct{}
}

// Definition is immutable service metadata. Adapter identifies a
// runtime-specific installer; a non-empty Adapter means generic Invoke returns
// ErrUnsupported instead of pretending to execute the operation.
type Definition struct {
	Name            Name
	Operations      []OperationID
	AsyncOperations []OperationID
	Adapter         string
}

func (d Definition) normalized() (Definition, error) {
	d.Name = NormalizeName(d.Name)
	if d.Name == "" {
		return Definition{}, fmt.Errorf("%w: service name is empty", ErrInvalidService)
	}
	if len(d.Operations) == 0 && len(d.AsyncOperations) == 0 {
		return Definition{}, fmt.Errorf("%w: service %q has no operations", ErrInvalidService, d.Name)
	}
	seen := make(map[OperationID]struct{}, len(d.Operations)+len(d.AsyncOperations))
	normalize := func(operations []OperationID) ([]OperationID, error) {
		out := make([]OperationID, len(operations))
		copy(out, operations)
		for _, op := range out {
			if op == 0 {
				return nil, fmt.Errorf("%w: service %q has operation 0", ErrInvalidService, d.Name)
			}
			if _, exists := seen[op]; exists {
				return nil, fmt.Errorf("%w: service %q operation %d", ErrInvalidService, d.Name, op)
			}
			seen[op] = struct{}{}
		}
		return out, nil
	}
	var err error
	if d.Operations, err = normalize(d.Operations); err != nil {
		return Definition{}, err
	}
	if d.AsyncOperations, err = normalize(d.AsyncOperations); err != nil {
		return Definition{}, err
	}
	return d, nil
}

func (d Definition) supports(operation OperationID) bool {
	for _, op := range d.Operations {
		if op == operation {
			return true
		}
	}
	return false
}

func (d Definition) supportsAsync(operation OperationID) bool {
	for _, op := range d.AsyncOperations {
		if op == operation {
			return true
		}
	}
	return false
}

// Service is a concrete engine-neutral provider. Adapter-only services are
// represented by Installer definitions and have no Service implementation.
type Service interface {
	Definition() Definition
	Invoke(Call) (Response, error)
}

// AsyncCall is the copied engine-neutral input passed to an asynchronous
// service. The service may retain it only through its scalar/byte fields.
type AsyncCall struct {
	ID   RequestID
	Call Call
	Sink AsyncSink
}

// AsyncSink receives asynchronous service data and terminal notifications.
type AsyncSink interface {
	Event(RequestID, Response) error
	Complete(RequestID, Response) error
	Close(RequestID, Response) error
}

// AsyncService extends Service with a request lifecycle.
type AsyncService interface {
	Service
	Start(AsyncCall) error
	Cancel(RequestID) error
}

// Installer owns one or more adapter bindings. Install is called exactly once
// before definitions become visible; Close is called exactly once when the
// returned Installation or its registry is closed.
type Installer interface {
	Owner() string
	Definitions() []Definition
	Install() error
	Close() error
}

type registryEntry struct {
	definition Definition
	service    Service
	owner      *Installation
}

type discardAsyncSink struct{}

func (discardAsyncSink) Event(RequestID, Response) error    { return nil }
func (discardAsyncSink) Complete(RequestID, Response) error { return nil }
func (discardAsyncSink) Close(RequestID, Response) error    { return nil }

type asyncRequest struct {
	registry    *Registry
	id          RequestID
	serviceName Name
	operation   OperationID
	service     AsyncService
	sink        AsyncSink

	mu            sync.Mutex
	terminal      bool
	terminalKind  EventKind
	terminalError error
}

func cloneResponse(response Response) Response {
	response.Bytes = append([]byte(nil), response.Bytes...)
	return response
}
func (p *asyncRequest) deliver(kind EventKind, response Response) error {
	if kind != EventData && kind != EventComplete && kind != EventClose {
		return fmt.Errorf("%w: event kind %d", ErrInvalidService, kind)
	}
	response = cloneResponse(response)
	if response.Status == 0 {
		response.Status = StatusOK
	}

	p.mu.Lock()
	if p.terminal {
		err := p.terminalError
		terminalKind := p.terminalKind
		p.mu.Unlock()
		if kind == terminalKind && kind != EventData {
			return nil
		}
		return err
	}
	terminal := kind == EventComplete || kind == EventClose
	if terminal {
		p.terminal = true
		p.terminalKind = kind
		p.terminalError = asyncTerminalError(p, response.Status)
	}
	sink := p.sink
	p.mu.Unlock()

	var err error
	switch kind {
	case EventData:
		err = sink.Event(p.id, response)
	case EventComplete:
		err = sink.Complete(p.id, response)
	case EventClose:
		err = sink.Close(p.id, response)
	}
	if terminal && p.registry != nil {
		p.registry.finishRequest(p)
	}
	return err
}
func (p *asyncRequest) Event(id RequestID, response Response) error {
	if id != p.id {
		return fmt.Errorf("%w: %d", ErrRequestNotFound, id)
	}
	return p.deliver(EventData, response)
}

func (p *asyncRequest) Complete(id RequestID, response Response) error {
	if id != p.id {
		return fmt.Errorf("%w: %d", ErrRequestNotFound, id)
	}
	return p.deliver(EventComplete, response)
}

func (p *asyncRequest) Close(id RequestID, response Response) error {
	if id != p.id {
		return fmt.Errorf("%w: %d", ErrRequestNotFound, id)
	}
	return p.deliver(EventClose, response)
}

func (p *asyncRequest) cancel(status Status) (bool, error) {
	p.mu.Lock()
	if p.terminal {
		p.mu.Unlock()
		return false, nil
	}
	p.terminal = true
	p.terminalKind = EventClose
	p.terminalError = asyncTerminalError(p, status)
	sink := p.sink
	p.mu.Unlock()

	err := sink.Close(p.id, Response{Status: status})
	if p.registry != nil {
		p.registry.finishRequest(p)
	}
	return true, err
}

func (p *asyncRequest) fail(err error) {
	p.mu.Lock()
	p.terminal = true
	p.terminalKind = EventClose
	p.terminalError = err
	p.mu.Unlock()
}

func asyncTerminalError(request *asyncRequest, status Status) error {
	var cause error
	switch status {
	case StatusOK:
		cause = ErrRequestCompleted
	case StatusCancelled:
		cause = ErrCancelled
	case StatusDeadlineExceeded:
		cause = ErrDeadlineExceeded
	case StatusPermissionDenied:
		cause = ErrPermissionDenied

	case StatusUnsupported:
		cause = ErrUnsupported
	case StatusClosed:
		cause = ErrRegistryClosed
	default:
		cause = fmt.Errorf("service request terminated with status %s", status)
	}
	return &CallError{
		Status:    status,
		Service:   request.serviceName,
		Operation: request.operation,
		Cause:     cause,
	}
}
func (r *Registry) finishRequest(request *asyncRequest) {
	if r == nil || request == nil {
		return
	}
	request.mu.Lock()
	// Keep the service reference for the in-flight Cancel call that may follow
	// a terminal transition; release the callback sink once no more callbacks
	// can be delivered.
	request.sink = discardAsyncSink{}
	request.mu.Unlock()
}

// PolicyProvider supplies the default policy for a call when the caller did
// not provide one explicitly. It runs outside the registry lock.
type PolicyProvider func(Call) Policy

// Registry stores stable named services and adapter-owned bindings.
type Registry struct {
	mu             sync.RWMutex
	lifecycleMu    sync.Mutex
	entries        map[Name]registryEntry
	order          []Name
	owners         map[string]*Installation
	installations  []*Installation
	requests       map[RequestID]*asyncRequest
	nextRequest    RequestID
	policyProvider PolicyProvider
	closed         bool
}

func NewRegistry() *Registry {
	return &Registry{
		entries:  make(map[Name]registryEntry),
		owners:   make(map[string]*Installation),
		requests: make(map[RequestID]*asyncRequest),
	}
}

// SetPolicyProvider supplies default authorization for calls that do not carry
// an explicit Policy. The provider is consulted outside the registry lock.
func (r *Registry) SetPolicyProvider(provider PolicyProvider) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.policyProvider = provider
	r.mu.Unlock()
}

func (r *Registry) policyFor(call Call) Policy {
	if call.Policy.Authorizer != nil || r == nil {
		return call.Policy
	}
	r.mu.RLock()
	provider := r.policyProvider
	r.mu.RUnlock()
	if provider == nil {
		return call.Policy
	}
	return provider(call)
}

// Register adds a concrete engine-neutral service.
func (r *Registry) Register(service Service) error {
	if r == nil || service == nil {
		return ErrInvalidService
	}
	definition, err := service.Definition().normalized()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrRegistryClosed
	}
	if _, exists := r.entries[definition.Name]; exists {
		return fmt.Errorf("%w: %q", ErrDuplicateService, definition.Name)
	}
	r.entries[definition.Name] = registryEntry{definition: definition, service: service}
	r.order = append(r.order, definition.Name)
	return nil
}

// Install registers all services owned by one adapter installer.
func (r *Registry) Install(installer Installer) (*Installation, error) {
	if r == nil || installer == nil {
		return nil, ErrInvalidService
	}
	owner := strings.TrimSpace(installer.Owner())
	if owner == "" {
		return nil, fmt.Errorf("%w: installer owner is empty", ErrInvalidService)
	}
	definitions := installer.Definitions()
	if len(definitions) == 0 {
		return nil, fmt.Errorf("%w: installer %q has no services", ErrInvalidService, owner)
	}
	normalized := make([]Definition, len(definitions))
	seen := make(map[Name]struct{}, len(definitions))
	for i, definition := range definitions {
		definition, err := definition.normalized()
		if err != nil {
			return nil, err
		}
		if _, exists := seen[definition.Name]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateService, definition.Name)
		}
		seen[definition.Name] = struct{}{}
		normalized[i] = definition
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrRegistryClosed
	}
	if _, exists := r.owners[owner]; exists {
		return nil, fmt.Errorf("%w: %q", ErrDuplicateOwner, owner)
	}
	for _, definition := range normalized {
		if _, exists := r.entries[definition.Name]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateService, definition.Name)
		}
	}
	if err := installer.Install(); err != nil {
		return nil, err
	}
	installation := &Installation{registry: r, installer: installer, owner: owner}
	for _, definition := range normalized {
		r.entries[definition.Name] = registryEntry{definition: definition, owner: installation}
		r.order = append(r.order, definition.Name)
		installation.names = append(installation.names, definition.Name)
	}
	r.owners[owner] = installation
	r.installations = append(r.installations, installation)
	return installation, nil
}

// Installation represents one ownership boundary in the registry.
type Installation struct {
	registry  *Registry
	installer Installer
	owner     string
	names     []Name
	closed    atomic.Bool
}

func (i *Installation) Owner() string {
	if i == nil {
		return ""
	}
	return i.owner
}

// Close removes the owned definitions and invokes the adapter shutdown hook.
func (i *Installation) Close() error {
	if i == nil || !i.closed.CompareAndSwap(false, true) {
		return nil
	}
	if i.registry != nil {
		i.registry.removeInstallation(i)
	}
	if i.installer != nil {
		return i.installer.Close()
	}
	return nil
}

func (i *Installation) closeFromRegistry() error {
	if i == nil || !i.closed.CompareAndSwap(false, true) {
		return nil
	}
	if i.installer != nil {
		return i.installer.Close()
	}
	return nil
}

func (r *Registry) removeInstallation(installation *Installation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range installation.names {
		if entry, ok := r.entries[name]; ok && entry.owner == installation {
			delete(r.entries, name)
		}
	}
	if r.owners[installation.owner] == installation {
		delete(r.owners, installation.owner)
	}
	for idx, candidate := range r.installations {
		if candidate == installation {
			r.installations = append(r.installations[:idx], r.installations[idx+1:]...)
			break
		}
	}
}

// Close shuts down every installation and pending asynchronous request exactly
// once. It is safe to call from a Loop.Close hook and does not wait on provider
// goroutines.
func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	installations := append([]*Installation(nil), r.installations...)
	requests := make([]*asyncRequest, 0, len(r.requests))
	for _, request := range r.requests {
		requests = append(requests, request)
	}
	r.entries = make(map[Name]registryEntry)
	r.order = nil
	r.owners = make(map[string]*Installation)
	r.installations = nil
	r.requests = nil
	r.mu.Unlock()

	var firstErr error
	for _, request := range requests {
		active, sinkErr := request.cancel(StatusClosed)
		if !active {
			continue
		}
		if sinkErr != nil && firstErr == nil {
			firstErr = sinkErr
		}
		if err := request.service.Cancel(request.id); err != nil && firstErr == nil {
			firstErr = &CallError{
				Status:    StatusInternal,
				Service:   request.serviceName,
				Operation: request.operation,
				Cause:     err,
			}
		}
	}
	for _, installation := range installations {
		if err := installation.closeFromRegistry(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Lookup returns an immutable definition snapshot.
func (r *Registry) Lookup(name Name) (Definition, error) {
	if r == nil {
		return Definition{}, ErrServiceNotFound
	}
	name = NormalizeName(name)
	r.mu.RLock()
	entry, ok := r.entries[name]
	r.mu.RUnlock()
	if !ok {
		return Definition{}, fmt.Errorf("%w: %q", ErrServiceNotFound, name)
	}
	definition := entry.definition
	definition.Operations = append([]OperationID(nil), definition.Operations...)
	definition.AsyncOperations = append([]OperationID(nil), definition.AsyncOperations...)
	return definition, nil
}

// Get is an alias for Lookup.
func (r *Registry) Get(name Name) (Definition, error) { return r.Lookup(name) }

// Names returns registration-order service names.
func (r *Registry) Names() []Name {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Name(nil), r.order...)
}

func (r *Registry) Start(call Call, sink AsyncSink) (RequestID, error) {
	return r.start(call, sink)
}

// StartNative dispatches a request originating at the native ABI boundary.
// The registry applies its configured PolicyProvider just like Goja calls.
func (r *Registry) StartNative(call Call, sink AsyncSink) (RequestID, error) {
	return r.start(call, sink)
}

// Start dispatches one asynchronous service operation. The registry wraps the
// supplied sink so providers cannot bypass request lifecycle validation.
func (r *Registry) start(call Call, sink AsyncSink) (RequestID, error) {
	if r == nil {
		return 0, ErrRegistryClosed
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	serviceName := NormalizeName(call.Request.Service)
	call.Request.Service = serviceName
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return 0, ErrRegistryClosed
	}
	entry, ok := r.entries[serviceName]
	r.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrServiceNotFound, serviceName)
	}
	if !entry.definition.supportsAsync(call.Request.Operation) {
		return 0, &CallError{
			Status:    StatusUnsupported,
			Service:   serviceName,
			Operation: call.Request.Operation,
			Cause:     ErrUnsupported,
		}
	}
	if !call.Deadline.IsZero() && !time.Now().Before(call.Deadline) {
		return 0, &CallError{
			Status:    StatusDeadlineExceeded,
			Service:   serviceName,
			Operation: call.Request.Operation,
			Cause:     ErrDeadlineExceeded,
		}
	}
	if call.Cancellation != nil {
		select {
		case <-call.Cancellation:
			return 0, &CallError{
				Status:    StatusCancelled,
				Service:   serviceName,
				Operation: call.Request.Operation,
				Cause:     ErrCancelled,
			}
		default:
		}
	}
	call.Policy = r.policyFor(call)
	target := call.Request.Target
	if target == "" {
		target = call.Request.String
	}
	if err := call.Policy.Authorize(serviceName, call.Request.Operation, target); err != nil {
		return 0, &CallError{
			Status:    StatusPermissionDenied,
			Service:   serviceName,
			Operation: call.Request.Operation,
			Cause:     err,
		}
	}
	asyncService, ok := entry.service.(AsyncService)
	if !ok || asyncService == nil {
		return 0, &CallError{
			Status:    StatusUnsupported,
			Service:   serviceName,
			Operation: call.Request.Operation,
			Cause:     ErrUnsupported,
		}
	}
	if sink == nil {
		sink = discardAsyncSink{}
	}
	call.Request.Bytes = append([]byte(nil), call.Request.Bytes...)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, ErrRegistryClosed
	}
	if r.requests == nil {
		r.requests = make(map[RequestID]*asyncRequest)
	}
	var id RequestID
	for {
		r.nextRequest++
		if r.nextRequest == 0 {
			continue
		}
		if _, exists := r.requests[r.nextRequest]; !exists {
			id = r.nextRequest
			break
		}
	}
	request := &asyncRequest{
		registry:    r,
		id:          id,
		serviceName: serviceName,
		operation:   call.Request.Operation,
		service:     asyncService,
		sink:        sink,
	}
	r.requests[id] = request
	r.mu.Unlock()

	if err := asyncService.Start(AsyncCall{ID: id, Call: call, Sink: request}); err != nil {
		callErr := &CallError{
			Status:    statusForError(err),
			Service:   serviceName,
			Operation: call.Request.Operation,
			Cause:     err,
		}
		request.fail(callErr)
		r.mu.Lock()
		if r.requests[id] == request {
			delete(r.requests, id)
		}
		r.mu.Unlock()
		return 0, callErr
	}
	return id, nil
}

// Deliver routes one provider event to a pending request.
func (r *Registry) Deliver(id RequestID, kind EventKind, response Response) error {
	if r == nil {
		return ErrRegistryClosed
	}
	if id == 0 {
		return ErrRequestNotFound
	}
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return ErrRegistryClosed
	}
	request, ok := r.requests[id]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %d", ErrRequestNotFound, id)
	}
	return request.deliver(kind, response)
}

// Cancel requests termination and closes the request sink exactly once.
func (r *Registry) Cancel(id RequestID) error {
	if r == nil {
		return ErrRegistryClosed
	}
	if id == 0 {
		return ErrRequestNotFound
	}
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return ErrRegistryClosed
	}
	request, ok := r.requests[id]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %d", ErrRequestNotFound, id)
	}
	active, sinkErr := request.cancel(StatusCancelled)
	if !active {
		return nil
	}
	cancelErr := request.service.Cancel(id)
	if sinkErr != nil {
		return sinkErr
	}
	if cancelErr != nil {
		return &CallError{
			Status:    StatusInternal,
			Service:   request.serviceName,
			Operation: request.operation,
			Cause:     cancelErr,
		}
	}
	return nil
}

// Invoke dispatches a concrete service or returns deterministic unsupported
// status for an adapter-owned binding.
func (r *Registry) Invoke(call Call) (Response, error) {
	return r.invoke(call)
}

// InvokeNative dispatches a request originating at the native ABI boundary.
// The registry applies its configured PolicyProvider just like Goja calls.
func (r *Registry) InvokeNative(call Call) (Response, error) {
	return r.invoke(call)
}

func (r *Registry) invoke(call Call) (Response, error) {
	if r == nil {
		return Response{Status: StatusClosed}, ErrRegistryClosed
	}
	serviceName := NormalizeName(call.Request.Service)
	call.Request.Service = serviceName
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return Response{Status: StatusClosed}, ErrRegistryClosed
	}
	entry, ok := r.entries[serviceName]
	r.mu.RUnlock()
	if !ok {
		return Response{Status: StatusInvalid}, fmt.Errorf("%w: %q", ErrServiceNotFound, serviceName)
	}
	if !entry.definition.supports(call.Request.Operation) {
		return Response{Status: StatusInvalid}, fmt.Errorf("%w: service %q operation %d", ErrInvalidService, serviceName, call.Request.Operation)
	}
	if !call.Deadline.IsZero() && !time.Now().Before(call.Deadline) {
		return Response{Status: StatusDeadlineExceeded}, &CallError{Status: StatusDeadlineExceeded, Service: serviceName, Operation: call.Request.Operation, Cause: ErrDeadlineExceeded}
	}
	if call.Cancellation != nil {
		select {
		case <-call.Cancellation:
			return Response{Status: StatusCancelled}, &CallError{Status: StatusCancelled, Service: serviceName, Operation: call.Request.Operation, Cause: ErrCancelled}
		default:
		}
	}
	call.Policy = r.policyFor(call)
	if err := call.Policy.Authorize(serviceName, call.Request.Operation, call.Request.String); err != nil {
		return Response{Status: StatusPermissionDenied}, &CallError{Status: StatusPermissionDenied, Service: serviceName, Operation: call.Request.Operation, Cause: err}
	}
	if entry.service == nil {
		return Response{Status: StatusUnsupported}, &CallError{Status: StatusUnsupported, Service: serviceName, Operation: call.Request.Operation, Cause: ErrUnsupported}
	}
	response, err := entry.service.Invoke(call)
	if err != nil {
		if response.Status == StatusOK {
			response.Status = statusForError(err)
		}
		return response, &CallError{Status: response.Status, Service: serviceName, Operation: call.Request.Operation, Cause: err}
	}
	if response.Status == 0 {
		response.Status = StatusOK
	}
	return response, nil
}

// CallError identifies the failed typed operation while preserving its
// deterministic sentinel through errors.Is.
type CallError struct {
	Status    Status
	Service   Name
	Operation OperationID
	Cause     error
}

func (e *CallError) Error() string {
	if e == nil {
		return "service call failed"
	}
	return fmt.Sprintf("service %q operation %d: %s", e.Service, e.Operation, e.Status)
}
func (e *CallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func statusForError(err error) Status {
	switch {
	case errors.Is(err, ErrCancelled):
		return StatusCancelled
	case errors.Is(err, ErrDeadlineExceeded):
		return StatusDeadlineExceeded
	case errors.Is(err, ErrPermissionDenied):
		return StatusPermissionDenied
	case errors.Is(err, ErrUnsupported):
		return StatusUnsupported
	default:
		return StatusInternal
	}
}

// Advertised reads the optional service names attached to an engine descriptor.
// Native ABI descriptors carry capability bits but not service names; the
// native loader supplies names from the package manifest.
func Advertised(descriptor jsengine.Descriptor) []Name {
	services := make([]Name, 0, len(descriptor.Services))
	for _, raw := range descriptor.Services {
		name := NormalizeName(Name(raw))
		if name != "" {
			services = append(services, name)
		}
	}
	return services
}

// RequireNativeService refuses a service unless it is explicitly advertised
// by the provider metadata. It never falls back to the Goja adapter.
func RequireNativeService(descriptor jsengine.Descriptor, name Name) error {
	name = NormalizeName(name)
	for _, advertised := range Advertised(descriptor) {
		if advertised == name {
			return nil
		}
	}
	return &CallError{Status: StatusUnsupported, Service: name, Cause: fmt.Errorf("%w: engine %q does not advertise service %q", ErrUnsupported, descriptor.ID, name)}
}
