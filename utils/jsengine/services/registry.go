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

	"Scardice-core/dice/sealpack"
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

const (
	OpConsoleLog   OperationID = 0x0101
	OpConsoleInfo  OperationID = 0x0102
	OpConsoleWarn  OperationID = 0x0103
	OpConsoleError OperationID = 0x0104

	OpCryptoDigest     OperationID = 0x0201
	OpCryptoRandomBytes OperationID = 0x0202

	OpFetchRequest OperationID = 0x0301
	OpHTTPRequest  OperationID = 0x0401

	OpWebSocketConnect OperationID = 0x0501
	OpWebSocketSend    OperationID = 0x0502
	OpWebSocketClose   OperationID = 0x0503

	OpFilesystemReadFile  OperationID = 0x0601
	OpFilesystemWriteFile OperationID = 0x0602
	OpFilesystemStat      OperationID = 0x0603
	OpFilesystemReadDir   OperationID = 0x0604
	OpFilesystemMkdir     OperationID = 0x0605
	OpFilesystemRemove    OperationID = 0x0606

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
)

// Request is the scalar/bytes request union. The operation determines which
// field is meaningful; adapters must reject a malformed field combination
// rather than interpreting it as an implicit JSON payload.
type Request struct {
	Service   Name
	Operation OperationID
	String    string
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

// Policy is the authorization context supplied for one service operation.
// A nil Sandbox intentionally denies filesystem/network operations; there is
// no unrestricted fallback.
type Policy struct {
	Sandbox *sealpack.Sandbox
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

// Authorize checks the SealPack sandbox for operations that can access the
// network or filesystem. Local pure services do not need a sandbox.
func (p Policy) Authorize(service Name, operation OperationID, target string) error {
	service = NormalizeName(service)
	requiresSandbox := service == Fetch || service == HTTP || service == WebSocket || service == Filesystem
	if !requiresSandbox {
		return nil
	}
	if p.Sandbox == nil {
		return &PolicyError{Service: service, Operation: operation, Target: target}
	}
	var err error
	switch service {
	case Fetch, HTTP, WebSocket:
		err = p.Sandbox.CheckNetworkPermission(target)
	case Filesystem:
		switch operation {
		case OpFilesystemReadFile, OpFilesystemReadDir, OpFilesystemStat:
			err = p.Sandbox.CheckFileReadPermission(target)
		case OpFilesystemWriteFile, OpFilesystemMkdir, OpFilesystemRemove:
			err = p.Sandbox.CheckFileWritePermission(target)
		default:
			err = fmt.Errorf("unknown filesystem operation %d", operation)
		}
	}
	if err != nil {
		return &PolicyError{Service: service, Operation: operation, Target: target, Cause: err}
	}
	return nil
}

// Call carries cancellation/deadline/policy metadata without exposing an
// engine value or reflection object. Cancellation is observed before dispatch
// and should also be observed by long-running providers.
type Call struct {
	Request      Request
	Policy       Policy
	Deadline     time.Time
	Cancellation <-chan struct{}
}

// Definition is immutable service metadata. Adapter identifies a
// runtime-specific installer; a non-empty Adapter means generic Invoke returns
// ErrUnsupported instead of pretending to execute the operation.
type Definition struct {
	Name       Name
	Operations []OperationID
	Adapter    string
}

func (d Definition) normalized() (Definition, error) {
	d.Name = NormalizeName(d.Name)
	if d.Name == "" {
		return Definition{}, fmt.Errorf("%w: service name is empty", ErrInvalidService)
	}
	if len(d.Operations) == 0 {
		return Definition{}, fmt.Errorf("%w: service %q has no operations", ErrInvalidService, d.Name)
	}
	seen := make(map[OperationID]struct{}, len(d.Operations))
	ops := make([]OperationID, len(d.Operations))
	copy(ops, d.Operations)
	for _, op := range ops {
		if op == 0 {
			return Definition{}, fmt.Errorf("%w: service %q has operation 0", ErrInvalidService, d.Name)
		}
		if _, exists := seen[op]; exists {
			return Definition{}, fmt.Errorf("%w: service %q operation %d", ErrInvalidService, d.Name, op)
		}
		seen[op] = struct{}{}
	}
	d.Operations = ops
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

// Service is a concrete engine-neutral provider. Adapter-only services are
// represented by Installer definitions and have no Service implementation.
type Service interface {
	Definition() Definition
	Invoke(Call) (Response, error)
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

// Registry stores stable named services and adapter-owned bindings.
type Registry struct {
	mu            sync.RWMutex
	entries       map[Name]registryEntry
	order         []Name
	owners        map[string]*Installation
	installations []*Installation
	closed        bool
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[Name]registryEntry), owners: make(map[string]*Installation)}
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

// Close shuts down every installation exactly once. It is safe to call from a
// Loop.Close hook and does not start goroutines or wait on provider goroutines.
func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	installations := append([]*Installation(nil), r.installations...)
	r.entries = make(map[Name]registryEntry)
	r.order = nil
	r.owners = make(map[string]*Installation)
	r.installations = nil
	r.mu.Unlock()

	var firstErr error
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

// Invoke dispatches a concrete service or returns deterministic unsupported
// status for an adapter-owned binding.
func (r *Registry) Invoke(call Call) (Response, error) {
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
// ABI-v1 native descriptors cannot carry this field, so they advertise none.
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
