package dice

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"

	"Scardice-core/utils"
	"Scardice-core/utils/jsengine"
	nativejs "Scardice-core/utils/jsengine/native"
	"Scardice-core/utils/jsengine/services"
)

type nativeConsoleService struct {
	printer *PrinterFunc
}

func (s *nativeConsoleService) Definition() services.Definition {
	return services.Definition{
		Name: services.Console,
		Operations: []services.OperationID{
			services.OpConsoleLog,
			services.OpConsoleInfo,
			services.OpConsoleWarn,
			services.OpConsoleError,
		},
	}
}

func (s *nativeConsoleService) Invoke(call services.Call) (services.Response, error) {
	if s == nil || s.printer == nil {
		return services.Response{Status: services.StatusInternal}, errors.New("native console printer is unavailable")
	}
	switch call.Request.Operation {
	case services.OpConsoleLog, services.OpConsoleInfo:
		s.printer.Log(call.Request.String)
	case services.OpConsoleWarn:
		s.printer.Warn(call.Request.String)
	case services.OpConsoleError:
		s.printer.Error(call.Request.String)
	default:
		return services.Response{Status: services.StatusInvalid}, fmt.Errorf("unsupported console operation %d", call.Request.Operation)
	}
	return services.Response{Status: services.StatusOK}, nil
}

type nativeCryptoService struct{}

func (s *nativeCryptoService) Definition() services.Definition {
	return services.Definition{
		Name: services.Crypto,
		Operations: []services.OperationID{
			services.OpCryptoDigest,
			services.OpCryptoRandomBytes,
		},
	}
}

func (s *nativeCryptoService) Invoke(call services.Call) (services.Response, error) {
	if s == nil {
		return services.Response{Status: services.StatusInternal}, errors.New("native crypto service is unavailable")
	}
	switch call.Request.Operation {
	case services.OpCryptoDigest:
		return s.digest(call.Request.String, call.Request.Bytes)
	case services.OpCryptoRandomBytes:
		if call.Request.Uint64 > 65536 {
			return services.Response{Status: services.StatusInvalid}, errors.New("random byte request exceeds 65536 bytes")
		}
		output := make([]byte, call.Request.Uint64)
		if _, err := rand.Read(output); err != nil {
			return services.Response{Status: services.StatusInternal}, fmt.Errorf("generate random bytes: %w", err)
		}
		return services.Response{Status: services.StatusOK, Bytes: output}, nil
	default:
		return services.Response{Status: services.StatusInvalid}, fmt.Errorf("unsupported crypto operation %d", call.Request.Operation)
	}
}

func (s *nativeCryptoService) digest(algorithm string, input []byte) (services.Response, error) {
	algorithm = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(algorithm), "-", ""))
	var factory func() hash.Hash
	switch algorithm {
	case "MD5":
		factory = md5.New
	case "SHA1":
		factory = sha1.New
	case "SHA224":
		factory = sha256.New224
	case "SHA256":
		factory = sha256.New
	case "SHA384":
		factory = sha512.New384
	case "SHA512":
		factory = sha512.New
	default:
		return services.Response{Status: services.StatusUnsupported}, fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}
	digest := factory()
	if _, err := digest.Write(input); err != nil {
		return services.Response{Status: services.StatusInternal}, fmt.Errorf("hash input: %w", err)
	}
	return services.Response{Status: services.StatusOK, Bytes: digest.Sum(nil)}, nil
}

type nativeFilesystemService struct {
	dice    *Dice
	mu      sync.Mutex
	pending map[services.RequestID]chan struct{}
}

func (s *nativeFilesystemService) Definition() services.Definition {
	return services.Definition{
		Name: services.Filesystem,
		Operations: []services.OperationID{
			services.OpFilesystemReadFileSync,
			services.OpFilesystemWriteFileSync,
		},
		AsyncOperations: []services.OperationID{
			services.OpFilesystemReadFile,
			services.OpFilesystemWriteFile,
		},
	}
}

func (s *nativeFilesystemService) Invoke(call services.Call) (services.Response, error) {
	if s == nil || s.dice == nil {
		return services.Response{Status: services.StatusInternal}, errors.New("native filesystem service is unavailable")
	}
	request := call.Request
	write := isFilesystemWriteOperation(request.Operation)
	resolved, err := s.prepare(request, write, jsOpaqueExecutionContext(call.Context))
	if err != nil {
		return services.Response{Status: statusForFilesystemError(err)}, err
	}
	if write {
		if err := jsFsEnsureParent(resolved); err != nil {
			return services.Response{Status: services.StatusInternal}, err
		}
		if err := utils.AtomicWriteFile(resolved.abs, request.Bytes, 0644); err != nil {
			return services.Response{Status: services.StatusInternal}, err
		}
		return services.Response{Status: services.StatusOK}, nil
	}
	data, err := os.ReadFile(resolved.abs)
	if err != nil {
		return services.Response{Status: services.StatusInternal}, err
	}
	if err := s.dice.validateNativeFilesystemBytes(data, false); err != nil {
		return services.Response{Status: services.StatusInvalid}, err
	}
	return services.Response{Status: services.StatusOK, Bytes: data}, nil
}

func isFilesystemReadOperation(operation services.OperationID) bool {
	return operation == services.OpFilesystemReadFile || operation == services.OpFilesystemReadFileSync
}

func isFilesystemWriteOperation(operation services.OperationID) bool {
	return operation == services.OpFilesystemWriteFile || operation == services.OpFilesystemWriteFileSync
}

func (s *nativeFilesystemService) prepare(request services.Request, write bool, context *jsExecutionContext) (jsFsResolvedPath, error) {
	if (write && !isFilesystemWriteOperation(request.Operation)) || (!write && !isFilesystemReadOperation(request.Operation)) {
		return jsFsResolvedPath{}, fmt.Errorf("%w: filesystem operation %d", services.ErrUnsupported, request.Operation)
	}
	if err := jsFilesystemAuthorizeWithContext(s.dice, context, request.String, write); err != nil {
		return jsFsResolvedPath{}, err
	}
	resolved, err := jsFsResolveAbsoluteWithContext(s.dice, request.String, context)
	if err != nil {
		return jsFsResolvedPath{}, err
	}
	if write {
		if err := s.dice.validateNativeFilesystemBytes(request.Bytes, true); err != nil {
			return jsFsResolvedPath{}, err
		}
		return resolved, nil
	}
	if err := jsFsEnsureExistingDataTargetInside(resolved); err != nil {
		return jsFsResolvedPath{}, err
	}
	return resolved, nil
}

func statusForFilesystemError(err error) services.Status {
	switch {
	case errors.Is(err, services.ErrPermissionDenied):
		return services.StatusPermissionDenied
	case errors.Is(err, services.ErrUnsupported):
		return services.StatusUnsupported
	default:
		return services.StatusInternal
	}
}

func (s *nativeFilesystemService) Start(call services.AsyncCall) error {
	if s == nil || s.dice == nil || call.Sink == nil {
		return errors.New("native filesystem service is unavailable")
	}
	request := call.Call.Request
	write := isFilesystemWriteOperation(request.Operation)
	resolved, err := s.prepare(request, write, jsOpaqueExecutionContext(call.Call.Context))
	if err != nil {
		return err
	}
	cancelled := make(chan struct{})
	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[services.RequestID]chan struct{})
	}
	s.pending[call.ID] = cancelled
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			if current, ok := s.pending[call.ID]; ok && current == cancelled {
				delete(s.pending, call.ID)
			}
			s.mu.Unlock()
		}()
		select {
		case <-cancelled:
			return
		case <-call.Call.Cancellation:
			return
		default:
		}
		var response services.Response
		switch request.Operation {
		case services.OpFilesystemReadFile:
			data, readErr := os.ReadFile(resolved.abs)
			if readErr != nil {
				response = services.Response{Status: services.StatusInternal, String: readErr.Error()}
			} else if sizeErr := s.dice.validateNativeFilesystemBytes(data, false); sizeErr != nil {
				response = services.Response{Status: services.StatusInvalid, String: sizeErr.Error()}
			} else {
				response = services.Response{Status: services.StatusOK, Bytes: data}
			}
		case services.OpFilesystemWriteFile:
			if writeErr := jsFsEnsureParent(resolved); writeErr != nil {
				response = services.Response{Status: services.StatusInternal, String: writeErr.Error()}
			} else if writeErr = utils.AtomicWriteFile(resolved.abs, request.Bytes, 0644); writeErr != nil {
				response = services.Response{Status: services.StatusInternal, String: writeErr.Error()}
			} else {
				response = services.Response{Status: services.StatusOK}
			}
		}
		select {
		case <-cancelled:
			return
		case <-call.Call.Cancellation:
			return
		default:
		}
		_ = call.Sink.Complete(call.ID, response)
	}()
	return nil
}

func (s *nativeFilesystemService) Cancel(id services.RequestID) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancelled, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
		close(cancelled)
	}
	s.mu.Unlock()
	return nil
}

func (d *Dice) validateNativeFilesystemBytes(data []byte, write bool) error {
	if d == nil {
		return errors.New("native filesystem service is unavailable")
	}
	limitMiB := d.Config.JsConfig.QuickJSMaxFilesystemReadMiB
	if write {
		limitMiB = d.Config.JsConfig.QuickJSMaxFilesystemWriteMiB
	}
	if limitMiB == 0 {
		return nil
	}
	const mib = uint64(1024 * 1024)
	if limitMiB > ^uint64(0)/mib {
		return errors.New("filesystem limit overflows byte size")
	}
	limit := limitMiB * mib
	if uint64(len(data)) > limit {
		mode := "read"
		if write {
			mode = "write"
		}
		return fmt.Errorf("filesystem %s exceeds %d MiB", mode, limitMiB)
	}
	return nil
}


type nativeServiceFactory struct {
	name       services.Name
	newService func(*Dice, jsengine.Loop) services.Service
}

var nativeServiceFactories = []nativeServiceFactory{
	{name: services.Console, newService: func(d *Dice, _ jsengine.Loop) services.Service {
		return &nativeConsoleService{printer: d.JsPrinter}
	}},
	{name: services.Crypto, newService: func(*Dice, jsengine.Loop) services.Service {
		return &nativeCryptoService{}
	}},
	{name: services.Fetch, newService: func(d *Dice, loop jsengine.Loop) services.Service {
		return newNativeFetchService(d, loop)
	}},
	{name: services.Filesystem, newService: func(d *Dice, _ jsengine.Loop) services.Service {
		return &nativeFilesystemService{dice: d}
	}},
}

type nativeServiceAuthorizer struct {
	dice    *Dice
	context *jsExecutionContext
}

func (a nativeServiceAuthorizer) Authorize(service services.Name, operation services.OperationID, target string) error {
	switch services.NormalizeName(service) {
	case services.Fetch, services.HTTP, services.WebSocket:
		return jsNetworkAuthorizeWithContext(a.dice, a.context, target)
	case services.Filesystem:
		write := operation == services.OpFilesystemWriteFile ||
			operation == services.OpFilesystemWriteFileSync ||
			operation == services.OpFilesystemMkdir ||
			operation == services.OpFilesystemRemove
		return jsFilesystemAuthorizeWithContext(a.dice, a.context, target, write)
	default:
		return nil
	}
}

func (d *Dice) installNativeJSServices(loop jsengine.Loop) (*services.Registry, error) {
	if loop == nil || !loop.Descriptor().Capabilities.Has(jsengine.CapabilityHostService) {
		return nil, nil
	}
	descriptor := loop.Descriptor()
	registry := services.NewRegistry()
	registry.SetPolicyProvider(func(call services.Call) services.Policy {
		return services.Policy{Authorizer: nativeServiceAuthorizer{
			dice:    d,
			context: jsOpaqueExecutionContext(call.Context),
		}}
	})
	for _, factory := range nativeServiceFactories {
		service := factory.newService(d, loop)
		definition := service.Definition()
		if len(definition.AsyncOperations) != 0 && !descriptor.Capabilities.Has(jsengine.CapabilityAsyncHostService) {
			continue
		}
		if err := services.RequireNativeService(descriptor, factory.name); err != nil {
			if errors.Is(err, services.ErrUnsupported) {
				continue
			}
			_ = registry.Close()
			return nil, err
		}
		if err := registry.Register(service); err != nil {
			_ = registry.Close()
			return nil, fmt.Errorf("register native %s service: %w", factory.name, err)
		}
	}
	if err := nativejs.InstallServiceRegistry(loop, registry); err != nil {
		_ = registry.Close()
		return nil, fmt.Errorf("attach native JS service registry: %w", err)
	}
	return registry, nil
}
