// Package gojaservices adapts the existing Goja-native modules to the shared
// host-service installation boundary. The module implementations remain
// adapter-owned; this package only controls registration, installation order,
// and lifecycle ownership.
package gojaservices

import (
	"errors"
	"net/http"
	"sync"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/buffer"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	"github.com/dop251/goja_nodejs/url"
	"github.com/dop251/goja_nodejs/util"

	"Scardice-core/utils/jsengine/services"
	sealabort "Scardice-core/utils/plugin/abort"
	sealcrypto "Scardice-core/utils/plugin/crypto"
	sealhttp "Scardice-core/utils/plugin/httpextra"
	sealsclone "Scardice-core/utils/plugin/structuredclone"
	sealutil "Scardice-core/utils/plugin/utilinspect"
	sealws "Scardice-core/utils/plugin/websocket"
)

// FilesystemHooks keep Dice's SealPack-aware filesystem implementation behind
// the adapter boundary without making that implementation part of the generic
// service registry.
type FilesystemHooks struct {
	Require func(*goja.Runtime, *goja.Object)
	Enable  func(*goja.Runtime)
}

// Options configures one Goja module installation.
type Options struct {
	Registry         *require.Registry
	Loop             *eventloop.EventLoop
	Proxy            http.Handler
	Printer          console.Printer
	Logger           sealws.Logger
	NetworkAuthorize func(string) error
	CurrentContext   func() any
	ScheduleOnLoop   func(any, func(*goja.Runtime) error) error
	Filesystem       FilesystemHooks
}

// Installer owns all Goja-native service bindings for one runtime generation.
type Installer struct {
	options Options

	mu             sync.Mutex
	installed      bool
	closed         bool
	fetchLifecycle *sealhttp.FetchLifecycle
}

func NewInstaller(options Options) *Installer {
	installer := &Installer{options: options}
	if options.Proxy != nil {
		installer.fetchLifecycle = sealhttp.NewFetchLifecycle()
	}
	return installer
}
func (i *Installer) Owner() string { return "goja" }

// runtime-owned dependencies are absent rather than being advertised as no-op
// implementations.
func (i *Installer) Definitions() []services.Definition {
	definitions := []services.Definition{
		{Name: services.Console, Operations: []services.OperationID{
			services.OpConsoleLog, services.OpConsoleInfo, services.OpConsoleWarn, services.OpConsoleError,
		}, Adapter: "goja"},
		{Name: services.Crypto, Operations: []services.OperationID{
			services.OpCryptoDigest, services.OpCryptoRandomBytes,
		}, Adapter: "goja"},
		{Name: services.Abort, Operations: []services.OperationID{
			services.OpAbortCreate, services.OpAbortCancel,
		}, Adapter: "goja"},
		{Name: services.StructuredClone, Operations: []services.OperationID{services.OpStructuredClone}, Adapter: "goja"},
		{Name: services.UtilInspect, Operations: []services.OperationID{services.OpUtilInspect}, Adapter: "goja"},
	}
	if i != nil && i.options.Loop != nil && i.options.Proxy != nil {
		definitions = append(definitions,
			services.Definition{Name: services.Fetch, Operations: []services.OperationID{services.OpFetchRequest}, Adapter: "goja"},
			services.Definition{Name: services.HTTP, Operations: []services.OperationID{services.OpHTTPRequest}, Adapter: "goja"},
			services.Definition{Name: services.WebSocket, Operations: []services.OperationID{
				services.OpWebSocketConnect, services.OpWebSocketSend, services.OpWebSocketClose,
			}, Adapter: "goja"},
		)
	}
	if i != nil && i.options.Filesystem.Require != nil && i.options.Filesystem.Enable != nil {
		definitions = append(definitions, services.Definition{Name: services.Filesystem, Operations: []services.OperationID{
			services.OpFilesystemReadFile, services.OpFilesystemWriteFile, services.OpFilesystemStat,
			services.OpFilesystemReadDir, services.OpFilesystemMkdir, services.OpFilesystemRemove,
		}, Adapter: "goja"})
	}
	return definitions
}

// Install registers CommonJS native loaders. Global objects are installed by
// Enable inside the owning Goja loop, preserving event-loop affinity.
func (i *Installer) Install() error {
	if i == nil {
		return errors.New("goja service installer is nil")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return errors.New("goja service installer is closed")
	}
	if i.options.Logger != nil {
		sealws.SetLogger(i.options.Logger)
	}
	if i.installed {
		return nil
	}
	if i.options.Registry == nil {
		return errors.New("goja require registry is required")
	}
	if i.options.Loop == nil {
		return errors.New("goja event loop is required")
	}
	printer := i.options.Printer
	if printer != nil {
		i.options.Registry.RegisterNativeModule("console", console.RequireWithPrinter(printer))
	} else {
		i.options.Registry.RegisterNativeModule("console", console.Require)
	}
	i.options.Registry.RegisterNativeModule("crypto", sealcrypto.Require)
	i.options.Registry.RegisterNativeModule("@seal/abort", sealabort.Require)
	i.options.Registry.RegisterNativeModule("@seal/http", sealhttp.Require)
	i.options.Registry.RegisterNativeModule("@seal/structuredclone", sealsclone.Require)
	i.options.Registry.RegisterNativeModule("@seal/utilinspect", sealutil.Require)
	if i.options.Filesystem.Require != nil && i.options.Filesystem.Enable != nil {
		i.options.Registry.RegisterNativeModule("fs", i.options.Filesystem.Require)
	}
	i.installed = true
	return nil
}

// Enable installs globals inside one Goja runtime. It must run on the owner
// loop, as do all existing Goja module APIs.
func (i *Installer) Enable(vm *goja.Runtime) error {
	if i == nil || vm == nil {
		return errors.New("goja runtime is required")
	}
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return errors.New("goja service installer is closed")
	}
	if !i.installed {
		i.mu.Unlock()
		return errors.New("goja service installer is not installed")
	}
	i.mu.Unlock()

	console.Enable(vm)
	sealws.EnableWithPolicy(vm, i.options.Loop, i.options.NetworkAuthorize)
	i.options.Registry.Enable(vm)
	sealcrypto.Enable(vm)
	buffer.Enable(vm)
	url.Enable(vm)
	sealabort.Enable(vm)
	sealhttp.Enable(vm)
	if i.options.Proxy != nil {
		if err := sealhttp.EnableFetchWithPolicyAndLifecycleAndContext(
			vm,
			i.options.Loop,
			i.options.Proxy,
			i.options.NetworkAuthorize,
			i.fetchLifecycle,
			sealhttp.AsyncContextHooks{
				CurrentContext: i.options.CurrentContext,
				ScheduleOnLoop: i.options.ScheduleOnLoop,
			},
		); err != nil {
			return err
		}
	}
	sealsclone.Enable(vm)
	sealutil.Enable(vm)
	if i.options.Filesystem.Enable != nil {
		i.options.Filesystem.Enable(vm)
	}
	utilMod := vm.NewObject()
	utilExports := vm.NewObject()
	if err := utilMod.Set("exports", utilExports); err != nil {
		return err
	}
	util.Require(vm, utilMod)
	if err := utilExports.Set("inspect", sealutil.Inspect(vm)); err != nil {
		return err
	}
	return vm.Set("util", utilExports)
}

// Close tears down adapter-owned external resources. Existing WebSocket
// connections own their event-loop goroutines and are closed before the loop
// is released by JsLoopManager.
func (i *Installer) Close() error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	i.mu.Unlock()
	if err := i.fetchLifecycle.Close(); err != nil {
		return err
	}
	sealws.GlobalConnManager.CloseAll()
	return nil
}
