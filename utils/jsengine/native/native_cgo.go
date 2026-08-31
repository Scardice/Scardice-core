//go:build cgo

package native

/*
#cgo linux LDFLAGS: -ldl
#cgo freebsd LDFLAGS: -ldl
#include "bridge.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"fmt"
	"path/filepath"
	"unsafe"

	"Scardice-core/utils/jsengine"
)

const (
	hostABIMajor    = 1
	hostABIMinor    = 0
	runtimeABIMajor = 1
	runtimeABIMinor = 0
)

type Provider struct {
	candidate Candidate
	descriptor jsengine.Descriptor
	library    uint64
}

type LoadedProvider = Provider

func Load(candidate Candidate) (*Provider, error) { return candidate.Load() }

func loadNative(candidate Candidate) (*Provider, error) {
	absolutePath, err := filepath.Abs(candidate.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMissingLibrary, candidate.LibraryPath, err)
	}
	candidate.LibraryPath = absolutePath
	path := C.CString(absolutePath)
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

func (p *Provider) Descriptor() jsengine.Descriptor { return p.descriptor }

func (p *Provider) Open(ctx context.Context, options jsengine.RuntimeOptions) (jsengine.Loop, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload := options.OptionsJSON
	var ptr *C.char
	if len(payload) != 0 {
		ptr = (*C.char)(C.CBytes(payload))
		defer C.free(unsafe.Pointer(ptr))
	}
	errorBuffer := make([]byte, 512)
	var runtimeHandle C.uint64_t
	status := C.sc_native_create(C.uint64_t(p.library), ptr, C.uint64_t(len(payload)), &runtimeHandle,
		(*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if status != C.SC_NATIVE_OK {
		return nil, wrapNativeError(status, p.candidate.LibraryPath, cError(errorBuffer))
	}
	status = C.sc_native_start(C.uint64_t(p.library), runtimeHandle, (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	if status != C.SC_NATIVE_OK {
		_ = C.sc_native_destroy(C.uint64_t(p.library), runtimeHandle, nil, 0)
		return nil, wrapNativeError(status, p.candidate.LibraryPath, cError(errorBuffer))
	}
	return &nativeLoop{provider: p, runtime: uint64(runtimeHandle)}, nil
}

type nativeLoop struct {
	provider *Provider
	runtime  uint64
	closed   bool
}

func (l *nativeLoop) Engine() jsengine.EngineID { return l.provider.descriptor.ID }
func (l *nativeLoop) Run(func(jsengine.Runtime) error) error { return ErrNativeUnavailable }
func (l *nativeLoop) Close() {
	if l.closed { return }
	l.closed = true
	var errorBuffer [256]byte
	_ = C.sc_native_stop(C.uint64_t(l.provider.library), C.uint64_t(l.runtime), (*C.char)(unsafe.Pointer(&errorBuffer[0])), C.uint64_t(len(errorBuffer)))
	_ = C.sc_native_destroy(C.uint64_t(l.provider.library), C.uint64_t(l.runtime), nil, 0)
}

func ResidentLibraryCount() uint64 { return uint64(C.sc_native_resident_count()) }
