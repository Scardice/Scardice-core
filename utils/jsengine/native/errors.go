package native

import "errors"

var (
	// Stable categories are intentionally independent of platform loader text.
	ErrMissingLibrary          = errors.New("native runtime library missing")
	ErrMissingQuerySymbol      = errors.New("native runtime query symbol missing")
	ErrRuntimeABIMismatch      = errors.New("native runtime ABI mismatch")
	ErrHostABIMismatch         = errors.New("native host ABI mismatch")
	ErrManifestIDVersionMismatch = errors.New("native manifest id/version mismatch")
	ErrDescriptorIDVersionMismatch = errors.New("native descriptor id/version mismatch")
	ErrManifestMismatch        = ErrManifestIDVersionMismatch
	ErrDescriptorMismatch      = ErrDescriptorIDVersionMismatch
	ErrUnsupportedArchitecture = errors.New("native runtime architecture unsupported")
	ErrPluginCreateFailure     = errors.New("native runtime create failed")
	ErrCorruptVTable           = errors.New("native runtime corrupt vtable")
	ErrTooSmallStruct          = errors.New("native runtime struct too small")
	ErrNativeUnavailable       = errors.New("native runtime unavailable")
)
