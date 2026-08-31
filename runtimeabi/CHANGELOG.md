# Changelog

All notable changes to the Scardice native runtime ABI are recorded here. The v1 surface is append-only: a compatible minor revision may add fields, function-pointer slots, or capability bits, but it must not reorder existing members or change their meaning.

## [1.0.0] — Frozen

### Added

- Public C/C++ header: `include/scardice_runtime_v1.h`.
- Runtime ABI and Host ABI version domains, both at major `1`, minor `0`.
- Fixed-width status, runtime, value, host-reference, host-function, and host-context types.
- Opaque string views and caller-provided two-call buffer APIs.
- Append-only runtime descriptor, create-info, query, runtime API, host API, and plugin structs.
- Capability masks for script, CommonJS, ESM, Promise, timers, host objects, host functions, asynchronous host services, and source locations.
- Explicit runtime lifecycle, value retain/release, host callback, thread-affinity, reentrancy, error, and no-unload rules.
- C and C++ compile/layout smoke fixtures with compile-time offset and size assertions.

### Compatibility constraints

- Handle value `0` is invalid/null.
- C++ exceptions and Go panics must not cross the ABI boundary.
- Native libraries remain loaded until process exit; v1 does not use `dlclose` or `FreeLibrary`.
- Seal JS API compatibility and Runtime Version are separate version domains from Runtime ABI and Host ABI.

[1.0.0]: include/scardice_runtime_v1.h
