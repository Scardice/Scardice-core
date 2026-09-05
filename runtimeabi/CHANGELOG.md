# Changelog

All notable changes to the Scardice native runtime ABI are recorded here. Released contracts are append-only, but the current development tree is an explicit paired break and is not an old-provider compatibility promise.
## Development tree — current paired ABI

### Changed

- The active header now appends typed asynchronous service start/cancel/event
  slots and the `sc_service_event_v1` envelope, plus the owner-thread `tick`
  progression hook.
- The current Core and standalone provider are rebuilt as one development
  pair. Older short tables and the former `compat/v1` fixture are not
  supported.
- QuickJS native service coverage now includes console, crypto, fetch, and
  filesystem operations, with separate synchronous filesystem operation
  identifiers.
- Runtime and provider version strings, and the numeric ABI constants, remain
  unchanged during development.
- Public entry-kind and value-type constants now live in the header.
- The plugin table appends a validated extension descriptor array. QuickJS
  exposes the context extension used to propagate opaque execution identity
  across script, timer, Promise, and host-service callbacks.
- `runtimeabi/tests/conformance.c` and the QuickJS CTest integration fixture
  validate constants and extension-table wiring beyond raw layout offsets.
- Added `SC_CAP_CONTEXT_PROPAGATION` / Go `CapabilityContextPropagation` at
  bit 10. QuickJS declares the capability; Core rejects the declaration if
  its context extension version, size, or callbacks are invalid.
- Retained Runtime ABI `1.0`, Host ABI `1.1`, and existing v1 header/query
  names. This remains a paired development contract, not an old-consumer
  compatibility or independent-release negotiation promise.


## [1.1.0] — Host service extension

### Added

- Host ABI v1.1 `service_call` with fixed-width scalar/bytes request and response unions.
- Typed `SC_SERVICE_*` statuses and console operation identifiers.
- `SC_CAP_HOST_SERVICE` capability bit for providers that dispatch synchronous host services.
- QuickJS native provider metadata for the `console` service.

### Compatibility constraints

- This development break intentionally has no old-provider downgrade path.
- A future published incompatible contract will use a new query symbol rather
  than silently changing an existing release contract.

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
