# Changelog

All notable changes to the Scardice native runtime ABI are recorded here.
Released contracts are append-only.

## Unreleased

### Changed

- Runtime ABI remains v1; the current Host ABI is v1.2.
- Runtime minor remains reserved at zero. Host minor 1 appends struct-size-
  gated HostRef proxy retain/release callbacks and a host-function owner
  query.
- Host minor 2 appends `execution_status` for owner-thread cancellation and
  deadline checks. Core and QuickJS require this contract instead of running
  native script without a cancellation mechanism.
- The previous service-event `reserved` word is now `flags`, preserving its
  layout. Host ABI 1.2 uses `SC_SERVICE_EVENT_DISCARD_CONTINUATIONS` for
  terminal-only cleanup after invocation, binding, or durable admission
  failure; providers release request values without running script.
- Runtime and Host ABI versions are queried independently and reported in the
  provider descriptor.
- `service_event`, `tick`, the plugin extension table, and Host service
  callbacks remain optional v1 tails guarded by `struct_size` and capability
  bits. Providers that create HostRef proxies must implement the Host ABI 1.1
  lifecycle callbacks and preserve an owner for retained method functions.
- Core accepts shorter v1 provider tables only when their declared
  capabilities do not require omitted callbacks.
- QuickJS native service coverage includes console, crypto, fetch,
  filesystem, and WebSocket operations.
- Public entry-kind and value-type constants live in the v1 header.
- The context extension propagates opaque execution identity across script,
  timer, Promise, and host-service callbacks.
- `runtimeabi/tests/conformance.c`, `runtimeabi/tests/compat_v1.c`, and the
  QuickJS CTest fixtures validate constants, stable prefixes, current version
  fields, and extension-table wiring.
- Added `SC_CAP_CONTEXT_PROPAGATION` / Go
  `CapabilityContextPropagation` at bit 10. Core rejects the declaration if
  its context extension version, size, or callbacks are invalid.

## Initial v1 contract

- Public C/C++ header: `include/scardice_runtime_v1.h`.
- Fixed-width status, runtime, value, host-reference, host-function,
  host-context, and service-request types.
- Opaque string views and caller-provided two-call buffer APIs.
- Append-only runtime descriptor, create-info, query, runtime API, host API,
  and plugin structs.
- Explicit runtime lifecycle, value retain/release, host callback,
  thread-affinity, reentrancy, error, and no-unload rules.
- Handle value `0` is invalid/null.
- C++ exceptions and Go panics must not cross the ABI boundary.
- Native libraries remain loaded until process exit.
- Seal JS API compatibility and Runtime Version are separate version domains
  from Runtime ABI and Host ABI.
