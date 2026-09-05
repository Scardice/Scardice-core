# Scardice Runtime ABI v1

This directory defines the current development C ABI used by Scardice Core to discover and drive a native JavaScript runtime. The v1 surface uses fixed-width integers, opaque handles, borrowed views, caller-owned buffers, function tables, and explicit status codes.

## Status

The current header is a paired development contract for Core and native
providers. Runtime ABI and Host ABI numeric constants remain `1.0` and `1.1`
while this development break is in flight; those numbers do not promise
binary compatibility with older providers. The active contract requires the
complete current runtime and host tables, including asynchronous service
start/cancel/event slots. There is no active `compat/v1` header or downgrade
path.

Core and provider evolve together; old-consumer compatibility and released
minor-version negotiation are outside this development contract.

The ABI directory contains the active contract, compile/layout fixtures, and
the service lifecycle rules used by native-provider smoke tests. Native
runtime loading and QuickJS integration live under
[`runtime-plugins/quickjs`](../runtime-plugins/quickjs).

## Contents

- [`include/scardice_runtime_v1.h`](include/scardice_runtime_v1.h) — the only
  active public C header.
- [`ABI.md`](ABI.md) — field order, call semantics, lifetime, threading,
  errors, service lifecycle, and negotiation rules.
- [`CHANGELOG.md`](CHANGELOG.md) — development-contract history.
- [`tests/layout.c`](tests/layout.c) and [`tests/layout.cc`](tests/layout.cc) —
  C and C++ compile/layout smoke fixtures.

- [`tests/conformance.c`](tests/conformance.c) — a linked C fixture that
  instantiates the plugin extension table and exercises the public entry/value
  constants.

## Focused verification

From the repository root:

```sh
gcc -std=c11 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.c -o /tmp/scardice-runtimeabi-layout.o
clang++ -std=c++17 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.cc -o /tmp/scardice-runtimeabi-layout-cxx.o
gcc -std=c11 -Wall -Wextra -Werror -Iruntimeabi/include \
  runtimeabi/tests/conformance.c -o /tmp/scardice-runtimeabi-conformance \
  && /tmp/scardice-runtimeabi-conformance
```

The fixtures compile without linking a runtime plugin. Their `_Static_assert`/
`static_assert` checks make accidental layout changes fail at compile time.

## Design rules at a glance

- Entry kinds (`SC_ENTRY_*`) and value tags (`SC_VALUE_TYPE_*`) are public
  numeric constants; callers do not duplicate private engine numbering.
- `sc_runtime_plugin_v1` appends an optional extension descriptor array. The
  context extension (`scardice.runtime.context.v1`) carries owner-thread
  execution-context tokens for script, timer, Promise, and service callbacks.
  Providers declare this guarantee with `SC_CAP_CONTEXT_PROPAGATION` (bit 10).
  Core rejects that declaration unless the context extension is valid.
- Handle `0` is invalid/null. `sc_runtime_t`, `sc_value_t`, `sc_host_ref_t`,
  `sc_host_func_t`, `sc_host_ctx_t`, and `sc_service_request_t` are opaque
  `uint64_t` values.
- Every v1 struct starts with `uint32_t struct_size`. The current paired
  provider must expose the complete table size; an older short table is
  rejected rather than downgraded.
- `service_call` is synchronous. `service_start` returns a request handle,
  `service_cancel` requests cancellation, and `service_event` delivers copied
  data followed by exactly one terminal complete/close event.
- `tick` is the host-driven owner-thread pump for Promise jobs and due timers;
  hosts call it while a runtime is alive.
- Async string/byte payloads are owned by the caller of `service_event` only
  for that call. A provider must copy anything it retains; no Go or QuickJS
  pointer crosses the boundary.
- Strings passed into a call use `sc_string_view` and are borrowed for that
  call. Returned text uses a caller-provided buffer and the two-call
  `required` protocol.
- Runtime values are handles. Values returned by a call are temporary unless
  retained with `value_retain`; release retained values with `value_release`
  before destroying the runtime.
- Runtime instances have thread affinity. A host callback may re-enter value/
  object operations and `function_call`, but lifecycle operations are not
  reentrant.
- C++ exceptions and Go panics stop at the ABI boundary and are reported as
  status codes. Native runtime code is trusted in-process code.
- v1 keeps loaded native libraries resident until process exit. Hosts must not
  call `dlclose` or `FreeLibrary`.
