# Scardice Runtime ABI v1

This directory defines the C ABI used by Scardice Core to discover and drive a native JavaScript runtime. The v1 surface uses fixed-width integers, opaque handles, borrowed views, caller-owned buffers, function tables, and explicit status codes.

## Status

The repository exposes Runtime ABI v1 and Host ABI v1 through
[`include/scardice_runtime_v1.h`](include/scardice_runtime_v1.h). Runtime
minor remains reserved at zero; Host ABI 1.1 adds an append-only,
`struct_size`-gated HostRef proxy retain/release tail and a method-owner query.

The service callbacks, `tick`, and extension descriptor array remain optional
v1 tails. QuickJS requires Host ABI 1.1: providers retain each HostRef proxy
until finalization and retain a method's owner while its function remains
reachable. Consumers validate every field they use through `struct_size`.

There is no second public compatibility header. Runtime and Host ABI versions
are negotiated independently through the query and descriptor fields.

The ABI directory contains the public contract, compile/layout fixtures, and
service lifecycle rules. Native runtime loading and QuickJS integration live
under [`runtime-plugins/quickjs`](../runtime-plugins/quickjs).

## Contents

- [`include/scardice_runtime_v1.h`](include/scardice_runtime_v1.h) — the only
  active public C header.
- [`ABI.md`](ABI.md) — field order, call semantics, lifetime, threading,
  errors, service lifecycle, and compatibility rules.
- [`CHANGELOG.md`](CHANGELOG.md) — development-contract history.
- [`tests/layout.c`](tests/layout.c) and [`tests/layout.cc`](tests/layout.cc) —
  C and C++ compile/layout smoke fixtures.

- [`tests/conformance.c`](tests/conformance.c) — a linked C fixture that
  instantiates the plugin extension table and exercises the public entry/value
  constants.
- [`tests/compat_v1.c`](tests/compat_v1.c) — compile-time assertions for the
  stable v1 prefixes and optional tails.

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
gcc -std=c11 -Wall -Wextra -Werror \
  runtimeabi/tests/compat_v1.c -o /tmp/scardice-runtimeabi-compat-v1 \
  && /tmp/scardice-runtimeabi-compat-v1
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
- Every v1 struct starts with `uint32_t struct_size`. Consumers read optional
  tail fields only when the producer's `struct_size` covers them and the
  associated capability requires them.
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
