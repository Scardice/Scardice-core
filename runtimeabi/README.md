# Scardice Runtime ABI v1

This directory freezes the C ABI used by Scardice Core to discover and drive a native JavaScript runtime. The v1 surface is intentionally small: fixed-width integers, opaque handles, borrowed views, caller-owned buffers, function tables, and explicit status codes.

## Status

Runtime ABI v1.0 and Host ABI v1.0 are frozen. Existing fields and function-pointer slots are append-only. A v1 implementation must not reorder or reinterpret an existing field. ABI v2 will use a new query symbol rather than changing this contract.

This phase defines the contract and compile/layout fixtures only. It does **not** implement a loader, native runtime, QuickJS integration, or Go adapter.

## Contents

- [`include/scardice_runtime_v1.h`](include/scardice_runtime_v1.h) — the public C header.
- [`ABI.md`](ABI.md) — field order, call semantics, lifetime, threading, errors, and negotiation rules.
- [`CHANGELOG.md`](CHANGELOG.md) — changes to the frozen ABI.
- [`tests/layout.c`](tests/layout.c) and [`tests/layout.cc`](tests/layout.cc) — C and C++ compile/layout smoke fixtures.

## Focused verification

From the repository root:

```sh
gcc -std=c11 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.c -o /tmp/scardice-runtimeabi-layout.o
clang++ -std=c++17 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.cc -o /tmp/scardice-runtimeabi-layout-cxx.o
```

The fixtures compile without linking a runtime plugin. Their `_Static_assert`/`static_assert` checks make accidental layout changes fail at compile time.

## Design rules at a glance

- Handle `0` is invalid/null. `sc_runtime_t`, `sc_value_t`, `sc_host_ref_t`, `sc_host_func_t`, and `sc_host_ctx_t` are opaque `uint64_t` values.
- Every v1 struct starts with `uint32_t struct_size`. Consumers read only the prefix they understand; producers set the size of the fields they provide.
- Strings passed into a call use `sc_string_view` and are borrowed for that call. Returned text uses a caller-provided buffer and the two-call `required` protocol; the DLL never allocates a string for the caller to free.
- Runtime values are handles. Values returned by a call are temporary unless retained with `value_retain`; release retained values with `value_release` before destroying the runtime.
- Runtime instances have thread affinity. A host callback may re-enter value/object operations and `function_call`, but lifecycle operations are not reentrant.
- C++ exceptions and Go panics stop at the ABI boundary and are reported as status codes. Native runtime code is trusted in-process code.
- v1 keeps loaded native libraries resident until process exit. Hosts must not call `dlclose` or `FreeLibrary`.

See [`ABI.md`](ABI.md) for the normative details.
