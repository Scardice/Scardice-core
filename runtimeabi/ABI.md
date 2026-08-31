# Runtime ABI v1 reference

This document is normative for `include/scardice_runtime_v1.h`. The ABI is a C layout contract that can also be included by C++. It contains no ABI-sensitive C enum, bitfield, `interface{}`, `reflect.Value`, Go pointer, Go map/slice/function, `*Dice`, or `*ExtInfo`.

## Version domains

Scardice keeps these versions independent:

| Domain | Controls |
| --- | --- |
| Runtime ABI | The Core-to-native-runtime binary protocol. |
| Host ABI | The runtime-to-HostBridge/service callback protocol. |
| Seal JS API | Compatibility of the user-facing `seal.*` JavaScript API. |
| Runtime Version | The implementation/version of a runtime provider (for example, QuickJS). |

The Scardice product version does not imply any of these versions. The header declares `SC_RUNTIME_ABI_MAJOR 1`, `SC_RUNTIME_ABI_MINOR 0`, `SC_HOST_ABI_MAJOR 1`, and `SC_HOST_ABI_MINOR 0`.

A host fills `sc_runtime_query_v1` with the versions it supports. A major-version mismatch rejects the plugin. With the same major, negotiation accepts a plugin when its required minor is less than or equal to the host minor. A minor release may only append fields, function-pointer slots, or capability bits. ABI v2 uses a new `scardice_runtime_query_v2` symbol.

Every v1 struct begins with `uint32_t struct_size`. A producer sets it to the byte size of the prefix it provides. A consumer checks that the received size covers a field before reading it and treats omitted tail fields as unavailable. Existing fields and slots must never be reordered, removed, or assigned new semantics. Unknown appended fields are ignored.

## Scalar types and constants

The public scalar types are fixed-width:

```c
typedef int32_t  sc_status_t;
typedef uint64_t sc_runtime_t;
typedef uint64_t sc_value_t;
typedef uint64_t sc_host_ref_t;
typedef uint64_t sc_host_func_t;
typedef uint64_t sc_host_ctx_t;
```

All handle values are opaque; `0` is invalid/null. The status constants are:

| Macro | Value | Meaning |
| --- | ---: | --- |
| `SC_OK` | 0 | Success. |
| `SC_EINVAL` | -1 | Invalid argument, handle, or buffer shape. |
| `SC_EABI` | -2 | ABI/version/struct-size incompatibility. |
| `SC_ENOTSUP` | -3 | Capability or operation is not supported. |
| `SC_ESTATE` | -4 | Operation is invalid for the current lifecycle state. |
| `SC_ECLOSED` | -5 | Runtime or host session has been closed. |
| `SC_EEXCEPTION` | -10 | The runtime caught a script/native exception. |
| `SC_EOOM` | -11 | Allocation failed. |
| `SC_ETIMEOUT` | -12 | A synchronous operation timed out. |
| `SC_EHOST` | -20 | Host callback failed. |
| `SC_EINTERNAL` | -100 | Unexpected provider/internal failure. |

The capability masks are fixed-width `UINT64_C(1) << n` values: `SC_CAP_SCRIPT` (0), `SC_CAP_COMMONJS` (1), `SC_CAP_ESM` (2), `SC_CAP_PROMISE` (3), `SC_CAP_TIMERS` (4), `SC_CAP_HOST_OBJECT` (5), `SC_CAP_HOST_FUNCTION` (6), `SC_CAP_ASYNC_HOST_SERVICE` (7), and `SC_CAP_SOURCE_LOCATION` (8).

## Strings and caller-provided buffers

`sc_string_view` contains a pointer and a byte length; it is not required to be NUL-terminated. Its `data` is borrowed only for the duration of the call. The caller keeps the pointed-to bytes immutable and alive until the callee returns. A zero-length view may use a null pointer.

`value_to_utf8_copy`, the runtime `last_error_copy`, `host_keys_json`, and the Host API `last_error_copy` never return an allocated string. They use this two-call protocol:

1. Set `buffer = NULL` and `capacity = 0`, provide a valid `required` pointer, and call to obtain the required byte count.
2. Allocate the buffer in the caller, call again with its capacity, and read the returned bytes.

The required count includes the bytes to copy and excludes a trailing NUL unless the API's documented text format requires one. The callee writes no more than `capacity`; insufficient capacity returns `SC_EINVAL` (or the provider's documented buffer status) and updates `required`. `required` must be non-null for both calls. Caller-owned buffers remain valid only for the call.

## Struct layout

The exact field order is:

```c
typedef struct sc_runtime_descriptor_v1 {
    uint32_t struct_size;
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t host_abi_major;
    uint32_t host_abi_minor;
    uint64_t capabilities;
    const char *id;
    const char *name;
    const char *version;
    const char *language;
} sc_runtime_descriptor_v1;

typedef struct sc_runtime_create_info_v1 {
    uint32_t struct_size;
    sc_string_view options_json;
} sc_runtime_create_info_v1;

typedef struct sc_runtime_query_v1 {
    uint32_t struct_size;
    uint32_t runtime_abi_major;
    uint32_t runtime_abi_minor;
    uint32_t host_abi_major;
    uint32_t host_abi_minor;
} sc_runtime_query_v1;
```

`options_json` is an opaque UTF-8 JSON byte view owned by the caller for `create`. The descriptor strings (`id`, `name`, `version`, and `language`) point to plugin static storage and remain valid from library load until process exit.

## Runtime API table

`sc_runtime_api_v1` starts with `struct_size`, followed by function pointers in this exact order:

1. `create(const sc_host_api_v1 *host, sc_host_ctx_t host_ctx, const sc_runtime_create_info_v1 *info, sc_runtime_t *out_runtime)`
2. `start(sc_runtime_t runtime)`
3. `stop(sc_runtime_t runtime)`
4. `destroy(sc_runtime_t runtime)`
5. `eval(sc_runtime_t runtime, sc_string_view filename, sc_string_view source, sc_value_t *out)`
6. `load_entry(sc_runtime_t runtime, uint32_t entry_kind, sc_string_view filename, sc_string_view source, sc_value_t *out)`
7. `global_get(sc_runtime_t runtime, sc_string_view name, sc_value_t *out)`
8. `global_set(sc_runtime_t runtime, sc_string_view name, sc_value_t value)`
9. `object_new(sc_runtime_t runtime, sc_value_t *out)`
10. `object_get(sc_runtime_t runtime, sc_value_t object, sc_string_view key, sc_value_t *out)`
11. `object_set(sc_runtime_t runtime, sc_value_t object, sc_string_view key, sc_value_t value)`
12. `object_has(sc_runtime_t runtime, sc_value_t object, sc_string_view key, uint32_t *out)`
13. `value_new_undefined(sc_runtime_t runtime, sc_value_t *out)`
14. `value_new_null(sc_runtime_t runtime, sc_value_t *out)`
15. `value_new_bool(sc_runtime_t runtime, uint32_t value, sc_value_t *out)`
16. `value_new_i64(sc_runtime_t runtime, int64_t value, sc_value_t *out)`
17. `value_new_u64(sc_runtime_t runtime, uint64_t value, sc_value_t *out)`
18. `value_new_f64(sc_runtime_t runtime, double value, sc_value_t *out)`
19. `value_new_string(sc_runtime_t runtime, sc_string_view value, sc_value_t *out)`
20. `value_type(sc_runtime_t runtime, sc_value_t value, uint32_t *out_type)`
21. `value_to_bool(sc_runtime_t runtime, sc_value_t value, uint32_t *out)`
22. `value_to_i64(sc_runtime_t runtime, sc_value_t value, int64_t *out)`
23. `value_to_u64(sc_runtime_t runtime, sc_value_t value, uint64_t *out)`
24. `value_to_f64(sc_runtime_t runtime, sc_value_t value, double *out)`
25. `value_to_utf8_copy(sc_runtime_t runtime, sc_value_t value, char *buffer, uint64_t capacity, uint64_t *required)`
26. `value_get_host_ref(sc_runtime_t runtime, sc_value_t value, sc_host_ref_t *out_ref, uint32_t *out_host_kind)`
27. `host_object_new(sc_runtime_t runtime, sc_host_ref_t ref, uint32_t host_kind, sc_value_t *out)`
28. `host_function_new(sc_runtime_t runtime, sc_host_func_t function, sc_value_t *out)`
29. `function_call(sc_runtime_t runtime, sc_value_t function, sc_value_t this_value, const sc_value_t *argv, uint64_t argc, sc_value_t *out)`
30. `value_retain(sc_runtime_t runtime, sc_value_t value)`
31. `value_release(sc_runtime_t runtime, sc_value_t value)`
32. `last_error_copy(sc_runtime_t runtime, char *buffer, uint64_t capacity, uint64_t *required)`

The constructors, conversion functions, object functions, and invocation functions write results only through caller-provided output pointers. `destroy` is the sole v1 lifecycle function with no status return; it must be safe to call after a successful `create` and the host must not use the runtime handle afterward.

## Host API table

`sc_host_api_v1` starts with `struct_size`, `abi_major`, and `abi_minor`, followed by these slots in exact order:

1. `host_get(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view key, sc_value_t *out)`
2. `host_set(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view key, sc_value_t value)`
3. `host_has(sc_host_ctx_t, sc_host_ref_t, sc_string_view key, uint32_t *out)`
4. `host_delete(sc_host_ctx_t, sc_host_ref_t, sc_string_view key, uint32_t *deleted)`
5. `host_keys_json(sc_host_ctx_t, sc_host_ref_t, char *buffer, uint64_t capacity, uint64_t *required)`
6. `host_call(sc_host_ctx_t, sc_runtime_t, sc_host_func_t, sc_value_t this_value, const sc_value_t *argv, uint64_t argc, sc_value_t *out)`
7. `last_error_copy(sc_host_ctx_t, char *buffer, uint64_t capacity, uint64_t *required)`

Host references and host function references are opaque session handles, not addresses. A host reference is valid for its runtime session and is released when that session closes; v1 does not require cross-session reference counting. A callback must not retain borrowed key/argument data after it returns. The host keeps the callback table and `host_ctx` valid until every runtime using them has been destroyed.

## Plugin query and lifecycle

The plugin exports exactly the stable query entry point:

```c
SC_EXPORT sc_status_t SC_CALL scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query,
    const sc_runtime_plugin_v1 **out_plugin);
```

`sc_runtime_plugin_v1` is append-only and contains `struct_size`, then the embedded `sc_runtime_descriptor_v1 descriptor`, then the embedded `sc_runtime_api_v1 api`. A successful query returns a pointer to plugin-owned static storage. The host validates the returned prefix, version fields, capabilities, and function pointers before calling `create`.

The lifecycle is `query → create → start → calls → stop → destroy`. `start` and `stop` are explicit and may return a status. `destroy` invalidates the runtime and all non-retained values. v1 never unloads a native library: the host must not call `dlclose` on POSIX or `FreeLibrary` on Windows; the library remains loaded through process exit.

## Value ownership and callbacks

A value handle returned by an API call is owned by the current runtime call scope. The host must not let an unretained value escape that scope. `value_retain` promotes a value to persistent ownership; every successful retain requires a matching `value_release` before `destroy`. Do not rely on a Go finalizer for correctness. A value from one runtime cannot be used with another runtime.

When a runtime invokes a host object or host function, the host callback may use borrowed arguments only until it returns. Host callbacks may call `value_new_*`, `value_type`, `value_to_*`, `host_object_new`, `host_function_new`, `value_retain`, `value_release`, `function_call`, `object_get`, and `object_set` reentrantly. `create`, `start`, `stop`, `destroy`, and `load_entry` are not reentrant from a host callback. Providers must avoid waiting on their own callback thread; an implementation that queues work to a worker executes reentrant calls inline on that worker to avoid deadlock.

Each runtime instance has thread affinity. The provider owns its scheduling policy, but all operations on a runtime and its values must obey the provider's documented affinity; a typical provider serializes calls on one runtime worker thread. The host must synchronize calls from other threads and must not use a runtime or its values concurrently unless the provider explicitly documents that support.

## Error and exception boundary

Functions report ordinary failure through `sc_status_t`; details are retrieved with the relevant `last_error_copy`. A script exception is `SC_EEXCEPTION`, a host callback failure is `SC_EHOST`, and unsupported capabilities return `SC_ENOTSUP`. C++ exceptions and Go panics must be caught before crossing the C ABI and converted to these statuses. No exception, panic, language runtime pointer, or allocated string crosses the boundary.

The native runtime is trusted in-process code. Loading a plugin is not a sandbox boundary: the host must only load code it trusts and must validate its descriptor and table before use.
