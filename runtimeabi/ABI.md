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

The header currently declares `SC_RUNTIME_ABI_MAJOR 1`, `SC_RUNTIME_ABI_MINOR 0`, `SC_HOST_ABI_MAJOR 1`, and `SC_HOST_ABI_MINOR 1`. Core and provider are a paired development contract: these numbers and the v1 header/query names remain unchanged, and do not promise compatibility with older consumers or providers. The current bridge requires matching Runtime and Host major/minor values; this is not a released minor-version negotiation policy.

The runtime plugin table keeps its original `struct_size`, descriptor, and API
prefix. `extension_count` and `extensions` are append-only optional tail
fields: a provider that reports only the original prefix is accepted with an
empty extension table. Providers that report a partial tail or malformed
extension descriptors are rejected before `create`.

Every v1 struct begins with `uint32_t struct_size`. Producers set it to the byte size of the fields they provide. Consumers validate that the received size covers every field they read. This protects diagnostics and layout validation; optional tail fields are read only when covered by `struct_size`.

## Scalar types and constants

The public scalar types are fixed-width:

```c
typedef int32_t  sc_status_t;
typedef uint64_t sc_runtime_t;
typedef uint64_t sc_value_t;
typedef uint64_t sc_host_ref_t;
typedef uint64_t sc_host_func_t;
typedef uint64_t sc_host_ctx_t;
typedef uint64_t sc_service_request_t;
```

The public entry-kind constants are:

| Macro | Value | Meaning |
| --- | ---: | --- |
| `SC_ENTRY_SCRIPT` | 0 | Evaluate a global script. |
| `SC_ENTRY_COMMONJS` | 1 | Evaluate a CommonJS module and return its exports. |
| `SC_ENTRY_ESMODULE` | 2 | Evaluate an ES module entry. |
| `SC_ENTRY_EXTENSION` | 3 | Evaluate an extension script. |

The public value-type constants are fixed-width numeric tags:
`SC_VALUE_TYPE_UNDEFINED` (0), `SC_VALUE_TYPE_NULL` (1),
`SC_VALUE_TYPE_BOOL` (2), `SC_VALUE_TYPE_I64` (3),
`SC_VALUE_TYPE_U64` (4), `SC_VALUE_TYPE_F64` (5),
`SC_VALUE_TYPE_STRING` (6), `SC_VALUE_TYPE_OBJECT` (7),
`SC_VALUE_TYPE_HOST_OBJECT` (8), `SC_VALUE_TYPE_HOST_FUNCTION` (9),
and `SC_VALUE_TYPE_FUNCTION` (10). These tags are returned by
`value_type`; they are not C enum types and therefore do not depend on
compiler enum width.

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

The capability masks are fixed-width `UINT64_C(1) << n` values: `SC_CAP_SCRIPT` (0), `SC_CAP_COMMONJS` (1), `SC_CAP_ESM` (2), `SC_CAP_PROMISE` (3), `SC_CAP_TIMERS` (4), `SC_CAP_HOST_OBJECT` (5), `SC_CAP_HOST_FUNCTION` (6), `SC_CAP_ASYNC_HOST_SERVICE` (7), `SC_CAP_SOURCE_LOCATION` (8), `SC_CAP_HOST_SERVICE` (9), and `SC_CAP_CONTEXT_PROPAGATION` (10).

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
33. `service_event(sc_runtime_t runtime, const sc_service_event_v1 *event)`
34. `tick(sc_runtime_t runtime)`

The constructors, conversion functions, object functions, and invocation functions write results only through caller-provided output pointers. `destroy` is the sole v1 lifecycle function with no status return; it must be safe to call after a successful `create` and the host must not use the runtime handle afterward.
`tick` is the host-driven event-loop progression hook. It executes pending Promise jobs and due timers on the runtime owner thread, and returns `SC_OK` when the queue is idle. Hosts should call it while the loop is alive; it is safe to call when no timer or job is pending.

## Host API table

`sc_host_api_v1` starts with `struct_size`, `abi_major`, and `abi_minor`, followed by these slots in exact order:

1. `host_get(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view key, sc_value_t *out)`
2. `host_set(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view key, sc_value_t value)`
3. `host_has(sc_host_ctx_t, sc_host_ref_t, sc_string_view key, uint32_t *out)`
4. `host_delete(sc_host_ctx_t, sc_host_ref_t, sc_string_view key, uint32_t *deleted)`
5. `host_keys_json(sc_host_ctx_t, sc_host_ref_t, char *buffer, uint64_t capacity, uint64_t *required)`
6. `host_call(sc_host_ctx_t, sc_runtime_t, sc_host_func_t, sc_value_t this_value, const sc_value_t *argv, uint64_t argc, sc_value_t *out)`
7. `last_error_copy(sc_host_ctx_t, char *buffer, uint64_t capacity, uint64_t *required)`
8. `service_call(sc_host_ctx_t, sc_runtime_t, sc_string_view service, const sc_host_service_request_v1 *request, sc_host_service_response_v1 *response)`
9. `service_start(sc_host_ctx_t, sc_runtime_t, sc_string_view service, const sc_host_service_request_v1 *request, sc_service_request_t *out_request)`
10. `service_cancel(sc_host_ctx_t, sc_runtime_t, sc_service_request_t request)`

Host references and host function references are opaque session handles, not addresses. A host reference is valid for its runtime session and is released when that session closes; v1 does not require cross-session reference counting. A callback must not retain borrowed key/argument data after it returns. The host keeps the callback table and `host_ctx` valid until every runtime using them has been destroyed.

The host-service request and response envelopes are fixed-width and contain no language-runtime pointers beyond borrowed string/byte views:

```c
typedef struct sc_host_service_request_v1 {
    uint32_t struct_size;
    uint32_t operation;
    sc_string_view string;
    const uint8_t *bytes;
    uint64_t bytes_len;
    uint32_t bool_value;
    int64_t int64_value;
    uint64_t uint64_value;
    double float64_value;
} sc_host_service_request_v1;

typedef struct sc_host_service_response_v1 {
    uint32_t struct_size;
    uint32_t status;
    char *string_buffer;
    uint64_t string_capacity;
    uint64_t string_required;
    uint8_t *bytes_buffer;
    uint64_t bytes_capacity;
    uint64_t bytes_required;
    uint32_t bool_value;
    int64_t int64_value;
    uint64_t uint64_value;
    double float64_value;
} sc_host_service_response_v1;
```

`service_call(sc_host_ctx_t, sc_runtime_t, sc_string_view service, const sc_host_service_request_v1 *request, sc_host_service_response_v1 *response)` is synchronous. The service name, request views, and response buffers are borrowed for the duration of the callback. A successful callback transport returns `SC_OK` even when `response.status` contains a typed non-OK `SC_SERVICE_*` result. `SC_CAP_HOST_SERVICE` identifies providers that can invoke this callback.

`service_start(sc_host_ctx_t, sc_runtime_t, sc_string_view service, const sc_host_service_request_v1 *request, sc_service_request_t *out_request)` starts an asynchronous operation and returns a non-zero opaque request ID. The host copies all request data needed after the callback returns. `service_cancel(sc_host_ctx_t, sc_runtime_t, sc_service_request_t request)` requests cancellation and is idempotent for a request that is already terminal. `SC_CAP_ASYNC_HOST_SERVICE` identifies providers that use these slots.

The runtime receives asynchronous results through:

```c
typedef struct sc_service_event_v1 {
    uint32_t struct_size;
    uint32_t kind;
    uint32_t status;
    uint32_t reserved;
    sc_service_request_t request;
    sc_string_view string;
    const uint8_t *bytes;
    uint64_t bytes_len;
    uint32_t bool_value;
    int64_t int64_value;
    uint64_t uint64_value;
    double float64_value;
} sc_service_event_v1;
```

`kind` is one of `SC_SERVICE_EVENT_DATA`, `SC_SERVICE_EVENT_COMPLETE`, or `SC_SERVICE_EVENT_CLOSE`. Data events are non-terminal. Complete and close events are terminal; each request accepts exactly one terminal event, and providers must reject unknown requests or events delivered after termination. Event payload views are borrowed only for the `service_event` call and must be copied by a provider if retained. Request IDs, event payloads, Go values, and QuickJS values never share ownership across the ABI boundary.

The QuickJS provider currently advertises the `console`, `crypto`, `fetch`, and `filesystem` services. Console operations are `0x0101` (`log`), `0x0102` (`info`), `0x0103` (`warn`), and `0x0104` (`error`). Crypto operations are `0x0201` (`digest`) and `0x0202` (`randomBytes`). Fetch uses asynchronous operation `0x0301` (`request`): the request metadata is JSON in `request.string`, request content is in `request.bytes`, and a successful terminal event returns JSON response metadata in `event.string` plus response content in `event.bytes`; HTTP status is carried in `event.int64_value`. Filesystem operations are `0x0601`/`0x0602` (`readFile`/`writeFile`) for asynchronous calls and `0x0607`/`0x0608` (`readFileSync`/`writeFileSync`) for synchronous calls. Console arguments are converted to JavaScript strings and joined with one space before dispatch. Filesystem requests carry the path in `request.string` and file contents in `request.bytes`; providers must apply the host's package authorization and configured size limits.

## Plugin query and lifecycle

The plugin exports exactly the stable query entry point:

```c
SC_EXPORT sc_status_t SC_CALL scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query,
    const sc_runtime_plugin_v1 **out_plugin);
```

`sc_runtime_plugin_v1` is append-only and contains `struct_size`, then the embedded `sc_runtime_descriptor_v1 descriptor`, the embedded `sc_runtime_api_v1 api`, and the optional extension tail. A successful query returns a pointer to plugin-owned static storage. The host validates the required prefix, version fields, capabilities, and function pointers before calling `create`; it reads the extension tail only when its fields are covered by `struct_size`.

The active plugin table appends an extension descriptor array after the
runtime API:

```c
typedef struct sc_runtime_extension_v1 {
    uint32_t struct_size;
    const char *name;
    uint32_t abi_major;
    uint32_t abi_minor;
    const void *table;
} sc_runtime_extension_v1;

typedef struct sc_runtime_plugin_v1 {
    uint32_t struct_size;
    sc_runtime_descriptor_v1 descriptor;
    sc_runtime_api_v1 api;
    uint32_t extension_count;
    const sc_runtime_extension_v1 *extensions;
} sc_runtime_plugin_v1;
```

The host validates every extension descriptor before use. `extension_count`
may be zero, but a non-zero count requires a non-null array; each descriptor
requires a complete descriptor-sized prefix, a non-null name, and a non-null
table. Extension names and tables are provider-owned static storage.

The current context extension is named
`SC_RUNTIME_EXTENSION_CONTEXT_V1` (`scardice.runtime.context.v1`) and has
ABI `1.0`:

```c
typedef struct sc_runtime_context_extension_v1 {
    uint32_t struct_size;
    sc_status_t (SC_CALL *set_current_context)(
        sc_runtime_t runtime, uint64_t token);
    uint64_t (SC_CALL *get_current_context)(sc_runtime_t runtime);
} sc_runtime_context_extension_v1;
```

The host supplies opaque non-zero tokens while entering a script, timer,
Promise job, or asynchronous service completion. The provider stores the
token on its owner thread and returns it to host callbacks through
`get_current_context`; token values have no meaning outside that runtime
instance. Providers without this optional extension cannot promise context
propagation.

A provider advertising `SC_CAP_CONTEXT_PROPAGATION` must expose this extension
with the supported major, at least the required extension minor, a complete
context table, and non-null set/get callbacks. The Core bridge rejects a false
declaration before accepting the plugin or calling `create`. QuickJS advertises
the bit in both its manifest and native descriptor. A generic provider may omit
the capability and continue ordinary execution; callers requiring contextual
execution must explicitly require the capability.

The lifecycle is `query → create → start → calls → stop → destroy`. `start` and `stop` are explicit and may return a status. `destroy` invalidates the runtime and all non-retained values. v1 never unloads a native library: the host must not call `dlclose` on POSIX or `FreeLibrary` on Windows; the library remains loaded through process exit.

## Value ownership and callbacks

A value handle returned by an API call is owned by the current runtime call scope. The host must not let an unretained value escape that scope. `value_retain` promotes a value to persistent ownership; every successful retain requires a matching `value_release` before `destroy`. Do not rely on a Go finalizer for correctness. A value from one runtime cannot be used with another runtime.

When a runtime invokes a host object or host function, the host callback may use borrowed arguments only until it returns. Host callbacks may call `value_new_*`, `value_type`, `value_to_*`, `host_object_new`, `host_function_new`, `value_retain`, `value_release`, `function_call`, `object_get`, and `object_set` reentrantly. `create`, `start`, `stop`, `destroy`, and `load_entry` are not reentrant from a host callback. Providers must avoid waiting on their own callback thread; an implementation that queues work to a worker executes reentrant calls inline on that worker to avoid deadlock.

Each runtime instance has thread affinity. The provider owns its scheduling policy, but all operations on a runtime and its values must obey the provider's documented affinity; a typical provider serializes calls on one runtime worker thread. The host must synchronize calls from other threads and must not use a runtime or its values concurrently unless the provider explicitly documents that support.

## Error and exception boundary

Functions report ordinary failure through `sc_status_t`; details are retrieved with the relevant `last_error_copy`. A script exception is `SC_EEXCEPTION`, a host callback failure is `SC_EHOST`, and unsupported capabilities return `SC_ENOTSUP`. C++ exceptions and Go panics must be caught before crossing the C ABI and converted to these statuses. No exception, panic, language runtime pointer, or allocated string crosses the boundary.

The native runtime is trusted in-process code. Loading a plugin is not a sandbox boundary: the host must only load code it trusts and must validate its descriptor and table before use.
