#ifndef SCARDICE_RUNTIME_V1_H
#define SCARDICE_RUNTIME_V1_H

#include <stdint.h>

#define SC_RUNTIME_ABI_MAJOR 1u
#define SC_RUNTIME_ABI_MINOR 0u
#define SC_HOST_ABI_MAJOR 1u
#define SC_HOST_ABI_MINOR 1u

#define SC_RUNTIME_EXTENSION_CONTEXT_V1 "scardice.runtime.context.v1"
#define SC_RUNTIME_EXTENSION_CONTEXT_ABI_MAJOR 1u
#define SC_RUNTIME_EXTENSION_CONTEXT_ABI_MINOR 0u

#define SC_ENTRY_SCRIPT UINT32_C(0)
#define SC_ENTRY_COMMONJS UINT32_C(1)
#define SC_ENTRY_ESMODULE UINT32_C(2)
#define SC_ENTRY_EXTENSION UINT32_C(3)

#define SC_VALUE_TYPE_UNDEFINED UINT32_C(0)
#define SC_VALUE_TYPE_NULL UINT32_C(1)
#define SC_VALUE_TYPE_BOOL UINT32_C(2)
#define SC_VALUE_TYPE_I64 UINT32_C(3)
#define SC_VALUE_TYPE_U64 UINT32_C(4)
#define SC_VALUE_TYPE_F64 UINT32_C(5)
#define SC_VALUE_TYPE_STRING UINT32_C(6)
#define SC_VALUE_TYPE_OBJECT UINT32_C(7)
#define SC_VALUE_TYPE_HOST_OBJECT UINT32_C(8)
#define SC_VALUE_TYPE_HOST_FUNCTION UINT32_C(9)
#define SC_VALUE_TYPE_FUNCTION UINT32_C(10)
typedef uint64_t sc_runtime_t;
typedef uint64_t sc_value_t;
typedef uint64_t sc_host_ctx_t;
typedef uint64_t sc_host_ref_t;
typedef uint64_t sc_host_func_t;
typedef uint64_t sc_service_request_t;
typedef int32_t sc_status_t;

typedef struct sc_string_view {
    const char *data;
    uint64_t len;
} sc_string_view;
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


#define SC_OK 0
#define SC_EINVAL -1
#define SC_EABI -2
#define SC_ENOTSUP -3
#define SC_ESTATE -4
#define SC_ECLOSED -5
#define SC_EEXCEPTION -10
#define SC_EOOM -11
#define SC_ETIMEOUT -12
#define SC_EHOST -20
#define SC_EINTERNAL -100
#define SC_SERVICE_OK 0U
#define SC_SERVICE_INVALID 1U
#define SC_SERVICE_PERMISSION_DENIED 2U
#define SC_SERVICE_CANCELLED 3U
#define SC_SERVICE_DEADLINE_EXCEEDED 4U
#define SC_SERVICE_UNSUPPORTED 5U
#define SC_SERVICE_CLOSED 6U
#define SC_SERVICE_INTERNAL 7U
#define SC_SERVICE_EVENT_DATA 1U
#define SC_SERVICE_EVENT_COMPLETE 2U
#define SC_SERVICE_EVENT_CLOSE 3U
#define SC_SERVICE_OP_CONSOLE_LOG UINT32_C(0x0101)
#define SC_SERVICE_OP_CONSOLE_INFO UINT32_C(0x0102)
#define SC_SERVICE_OP_CONSOLE_WARN UINT32_C(0x0103)
#define SC_SERVICE_OP_CONSOLE_ERROR UINT32_C(0x0104)
#define SC_SERVICE_OP_CRYPTO_DIGEST UINT32_C(0x0201)
#define SC_SERVICE_OP_CRYPTO_RANDOM_BYTES UINT32_C(0x0202)
#define SC_SERVICE_OP_FETCH_REQUEST UINT32_C(0x0301)
#define SC_SERVICE_OP_HTTP_REQUEST UINT32_C(0x0401)
#define SC_SERVICE_OP_WEBSOCKET_CONNECT UINT32_C(0x0501)
#define SC_SERVICE_OP_WEBSOCKET_SEND UINT32_C(0x0502)
#define SC_SERVICE_OP_WEBSOCKET_CLOSE UINT32_C(0x0503)
#define SC_SERVICE_OP_FILESYSTEM_READ_FILE UINT32_C(0x0601)
#define SC_SERVICE_OP_FILESYSTEM_WRITE_FILE UINT32_C(0x0602)
#define SC_SERVICE_OP_FILESYSTEM_STAT UINT32_C(0x0603)
#define SC_SERVICE_OP_FILESYSTEM_READ_DIR UINT32_C(0x0604)
#define SC_SERVICE_OP_FILESYSTEM_MKDIR UINT32_C(0x0605)
#define SC_SERVICE_OP_FILESYSTEM_REMOVE UINT32_C(0x0606)
#define SC_SERVICE_OP_FILESYSTEM_READ_FILE_SYNC UINT32_C(0x0607)
#define SC_SERVICE_OP_FILESYSTEM_WRITE_FILE_SYNC UINT32_C(0x0608)
#define SC_SERVICE_OP_ABORT_CREATE UINT32_C(0x0701)
#define SC_SERVICE_OP_ABORT_CANCEL UINT32_C(0x0702)
#define SC_SERVICE_OP_STRUCTURED_CLONE UINT32_C(0x0801)
#define SC_SERVICE_OP_UTIL_INSPECT UINT32_C(0x0901)

#if defined(_WIN32)
#define SC_EXPORT __declspec(dllexport)
#define SC_CALL __cdecl
#else
#define SC_EXPORT __attribute__((visibility("default")))
#define SC_CALL
#endif

#define SC_CAP_SCRIPT (UINT64_C(1) << 0)
#define SC_CAP_COMMONJS (UINT64_C(1) << 1)
#define SC_CAP_ESM (UINT64_C(1) << 2)
#define SC_CAP_PROMISE (UINT64_C(1) << 3)
#define SC_CAP_TIMERS (UINT64_C(1) << 4)
#define SC_CAP_HOST_OBJECT (UINT64_C(1) << 5)
#define SC_CAP_HOST_FUNCTION (UINT64_C(1) << 6)
#define SC_CAP_ASYNC_HOST_SERVICE (UINT64_C(1) << 7)
#define SC_CAP_SOURCE_LOCATION (UINT64_C(1) << 8)
#define SC_CAP_HOST_SERVICE (UINT64_C(1) << 9)
/* Requires a valid SC_RUNTIME_EXTENSION_CONTEXT_V1 table. */
#define SC_CAP_CONTEXT_PROPAGATION (UINT64_C(1) << 10)

typedef struct sc_runtime_extension_v1 {
    uint32_t struct_size;
    const char *name;
    uint32_t abi_major;
    uint32_t abi_minor;
    const void *table;
} sc_runtime_extension_v1;

typedef struct sc_runtime_context_extension_v1 {
    uint32_t struct_size;
    sc_status_t (SC_CALL *set_current_context)(sc_runtime_t runtime, uint64_t token);
    uint64_t (SC_CALL *get_current_context)(sc_runtime_t runtime);
} sc_runtime_context_extension_v1;

typedef struct sc_host_api_v1 sc_host_api_v1;
typedef struct sc_runtime_create_info_v1 sc_runtime_create_info_v1;
typedef struct sc_runtime_query_v1 sc_runtime_query_v1;
typedef struct sc_runtime_api_v1 sc_runtime_api_v1;
typedef struct sc_runtime_plugin_v1 sc_runtime_plugin_v1;

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

typedef struct sc_runtime_api_v1 {
    uint32_t struct_size;

    sc_status_t (SC_CALL *create)(
        const sc_host_api_v1 *host,
        sc_host_ctx_t host_ctx,
        const sc_runtime_create_info_v1 *info,
        sc_runtime_t *out_runtime);
    sc_status_t (SC_CALL *start)(sc_runtime_t runtime);
    sc_status_t (SC_CALL *stop)(sc_runtime_t runtime);
    void (SC_CALL *destroy)(sc_runtime_t runtime);

    sc_status_t (SC_CALL *eval)(
        sc_runtime_t runtime,
        sc_string_view filename,
        sc_string_view source,
        sc_value_t *out);
    sc_status_t (SC_CALL *load_entry)(
        sc_runtime_t runtime,
        uint32_t entry_kind,
        sc_string_view filename,
        sc_string_view source,
        sc_value_t *out);
    sc_status_t (SC_CALL *global_get)(
        sc_runtime_t runtime,
        sc_string_view name,
        sc_value_t *out);
    sc_status_t (SC_CALL *global_set)(
        sc_runtime_t runtime,
        sc_string_view name,
        sc_value_t value);
    sc_status_t (SC_CALL *object_new)(sc_runtime_t runtime, sc_value_t *out);
    sc_status_t (SC_CALL *object_get)(
        sc_runtime_t runtime,
        sc_value_t object,
        sc_string_view key,
        sc_value_t *out);
    sc_status_t (SC_CALL *object_set)(
        sc_runtime_t runtime,
        sc_value_t object,
        sc_string_view key,
        sc_value_t value);
    sc_status_t (SC_CALL *object_has)(
        sc_runtime_t runtime,
        sc_value_t object,
        sc_string_view key,
        uint32_t *out);

    sc_status_t (SC_CALL *value_new_undefined)(sc_runtime_t, sc_value_t *);
    sc_status_t (SC_CALL *value_new_null)(sc_runtime_t, sc_value_t *);
    sc_status_t (SC_CALL *value_new_bool)(sc_runtime_t, uint32_t, sc_value_t *);
    sc_status_t (SC_CALL *value_new_i64)(sc_runtime_t, int64_t, sc_value_t *);
    sc_status_t (SC_CALL *value_new_u64)(sc_runtime_t, uint64_t, sc_value_t *);
    sc_status_t (SC_CALL *value_new_f64)(sc_runtime_t, double, sc_value_t *);
    sc_status_t (SC_CALL *value_new_string)(sc_runtime_t, sc_string_view, sc_value_t *);

    sc_status_t (SC_CALL *value_type)(sc_runtime_t, sc_value_t, uint32_t *);
    sc_status_t (SC_CALL *value_to_bool)(sc_runtime_t, sc_value_t, uint32_t *);
    sc_status_t (SC_CALL *value_to_i64)(sc_runtime_t, sc_value_t, int64_t *);
    sc_status_t (SC_CALL *value_to_u64)(sc_runtime_t, sc_value_t, uint64_t *);
    sc_status_t (SC_CALL *value_to_f64)(sc_runtime_t, sc_value_t, double *);
    sc_status_t (SC_CALL *value_to_utf8_copy)(
        sc_runtime_t,
        sc_value_t,
        char *buffer,
        uint64_t capacity,
        uint64_t *required);
    sc_status_t (SC_CALL *value_get_host_ref)(
        sc_runtime_t,
        sc_value_t,
        sc_host_ref_t *,
        uint32_t *host_kind);

    sc_status_t (SC_CALL *host_object_new)(
        sc_runtime_t,
        sc_host_ref_t,
        uint32_t host_kind,
        sc_value_t *);
    sc_status_t (SC_CALL *host_function_new)(
        sc_runtime_t,
        sc_host_func_t,
        sc_value_t *);

    sc_status_t (SC_CALL *function_call)(
        sc_runtime_t,
        sc_value_t function,
        sc_value_t this_value,
        const sc_value_t *argv,
        uint64_t argc,
        sc_value_t *out);

    sc_status_t (SC_CALL *value_retain)(sc_runtime_t, sc_value_t);
    void (SC_CALL *value_release)(sc_runtime_t, sc_value_t);
    sc_status_t (SC_CALL *last_error_copy)(
        sc_runtime_t,
        char *buffer,
        uint64_t capacity,
        uint64_t *required);
    sc_status_t (SC_CALL *service_event)(
        sc_runtime_t runtime,
        const sc_service_event_v1 *event);
    sc_status_t (SC_CALL *tick)(sc_runtime_t runtime);
} sc_runtime_api_v1;

typedef struct sc_host_api_v1 {
    uint32_t struct_size;
    uint32_t abi_major;
    uint32_t abi_minor;

    sc_status_t (SC_CALL *host_get)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_host_ref_t,
        sc_string_view key,
        sc_value_t *out);
    sc_status_t (SC_CALL *host_set)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_host_ref_t,
        sc_string_view key,
        sc_value_t value);
    sc_status_t (SC_CALL *host_has)(
        sc_host_ctx_t,
        sc_host_ref_t,
        sc_string_view key,
        uint32_t *out);
    sc_status_t (SC_CALL *host_delete)(
        sc_host_ctx_t,
        sc_host_ref_t,
        sc_string_view key,
        uint32_t *deleted);
    sc_status_t (SC_CALL *host_keys_json)(
        sc_host_ctx_t,
        sc_host_ref_t,
        char *buffer,
        uint64_t capacity,
        uint64_t *required);
    sc_status_t (SC_CALL *host_call)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_host_func_t,
        sc_value_t this_value,
        const sc_value_t *argv,
        uint64_t argc,
        sc_value_t *out);
    sc_status_t (SC_CALL *last_error_copy)(
        sc_host_ctx_t,
        char *buffer,
        uint64_t capacity,
        uint64_t *required);
    /*
     * Current development ABI. The paired host table contains the complete
     * synchronous and asynchronous service surface.
     */
    sc_status_t (SC_CALL *service_call)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_string_view service,
        const sc_host_service_request_v1 *request,
        sc_host_service_response_v1 *response);
    sc_status_t (SC_CALL *service_start)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_string_view service,
        const sc_host_service_request_v1 *request,
        sc_service_request_t *out_request);
    sc_status_t (SC_CALL *service_cancel)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_service_request_t request);
} sc_host_api_v1;

/*
 * extension_count and extensions are optional tail fields. Hosts accept the
 * original table through sc_runtime_api_v1 and treat a missing extension tail
 * as an empty table.
 */
typedef struct sc_runtime_plugin_v1 {
    uint32_t struct_size;
    sc_runtime_descriptor_v1 descriptor;
    sc_runtime_api_v1 api;
    uint32_t extension_count;
    const sc_runtime_extension_v1 *extensions;
} sc_runtime_plugin_v1;

#ifdef __cplusplus
extern "C" {
#endif

SC_EXPORT sc_status_t SC_CALL scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query,
    const sc_runtime_plugin_v1 **out_plugin);

#ifdef __cplusplus
}
#endif

#endif /* SCARDICE_RUNTIME_V1_H */
