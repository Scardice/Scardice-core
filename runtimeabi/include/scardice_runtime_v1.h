#ifndef SCARDICE_RUNTIME_V1_H
#define SCARDICE_RUNTIME_V1_H

#include <stdint.h>

#define SC_RUNTIME_ABI_MAJOR 1
#define SC_RUNTIME_ABI_MINOR 0
#define SC_HOST_ABI_MAJOR 1
#define SC_HOST_ABI_MINOR 0

typedef int32_t sc_status_t;
typedef uint64_t sc_runtime_t;
typedef uint64_t sc_value_t;
typedef uint64_t sc_host_ref_t;
typedef uint64_t sc_host_func_t;
typedef uint64_t sc_host_ctx_t;

typedef struct sc_string_view {
    const char *data;
    uint64_t len;
} sc_string_view;

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
} sc_host_api_v1;

typedef struct sc_runtime_plugin_v1 {
    uint32_t struct_size;
    sc_runtime_descriptor_v1 descriptor;
    sc_runtime_api_v1 api;
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
