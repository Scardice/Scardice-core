#ifndef SCARDICE_NATIVE_BRIDGE_H
#define SCARDICE_NATIVE_BRIDGE_H

#include <stdint.h>
#include "../../../runtimeabi/include/scardice_runtime_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SC_NATIVE_OK = 0,
    SC_NATIVE_MISSING_LIBRARY = -1001,
    SC_NATIVE_MISSING_SYMBOL = -1002,
    SC_NATIVE_RUNTIME_ABI = -1003,
    SC_NATIVE_HOST_ABI = -1004,
    SC_NATIVE_DESCRIPTOR = -1005,
    SC_NATIVE_CREATE = -1009,
    SC_NATIVE_CORRUPT_VTABLE = -1010,
    SC_NATIVE_TOO_SMALL = -1011,
    SC_NATIVE_UNSUPPORTED = -1012,
    SC_NATIVE_INTERNAL = -1099
};

typedef struct sc_native_descriptor {
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t host_abi_major;
    uint32_t host_abi_minor;
    uint64_t capabilities;
    char id[256];
    char name[256];
    char version[128];
    char language[64];
} sc_native_descriptor;

/* The identity is an integer owned by C. It is never a Go pointer. */
int sc_native_open(const char *path, uint64_t *out_library, char *error, uint64_t capacity);
int sc_native_query(uint64_t library, uint32_t runtime_major, uint32_t runtime_minor,
                    uint32_t host_major, uint32_t host_minor,
                    sc_native_descriptor *out, char *error, uint64_t capacity);
int sc_native_create(uint64_t library, uint64_t host_ctx, const char *options, uint64_t options_len,
                     uint64_t *out_runtime, char *error, uint64_t capacity);
int sc_native_start(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
int sc_native_stop(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
int sc_native_destroy(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
uint64_t sc_native_resident_count(void);
int sc_native_eval(uint64_t library, uint64_t runtime, const char *filename, uint64_t filename_len,
                   const char *source, uint64_t source_len, uint64_t *out, char *error, uint64_t capacity);
int sc_native_load_entry(uint64_t library, uint64_t runtime, uint32_t kind,
                         const char *filename, uint64_t filename_len,
                         const char *source, uint64_t source_len,
                         uint64_t *out, char *error, uint64_t capacity);
int sc_native_global_get(uint64_t library, uint64_t runtime, const char *name, uint64_t name_len,
                         uint64_t *out, char *error, uint64_t capacity);
int sc_native_global_set(uint64_t library, uint64_t runtime, const char *name, uint64_t name_len,
                         uint64_t value, char *error, uint64_t capacity);
int sc_native_object_new(uint64_t library, uint64_t runtime, uint64_t *out, char *error, uint64_t capacity);
int sc_native_object_get(uint64_t library, uint64_t runtime, uint64_t object,
                         const char *key, uint64_t key_len,
                         uint64_t *out, char *error, uint64_t capacity);
int sc_native_object_set(uint64_t library, uint64_t runtime, uint64_t object,
                         const char *key, uint64_t key_len, uint64_t value,
                         char *error, uint64_t capacity);
int sc_native_object_has(uint64_t library, uint64_t runtime, uint64_t object,
                         const char *key, uint64_t key_len, uint32_t *out,
                         char *error, uint64_t capacity);
int sc_native_value_new_undefined(uint64_t library, uint64_t runtime, uint64_t *out,
                                  char *error, uint64_t capacity);
int sc_native_value_new_null(uint64_t library, uint64_t runtime, uint64_t *out,
                             char *error, uint64_t capacity);
int sc_native_value_new_bool(uint64_t library, uint64_t runtime, uint32_t value,
                             uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_new_i64(uint64_t library, uint64_t runtime, int64_t value,
                            uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_new_u64(uint64_t library, uint64_t runtime, uint64_t value,
                            uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_new_f64(uint64_t library, uint64_t runtime, double value,
                            uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_new_string(uint64_t library, uint64_t runtime,
                               const char *value, uint64_t value_len,
                               uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_type(uint64_t library, uint64_t runtime, uint64_t value,
                         uint32_t *out, char *error, uint64_t capacity);
int sc_native_value_to_bool(uint64_t library, uint64_t runtime, uint64_t value,
                            uint32_t *out, char *error, uint64_t capacity);
int sc_native_value_to_i64(uint64_t library, uint64_t runtime, uint64_t value,
                           int64_t *out, char *error, uint64_t capacity);
int sc_native_value_to_u64(uint64_t library, uint64_t runtime, uint64_t value,
                           uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_to_f64(uint64_t library, uint64_t runtime, uint64_t value,
                           double *out, char *error, uint64_t capacity);
int sc_native_value_to_utf8_copy(uint64_t library, uint64_t runtime, uint64_t value,
                                 char *buffer, uint64_t buffer_capacity, uint64_t *required,
                                 char *error, uint64_t capacity);
int sc_native_value_get_host_ref(uint64_t library, uint64_t runtime, uint64_t value,
                                 uint64_t *host_ref, uint32_t *host_kind,
                                 char *error, uint64_t capacity);
int sc_native_host_object_new(uint64_t library, uint64_t runtime, uint64_t host_ref,
                              uint32_t host_kind, uint64_t *out,
                              char *error, uint64_t capacity);
int sc_native_host_function_new(uint64_t library, uint64_t runtime, uint64_t host_function,
                                uint64_t *out, char *error, uint64_t capacity);
int sc_native_function_call(uint64_t library, uint64_t runtime, uint64_t function,
                            uint64_t this_value, const uint64_t *argv, uint64_t argc,
                            uint64_t *out, char *error, uint64_t capacity);
int sc_native_value_retain(uint64_t library, uint64_t runtime, uint64_t value,
                           char *error, uint64_t capacity);
void sc_native_value_release(uint64_t library, uint64_t runtime, uint64_t value);
int sc_native_last_error_copy(uint64_t library, uint64_t runtime, char *buffer,
                              uint64_t buffer_capacity, uint64_t *required,
                              char *error, uint64_t capacity);
int sc_native_service_event(uint64_t library, uint64_t runtime, uint32_t kind,
                            uint32_t status, uint64_t request,
                            const char *string, uint64_t string_len,
                            const uint8_t *bytes, uint64_t bytes_len,
                            uint32_t bool_value, int64_t int64_value,
                            uint64_t uint64_value, double float64_value,
                            char *error, uint64_t capacity);
int sc_native_tick(uint64_t library, uint64_t runtime, char *error, uint64_t capacity);
int sc_native_set_context(uint64_t library, uint64_t runtime, uint64_t token,
                          char *error, uint64_t capacity);
uint64_t sc_native_current_context(uint64_t library, uint64_t runtime);

#ifdef __cplusplus
}
#endif
#endif
