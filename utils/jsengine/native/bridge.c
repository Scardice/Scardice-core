#include "bridge.h"
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *sc_platform_library;
sc_platform_library sc_platform_load(const char *path, char *error, uint64_t capacity);
void *sc_platform_symbol(sc_platform_library library, const char *name);

_Static_assert(sizeof(uintptr_t) <= sizeof(uint64_t), "native handle must fit fixed-width identity");

typedef struct sc_native_state {
    sc_platform_library library;
    const sc_runtime_plugin_v1 *plugin;
    uint64_t runtime_count;
    sc_host_ctx_t host_ctx;
} sc_native_state;

static _Atomic uint64_t resident_count = 0;

static void set_error(char *error, uint64_t capacity, const char *message) {
    if (error == NULL || capacity == 0) return;
    (void)snprintf(error, (size_t)capacity, "%s", message != NULL ? message : "native loader error");
}

static sc_native_state *state_from_id(uint64_t id) {
    return (sc_native_state *)(uintptr_t)id;
}

static int copy_string(char *out, size_t capacity, const char *value) {
    size_t length;
    if (value == NULL) return 0;
    length = strlen(value);
    if (length >= capacity) return 0;
    memcpy(out, value, length + 1);
    return 1;
}

int sc_native_open(const char *path, uint64_t *out_library, char *error, uint64_t capacity) {
    sc_native_state *state;
    if (path == NULL || out_library == NULL) {
        set_error(error, capacity, "native library path is empty");
        return SC_NATIVE_MISSING_LIBRARY;
    }
    state = (sc_native_state *)calloc(1, sizeof(*state));
    if (state == NULL) {
        set_error(error, capacity, "out of memory allocating native library state");
        return SC_NATIVE_INTERNAL;
    }
    state->library = sc_platform_load(path, error, capacity);
    if (state->library == NULL) {
        free(state);
        return SC_NATIVE_MISSING_LIBRARY;
    }
    *out_library = (uint64_t)(uintptr_t)state;
    atomic_fetch_add_explicit(&resident_count, 1, memory_order_relaxed);
    return SC_NATIVE_OK;
}

int sc_native_query(uint64_t library, uint32_t runtime_major, uint32_t runtime_minor,
                    uint32_t host_major, uint32_t host_minor,
                    sc_native_descriptor *out, char *error, uint64_t capacity) {
    sc_native_state *state = state_from_id(library);
    sc_status_t (SC_CALL *query_fn)(const sc_runtime_query_v1 *, const sc_runtime_plugin_v1 **);
    sc_runtime_query_v1 query;
    const sc_runtime_plugin_v1 *plugin = NULL;
    int status;
    if (state == NULL || out == NULL) {
        set_error(error, capacity, "invalid native library handle");
        return SC_NATIVE_INTERNAL;
    }
    query_fn = (sc_status_t (SC_CALL *)(const sc_runtime_query_v1 *, const sc_runtime_plugin_v1 **))
        sc_platform_symbol(state->library, "scardice_runtime_query_v1");
    if (query_fn == NULL) {
        set_error(error, capacity, "scardice_runtime_query_v1 symbol is missing");
        return SC_NATIVE_MISSING_SYMBOL;
    }
    memset(&query, 0, sizeof(query));
    query.struct_size = (uint32_t)sizeof(query);
    query.runtime_abi_major = runtime_major;
    query.runtime_abi_minor = runtime_minor;
    query.host_abi_major = host_major;
    query.host_abi_minor = host_minor;
    status = query_fn(&query, &plugin);
    if (status != SC_OK) {
        set_error(error, capacity, "runtime query rejected the requested ABI");
        return status == SC_EHOST ? SC_NATIVE_HOST_ABI : SC_NATIVE_RUNTIME_ABI;
    }
    if (plugin == NULL) {
        set_error(error, capacity, "runtime query returned a null plugin");
        return SC_NATIVE_CORRUPT_VTABLE;
    }
    if (plugin->struct_size < sizeof(sc_runtime_plugin_v1)) {
        set_error(error, capacity, "runtime plugin struct_size is too small");
        return SC_NATIVE_TOO_SMALL;
    }
    if (plugin->descriptor.struct_size < sizeof(sc_runtime_descriptor_v1)) {
        set_error(error, capacity, "runtime descriptor struct_size is too small");
        return SC_NATIVE_TOO_SMALL;
    }
    if (plugin->api.struct_size < sizeof(sc_runtime_api_v1)) {
        set_error(error, capacity, "runtime API struct_size is too small");
        return SC_NATIVE_TOO_SMALL;
    }
    if (plugin->descriptor.id == NULL || plugin->descriptor.name == NULL ||
        plugin->descriptor.version == NULL || plugin->descriptor.language == NULL) {
        set_error(error, capacity, "runtime descriptor contains a null string");
        return SC_NATIVE_CORRUPT_VTABLE;
    }
#define REQUIRE_API_FIELD(field) do { if (plugin->api.field == NULL) { \
        set_error(error, capacity, "runtime API vtable contains a null function"); \
        return SC_NATIVE_CORRUPT_VTABLE; } } while (0)
    REQUIRE_API_FIELD(create); REQUIRE_API_FIELD(start); REQUIRE_API_FIELD(stop); REQUIRE_API_FIELD(destroy);
    REQUIRE_API_FIELD(eval); REQUIRE_API_FIELD(load_entry); REQUIRE_API_FIELD(global_get); REQUIRE_API_FIELD(global_set);
    REQUIRE_API_FIELD(object_new); REQUIRE_API_FIELD(object_get); REQUIRE_API_FIELD(object_set); REQUIRE_API_FIELD(object_has);
    REQUIRE_API_FIELD(value_new_undefined); REQUIRE_API_FIELD(value_new_null); REQUIRE_API_FIELD(value_new_bool);
    REQUIRE_API_FIELD(value_new_i64); REQUIRE_API_FIELD(value_new_u64); REQUIRE_API_FIELD(value_new_f64);
    REQUIRE_API_FIELD(value_new_string); REQUIRE_API_FIELD(value_type); REQUIRE_API_FIELD(value_to_bool);
    REQUIRE_API_FIELD(value_to_i64); REQUIRE_API_FIELD(value_to_u64); REQUIRE_API_FIELD(value_to_f64);
    REQUIRE_API_FIELD(value_to_utf8_copy); REQUIRE_API_FIELD(value_get_host_ref); REQUIRE_API_FIELD(host_object_new);
    REQUIRE_API_FIELD(host_function_new); REQUIRE_API_FIELD(function_call); REQUIRE_API_FIELD(value_retain);
    REQUIRE_API_FIELD(value_release); REQUIRE_API_FIELD(last_error_copy);
#undef REQUIRE_API_FIELD
    if (plugin->descriptor.abi_major != runtime_major || plugin->descriptor.abi_minor > runtime_minor) {
        set_error(error, capacity, "runtime ABI major/minor is incompatible");
        return SC_NATIVE_RUNTIME_ABI;
    }
    if (plugin->descriptor.host_abi_major != host_major || plugin->descriptor.host_abi_minor > host_minor) {
        set_error(error, capacity, "host ABI major/minor is incompatible");
        return SC_NATIVE_HOST_ABI;
    }
    memset(out, 0, sizeof(*out));
    out->abi_major = plugin->descriptor.abi_major;
    out->abi_minor = plugin->descriptor.abi_minor;
    out->host_abi_major = plugin->descriptor.host_abi_major;
    out->host_abi_minor = plugin->descriptor.host_abi_minor;
    out->capabilities = plugin->descriptor.capabilities;
    if (!copy_string(out->id, sizeof(out->id), plugin->descriptor.id) ||
        !copy_string(out->name, sizeof(out->name), plugin->descriptor.name) ||
        !copy_string(out->version, sizeof(out->version), plugin->descriptor.version) ||
        !copy_string(out->language, sizeof(out->language), plugin->descriptor.language)) {
        set_error(error, capacity, "runtime descriptor string is too long");
        return SC_NATIVE_CORRUPT_VTABLE;
    }
    state->plugin = plugin;
    return SC_NATIVE_OK;
}

extern sc_status_t SC_CALL sc_native_go_host_get(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view, sc_value_t *);
extern sc_status_t SC_CALL sc_native_go_host_set(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view, sc_value_t);
extern sc_status_t SC_CALL sc_native_go_host_has(sc_host_ctx_t, sc_host_ref_t, sc_string_view, uint32_t *);
extern sc_status_t SC_CALL sc_native_go_host_delete(sc_host_ctx_t, sc_host_ref_t, sc_string_view, uint32_t *);
extern sc_status_t SC_CALL sc_native_go_host_keys(sc_host_ctx_t, sc_host_ref_t, char *, uint64_t, uint64_t *);
extern sc_status_t SC_CALL sc_native_go_host_call(sc_host_ctx_t, sc_runtime_t, sc_host_func_t, sc_value_t, const sc_value_t *, uint64_t, sc_value_t *);
extern sc_status_t SC_CALL sc_native_go_host_last(sc_host_ctx_t, char *, uint64_t, uint64_t *);

static sc_status_t SC_CALL host_get(sc_host_ctx_t c, sc_runtime_t r, sc_host_ref_t h, sc_string_view k, sc_value_t *o) {
    return sc_native_go_host_get(c, r, h, k, o);
}
static sc_status_t SC_CALL host_set(sc_host_ctx_t c, sc_runtime_t r, sc_host_ref_t h, sc_string_view k, sc_value_t v) {
    return sc_native_go_host_set(c, r, h, k, v);
}
static sc_status_t SC_CALL host_has(sc_host_ctx_t c, sc_host_ref_t h, sc_string_view k, uint32_t *o) {
    return sc_native_go_host_has(c, h, k, o);
}
static sc_status_t SC_CALL host_delete(sc_host_ctx_t c, sc_host_ref_t h, sc_string_view k, uint32_t *o) {
    return sc_native_go_host_delete(c, h, k, o);
}
static sc_status_t SC_CALL host_keys(sc_host_ctx_t c, sc_host_ref_t h, char *b, uint64_t n, uint64_t *o) {
    return sc_native_go_host_keys(c, h, b, n, o);
}
static sc_status_t SC_CALL host_call(sc_host_ctx_t c, sc_runtime_t r, sc_host_func_t f, sc_value_t t, const sc_value_t *a, uint64_t n, sc_value_t *o) {
    return sc_native_go_host_call(c, r, f, t, a, n, o);
}
static sc_status_t SC_CALL host_last(sc_host_ctx_t c, char *b, uint64_t n, uint64_t *o) {
    return sc_native_go_host_last(c, b, n, o);
}

static const sc_host_api_v1 host_api = {
    sizeof(sc_host_api_v1), SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR,
    host_get, host_set, host_has, host_delete, host_keys, host_call, host_last
};

int sc_native_create(uint64_t library, uint64_t host_ctx, const char *options, uint64_t options_len,
                     uint64_t *out_runtime, char *error, uint64_t capacity) {
    sc_native_state *state = state_from_id(library);
    sc_runtime_create_info_v1 info;
    sc_string_view options_view;
    sc_runtime_t runtime = 0;
    sc_status_t status;
    if (state == NULL || state->plugin == NULL || out_runtime == NULL) {
        set_error(error, capacity, "native library has not been queried");
        return SC_NATIVE_INTERNAL;
    }
    options_view.data = options != NULL ? options : "";
    options_view.len = options_len;
    memset(&info, 0, sizeof(info));
    info.struct_size = (uint32_t)sizeof(info);
    info.options_json = options_view;
    status = state->plugin->api.create(&host_api, (sc_host_ctx_t)host_ctx, &info, &runtime);
    if (status != SC_OK) {
        set_error(error, capacity, "runtime create failed");
        return SC_NATIVE_CREATE;
    }
    state->runtime_count++;
    state->host_ctx = (sc_host_ctx_t)host_ctx;
    *out_runtime = runtime;
    return SC_NATIVE_OK;
}

int sc_native_start(uint64_t library, uint64_t runtime, char *error, uint64_t capacity) {
    sc_native_state *state = state_from_id(library);
    sc_status_t status;
    if (state == NULL || state->plugin == NULL) {
        set_error(error, capacity, "invalid native library handle");
        return SC_NATIVE_INTERNAL;
    }
    status = state->plugin->api.start((sc_runtime_t)runtime);
    if (status != SC_OK) {
        set_error(error, capacity, "runtime start failed");
        return (int)status;
    }
    return SC_NATIVE_OK;
}

int sc_native_stop(uint64_t library, uint64_t runtime, char *error, uint64_t capacity) {
    sc_native_state *state = state_from_id(library);
    sc_status_t status;
    if (state == NULL || state->plugin == NULL) {
        set_error(error, capacity, "invalid native library handle");
        return SC_NATIVE_INTERNAL;
    }
    status = state->plugin->api.stop((sc_runtime_t)runtime);
    if (status != SC_OK) {
        set_error(error, capacity, "runtime stop failed");
        return (int)status;
    }
    return SC_NATIVE_OK;
}

int sc_native_destroy(uint64_t library, uint64_t runtime, char *error, uint64_t capacity) {
    sc_native_state *state = state_from_id(library);
    if (state == NULL || state->plugin == NULL) return SC_NATIVE_INTERNAL;
    state->plugin->api.destroy((sc_runtime_t)runtime);
    if (state->runtime_count > 0) state->runtime_count--;
    (void)error; (void)capacity;
    return SC_NATIVE_OK;
}

uint64_t sc_native_resident_count(void) {
    /* There is deliberately no close entry point in v1. */
    return atomic_load_explicit(&resident_count, memory_order_relaxed);
}
static sc_native_state *checked_state(uint64_t library, char *error, uint64_t capacity) {
    sc_native_state *state = state_from_id(library);
    if (state == NULL || state->plugin == NULL) {
        set_error(error, capacity, "invalid native library handle");
        return NULL;
    }
    return state;
}

static int operation_status(sc_native_state *state, sc_runtime_t runtime,
                            sc_status_t status, char *error, uint64_t capacity) {
    uint64_t required = 0;
    if (status == SC_OK) return SC_NATIVE_OK;
    if (status == SC_EHOST && state != NULL && state->host_ctx != 0 &&
        host_api.last_error_copy != NULL &&
        host_api.last_error_copy(state->host_ctx, error, capacity, &required) == SC_OK) {
        return (int)status;
    }
    if (state != NULL && state->plugin != NULL && runtime != 0 &&
        state->plugin->api.last_error_copy != NULL &&
        state->plugin->api.last_error_copy(runtime, error, capacity, &required) == SC_OK) {
        return (int)status;
    }
    set_error(error, capacity, "native runtime operation failed");
    return (int)status;
}

int sc_native_eval(uint64_t library, uint64_t runtime, const char *filename, uint64_t filename_len,
                   const char *source, uint64_t source_len, uint64_t *out,
                   char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view filename_view = {filename, filename_len};
    sc_string_view source_view = {source, source_len};
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.eval((sc_runtime_t)runtime, filename_view, source_view, (sc_value_t *)out),
        error, capacity);
}

int sc_native_load_entry(uint64_t library, uint64_t runtime, uint32_t kind,
                         const char *filename, uint64_t filename_len,
                         const char *source, uint64_t source_len, uint64_t *out,
                         char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view filename_view = {filename, filename_len};
    sc_string_view source_view = {source, source_len};
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.load_entry((sc_runtime_t)runtime, kind, filename_view, source_view,
            (sc_value_t *)out), error, capacity);
}

int sc_native_global_get(uint64_t library, uint64_t runtime, const char *name, uint64_t name_len,
                         uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view name_view = {name, name_len};
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.global_get((sc_runtime_t)runtime, name_view, (sc_value_t *)out),
        error, capacity);
}

int sc_native_global_set(uint64_t library, uint64_t runtime, const char *name, uint64_t name_len,
                         uint64_t value, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view name_view = {name, name_len};
    if (state == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.global_set((sc_runtime_t)runtime, name_view, (sc_value_t)value),
        error, capacity);
}

int sc_native_object_new(uint64_t library, uint64_t runtime, uint64_t *out,
                         char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.object_new((sc_runtime_t)runtime, (sc_value_t *)out),
        error, capacity);
}

int sc_native_object_get(uint64_t library, uint64_t runtime, uint64_t object,
                         const char *key, uint64_t key_len, uint64_t *out,
                         char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view key_view = {key, key_len};
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.object_get((sc_runtime_t)runtime, (sc_value_t)object, key_view,
            (sc_value_t *)out), error, capacity);
}

int sc_native_object_set(uint64_t library, uint64_t runtime, uint64_t object,
                         const char *key, uint64_t key_len, uint64_t value,
                         char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view key_view = {key, key_len};
    if (state == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.object_set((sc_runtime_t)runtime, (sc_value_t)object, key_view,
            (sc_value_t)value), error, capacity);
}

int sc_native_object_has(uint64_t library, uint64_t runtime, uint64_t object,
                         const char *key, uint64_t key_len, uint32_t *out,
                         char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view key_view = {key, key_len};
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.object_has((sc_runtime_t)runtime, (sc_value_t)object, key_view, out),
        error, capacity);
}

int sc_native_value_new_undefined(uint64_t library, uint64_t runtime, uint64_t *out,
                                  char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_undefined((sc_runtime_t)runtime, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_new_null(uint64_t library, uint64_t runtime, uint64_t *out,
                             char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_null((sc_runtime_t)runtime, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_new_bool(uint64_t library, uint64_t runtime, uint32_t value,
                             uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_bool((sc_runtime_t)runtime, value, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_new_i64(uint64_t library, uint64_t runtime, int64_t value,
                            uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_i64((sc_runtime_t)runtime, value, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_new_u64(uint64_t library, uint64_t runtime, uint64_t value,
                            uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_u64((sc_runtime_t)runtime, value, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_new_f64(uint64_t library, uint64_t runtime, double value,
                            uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_f64((sc_runtime_t)runtime, value, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_new_string(uint64_t library, uint64_t runtime, const char *value,
                               uint64_t value_len, uint64_t *out, char *error,
                               uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    sc_string_view value_view = {value, value_len};
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_new_string((sc_runtime_t)runtime, value_view, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_type(uint64_t library, uint64_t runtime, uint64_t value, uint32_t *out,
                         char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_type((sc_runtime_t)runtime, (sc_value_t)value, out),
        error, capacity);
}

int sc_native_value_to_bool(uint64_t library, uint64_t runtime, uint64_t value, uint32_t *out,
                            char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_to_bool((sc_runtime_t)runtime, (sc_value_t)value, out),
        error, capacity);
}

int sc_native_value_to_i64(uint64_t library, uint64_t runtime, uint64_t value, int64_t *out,
                           char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_to_i64((sc_runtime_t)runtime, (sc_value_t)value, out),
        error, capacity);
}

int sc_native_value_to_u64(uint64_t library, uint64_t runtime, uint64_t value, uint64_t *out,
                           char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_to_u64((sc_runtime_t)runtime, (sc_value_t)value, out),
        error, capacity);
}

int sc_native_value_to_f64(uint64_t library, uint64_t runtime, uint64_t value, double *out,
                           char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_to_f64((sc_runtime_t)runtime, (sc_value_t)value, out),
        error, capacity);
}

int sc_native_value_to_utf8_copy(uint64_t library, uint64_t runtime, uint64_t value,
                                char *buffer, uint64_t buffer_capacity, uint64_t *required,
                                char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || required == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_to_utf8_copy((sc_runtime_t)runtime, (sc_value_t)value,
            buffer, buffer_capacity, required), error, capacity);
}

int sc_native_value_get_host_ref(uint64_t library, uint64_t runtime, uint64_t value,
                                 uint64_t *host_ref, uint32_t *host_kind,
                                 char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || host_ref == NULL || host_kind == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_get_host_ref((sc_runtime_t)runtime, (sc_value_t)value,
            (sc_host_ref_t *)host_ref, host_kind), error, capacity);
}

int sc_native_host_object_new(uint64_t library, uint64_t runtime, uint64_t host_ref,
                              uint32_t host_kind, uint64_t *out, char *error,
                              uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.host_object_new((sc_runtime_t)runtime, (sc_host_ref_t)host_ref,
            host_kind, (sc_value_t *)out), error, capacity);
}

int sc_native_host_function_new(uint64_t library, uint64_t runtime, uint64_t host_function,
                                uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.host_function_new((sc_runtime_t)runtime,
            (sc_host_func_t)host_function, (sc_value_t *)out), error, capacity);
}

int sc_native_function_call(uint64_t library, uint64_t runtime, uint64_t function,
                            uint64_t this_value, const uint64_t *argv, uint64_t argc,
                            uint64_t *out, char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || out == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.function_call((sc_runtime_t)runtime, (sc_value_t)function,
            (sc_value_t)this_value, (const sc_value_t *)argv, argc, (sc_value_t *)out),
        error, capacity);
}

int sc_native_value_retain(uint64_t library, uint64_t runtime, uint64_t value,
                           char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.value_retain((sc_runtime_t)runtime, (sc_value_t)value),
        error, capacity);
}

void sc_native_value_release(uint64_t library, uint64_t runtime, uint64_t value) {
    sc_native_state *state = state_from_id(library);
    if (state != NULL && state->plugin != NULL && runtime != 0 && value != 0) {
        state->plugin->api.value_release((sc_runtime_t)runtime, (sc_value_t)value);
    }
}

int sc_native_last_error_copy(uint64_t library, uint64_t runtime, char *buffer,
                              uint64_t buffer_capacity, uint64_t *required,
                              char *error, uint64_t capacity) {
    sc_native_state *state = checked_state(library, error, capacity);
    if (state == NULL || required == NULL) return SC_NATIVE_INTERNAL;
    return operation_status(state, (sc_runtime_t)runtime,
        state->plugin->api.last_error_copy((sc_runtime_t)runtime, buffer, buffer_capacity,
            required), error, capacity);
}
