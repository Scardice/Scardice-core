#include "scardice_runtime_v1.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ECHO_MAX_VALUES 128
#define ECHO_MAX_PROPERTIES 32
#define ECHO_MAX_KEY 32
#define ECHO_ERROR_CAPACITY 256

#define ECHO_TYPE_UNDEFINED 0U
#define ECHO_TYPE_NULL 1U
#define ECHO_TYPE_BOOL 2U
#define ECHO_TYPE_I64 3U
#define ECHO_TYPE_U64 4U
#define ECHO_TYPE_F64 5U
#define ECHO_TYPE_STRING 6U
#define ECHO_TYPE_OBJECT 7U
#define ECHO_TYPE_HOST_OBJECT 8U
#define ECHO_TYPE_HOST_FUNCTION 9U

typedef struct echo_property {
    uint32_t used;
    char key[ECHO_MAX_KEY];
    sc_value_t value;
} echo_property;

typedef struct echo_value {
    uint32_t used;
    uint32_t type;
    uint32_t refs;
    union {
        uint32_t boolean;
        int64_t i64;
        uint64_t u64;
        double f64;
        struct {
            char *data;
            uint64_t len;
        } string;
        struct {
            sc_host_ref_t ref;
            uint32_t kind;
        } host_object;
        sc_host_func_t host_function;
    } as;
    echo_property properties[ECHO_MAX_PROPERTIES];
} echo_value;

typedef struct echo_runtime {
    uint32_t used;
    uint32_t state;
    const sc_host_api_v1 *host;
    sc_host_ctx_t host_ctx;
    echo_value values[ECHO_MAX_VALUES];
    echo_property globals[ECHO_MAX_PROPERTIES];
    char last_error[ECHO_ERROR_CAPACITY];
} echo_runtime;

static echo_runtime g_runtime;

static sc_status_t echo_error(const char *message, sc_status_t status) {
    size_t length = strlen(message);
    if (length >= sizeof(g_runtime.last_error)) {
        length = sizeof(g_runtime.last_error) - 1;
    }
    memcpy(g_runtime.last_error, message, length);
    g_runtime.last_error[length] = '\0';
    return status;
}

static sc_status_t echo_runtime_check(sc_runtime_t runtime, uint32_t started,
                                      echo_runtime **out) {
    if (runtime == 0 || runtime != 1 || !g_runtime.used) {
        return echo_error("invalid runtime handle", SC_EINVAL);
    }
    if (started && g_runtime.state != 2) {
        return echo_error("runtime is not started", SC_ESTATE);
    }
    *out = &g_runtime;
    return SC_OK;
}

static echo_value *echo_value_lookup(echo_runtime *runtime, sc_value_t value) {
    if (value == 0 || value > ECHO_MAX_VALUES) {
        return NULL;
    }
    echo_value *entry = &runtime->values[value - 1];
    return entry->used ? entry : NULL;
}

static sc_status_t echo_value_check(echo_runtime *runtime, sc_value_t value,
                                    echo_value **out) {
    *out = echo_value_lookup(runtime, value);
    if (*out == NULL) {
        return echo_error("invalid value handle", SC_EINVAL);
    }
    return SC_OK;
}

static void echo_value_release_internal(echo_runtime *runtime, sc_value_t value);

static void echo_properties_clear(echo_runtime *runtime, echo_property *properties) {
    for (uint32_t i = 0; i < ECHO_MAX_PROPERTIES; ++i) {
        if (properties[i].used) {
            echo_value_release_internal(runtime, properties[i].value);
            properties[i].used = 0;
            properties[i].key[0] = '\0';
            properties[i].value = 0;
        }
    }
}

static void echo_value_release_internal(echo_runtime *runtime, sc_value_t value) {
    echo_value *entry = echo_value_lookup(runtime, value);
    if (entry == NULL || entry->refs == 0) {
        return;
    }
    entry->refs--;
    if (entry->refs != 0) {
        return;
    }
    if (entry->type == ECHO_TYPE_STRING) {
        free(entry->as.string.data);
    } else if (entry->type == ECHO_TYPE_OBJECT) {
        echo_properties_clear(runtime, entry->properties);
    }
    memset(entry, 0, sizeof(*entry));
}

static int echo_key_matches(const char *stored, sc_string_view key) {
    size_t length = strlen(stored);
    return length == key.len && memcmp(stored, key.data, (size_t)key.len) == 0;
}

static sc_status_t echo_property_get(echo_runtime *runtime, echo_property *properties,
                                     sc_string_view key, sc_value_t *out) {
    if (out == NULL || key.data == NULL || key.len >= ECHO_MAX_KEY) {
        return echo_error("invalid property arguments", SC_EINVAL);
    }
    for (uint32_t i = 0; i < ECHO_MAX_PROPERTIES; ++i) {
        if (properties[i].used && echo_key_matches(properties[i].key, key)) {
            echo_value *entry = echo_value_lookup(runtime, properties[i].value);
            if (entry == NULL) {
                return echo_error("dangling property value", SC_EINTERNAL);
            }
            entry->refs++;
            *out = properties[i].value;
            return SC_OK;
        }
    }
    return echo_error("property is not present", SC_EINVAL);
}

static sc_status_t echo_property_set(echo_runtime *runtime, echo_property *properties,
                                     sc_string_view key, sc_value_t value) {
    if (key.data == NULL || key.len == 0 || key.len >= ECHO_MAX_KEY) {
        return echo_error("invalid property key", SC_EINVAL);
    }
    if (echo_value_lookup(runtime, value) == NULL) {
        return echo_error("invalid property value", SC_EINVAL);
    }
    for (uint32_t i = 0; i < ECHO_MAX_PROPERTIES; ++i) {
        if (properties[i].used && echo_key_matches(properties[i].key, key)) {
            if (properties[i].value == value) {
                return SC_OK;
            }
            echo_value *entry = echo_value_lookup(runtime, value);
            if (entry == NULL) {
                return echo_error("invalid property value", SC_EINVAL);
            }
            entry->refs++;
            echo_value_release_internal(runtime, properties[i].value);
            properties[i].value = value;
            return SC_OK;
        }
    }
    for (uint32_t i = 0; i < ECHO_MAX_PROPERTIES; ++i) {
        if (!properties[i].used) {
            properties[i].used = 1;
            memcpy(properties[i].key, key.data, (size_t)key.len);
            properties[i].key[key.len] = '\0';
            echo_value *entry = echo_value_lookup(runtime, value);
            entry->refs++;
            properties[i].value = value;
            return SC_OK;
        }
    }
    return echo_error("property table is full", SC_EOOM);
}

static int echo_property_has(echo_property *properties, sc_string_view key) {
    for (uint32_t i = 0; i < ECHO_MAX_PROPERTIES; ++i) {
        if (properties[i].used && echo_key_matches(properties[i].key, key)) {
            return 1;
        }
    }
    return 0;
}

static sc_status_t echo_value_new(echo_runtime *runtime, uint32_t type, sc_value_t *out) {
    if (out == NULL) {
        return echo_error("missing value output", SC_EINVAL);
    }
    for (uint32_t i = 0; i < ECHO_MAX_VALUES; ++i) {
        if (!runtime->values[i].used) {
            memset(&runtime->values[i], 0, sizeof(runtime->values[i]));
            runtime->values[i].used = 1;
            runtime->values[i].type = type;
            runtime->values[i].refs = 1;
            *out = i + 1;
            return SC_OK;
        }
    }
    return echo_error("value table is full", SC_EOOM);
}

static sc_status_t SC_CALL echo_create(const sc_host_api_v1 *host, sc_host_ctx_t host_ctx,
                                       const sc_runtime_create_info_v1 *info,
                                       sc_runtime_t *out_runtime) {
    if (host == NULL || out_runtime == NULL || host->struct_size < sizeof(*host) ||
        host->abi_major != SC_HOST_ABI_MAJOR || host->abi_minor > SC_HOST_ABI_MINOR ||
        info == NULL || info->struct_size < sizeof(*info)) {
        return echo_error("invalid create or host ABI", SC_EABI);
    }
    if (g_runtime.used) {
        return echo_error("runtime already exists", SC_ESTATE);
    }
    memset(&g_runtime, 0, sizeof(g_runtime));
    g_runtime.used = 1;
    g_runtime.state = 1;
    g_runtime.host = host;
    g_runtime.host_ctx = host_ctx;
    *out_runtime = 1;
    return SC_OK;
}

static sc_status_t SC_CALL echo_start(sc_runtime_t runtime) {
    echo_runtime *state = NULL;
    sc_status_t status = echo_runtime_check(runtime, 0, &state);
    if (status != SC_OK) {
        return status;
    }
    if (state->state != 1) {
        return echo_error("runtime cannot start in current state", SC_ESTATE);
    }
    state->state = 2;
    return SC_OK;
}

static sc_status_t SC_CALL echo_stop(sc_runtime_t runtime) {
    echo_runtime *state = NULL;
    sc_status_t status = echo_runtime_check(runtime, 0, &state);
    if (status != SC_OK) {
        return status;
    }
    if (state->state != 2) {
        return echo_error("runtime cannot stop in current state", SC_ESTATE);
    }
    state->state = 3;
    return SC_OK;
}

static void SC_CALL echo_destroy(sc_runtime_t runtime) {
    if (runtime != 1 || !g_runtime.used) {
        return;
    }
    echo_properties_clear(&g_runtime, g_runtime.globals);
    for (uint32_t i = 0; i < ECHO_MAX_VALUES; ++i) {
        if (g_runtime.values[i].used) {
            g_runtime.values[i].refs = 1;
            echo_value_release_internal(&g_runtime, i + 1);
        }
    }
    memset(&g_runtime, 0, sizeof(g_runtime));
}

/*
 * Fixture source contract: eval accepts exactly "1 + 2" (the i64 value 3)
 * and "throw echo error" (SC_EEXCEPTION with runtime-local last error text).
 */
static sc_status_t SC_CALL echo_eval(sc_runtime_t runtime, sc_string_view filename,
                                     sc_string_view source, sc_value_t *out) {
    echo_runtime *state = NULL;
    (void)filename;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK || out == NULL || source.data == NULL) {
        return SC_EINVAL;
    }
    if (source.len == 5 && memcmp(source.data, "1 + 2", 5) == 0) {
        sc_status_t status = echo_value_new(state, ECHO_TYPE_I64, out);
        if (status == SC_OK) {
            state->values[*out - 1].as.i64 = 3;
        }
        return status;
    }
    if (source.len == 16 && memcmp(source.data, "throw echo error", 16) == 0) {
        return echo_error("echo eval error: deterministic failure", SC_EEXCEPTION);
    }
    return echo_error("unsupported echo source", SC_ENOTSUP);
}

static sc_status_t SC_CALL echo_load_entry(sc_runtime_t runtime, uint32_t entry_kind,
                                           sc_string_view filename, sc_string_view source,
                                           sc_value_t *out) {
    (void)runtime;
    (void)entry_kind;
    (void)filename;
    (void)source;
    (void)out;
    return echo_error("load_entry is not supported by echo runtime", SC_ENOTSUP);
}

static sc_status_t SC_CALL echo_global_get(sc_runtime_t runtime, sc_string_view name,
                                           sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) {
        return SC_EINVAL;
    }
    return echo_property_get(state, state->globals, name, out);
}

static sc_status_t SC_CALL echo_global_set(sc_runtime_t runtime, sc_string_view name,
                                           sc_value_t value) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) {
        return SC_EINVAL;
    }
    return echo_property_set(state, state->globals, name, value);
}

static sc_status_t SC_CALL echo_object_new(sc_runtime_t runtime, sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) {
        return SC_EINVAL;
    }
    return echo_value_new(state, ECHO_TYPE_OBJECT, out);
}

static sc_status_t SC_CALL echo_object_get(sc_runtime_t runtime, sc_value_t object,
                                           sc_string_view key, sc_value_t *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, object, &entry) != SC_OK) {
        return SC_EINVAL;
    }
    if (entry->type == ECHO_TYPE_HOST_OBJECT) {
        if (state->host->host_get == NULL) {
            return echo_error("host_get is unavailable", SC_ENOTSUP);
        }
        return state->host->host_get(state->host_ctx, runtime, entry->as.host_object.ref, key, out);
    }
    if (entry->type != ECHO_TYPE_OBJECT) {
        return echo_error("value is not an object", SC_EINVAL);
    }
    return echo_property_get(state, entry->properties, key, out);
}

static sc_status_t SC_CALL echo_object_set(sc_runtime_t runtime, sc_value_t object,
                                           sc_string_view key, sc_value_t value) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, object, &entry) != SC_OK) {
        return SC_EINVAL;
    }
    if (entry->type == ECHO_TYPE_HOST_OBJECT) {
        if (state->host->host_set == NULL) {
            return echo_error("host_set is unavailable", SC_ENOTSUP);
        }
        return state->host->host_set(state->host_ctx, runtime, entry->as.host_object.ref, key, value);
    }
    if (entry->type != ECHO_TYPE_OBJECT) {
        return echo_error("value is not an object", SC_EINVAL);
    }
    return echo_property_set(state, entry->properties, key, value);
}

static sc_status_t SC_CALL echo_object_has(sc_runtime_t runtime, sc_value_t object,
                                           sc_string_view key, uint32_t *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, object, &entry) != SC_OK) {
        return SC_EINVAL;
    }
    if (entry->type == ECHO_TYPE_HOST_OBJECT) {
        if (state->host->host_has == NULL) {
            return echo_error("host_has is unavailable", SC_ENOTSUP);
        }
        return state->host->host_has(state->host_ctx, entry->as.host_object.ref, key, out);
    }
    if (entry->type != ECHO_TYPE_OBJECT) {
        return echo_error("value is not an object", SC_EINVAL);
    }
    *out = echo_property_has(entry->properties, key) ? 1U : 0U;
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_new_undefined(sc_runtime_t runtime, sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    return echo_value_new(state, ECHO_TYPE_UNDEFINED, out);
}

static sc_status_t SC_CALL echo_value_new_null(sc_runtime_t runtime, sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    return echo_value_new(state, ECHO_TYPE_NULL, out);
}

static sc_status_t SC_CALL echo_value_new_bool(sc_runtime_t runtime, uint32_t value,
                                               sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_BOOL, out);
    if (status == SC_OK) state->values[*out - 1].as.boolean = value ? 1U : 0U;
    return status;
}

static sc_status_t SC_CALL echo_value_new_i64(sc_runtime_t runtime, int64_t value,
                                              sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_I64, out);
    if (status == SC_OK) state->values[*out - 1].as.i64 = value;
    return status;
}

static sc_status_t SC_CALL echo_value_new_u64(sc_runtime_t runtime, uint64_t value,
                                              sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_U64, out);
    if (status == SC_OK) state->values[*out - 1].as.u64 = value;
    return status;
}

static sc_status_t SC_CALL echo_value_new_f64(sc_runtime_t runtime, double value,
                                              sc_value_t *out) {
    echo_runtime *state = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_F64, out);
    if (status == SC_OK) state->values[*out - 1].as.f64 = value;
    return status;
}

static sc_status_t SC_CALL echo_value_new_string(sc_runtime_t runtime, sc_string_view value,
                                                 sc_value_t *out) {
    echo_runtime *state = NULL;
    if (value.data == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_STRING, out);
    if (status != SC_OK) return status;
    char *copy = (char *)malloc((size_t)value.len + 1);
    if (copy == NULL) {
        echo_value_release_internal(state, *out);
        return echo_error("string allocation failed", SC_EOOM);
    }
    memcpy(copy, value.data, (size_t)value.len);
    copy[value.len] = '\0';
    state->values[*out - 1].as.string.data = copy;
    state->values[*out - 1].as.string.len = value.len;
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_type(sc_runtime_t runtime, sc_value_t value, uint32_t *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    *out = entry->type;
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_to_bool(sc_runtime_t runtime, sc_value_t value,
                                              uint32_t *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    if (entry->type != ECHO_TYPE_BOOL) return echo_error("value is not a bool", SC_EINVAL);
    *out = entry->as.boolean;
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_to_i64(sc_runtime_t runtime, sc_value_t value,
                                             int64_t *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    if (entry->type == ECHO_TYPE_I64) *out = entry->as.i64;
    else if (entry->type == ECHO_TYPE_U64 && entry->as.u64 <= INT64_MAX) *out = (int64_t)entry->as.u64;
    else return echo_error("value is not an i64", SC_EINVAL);
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_to_u64(sc_runtime_t runtime, sc_value_t value,
                                             uint64_t *out) {
    sc_runtime_t ignored = runtime;
    (void)ignored;
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    if (entry->type != ECHO_TYPE_U64) return echo_error("value is not a u64", SC_EINVAL);
    *out = entry->as.u64;
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_to_f64(sc_runtime_t runtime, sc_value_t value,
                                             double *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    if (entry->type != ECHO_TYPE_F64) return echo_error("value is not an f64", SC_EINVAL);
    *out = entry->as.f64;
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_to_utf8_copy(sc_runtime_t runtime, sc_value_t value,
                                                   char *buffer, uint64_t capacity,
                                                   uint64_t *required) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (required == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    if (entry->type != ECHO_TYPE_STRING) return echo_error("value is not a string", SC_EINVAL);
    *required = entry->as.string.len + 1;
    if (buffer == NULL || capacity < *required) return echo_error("string buffer is too small", SC_EINVAL);
    memcpy(buffer, entry->as.string.data, (size_t)*required);
    return SC_OK;
}

static sc_status_t SC_CALL echo_value_get_host_ref(sc_runtime_t runtime, sc_value_t value,
                                                   sc_host_ref_t *out_ref, uint32_t *host_kind) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (out_ref == NULL || host_kind == NULL || echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, value, &entry) != SC_OK) return SC_EINVAL;
    if (entry->type != ECHO_TYPE_HOST_OBJECT) return echo_error("value is not a host object", SC_EINVAL);
    *out_ref = entry->as.host_object.ref;
    *host_kind = entry->as.host_object.kind;
    return SC_OK;
}

static sc_status_t SC_CALL echo_host_object_new(sc_runtime_t runtime, sc_host_ref_t ref,
                                                uint32_t kind, sc_value_t *out) {
    echo_runtime *state = NULL;
    if (ref == 0 || kind == 0 || echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_HOST_OBJECT, out);
    if (status == SC_OK) {
        state->values[*out - 1].as.host_object.ref = ref;
        state->values[*out - 1].as.host_object.kind = kind;
    }
    return status;
}

static sc_status_t SC_CALL echo_host_function_new(sc_runtime_t runtime, sc_host_func_t function,
                                                  sc_value_t *out) {
    echo_runtime *state = NULL;
    if (function == 0 || echo_runtime_check(runtime, 1, &state) != SC_OK) return SC_EINVAL;
    sc_status_t status = echo_value_new(state, ECHO_TYPE_HOST_FUNCTION, out);
    if (status == SC_OK) state->values[*out - 1].as.host_function = function;
    return status;
}

static sc_status_t SC_CALL echo_function_call(sc_runtime_t runtime, sc_value_t function,
                                              sc_value_t this_value, const sc_value_t *argv,
                                              uint64_t argc, sc_value_t *out) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK ||
        echo_value_check(state, function, &entry) != SC_OK || out == NULL) return SC_EINVAL;
    if (entry->type != ECHO_TYPE_HOST_FUNCTION || state->host->host_call == NULL) {
        return echo_error("value is not a callable host function", SC_EINVAL);
    }
    return state->host->host_call(state->host_ctx, runtime, entry->as.host_function,
                                  this_value, argv, argc, out);
}

static sc_status_t SC_CALL echo_value_retain(sc_runtime_t runtime, sc_value_t value) {
    echo_runtime *state = NULL;
    echo_value *entry = NULL;
    if (echo_runtime_check(runtime, 1, &state) != SC_OK || echo_value_check(state, value, &entry) != SC_OK) {
        return SC_EINVAL;
    }
    if (entry->refs == UINT32_MAX) return echo_error("value refcount overflow", SC_EOOM);
    entry->refs++;
    return SC_OK;
}

static void SC_CALL echo_value_release(sc_runtime_t runtime, sc_value_t value) {
    if (runtime == 1 && g_runtime.used) echo_value_release_internal(&g_runtime, value);
}

static sc_status_t SC_CALL echo_last_error_copy(sc_runtime_t runtime, char *buffer,
                                                uint64_t capacity, uint64_t *required) {
    echo_runtime *state = NULL;
    if (required == NULL || echo_runtime_check(runtime, 0, &state) != SC_OK) return SC_EINVAL;
    *required = (uint64_t)strlen(state->last_error) + 1;
    if (buffer == NULL || capacity < *required) return SC_EINVAL;
    memcpy(buffer, state->last_error, (size_t)*required);
    return SC_OK;
}

static const sc_runtime_descriptor_v1 ECHO_DESCRIPTOR = {
    sizeof(sc_runtime_descriptor_v1),
    SC_RUNTIME_ABI_MAJOR,
    SC_RUNTIME_ABI_MINOR,
    SC_HOST_ABI_MAJOR,
    SC_HOST_ABI_MINOR,
    SC_CAP_SCRIPT | SC_CAP_HOST_OBJECT | SC_CAP_HOST_FUNCTION,
    "echo-runtime",
    "Scardice Echo Runtime",
    "1.0.0",
    "echo",
};

static const sc_runtime_api_v1 ECHO_API = {
    sizeof(sc_runtime_api_v1),
    echo_create,
    echo_start,
    echo_stop,
    echo_destroy,
    echo_eval,
    echo_load_entry,
    echo_global_get,
    echo_global_set,
    echo_object_new,
    echo_object_get,
    echo_object_set,
    echo_object_has,
    echo_value_new_undefined,
    echo_value_new_null,
    echo_value_new_bool,
    echo_value_new_i64,
    echo_value_new_u64,
    echo_value_new_f64,
    echo_value_new_string,
    echo_value_type,
    echo_value_to_bool,
    echo_value_to_i64,
    echo_value_to_u64,
    echo_value_to_f64,
    echo_value_to_utf8_copy,
    echo_value_get_host_ref,
    echo_host_object_new,
    echo_host_function_new,
    echo_function_call,
    echo_value_retain,
    echo_value_release,
    echo_last_error_copy,
};

static const sc_runtime_plugin_v1 ECHO_PLUGIN = {
    sizeof(sc_runtime_plugin_v1),
    ECHO_DESCRIPTOR,
    ECHO_API,
};

SC_EXPORT sc_status_t SC_CALL scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query, const sc_runtime_plugin_v1 **out_plugin) {
    if (query == NULL || out_plugin == NULL || query->struct_size < sizeof(*query) ||
        query->runtime_abi_major != SC_RUNTIME_ABI_MAJOR ||
        query->runtime_abi_minor > SC_RUNTIME_ABI_MINOR ||
        query->host_abi_major != SC_HOST_ABI_MAJOR ||
        query->host_abi_minor > SC_HOST_ABI_MINOR) {
        return SC_EABI;
    }
    *out_plugin = &ECHO_PLUGIN;
    return SC_OK;
}
