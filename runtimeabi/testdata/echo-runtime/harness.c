#include "scardice_runtime_v1.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TYPE_UNDEFINED 0U
#define TYPE_NULL 1U
#define TYPE_BOOL 2U
#define TYPE_I64 3U
#define TYPE_U64 4U
#define TYPE_F64 5U
#define TYPE_STRING 6U
#define TYPE_OBJECT 7U
#define TYPE_HOST_OBJECT 8U
#define TYPE_HOST_FUNCTION 9U

static const sc_runtime_api_v1 *g_api;
static int g_host_gets;
static int g_host_sets;
static int g_host_has;
static int g_host_calls;
static int g_host_seen;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", message, __LINE__); \
            return 1; \
        } \
    } while (0)
#define STATUS(actual, expected, message) \
    CHECK((actual) == (expected), message)

static sc_string_view sv(const char *text) {
    sc_string_view view = {text, (uint64_t)strlen(text)};
    return view;
}

static sc_status_t SC_CALL host_get(sc_host_ctx_t ctx, sc_runtime_t runtime,
                                    sc_host_ref_t object, sc_string_view key,
                                    sc_value_t *out) {
    (void)ctx;
    (void)object;
    g_host_gets++;
    if (key.len != 6 || memcmp(key.data, "answer", 6) != 0) {
        return SC_EINVAL;
    }
    return g_api->value_new_i64(runtime, 42, out);
}

static sc_status_t SC_CALL host_set(sc_host_ctx_t ctx, sc_runtime_t runtime,
                                    sc_host_ref_t object, sc_string_view key,
                                    sc_value_t value) {
    int64_t number = 0;
    (void)ctx;
    (void)object;
    g_host_sets++;
    if (key.len != 4 || memcmp(key.data, "seen", 4) != 0 ||
        g_api->value_to_i64(runtime, value, &number) != SC_OK || number != 9) {
        return SC_EINVAL;
    }
    g_host_seen = 1;
    return SC_OK;
}

static sc_status_t SC_CALL host_has(sc_host_ctx_t ctx, sc_host_ref_t object,
                                    sc_string_view key, uint32_t *out) {
    (void)ctx;
    (void)object;
    g_host_has++;
    *out = (key.len == 6 && memcmp(key.data, "answer", 6) == 0) ? 1U : 0U;
    return SC_OK;
}

static sc_status_t SC_CALL host_call(sc_host_ctx_t ctx, sc_runtime_t runtime,
                                     sc_host_func_t function, sc_value_t this_value,
                                     const sc_value_t *argv, uint64_t argc,
                                     sc_value_t *out) {
    int64_t total = 0;
    (void)ctx;
    (void)this_value;
    g_host_calls++;
    if (function != 7 || argc != 2 || g_api->value_to_i64(runtime, argv[0], &total) != SC_OK) {
        return SC_EINVAL;
    }
    for (uint64_t i = 1; i < argc; ++i) {
        int64_t value = 0;
        if (g_api->value_to_i64(runtime, argv[i], &value) != SC_OK) {
            return SC_EINVAL;
        }
        total += value;
    }
    return g_api->value_new_i64(runtime, total, out);
}

int main(int argc, char **argv) {
    const char *library_path = argc > 1 ? argv[1] : "libecho_runtime.so";
    void *library = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
    CHECK(library != NULL, "provider shared library loads");

    sc_status_t(SC_CALL *query_fn)(const sc_runtime_query_v1 *, const sc_runtime_plugin_v1 **);
    *(void **)(&query_fn) = dlsym(library, "scardice_runtime_query_v1");
    CHECK(query_fn != NULL, "provider exports v1 query symbol");

    const sc_runtime_plugin_v1 *plugin = NULL;
    sc_runtime_query_v1 short_query = {sizeof(uint32_t), 1, 0, 1, 0};
    STATUS(query_fn(&short_query, &plugin), SC_EABI, "short query is rejected");

    sc_runtime_query_v1 query = {sizeof(query), SC_RUNTIME_ABI_MAJOR, SC_RUNTIME_ABI_MINOR,
                                 SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR};
    STATUS(query_fn(&query, &plugin), SC_OK, "ABI query succeeds");
    CHECK(plugin != NULL, "query returns plugin");
    CHECK(plugin->struct_size == sizeof(*plugin), "plugin struct size is exact");
    CHECK(plugin->descriptor.struct_size == sizeof(plugin->descriptor), "descriptor struct size is exact");
    CHECK(plugin->descriptor.abi_major == SC_RUNTIME_ABI_MAJOR &&
              plugin->descriptor.host_abi_major == SC_HOST_ABI_MAJOR,
          "descriptor ABI versions match");
    CHECK(strcmp(plugin->descriptor.id, "echo-runtime") == 0 &&
              strcmp(plugin->descriptor.language, "echo") == 0,
          "descriptor has static identity");
    CHECK(plugin->api.struct_size == sizeof(plugin->api), "API struct size is exact");
    g_api = &plugin->api;

    sc_host_api_v1 host = {sizeof(host), SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR,
                           host_get, host_set, host_has, NULL, NULL, host_call, NULL};
    sc_runtime_create_info_v1 info = {sizeof(info), sv("{}")};
    sc_runtime_t runtime = 0;
    STATUS(g_api->create(&host, 123, &info, &runtime), SC_OK, "create succeeds");
    CHECK(runtime != 0, "runtime handle is nonzero");
    STATUS(g_api->start(runtime), SC_OK, "start succeeds");

    sc_value_t value = 0;
    STATUS(g_api->eval(runtime, sv("fixture.echo"), sv("1 + 2"), &value), SC_OK,
           "deterministic eval succeeds");
    int64_t integer = 0;
    STATUS(g_api->value_to_i64(runtime, value, &integer), SC_OK, "eval result converts to i64");
    CHECK(integer == 3, "eval result equals three");
    g_api->value_release(runtime, value);

    STATUS(g_api->eval(runtime, sv("fixture.echo"), sv("throw echo error"), &value), SC_EEXCEPTION,
           "deterministic eval error returns exception status");
    uint64_t required = 0;
    STATUS(g_api->last_error_copy(runtime, NULL, 0, &required), SC_EINVAL,
           "last error first call reports insufficient buffer");
    CHECK(required > 1, "last error reports required capacity");
    char *error = (char *)calloc(1, (size_t)required);
    CHECK(error != NULL, "error buffer allocates");
    STATUS(g_api->last_error_copy(runtime, error, required, &required), SC_OK,
           "last error second call succeeds");
    CHECK(strstr(error, "echo eval error") != NULL, "last error text is visible");
    free(error);

    sc_value_t nine = 0;
    STATUS(g_api->value_new_i64(runtime, 9, &nine), SC_OK, "integer constructor succeeds");
    STATUS(g_api->global_set(runtime, sv("answer"), nine), SC_OK, "global set succeeds");
    g_api->value_release(runtime, nine);
    STATUS(g_api->global_get(runtime, sv("answer"), &value), SC_OK, "global get succeeds");
    STATUS(g_api->value_to_i64(runtime, value, &integer), SC_OK, "global value converts");
    CHECK(integer == 9, "global value round trips");
    g_api->value_release(runtime, value);

    sc_value_t object = 0;
    STATUS(g_api->object_new(runtime, &object), SC_OK, "object new succeeds");
    sc_value_t persistent = 0;
    STATUS(g_api->value_new_string(runtime, sv("persistent"), &persistent), SC_OK,
           "string constructor succeeds");
    STATUS(g_api->value_retain(runtime, persistent), SC_OK, "value retain succeeds");
    g_api->value_release(runtime, persistent);
    STATUS(g_api->object_set(runtime, object, sv("name"), persistent), SC_OK,
           "object set retains value");
    g_api->value_release(runtime, persistent);
    uint32_t object_has_name = 0;
    STATUS(g_api->object_has(runtime, object, sv("name"), &object_has_name), SC_OK,
           "object has succeeds");
    CHECK(object_has_name == 1, "object has finds name");
    STATUS(g_api->object_get(runtime, object, sv("name"), &value), SC_OK, "object get succeeds");
    required = 0;
    STATUS(g_api->value_to_utf8_copy(runtime, value, NULL, 0, &required), SC_EINVAL,
           "string first copy reports insufficient buffer");
    CHECK(required == strlen("persistent") + 1, "string reports required capacity");
    char text[32];
    STATUS(g_api->value_to_utf8_copy(runtime, value, text, sizeof(text), &required), SC_OK,
           "string second copy succeeds");
    CHECK(strcmp(text, "persistent") == 0, "object string value round trips");
    g_api->value_release(runtime, value);
    g_api->value_release(runtime, object);

    sc_value_t host_object = 0;
    STATUS(g_api->host_object_new(runtime, 55, 1, &host_object), SC_OK,
           "host object proxy constructor succeeds");
    STATUS(g_api->object_get(runtime, host_object, sv("answer"), &value), SC_OK,
           "host object get delegates");
    STATUS(g_api->value_to_i64(runtime, value, &integer), SC_OK, "host get result converts");
    CHECK(integer == 42 && g_host_gets == 1, "host get callback is observable");
    g_api->value_release(runtime, value);
    STATUS(g_api->object_set(runtime, host_object, sv("seen"), host_object), SC_EINVAL,
           "host set rejects non-integer value");
    STATUS(g_api->value_new_i64(runtime, 9, &value), SC_OK, "host set value constructs");
    STATUS(g_api->object_set(runtime, host_object, sv("seen"), value), SC_OK,
           "host object set delegates");
    g_api->value_release(runtime, value);
    uint32_t has = 0;
    STATUS(g_api->object_has(runtime, host_object, sv("answer"), &has), SC_OK,
           "host object has delegates");
    CHECK(has == 1 && g_host_sets == 2 && g_host_seen && g_host_has == 1,
          "host callbacks receive expected operations");
    sc_host_ref_t host_ref = 0;
    uint32_t host_kind = 0;
    STATUS(g_api->value_get_host_ref(runtime, host_object, &host_ref, &host_kind), SC_OK,
           "host reference inspection succeeds");
    CHECK(host_ref == 55 && host_kind == 1, "host reference round trips");
    g_api->value_release(runtime, host_object);

    sc_value_t function = 0;
    STATUS(g_api->host_function_new(runtime, 7, &function), SC_OK,
           "host function proxy constructor succeeds");
    sc_value_t args[2];
    STATUS(g_api->value_new_i64(runtime, 2, &args[0]), SC_OK, "first callback argument constructs");
    STATUS(g_api->value_new_i64(runtime, 3, &args[1]), SC_OK, "second callback argument constructs");
    STATUS(g_api->function_call(runtime, function, 0, args, 2, &value), SC_OK,
           "function call delegates");
    STATUS(g_api->value_to_i64(runtime, value, &integer), SC_OK, "callback result converts");
    CHECK(integer == 5 && g_host_calls == 1, "host function callback is observable");
    g_api->value_release(runtime, value);
    g_api->value_release(runtime, args[0]);
    g_api->value_release(runtime, args[1]);
    g_api->value_release(runtime, function);

    sc_value_t primitive = 0;
    uint32_t type = 99;
    STATUS(g_api->value_new_undefined(runtime, &primitive), SC_OK, "undefined constructor succeeds");
    STATUS(g_api->value_type(runtime, primitive, &type), SC_OK, "undefined type inspection succeeds");
    CHECK(type == TYPE_UNDEFINED, "undefined type is reported");
    g_api->value_release(runtime, primitive);
    STATUS(g_api->value_new_null(runtime, &primitive), SC_OK, "null constructor succeeds");
    STATUS(g_api->value_type(runtime, primitive, &type), SC_OK, "null type inspection succeeds");
    CHECK(type == TYPE_NULL, "null type is reported");
    g_api->value_release(runtime, primitive);
    STATUS(g_api->value_new_bool(runtime, 1, &primitive), SC_OK, "bool constructor succeeds");
    uint32_t boolean = 0;
    STATUS(g_api->value_to_bool(runtime, primitive, &boolean), SC_OK, "bool conversion succeeds");
    CHECK(boolean == 1, "bool value is reported");
    g_api->value_release(runtime, primitive);
    STATUS(g_api->value_new_u64(runtime, 123, &primitive), SC_OK, "u64 constructor succeeds");
    uint64_t unsigned_value = 0;
    STATUS(g_api->value_to_u64(runtime, primitive, &unsigned_value), SC_OK, "u64 conversion succeeds");
    CHECK(unsigned_value == 123, "u64 value is reported");
    g_api->value_release(runtime, primitive);
    STATUS(g_api->value_new_f64(runtime, 2.5, &primitive), SC_OK, "f64 constructor succeeds");
    double floating = 0;
    STATUS(g_api->value_to_f64(runtime, primitive, &floating), SC_OK, "f64 conversion succeeds");
    CHECK(floating == 2.5, "f64 value is reported");
    g_api->value_release(runtime, primitive);

    STATUS(g_api->stop(runtime), SC_OK, "stop succeeds");
    g_api->destroy(runtime);
    dlclose(library);
    puts("echo runtime integration: PASS");
    return 0;
}
