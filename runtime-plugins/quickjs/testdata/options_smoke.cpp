#include "scardice_runtime_v1.h"

#include "dynamic_loader.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

sc_status_t SC_CALL unsupported_get(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view,
                                    sc_value_t *) { return SC_ENOTSUP; }
sc_status_t SC_CALL unsupported_set(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view,
                                    sc_value_t) { return SC_ENOTSUP; }
sc_status_t SC_CALL unsupported_has(sc_host_ctx_t, sc_host_ref_t, sc_string_view, uint32_t *) {
    return SC_ENOTSUP;
}
sc_status_t SC_CALL unsupported_delete(sc_host_ctx_t, sc_host_ref_t, sc_string_view, uint32_t *) {
    return SC_ENOTSUP;
}
sc_status_t SC_CALL unsupported_keys(sc_host_ctx_t, sc_host_ref_t, char *, uint64_t, uint64_t *) {
    return SC_ENOTSUP;
}
sc_status_t SC_CALL unsupported_call(sc_host_ctx_t, sc_runtime_t, sc_host_func_t, sc_value_t,
                                     const sc_value_t *, uint64_t, sc_value_t *) { return SC_ENOTSUP; }
sc_status_t SC_CALL unsupported_error(sc_host_ctx_t, char *, uint64_t, uint64_t *) { return SC_ENOTSUP; }

sc_string_view view(const char *text) {
    return sc_string_view{text, static_cast<uint64_t>(std::strlen(text))};
}

bool expect(bool condition, const char *message) {
    if (!condition) {
        std::fprintf(stderr, "options smoke failure: %s\n", message);
        return false;
    }
    return true;
}

int run(const char *library_path, const char *mode) {
    scardice_test::library_handle library = scardice_test::open_library(library_path);
    if (!expect(scardice_test::library_is_open(library), "open provider")) return 1;
    auto query = reinterpret_cast<decltype(&scardice_runtime_query_v1)>(
        scardice_test::lookup_symbol(library, "scardice_runtime_query_v1"));
    if (!expect(query != nullptr, "query symbol")) return 1;
    sc_runtime_query_v1 query_request{sizeof(query_request), SC_RUNTIME_ABI_MAJOR, SC_RUNTIME_ABI_MINOR,
                                       SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR};
    const sc_runtime_plugin_v1 *plugin = nullptr;
    if (!expect(query(&query_request, &plugin) == SC_OK && plugin != nullptr, "query succeeds")) return 1;
    const sc_runtime_api_v1 *api = &plugin->api;
    sc_host_api_v1 host{sizeof(host), SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR, unsupported_get, unsupported_set,
                        unsupported_has, unsupported_delete, unsupported_keys, unsupported_call, unsupported_error};

    const char *options = "";
    const char *source = "0";
    sc_status_t expected_create = SC_OK;
    if (std::strcmp(mode, "malformed") == 0) {
        options = "{\"version\":1,\"runtime\":";
        expected_create = SC_EINVAL;
    } else if (std::strcmp(mode, "unknown") == 0) {
        options = "{\"version\":1,\"unknown\":1}";
        expected_create = SC_EINVAL;
    } else if (std::strcmp(mode, "out-of-range") == 0) {
        options = "{\"version\":1,\"runtime\":{\"memoryLimitBytes\":1099511627777}}";
        expected_create = SC_EINVAL;
    } else if (std::strcmp(mode, "timeout") == 0) {
        options = "{\"version\":1,\"runtime\":{\"executionTimeoutMillis\":10}}";
        source = "for (;;) {}";
    } else if (std::strcmp(mode, "full") == 0) {
        options = "{\"version\":1,\"runtime\":{\"memoryLimitBytes\":134217728,\"gcThresholdBytes\":33554432,\"maxStackSizeBytes\":524288,\"executionTimeoutMillis\":3000},\"services\":{\"fetch\":{\"maxConcurrent\":2,\"maxResponseBytes\":4194304},\"websocket\":{\"maxConnections\":5,\"maxMessageBytes\":6291456},\"filesystem\":{\"maxReadBytes\":7340032,\"maxWriteBytes\":8388608},\"pbkdf2\":{\"maxIterations\":9,\"maxOutputBytes\":10}}}";
    } else if (std::strcmp(mode, "memory") == 0) {
        options = "{\"version\":1,\"runtime\":{\"memoryLimitBytes\":4194304}}";
        source = "new ArrayBuffer(8388608)";
    } else if (std::strcmp(mode, "stack") == 0) {
        options = "{\"version\":1,\"runtime\":{\"maxStackSizeBytes\":65536}}";
        source = "function f(){return f()} f()";
    } else {
        std::fprintf(stderr, "unknown options smoke mode: %s\n", mode);
        return 1;
    }
    sc_runtime_create_info_v1 info{sizeof(info), view(options)};
    sc_runtime_t runtime = 0;
    sc_status_t status = api->create(&host, 0, &info, &runtime);
    if (!expect(status == expected_create, "create status")) return 1;
    if (expected_create != SC_OK) return 0;
    if (!expect(api->start(runtime) == SC_OK, "start status")) {
        api->destroy(runtime);
        return 1;
    }
    sc_value_t result = 0;
    status = api->eval(runtime, view("options.js"), view(source), &result);
    bool valid = std::strcmp(mode, "full") == 0 ? status == SC_OK
                                                : (std::strcmp(mode, "timeout") == 0 ? status == SC_ETIMEOUT
                                                                                     : status == SC_EEXCEPTION || status == SC_EOOM);
    if (result != 0) api->value_release(runtime, result);
    api->destroy(runtime);
    return expect(valid, "resource limit status") ? 0 : 1;
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    return run(argv[1], argv[2]);
}
