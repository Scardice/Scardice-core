#include "scardice_runtime_v1.h"
#include "dynamic_loader.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

sc_status_t SC_CALL unsupported_get(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view,
                                    sc_value_t *) {
    return SC_ENOTSUP;
}

sc_status_t SC_CALL unsupported_set(sc_host_ctx_t, sc_runtime_t, sc_host_ref_t, sc_string_view, sc_value_t) {
    return SC_ENOTSUP;
}

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
                                    const sc_value_t *, uint64_t, sc_value_t *) {
    return SC_ENOTSUP;
}

sc_status_t SC_CALL unsupported_error(sc_host_ctx_t, char *, uint64_t, uint64_t *) {
    return SC_ENOTSUP;
}

sc_string_view view(const char *text) noexcept {
    return sc_string_view{text, static_cast<uint64_t>(std::strlen(text))};
}

bool expect(bool condition, const char *message) {
    if (!condition) {
        std::fprintf(stderr, "compat v1 smoke failure: %s\n", message);
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv) {
    if (!expect(argc == 2, "provider path argument")) return 1;

    scardice_test::library_handle library = scardice_test::open_library(argv[1]);
    if (!expect(scardice_test::library_is_open(library), "open provider")) return 1;
    auto query = reinterpret_cast<decltype(&scardice_runtime_query_v1)>(
        scardice_test::lookup_symbol(library, "scardice_runtime_query_v1"));
    if (!expect(query != nullptr, "query symbol")) return 1;

    sc_runtime_query_v1 request{sizeof(request), SC_RUNTIME_ABI_MAJOR, SC_RUNTIME_ABI_MINOR,
                                SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR};
    const sc_runtime_plugin_v1 *plugin = nullptr;
    if (!expect(query(&request, &plugin) == SC_OK && plugin != nullptr, "query succeeds")) return 1;
    if (!expect(plugin->struct_size >= sizeof(sc_runtime_plugin_v1), "plugin struct size") ||
        !expect(plugin->descriptor.struct_size >= sizeof(sc_runtime_descriptor_v1), "descriptor struct size") ||
        !expect(plugin->descriptor.abi_major == SC_RUNTIME_ABI_MAJOR &&
                    plugin->descriptor.abi_minor <= SC_RUNTIME_ABI_MINOR &&
                    plugin->descriptor.host_abi_major == SC_HOST_ABI_MAJOR &&
                    plugin->descriptor.host_abi_minor <= SC_HOST_ABI_MINOR,
                "descriptor ABI versions") ||
        !expect(std::strcmp(plugin->descriptor.id, "quickjs") == 0, "descriptor identity")) {
        return 1;
    }

    sc_host_api_v1 host{sizeof(host), SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR, unsupported_get, unsupported_set,
                        unsupported_has, unsupported_delete, unsupported_keys, unsupported_call, unsupported_error};
    sc_runtime_create_info_v1 info{sizeof(info), view("")};
    sc_runtime_t runtime = 0;
    const sc_runtime_api_v1 *api = &plugin->api;
    if (!expect(api->create(&host, 0, &info, &runtime) == SC_OK, "create succeeds") ||
        !expect(api->start(runtime) == SC_OK, "start succeeds")) {
        if (runtime != 0) api->destroy(runtime);
        return 1;
    }

    sc_value_t result = 0;
    const sc_status_t eval_status = api->eval(runtime, view("compat-v1.js"), view("1 + 1"), &result);
    int64_t answer = 0;
    const bool valid = expect(eval_status == SC_OK, "eval succeeds") &&
                       expect(api->value_to_i64(runtime, result, &answer) == SC_OK, "convert result") &&
                       expect(answer == 2, "result value");
    if (result != 0) api->value_release(runtime, result);
    api->stop(runtime);
    api->destroy(runtime);
    return valid ? 0 : 1;
}
