#include <cstddef>
#include <cstdint>

extern "C" {
#include "scardice_runtime_v1.h"
}

static_assert(sizeof(sc_string_view) == 16, "sc_string_view layout");
static_assert(offsetof(sc_string_view, len) == 8, "sc_string_view.len offset");
static_assert(sizeof(sc_runtime_descriptor_v1) == 64, "descriptor layout");
static_assert(offsetof(sc_runtime_descriptor_v1, struct_size) == 0, "descriptor struct_size offset");
static_assert(offsetof(sc_runtime_descriptor_v1, capabilities) == 24, "descriptor capabilities offset");
static_assert(sizeof(sc_runtime_create_info_v1) == 24, "create info layout");
static_assert(offsetof(sc_runtime_create_info_v1, options_json) == 8, "create info options offset");
static_assert(sizeof(sc_runtime_query_v1) == 20, "query layout");
static_assert(offsetof(sc_runtime_query_v1, host_abi_minor) == 16, "query host minor offset");

static_assert(offsetof(sc_runtime_api_v1, struct_size) == 0, "runtime api struct_size offset");
static_assert(offsetof(sc_runtime_api_v1, create) == 8, "runtime api create prefix");
static_assert(offsetof(sc_runtime_api_v1, eval) == offsetof(sc_runtime_api_v1, create) + 4 * sizeof(void *), "runtime api eval order");
static_assert(offsetof(sc_runtime_api_v1, value_new_undefined) == offsetof(sc_runtime_api_v1, create) + 12 * sizeof(void *), "runtime api constructor order");
static_assert(offsetof(sc_runtime_api_v1, value_type) == offsetof(sc_runtime_api_v1, create) + 19 * sizeof(void *), "runtime api inspection order");
static_assert(offsetof(sc_runtime_api_v1, function_call) == offsetof(sc_runtime_api_v1, create) + 28 * sizeof(void *), "runtime api call order");
static_assert(offsetof(sc_runtime_api_v1, value_retain) == offsetof(sc_runtime_api_v1, create) + 29 * sizeof(void *), "runtime api retain order");
static_assert(offsetof(sc_host_api_v1, host_get) == 16, "host api prefix");
static_assert(offsetof(sc_host_api_v1, host_call) == offsetof(sc_host_api_v1, host_get) + 5 * sizeof(void *), "host api host_call order");
static_assert(offsetof(sc_runtime_plugin_v1, descriptor) == 8, "plugin descriptor prefix");
static_assert(offsetof(sc_runtime_plugin_v1, api) == 72, "plugin api prefix");

static_assert(SC_CAP_SCRIPT == (UINT64_C(1) << 0), "script capability");
static_assert(SC_CAP_SOURCE_LOCATION == (UINT64_C(1) << 8), "source location capability");

using query_fn = sc_status_t (SC_CALL *)(const sc_runtime_query_v1 *, const sc_runtime_plugin_v1 **);
static_assert(sizeof(query_fn) == sizeof(void *), "query function pointer");

int main() {
    query_fn query = &scardice_runtime_query_v1;
    return query(nullptr, nullptr);
}
