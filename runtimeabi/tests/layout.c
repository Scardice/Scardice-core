#include <stddef.h>
#include <stdint.h>

#include "scardice_runtime_v1.h"

_Static_assert(sizeof(sc_string_view) == 16, "sc_string_view layout");
_Static_assert(offsetof(sc_string_view, data) == 0, "sc_string_view.data offset");
_Static_assert(offsetof(sc_string_view, len) == 8, "sc_string_view.len offset");

_Static_assert(sizeof(sc_runtime_descriptor_v1) == 64, "descriptor layout");
_Static_assert(offsetof(sc_runtime_descriptor_v1, struct_size) == 0, "descriptor struct_size offset");
_Static_assert(offsetof(sc_runtime_descriptor_v1, capabilities) == 24, "descriptor capabilities offset");
_Static_assert(offsetof(sc_runtime_descriptor_v1, id) == 32, "descriptor id offset");

_Static_assert(sizeof(sc_runtime_create_info_v1) == 24, "create info layout");
_Static_assert(offsetof(sc_runtime_create_info_v1, options_json) == 8, "create info options offset");
_Static_assert(sizeof(sc_runtime_query_v1) == 20, "query layout");
_Static_assert(offsetof(sc_runtime_query_v1, host_abi_minor) == 16, "query host minor offset");

_Static_assert(offsetof(sc_runtime_api_v1, struct_size) == 0, "runtime api struct_size offset");
_Static_assert(offsetof(sc_runtime_api_v1, create) == 8, "runtime api create prefix");
_Static_assert(offsetof(sc_runtime_api_v1, start) == offsetof(sc_runtime_api_v1, create) + sizeof(void *), "runtime api start order");
_Static_assert(offsetof(sc_runtime_api_v1, eval) == offsetof(sc_runtime_api_v1, create) + 4 * sizeof(void *), "runtime api eval order");
_Static_assert(offsetof(sc_runtime_api_v1, value_new_undefined) == offsetof(sc_runtime_api_v1, create) + 12 * sizeof(void *), "runtime api constructor order");
_Static_assert(offsetof(sc_runtime_api_v1, value_type) == offsetof(sc_runtime_api_v1, create) + 19 * sizeof(void *), "runtime api inspection order");
_Static_assert(offsetof(sc_runtime_api_v1, function_call) == offsetof(sc_runtime_api_v1, create) + 28 * sizeof(void *), "runtime api call order");
_Static_assert(offsetof(sc_runtime_api_v1, value_retain) == offsetof(sc_runtime_api_v1, create) + 29 * sizeof(void *), "runtime api retain order");

_Static_assert(offsetof(sc_host_api_v1, struct_size) == 0, "host api struct_size offset");
_Static_assert(offsetof(sc_host_api_v1, abi_major) == 4, "host api major offset");
_Static_assert(offsetof(sc_host_api_v1, abi_minor) == 8, "host api minor offset");
_Static_assert(offsetof(sc_host_api_v1, host_get) == 16, "host api host_get prefix");
_Static_assert(offsetof(sc_host_api_v1, host_set) == offsetof(sc_host_api_v1, host_get) + sizeof(void *), "host api host_set order");
_Static_assert(offsetof(sc_host_api_v1, host_call) == offsetof(sc_host_api_v1, host_get) + 5 * sizeof(void *), "host api host_call order");
_Static_assert(offsetof(sc_host_api_v1, last_error_copy) == offsetof(sc_host_api_v1, host_get) + 6 * sizeof(void *), "host api error order");

_Static_assert(offsetof(sc_runtime_plugin_v1, struct_size) == 0, "plugin struct_size offset");
_Static_assert(offsetof(sc_runtime_plugin_v1, descriptor) == 8, "plugin descriptor prefix");
_Static_assert(offsetof(sc_runtime_plugin_v1, api) == 72, "plugin api prefix");

_Static_assert(SC_CAP_SCRIPT == UINT64_C(1) << 0, "script capability");
_Static_assert(SC_CAP_SOURCE_LOCATION == UINT64_C(1) << 8, "source location capability");

static sc_status_t SC_CALL compile_query_signature(const sc_runtime_query_v1 *query, const sc_runtime_plugin_v1 **out_plugin) {
    return scardice_runtime_query_v1(query, out_plugin);
}

int main(void) {
    return compile_query_signature(NULL, NULL);
}
