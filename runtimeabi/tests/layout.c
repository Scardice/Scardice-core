#include <stddef.h>
#include <stdint.h>

#include "scardice_runtime_v1.h"

_Static_assert(sizeof(sc_string_view) == 16, "sc_string_view layout");
_Static_assert(offsetof(sc_string_view, data) == 0, "sc_string_view.data offset");
_Static_assert(offsetof(sc_string_view, len) == 8, "sc_string_view.len offset");

_Static_assert(sizeof(sc_host_service_request_v1) == 72, "host service request layout");
_Static_assert(offsetof(sc_host_service_request_v1, operation) == 4, "host service operation offset");
_Static_assert(offsetof(sc_host_service_request_v1, string) == 8, "host service string offset");
_Static_assert(sizeof(sc_host_service_response_v1) == 88, "host service response layout");
_Static_assert(offsetof(sc_host_service_response_v1, status) == 4, "host service status offset");
_Static_assert(offsetof(sc_host_service_response_v1, string_buffer) == 8, "host service string buffer offset");
_Static_assert(sizeof(sc_service_event_v1) == 88, "service event layout");
_Static_assert(offsetof(sc_service_event_v1, kind) == 4, "service event kind offset");
_Static_assert(offsetof(sc_service_event_v1, status) == 8, "service event status offset");
_Static_assert(offsetof(sc_service_event_v1, request) == 16, "service event request offset");
_Static_assert(offsetof(sc_service_event_v1, string) == 24, "service event string offset");
_Static_assert(offsetof(sc_service_event_v1, bytes) == 40, "service event bytes offset");
_Static_assert(offsetof(sc_service_event_v1, bytes_len) == 48, "service event bytes length offset");
_Static_assert(offsetof(sc_service_event_v1, bool_value) == 56, "service event bool offset");
_Static_assert(offsetof(sc_service_event_v1, int64_value) == 64, "service event int64 offset");
_Static_assert(offsetof(sc_service_event_v1, uint64_value) == 72, "service event uint64 offset");
_Static_assert(offsetof(sc_service_event_v1, float64_value) == 80, "service event float64 offset");

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
_Static_assert(offsetof(sc_runtime_api_v1, service_event) == offsetof(sc_runtime_api_v1, last_error_copy) + sizeof(void *), "runtime api service event order");
_Static_assert(offsetof(sc_runtime_api_v1, tick) == offsetof(sc_runtime_api_v1, service_event) + sizeof(void *), "runtime api tick order");
_Static_assert(sizeof(sc_runtime_api_v1) == offsetof(sc_runtime_api_v1, tick) + sizeof(void *), "runtime api tick size");
_Static_assert(offsetof(sc_host_api_v1, struct_size) == 0, "host api struct_size offset");
_Static_assert(offsetof(sc_host_api_v1, abi_major) == 4, "host api major offset");
_Static_assert(offsetof(sc_host_api_v1, abi_minor) == 8, "host api minor offset");
_Static_assert(offsetof(sc_host_api_v1, host_get) == 16, "host api host_get prefix");
_Static_assert(offsetof(sc_host_api_v1, host_set) == offsetof(sc_host_api_v1, host_get) + sizeof(void *), "host api host_set order");
_Static_assert(offsetof(sc_host_api_v1, host_call) == offsetof(sc_host_api_v1, host_get) + 5 * sizeof(void *), "host api host_call order");
_Static_assert(offsetof(sc_host_api_v1, last_error_copy) == offsetof(sc_host_api_v1, host_get) + 6 * sizeof(void *), "host api error order");
_Static_assert(offsetof(sc_host_api_v1, service_call) == offsetof(sc_host_api_v1, host_get) + 7 * sizeof(void *), "host api service order");
_Static_assert(offsetof(sc_host_api_v1, service_start) == offsetof(sc_host_api_v1, service_call) + sizeof(void *), "host api service start order");
_Static_assert(offsetof(sc_host_api_v1, service_cancel) == offsetof(sc_host_api_v1, service_start) + sizeof(void *), "host api service cancel order");
_Static_assert(sizeof(sc_host_api_v1) == offsetof(sc_host_api_v1, service_cancel) + sizeof(void *), "host api service size");

_Static_assert(offsetof(sc_runtime_plugin_v1, struct_size) == 0, "plugin struct_size offset");
_Static_assert(offsetof(sc_runtime_plugin_v1, descriptor) == 8, "plugin descriptor prefix");
_Static_assert(offsetof(sc_runtime_plugin_v1, api) == 72, "plugin api prefix");

_Static_assert(SC_CAP_SCRIPT == UINT64_C(1) << 0, "script capability");
_Static_assert(SC_CAP_SOURCE_LOCATION == UINT64_C(1) << 8, "source location capability");
_Static_assert(SC_CAP_HOST_SERVICE == UINT64_C(1) << 9, "host service capability");
_Static_assert(SC_SERVICE_OP_FETCH_REQUEST == UINT32_C(0x0301), "fetch request operation");
_Static_assert(SC_SERVICE_OP_HTTP_REQUEST == UINT32_C(0x0401), "http request operation");
_Static_assert(SC_SERVICE_OP_WEBSOCKET_CONNECT == UINT32_C(0x0501), "websocket connect operation");
_Static_assert(SC_SERVICE_OP_WEBSOCKET_SEND == UINT32_C(0x0502), "websocket send operation");
_Static_assert(SC_SERVICE_OP_WEBSOCKET_CLOSE == UINT32_C(0x0503), "websocket close operation");
_Static_assert(SC_SERVICE_OP_FILESYSTEM_STAT == UINT32_C(0x0603), "filesystem stat operation");
_Static_assert(SC_SERVICE_OP_FILESYSTEM_READ_DIR == UINT32_C(0x0604), "filesystem read dir operation");
_Static_assert(SC_SERVICE_OP_FILESYSTEM_MKDIR == UINT32_C(0x0605), "filesystem mkdir operation");
_Static_assert(SC_SERVICE_OP_FILESYSTEM_REMOVE == UINT32_C(0x0606), "filesystem remove operation");
_Static_assert(SC_SERVICE_OP_ABORT_CREATE == UINT32_C(0x0701), "abort create operation");
_Static_assert(SC_SERVICE_OP_ABORT_CANCEL == UINT32_C(0x0702), "abort cancel operation");
_Static_assert(SC_SERVICE_OP_STRUCTURED_CLONE == UINT32_C(0x0801), "structured clone operation");
_Static_assert(SC_SERVICE_OP_UTIL_INSPECT == UINT32_C(0x0901), "util inspect operation");
_Static_assert(SC_SERVICE_OP_FILESYSTEM_READ_FILE_SYNC == UINT32_C(0x0607), "filesystem sync read operation");
_Static_assert(SC_SERVICE_OP_FILESYSTEM_WRITE_FILE_SYNC == UINT32_C(0x0608), "filesystem sync write operation");

static sc_status_t SC_CALL compile_query_signature(const sc_runtime_query_v1 *query, const sc_runtime_plugin_v1 **out_plugin) {
    return scardice_runtime_query_v1(query, out_plugin);
}

int main(void) {
    return compile_query_signature(NULL, NULL);
}
