#include <cstddef>
#include <cstdint>

extern "C" {
#include "scardice_runtime_v1.h"
}

static_assert(sizeof(sc_string_view) == 16, "sc_string_view layout");
static_assert(offsetof(sc_string_view, len) == 8, "sc_string_view.len offset");

static_assert(sizeof(sc_host_service_request_v1) == 72, "host service request layout");
static_assert(sizeof(sc_host_service_response_v1) == 88, "host service response layout");
static_assert(sizeof(sc_service_event_v1) == 88, "service event layout");
static_assert(offsetof(sc_service_event_v1, kind) == 4, "service event kind offset");
static_assert(offsetof(sc_service_event_v1, status) == 8, "service event status offset");
static_assert(offsetof(sc_service_event_v1, request) == 16, "service event request offset");
static_assert(offsetof(sc_service_event_v1, string) == 24, "service event string offset");
static_assert(offsetof(sc_service_event_v1, bytes) == 40, "service event bytes offset");
static_assert(offsetof(sc_service_event_v1, bytes_len) == 48, "service event bytes length offset");
static_assert(offsetof(sc_service_event_v1, bool_value) == 56, "service event bool offset");
static_assert(offsetof(sc_service_event_v1, int64_value) == 64, "service event int64 offset");
static_assert(offsetof(sc_service_event_v1, uint64_value) == 72, "service event uint64 offset");
static_assert(offsetof(sc_service_event_v1, float64_value) == 80, "service event float64 offset");
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
static_assert(offsetof(sc_runtime_api_v1, service_event) == offsetof(sc_runtime_api_v1, last_error_copy) + sizeof(void *), "runtime api service event order");
static_assert(offsetof(sc_runtime_api_v1, tick) == offsetof(sc_runtime_api_v1, service_event) + sizeof(void *), "runtime api tick order");
static_assert(sizeof(sc_runtime_api_v1) == offsetof(sc_runtime_api_v1, tick) + sizeof(void *), "runtime api tick size");
static_assert(offsetof(sc_host_api_v1, host_get) == 16, "host api prefix");
static_assert(offsetof(sc_host_api_v1, host_call) == offsetof(sc_host_api_v1, host_get) + 5 * sizeof(void *), "host api host_call order");
static_assert(offsetof(sc_host_api_v1, service_call) == offsetof(sc_host_api_v1, host_get) + 7 * sizeof(void *), "host api service order");
static_assert(offsetof(sc_host_api_v1, service_start) == offsetof(sc_host_api_v1, service_call) + sizeof(void *), "host api service start order");
static_assert(offsetof(sc_host_api_v1, service_cancel) == offsetof(sc_host_api_v1, service_start) + sizeof(void *), "host api service cancel order");
static_assert(sizeof(sc_host_api_v1) == offsetof(sc_host_api_v1, service_cancel) + sizeof(void *), "host api service size");
static_assert(offsetof(sc_runtime_plugin_v1, descriptor) == 8, "plugin descriptor prefix");
static_assert(offsetof(sc_runtime_plugin_v1, api) == 72, "plugin api prefix");

static_assert(SC_CAP_SCRIPT == (UINT64_C(1) << 0), "script capability");
static_assert(SC_CAP_SOURCE_LOCATION == (UINT64_C(1) << 8), "source location capability");
static_assert(SC_CAP_HOST_SERVICE == (UINT64_C(1) << 9), "host service capability");
static_assert(SC_SERVICE_OP_FETCH_REQUEST == UINT32_C(0x0301), "fetch request operation");
static_assert(SC_SERVICE_OP_HTTP_REQUEST == UINT32_C(0x0401), "http request operation");
static_assert(SC_SERVICE_OP_WEBSOCKET_CONNECT == UINT32_C(0x0501), "websocket connect operation");
static_assert(SC_SERVICE_OP_WEBSOCKET_SEND == UINT32_C(0x0502), "websocket send operation");
static_assert(SC_SERVICE_OP_WEBSOCKET_CLOSE == UINT32_C(0x0503), "websocket close operation");
static_assert(SC_SERVICE_OP_FILESYSTEM_STAT == UINT32_C(0x0603), "filesystem stat operation");
static_assert(SC_SERVICE_OP_FILESYSTEM_READ_DIR == UINT32_C(0x0604), "filesystem read dir operation");
static_assert(SC_SERVICE_OP_FILESYSTEM_MKDIR == UINT32_C(0x0605), "filesystem mkdir operation");
static_assert(SC_SERVICE_OP_FILESYSTEM_REMOVE == UINT32_C(0x0606), "filesystem remove operation");
static_assert(SC_SERVICE_OP_ABORT_CREATE == UINT32_C(0x0701), "abort create operation");
static_assert(SC_SERVICE_OP_ABORT_CANCEL == UINT32_C(0x0702), "abort cancel operation");
static_assert(SC_SERVICE_OP_STRUCTURED_CLONE == UINT32_C(0x0801), "structured clone operation");
static_assert(SC_SERVICE_OP_UTIL_INSPECT == UINT32_C(0x0901), "util inspect operation");
static_assert(SC_SERVICE_OP_FILESYSTEM_READ_FILE_SYNC == UINT32_C(0x0607), "filesystem sync read operation");
static_assert(SC_SERVICE_OP_FILESYSTEM_WRITE_FILE_SYNC == UINT32_C(0x0608), "filesystem sync write operation");

using query_fn = sc_status_t (SC_CALL *)(const sc_runtime_query_v1 *, const sc_runtime_plugin_v1 **);
static_assert(sizeof(query_fn) == sizeof(void *), "query function pointer");

int main() {
    query_fn query = &scardice_runtime_query_v1;
    return query(nullptr, nullptr);
}
