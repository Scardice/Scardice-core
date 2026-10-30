#include <stddef.h>
#include <stdint.h>

#include "../include/scardice_runtime_v1.h"

_Static_assert(SC_RUNTIME_ABI_MAJOR == 1, "runtime ABI major changed");
_Static_assert(SC_RUNTIME_ABI_MINOR == 0,
               "runtime ABI minor is reserved and must remain zero");
_Static_assert(SC_HOST_ABI_MAJOR == 1, "host ABI major changed");
_Static_assert(SC_HOST_ABI_MINOR == 1,
               "host ABI minor must include HostRef proxy lifecycle");

_Static_assert(sizeof(sc_string_view) == 16, "string view layout changed");
_Static_assert(sizeof(sc_runtime_descriptor_v1) == 64, "descriptor layout changed");
_Static_assert(sizeof(sc_runtime_create_info_v1) == 24, "create info layout changed");
_Static_assert(sizeof(sc_runtime_query_v1) == 20, "query layout changed");

_Static_assert(offsetof(sc_runtime_api_v1, create) == 8, "runtime API prefix changed");
_Static_assert(offsetof(sc_runtime_api_v1, last_error_copy) ==
                   offsetof(sc_runtime_api_v1, create) + 31 * sizeof(void *),
               "runtime API v1 base tail changed");
_Static_assert(offsetof(sc_runtime_api_v1, service_event) ==
                   offsetof(sc_runtime_api_v1, last_error_copy) + sizeof(void *),
               "runtime API optional tail moved");
_Static_assert(offsetof(sc_host_api_v1, host_get) == 16, "host API prefix changed");
_Static_assert(offsetof(sc_host_api_v1, last_error_copy) ==
                   offsetof(sc_host_api_v1, host_get) + 6 * sizeof(void *),
               "host API v1 base tail changed");
_Static_assert(offsetof(sc_host_api_v1, service_call) ==
                   offsetof(sc_host_api_v1, last_error_copy) + sizeof(void *),
               "host API optional tail moved");
_Static_assert(offsetof(sc_runtime_plugin_v1, descriptor) == 8,
               "plugin descriptor prefix changed");
_Static_assert(offsetof(sc_runtime_plugin_v1, api) == 72,
               "plugin API prefix changed");

int main(void) { return 0; }
