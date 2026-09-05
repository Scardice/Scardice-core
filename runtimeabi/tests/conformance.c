#include "scardice_runtime_v1.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

_Static_assert(SC_ENTRY_SCRIPT == 0, "script entry kind changed");
_Static_assert(SC_ENTRY_COMMONJS == 1, "CommonJS entry kind changed");
_Static_assert(SC_ENTRY_ESMODULE == 2, "ES module entry kind changed");
_Static_assert(SC_ENTRY_EXTENSION == 3, "extension entry kind changed");
_Static_assert(SC_VALUE_TYPE_UNDEFINED == 0, "undefined value type changed");
_Static_assert(SC_VALUE_TYPE_NULL == 1, "null value type changed");
_Static_assert(SC_VALUE_TYPE_FUNCTION == 10, "function value type changed");

static sc_status_t SC_CALL set_context(sc_runtime_t runtime, uint64_t token) {
    (void)runtime;
    (void)token;
    return SC_OK;
}

static uint64_t SC_CALL get_context(sc_runtime_t runtime) {
    (void)runtime;
    return 42;
}

typedef struct legacy_plugin_fixture {
    uint32_t struct_size;
    sc_runtime_descriptor_v1 descriptor;
    sc_runtime_api_v1 api;
} legacy_plugin_fixture;

_Static_assert(offsetof(sc_runtime_plugin_v1, extension_count) ==
                   sizeof(legacy_plugin_fixture),
               "extension table must remain an optional append-only tail");

int main(void) {
    static const sc_runtime_context_extension_v1 context_table = {
        sizeof(context_table),
        set_context,
        get_context,
    };
    static const sc_runtime_extension_v1 extensions[] = {
        {sizeof(extensions[0]), SC_RUNTIME_EXTENSION_CONTEXT_V1, 1, 0, &context_table},
    };
    sc_runtime_plugin_v1 plugin = {0};
    plugin.struct_size = sizeof(plugin);
    plugin.extensions = extensions;
    plugin.extension_count = sizeof(extensions) / sizeof(extensions[0]);

    assert(plugin.extension_count == 1);
    assert(plugin.extensions[0].table == &context_table);
    assert(strcmp(plugin.extensions[0].name, SC_RUNTIME_EXTENSION_CONTEXT_V1) == 0);
    assert(offsetof(sc_runtime_plugin_v1, extensions) > offsetof(sc_runtime_plugin_v1, api));
    assert(context_table.get_current_context(0) == 42);
    assert(context_table.set_current_context(0, 42) == SC_OK);
    return 0;
}
