/* Current development ABI fixture; not a historical/versioned provider. */
#define scardice_runtime_query_v1 echo_query_base
#include "echo_runtime.c"
#undef scardice_runtime_query_v1

static uint64_t current_context;

static sc_status_t SC_CALL fixture_set_context(sc_runtime_t runtime, uint64_t token) {
    (void)runtime;
    current_context = token;
    return SC_OK;
}

static uint64_t SC_CALL fixture_get_context(sc_runtime_t runtime) {
    (void)runtime;
    return current_context;
}

SC_EXPORT sc_status_t SC_CALL scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query, const sc_runtime_plugin_v1 **out_plugin) {
    const sc_runtime_plugin_v1 *base = NULL;
    sc_status_t status = echo_query_base(query, &base);
    if (status != SC_OK) {
        return status;
    }
    static sc_runtime_context_extension_v1 context_table;
    static sc_runtime_extension_v1 extension;
    static sc_runtime_plugin_v1 plugin;
    context_table = (sc_runtime_context_extension_v1){
        sizeof(context_table), fixture_set_context, fixture_get_context};
    extension = (sc_runtime_extension_v1){
        sizeof(extension), SC_RUNTIME_EXTENSION_CONTEXT_V1,
        SC_RUNTIME_EXTENSION_CONTEXT_ABI_MAJOR,
        SC_RUNTIME_EXTENSION_CONTEXT_ABI_MINOR, &context_table};
    plugin = *base;
    plugin.struct_size = sizeof(plugin);
    plugin.descriptor.capabilities |= SC_CAP_CONTEXT_PROPAGATION;
    plugin.extension_count = 1;
    plugin.extensions = &extension;
#if FIXTURE_CASE == 1
    plugin.extension_count = 0;
    plugin.extensions = NULL;
#elif FIXTURE_CASE == 2
    extension.abi_major += 1;
#elif FIXTURE_CASE == 3
    context_table.struct_size = sizeof(uint32_t);
#elif FIXTURE_CASE == 4
    context_table.set_current_context = NULL;
#elif FIXTURE_CASE == 5
    context_table.get_current_context = NULL;
#elif FIXTURE_CASE == 6
    plugin.descriptor.capabilities &= ~SC_CAP_CONTEXT_PROPAGATION;
    plugin.extension_count = 0;
    plugin.extensions = NULL;
#endif
    *out_plugin = &plugin;
    return SC_OK;
}
