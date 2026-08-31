#include "scardice_runtime_v1.h"

#include <dlfcn.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <map>
#include <string>
#include <thread>

namespace {

struct HostState {
    const sc_runtime_api_v1 *api = nullptr;
    sc_runtime_t runtime = 0;
    int64_t answer = 40;
    bool answer_present = true;
    std::string error;
};

HostState *state(sc_host_ctx_t ctx) noexcept {
    return reinterpret_cast<HostState *>(static_cast<uintptr_t>(ctx));
}

sc_string_view view(const char *text) noexcept {
    return sc_string_view{text, static_cast<uint64_t>(std::strlen(text))};
}

sc_status_t SC_CALL host_get(sc_host_ctx_t ctx, sc_runtime_t runtime, sc_host_ref_t ref,
                             sc_string_view key, sc_value_t *out) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || host->api == nullptr || runtime != host->runtime || ref != 42 || out == nullptr) {
            return SC_EINVAL;
        }
        if (key.len == 6 && std::memcmp(key.data, "answer", 6) == 0 && host->answer_present) {
            return host->api->value_new_i64(runtime, host->answer, out);
        }
        if (key.len == 3 && std::memcmp(key.data, "add", 3) == 0) {
            return host->api->host_function_new(runtime, 7, out);
        }
        return host->api->value_new_undefined(runtime, out);
    } catch (...) {
        return SC_EINTERNAL;
    }
}

sc_status_t SC_CALL host_set(sc_host_ctx_t ctx, sc_runtime_t runtime, sc_host_ref_t ref,
                             sc_string_view key, sc_value_t value) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || host->api == nullptr || runtime != host->runtime || ref != 42) {
            return SC_EINVAL;
        }
        if (key.len != 6 || std::memcmp(key.data, "answer", 6) != 0) {
            return SC_EINVAL;
        }
        int64_t answer = 0;
        if (host->api->value_to_i64(runtime, value, &answer) != SC_OK) {
            return SC_EINVAL;
        }
        host->answer = answer;
        host->answer_present = true;
        return SC_OK;
    } catch (...) {
        return SC_EINTERNAL;
    }
}

sc_status_t SC_CALL host_has(sc_host_ctx_t ctx, sc_host_ref_t, sc_string_view key,
                             uint32_t *out) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || out == nullptr) {
            return SC_EINVAL;
        }
        *out = (key.len == 6 && std::memcmp(key.data, "answer", 6) == 0 && host->answer_present) ||
                       (key.len == 3 && std::memcmp(key.data, "add", 3) == 0)
                   ? 1U
                   : 0U;
        return SC_OK;
    } catch (...) {
        return SC_EINTERNAL;
    }
}

sc_status_t SC_CALL host_delete(sc_host_ctx_t ctx, sc_host_ref_t, sc_string_view key,
                                uint32_t *deleted) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || deleted == nullptr) {
            return SC_EINVAL;
        }
        if (key.len == 6 && std::memcmp(key.data, "answer", 6) == 0 && host->answer_present) {
            host->answer_present = false;
            *deleted = 1;
        } else {
            *deleted = 0;
        }
        return SC_OK;
    } catch (...) {
        return SC_EINTERNAL;
    }
}

sc_status_t SC_CALL host_keys_json(sc_host_ctx_t ctx, sc_host_ref_t, char *buffer,
                                   uint64_t capacity, uint64_t *required) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || required == nullptr) {
            return SC_EINVAL;
        }
        const std::string keys = host->answer_present ? "[\"add\",\"answer\"]" : "[\"add\"]";
        *required = static_cast<uint64_t>(keys.size());
        if (buffer == nullptr || capacity < *required) {
            return SC_EINVAL;
        }
        std::memcpy(buffer, keys.data(), keys.size());
        return SC_OK;
    } catch (...) {
        return SC_EINTERNAL;
    }
}

sc_status_t SC_CALL host_call(sc_host_ctx_t ctx, sc_runtime_t runtime, sc_host_func_t function,
                              sc_value_t this_value, const sc_value_t *argv, uint64_t argc,
                              sc_value_t *out) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || host->api == nullptr || runtime != host->runtime || out == nullptr) {
            return SC_EINVAL;
        }
        if (function == 8) {
            host->error = "host function refused call";
            return SC_EHOST;
        }
        if (function != 7 || argc != 1 || argv == nullptr) {
            return SC_EINVAL;
        }
        sc_host_ref_t this_ref = 0;
        uint32_t this_kind = 0;
        if (host->api->value_get_host_ref(runtime, this_value, &this_ref, &this_kind) != SC_OK ||
            this_ref != 42 || this_kind != 17) {
            host->error = "incorrect host this value";
            return SC_EHOST;
        }
        int64_t delta = 0;
        if (host->api->value_to_i64(runtime, argv[0], &delta) != SC_OK) {
            return SC_EINVAL;
        }
        return host->api->value_new_i64(runtime, host->answer + delta, out);
    } catch (...) {
        return SC_EINTERNAL;
    }
}

sc_status_t SC_CALL host_last_error(sc_host_ctx_t ctx, char *buffer, uint64_t capacity,
                                    uint64_t *required) noexcept {
    try {
        HostState *host = state(ctx);
        if (host == nullptr || required == nullptr) {
            return SC_EINVAL;
        }
        *required = static_cast<uint64_t>(host->error.size());
        if (buffer == nullptr || capacity < *required) {
            return SC_EINVAL;
        }
        std::memcpy(buffer, host->error.data(), host->error.size());
        return SC_OK;
    } catch (...) {
        return SC_EINTERNAL;
    }
}

bool expect(bool condition, const char *message) {
    if (!condition) {
        std::fprintf(stderr, "smoke failure: %s\n", message);
        return false;
    }
    return true;
}

bool expect_status(sc_status_t got, sc_status_t want, const char *message) {
    if (got != want) {
        std::fprintf(stderr, "smoke failure: %s (got %d, want %d)\n", message, got, want);
        return false;
    }
    return true;
}

bool read_i64(const sc_runtime_api_v1 *api, sc_runtime_t runtime, sc_value_t value, int64_t want,
              const char *message) {
    int64_t got = 0;
    return expect_status(api->value_to_i64(runtime, value, &got), SC_OK, message) && expect(got == want, message);
}

bool read_utf8(const sc_runtime_api_v1 *api, sc_runtime_t runtime, sc_value_t value,
               const char *want, const char *message) {
    uint64_t required = 0;
    if (!expect_status(api->value_to_utf8_copy(runtime, value, nullptr, 0, &required), SC_EINVAL, message)) {
        return false;
    }
    std::string got(static_cast<size_t>(required), '\0');
    if (!expect_status(api->value_to_utf8_copy(runtime, value, got.data(), required, &required), SC_OK, message)) {
        return false;
    }
    return expect(got == want, message);
}

} // namespace

int main(int argc, char **argv) {
    if (!expect(argc == 2, "provider path argument")) {
        return 1;
    }
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!expect(library != nullptr, "dlopen provider")) {
        return 1;
    }
    auto query = reinterpret_cast<decltype(&scardice_runtime_query_v1)>(dlsym(library, "scardice_runtime_query_v1"));
    if (!expect(query != nullptr, "query symbol")) {
        return 1;
    }

    sc_runtime_query_v1 request{sizeof(request), SC_RUNTIME_ABI_MAJOR, SC_RUNTIME_ABI_MINOR,
                                SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR};
    const sc_runtime_plugin_v1 *plugin = nullptr;
    if (!expect_status(query(&request, &plugin), SC_OK, "query succeeds") ||
        !expect(plugin != nullptr, "query plugin") ||
        !expect(plugin->struct_size >= sizeof(sc_runtime_plugin_v1), "plugin struct size") ||
        !expect(plugin->descriptor.struct_size >= sizeof(sc_runtime_descriptor_v1), "descriptor struct size") ||
        !expect(plugin->descriptor.abi_major == SC_RUNTIME_ABI_MAJOR &&
                    plugin->descriptor.abi_minor <= SC_RUNTIME_ABI_MINOR &&
                    plugin->descriptor.host_abi_major == SC_HOST_ABI_MAJOR &&
                    plugin->descriptor.host_abi_minor <= SC_HOST_ABI_MINOR,
                "descriptor ABI versions") ||
        !expect(std::strcmp(plugin->descriptor.id, "quickjs") == 0 &&
                    std::strcmp(plugin->descriptor.version, "0.7.7") == 0 &&
                    plugin->descriptor.capabilities ==
                        (SC_CAP_SCRIPT | SC_CAP_COMMONJS | SC_CAP_ESM | SC_CAP_PROMISE | SC_CAP_TIMERS |
                         SC_CAP_HOST_OBJECT | SC_CAP_HOST_FUNCTION | SC_CAP_SOURCE_LOCATION),
                "descriptor identity and capabilities")) {
        return 1;
    }

    const sc_runtime_api_v1 *api = &plugin->api;
    HostState host_state;
    sc_host_api_v1 host{sizeof(host), SC_HOST_ABI_MAJOR, SC_HOST_ABI_MINOR, host_get, host_set, host_has,
                        host_delete, host_keys_json, host_call, host_last_error};
    sc_runtime_create_info_v1 info{sizeof(info), sc_string_view{nullptr, 0}};
    sc_runtime_t runtime = 0;
    const sc_host_ctx_t host_ctx = static_cast<sc_host_ctx_t>(reinterpret_cast<uintptr_t>(&host_state));
    if (!expect_status(api->create(&host, host_ctx, &info, &runtime), SC_OK, "create succeeds")) {
        return 1;
    }
    host_state.api = api;
    host_state.runtime = runtime;
    if (!expect_status(api->start(runtime), SC_OK, "start succeeds")) {
        api->destroy(runtime);
        return 1;
    }

    sc_value_t value = 0;
    if (!expect_status(api->eval(runtime, view("eval.js"), view("1 + 2"), &value), SC_OK, "eval succeeds") ||
        !read_i64(api, runtime, value, 3, "eval result") ||
        !expect_status(api->value_retain(runtime, value), SC_OK, "value retain") ||
        !expect_status(api->value_retain(runtime, value), SC_OK, "second value retain") ) {
        return 1;
    }
    api->value_release(runtime, value);
    api->value_release(runtime, value);
    api->value_release(runtime, value);

    sc_value_t object = 0;
    sc_value_t answer = 0;
    sc_value_t got = 0;
    uint32_t has = 0;
    if (!expect_status(api->object_new(runtime, &object), SC_OK, "object new") ||
        !expect_status(api->value_new_i64(runtime, 41, &answer), SC_OK, "integer new") ||
        !expect_status(api->object_set(runtime, object, view("answer"), answer), SC_OK, "object set") ||
        !expect_status(api->object_has(runtime, object, view("answer"), &has), SC_OK, "object has") ||
        !expect(has == 1, "object property exists") ||
        !expect_status(api->object_get(runtime, object, view("answer"), &got), SC_OK, "object get") ||
        !read_i64(api, runtime, got, 41, "object property value")) {
        return 1;
    }
    api->value_release(runtime, got);
    api->value_release(runtime, answer);
    api->value_release(runtime, object);

    sc_value_t string = 0;
    if (!expect_status(api->value_new_string(runtime, view("hello"), &string), SC_OK, "string new") ||
        !read_utf8(api, runtime, string, "hello", "string conversion")) {
        return 1;
    }
    api->value_release(runtime, string);

    sc_value_t host_object = 0;
    sc_host_ref_t host_ref = 0;
    uint32_t host_kind = 0;
    if (!expect_status(api->host_object_new(runtime, 42, 17, &host_object), SC_OK, "host object new") ||
        !expect_status(api->value_get_host_ref(runtime, host_object, &host_ref, &host_kind), SC_OK, "host ref") ||
        !expect(host_ref == 42 && host_kind == 17, "host ref values") ||
        !expect_status(api->global_set(runtime, view("host"), host_object), SC_OK, "global host set")) {
        return 1;
    }
    sc_value_t host_result = 0;
    if (!expect_status(api->eval(runtime, view("host-keys.js"), view("Object.keys(host).sort().join(',')"),
                                 &host_result),
                       SC_OK,
                       "host keys") ||
        !read_utf8(api, runtime, host_result, "add,answer", "host property names")) {
        return 1;
    }
    api->value_release(runtime, host_result);
    sc_status_t host_status = api->eval(runtime, view("host.js"), view("host.answer = 41; host.add(1)"), &host_result);
    if (!expect_status(host_status, SC_OK, "host callbacks") ||
        !read_i64(api, runtime, host_result, 42, "host function result") ||
        !expect(host_state.answer == 41, "host setter")) {
        return 1;
    }
    api->value_release(runtime, host_result);
    if (!expect_status(api->eval(runtime, view("delete.js"), view("delete host.answer"), &host_result), SC_OK,
                       "host delete") ||
        !expect_status(api->object_has(runtime, host_object, view("answer"), &has), SC_OK, "host has after delete") ||
        !expect(has == 0, "host property deleted")) {
        return 1;
    }
    api->value_release(runtime, host_result);
    api->value_release(runtime, host_object);

    if (!expect_status(api->eval(runtime, view("error.js"), view("throw new Error('boom')"), &value),
                       SC_EEXCEPTION,
                       "script exception")) {
        return 1;
    }
    uint64_t required = 0;
    if (!expect_status(api->last_error_copy(runtime, nullptr, 0, &required), SC_EINVAL, "last error size") || required == 0) {
        return 1;
    }
    std::string error(static_cast<size_t>(required), '\0');
    if (!expect_status(api->last_error_copy(runtime, error.data(), required, &required), SC_OK, "last error copy") ||
        !expect(error.find("boom") != std::string::npos, "last error text")) {
        return 1;
    }

    if (!expect_status(api->eval(runtime, view("promise.js"), view("Promise.resolve(4)"), &value), SC_OK,
                       "promise eval") ||
        !expect_status(api->value_type(runtime, value, &host_kind), SC_OK, "promise type")) {
        return 1;
    }
    api->value_release(runtime, value);

    sc_value_t event_value = 0;
    if (!expect_status(api->eval(runtime, view("events.js"),
                                 view("globalThis.eventOrder=[];"
                                      "globalThis.timerA=setTimeout(()=>eventOrder.push('late'),20);"
                                      "globalThis.timerB=setTimeout(()=>eventOrder.push('early'),5);"
                                      "globalThis.cancelledHandle=setTimeout(()=>eventOrder.push('cancelled'),0);"
                                      "clearTimeout(cancelledHandle);"
                                      "if (!(timerA > 0 && timerB > 0 && timerA !== timerB)) throw new Error('unstable timer handles');"
                                      "Promise.resolve().then(()=>eventOrder.push('promise'));"
                                      "queueMicrotask(()=>eventOrder.push('microtask'));"
                                      "setTimeout(()=>eventOrder.push('zero'),0);"
                                      "0"),
                                 &event_value),
                       SC_OK,
                       "event loop ordering") ||
        !read_i64(api, runtime, event_value, 0, "event setup result")) {
        return 1;
    }
    api->value_release(runtime, event_value);
    if (!expect_status(api->eval(runtime, view("events-observe.js"), view("eventOrder.join(',')"), &event_value),
                       SC_OK,
                       "microtask ordering") ||
        !read_utf8(api, runtime, event_value, "promise,microtask,zero", "promise/microtask/timer order")) {
        return 1;
    }
    api->value_release(runtime, event_value);
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    if (!expect_status(api->eval(runtime, view("events-due-pump.js"), view("0"), &event_value),
                       SC_OK,
                       "due timer pumping") ||
        !read_i64(api, runtime, event_value, 0, "due timer pump result")) {
        return 1;
    }
    api->value_release(runtime, event_value);
    if (!expect_status(api->eval(runtime, view("events-due-observe.js"), view("eventOrder.join(',')"), &event_value),
                       SC_OK,
                       "deterministic timer order") ||
        !read_utf8(api, runtime, event_value, "promise,microtask,zero,early,late", "deterministic timer order")) {
        return 1;
    }
    api->value_release(runtime, event_value);

    if (!expect_status(api->eval(runtime, view("timer-error.js"),
                                 view("setTimeout(()=>{ throw new Error('timer-boom') },0)"), &event_value),
                       SC_EEXCEPTION,
                       "timer exception")) {
        return 1;
    }
    if (!expect_status(api->last_error_copy(runtime, nullptr, 0, &required), SC_EINVAL, "timer error size") ||
        required == 0) {
        return 1;
    }
    error.assign(static_cast<size_t>(required), '\0');
    if (!expect_status(api->last_error_copy(runtime, error.data(), required, &required), SC_OK, "timer error text") ||
        !expect(error.find("timer-boom") != std::string::npos, "timer error detail")) {
        return 1;
    }

    if (!expect_status(api->eval(runtime, view("microtask-error.js"),
                                 view("queueMicrotask(()=>{ throw new Error('microtask-boom') })"), &event_value),
                       SC_EEXCEPTION,
                       "microtask exception")) {
        return 1;
    }
    if (!expect_status(api->last_error_copy(runtime, nullptr, 0, &required), SC_EINVAL, "microtask error size") ||
        required == 0) {
        return 1;
    }
    error.assign(static_cast<size_t>(required), '\0');
    if (!expect_status(api->last_error_copy(runtime, error.data(), required, &required), SC_OK, "microtask error text") ||
        !expect(error.find("microtask-boom") != std::string::npos, "microtask error detail")) {
        return 1;
    }


    const struct {
        uint32_t kind;
        const char *name;
        const char *source;
    } entries[] = {{0, "script.js", "globalThis.scriptValue = 7"},
                   {1, "module.js", "module.exports = { answer: 8 }"},
                   {2, "entry.js", "globalThis.moduleValue = 9; export const answer = 9"},
                   {3, "extension.js", "globalThis.extensionValue = 10"}};
    for (const auto &entry : entries) {
        if (!expect_status(api->load_entry(runtime, entry.kind, view(entry.name), view(entry.source), &value), SC_OK,
                           "load entry")) {
            return 1;
        }
        api->value_release(runtime, value);
    }

    sc_value_t error_function = 0;
    if (!expect_status(api->host_function_new(runtime, 8, &error_function), SC_OK, "error host function new") ||
        !expect_status(api->function_call(runtime, error_function, 0, nullptr, 0, &value), SC_EHOST,
                       "host callback error status")) {
        return 1;
    }
    api->value_release(runtime, error_function);

    sc_status_t thread_status = SC_OK;
    std::thread wrong_thread([&]() { thread_status = api->value_new_i64(runtime, 1, &value); });
    wrong_thread.join();
    if (!expect_status(thread_status, SC_ESTATE, "thread affinity")) {
        return 1;
    }

    if (!expect_status(api->eval(runtime, view("bounded-loop.js"),
                                 view("setTimeout(()=>host.answer=999,1);"
                                      "globalThis.remaining=2048;"
                                      "queueMicrotask(function tick(){"
                                      "  if (--remaining > 0) queueMicrotask(tick);"
                                      "});"),
                                 &event_value),
                       SC_ETIMEOUT,
                       "microtask convergence threshold")) {
        return 1;
    }
    if (!expect_status(api->last_error_copy(runtime, nullptr, 0, &required), SC_EINVAL, "timeout error size") ||
        required == 0) {
        return 1;
    }
    error.assign(static_cast<size_t>(required), '\0');
    if (!expect_status(api->last_error_copy(runtime, error.data(), required, &required), SC_OK, "timeout error text") ||
        !expect(error.find("converge") != std::string::npos, "timeout error detail")) {
        return 1;
    }
    if (!expect_status(api->stop(runtime), SC_OK, "stop aborts pending jobs") ||
        !expect(!host_state.answer_present || host_state.answer != 999, "timer callback after stop")) {
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (!expect(!host_state.answer_present || host_state.answer != 999, "timer callback after shutdown")) {
        return 1;
    }
    if (!expect_status(api->eval(runtime, view("closed.js"), view("1"), &value), SC_ESTATE,
                       "calls rejected after stop")) {
        return 1;
    }
    api->destroy(runtime);
    return 0;
}
