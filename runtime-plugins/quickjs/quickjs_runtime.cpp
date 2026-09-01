#include "quickjs.h"
#include "scardice_runtime_v1.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

constexpr uint32_t kTypeUndefined = 0;
constexpr uint32_t kTypeNull = 1;
constexpr uint32_t kTypeBool = 2;
constexpr uint32_t kTypeI64 = 3;
constexpr uint32_t kTypeU64 = 4;
constexpr uint32_t kTypeF64 = 5;
constexpr uint32_t kTypeString = 6;
constexpr uint32_t kTypeObject = 7;
constexpr uint32_t kTypeHostObject = 8;
constexpr uint32_t kTypeHostFunction = 9;
constexpr uint32_t kTypeFunction = 10;

constexpr uint32_t kEntryScript = 0;
constexpr uint32_t kEntryCommonJS = 1;
constexpr uint32_t kEntryESModule = 2;
constexpr uint32_t kEntryExtension = 3;
constexpr size_t kMaxPendingJobs = 1024;

struct Runtime;
struct Value;
struct HostProxy;

static JSClassID g_host_class_id = JS_INVALID_CLASS_ID;
static std::mutex g_host_class_mutex;

static JSValue host_get_property(JSContext *, JSValueConst, JSAtom, JSValueConst);
static int host_set_property(JSContext *, JSValueConst, JSAtom, JSValueConst, JSValueConst, int);
static int host_has_property(JSContext *, JSValueConst, JSAtom);
static int host_delete_property(JSContext *, JSValueConst, JSAtom);
static int host_get_own_property(JSContext *, JSPropertyDescriptor *, JSValueConst, JSAtom);
static int host_get_own_property_names(JSContext *, JSPropertyEnum **, uint32_t *, JSValueConst);
static int host_define_own_property(JSContext *, JSValueConst, JSAtom, JSValueConst, JSValueConst, JSValueConst, int);
static void host_finalizer(JSRuntime *, JSValueConst) noexcept;
static JSValue host_function_call(JSContext *, JSValueConst, int, JSValueConst *, int, JSValueConst *) noexcept;
static char *module_normalize(JSContext *, const char *, const char *, void *) noexcept;
static JSModuleDef *module_loader(JSContext *, const char *, void *) noexcept;
static JSValue require_call(JSContext *, JSValueConst, int, JSValueConst *) noexcept;
static int runtime_interrupt(JSRuntime *, void *) noexcept;

static JSValue timer_set_timeout(JSContext *, JSValueConst, int, JSValueConst *) noexcept;
static JSValue timer_clear_timeout(JSContext *, JSValueConst, int, JSValueConst *) noexcept;
static JSValue queue_microtask_call(JSContext *, JSValueConst, int, JSValueConst *) noexcept;
static JSValue microtask_job(JSContext *, int, JSValueConst *) noexcept;
static JSClassExoticMethods g_host_exotic = {
    host_get_own_property,
    host_get_own_property_names,
    host_delete_property,
    host_define_own_property,
    host_has_property,
    host_get_property,
    host_set_property,
};

static const JSClassDef g_host_class = {
    "ScardiceHostObject",
    host_finalizer,
    nullptr,
    nullptr,
    &g_host_exotic,
};

struct HostProxy {
    Runtime *runtime = nullptr;
    sc_host_ref_t ref = 0;
    uint32_t kind = 0;
};

struct Value {
    Runtime *runtime = nullptr;
    JSValue value = JS_UNDEFINED;
    uint32_t type = kTypeUndefined;
    sc_host_ref_t host_ref = 0;
    uint32_t host_kind = 0;
    sc_host_func_t host_function = 0;
    uint64_t refs = 1;
    bool alive = true;
};

static bool view_valid(sc_string_view view) {
    return view.len == 0 || view.data != nullptr;
}
static bool bigint_fits_i64(const char *text, size_t length) {
    if (text == nullptr || length == 0) {
        return false;
    }
    size_t offset = text[0] == '-' ? 1 : 0;
    if (offset == length) {
        return true;
    }
    while (offset + 1 < length && text[offset] == '0') {
        ++offset;
    }
    constexpr char kMax[] = "9223372036854775807";
    size_t digits = length - offset;
    if (digits != sizeof(kMax) - 1) {
        return digits < sizeof(kMax) - 1;
    }
    return std::memcmp(text + offset, kMax, sizeof(kMax) - 1) <= 0;
}

static std::string view_string(sc_string_view view) {
    if (!view_valid(view) || view.len > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        throw std::bad_alloc();
    }
    if (view.len == 0) {
        return {};
    }
    return std::string(view.data, static_cast<size_t>(view.len));
}


static std::string join_module_name(const char *base_name, const char *name) {
    std::string requested = name == nullptr ? std::string() : std::string(name);
    if (requested.empty() || requested[0] != '.') {
        return requested;
    }
    std::string base = base_name == nullptr ? std::string() : std::string(base_name);
    size_t slash = base.rfind('/');
    std::string result = slash == std::string::npos ? std::string() : base.substr(0, slash + 1);
    result += requested;
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= result.size()) {
        size_t end = result.find('/', start);
        std::string part = result.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (part.empty() || part == ".") {
            // Nothing.
        } else if (part == "..") {
            if (!parts.empty()) {
                parts.pop_back();
            }
        } else {
            parts.push_back(std::move(part));
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    result.clear();
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            result.push_back('/');
        }
        result += parts[i];
    }
    return result;
}
constexpr size_t kMaxOptionsBytes = 64 * 1024;
constexpr uint64_t kMaxMemoryBytes = UINT64_C(1) << 40;
constexpr uint64_t kMaxStackBytes = UINT64_C(1) << 30;
constexpr uint64_t kMaxTimeoutMillis = UINT64_C(24) * 60 * 60 * 1000;

struct ParsedOptions {
    uint64_t memory_limit = 0;
    uint64_t gc_threshold = 0;
    uint64_t stack_size = 0;
    uint64_t timeout_millis = 0;
};

class OptionsParser {
  public:
    OptionsParser(const char *data, size_t length) : begin_(data), current_(data), end_(data + length) {}

    bool parse(ParsedOptions *options, std::string *error) {
        skip_space();
        if (current_ == end_) {
            return true;
        }
        if (!parse_top_object(options, error)) {
            return false;
        }
        skip_space();
        if (current_ != end_) {
            return fail(error, "trailing runtime options");
        }
        return true;
    }

  private:
    const char *begin_;
    const char *current_;
    const char *end_;

    void skip_space() {
        while (current_ != end_ && (*current_ == ' ' || *current_ == '\n' || *current_ == '\r' ||
                                    *current_ == '\t')) {
            ++current_;
        }
    }

    bool fail(std::string *error, const char *message) {
        if (error != nullptr) {
            *error = message;
        }
        return false;
    }

    bool expect(char value, std::string *error) {
        skip_space();
        if (current_ == end_ || *current_ != value) {
            return fail(error, "malformed runtime options");
        }
        ++current_;
        return true;
    }

    bool parse_key(std::string *key, std::string *error) {
        skip_space();
        if (current_ == end_ || *current_ != '"') {
            return fail(error, "runtime option key must be a string");
        }
        ++current_;
        key->clear();
        while (current_ != end_ && *current_ != '"') {
            if (*current_ == '\\') {
                return fail(error, "escaped runtime option keys are not supported");
            }
            if (static_cast<unsigned char>(*current_) < 0x20) {
                return fail(error, "control character in runtime option key");
            }
            key->push_back(*current_++);
        }
        if (current_ == end_) {
            return fail(error, "unterminated runtime option key");
        }
        ++current_;
        return true;
    }

    bool parse_uint(uint64_t *value, std::string *error) {
        skip_space();
        if (current_ == end_ || *current_ < '0' || *current_ > '9') {
            return fail(error, "runtime option must be an unsigned integer");
        }
        if (*current_ == '0' && current_ + 1 != end_ && current_[1] >= '0' && current_[1] <= '9') {
            return fail(error, "leading zero in runtime option");
        }
        uint64_t result = 0;
        while (current_ != end_ && *current_ >= '0' && *current_ <= '9') {
            const uint64_t digit = static_cast<uint64_t>(*current_ - '0');
            if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
                return fail(error, "runtime option integer overflow");
            }
            result = result * 10 + digit;
            ++current_;
        }
        *value = result;
        return true;
    }

    bool parse_runtime_field(const std::string &key, ParsedOptions *options,
                             std::unordered_set<std::string> *seen, std::string *error) {
        if (seen->find(key) != seen->end()) {
            return fail(error, "duplicate runtime option");
        }
        seen->insert(key);
        uint64_t value = 0;
        if (!parse_uint(&value, error)) {
            return false;
        }
        if (key == "memoryLimitBytes") {
            options->memory_limit = value;
        } else if (key == "gcThresholdBytes") {
            options->gc_threshold = value;
        } else if (key == "maxStackSizeBytes") {
            options->stack_size = value;
        } else if (key == "executionTimeoutMillis") {
            options->timeout_millis = value;
        } else {
            return fail(error, "unknown runtime option");
        }
        return true;
    }

    bool parse_runtime_object(ParsedOptions *options, std::string *error) {
        if (!expect('{', error)) {
            return false;
        }
        std::unordered_set<std::string> seen;
        skip_space();
        if (current_ != end_ && *current_ == '}') {
            ++current_;
            return true;
        }
        for (;;) {
            std::string key;
            if (!parse_key(&key, error) || !expect(':', error) ||
                !parse_runtime_field(key, options, &seen, error)) {
                return false;
            }
            skip_space();
            if (current_ != end_ && *current_ == '}') {
                ++current_;
                return true;
            }
            if (!expect(',', error)) {
                return false;
            }
        }
    }

    bool parse_policy_field(const std::string &service, const std::string &key,
                            std::unordered_set<std::string> *seen, std::string *error) {
        if (seen->find(key) != seen->end()) {
            return fail(error, "duplicate service option");
        }
        const bool allowed =
            (service == "fetch" && (key == "maxConcurrent" || key == "maxResponseBytes")) ||
            (service == "websocket" && (key == "maxConnections" || key == "maxMessageBytes")) ||
            (service == "filesystem" && (key == "maxReadBytes" || key == "maxWriteBytes")) ||
            (service == "pbkdf2" && (key == "maxIterations" || key == "maxOutputBytes"));
        if (!allowed) {
            return fail(error, "unknown service option");
        }
        seen->insert(key);
        uint64_t value = 0;
        if (!parse_uint(&value, error)) {
            return false;
        }
        if (value > kMaxMemoryBytes) {
            return fail(error, "service option is out of range");
        }
        return true;
    }

    bool parse_policy_object(const std::string &service, std::string *error) {
        if (!expect('{', error)) {
            return false;
        }
        std::unordered_set<std::string> seen;
        skip_space();
        if (current_ != end_ && *current_ == '}') {
            ++current_;
            return true;
        }
        for (;;) {
            std::string key;
            if (!parse_key(&key, error) || !expect(':', error) ||
                !parse_policy_field(service, key, &seen, error)) {
                return false;
            }
            skip_space();
            if (current_ != end_ && *current_ == '}') {
                ++current_;
                return true;
            }
            if (!expect(',', error)) {
                return false;
            }
        }
    }

    bool parse_services_object(std::string *error) {
        if (!expect('{', error)) {
            return false;
        }
        std::unordered_set<std::string> seen;
        skip_space();
        if (current_ != end_ && *current_ == '}') {
            ++current_;
            return true;
        }
        for (;;) {
            std::string key;
            if (!parse_key(&key, error)) {
                return false;
            }
            if (seen.find(key) != seen.end()) {
                return fail(error, "duplicate service");
            }
            seen.insert(key);
            if (key != "fetch" && key != "websocket" && key != "filesystem" && key != "pbkdf2") {
                return fail(error, "unknown service option");
            }
            if (!expect(':', error) || !parse_policy_object(key, error)) {
                return false;
            }
            skip_space();
            if (current_ != end_ && *current_ == '}') {
                ++current_;
                return true;
            }
            if (!expect(',', error)) {
                return false;
            }
        }
    }

    bool parse_top_object(ParsedOptions *options, std::string *error) {
        if (!expect('{', error)) {
            return false;
        }
        std::unordered_set<std::string> seen;
        bool has_version = false;
        skip_space();
        if (current_ != end_ && *current_ == '}') {
            ++current_;
            return true;
        }
        for (;;) {
            std::string key;
            if (!parse_key(&key, error)) {
                return false;
            }
            if (seen.find(key) != seen.end()) {
                return fail(error, "duplicate top-level runtime option");
            }
            seen.insert(key);
            if (key == "version") {
                uint64_t version = 0;
                if (!expect(':', error) || !parse_uint(&version, error)) {
                    return false;
                }
                if (version != 1) {
                    return fail(error, "unsupported runtime options version");
                }
                has_version = true;
            } else if (key == "runtime") {
                if (!expect(':', error) || !parse_runtime_object(options, error)) {
                    return false;
                }
            } else if (key == "services") {
                if (!expect(':', error) || !parse_services_object(error)) {
                    return false;
                }
            } else {
                return fail(error, "unknown top-level runtime option");
            }
            skip_space();
            if (current_ != end_ && *current_ == '}') {
                ++current_;
                if (!has_version) {
                    return fail(error, "runtime options version is required");
                }
                if (options->memory_limit > kMaxMemoryBytes || options->gc_threshold > kMaxMemoryBytes ||
                    options->stack_size > kMaxStackBytes || options->timeout_millis > kMaxTimeoutMillis) {
                    return fail(error, "runtime option is out of range");
                }
                if (options->memory_limit != 0 && options->gc_threshold > options->memory_limit) {
                    return fail(error, "GC threshold exceeds memory limit");
                }
                return true;
            }
            if (!expect(',', error)) {
                return false;
            }
        }
    }
};

struct Runtime {
    struct Timer {
        uint64_t id = 0;
        std::chrono::steady_clock::time_point deadline;
        JSValue callback = JS_UNDEFINED;
    };

    JSRuntime *js_runtime = nullptr;
    JSContext *context = nullptr;
    const sc_host_api_v1 *host = nullptr;
    sc_host_ctx_t host_ctx = 0;
    std::thread::id owner;
    bool started = false;
    bool stopped = false;
    bool stopping = false;
    bool destroying = false;
    bool pumping_events = false;
    std::string last_error;
    sc_status_t pending_host_status = SC_OK;
    std::unordered_set<Value *> values;
    std::map<std::string, std::string> modules;
    // CommonJS modules are evaluated once per runtime, matching the legacy
    // adapter's module cache contract.
    std::map<std::string, JSValue> commonjs_cache;
    std::vector<Timer> timers;
    uint64_t next_timer_id = 1;
    ParsedOptions options;
    bool deadline_active = false;
    std::chrono::steady_clock::time_point deadline;

    ~Runtime() { destroy(); }

    void clear_error() {
        last_error.clear();
        pending_host_status = SC_OK;
    }
    void begin_execution() {
        if (options.timeout_millis == 0) {
            deadline_active = false;
            return;
        }
        deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.timeout_millis);
        deadline_active = true;
    }

    void end_execution() { deadline_active = false; }

    sc_status_t fail(sc_status_t status, const char *message) noexcept {
        try {
            last_error = message == nullptr ? std::string() : std::string(message);
        } catch (...) {
            try {
                last_error = "native QuickJS provider error";
            } catch (...) {
            }
        }
        return status;
    }

    sc_status_t fail_string(sc_status_t status, const std::string &message) noexcept {
        try {
            last_error = message;
        } catch (...) {
            try {
                last_error = "native QuickJS provider error";
            } catch (...) {
            }
        }
        return status;
    }

    bool thread_ok() const { return owner == std::this_thread::get_id(); }

    sc_status_t check_started() {
        if (context == nullptr || js_runtime == nullptr) {
            return fail(SC_ECLOSED, "QuickJS runtime is closed");
        }
        if (!thread_ok()) {
            return fail(SC_ESTATE, "QuickJS runtime called from the wrong thread");
        }
        if (!started || stopped) {
            return fail(SC_ESTATE, "QuickJS runtime is not started");
        }
        return SC_OK;
    }

    void capture_exception() noexcept {
        try {
            if (context == nullptr) {
                last_error = "JavaScript exception";
                return;
            }
            JSValue exception = JS_GetException(context);
            size_t length = 0;
            const char *text = JS_ToCStringLen(context, &length, exception);
            if (text != nullptr) {
                try {
                    last_error.assign(text, length);
                } catch (...) {
                    last_error = "JavaScript exception";
                }
                JS_FreeCString(context, text);
            } else {
                last_error = "JavaScript exception";
            }
            JS_FreeValue(context, exception);
        } catch (...) {
            try {
                last_error = "JavaScript exception";
            } catch (...) {
            }
        }
    }

    uint32_t detect_type(JSValueConst raw) {
        if (JS_IsUndefined(raw)) {
            return kTypeUndefined;
        }
        if (JS_IsNull(raw)) {
            return kTypeNull;
        }
        if (JS_IsBool(raw)) {
            return kTypeBool;
        }
        if (JS_IsBigInt(raw)) {
            size_t length = 0;
            const char *text = JS_ToCStringLen(context, &length, raw);
            uint32_t type = bigint_fits_i64(text, length) ? kTypeI64 : kTypeU64;
            if (text != nullptr) {
                JS_FreeCString(context, text);
            }
            return type;
        }
        if (JS_IsString(raw)) {
            return kTypeString;
        }
        if (JS_IsObject(raw)) {
            if (g_host_class_id != JS_INVALID_CLASS_ID && JS_GetOpaque(raw, g_host_class_id) != nullptr) {
                return kTypeHostObject;
            }
            return JS_IsFunction(context, raw) ? kTypeFunction : kTypeObject;
        }
        if (JS_VALUE_GET_NORM_TAG(raw) == JS_TAG_INT) {
            return kTypeI64;
        }
        if (JS_VALUE_GET_NORM_TAG(raw) == JS_TAG_FLOAT64) {
            return kTypeF64;
        }
        return kTypeObject;
    }

    Value *add(JSValue raw, uint32_t forced_type = 0) {
        if (JS_IsException(raw)) {
            capture_exception();
            return nullptr;
        }
        Value *value = nullptr;
        try {
            const uint32_t type = forced_type == 0 ? detect_type(raw) : forced_type;
            value = new Value{this, raw, type};
            if (type == kTypeHostObject && g_host_class_id != JS_INVALID_CLASS_ID) {
                HostProxy *proxy = static_cast<HostProxy *>(JS_GetOpaque(raw, g_host_class_id));
                if (proxy != nullptr) {
                    value->host_ref = proxy->ref;
                    value->host_kind = proxy->kind;
                }
            }
            values.insert(value);
        } catch (...) {
            if (value != nullptr) {
                delete value;
            } else {
                JS_FreeValue(context, raw);
            }
            throw;
        }
        return value;
    }

    Value *lookup(sc_value_t handle) const noexcept {
        if (handle == 0) {
            return nullptr;
        }
        Value *value = reinterpret_cast<Value *>(static_cast<uintptr_t>(handle));
        if (value == nullptr || value->runtime != this || !value->alive || value->refs == 0) {
            return nullptr;
        }
        return value;
    }

    sc_status_t release(sc_value_t handle) noexcept {
        if (!thread_ok()) {
            return fail(SC_ESTATE, "QuickJS value released from the wrong thread");
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        if (--value->refs != 0) {
            return SC_OK;
        }
        value->alive = false;
        values.erase(value);
        JS_FreeValue(context, value->value);
        delete value;
        return SC_OK;
    }

    sc_status_t retain(sc_value_t handle) {
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        if (value->refs == std::numeric_limits<uint64_t>::max()) {
            return fail(SC_EOOM, "JavaScript value reference count overflow");
        }
        ++value->refs;
        return SC_OK;
    }

    JSValue duplicate(sc_value_t handle) {
        Value *value = lookup(handle);
        if (value == nullptr) {
            fail(SC_EINVAL, "invalid JavaScript value handle");
            return JS_EXCEPTION;
        }
        return JS_DupValue(context, value->value);
    }

    sc_status_t output(Value *value, sc_value_t *out) {
        if (out == nullptr || value == nullptr || !value->alive) {
            return fail(SC_EINVAL, "missing JavaScript value output");
        }
        *out = static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(value));
        return SC_OK;
    }

    sc_status_t output_raw(JSValue raw, sc_value_t *out, uint32_t forced_type = 0) {
        if (out == nullptr) {
            JS_FreeValue(context, raw);
            return fail(SC_EINVAL, "missing JavaScript value output");
        }
        Value *value = add(raw, forced_type);
        if (value == nullptr) {
            return SC_EEXCEPTION;
        }
        return output(value, out);
    }

    JSValue to_js(sc_value_t handle) { return duplicate(handle); }

    JSValue take_js(sc_value_t handle) {
        JSValue raw = duplicate(handle);
        if (!JS_IsException(raw)) {
            release(handle);
        }
        return raw;
    }

    sc_status_t initialize(const sc_host_api_v1 *host_api, sc_host_ctx_t context_handle,
                           sc_string_view options_view) {
        if (host_api == nullptr || host_api->struct_size < sizeof(sc_host_api_v1) ||
            host_api->abi_major != SC_HOST_ABI_MAJOR || host_api->abi_minor > SC_HOST_ABI_MINOR) {
            return fail(SC_EABI, "unsupported host ABI");
        }
        if (!view_valid(options_view) ||
            options_view.len > static_cast<uint64_t>(kMaxOptionsBytes)) {
            return fail(SC_EINVAL, "invalid runtime options");
        }
        ParsedOptions parsed_options;
        std::string options_error;
        try {
            if (options_view.len != 0) {
                OptionsParser parser(options_view.data, static_cast<size_t>(options_view.len));
                if (!parser.parse(&parsed_options, &options_error)) {
                    return fail_string(SC_EINVAL, "invalid runtime options: " + options_error);
                }
            }
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "parse runtime options");
        }
        host = host_api;
        host_ctx = context_handle;
        options = parsed_options;
        owner = std::this_thread::get_id();
        js_runtime = JS_NewRuntime();
        if (js_runtime == nullptr) {
            return fail(SC_EOOM, "create QuickJS runtime");
        }
        if (options.memory_limit != 0) {
            JS_SetMemoryLimit(js_runtime, static_cast<size_t>(options.memory_limit));
        }
        if (options.gc_threshold != 0) {
            JS_SetGCThreshold(js_runtime, static_cast<size_t>(options.gc_threshold));
        }
        if (options.stack_size != 0) {
            JS_SetMaxStackSize(js_runtime, static_cast<size_t>(options.stack_size));
        }
        JS_SetInterruptHandler(js_runtime, runtime_interrupt, this);
        context = JS_NewContext(js_runtime);
        if (context == nullptr) {
            return fail(SC_EOOM, "create QuickJS context");
        }
        JS_SetContextOpaque(context, this);
        JS_SetModuleLoaderFunc(js_runtime, module_normalize, module_loader, this);
        {
            std::lock_guard<std::mutex> lock(g_host_class_mutex);
            if (g_host_class_id == JS_INVALID_CLASS_ID) {
                JS_NewClassID(js_runtime, &g_host_class_id);
            }
            if (!JS_IsRegisteredClass(js_runtime, g_host_class_id) &&
                JS_NewClass(js_runtime, g_host_class_id, &g_host_class) < 0) {
                return fail(SC_EINTERNAL, "register QuickJS host object class");
            }
        }
        return install_event_loop_api();
    }

    sc_status_t install_event_loop_api() {
        JSValue global = JS_GetGlobalObject(context);
        if (JS_IsException(global)) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        struct EventFunction {
            const char *name;
            JSCFunction *function;
            int length;
        };
        const EventFunction functions[] = {
            {"setTimeout", timer_set_timeout, 2},
            {"clearTimeout", timer_clear_timeout, 1},
            {"queueMicrotask", queue_microtask_call, 1},
        };
        for (const EventFunction &definition : functions) {
            JSValue function = JS_NewCFunction(context, definition.function, definition.name, definition.length);
            if (JS_IsException(function) ||
                JS_SetPropertyStr(context, global, definition.name, function) < 0) {
                JS_FreeValue(context, global);
                capture_exception();
                return SC_EEXCEPTION;
            }
        }
        JS_FreeValue(context, global);
        return SC_OK;
    }


    sc_status_t start() {
        if (js_runtime == nullptr || context == nullptr) {
            return fail(SC_ECLOSED, "QuickJS runtime is closed");
        }
        if (started || stopped) {
            return fail(SC_ESTATE, "QuickJS runtime has already started or stopped");
        }
        if (!thread_ok()) {
            return fail(SC_ESTATE, "QuickJS runtime started from the wrong thread");
        }
        started = true;
        JS_UpdateStackTop(js_runtime);
        return SC_OK;
    }

    sc_status_t drain_jobs() {
        if (stopping || stopped) {
            return SC_OK;
        }
        for (size_t count = 0; count < kMaxPendingJobs; ++count) {
            if (stopping || stopped) {
                return SC_OK;
            }
            JSContext *job_context = nullptr;
            int status = JS_ExecutePendingJob(js_runtime, &job_context);
            if (status < 0) {
                capture_exception();
                return pending_host_status != SC_OK ? pending_host_status : SC_EEXCEPTION;
            }
            if (status == 0) {
                return SC_OK;
            }
        }
        if (stopping || stopped) {
            return SC_OK;
        }
        if (!JS_IsJobPending(js_runtime)) {
            return SC_OK;
        }
        return fail(SC_ETIMEOUT, "pending JavaScript jobs did not converge");
    }
    uint64_t allocate_timer_id() const {
        uint64_t candidate = next_timer_id;
        if (candidate == 0 || candidate > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            candidate = 1;
        }
        const uint64_t first = candidate;
        do {
            const bool used = std::any_of(timers.begin(), timers.end(), [candidate](const Timer &timer) {
                return timer.id == candidate;
            });
            if (!used) {
                return candidate;
            }
            candidate = candidate == static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ? 1 : candidate + 1;
        } while (candidate != first);
        return 0;
    }

    uint64_t schedule_timer(JSValueConst callback, int64_t delay_ms) {
        if (!JS_IsFunction(context, callback)) {
            return 0;
        }
        uint64_t id = allocate_timer_id();
        if (id == 0) {
            return 0;
        }
        next_timer_id = id == static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ? 1 : id + 1;
        int64_t bounded_delay = std::max<int64_t>(delay_ms, 0);
        const auto now = std::chrono::steady_clock::now();
        std::chrono::milliseconds requested(bounded_delay);
        const auto max_delay =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::time_point::max() - now);
        if (requested > max_delay) {
            requested = max_delay;
        }
        Timer timer;
        timer.id = id;
        timer.deadline = now + requested;
        timer.callback = JS_DupValue(context, callback);
        try {
            timers.push_back(timer);
        } catch (...) {
            JS_FreeValue(context, timer.callback);
            throw;
        }
        return id;
    }

    void cancel_timer(uint64_t id) noexcept {
        for (auto it = timers.begin(); it != timers.end(); ++it) {
            if (it->id == id) {
                JS_FreeValue(context, it->callback);
                timers.erase(it);
                return;
            }
        }
    }

    void cancel_timers() noexcept {
        if (context != nullptr) {
            for (const Timer &timer : timers) {
                JS_FreeValue(context, timer.callback);
            }
        }
        timers.clear();
    }

    sc_status_t pump_events() {
        if (pumping_events) {
            return SC_OK;
        }
        pumping_events = true;
        for (size_t step = 0; step < kMaxPendingJobs; ++step) {
            if (stopping || stopped) {
                pumping_events = false;
                return SC_OK;
            }
            sc_status_t status = drain_jobs();
            if (status != SC_OK) {
                pumping_events = false;
                return status;
            }
            auto now = std::chrono::steady_clock::now();
            auto it = std::min_element(timers.begin(), timers.end(), [](const Timer &left, const Timer &right) {
                if (left.deadline != right.deadline) {
                    return left.deadline < right.deadline;
                }
                return left.id < right.id;
            });
            if (it == timers.end() || it->deadline > now) {
                pumping_events = false;
                return SC_OK;
            }
            JSValue callback = it->callback;
            timers.erase(it);
            JSValue result = JS_Call(context, callback, JS_UNDEFINED, 0, nullptr);
            JS_FreeValue(context, callback);
            if (JS_IsException(result)) {
                capture_exception();
                if (pending_host_status == SC_ETIMEOUT) {
                    last_error = "QuickJS execution timeout";
                }
                pumping_events = false;
                return pending_host_status != SC_OK ? pending_host_status : SC_EEXCEPTION;
            }
            JS_FreeValue(context, result);
        }
        if (!stopping && !stopped && !JS_IsJobPending(js_runtime)) {
            const auto now = std::chrono::steady_clock::now();
            const bool has_due_timer = std::any_of(timers.begin(), timers.end(), [now](const Timer &timer) {
                return timer.deadline <= now;
            });
            if (!has_due_timer) {
                pumping_events = false;
                return SC_OK;
            }
        }
        pumping_events = false;
        return fail(SC_ETIMEOUT, "QuickJS event queue did not converge");
    }

    sc_status_t stop() {
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        stopping = true;
        cancel_timers();
        started = false;
        stopped = true;
        return SC_OK;
    }

    void destroy() noexcept {
        if (destroying) {
            return;
        }
        destroying = true;
        cancel_timers();
        if (context != nullptr) {
            for (Value *value : values) {
                value->alive = false;
                JS_FreeValue(context, value->value);
                delete value;
            }
            for (auto &[filename, cached] : commonjs_cache) {
                (void)filename;
                JS_FreeValue(context, cached);
            }
        }
        values.clear();
        commonjs_cache.clear();
        modules.clear();
        if (context != nullptr) {
            JS_FreeContext(context);
            context = nullptr;
        }
        if (js_runtime != nullptr) {
            JS_FreeRuntime(js_runtime);
            js_runtime = nullptr;
        }
        started = false;
        stopped = true;
    }

    sc_status_t eval_raw(const std::string &filename, const std::string &source,
                         int flags, sc_value_t *out) {
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        clear_error();
        begin_execution();
        JSValue result = JS_Eval(context, source.c_str(), source.size(), filename.c_str(), flags);
        if (JS_IsException(result)) {
            capture_exception();
            if (pending_host_status == SC_ETIMEOUT) {
                last_error = "QuickJS execution timeout";
            }
            end_execution();
            return pending_host_status != SC_OK ? pending_host_status : SC_EEXCEPTION;
        }
        status = pump_events();
        end_execution();
        if (status != SC_OK) {
            JS_FreeValue(context, result);
            return status;
        }
        return output_raw(result, out);
    }

    JSValue eval_module_source(const std::string &filename, const std::string &source) {
        JSValue result = JS_Eval(context, source.c_str(), source.size(), filename.c_str(), JS_EVAL_TYPE_MODULE);
        if (JS_IsException(result)) {
            capture_exception();
        }
        return result;
    }

    JSValue eval_commonjs_raw(const std::string &filename, const std::string &source) {
        auto cached = commonjs_cache.find(filename);
        if (cached != commonjs_cache.end()) {
            return JS_DupValue(context, cached->second);
        }
        std::string wrapped;
        wrapped.reserve(source.size() + 64);
        wrapped = "(function(module, exports, require) {\n";
        wrapped += source;
        wrapped += "\n})";
        JSValue function = JS_Eval(context, wrapped.c_str(), wrapped.size(), filename.c_str(), JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(function)) {
            capture_exception();
            return JS_EXCEPTION;
        }
        JSValue module = JS_NewObject(context);
        JSValue exports = JS_NewObject(context);
        JSValue require = JS_NewCFunction(context, require_call, "require", 1);
        if (JS_IsException(module) || JS_IsException(exports) || JS_IsException(require)) {
            JS_FreeValue(context, function);
            JS_FreeValue(context, module);
            JS_FreeValue(context, exports);
            JS_FreeValue(context, require);
            fail(SC_EEXCEPTION, "create CommonJS module objects");
            return JS_EXCEPTION;
        }
        if (JS_SetPropertyStr(context, module, "exports", JS_DupValue(context, exports)) < 0) {
            JS_FreeValue(context, function);
            JS_FreeValue(context, module);
            JS_FreeValue(context, exports);
            JS_FreeValue(context, require);
            capture_exception();
            return JS_EXCEPTION;
        }
        JSValue arguments[3] = {module, exports, require};
        JSValue call_result = JS_Call(context, function, JS_UNDEFINED, 3, arguments);
        bool failed = JS_IsException(call_result);
        if (failed) {
            capture_exception();
        }
        JS_FreeValue(context, call_result);
        JS_FreeValue(context, function);
        JS_FreeValue(context, exports);
        JS_FreeValue(context, require);
        if (failed) {
            JS_FreeValue(context, module);
            return JS_EXCEPTION;
        }
        JSValue result = JS_GetPropertyStr(context, module, "exports");
        JS_FreeValue(context, module);
        if (JS_IsException(result)) {
            capture_exception();
        }
        if (!JS_IsException(result)) {
            commonjs_cache.emplace(filename, JS_DupValue(context, result));
        }
        return result;
    }

    sc_status_t load_entry(uint32_t kind, sc_string_view filename_view,
                           sc_string_view source_view, sc_value_t *out) {
        if (out == nullptr || !view_valid(filename_view) || !view_valid(source_view)) {
            return fail(SC_EINVAL, "invalid JavaScript entry");
        }
        std::string filename;
        std::string source;
        try {
            filename = view_string(filename_view);
            source = view_string(source_view);
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "copy JavaScript entry");
        }
        if (kind == kEntryScript || kind == kEntryExtension) {
            return eval_raw(filename, source, JS_EVAL_TYPE_GLOBAL, out);
        }
        if (kind == kEntryESModule) {
            sc_status_t status = check_started();
            if (status != SC_OK) {
                return status;
            }
            modules[filename] = source;
            clear_error();
            JSValue result = eval_module_source(filename, source);
            if (JS_IsException(result)) {
                return SC_EEXCEPTION;
            }
            status = pump_events();
            if (status != SC_OK) {
                JS_FreeValue(context, result);
                return status;
            }
            return output_raw(result, out);
        }
        if (kind == kEntryCommonJS) {
            sc_status_t status = check_started();
            if (status != SC_OK) {
                return status;
            }
            modules[filename] = source;
            clear_error();
            JSValue result = eval_commonjs_raw(filename, source);
            if (JS_IsException(result)) {
                return SC_EEXCEPTION;
            }
            status = pump_events();
            if (status != SC_OK) {
                JS_FreeValue(context, result);
                return status;
            }
            return output_raw(result, out);
        }
        return fail(SC_EINVAL, "unknown JavaScript entry kind");
    }

    sc_status_t global_get(sc_string_view name_view, sc_value_t *out) {
        if (out == nullptr || !view_valid(name_view)) {
            return fail(SC_EINVAL, "invalid global name");
        }
        std::string name;
        try {
            name = view_string(name_view);
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "copy global name");
        }
        if (name.empty()) {
            return fail(SC_EINVAL, "empty global name");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        JSValue global = JS_GetGlobalObject(context);
        JSAtom atom = JS_NewAtomLen(context, name.data(), name.size());
        if (atom == JS_ATOM_NULL) {
            JS_FreeValue(context, global);
            capture_exception();
            return SC_EEXCEPTION;
        }
        JSValue result = JS_GetProperty(context, global, atom);
        JS_FreeAtom(context, atom);
        JS_FreeValue(context, global);
        return output_raw(result, out);
    }

    sc_status_t global_set(sc_string_view name_view, sc_value_t value_handle) {
        if (!view_valid(name_view)) {
            return fail(SC_EINVAL, "invalid global name");
        }
        std::string name;
        try {
            name = view_string(name_view);
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "copy global name");
        }
        if (name.empty()) {
            return fail(SC_EINVAL, "empty global name");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        JSValue value = duplicate(value_handle);
        if (JS_IsException(value)) {
            return SC_EINVAL;
        }
        JSValue global = JS_GetGlobalObject(context);
        JSAtom atom = JS_NewAtomLen(context, name.data(), name.size());
        if (atom == JS_ATOM_NULL) {
            JS_FreeValue(context, value);
            JS_FreeValue(context, global);
            capture_exception();
            return SC_EEXCEPTION;
        }
        int result = JS_SetProperty(context, global, atom, value);
        JS_FreeAtom(context, atom);
        JS_FreeValue(context, global);
        if (result < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        return SC_OK;
    }

    sc_status_t object_get(sc_value_t object_handle, sc_string_view key_view, sc_value_t *out) {
        if (out == nullptr || !view_valid(key_view)) {
            return fail(SC_EINVAL, "invalid object property");
        }
        std::string key;
        try {
            key = view_string(key_view);
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "copy object property");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *object = lookup(object_handle);
        if (object == nullptr || !JS_IsObject(object->value)) {
            return fail(SC_EINVAL, "object handle is not an object");
        }
        JSAtom atom = JS_NewAtomLen(context, key.data(), key.size());
        if (atom == JS_ATOM_NULL) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        JSValue result = JS_GetProperty(context, object->value, atom);
        JS_FreeAtom(context, atom);
        return output_raw(result, out);
    }

    sc_status_t object_set(sc_value_t object_handle, sc_string_view key_view, sc_value_t value_handle) {
        if (!view_valid(key_view)) {
            return fail(SC_EINVAL, "invalid object property");
        }
        std::string key;
        try {
            key = view_string(key_view);
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "copy object property");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *object = lookup(object_handle);
        if (object == nullptr || !JS_IsObject(object->value)) {
            return fail(SC_EINVAL, "object handle is not an object");
        }
        JSValue value = duplicate(value_handle);
        if (JS_IsException(value)) {
            return SC_EINVAL;
        }
        JSAtom atom = JS_NewAtomLen(context, key.data(), key.size());
        if (atom == JS_ATOM_NULL) {
            JS_FreeValue(context, value);
            capture_exception();
            return SC_EEXCEPTION;
        }
        int result = JS_SetProperty(context, object->value, atom, value);
        JS_FreeAtom(context, atom);
        if (result < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        return SC_OK;
    }

    sc_status_t object_has(sc_value_t object_handle, sc_string_view key_view, uint32_t *out) {
        if (out == nullptr || !view_valid(key_view)) {
            return fail(SC_EINVAL, "invalid object property");
        }
        std::string key;
        try {
            key = view_string(key_view);
        } catch (const std::bad_alloc &) {
            return fail(SC_EOOM, "copy object property");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *object = lookup(object_handle);
        if (object == nullptr || !JS_IsObject(object->value)) {
            return fail(SC_EINVAL, "object handle is not an object");
        }
        JSAtom atom = JS_NewAtomLen(context, key.data(), key.size());
        if (atom == JS_ATOM_NULL) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        int result = JS_HasProperty(context, object->value, atom);
        JS_FreeAtom(context, atom);
        if (result < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        *out = result != 0 ? 1U : 0U;
        return SC_OK;
    }

    sc_status_t new_primitive(JSValue value, uint32_t type, sc_value_t *out) {
        sc_status_t status = check_started();
        if (status != SC_OK) {
            JS_FreeValue(context, value);
            return status;
        }
        return output_raw(value, out, type);
    }

    sc_status_t value_type(sc_value_t handle, uint32_t *out) {
        if (out == nullptr) {
            return fail(SC_EINVAL, "missing value type output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        *out = value->type;
        return SC_OK;
    }

    sc_status_t value_to_bool(sc_value_t handle, uint32_t *out) {
        if (out == nullptr) {
            return fail(SC_EINVAL, "missing boolean output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        int result = JS_ToBool(context, value->value);
        if (result < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        *out = result != 0 ? 1U : 0U;
        return SC_OK;
    }

    sc_status_t value_to_i64(sc_value_t handle, int64_t *out) {
        if (out == nullptr) {
            return fail(SC_EINVAL, "missing signed integer output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        int result = JS_IsBigInt(value->value) ? JS_ToBigInt64(context, out, value->value)
                                               : JS_ToInt64(context, out, value->value);
        if (result < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        return SC_OK;
    }

    sc_status_t value_to_u64(sc_value_t handle, uint64_t *out) {
        if (out == nullptr) {
            return fail(SC_EINVAL, "missing unsigned integer output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        if (JS_IsBigInt(value->value)) {
            if (JS_ToBigUint64(context, out, value->value) < 0) {
                capture_exception();
                return SC_EEXCEPTION;
            }
            return SC_OK;
        }
        int64_t signed_value = 0;
        if (JS_ToInt64Ext(context, &signed_value, value->value) < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        if (signed_value < 0) {
            return fail(SC_EINVAL, "negative value cannot convert to unsigned");
        }
        *out = static_cast<uint64_t>(signed_value);
        return SC_OK;
    }

    sc_status_t value_to_f64(sc_value_t handle, double *out) {
        if (out == nullptr) {
            return fail(SC_EINVAL, "missing floating point output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        if (JS_ToFloat64(context, out, value->value) < 0) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        return SC_OK;
    }

    sc_status_t value_to_utf8(sc_value_t handle, char *buffer, uint64_t capacity, uint64_t *required) {
        if (required == nullptr) {
            return fail(SC_EINVAL, "missing string size output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr) {
            return fail(SC_EINVAL, "invalid JavaScript value handle");
        }
        size_t length = 0;
        const char *text = JS_ToCStringLen(context, &length, value->value);
        if (text == nullptr) {
            capture_exception();
            return SC_EEXCEPTION;
        }
        *required = static_cast<uint64_t>(length);
        if (buffer == nullptr || capacity < static_cast<uint64_t>(length)) {
            JS_FreeCString(context, text);
            return SC_EINVAL;
        }
        if (length != 0) {
            std::memcpy(buffer, text, length);
        }
        JS_FreeCString(context, text);
        return SC_OK;
    }

    sc_status_t value_get_host_ref(sc_value_t handle, sc_host_ref_t *out_ref, uint32_t *out_kind) {
        if (out_ref == nullptr || out_kind == nullptr) {
            return fail(SC_EINVAL, "missing host reference output");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        Value *value = lookup(handle);
        if (value == nullptr || (value->type != kTypeHostObject && value->type != kTypeHostFunction)) {
            return fail(SC_EINVAL, "value is not a host reference");
        }
        *out_ref = value->type == kTypeHostFunction ? value->host_function : value->host_ref;
        *out_kind = value->host_kind;
        return SC_OK;
    }

    sc_status_t host_error(sc_status_t status) {
        std::string message;
        if (host != nullptr && host->last_error_copy != nullptr) {
            uint64_t required = 0;
            sc_status_t first = host->last_error_copy(host_ctx, nullptr, 0, &required);
            if (first == SC_OK || first == SC_EINVAL) {
                if (required <= static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
                    std::vector<char> buffer(static_cast<size_t>(required) + 1, '\0');
                    if (host->last_error_copy(host_ctx, buffer.data(), required, &required) == SC_OK) {
                        message.assign(buffer.data(), static_cast<size_t>(required));
                    }
                }
            }
        }
        pending_host_status = status;
        if (message.empty()) {
            message = "host callback failed";
        }
        return fail_string(status, message);
    }

    JSValue host_get_js(sc_host_ref_t ref, const std::string &key) {
        if (host == nullptr || host->host_get == nullptr) {
            fail(SC_EHOST, "host_get is unavailable");
            return JS_EXCEPTION;
        }
        sc_value_t result = 0;
        sc_status_t status = host->host_get(host_ctx, static_cast<sc_runtime_t>(reinterpret_cast<uintptr_t>(this)),
                                             ref, sc_string_view{key.data(), static_cast<uint64_t>(key.size())}, &result);
        if (status != SC_OK) {
            host_error(status);
            return JS_EXCEPTION;
        }
        JSValue value = take_js(result);
        if (JS_IsException(value)) {
            return JS_EXCEPTION;
        }
        return value;
    }

    int host_set_js(sc_host_ref_t ref, const std::string &key, JSValueConst raw) {
        if (host == nullptr || host->host_set == nullptr) {
            fail(SC_EHOST, "host_set is unavailable");
            return -1;
        }
        Value *value = add(JS_DupValue(context, raw));
        if (value == nullptr) {
            return -1;
        }
        sc_status_t status = host->host_set(
            host_ctx, static_cast<sc_runtime_t>(reinterpret_cast<uintptr_t>(this)), ref,
            sc_string_view{key.data(), static_cast<uint64_t>(key.size())},
            static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(value)));
        release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(value)));
        if (status != SC_OK) {
            host_error(status);
            return -1;
        }
        return 0;
    }

    int host_has(sc_host_ref_t ref, const std::string &key, uint32_t *out) {
        if (host == nullptr || host->host_has == nullptr || out == nullptr) {
            fail(SC_EHOST, "host_has is unavailable");
            return -1;
        }
        sc_status_t status = host->host_has(host_ctx, ref,
                                             sc_string_view{key.data(), static_cast<uint64_t>(key.size())}, out);
        if (status != SC_OK) {
            host_error(status);
            return -1;
        }
        return 0;
    }

    int host_delete(sc_host_ref_t ref, const std::string &key, uint32_t *out) {
        if (host == nullptr || host->host_delete == nullptr || out == nullptr) {
            fail(SC_EHOST, "host_delete is unavailable");
            return -1;
        }
        sc_status_t status = host->host_delete(host_ctx, ref,
                                                sc_string_view{key.data(), static_cast<uint64_t>(key.size())}, out);
        if (status != SC_OK) {
            host_error(status);
            return -1;
        }
        return 0;
    }

    std::vector<std::string> host_keys(sc_host_ref_t ref, bool *ok) {
        std::vector<std::string> result;
        *ok = false;
        if (host == nullptr || host->host_keys_json == nullptr) {
            fail(SC_EHOST, "host_keys_json is unavailable");
            return result;
        }
        uint64_t required = 0;
        sc_status_t status = host->host_keys_json(host_ctx, ref, nullptr, 0, &required);
        if (status != SC_OK && status != SC_EINVAL) {
            host_error(status);
            return result;
        }
        if (required > static_cast<uint64_t>(std::numeric_limits<size_t>::max() - 1)) {
            fail(SC_EOOM, "host key list is too large");
            return result;
        }
        std::vector<char> buffer(static_cast<size_t>(required) + 1, '\0');
        status = host->host_keys_json(host_ctx, ref, buffer.data(), required, &required);
        if (status != SC_OK) {
            host_error(status);
            return result;
        }
        JSValue parsed = JS_ParseJSON(context, buffer.data(), static_cast<size_t>(required), "host keys");
        if (JS_IsException(parsed)) {
            capture_exception();
            return result;
        }
        if (!JS_IsArray(parsed)) {
            JS_FreeValue(context, parsed);
            fail(SC_EHOST, "host_keys_json did not return an array");
            return result;
        }
        int64_t length = 0;
        if (JS_GetLength(context, parsed, &length) < 0 || length < 0 ||
            static_cast<uint64_t>(length) > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
            JS_FreeValue(context, parsed);
            capture_exception();
            return result;
        }
        result.reserve(static_cast<size_t>(length));
        for (int64_t index = 0; index < length; ++index) {
            JSValue item = JS_GetPropertyUint32(context, parsed, static_cast<uint32_t>(index));
            size_t item_length = 0;
            const char *text = JS_ToCStringLen(context, &item_length, item);
            JS_FreeValue(context, item);
            if (text == nullptr) {
                JS_FreeValue(context, parsed);
                capture_exception();
                return result;
            }
            try {
                result.emplace_back(text, item_length);
            } catch (...) {
                JS_FreeCString(context, text);
                JS_FreeValue(context, parsed);
                throw;
            }
            JS_FreeCString(context, text);
        }
        JS_FreeValue(context, parsed);
        *ok = true;
        return result;
    }

    int host_call(sc_host_func_t function, JSValueConst this_value, int argc,
                  JSValueConst *argv, JSValue *out) {
        if (host == nullptr || host->host_call == nullptr || out == nullptr || argc < 0) {
            fail(SC_EHOST, "host_call is unavailable");
            return -1;
        }
        HostProxy *this_proxy = static_cast<HostProxy *>(JS_GetOpaque(this_value, g_host_class_id));
        uint32_t this_type = this_proxy != nullptr ? kTypeHostObject : 0;
        Value *this_handle = add(JS_DupValue(context, this_value), this_type);
        if (this_handle == nullptr) {
            return -1;
        }
        if (this_proxy != nullptr) {
            this_handle->host_ref = this_proxy->ref;
            this_handle->host_kind = this_proxy->kind;
        }
        std::vector<Value *> arguments;
        try {
            arguments.reserve(static_cast<size_t>(argc));
            for (int i = 0; i < argc; ++i) {
                Value *value = add(JS_DupValue(context, argv[i]));
                if (value == nullptr) {
                    for (Value *item : arguments) {
                        release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(item)));
                    }
                    release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(this_handle)));
                    return -1;
                }
                arguments.push_back(value);
            }
        } catch (...) {
            for (Value *item : arguments) {
                release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(item)));
            }
            release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(this_handle)));
            throw;
        }
        std::vector<sc_value_t> handles;
        handles.reserve(arguments.size());
        for (Value *value : arguments) {
            handles.push_back(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(value)));
        }
        sc_value_t result = 0;
        sc_status_t status = host->host_call(
            host_ctx, static_cast<sc_runtime_t>(reinterpret_cast<uintptr_t>(this)), function,
            static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(this_handle)),
            handles.empty() ? nullptr : handles.data(), handles.size(), &result);
        for (Value *item : arguments) {
            release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(item)));
        }
        release(static_cast<sc_value_t>(reinterpret_cast<uintptr_t>(this_handle)));
        if (status != SC_OK) {
            host_error(status);
            return -1;
        }
        JSValue converted = take_js(result);
        if (JS_IsException(converted)) {
            return -1;
        }
        *out = converted;
        return 0;
    }

    sc_status_t call_function(sc_value_t function_handle, sc_value_t this_handle,
                              const sc_value_t *argv, uint64_t argc, sc_value_t *out) {
        if (argc > static_cast<uint64_t>(std::numeric_limits<int>::max()) ||
            (argc != 0 && argv == nullptr)) {
            return fail(SC_EINVAL, "invalid JavaScript function arguments");
        }
        sc_status_t status = check_started();
        if (status != SC_OK) {
            return status;
        }
        clear_error();
        Value *function = lookup(function_handle);
        if (function == nullptr || !JS_IsFunction(context, function->value)) {
            return fail(SC_EINVAL, "value is not a JavaScript function");
        }
        JSValue this_value = this_handle == 0 ? JS_UNDEFINED : duplicate(this_handle);
        if (this_handle != 0 && JS_IsException(this_value)) {
            return SC_EINVAL;
        }
        std::vector<JSValue> arguments;
        try {
            arguments.reserve(static_cast<size_t>(argc));
            for (uint64_t i = 0; i < argc; ++i) {
                JSValue value = duplicate(argv[i]);
                if (JS_IsException(value)) {
                    JS_FreeValue(context, this_value);
                    return SC_EINVAL;
                }
                arguments.push_back(value);
            }
        } catch (...) {
            for (JSValue value : arguments) {
                JS_FreeValue(context, value);
            }
            JS_FreeValue(context, this_value);
            throw;
        }
        JSValue result = JS_Call(context, function->value, this_value,
                                 static_cast<int>(argc), arguments.empty() ? nullptr : arguments.data());
        JS_FreeValue(context, this_value);
        for (JSValue value : arguments) {
            JS_FreeValue(context, value);
        }
        if (JS_IsException(result)) {
            capture_exception();
            return pending_host_status != SC_OK ? pending_host_status : SC_EEXCEPTION;
        }
        status = pump_events();
        if (status != SC_OK) {
            JS_FreeValue(context, result);
            return status;
        }
        return output_raw(result, out);
    }
};


static Runtime *runtime_from_context(JSContext *context) noexcept {
    if (context == nullptr) {
        return nullptr;
    }
    Runtime *runtime = static_cast<Runtime *>(JS_GetContextOpaque(context));
    if (runtime == nullptr || runtime->context != context) {
        return nullptr;
    }
    return runtime;
}

static JSValue timer_set_timeout(JSContext *context, JSValueConst, int argc,
                                 JSValueConst *argv) noexcept {
    Runtime *runtime = runtime_from_context(context);
    if (runtime == nullptr || !runtime->started || runtime->stopping) {
        return JS_ThrowInternalError(context, "QuickJS runtime is stopping");
    }
    if (argc < 1 || !JS_IsFunction(context, argv[0])) {
        return JS_ThrowTypeError(context, "setTimeout callback must be a function");
    }
    int64_t delay = 0;
    if (argc > 1 && JS_ToInt64(context, &delay, argv[1]) < 0) {
        return JS_EXCEPTION;
    }
    try {
        uint64_t id = runtime->schedule_timer(argv[0], delay);
        if (id == 0) {
            return JS_ThrowTypeError(context, "setTimeout callback must be a function");
        }
        return JS_NewInt64(context, static_cast<int64_t>(id));
    } catch (const std::bad_alloc &) {
        return JS_ThrowOutOfMemory(context);
    } catch (...) {
        return JS_ThrowInternalError(context, "schedule QuickJS timer failed");
    }
}

static JSValue timer_clear_timeout(JSContext *context, JSValueConst, int argc,
                                   JSValueConst *argv) noexcept {
    Runtime *runtime = runtime_from_context(context);
    if (runtime == nullptr || !runtime->started || runtime->stopping) {
        return JS_ThrowInternalError(context, "QuickJS runtime is stopping");
    }
    if (argc < 1) {
        return JS_UNDEFINED;
    }
    int64_t id = 0;
    if (JS_ToInt64(context, &id, argv[0]) < 0) {
        return JS_EXCEPTION;
    }
    if (id > 0) {
        runtime->cancel_timer(static_cast<uint64_t>(id));
    }
    return JS_UNDEFINED;
}

static JSValue microtask_job(JSContext *context, int argc, JSValueConst *argv) noexcept {
    if (argc < 1 || !JS_IsFunction(context, argv[0])) {
        return JS_ThrowTypeError(context, "queued microtask is not callable");
    }
    JSValue result = JS_Call(context, argv[0], JS_UNDEFINED, 0, nullptr);
    if (JS_IsException(result)) {
        return result;
    }
    JS_FreeValue(context, result);
    return JS_UNDEFINED;
}

static JSValue queue_microtask_call(JSContext *context, JSValueConst, int argc,
                                    JSValueConst *argv) noexcept {
    Runtime *runtime = runtime_from_context(context);
    if (runtime == nullptr || !runtime->started || runtime->stopping) {
        return JS_ThrowInternalError(context, "QuickJS runtime is stopping");
    }
    if (argc < 1 || !JS_IsFunction(context, argv[0])) {
        return JS_ThrowTypeError(context, "queueMicrotask callback must be a function");
    }
    JSValue callback = JS_DupValue(context, argv[0]);
    if (JS_EnqueueJob(context, microtask_job, 1, &callback) < 0) {
        JS_FreeValue(context, callback);
        return JS_ThrowOutOfMemory(context);
    }
    JS_FreeValue(context, callback);
    return JS_UNDEFINED;
}

static Runtime *runtime_from(sc_runtime_t handle) noexcept {
    if (handle == 0) {
        return nullptr;
    }
    return reinterpret_cast<Runtime *>(static_cast<uintptr_t>(handle));
}

template <typename Function>
static sc_status_t boundary(Runtime *runtime, Function &&function) noexcept {
    if (runtime == nullptr) {
        return SC_EINVAL;
    }
    try {
        return function();
    } catch (const std::bad_alloc &) {
        return runtime->fail(SC_EOOM, "native QuickJS allocation failed");
    } catch (const std::exception &exception) {
        return runtime->fail_string(SC_EINTERNAL, exception.what());
    } catch (...) {
        return runtime->fail(SC_EINTERNAL, "native QuickJS provider exception");
    }
}

static JSValue throw_runtime_error(JSContext *context, Runtime *runtime, sc_status_t status) noexcept {
    if (runtime == nullptr) {
        return JS_ThrowInternalError(context, "native QuickJS runtime is unavailable");
    }
    const char *message = runtime->last_error.empty() ? "host callback failed" : runtime->last_error.c_str();
    if (status == SC_EEXCEPTION) {
        return JS_ThrowInternalError(context, "%s", message);
    }
    return JS_ThrowTypeError(context, "%s", message);
}

static HostProxy *proxy_from(JSValueConst object) {
    if (!JS_IsObject(object) || g_host_class_id == JS_INVALID_CLASS_ID) {
        return nullptr;
    }
    return static_cast<HostProxy *>(JS_GetOpaque(object, g_host_class_id));
}

static std::string atom_string(JSContext *context, JSAtom atom) {
    size_t length = 0;
    const char *text = JS_AtomToCStringLen(context, &length, atom);
    if (text == nullptr) {
        throw std::bad_alloc();
    }
    std::string result(text, length);
    JS_FreeCString(context, text);
    return result;
}

static JSValue host_get_property(JSContext *context, JSValueConst object, JSAtom atom, JSValueConst) {
    try {
        HostProxy *proxy = proxy_from(object);
        if (proxy == nullptr || proxy->runtime == nullptr) {
            return JS_ThrowTypeError(context, "invalid Scardice host object");
        }
        Runtime *runtime = proxy->runtime;
        return runtime->host_get_js(proxy->ref, atom_string(context, atom));
    } catch (const std::bad_alloc &) {
        return JS_ThrowOutOfMemory(context);
    } catch (...) {
        return JS_ThrowInternalError(context, "host property access failed");
    }
}

static int host_set_property(JSContext *context, JSValueConst object, JSAtom atom,
                             JSValueConst value, JSValueConst, int) {
    try {
        HostProxy *proxy = proxy_from(object);
        if (proxy == nullptr || proxy->runtime == nullptr) {
            JS_ThrowTypeError(context, "invalid Scardice host object");
            return -1;
        }
        Runtime *runtime = proxy->runtime;
        if (runtime->host_set_js(proxy->ref, atom_string(context, atom), value) < 0) {
            throw_runtime_error(context, runtime, SC_EHOST);
            return -1;
        }
        return 1;
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return -1;
    } catch (...) {
        JS_ThrowInternalError(context, "host property assignment failed");
        return -1;
    }
}

static int host_has_property(JSContext *context, JSValueConst object, JSAtom atom) {
    try {
        HostProxy *proxy = proxy_from(object);
        if (proxy == nullptr || proxy->runtime == nullptr) {
            JS_ThrowTypeError(context, "invalid Scardice host object");
            return -1;
        }
        uint32_t result = 0;
        Runtime *runtime = proxy->runtime;
        if (runtime->host_has(proxy->ref, atom_string(context, atom), &result) < 0) {
            throw_runtime_error(context, runtime, SC_EHOST);
            return -1;
        }
        return result != 0 ? 1 : 0;
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return -1;
    } catch (...) {
        JS_ThrowInternalError(context, "host property lookup failed");
        return -1;
    }
}

static int host_delete_property(JSContext *context, JSValueConst object, JSAtom atom) {
    try {
        HostProxy *proxy = proxy_from(object);
        if (proxy == nullptr || proxy->runtime == nullptr) {
            JS_ThrowTypeError(context, "invalid Scardice host object");
            return -1;
        }
        uint32_t deleted = 0;
        Runtime *runtime = proxy->runtime;
        if (runtime->host_delete(proxy->ref, atom_string(context, atom), &deleted) < 0) {
            throw_runtime_error(context, runtime, SC_EHOST);
            return -1;
        }
        return deleted != 0 ? 1 : 0;
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return -1;
    } catch (...) {
        JS_ThrowInternalError(context, "host property deletion failed");
        return -1;
    }
}

static int host_get_own_property(JSContext *context, JSPropertyDescriptor *descriptor,
                                JSValueConst object, JSAtom atom) {
    try {
        HostProxy *proxy = proxy_from(object);
        if (proxy == nullptr || proxy->runtime == nullptr) {
            JS_ThrowTypeError(context, "invalid Scardice host object");
            return -1;
        }
        Runtime *runtime = proxy->runtime;
        std::string key = atom_string(context, atom);
        uint32_t present = 0;
        if (runtime->host_has(proxy->ref, key, &present) < 0) {
            throw_runtime_error(context, runtime, SC_EHOST);
            return -1;
        }
        if (present == 0) {
            return 0;
        }
        if (descriptor == nullptr) {
            return 1;
        }
        JSValue value = runtime->host_get_js(proxy->ref, key);
        if (JS_IsException(value)) {
            throw_runtime_error(context, runtime, SC_EHOST);
            return -1;
        }
        descriptor->flags = JS_PROP_C_W_E | JS_PROP_HAS_VALUE;
        descriptor->value = value;
        descriptor->getter = JS_UNDEFINED;
        descriptor->setter = JS_UNDEFINED;
        return 1;
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return -1;
    } catch (...) {
        JS_ThrowInternalError(context, "host property descriptor failed");
        return -1;
    }
}

static int host_get_own_property_names(JSContext *context, JSPropertyEnum **properties,
                                       uint32_t *length, JSValueConst object) {
    try {
        if (properties == nullptr || length == nullptr) {
            JS_ThrowTypeError(context, "invalid host property list output");
            return -1;
        }
        HostProxy *proxy = proxy_from(object);
        if (proxy == nullptr || proxy->runtime == nullptr) {
            JS_ThrowTypeError(context, "invalid Scardice host object");
            return -1;
        }
        bool ok = false;
        std::vector<std::string> keys = proxy->runtime->host_keys(proxy->ref, &ok);
        if (!ok || keys.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
            throw_runtime_error(context, proxy->runtime, SC_EHOST);
            return -1;
        }
        JSPropertyEnum *items = static_cast<JSPropertyEnum *>(
            js_mallocz(context, keys.size() * sizeof(JSPropertyEnum)));
        if (items == nullptr && !keys.empty()) {
            JS_ThrowOutOfMemory(context);
            return -1;
        }
        for (size_t i = 0; i < keys.size(); ++i) {
            items[i].atom = JS_NewAtomLen(context, keys[i].data(), keys[i].size());
            if (items[i].atom == JS_ATOM_NULL) {
                for (size_t j = 0; j < i; ++j) {
                    JS_FreeAtom(context, items[j].atom);
                }
                js_free(context, items);
                JS_ThrowOutOfMemory(context);
                return -1;
            }
            items[i].is_enumerable = true;
        }
        *properties = items;
        *length = static_cast<uint32_t>(keys.size());
        return 0;
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return -1;
    } catch (...) {
        JS_ThrowInternalError(context, "host property list failed");
        return -1;
    }
}

static int host_define_own_property(JSContext *context, JSValueConst object, JSAtom atom,
                                    JSValueConst value, JSValueConst getter, JSValueConst setter, int flags) {
    try {
        if ((flags & (JS_PROP_HAS_GET | JS_PROP_HAS_SET)) != 0) {
            JS_ThrowTypeError(context, "accessor properties are not supported on host objects");
            return -1;
        }
        if ((flags & JS_PROP_HAS_VALUE) == 0) {
            return 1;
        }
        (void)getter;
        (void)setter;
        return host_set_property(context, object, atom, value, object, flags);
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return -1;
    } catch (...) {
        JS_ThrowInternalError(context, "host property definition failed");
        return -1;
    }
}

static void host_finalizer(JSRuntime *, JSValueConst object) noexcept {
    HostProxy *proxy = proxy_from(object);
    delete proxy;
}

static JSValue host_function_call(JSContext *context, JSValueConst this_value, int argc,
                                  JSValueConst *argv, int, JSValueConst *function_data) noexcept {
    try {
        Runtime *runtime = static_cast<Runtime *>(JS_GetContextOpaque(context));
        if (runtime == nullptr || function_data == nullptr || argc < 0) {
            return JS_ThrowInternalError(context, "invalid Scardice host function");
        }
        uint64_t function = 0;
        if (JS_ToBigUint64(context, &function, function_data[0]) < 0 || function == 0) {
            runtime->capture_exception();
            return JS_ThrowTypeError(context, "%s", runtime->last_error.c_str());
        }
        JSValue result = JS_UNDEFINED;
        if (runtime->host_call(function, this_value, argc, argv, &result) < 0) {
            return throw_runtime_error(context, runtime, SC_EHOST);
        }
        return result;
    } catch (const std::bad_alloc &) {
        return JS_ThrowOutOfMemory(context);
    } catch (...) {
        return JS_ThrowInternalError(context, "host function call failed");
    }
}

static std::string module_name_for(const char *base_name, const char *name) {
    return join_module_name(base_name, name);
}

static char *module_normalize(JSContext *context, const char *base_name, const char *name, void *) noexcept {
    try {
        std::string normalized = module_name_for(base_name, name);
        return js_strdup(context, normalized.c_str());
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return nullptr;
    } catch (...) {
        JS_ThrowInternalError(context, "module name normalization failed");
        return nullptr;
    }
}

static JSModuleDef *module_loader(JSContext *context, const char *module_name, void *opaque) noexcept {
    try {
        Runtime *runtime = static_cast<Runtime *>(opaque);
        if (runtime == nullptr || module_name == nullptr) {
            JS_ThrowReferenceError(context, "invalid JavaScript module");
            return nullptr;
        }
        auto it = runtime->modules.find(module_name);
        if (it == runtime->modules.end()) {
            JS_ThrowReferenceError(context, "module '%s' was not loaded", module_name);
            return nullptr;
        }
        JSValue compiled = JS_Eval(context, it->second.c_str(), it->second.size(), module_name,
                                   JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        if (JS_IsException(compiled)) {
            runtime->capture_exception();
            return nullptr;
        }
        return reinterpret_cast<JSModuleDef *>(JS_VALUE_GET_PTR(compiled));
    } catch (const std::bad_alloc &) {
        JS_ThrowOutOfMemory(context);
        return nullptr;
    } catch (...) {
        JS_ThrowInternalError(context, "module loading failed");
        return nullptr;
    }
}

static JSValue require_call(JSContext *context, JSValueConst, int argc, JSValueConst *argv) noexcept {
    try {
        Runtime *runtime = static_cast<Runtime *>(JS_GetContextOpaque(context));
        if (runtime == nullptr || argc != 1) {
            return JS_ThrowTypeError(context, "require expects one module name");
        }
        size_t length = 0;
        const char *name = JS_ToCStringLen(context, &length, argv[0]);
        if (name == nullptr) {
            runtime->capture_exception();
            return JS_EXCEPTION;
        }
        std::string module_name;
        try {
            module_name.assign(name, length);
        } catch (...) {
            JS_FreeCString(context, name);
            return JS_ThrowOutOfMemory(context);
        }
        JS_FreeCString(context, name);
        auto it = runtime->modules.find(module_name);
        if (it == runtime->modules.end()) {
            return JS_ThrowReferenceError(context, "module '%s' was not loaded", module_name.c_str());
        }
        JSValue result = runtime->eval_commonjs_raw(module_name, it->second);
        if (JS_IsException(result)) {
            return JS_EXCEPTION;
        }
        return result;
    } catch (const std::bad_alloc &) {
        return JS_ThrowOutOfMemory(context);
    } catch (...) {
        return JS_ThrowInternalError(context, "require failed");
    }
}

static sc_status_t SC_CALL api_create(const sc_host_api_v1 *host, sc_host_ctx_t host_ctx,
                                      const sc_runtime_create_info_v1 *info, sc_runtime_t *out) noexcept {
    if (host == nullptr || info == nullptr || out == nullptr ||
        info->struct_size < sizeof(sc_runtime_create_info_v1)) {
        return SC_EINVAL;
    }
    Runtime *runtime = nullptr;
    try {
        runtime = new Runtime();
        sc_status_t status = runtime->initialize(host, host_ctx, info->options_json);
        if (status != SC_OK) {
            delete runtime;
            return status;
        }
        *out = static_cast<sc_runtime_t>(reinterpret_cast<uintptr_t>(runtime));
        return SC_OK;
    } catch (const std::bad_alloc &) {
        if (runtime != nullptr) {
            delete runtime;
        }
        return SC_EOOM;
    } catch (...) {
        if (runtime != nullptr) {
            delete runtime;
        }
        return SC_EINTERNAL;
    }
}

static sc_status_t SC_CALL api_start(sc_runtime_t handle) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime]() { return runtime->start(); });
}

static sc_status_t SC_CALL api_stop(sc_runtime_t handle) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime]() { return runtime->stop(); });
}

static void SC_CALL api_destroy(sc_runtime_t handle) noexcept {
    Runtime *runtime = runtime_from(handle);
    try {
        delete runtime;
    } catch (...) {
        // The Runtime destructor is noexcept; keep this boundary defensive
        // if its implementation changes in a future provider revision.
    }
}

static sc_status_t SC_CALL api_eval(sc_runtime_t handle, sc_string_view filename,
                                    sc_string_view source, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, filename, source, out]() {
        if (out == nullptr || !view_valid(filename) || !view_valid(source)) {
            return runtime->fail(SC_EINVAL, "invalid JavaScript source");
        }
        std::string file = view_string(filename);
        std::string text = view_string(source);
        return runtime->eval_raw(file, text, JS_EVAL_TYPE_GLOBAL, out);
    });
}

static sc_status_t SC_CALL api_load_entry(sc_runtime_t handle, uint32_t kind,
                                          sc_string_view filename, sc_string_view source,
                                          sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, kind, filename, source, out]() {
        return runtime->load_entry(kind, filename, source, out);
    });
}

static sc_status_t SC_CALL api_global_get(sc_runtime_t handle, sc_string_view name,
                                          sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, name, out]() { return runtime->global_get(name, out); });
}

static sc_status_t SC_CALL api_global_set(sc_runtime_t handle, sc_string_view name,
                                          sc_value_t value) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, name, value]() { return runtime->global_set(name, value); });
}

static sc_status_t SC_CALL api_object_new(sc_runtime_t handle, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, out]() {
        if (out == nullptr) {
            return runtime->fail(SC_EINVAL, "missing object output");
        }
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        return runtime->output_raw(JS_NewObject(runtime->context), out, kTypeObject);
    });
}

static sc_status_t SC_CALL api_object_get(sc_runtime_t handle, sc_value_t object,
                                          sc_string_view key, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, object, key, out]() { return runtime->object_get(object, key, out); });
}

static sc_status_t SC_CALL api_object_set(sc_runtime_t handle, sc_value_t object,
                                          sc_string_view key, sc_value_t value) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, object, key, value]() { return runtime->object_set(object, key, value); });
}

static sc_status_t SC_CALL api_object_has(sc_runtime_t handle, sc_value_t object,
                                          sc_string_view key, uint32_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, object, key, out]() { return runtime->object_has(object, key, out); });
}

static sc_status_t SC_CALL api_new_undefined(sc_runtime_t handle, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, out]() { return runtime->new_primitive(JS_UNDEFINED, kTypeUndefined, out); });
}

static sc_status_t SC_CALL api_new_null(sc_runtime_t handle, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, out]() { return runtime->new_primitive(JS_NULL, kTypeNull, out); });
}

static sc_status_t SC_CALL api_new_bool(sc_runtime_t handle, uint32_t value, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() {
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        return runtime->new_primitive(JS_NewBool(runtime->context, value != 0), kTypeBool, out);
    });
}

static sc_status_t SC_CALL api_new_i64(sc_runtime_t handle, int64_t value, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() {
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        return runtime->new_primitive(JS_NewInt64(runtime->context, value), kTypeI64, out);
    });
}

static sc_status_t SC_CALL api_new_u64(sc_runtime_t handle, uint64_t value, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() {
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        JSValue raw = value <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
                          ? JS_NewInt64(runtime->context, static_cast<int64_t>(value))
                          : JS_NewBigUint64(runtime->context, value);
        return runtime->new_primitive(raw, kTypeU64, out);
    });
}

static sc_status_t SC_CALL api_new_f64(sc_runtime_t handle, double value, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() {
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        return runtime->new_primitive(JS_NewFloat64(runtime->context, value), kTypeF64, out);
    });
}

static sc_status_t SC_CALL api_new_string(sc_runtime_t handle, sc_string_view value,
                                           sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() {
        if (out == nullptr || !view_valid(value)) {
            return runtime->fail(SC_EINVAL, "invalid JavaScript string");
        }
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        std::string text = view_string(value);
        return runtime->new_primitive(JS_NewStringLen(runtime->context, text.data(), text.size()), kTypeString, out);
    });
}

static sc_status_t SC_CALL api_value_type(sc_runtime_t handle, sc_value_t value, uint32_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() { return runtime->value_type(value, out); });
}

static sc_status_t SC_CALL api_value_bool(sc_runtime_t handle, sc_value_t value, uint32_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() { return runtime->value_to_bool(value, out); });
}

static sc_status_t SC_CALL api_value_i64(sc_runtime_t handle, sc_value_t value, int64_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() { return runtime->value_to_i64(value, out); });
}

static sc_status_t SC_CALL api_value_u64(sc_runtime_t handle, sc_value_t value, uint64_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() { return runtime->value_to_u64(value, out); });
}

static sc_status_t SC_CALL api_value_f64(sc_runtime_t handle, sc_value_t value, double *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, out]() { return runtime->value_to_f64(value, out); });
}

static sc_status_t SC_CALL api_value_utf8(sc_runtime_t handle, sc_value_t value, char *buffer,
                                          uint64_t capacity, uint64_t *required) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, buffer, capacity, required]() {
        return runtime->value_to_utf8(value, buffer, capacity, required);
    });
}

static sc_status_t SC_CALL api_value_host_ref(sc_runtime_t handle, sc_value_t value,
                                              sc_host_ref_t *ref, uint32_t *kind) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value, ref, kind]() { return runtime->value_get_host_ref(value, ref, kind); });
}


static sc_status_t SC_CALL api_host_object_new(sc_runtime_t handle, sc_host_ref_t ref,
                                               uint32_t kind, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, ref, kind, out]() {
        if (out == nullptr || ref == 0) {
            return runtime->fail(SC_EINVAL, "invalid host object reference");
        }
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        JSValue object = JS_NewObjectClass(runtime->context, g_host_class_id);
        if (JS_IsException(object)) {
            runtime->capture_exception();
            return SC_EEXCEPTION;
        }
        HostProxy *proxy = new HostProxy{runtime, ref, kind};
        if (JS_SetOpaque(object, proxy) < 0) {
            delete proxy;
            JS_FreeValue(runtime->context, object);
            return runtime->fail(SC_EINTERNAL, "attach host object reference");
        }
        Value *value = runtime->add(object, kTypeHostObject);
        if (value == nullptr) {
            return SC_EEXCEPTION;
        }
        value->host_ref = ref;
        value->host_kind = kind;
        return runtime->output(value, out);
    });
}

static sc_status_t SC_CALL api_host_function_new(sc_runtime_t handle, sc_host_func_t function,
                                                 sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, function, out]() {
        if (out == nullptr || function == 0) {
            return runtime->fail(SC_EINVAL, "invalid host function reference");
        }
        sc_status_t status = runtime->check_started();
        if (status != SC_OK) {
            return status;
        }
        JSValue data = JS_NewBigUint64(runtime->context, function);
        if (JS_IsException(data)) {
            runtime->capture_exception();
            return SC_EEXCEPTION;
        }
        JSValue function_value = JS_NewCFunctionData2(runtime->context, host_function_call,
                                                       "hostFunction", 0, 0, 1, &data);
        JS_FreeValue(runtime->context, data);
        if (JS_IsException(function_value)) {
            runtime->capture_exception();
            return SC_EEXCEPTION;
        }
        Value *value = runtime->add(function_value, kTypeHostFunction);
        if (value == nullptr) {
            return SC_EEXCEPTION;
        }
        value->host_function = function;
        value->host_kind = static_cast<uint32_t>(SC_HOST_ABI_MINOR == 0 ? 9 : 9);
        return runtime->output(value, out);
    });
}

static sc_status_t SC_CALL api_function_call(sc_runtime_t handle, sc_value_t function,
                                              sc_value_t this_value, const sc_value_t *argv,
                                              uint64_t argc, sc_value_t *out) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, function, this_value, argv, argc, out]() {
        return runtime->call_function(function, this_value, argv, argc, out);
    });
}


static sc_status_t SC_CALL api_retain(sc_runtime_t handle, sc_value_t value) noexcept {
    Runtime *runtime = runtime_from(handle);
    return boundary(runtime, [runtime, value]() { return runtime->retain(value); });
}

static void SC_CALL api_release(sc_runtime_t handle, sc_value_t value) noexcept {
    Runtime *runtime = runtime_from(handle);
    if (runtime != nullptr) {
        try {
            runtime->release(value);
        } catch (...) {
            runtime->fail(SC_EINTERNAL, "release JavaScript value failed");
        }
    }
}

static sc_status_t SC_CALL api_last_error(sc_runtime_t handle, char *buffer,
                                           uint64_t capacity, uint64_t *required) noexcept {
    Runtime *runtime = runtime_from(handle);
    if (runtime == nullptr || required == nullptr) {
        return SC_EINVAL;
    }
    try {
        *required = static_cast<uint64_t>(runtime->last_error.size());
        if (buffer == nullptr || capacity < *required) {
            return SC_EINVAL;
        }
        if (*required != 0) {
            std::memcpy(buffer, runtime->last_error.data(), static_cast<size_t>(*required));
        }
        return SC_OK;
    } catch (...) {
        return SC_EINTERNAL;
    }
}

static const sc_runtime_descriptor_v1 kDescriptor = {
    sizeof(sc_runtime_descriptor_v1),
    SC_RUNTIME_ABI_MAJOR,
    SC_RUNTIME_ABI_MINOR,
    SC_HOST_ABI_MAJOR,
    SC_HOST_ABI_MINOR,
    SC_CAP_SCRIPT | SC_CAP_COMMONJS | SC_CAP_ESM | SC_CAP_PROMISE | SC_CAP_TIMERS |
        SC_CAP_HOST_OBJECT | SC_CAP_HOST_FUNCTION | SC_CAP_SOURCE_LOCATION,
    "quickjs",
    "QuickJS-NG native provider",
    "0.7.7",
    "C++",
};

static const sc_runtime_api_v1 kApi = {
    sizeof(sc_runtime_api_v1),
    api_create,
    api_start,
    api_stop,
    api_destroy,
    api_eval,
    api_load_entry,
    api_global_get,
    api_global_set,
    api_object_new,
    api_object_get,
    api_object_set,
    api_object_has,
    api_new_undefined,
    api_new_null,
    api_new_bool,
    api_new_i64,
    api_new_u64,
    api_new_f64,
    api_new_string,
    api_value_type,
    api_value_bool,
    api_value_i64,
    api_value_u64,
    api_value_f64,
    api_value_utf8,
    api_value_host_ref,
    api_host_object_new,
    api_host_function_new,
    api_function_call,
    api_retain,
    api_release,
    api_last_error,
};
static const sc_runtime_plugin_v1 kPlugin = {
    sizeof(sc_runtime_plugin_v1),
    kDescriptor,
    kApi,
};


static int runtime_interrupt(JSRuntime *, void *opaque) noexcept {
    Runtime *runtime = static_cast<Runtime *>(opaque);
    if (runtime == nullptr) {
        return 0;
    }
    if (runtime->pending_host_status != SC_OK) {
        return 1;
    }
    if (runtime->deadline_active && std::chrono::steady_clock::now() >= runtime->deadline) {
        runtime->pending_host_status = SC_ETIMEOUT;
        runtime->fail(SC_ETIMEOUT, "QuickJS execution timeout");
        return 1;
    }
    return 0;
}

} // namespace

extern "C" SC_EXPORT sc_status_t SC_CALL scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query, const sc_runtime_plugin_v1 **out_plugin) {
    try {
        if (query == nullptr || out_plugin == nullptr || query->struct_size < sizeof(sc_runtime_query_v1)) {
            return SC_EINVAL;
        }
        if (query->runtime_abi_major != SC_RUNTIME_ABI_MAJOR || query->runtime_abi_minor > SC_RUNTIME_ABI_MINOR) {
            return SC_EABI;
        }
        if (query->host_abi_major != SC_HOST_ABI_MAJOR || query->host_abi_minor > SC_HOST_ABI_MINOR) {
            return SC_EABI;
        }
        *out_plugin = reinterpret_cast<const sc_runtime_plugin_v1 *>(&kPlugin);
        return SC_OK;
    } catch (const std::bad_alloc &) {
        return SC_EOOM;
    } catch (...) {
        return SC_EINTERNAL;
    }
}
