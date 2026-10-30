# Scardice Runtime Plugin C ABI — Full Implementation Plan

## 0. 最终目标

目标分支：

```text
在 https://github.com/Scardice/Scardice-core/tree/quickjs-experimental-20260901 的基础上创建新分支 feat/pluggable-plugin-runtime
然后在 feat/pluggable-plugin-runtime 分支上完成后续工作
```

最终形成：

```text
Scardice Core
│
├── jsengine
│   ├── Provider Registry
│   │   ├── builtin: goja
│   │   └── native runtime loader
│   │
│   ├── generic Loop / Runtime / Value / Object
│   └── hostbridge
│       └── Go reflection / jsbind / callback trampoline
│
├── C ABI bridge
│
└── runtimes/
    └── quickjs/
        ├── runtime.json
        └── scardice-runtime-quickjs.dll
            libscardice-runtime-quickjs.so
            libscardice-runtime-quickjs.dylib
```

必须满足：

```text
Scardice.exe 编译完成
        ↓
没有 QuickJS runtime
        ↓
Goja 正常运行

之后：
只下载 quickjs runtime package
        ↓
扔进 runtimes/quickjs/
        ↓
重启 Scardice
        ↓
jsEngine=quickjs 可用

整个过程：
Scardice Core 不重新编译
```

最终 Core module graph 中必须不存在：

```text
github.com/buke/quickjs-go
github.com/Scardice/quickjs_nodejs
utils/jsengine/quickjs
```

当前分支这些依赖仍然直接进入 Core，而 `EngineID`、`ParseEngineID()`、`dice_jsvm.go` 也仍明确认识 `goja/quickjs`；现有 `Runtime/Loop/Value/Object` 则已经提供了很好的内部抽象基础。([GitHub][2])

---

# 1. Code Agent 的硬约束

执行过程中遵守这些规则，不要自行简化：

1. **Goja 永远保留 builtin，并继续作为默认 runtime。**
2. **显式配置 `jsEngine=quickjs` 而插件不存在时，必须报错，不得偷偷 fallback 到 Goja。**
3. `EngineID` 是动态字符串 ID，不再通过 switch 枚举“世界上有哪些 engine”。
4. `dice`、`ExtInfo`、插件加载器不得 import QuickJS 实现。
5. C ABI 边界不得出现：

   ```text
   interface{}
   reflect.Value
   Go func
   Go map
   Go slice
   Go pointer
   *Dice
   *ExtInfo
   ```
6. C ABI 仅通过：

   ```text
   fixed-width integers
   opaque handles
   borrowed buffers
   function tables
   explicit status codes
   ```
7. **v1 不支持动态 `dlclose/FreeLibrary`。**
8. 可以销毁/recreate runtime instance，但 native library 一旦载入就保留到进程退出。
9. native runtime plugin 视为受信任原生代码，不宣称有 sandbox。
10. QuickJS 正式 provider 使用 C/C++ QuickJS，不使用 Go c-shared。
11. 当前 QuickJS-Go 实现保留到行为兼容测试完成，然后从 Core 删除。
12. 每个阶段保持 Goja 可构建、可运行、可测试。
13. 不进行 big-bang rewrite。
14. ABI major v1 发布后不得修改已有字段布局或已有函数语义，只能 append。
15. 所有 C ABI panic/exception 都必须截断在边界内：

    * Go panic 不跨 C；
    * C++ exception 不跨 ABI。
16. explicit runtime selection 的失败必须可诊断：

    ```text
    provider not found
    ABI incompatible
    missing symbol
    architecture mismatch
    plugin create failure
    capability missing
    ```
17. runtime native library 的搜索目录和普通 JS 扩展目录严格分离。

Go 官方 cgo 规则也决定了这里必须这么做：`interface`、`map`、`func` 等 Go 类型内部包含 Go pointer，C 不能长期持有这些引用；官方建议跨 C 保存 Go 对象身份时使用 integer handle 一类机制。([Go 语言][3])

---

# 2. 当前代码需要解决的几个具体结构问题

## 2.1 Engine 枚举化

当前：

```go
type EngineID string

const (
    EngineGoja    EngineID = "goja"
    EngineQuickJS EngineID = "quickjs"
)
```

以及：

```go
ParseEngineID()
```

通过 switch 决定合法 runtime。([GitHub][4])

目标：

```go
type EngineID string

const EngineGoja EngineID = "goja"

func NormalizeEngineID(raw string) EngineID
```

合法性改成：

```go
registry.Resolve(id)
```

判断。

---

## 2.2 Dice 直接认识 QuickJS

当前 `dice_jsvm.go` 中有：

```go
if engine == jsengine.EngineQuickJS {
    d.jsInitQuickJS()
    return
}
```

脚本加载也会判断 QuickJS 后调用 QuickJS-specific `LoadModule()`。([GitHub][5])

全部需要消失。

最终：

```go
loop, err := d.JSRuntimeRegistry.Open(
    d.Config.JsEngine,
    options,
)

d.ExtLoopManager.SetLoop(loop)
```

脚本：

```go
err := loop.LoadEntry(jsengine.Entry{
    Filename: targetPath,
    Source:   source,
    Kind:     jsengine.EntryExtension,
})
```

Dice 不关心这是：

```text
Goja
QuickJS
Lua
V8
Python
```

---

## 2.3 JsLoopManager 还是双轨

现在它同时保存：

```go
*eventloop.EventLoop
jsengine.Loop
```

并有：

```text
GetLoop
GetEngineLoop
SetLoop
SetEngineLoop
```

两套生命周期。([GitHub][6])

最终必须只剩：

```go
type JsLoopManager struct {
    mu         sync.RWMutex
    loop       jsengine.Loop
    generation uint64
}
```

---

## 2.4 回调仍有 Goja 专属路径

当前 `callWithJsCheck()` 仍会直接：

```go
d.ExtLoopManager.GetLoop(...)
loop.RunOnLoop(...)
```

而 `OnMessagePreprocess` 等字段同时存在 Goja 和 engine-neutral 两套版本。([GitHub][7])

这必须在独立阶段迁移。

否则会出现：

```text
QuickJS DLL 成功加载
JS 也成功执行

但是：
事件触发
 ↓
旧 callback dispatcher
 ↓
找 Goja eventloop
 ↓
失败
```

---

# 3. 最终内部 Go 架构

新增：

```text
utils/jsengine/
├── engine.go
├── runtime.go
├── provider.go
├── registry.go
├── descriptor.go
├── capability.go
├── entry.go
│
├── builtin/
│   └── goja/
│
├── hostbridge/
│   ├── bridge.go
│   ├── registry.go
│   ├── reflect.go
│   ├── bind_struct.go
│   ├── map.go
│   ├── slice.go
│   ├── callback.go
│   ├── convert.go
│   └── errors.go
│
└── native/
    ├── provider.go
    ├── loader.go
    ├── runtime.go
    ├── loop.go
    ├── value.go
    ├── object.go
    ├── scope.go
    ├── errors.go
    │
    ├── native_cgo.go
    ├── native_nocgo.go
    ├── bridge.h
    ├── bridge.c
    ├── loader_unix.c
    └── loader_windows.c
```

---

# 4. Provider 抽象

新增：

```go
type Provider interface {
    Descriptor() Descriptor

    Open(
        ctx context.Context,
        options RuntimeOptions,
    ) (Loop, error)
}
```

Descriptor：

```go
type Descriptor struct {
    ID           EngineID
    Name         string
    Version      string
    Language     string

    ABIMajor     uint32
    ABIMinor     uint32

    HostABIMajor uint32
    HostABIMinor uint32

    Capabilities CapabilitySet

    Builtin      bool
    Path         string
}
```

Registry：

```go
type Registry interface {
    RegisterBuiltin(Provider) error
    RegisterCandidate(RuntimeManifest) error

    Resolve(EngineID) (Provider, error)

    Descriptors() []Descriptor
}
```

### 注册规则

```text
goja
  → builtin registry

quickjs
  → manifest candidate
  → 首次 Resolve 时才真正 LoadLibrary
```

不要启动时 eagerly load 所有 DLL。

原因：

```text
扫描 manifest ≠ 执行 native code
```

只有用户真的选择：

```yaml
jsEngine: quickjs
```

时才执行 DLL。

---

# 5. Loop 接口需要升级

当前接口主要是：

```go
type Loop interface {
    Engine() EngineID
    Run(func(Runtime) error) error
    Close()
}
```

建议改成：

```go
type Loop interface {
    Engine() EngineID
    Descriptor() Descriptor

    Run(func(Runtime) error) error

    LoadEntry(Entry) error

    Close() error
}
```

新增：

```go
type EntryKind uint32

const (
    EntryScript EntryKind = iota
    EntryCommonJS
    EntryESModule

    // Scardice extension entrypoint.
    EntryExtension
)

type Entry struct {
    Filename string
    Source   string
    Kind     EntryKind
}
```

其中：

```text
Goja Provider:
EntryExtension → 当前 RequireModule 语义

QuickJS Provider:
EntryExtension → 当前 experimental QuickJS ESM/module 语义
```

这样当前 QuickJS 特有的：

```go
quickjs.LoadModule(...)
```

可以彻底消失。

目前这个函数本来就因为 QuickJS 特异性被刻意留在公共 `Runtime` 接口之外，正说明这一职责更适合归到 Provider/Loop 生命周期层。([GitHub][8])

---

# 6. C ABI v1

创建唯一公共头：

```text
runtimeabi/include/scardice_runtime_v1.h
```

此文件一旦发布 v1，不允许破坏性修改。

建议从以下形态开始。

```c
#ifndef SCARDICE_RUNTIME_V1_H
#define SCARDICE_RUNTIME_V1_H

#include <stdint.h>

#ifdef _WIN32
#define SC_EXPORT __declspec(dllexport)
#define SC_CALL __cdecl
#else
#define SC_EXPORT __attribute__((visibility("default")))
#define SC_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SC_RUNTIME_ABI_MAJOR 1
#define SC_RUNTIME_ABI_MINOR 0

#define SC_HOST_ABI_MAJOR 1
#define SC_HOST_ABI_MINOR 0

typedef int32_t  sc_status_t;

typedef uint64_t sc_runtime_t;
typedef uint64_t sc_value_t;
typedef uint64_t sc_host_ref_t;
typedef uint64_t sc_host_func_t;
typedef uint64_t sc_host_ctx_t;

typedef struct sc_string_view {
    const char *data;
    uint64_t len;
} sc_string_view;
```

约定：

```text
0 handle = invalid/null handle
```

---

# 7. Status 统一

不要传播：

```text
errno
HRESULT
Go error pointer
C++ exception
QuickJS exception pointer
```

ABI 定：

```c
enum {
    SC_OK             = 0,

    SC_EINVAL         = -1,
    SC_EABI           = -2,
    SC_ENOTSUP        = -3,
    SC_ESTATE         = -4,
    SC_ECLOSED        = -5,

    SC_EEXCEPTION     = -10,
    SC_EOOM           = -11,
    SC_ETIMEOUT       = -12,

    SC_EHOST          = -20,
    SC_EINTERNAL      = -100
};
```

具体错误文本统一：

```c
last_error_copy(...)
```

使用 caller-provided buffer：

```c
sc_status_t (*last_error_copy)(
    sc_runtime_t runtime,
    char *buffer,
    uint64_t capacity,
    uint64_t *required
);
```

调用方式：

```text
buffer=NULL
capacity=0
 ↓
得到 required
 ↓
分配
 ↓
第二次 copy
```

这样完全没有：

```text
malloc from DLL
free from host
```

这种跨 CRT 问题。

---

# 8. ABI Descriptor

```c
typedef struct sc_runtime_descriptor_v1 {
    uint32_t struct_size;

    uint32_t abi_major;
    uint32_t abi_minor;

    uint32_t host_abi_major;
    uint32_t host_abi_minor;

    uint64_t capabilities;

    const char *id;
    const char *name;
    const char *version;
    const char *language;
} sc_runtime_descriptor_v1;
```

这些字符串：

```text
plugin static storage
```

生命周期：

```text
library loaded → process exit
```

因为 v1 根本不卸载 library。

---

# 9. Runtime API vtable

建议 v1 至少包括：

```c
typedef struct sc_runtime_api_v1 {
    uint32_t struct_size;

    sc_status_t (SC_CALL *create)(
        const struct sc_host_api_v1 *host,
        sc_host_ctx_t host_ctx,
        const struct sc_runtime_create_info_v1 *info,
        sc_runtime_t *out_runtime
    );

    sc_status_t (SC_CALL *start)(
        sc_runtime_t runtime
    );

    sc_status_t (SC_CALL *stop)(
        sc_runtime_t runtime
    );

    void (SC_CALL *destroy)(
        sc_runtime_t runtime
    );

    sc_status_t (SC_CALL *eval)(
        sc_runtime_t runtime,
        sc_string_view filename,
        sc_string_view source,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *load_entry)(
        sc_runtime_t runtime,
        uint32_t entry_kind,
        sc_string_view filename,
        sc_string_view source,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *global_get)(
        sc_runtime_t runtime,
        sc_string_view name,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *global_set)(
        sc_runtime_t runtime,
        sc_string_view name,
        sc_value_t value
    );

    sc_status_t (SC_CALL *object_new)(
        sc_runtime_t runtime,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *object_get)(
        sc_runtime_t runtime,
        sc_value_t object,
        sc_string_view key,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *object_set)(
        sc_runtime_t runtime,
        sc_value_t object,
        sc_string_view key,
        sc_value_t value
    );

    sc_status_t (SC_CALL *object_has)(
        sc_runtime_t runtime,
        sc_value_t object,
        sc_string_view key,
        uint32_t *out
    );

    /* primitive constructors */
    sc_status_t (SC_CALL *value_new_undefined)(
        sc_runtime_t, sc_value_t *);

    sc_status_t (SC_CALL *value_new_null)(
        sc_runtime_t, sc_value_t *);

    sc_status_t (SC_CALL *value_new_bool)(
        sc_runtime_t, uint32_t, sc_value_t *);

    sc_status_t (SC_CALL *value_new_i64)(
        sc_runtime_t, int64_t, sc_value_t *);

    sc_status_t (SC_CALL *value_new_u64)(
        sc_runtime_t, uint64_t, sc_value_t *);

    sc_status_t (SC_CALL *value_new_f64)(
        sc_runtime_t, double, sc_value_t *);

    sc_status_t (SC_CALL *value_new_string)(
        sc_runtime_t, sc_string_view, sc_value_t *);

    /* inspection/conversion */
    sc_status_t (SC_CALL *value_type)(
        sc_runtime_t, sc_value_t, uint32_t *);

    sc_status_t (SC_CALL *value_to_bool)(
        sc_runtime_t, sc_value_t, uint32_t *);

    sc_status_t (SC_CALL *value_to_i64)(
        sc_runtime_t, sc_value_t, int64_t *);

    sc_status_t (SC_CALL *value_to_u64)(
        sc_runtime_t, sc_value_t, uint64_t *);

    sc_status_t (SC_CALL *value_to_f64)(
        sc_runtime_t, sc_value_t, double *);

    sc_status_t (SC_CALL *value_to_utf8_copy)(
        sc_runtime_t,
        sc_value_t,
        char *,
        uint64_t,
        uint64_t *
    );

    sc_status_t (SC_CALL *value_get_host_ref)(
        sc_runtime_t,
        sc_value_t,
        sc_host_ref_t *,
        uint32_t *host_kind
    );

    /* host proxies */
    sc_status_t (SC_CALL *host_object_new)(
        sc_runtime_t,
        sc_host_ref_t,
        uint32_t host_kind,
        sc_value_t *
    );

    sc_status_t (SC_CALL *host_function_new)(
        sc_runtime_t,
        sc_host_func_t,
        sc_value_t *
    );

    /* function invocation */
    sc_status_t (SC_CALL *function_call)(
        sc_runtime_t,
        sc_value_t function,
        sc_value_t this_value,
        const sc_value_t *argv,
        uint64_t argc,
        sc_value_t *out
    );

    /* lifetime */
    sc_status_t (SC_CALL *value_retain)(
        sc_runtime_t,
        sc_value_t
    );

    void (SC_CALL *value_release)(
        sc_runtime_t,
        sc_value_t
    );

    sc_status_t (SC_CALL *last_error_copy)(
        sc_runtime_t,
        char *,
        uint64_t,
        uint64_t *
    );
} sc_runtime_api_v1;
```

这是 v1 的核心。

---

# 10. Host API vtable

方向是：

```text
runtime plugin
      ↓
Scardice Core
```

不要暴露 Dice。

只暴露反射对象系统。

```c
typedef struct sc_host_api_v1 {
    uint32_t struct_size;
    uint32_t abi_major;
    uint32_t abi_minor;

    sc_status_t (SC_CALL *host_get)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_host_ref_t,
        sc_string_view key,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *host_set)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_host_ref_t,
        sc_string_view key,
        sc_value_t value
    );

    sc_status_t (SC_CALL *host_has)(
        sc_host_ctx_t,
        sc_host_ref_t,
        sc_string_view key,
        uint32_t *out
    );

    sc_status_t (SC_CALL *host_delete)(
        sc_host_ctx_t,
        sc_host_ref_t,
        sc_string_view key,
        uint32_t *deleted
    );

    sc_status_t (SC_CALL *host_keys_json)(
        sc_host_ctx_t,
        sc_host_ref_t,
        char *buffer,
        uint64_t capacity,
        uint64_t *required
    );

    sc_status_t (SC_CALL *host_call)(
        sc_host_ctx_t,
        sc_runtime_t,
        sc_host_func_t,
        sc_value_t this_value,
        const sc_value_t *argv,
        uint64_t argc,
        sc_value_t *out
    );

    sc_status_t (SC_CALL *last_error_copy)(
        sc_host_ctx_t,
        char *buffer,
        uint64_t capacity,
        uint64_t *required
    );
} sc_host_api_v1;
```

---

# 11. 为什么 Host API 返回 `sc_value_t`

这是整个设计的关键。

当前 QuickJS compatibility bridge 已经在做：

```text
Go reflect.Value
      ↓
QuickJS JSValue
```

并且会处理：

```text
struct
pointer
jsbind tags
map Proxy
slice Proxy
Go func
JS func → reflect.MakeFunc
```

([GitHub][9])

新的 HostBridge 仍然在 Core 做 reflection，但：

```text
Go value
   ↓
hostbridge
   ↓
runtime vtable
   ↓
sc_value_t
```

比如：

```go
func convertToRuntime(v reflect.Value) sc_value_t
```

内部：

```text
string
→ value_new_string()

int
→ value_new_i64()

pointer to struct
→ HostRef allocation
→ host_object_new()

map
→ HostRef allocation
→ host_object_new(kind=MAP)

slice
→ HostRef allocation
→ host_object_new(kind=SLICE)

Go func
→ HostFuncRef allocation
→ host_function_new()
```

这正好保住你现在“同一套 Goja Host API 定义写法”。

---

# 12. HostRef Registry

Core：

```go
type Registry struct {
    nextHostRef atomic.Uint64
    nextFuncRef atomic.Uint64

    objects map[HostRef]reflect.Value
    funcs   map[HostFuncRef]reflect.Value
}
```

所有 C 侧只看到：

```text
42
58
127
```

绝对看不到：

```text
0xc000123456
```

HostRef 在：

```text
一个 runtime session
```

生命周期内有效。

v1 不做复杂 reference counting。

runtime 关闭时统一释放。

这基本符合当前 QuickJS host storage 的生命周期模式。([GitHub][9])

---

# 13. JS function → Go func

这是最需要单独设计的路径。

例如：

```go
type ExtInfo struct {
    OnCommandReceived func(...)
}
```

JS：

```js
ext.onCommandReceived = function(ctx, msg) {
    ...
}
```

HostBridge 看到 Go 目标类型是：

```text
func(...)
```

而输入 `sc_value_t` 是 JS function。

执行：

```text
value_retain(jsFunction)
        ↓
PersistentFunction {
    runtimeSession
    valueHandle
    generation
}
        ↓
reflect.MakeFunc()
```

Go 以后调用这个 func：

```text
reflect.MakeFunc trampoline
          ↓
runtime function_call()
          ↓
QuickJS worker
          ↓
JS callback
```

替换字段时：

```text
release old retained value
retain new value
```

runtime close：

```text
release all PersistentFunction values
```

这就是现有 QuickJS `newCallback()` + `reflect.MakeFunc()` 思路的 C ABI 化。([GitHub][9])

---

# 14. Callback generation

保留并强化当前 `JsLoopManager.version` 思路。

```go
type RuntimeSession struct {
    generation uint64
}
```

PersistentFunction 保存：

```go
generation uint64
```

调用时：

```go
if callback.generation != session.generation {
    return ErrStaleRuntimeCallback
}
```

防止：

```text
JS runtime reload
 ↓
旧 ExtInfo callback 仍被 Go 保存
 ↓
访问已经销毁的 sc_value_t
```

---

# 15. Runtime Value 生命周期

当前 `jsengine.Runtime` 已经明确要求 `Value` 不逃出 runtime callback。([GitHub][10])

保留这个优秀约束。

Native provider：

```go
loop.Run(func(rt Runtime) error {
    ...
})
```

进入时创建：

```go
nativeScope
```

每个 ABI 返回的 `sc_value_t`：

```text
自动登记到 scope
```

callback 返回：

```text
scope.releaseAll()
```

除非：

```text
value_retain()
```

变成 PersistentFunction 等长期对象。

不要依赖 Go finalizer 保证正确性。

---

# 16. QuickJS Provider 的线程模型

QuickJS provider 建议直接用 C++ 实现。

目录：

```text
runtime-plugins/quickjs/
├── CMakeLists.txt
├── include/
├── src/
│   ├── plugin.cpp
│   ├── runtime.cpp
│   ├── worker.cpp
│   ├── value_table.cpp
│   ├── host_object.cpp
│   ├── host_function.cpp
│   ├── module_loader.cpp
│   ├── event_loop.cpp
│   └── errors.cpp
│
├── js/
│   └── bootstrap/
│
└── third_party/
    └── quickjs/
```

每个 runtime instance：

```text
ScRuntime
│
├── one QuickJS JSRuntime
├── one JSContext
├── one worker OS thread
├── one task queue
├── timer/event loop
├── value handle table
└── host API pointer
```

所有 QuickJS API 都只在这个 worker thread 上执行。

---

# 17. Runtime call 调度

Core goroutine：

```text
function_call()
      ↓
C ABI
      ↓
QuickJS provider
      ↓
enqueue
      ↓
worker thread
      ↓
JS_Call()
      ↓
signal result
```

调用方同步等待。

因此 ABI 看起来同步，但 runtime 内部有 thread affinity。

---

# 18. Reentrancy 必须作为 ABI 语义明确下来

非常重要。

调用链可能是：

```text
QuickJS
 ↓
host function
 ↓
C → Go callback
 ↓
Go method
 ↓
调用一个 JS callback
 ↓
Go → C
 ↓
QuickJS
```

如果第二次 C 调用又 enqueue + 等 worker：

```text
worker 等 Go
Go 等 worker
```

直接死锁。

因此 QuickJS provider：

```cpp
if (std::this_thread::get_id() == runtime->workerThreadId) {
    executeInline();
} else {
    enqueueAndWait();
}
```

ABI 文档明确：

以下操作允许 host callback 期间 reentrant：

```text
value_new_*
value_type
value_to_*
host_object_new
host_function_new
value_retain
value_release
function_call
object_get
object_set
```

禁止 reentrant：

```text
create
start
stop
destroy
load_entry
```

必须写专门测试覆盖。

---

# 19. QuickJS Value Handle Table

绝对不要把：

```text
JSValue
JSObject*
JSContext*
```

跨 ABI。

Provider 内：

```cpp
uint64_t nextValueId;

unordered_map<uint64_t, ValueEntry> values;
```

例如：

```cpp
struct ValueEntry {
    JSValue value;
    uint32_t refs;
};
```

API 返回：

```text
sc_value_t = 114514
```

retain：

```text
refs++
```

release：

```text
--refs
if 0:
    JS_FreeValue()
```

runtime destroy 时 assert：

```text
没有异常 persistent handle
```

release build 可以强制清理，debug build 报 leak。

---

# 20. QuickJS Host Object

JS：

```js
ctx.player.name
```

内部：

```text
QuickJS Proxy/Class
      ↓
HostRef=42
      ↓
host_get(42, "player")
      ↓
Core HostBridge
      ↓
reflect
      ↓
HostRef=43
      ↓
host_object_new(43)
```

map/slice/struct 的行为全部由 Core HostBridge 决定。

QuickJS provider 只负责把操作转发。

这样以后：

```text
Lua provider
Python provider
V8 provider
```

可以复用同一套 Go HostBridge。

---

# 21. `jsbind` 兼容层迁移

当前 QuickJS `host.go` 做的 reflection 工作，拆到：

```text
utils/jsengine/hostbridge/
```

第一阶段严格按当前语义迁移，不趁机“优化设计”。

必须覆盖：

```text
jsbind tag
jsbindlock
pointer-to-struct
struct copy semantics
map get/set/delete
map ownKeys
slice numeric access
slice length
slice push
Go method binding
Go func
JS function → Go func
pointer identity
host object identity
error return
panic recovery
```

现有实现大量基于 `reflect.Value` 和 Proxy，这正是应该从 QuickJS-specific adapter 抽出来的部分。([GitHub][9])

---

# 22. Goja 不需要走 C ABI

不要犯这个错误：

```text
为了统一
↓
Goja builtin
↓
也绕一圈 C ABI
```

没必要。

结构应该是：

```text
               jsengine.Runtime
                 /        \
                /          \
       GojaAdapter      NativeAdapter
           │                │
      direct Go         C ABI
```

对 Dice 而言统一即可。

---

# 23. 但是 JsLoopManager 要统一

最终：

```go
type JsLoopManager struct {
    mu sync.RWMutex

    loop       jsengine.Loop
    generation uint64
}

func (m *JsLoopManager) SetLoop(loop jsengine.Loop) uint64

func (m *JsLoopManager) GetLoop(
    expectedGeneration uint64,
) (jsengine.Loop, error)

func (m *JsLoopManager) Close() error
```

删除：

```text
GetWebLoop
GetEngineLoop
SetEngineLoop
*eventloop.EventLoop field
```

Goja Provider 自己持有其 Goja eventloop。

---

# 24. `callWithJsCheck()` 统一

不要再：

```go
if goja ...
if quickjs ...
```

统一变成：

```go
func (d *Dice) callWithJSCheck(
    ext *ExtInfo,
    f func(),
) error {
    loop, err := d.ExtLoopManager.GetLoop(ext.JSLoopVersion)
    if err != nil {
        return err
    }

    return loop.Run(func(runtime jsengine.Runtime) error {
        f()
        return nil
    })
}
```

Goja：

```text
Loop.Run
→ RunOnLoop
→ f()
```

Native QuickJS：

```text
Loop.Run
→ runtime scope
→ f()
→ JS PersistentFunction trampoline
→ C ABI
```

这样 Core 层没有 engine branching。

---

# 25. Runtime Library Loader

## Unix

```text
dlopen(path, RTLD_NOW | RTLD_LOCAL)
dlsym(handle, "scardice_runtime_query_v1")
```

## Windows

使用绝对路径：

```text
LoadLibraryExW
GetProcAddress
```

不要依赖：

```text
CWD DLL search
PATH 中偶然找到同名 DLL
```

DLL dependency lookup 应限制在：

```text
runtime package directory
system trusted dirs
```

Windows ABI 固定：

```text
__cdecl
```

---

# 26. 为什么 Core 需要一个小 C shim

Go 不能优雅、可移植地直接调用：

```text
vtable 中随 dlopen 得到的 C function pointer
```

所以：

```text
Go
 ↓
bridge.c
 ↓
api->function(...)
```

例如：

```c
sc_status_t sc_call_runtime_eval(
    const sc_runtime_api_v1 *api,
    sc_runtime_t runtime,
    sc_string_view filename,
    sc_string_view source,
    sc_value_t *out
) {
    return api->eval(
        runtime,
        filename,
        source,
        out
    );
}
```

Go 只调用：

```go
C.sc_call_runtime_eval(...)
```

---

# 27. C → Go Host callback

不要把 Go function pointer直接塞到插件。

Core C shim 里生成：

```c
static sc_status_t core_host_get(...) {
    return sc_go_host_get(...);
}
```

其中：

```c
sc_go_host_get
```

是 `//export` Go callback。

然后静态：

```c
static const sc_host_api_v1 host_api = {
    ...
    .host_get = core_host_get,
    ...
};
```

插件拿：

```text
const sc_host_api_v1*
```

这个表。

注意 cgo 的 `//export` 文件中不要把 C definitions 塞在 preamble；官方明确指出这会导致重复定义，具体实现放独立 `.c` 文件。([Go 语言][3])

---

# 28. `host_ctx` 不允许是 Go pointer

不要：

```c
void *ctx = &goObject;
```

改成：

```go
type HostContextID uint64
```

Core：

```go
map[uint64]*HostSession
```

C：

```text
host_ctx = 123
```

callback 回 Go：

```go
session := registry.Resolve(123)
```

---

# 29. ABI Query

DLL 只导出一个稳定 symbol：

```c
SC_EXPORT
sc_status_t SC_CALL
scardice_runtime_query_v1(
    const sc_runtime_query_v1 *query,
    const sc_runtime_plugin_v1 **out_plugin
);
```

Query：

```c
typedef struct sc_runtime_query_v1 {
    uint32_t struct_size;

    uint32_t runtime_abi_major;
    uint32_t runtime_abi_minor;

    uint32_t host_abi_major;
    uint32_t host_abi_minor;
} sc_runtime_query_v1;
```

返回：

```c
typedef struct sc_runtime_plugin_v1 {
    uint32_t struct_size;

    sc_runtime_descriptor_v1 descriptor;
    sc_runtime_api_v1 api;
} sc_runtime_plugin_v1;
```

整个对象 static const。

---

# 30. ABI Versioning 规则

必须从第一版分开四个版本域：

| 版本              | 控制什么                                  |
| --------------- | ------------------------------------- |
| Runtime ABI     | Core ↔ runtime DLL 的二进制协议             |
| Host ABI        | runtime ↔ HostBridge/service callback |
| Seal JS API     | `seal.*` 用户脚本兼容                       |
| Runtime Version | QuickJS provider 本身版本                 |

绝对不要这样：

```text
Scardice 1.5.2
= ABI 1.5.2
= JS API 1.5.2
= QuickJS plugin 1.5.2
```

ABI：

```text
major != 1 → reject
reserved minor != 0 → reject
major == 1 → validate struct_size + capabilities
```

每个 struct 有：

```text
struct_size
```

v1 内只能追加可选字段或函数指针；消费者必须先检查
`struct_size`，再按 capability 判断该尾部是否必需。不提供另一个
v1.x 公共头，也不通过 minor 协商功能。不允许 reorder。

ABI v2 时直接新 symbol：

```text
scardice_runtime_query_v2
```

---

# 31. Capability

定义 bitmask：

```text
SC_CAP_SCRIPT
SC_CAP_COMMONJS
SC_CAP_ESM
SC_CAP_PROMISE
SC_CAP_TIMERS
SC_CAP_HOST_OBJECT
SC_CAP_HOST_FUNCTION
SC_CAP_ASYNC_HOST_SERVICE
SC_CAP_SOURCE_LOCATION
```

Dice 不检查：

```go
engine == quickjs
```

只检查：

```go
provider.Capabilities().Has(...)
```

---

# 32. Manifest

安装：

```text
runtimes/
└── quickjs/
    ├── runtime.json
    ├── scardice-runtime-quickjs.dll
    └── ...
```

示例：

```json
{
  "schema": 1,

  "id": "quickjs",
  "name": "QuickJS",
  "version": "0.1.0",

  "language": "javascript",

  "runtimeAbi": {
    "major": 1
  },

  "hostAbi": {
    "major": 1
  },

  "libraries": {
    "windows-amd64": "scardice-runtime-quickjs.dll",
    "linux-amd64": "libscardice-runtime-quickjs.so",
    "linux-arm64": "libscardice-runtime-quickjs.so",
    "darwin-amd64": "libscardice-runtime-quickjs.dylib",
    "darwin-arm64": "libscardice-runtime-quickjs.dylib"
  }
}
```

Manifest 是 discovery metadata。

**DLL descriptor 才是 authoritative。**

两边 ID/version 对不上：

```text
reject
```

---

# 33. Discovery Policy

默认搜索：

```text
<executable-dir>/runtimes/*/runtime.json
```

以后可以增加管理员配置：

```text
JsRuntimeSearchPaths
```

但 v1 不要搜索：

```text
extensions/
plugins/
data/extensions/
CWD
/tmp
用户上传目录
```

native runtime 是整个进程权限的本地代码。

---

# 34. Duplicate ID Policy

例如：

```text
builtin goja
external goja
```

v1：

```text
reject duplicate
```

不要允许 DLL 静默覆盖 builtin。

同理：

```text
runtimes/quickjs-a
runtimes/quickjs-b

都声明 id=quickjs
```

启动解析 candidate 时报告冲突。

---

# 35. 不 unload DLL

这是硬设计。

运行时：

```text
QuickJS realm reload
→ destroy ScRuntime
→ create ScRuntime
```

可以。

但是：

```text
FreeLibrary
dlclose
```

v1 禁止。

理由包括：

```text
function pointer
static descriptor
callbacks
thread-local storage
native runtime globals
future third-party runtime behavior
```

全部可能在 unload 时产生悬空。

升级 runtime binary：

```text
restart Scardice
```

即可。

---

# 36. QuickJS-Go 怎么处理

现有 QuickJS-Go 代码不要立刻删。

它的角色改变成：

```text
behavior oracle
```

也就是：

```text
legacy QuickJS-Go
        │
        ├── compatibility tests
        ├── Host API expected behavior
        ├── callback behavior
        ├── module behavior
        └── resource limit behavior
             ↓
new C++ QuickJS runtime
```

等测试 parity 通过后再删除。

这能守住现有 experimental 分支已经做的大量兼容工作，而不是重新凭感觉实现一次。

---

# 37. QuickJS runtime 不得 import Scardice Go code

最终 external QuickJS provider：

```text
runtime-plugins/quickjs/
```

绝不能 import：

```text
Scardice-core/dice
Scardice-core/utils/jsengine
Scardice-core/utils/jsengine/hostbridge
```

唯一共享代码：

```text
scardice_runtime_v1.h
```

以及可选纯 JS compatibility scripts。

这才叫 ABI。

---

# 38. Runtime-specific options

当前 `JsConfig` 里直接塞了一批 QuickJS 字段，例如 memory limit、stack、fetch、websocket、filesystem、PBKDF2 限制。([GitHub][11])

目标增加：

```go
JsRuntimeOptions map[string]json.RawMessage
```

配置：

```json
{
  "jsEngine": "quickjs",

  "jsRuntimeOptions": {
    "quickjs": {
      "memoryLimitMiB": 256,
      "gcThresholdMiB": 64,
      "maxStackSizeKiB": 1024,
      "executeTimeoutSeconds": 30
    }
  }
}
```

Core 不解释这些字段。

它只把：

```text
quickjs JSON object
```

原样通过：

```text
sc_runtime_create_info_v1.options_json
```

传给 plugin。

---

# 39. 配置迁移

至少保留一个 release cycle：

```text
QuickJSMemoryLimitMiB
QuickJSGCThresholdMiB
...
```

兼容规则：

```text
旧字段存在
    ↓
转换成 quickjs options

新 jsRuntimeOptions 同时存在
    ↓
新字段优先
    ↓
日志 warning
```

下一大版本再删除旧字段。

---

# 40. Host services 和 Node-like modules

这里不要把问题混为一谈。

有两层：

```text
A. Go object reflection bridge
B. console/fs/http/fetch/websocket/crypto 等 service
```

A 在 runtime ABI v1 必须完成。

B 单独抽象。

当前 Goja 初始化会注册 console、crypto、HTTP、fetch、fs 等一系列 engine-specific 模块。([GitHub][5])

不能让 external QuickJS DLL：

```text
反过来调用 Goja module
```

正确方向是：

```text
Core
│
└── Host Services
    ├── filesystem policy
    ├── HTTP policy
    ├── logging
    ├── RNG
    └── plugin identity

Goja
└── Goja-specific JS shim

QuickJS
└── QuickJS-specific JS shim
```

底层 policy/service 共享。

---

# 41. Host Service ABI 暂时不要过度设计

第一轮 externalization 的验收目标：

> 与当前 experimental QuickJS 行为保持 parity。

Code Agent 先制作：

```text
docs/runtime-abi/quickjs-parity.md
```

列：

| Feature         | legacy QuickJS-Go | new QuickJS native |
| --------------- | ----------------: | -----------------: |
| seal.*          |                   |                    |
| CommonJS        |                   |                    |
| ESM             |                   |                    |
| Promise         |                   |                    |
| timer           |                   |                    |
| console         |                   |                    |
| crypto          |                   |                    |
| fetch           |                   |                    |
| websocket       |                   |                    |
| fs              |                   |                    |
| abort           |                   |                    |
| structuredclone |                   |                    |
| utilinspect     |                   |                    |

只有当前 experimental path 支持的内容才是第一阶段 blocker。

不要顺手要求：

```text
QuickJS 必须达到完整 Node.js
```

---

# 42. Phase 0 — Baseline

Code Agent 第一件事：

```bash
git checkout quickjs-experimental-20260901

go version
go env CGO_ENABLED GOOS GOARCH CC

git status

rg -n \
  'jsInitQuickJS|configuredJSEngine|isQuickJSExperiment|EngineQuickJS' \
  .

rg -n \
  'GetWebLoop|GetEngineLoop|SetEngineLoop|RunOnLoop' \
  dice utils

rg -n '\.Export\(' .

go test ./utils/jsengine/...
go test ./dice/...
go test -race ./...
```

记录任何已有失败：

```text
docs/runtime-abi/architecture.md
```

不要把已有失败误认为本次改造引入。

我从当前 web-visible snapshot 能看到 `jsInitQuickJS()` 的调用，但可见的 `dice_jsvm.go` 中没有对应实现体，因此 Code Agent 必须以本地 checkout 为权威做一次完整 symbol inventory。([GitHub][5])

---

# 43. Phase 1 — Provider Registry

实施：

```text
provider.go
descriptor.go
registry.go
capability.go
entry.go
```

Goja 注册成：

```go
RegisterBuiltin(goja.Provider())
```

修改 EngineID：

```text
不再 hardcode QuickJS
```

此阶段：

```text
不改变现有 JS 行为
```

测试：

```text
default engine → goja
unknown runtime → ErrProviderNotFound
duplicate builtin → error
duplicate runtime id → error
normalization
descriptor lookup
```

验收：

```bash
go test ./utils/jsengine/...
go test ./dice/...
go test -race ./...
```

---

# 44. Phase 2 — Freeze ABI Header

创建：

```text
runtimeabi/
├── include/
│   └── scardice_runtime_v1.h
├── README.md
├── ABI.md
└── CHANGELOG.md
```

写清：

```text
ownership
threading
reentrancy
version negotiation
status
string lifetime
value lifetime
host callback lifetime
no unload
```

同时添加 C/C++：

```c
static_assert(...)
```

检查关键 struct offset/size。

Windows/MSVC、MinGW、GCC、Clang 不允许出现 bitfield/enum-size ABI 差异。

---

# 45. Phase 3 — Fake C Runtime

**先不要碰 QuickJS。**

创建极小测试 provider：

```text
runtimeabi/testdata/echo-runtime/
├── CMakeLists.txt
└── echo_runtime.c
```

支持：

```text
create
destroy
eval primitive
global get/set
object get/set
host callback
function callback
retain/release
error
```

这一步专门证明：

```text
C ABI 本身成立
```

而不是“QuickJS 恰好能跑”。

---

# 46. Phase 4 — Native Loader

实现：

```text
utils/jsengine/native/
```

包括：

```text
dlopen / LoadLibrary
query symbol
ABI negotiation
descriptor verification
manifest verification
native Provider
```

测试错误情况：

```text
missing library
missing query symbol
ABI major mismatch
host ABI mismatch
manifest ID mismatch
descriptor ID mismatch
unsupported architecture
create error
corrupt vtable
too-small struct_size
```

---

# 47. Phase 5 — !cgo fallback

新增：

```go
//go:build !cgo
```

实现：

```go
var ErrNativeRuntimeUnsupported = ...
```

`CGO_ENABLED=0`：

```text
Goja 正常
runtime manifests 可以扫描
实际加载 native provider → 可诊断错误
```

验收：

```bash
CGO_ENABLED=0 go test ./...
```

这很重要，因为“支持 native runtime”不应该让整个 Core 在无 C toolchain 环境下直接不能编译。

---

# 48. Phase 6 — HostBridge extraction

把当前 QuickJS `host.go` 的 reflection 逻辑迁移到：

```text
utils/jsengine/hostbridge
```

此时仍可暂时让 legacy QuickJS adapter 使用新 HostBridge。

目标是先证明：

```text
抽象没有改变现有 QuickJS 行为
```

添加单元测试：

```text
struct getter
struct setter
jsbind
jsbindlock
method
pointer identity
map
slice
nested host object
Go func
JS callback
error return
panic recovery
nil pointer
invalid type
```

---

# 49. Phase 7 — Native Runtime Adapter

实现：

```text
nativeLoop
nativeRuntime
nativeValue
nativeObject
nativeScope
```

要求它实现当前：

```go
jsengine.Loop
jsengine.Runtime
jsengine.Value
jsengine.Object
```

Core 其余代码继续面对 Go interface。

C ABI 只是 native provider 的实现细节。

---

# 50. `Export()` 在这一阶段专门审计

当前接口：

```go
Export() interface{}
```

它本质上不够适合作为跨 runtime 的强契约。

Code Agent 先：

```bash
rg -n '\.Export\(' .
```

分类实际需求。

如果只需要：

```text
primitive
HostRef
```

native provider 实现这些即可。

如果 Core 确实要求：

```text
任意 JS object → Go object
```

不要随便 JSON stringify。

改成显式 API，例如：

```go
ExportPrimitive() (any, error)
```

或增加明确转换方法并迁移调用点。

不要在 ABI 中定义“神奇 Export”。

---

# 51. Phase 8 — Callback Dispatcher 统一

先让：

```text
JsLoopManager
```

只存：

```go
jsengine.Loop
```

迁移：

```text
callWithJsCheck
OnMessagePreprocess
Solve
command callbacks
extension callbacks
```

全部只经过：

```text
jsengine.Loop
```

删除 QuickJS/Goja 二分判断。

现有 `ExtInfo`/`CmdItemInfo` 里 legacy Goja callback 和 engine-neutral callback 并存，所以这一阶段必须单独做，不要和 DLL loader 混在一个 PR。

---

# 52. Phase 9 — QuickJS C++ Runtime Skeleton

这时候才开始真正 QuickJS DLL。

先只实现：

```text
create
destroy
worker thread
eval
ESM
CommonJS if required
primitive conversion
object
host proxy
host function
function callback
exception
retain/release
```

不要第一天就移植 fetch/websocket。

验收最小 JS：

```js
1 + 2
```

然后：

```js
seal
```

再：

```js
seal.ext.new(...)
```

最后：

```js
ext.someCallback = () => ...
```

---

# 53. Phase 10 — Host proxy parity

对照旧 QuickJS-Go：

```text
struct
map
slice
func
callback
```

运行同一组测试。

特别覆盖：

```js
obj.foo
obj.foo = 1

Object.keys(obj)

delete map.foo

slice[0]
slice[0] = x
slice.length
slice.push(...)

obj.method(...)
```

旧 QuickJS host bridge 已经明确通过 Proxy/reflection 实现 map 和 slice 等行为，因此这些应当做成自动 parity tests，而不是人工验证。([GitHub][9])

---

# 54. Phase 11 — Reentrant Callback Tests

至少做以下测试：

### A

```text
Go → JS
```

### B

```text
JS → Go
```

### C

```text
Go → JS → Go
```

### D

```text
JS → Go → JS
```

### E

```text
Go → JS → Go → JS
```

### F

runtime reload 后：

```text
old callback invoked
→ deterministic stale callback error
```

### G

callback 中发生：

```text
panic
JS exception
runtime timeout
```

不能死锁。

---

# 55. Phase 12 — QuickJS event loop

实现：

```text
Promise jobs
timer queue
async completion queue
shutdown cancellation
```

每完成一次：

```text
JS command
timer
async event
```

适当执行：

```text
JS_ExecutePendingJob
```

直到收敛或达到安全阈值。

runtime stop：

```text
reject new work
cancel timers
cancel async requests
drain/abort queue
wait active callback
```

---

# 56. Phase 13 — Current QuickJS feature parity

建立 black-box fixture corpus。

把当前 experimental QuickJS-Go 当 oracle：

```text
old implementation output
new native implementation output
```

重点：

```text
module loading
Promise
timers
seal.*
extension registration
events
error stack
resource limit behavior
```

允许底层 error string 不完全一致。

但：

```text
observable JS behavior
```

必须对齐。

---

# 57. Phase 14 — Host Services

再处理：

```text
console
crypto
fetch
HTTP
websocket
filesystem
abort
structured clone
util inspect
```

建议新增：

```text
ScHostServices
```

而不是把这些东西全塞进 reflection Host API。

逻辑：

```text
Reflection Host API
→ 高频、对象绑定

Host Services
→ IO、系统服务、权限策略
```

如果 async service 需要 ABI：

```text
host_service_start(...)
       ↓
operation_id

Core async work

runtime_async_complete(
    runtime,
    operation_id,
    result
)
```

QuickJS provider收到 completion：

```text
enqueue worker
→ resolve/reject Promise
```

---

# 58. Phase 15 — QuickJS Resource Limits

把当前 QuickJS-specific config 映射进 plugin options：

```text
memory
GC threshold
stack
execution timeout
fetch concurrency
fetch response size
websocket limits
filesystem limits
PBKDF2 limits
```

这些字段当前已经在 `JsConfig` 中。([GitHub][11])

QuickJS provider解析自己的 JSON：

```cpp
QuickJSOptions
```

Core 不认识其内部语义。

---

# 59. Phase 16 — Cutover

在这一步之前：

```text
legacy QuickJS-Go
new QuickJS native
```

都存在。

临时测试 ID 可以叫：

```text
quickjs-native
```

不要让用户长期看到。

Parity 全部通过后：

```text
old quickjs → 删除
new native quickjs → id=quickjs
```

然后执行：

```bash
go mod tidy

go list -deps ./... \
  | rg 'buke/quickjs-go|Scardice/quickjs_nodejs'
```

输出必须为空。

以及：

```bash
rg -n \
  'jsengine/quickjs|quickjs-go|quickjs_nodejs' \
  --glob '!runtime-plugins/quickjs/**' \
  .
```

除文档/迁移记录外必须为空。

这正是判断“QuickJS 是否真的外置”的硬指标。

---

# 60. Phase 17 — 删除 engine branching

全仓：

```bash
rg -n \
  'EngineQuickJS|EngineGoja|==.*quickjs|==.*goja' \
  .
```

允许存在：

```text
builtin Goja provider registration
default config = goja
migration code
tests
```

不允许出现在：

```text
Dice execution
script loader
extension callback
message dispatch
runtime lifecycle
```

---

# 61. Phase 18 — Distribution

最终发行：

```text
Scardice-core.zip

Scardice-runtime-quickjs-windows-amd64.zip
Scardice-runtime-quickjs-linux-amd64.tar.gz
Scardice-runtime-quickjs-linux-arm64.tar.gz
Scardice-runtime-quickjs-darwin-arm64.tar.gz
...
```

QuickJS runtime 包：

```text
quickjs/
├── runtime.json
├── LICENSES/
├── scardice-runtime-quickjs.*
└── optional assets
```

用户只需要解压：

```text
runtimes/quickjs/
```

---

# 62. Runtime Manager diagnostics

至少提供：

```go
type RuntimeStatus struct {
    ID          string
    Installed   bool
    Loaded      bool
    Builtin     bool

    Version     string
    ABI         string
    Path        string

    Capabilities []string

    Error string
}
```

这样 UI/日志可以显示：

```text
goja
builtin
available

quickjs
external
0.1.0
Runtime ABI v1
loaded from ...
```

错误也可以明确：

```text
QuickJS runtime installed but incompatible:
plugin requires Host ABI v2, Core provides v1
```

---

# 63. Native plugin 信任边界

必须在文档里明确：

```text
JS Extension
≠
Runtime Plugin
```

JS Extension：

```text
受 runtime / permissions 控制
```

Runtime Plugin：

```text
原生 DLL
进程内任意代码执行
与 Scardice 同权限
```

因此 runtime package 不应该允许普通 JS 插件自动安装。

以后可以增加：

```text
signature
SHA-256 manifest
trusted publisher
```

但不是 ABI v1 blocker。

---

# 64. Shutdown 顺序

固定：

```text
1. mark RuntimeSession closing

2. reject new Loop.Run

3. cancel Core-owned async operations

4. provider.stop()
   └── stop timers
   └── stop async callbacks
   └── wait in-flight runtime work

5. release PersistentFunction handles

6. release remaining scoped/persistent sc_value_t

7. provider.destroy()

8. clear HostRef / HostFuncRef registry

9. increment generation

10. DO NOT unload DLL
```

顺序不要随意修改。

---

# 65. Panic / exception 边界

C → Go：

```go
//export ...
func hostCallback(...) (ret C.int32) {
    defer func() {
        if v := recover(); v != nil {
            storeHostError(...)
            ret = C.SC_EHOST
        }
    }()
```

C++ API：

```cpp
extern "C" sc_status_t api_call(...) noexcept {
    try {
        ...
    } catch (const std::bad_alloc &) {
        return SC_EOOM;
    } catch (...) {
        return SC_EINTERNAL;
    }
}
```

QuickJS exception：

```text
JS exception
→ extract stack/message
→ runtime last_error
→ SC_EEXCEPTION
```

---

# 66. CI

当前项目 CI 已经在 Ubuntu + Go 1.25 下执行 `go test -race ./...`、vet 和 lint。([GitHub][12])

扩充成：

| Job             | 内容                            |
| --------------- | ----------------------------- |
| Go Core Linux   | `go test -race ./...`         |
| Core no-cgo     | `CGO_ENABLED=0 go test ./...` |
| ABI C smoke     | build/load echo runtime       |
| QuickJS Linux   | CMake + tests                 |
| Windows ABI     | DLL loader integration        |
| Windows QuickJS | build/load QuickJS            |
| macOS ABI       | dylib loader                  |
| macOS QuickJS   | QuickJS integration           |
| ASan/UBSan      | C++ runtime                   |
| module graph    | QuickJS deps不得泄漏到Core         |

不要依赖 cross compilation 验证 ABI。

Windows/macOS 使用 native runner。

---

# 67. ABI compatibility CI

不保留第二份公开头。兼容夹具使用当前 v1 头构造较短的
`struct_size` 前缀表：

```text
current Core
+
v1 provider with omitted optional tails
```

必须加载。反向兼容通过独立 host fixture 验证：

```text
v1 host fixture
+
current v1 plugin
```

仅当 capability 需要缺失的尾部字段时才拒绝。

---

# 68. 性能基准

增加：

```text
BenchmarkNativePrimitiveGet
BenchmarkNativePrimitiveSet
BenchmarkNativeHostPropertyGet
BenchmarkNativeHostMethod
BenchmarkNativeCallback
BenchmarkNativeNestedCallback
BenchmarkGojaEquivalent
```

关注：

```text
Cgo crossings / operation
```

v1 先以 correctness 为优先。

若以后发现 host property 访问过多，再增加：

```text
bulk operations
cached property descriptors
batched calls
```

不要现在提前复杂化 ABI。

---

# 69. Definition of Done

只有全部满足才能称为完成：

```text
[ ] Goja builtin 正常
[ ] Goja 仍是默认
[ ] EngineID 不再 hardcode QuickJS
[ ] Provider Registry 成为 runtime 入口
[ ] Dice 不 import QuickJS
[ ] Dice 没有 QuickJS-specific branching
[ ] JsLoopManager 只有 jsengine.Loop
[ ] C ABI v1 header frozen
[ ] Linux loader 工作
[ ] Windows loader 工作
[ ] macOS loader 工作
[ ] !cgo Core 可以运行 Goja
[ ] HostRef 不暴露 Go pointer
[ ] JS function callback 可以跨 ABI
[ ] nested callback 不死锁
[ ] stale callback 被拒绝
[ ] runtime reload 不泄漏 retained value
[ ] runtime library 不 unload
[ ] fake C provider integration tests 通过
[ ] native QuickJS provider 通过
[ ] current experimental QuickJS parity tests 通过
[ ] QuickJS options 外置
[ ] root go.mod 不依赖 quickjs-go
[ ] root module graph 不依赖 quickjs_nodejs
[ ] 删除 utils/jsengine/quickjs
[ ] QuickJS runtime 可以后安装
[ ] 显式选择缺失 QuickJS 时不 silent fallback
[ ] runtime diagnostics 能显示 ABI/version/path/error
[ ] CI 覆盖 Linux/Windows/macOS
```

---

# 70. 推荐提交边界

不要一整个巨型 PR。

建议：

```text
Commit 1
jsengine provider registry

Commit 2
runtime ABI v1 + fake C provider

Commit 3
native loader + native Runtime adapter

Commit 4
hostbridge extraction

Commit 5
callback / JsLoopManager unification

Commit 6
QuickJS native skeleton

Commit 7
QuickJS Host API parity

Commit 8
QuickJS async/module parity

Commit 9
external QuickJS cutover

Commit 10
remove legacy QuickJS-Go + config cleanup

Commit 11
distribution + cross-platform CI
```

每个 Commit 独立可验证。

---

# 71. Code Agent 执行优先级

如果让 Agent 从这一刻直接开始，我会要求它严格按：

```text
P0 baseline
 ↓
P1 Provider Registry
 ↓
P2 ABI header
 ↓
P3 fake C runtime
 ↓
P4 native loader
 ↓
P5 HostBridge
 ↓
P6 callback unification
 ↓
P7 C++ QuickJS
 ↓
P8 parity
 ↓
P9 cutover
 ↓
P10 dependency removal
```

不要先写 QuickJS DLL。

**fake C runtime 能完整跑通 HostRef + callback + retain/release 以后，C ABI 才算经过验证。**

---

# 72. 两个明确退出阈值

### ABI 设计停止扩张的阈值

一旦以下路径成立：

```text
eval
object
host property
host method
Go → JS
JS → Go
JS → Go → JS
persistent callback
runtime reload
```

就冻结 ABI v1。

不要因为：

```text
fetch
websocket
某个 QuickJS module
```

继续往核心 runtime ABI 塞东西。

那些属于 Host Service。

### QuickJS cutover 阈值

在：

```bash
go list -deps ./...
```

还会拉：

```text
quickjs-go
quickjs_nodejs
```

之前，都不算 external runtime 完成。

---

还有一个我认为值得直接写进 ADR 的架构判断：

```text
jsengine.Runtime
```

是 **Scardice 内部语言抽象**；

```text
scardice_runtime_v1.h
```

是 **稳定二进制插件协议**；

```text
HostBridge
```

是 **Go 对象模型 → 语言对象模型** 的唯一翻译层。

这三层永远不要再次合并。

这样以后新增 Lua，比如：

```text
runtimes/lua54/
└── scardice-runtime-lua54.dll
```

Core 真正需要做的应该只是：

```text
0 行 Dice 修改
0 行 Host API 修改
0 次 Scardice 重编译
```

最多只是 Lua provider 自己实现同一个 ABI。

这套边界够稳，可以直接开工。

[1]: https://pkg.go.dev/cmd/go?utm_source=chatgpt.com "go command - cmd/go - Go Packages"
[2]: https://github.com/Scardice/Scardice-core/blob/quickjs-experimental-20260901/go.mod "https://github.com/Scardice/Scardice-core/blob/quickjs-experimental-20260901/go.mod"
[3]: https://go.dev/src/cmd/cgo/doc.go?h=ide "https://go.dev/src/cmd/cgo/doc.go?h=ide"
[4]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/engine.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/engine.go"
[5]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/dice_jsvm.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/dice_jsvm.go"
[6]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/dice.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/dice.go"
[7]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/ext.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/ext.go"
[8]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/quickjs/runtime.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/quickjs/runtime.go"
[9]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/quickjs/host.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/quickjs/host.go"
[10]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/runtime.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/utils/jsengine/runtime.go"
[11]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/dice_config.go "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/dice/dice_config.go"
[12]: https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/.github/workflows/test-and-lint.yml "https://raw.githubusercontent.com/Scardice/Scardice-core/quickjs-experimental-20260901/.github/workflows/test-and-lint.yml"
