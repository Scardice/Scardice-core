# JavaScript 运行时架构

`utils/jsengine` 提供引擎中立的 Provider、Loop、Runtime、Value 与 Object 接口。应用通过 Registry 选择内建 Goja 或原生运行时 Provider；原生 Provider 通过 Runtime ABI v1 和 Host ABI v1.1 接入。每个 Loop 拥有一个 JavaScript realm、串行执行入口、执行上下文和回调作用域值。

## 组件模型

运行时由注册、实例化、执行和宿主桥接四层组成。

| 组件 | 职责 |
| --- | --- |
| `jsengine.Registry` | 按规范化 `EngineID` 保存内建 Provider 和延迟加载的原生候选项，并返回描述符快照。 |
| `jsengine.Provider` | 以值快照公开 `Descriptor`，根据命名空间化 `RuntimeOptions` 创建一个 `Loop`。 |
| `jsengine.Loop` | 拥有单个 realm，串行执行 `Run`、`LoadEntry` 与 `Close`。 |
| `jsengine.Runtime` | 在一次 Loop 回调内执行脚本、加载 CommonJS、访问全局对象并绑定宿主值。 |
| `jsengine.Value` / `jsengine.Object` | 表示当前回调作用域内的引擎值和对象操作。 |
| `utils/jsengine/goja` | 实现内建 Goja Loop、上下文传播、Promise 观察和 JSON 解析。 |
| `utils/jsengine/native` | 发现原生运行时包，验证清单与 ABI 描述符，并把 C ABI 映射为 `jsengine` 接口。 |
| HostBridge 与 Service Registry | 将 Go 对象、函数以及 `console`、网络、文件系统等宿主服务投影到运行时。 |

## Provider 解析

Registry 对 `EngineID` 执行去空白和小写规范化。空 ID 解析为 `goja`；应用显式注册内建 Goja Provider，并把原生清单作为候选项注册。

内建 Goja 描述符声明 `.js`、`.ts`，以及 Script、CommonJS、Host Object、Host Function 和 Context Propagation 能力。原生 Loader 扫描运行时根目录的直接子目录，读取 schema 1 的 `runtime.json`，选择当前 `GOOS-GOARCH` 对应的包内动态库。候选项注册阶段仅保存元数据；首次 `Resolve` 加载动态库、查询 Provider，并缓存解析结果。

原生加载器核对清单与 Provider 描述符的 ID、版本、Runtime ABI major 和 Host ABI major。重复 ID 返回 `ErrDuplicateProvider`，未知 ID 返回 `ErrProviderNotFound`，描述符或清单错误返回对应的 native loader 分类。`RuntimeRequirements` 在 `Open` 前验证能力位，并在 `Open` 后验证 `ContextAwareLoop` 等接口。

Provider 只读取 `RuntimeOptions.Providers[NormalizeEngineID(id)]`。原生动态库从首次加载起驻留到进程退出；每次 `Provider.Open` 创建独立的运行时实例和 Loop。

## 原生 ABI 边界

[`runtimeabi/include/scardice_runtime_v1.h`](../../runtimeabi/include/scardice_runtime_v1.h) 定义 Runtime ABI v1.0 与 Host ABI v1.1。Provider 导出稳定入口 `scardice_runtime_query_v1`，返回静态存储中的描述符、运行时函数表和扩展表。

所有 ABI 结构以 `struct_size` 开头。Core 按字段覆盖范围读取追加尾部，并结合 capability 位验证必需函数。运行时句柄、值句柄、HostRef、HostFunc、Host Context 和 Service Request 都使用 opaque `uint64_t`；值 `0` 表示空句柄。

`sc_string_view` 在当前调用期间借用调用方字节。返回文本采用调用方分配缓冲区和两次 `required` 查询协议。异步服务事件的字符串与字节视图覆盖当前 `service_event` 调用，Provider 为延长使用期复制载荷。ABI 边界传递固定宽度标量、句柄、借用视图和状态码。

原生实例遵循 `query → create → start → calls → stop → destroy`。`sc_status_t` 表达参数、ABI、状态、关闭、脚本异常、内存、超时、宿主和内部错误；`last_error_copy` 提供诊断文本。原生 Provider 与 Core 共享进程权限，部署方加载受信任的运行时包。

## Owner Loop 与关闭顺序

Loop 为一个 realm 建立唯一执行所有者。调用方从 realm 外使用 `Run` 或 `RunWithContext` 并等待结果；宿主回调、Timer、Promise continuation 和 Service completion 使用 `Schedule` 或 `ScheduleWithContext` 入队。

原生 Loop 创建专用 worker goroutine，并通过 `runtime.LockOSThread` 固定 owner OS thread。worker 串行处理同步任务、已调度回调、宿主服务事件和 `tick`；`tick` 推进 Promise job 与到期 Timer。owner 内的重入值操作直接在当前 scope 执行。

`Close` 先关闭新任务准入，再执行以下顺序：

1. 丢弃排队的 Service event、已调度回调和 Promise observation。
2. 调用 Provider `stop`。
3. 释放持久值、Promise/JSON helper 和宿主 callback。
4. 清空上下文 token。
5. 调用 Provider `destroy`。
6. teardown HostBridge session 并结束 worker。

## 值与宿主引用生命周期

`Runtime`、`Value` 和 `Object` 归属当前 Loop 回调。普通调用方在回调返回前读取值、访问对象或转换原语；Promise settlement 值在 owner 上执行的 `settled` 回调内消费。

原生适配器为每次任务创建 `nativeScope`。ABI 调用返回的值句柄登记到该 scope，并在 scope 结束时按逆序释放。内部 Promise helper、JSON helper 和跨回调宿主 callback 通过 `value_retain` 提升为持久值，每次 retain 对应一次 `value_release`，关闭流程在 `destroy` 前释放剩余持久值。

值句柄与创建它的 runtime 绑定。跨 runtime、过期 scope 和已关闭 Loop 的操作返回所有权或生命周期错误。Goja 原语通过复制导出为 Go 标量；Goja 对象和函数继续归属其 realm 图。通用转换规则见[值导出契约](export-contract.md)。

HostBridge 使用 session 句柄表示 Go 对象和函数。Host ABI v1.1 为每个 JavaScript HostRef proxy 配对 `host_ref_retain` 与 `host_ref_release`；`host_function_owner` 使方法函数在其可达期间持有 owner proxy。session teardown 统一结束剩余引用。

## 执行上下文

`ContextAwareLoop` 在 `LoadEntryWithContext`、`RunWithContext` 和 `ScheduleWithContext` 间携带宿主提供的 opaque 上下文。`CurrentContext` 返回 owner 当前上下文，`OwnerAwareLoop.InOwner` 报告 owner 亲和性。

原生 Provider 通过 `scardice.runtime.context.v1` 扩展传递 `uint64_t` token。Core 在进入脚本、Timer、Promise reaction 或异步服务完成回调时设置 token，Provider 在宿主回调中返回当前 token。`SC_CAP_CONTEXT_PROPAGATION` 与有效扩展表共同构成该能力的准入条件。

实现 `ContextKeyer` 的上下文以可比较 key 复用 token。`ExecutionScope` 提供 `context.Context` 生命周期，`GuardedExecutionScope` 提供调用准入；取消会移除 token 映射，已撤销 token 解析为 `RevokedExecutionScope`。同一调用内的嵌套回调复用当前准入 guard。

## JSON 能力

`jsengine.JSONParser` 把 UTF-8 JSON 文本解析为引擎原生值。调用方在当前 owner 回调内执行 `ParseJSON`，并按同一回调作用域消费返回的对象和数组；格式错误返回引擎解析错误。

Goja 在脚本入口运行前捕获 realm 的 `JSON.parse`。原生适配器在 worker 启动期捕获并各保留一次 `JSON.parse` 与经过兼容性校验的 `JSON.stringify`，因此宿主转换始终使用启动期 intrinsic。原生 JSON capability 的准入条件是成功捕获对应 helper；条件校验返回 `errNativeJSONParseUnavailable` 或 `errNativeJSONStringifyUnavailable`。

HostBridge 将 JSON-compatible 对象序列化为 `KindJSON` 快照，并把快照解码到显式的 map、slice 或 interface 目标。快照校验接受字符串键、有限数值、布尔值、字符串、数组、对象和 `null`；类型、循环引用和 getter 异常沿宿主回调错误路径返回。Runtime ABI 的现有值类型、函数调用和对象操作承载此能力。

QuickJS 的具体能力与服务语义见 [QuickJS 运行时能力](quickjs-parity.md)，完整 C 协议见 [Runtime ABI v1 reference](../../runtimeabi/ABI.md)。
