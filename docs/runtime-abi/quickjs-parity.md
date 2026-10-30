# QuickJS 运行时能力

`quickjs` 是通过 Runtime ABI 加载的原生 QuickJS-NG Provider。它提供 Script、CommonJS、ESM、Promise、Timer、Host Object、Host Function、同步与异步 Host Service、源码位置和上下文传播能力；Goja 继续作为空 `EngineID` 的默认 Provider。

## 运行时包契约

`runtime-plugins/quickjs/runtime.json` 定义安装包元数据和动态库选择。

| 字段 | 值 |
| --- | --- |
| Manifest schema | `1` |
| Provider ID | `quickjs` |
| Provider version | `0.8.0` |
| Runtime ABI | v1 |
| Host ABI | v1.1 |
| Capability mask | `2047`，即 `SC_CAP_*` bit 0–10 |
| Extensions | `.js`、`.ts` |
| Host services | `console`、`crypto`、`fetch`、`filesystem`、`websocket` |
| Library targets | Linux amd64/arm64、Darwin amd64/arm64、Windows amd64/arm64 |

配置 `quickjs` 时，Registry 解析对应候选项并加载其动态库。候选项为空、平台映射缺失、动态库文件缺失分别返回 `ErrProviderNotFound`、`ErrUnsupportedArchitecture`、`ErrMissingLibrary`；清单一致性与 ABI 校验失败返回对应分类诊断。配置空 ID 或 `goja` 时，Registry 选择内建 Goja。

## JavaScript 能力

QuickJS realm 提供以下用户可见入口。

| 能力 | 语义 |
| --- | --- |
| `seal.*` Host API | 通过 HostBridge 暴露 Dice 对象、函数和扩展能力。 |
| Global Script | 以 `SC_ENTRY_SCRIPT` 执行全局脚本。 |
| CommonJS / `require` | 缓存模块 exports；解析内建模块与宿主预加载模块；表外 specifier 返回模块解析错误。 |
| ESM | 以 `SC_ENTRY_ESMODULE` 加载模块入口。 |
| Promise、Timer、Microtask | `tick` 推进 Promise job、`setTimeout`、`clearTimeout` 和 `queueMicrotask`。 |
| `console` | `log`、`info`、`warn`、`error` 通过同步 Host Service 输出。 |
| `Buffer`、`Blob` | 提供字节缓冲区，以及 `Blob.size`、`type`、`slice`、`text`、`arrayBuffer`。 |
| URL | 提供 `URL` 与 `URLSearchParams`。 |
| Crypto | 提供 `crypto.subtle.digest`、`getRandomValues` 和 `randomUUID`。 |
| Fetch | 通过异步 Host Service 返回 Promise、响应元数据和 body。 |
| WebSocket | 通过异步连接与流式 Service event 提供消息和关闭事件。 |
| Filesystem | 使用 Dice 的 extension-aware 授权策略提供同步与异步文件读写。 |
| Abort | 提供 `AbortController` 与 `AbortSignal`。 |
| Structured clone | 提供 `structuredClone`。 |
| Message channel | 提供 `MessageChannel`、`MessagePort` 和排队克隆交付。 |
| Utility | 提供 `util.inspect` 和 `EventEmitter` 等内建模块。 |
| Resource limits | Provider 读取 `memoryLimitBytes`、`gcThresholdBytes`、`maxStackSizeBytes` 和 `executionTimeoutMillis`。 |

## Host Service 协议

Provider 通过 Host ABI 的固定 operation ID 调用 Dice 服务。Dice Service Registry 负责网络、文件系统、并发、大小和 extension 权限。

| Service | Operation | 交付方式 |
| --- | --- | --- |
| `console` | `0x0101`–`0x0104` | 同步文本调用。 |
| `crypto` | `0x0201` digest、`0x0202` random bytes | 同步 string/bytes 请求与 bytes 响应。 |
| `fetch` | `0x0301` request | 异步请求；终态 event 携带 JSON 响应元数据、body 和 HTTP status。 |
| `websocket` | `0x0501` connect、`0x0502` send、`0x0503` close | connect 使用异步流式 event，send 与 close 使用同步调用。 |
| `filesystem` | `0x0601` read、`0x0602` write、`0x0607` read sync、`0x0608` write sync | 异步与同步文件读写。 |

`service_call` 返回传输状态和 typed service status。`service_start` 返回 opaque request ID，`service_cancel` 请求取消，`service_event` 交付 data、complete 或 close。每个 request 接受一个终态 complete/close event；event 字符串和 byte 载荷在当前调用内借用，Provider 为延长使用期复制数据。

## Owner、上下文与引用

Core 的 native Loop 把每个 QuickJS runtime 固定到专用 owner OS thread。`RunWithContext` 在 owner 上串行执行并等待结果；`ScheduleWithContext` 将宿主回调、Timer、Promise reaction 和 Service completion 排入 owner 队列。外层 Loop lock 在 Host callback 期间保持可重入值操作畅通。

Provider 公开 `scardice.runtime.context.v1` 扩展，并声明 `SC_CAP_CONTEXT_PROPAGATION`。Core 在每次入口设置 opaque 上下文 token；QuickJS 在 Timer、Microtask、Promise 和 Service callback 中恢复 token，HostBridge 据此解析当前插件执行上下文。

Host ABI v1.1 为每个 HostRef proxy 配对 retain/release。方法函数通过 `host_function_owner` 持有 parent proxy，因此函数在脱离父对象后仍保持可调用状态。`Object.Has` 使用 own-property 语义，throwing getter 的异常通过 `GetWithError` 和宿主 callback 错误路径返回。

## 生命周期

原生实例执行 `create → start → calls → stop → destroy`。运行期间，Core 持续调用 `tick` 推进 Promise 和 Timer。关闭时，Provider 结束 Timer、WebSocket、待处理 Service、callback 和 retained value；Core 随后销毁 runtime 与 HostBridge session。动态库驻留到进程退出。

QuickJS Provider 与 Core 位于同一进程安全域。安装与更新流程使用受信任的 Provider 包，并由 Loader 校验清单、描述符、ABI、函数表和上下文扩展。

值生命周期、JSON capability 和通用 owner 规则见[运行时架构](architecture.md)，原语与对象转换见[值导出契约](export-contract.md)。
