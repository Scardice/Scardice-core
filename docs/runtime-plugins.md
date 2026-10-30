# JavaScript Runtime 与插件接口

Scardice 通过 runtime provider 执行 JavaScript 扩展。Core 管理宿主 API、权限、消息上下文和生命周期；provider 管理语言执行、realm、heap 与 event loop。

Runtime plugin 是实现 `runtimeabi/include/scardice_runtime_v1.h` 的进程内原生动态库，与 Core 共享操作系统权限、文件、网络和进程资源。原生库的崩溃或内存错误会影响 Core。安装来源采用可信发布者提供的构建产物；JavaScript 扩展的权限策略作用于 Core 宿主 API。

## JavaScript 扩展契约

公开接口、上下文字段、回调顺序和错误契约定义于 [`manifest.v1.json`](../dice/testdata/plugin_compat/manifest.v1.json)。

- 回调准入校验 runtime generation、callback kind、稳定 callback identity、provider event ID 与所属 realm。
- `$m` 和 `$g` 属性写入返回 `ErrJSUnsupportedOwner`。
- `onMessagePreprocess(ctx, msg)` 在脚本所属 loop 内执行和解析结果。Goja、QuickJS 均提供该钩子。
- `seal.ext.getConfig(ext, key)` 对已注册配置返回配置项，对注册表外的可选 key 返回 `null`。配置注册使用注册接口，配置写入要求 key 已注册。存储与 runtime 故障通过错误返回。
- 定时任务配置在持久化和调度前校验并规范化 cron、daily 与 one-shot 表达式。校验失败时保留原配置和调度。相对 one-shot 延迟转换为绝对截止时间后持久化，再启动定时器。

## Provider 配置与凭据

`jsRuntimeOptions` 按 provider 保存公开 JSON 配置，存储形式为 Core 配置中的明文 JSON。密码、API key、token 和私钥使用各自的凭据管理渠道。

端点 adapter 的 `SecretRef` 由所属 owner 的解析路径处理。JavaScript provider options 与 adapter 凭据分别属于独立的配置接口。

## 执行与重放

| 执行模式 | 职责 |
| --- | --- |
| `live` | 执行 JavaScript 回调、调度回调任务、收集 durable outbox effect |
| `replay` | 通过事件解码器和 projector 恢复投影 |
| `rebuild` | 通过事件解码器和 projector 构建 shadow projection |

文件系统与网络调用在执行前完成权限检查，执行归属为 live 回调。Outbox 管理 durable 出站 effect。

回调跨越外部 I/O 边界后，待确认结果归类为 `ambiguous`（`ErrJSExternalEffectAmbiguous`）。该项保留诊断证据并释放同 lane 后继项的领取资格；重试由操作者显式决策。确定性校验错误使用独立错误分类。

Durable 消息发送提交成功结果后，Core 以 best-effort 方式调度 `OnMessageSend`。发送事实以已提交的 durable 结果为准，钩子作为附加通知执行。

## Runtime 安装

管理员通过 `/mod/runtime` 管理 runtime package。安装与卸载操作记录为待重启变更，由管理员重启 Core 后应用。Provider 在使用时加载 native library。

管理接口使用 Core 认证：

| 接口 | 请求与结果 |
| --- | --- |
| `GET /sd-api/js/runtime/management` | 读取 provider 状态、全局默认、扩展包路由和待重启变更 |
| `POST /sd-api/js/runtime/config` | 保存全局默认 runtime 和按扩展包 ID 设置的 route；空 route 使用全局默认 |
| `POST /sd-api/js/runtime/install` | 以 `application/octet-stream` 上传 `.tar.gz` 或 `.zip` 原始归档字节 |
| `POST /sd-api/js/runtime/uninstall` | 以 `{"id":"quickjs"}` 指定此 Dice 托管的 runtime |

归档采用单一根目录，目录名与 manifest 的 runtime `id` 一致。条目采用唯一的根目录内相对路径，类型为普通文件或目录；native library 内容长度大于零，平台与 ABI 主版本匹配 Core。压缩大小上限为 64 MiB，解压大小上限为 256 MiB，条目上限为 512。

上传和状态检查读取文件及 manifest；启动应用待处理安装前再次校验。动态库加载发生于 provider 打开流程。

托管 package 位于 `<dataDir>/js-runtimes/active/<runtime-id>/`，待处理操作保存在同级管理目录。外部 runtime 根目录采用手工部署方式，并参与发现和选择：

```text
<scardice-data-or-install-root>/runtimes/quickjs/
├── runtime.json
├── LICENSES/
└── libscardice-runtime-quickjs.so  # Windows/macOS 使用对应平台文件名
```

QuickJS 归档由 [Scardice Runtime QuickJS](https://github.com/Scardice/scardice-runtime-quickjs) 的 CMake/CPack 配置生成，例如 `Scardice-runtime-quickjs-linux-amd64.tar.gz`。Core 通过 `runtime-plugins/quickjs` submodule 固定构建源码。Manifest 声明 provider 身份和脚本后缀：

```json
{
  "id": "quickjs",
  "author": "Scardice",
  "extensions": [".js", ".ts"]
}
```

## Runtime 选择与脚本加载

`jsEngine` 决定默认 runtime 和 Core loop：

```yaml
jsEngine: quickjs
```

每个 UserScript 独立选择 runtime。元数据中的多个候选按书写顺序排列：

```js
// ==UserScript==
// @name QuickJS plugin
// @runtime quickjs:Scardice,goja:Scardice
// ==/UserScript==
```

选择优先级为：

1. `@runtime` 候选。
2. 扩展包 ID 对应的 runtime route。
3. 全局 `jsEngine`。
4. 按注册与发现顺序选择声明该脚本后缀的 provider。

候选解析或打开失败时继续选择下一项。候选耗尽或后缀校验失败时，脚本加载返回错误。默认配置选择内置 Goja；管理员通过 `/mod/runtime` 调整全局默认。

重载先打开并准入 runtime，固定实例与 generation，再执行插件依赖检查和加载。Provider 准入要求脚本、host object、host function、context propagation 能力及对应的 loop 上下文接口。已运行的 provider 复用原 event loop 和插件状态。

Runtime package 的安装、移除和更新通过重启应用。元数据缓存按 provider 顺序、身份及动态库文件状态校验；缓存失效时重新解析脚本并选择 runtime。

新增文件采用增量加载，前提为 JS 已启用、全量重载空闲、文件身份和插件名属于新增项。依赖到达后，等待该 `@depends` 的插件按依赖顺序加载。已加载脚本的更新、同名替换及禁用、删除后的实例卸载采用全量重载流程。

## Realm 与上下文

| 范围 | 所有权 |
| --- | --- |
| 同一 runtime | 插件共享 module、heap、global 和语言 event loop；直接插件依赖在此范围内解析 |
| 各 runtime | 各自持有独立 realm、heap、global 和语言 event loop |
| Core | 管理可供多个 runtime host service 使用的 scheduler 与 reactor |

跨 runtime 的直接插件依赖返回依赖校验错误。

进入 realm 的接口分为两类：

| 入口 | 调用位置与完成语义 |
| --- | --- |
| `jsengine.RunWithContext` | realm 外部调用，等待回调结束 |
| `jsengine.ScheduleWithContext` | realm 内外均可调用，完成排队后返回 |

消息管线、定时任务和启动流程使用等待型入口。宿主函数、timer、Promise continuation、host service completion 和发送通知使用排队型入口。

`Run`、`Schedule`、`LoadEntry` 在 owner 内继承执行上下文；其他 goroutine 或线程提交的调用使用宿主级上下文。异步操作通过 `*WithContext` 显式携带插件、消息和事务归属。

`seal.replyToSender` 触发的 `onMessageSend` 通过通知队列执行。消息收尾等待已登记的发送钩子及其返回的 Promise。排队能力校验失败返回 `jsengine.ErrScheduleUnsupported`。

## 异步钩子与 ctx 生命周期

带 `ctx` 的事件钩子和 `cmd.solve` 支持返回 Promise。Core 在所属 runtime 内等待并消费结果，再继续消息处理或收尾。Promise 判定采用引擎原生类型，普通返回值使用同步语义。

- Goja 原生 `await` 保留发起者的插件、消息和事务归属，continuation 的写入属于发起调用。
- 每条消息共用 10 秒总期限，覆盖排队、同步 JavaScript 与全部 Promise 等待。取消操作撤销调用权限并取消关联的 `fetch` 请求。
- `ctx` 的发送和写入权限覆盖该调用的有效生命周期。业务异步工作通过返回或等待的 Promise 加入此生命周期；独立定时器和悬空协程使用各自的执行生命周期。
- Durable 发送成功后的 `onMessageSend` 使用独立、best-effort 的宿主上下文，生命周期持续至返回的 Promise 结束。原消息事务保持已提交状态。
- Runtime 停止或替换时结束等待者；取消和关闭释放宿主观察器的消息引用。插件保存的 JavaScript 对象和协程按语言引用关系回收。

JavaScript `finally` 随 VM 控制流执行；Goja 硬中断的资源收尾由宿主负责。独立调用使用独立中断状态。`onLoad`、`GetDescText` 和 `HelpFunc` 使用同步契约。

## Adapter 透传 API

`ext.onAdapterEvent(ctx, event)` 订阅协议事件，`seal.adapter` 调用协议端 API。Provider 范围为 OneBot 11，包括 pureonebot 和共用 OneBot 传输的内建 runtime。能力校验在指定端点完成，校验失败返回错误。

### 订阅与过滤

`ext.adapterEventFilter` 使用 JavaScript 对象。省略、`null` 或 `{}` 表示订阅 `notice`。

- `events: ["message", "notice"]` 指定事件类别集合；空数组表示空集合。
- `events: "all"` 订阅全部协议事件类别。API 响应帧由请求关联通道处理。
- `where` 匹配协议 JSON 顶层字段。字段之间为 AND，候选数组内为 OR；匹配同时比较类型和值，字段存在性独立于 `null` 值。
- 谓词值采用字符串、布尔值、有限数值、`null` 或这些标量组成的数组；可枚举属性键采用字符串。类型或形状校验失败返回错误。
- 配置支持整个对象重新赋值，以及 `where` 字段值替换。

| `event` 字段 | 类型 | 含义 |
| --- | --- | --- |
| `type` | string | OneBot 的 `post_type` |
| `protocol` | string | `onebot11` |
| `body` | object | 按所属引擎 `JSON.parse` 语义和数值范围解析；每个扩展拥有独立的原生对象与数组 |
| `rawJson` | string | 原始 JSON 文本，保留空白和数字字面量 |
| `endPoint` | EndPointInfo | 接收事件的端点 |

群和私聊事件遵守扩展激活规则，群事件要求群内骰子处于开启状态。会话标识为空的事件使用全局订阅，`ctx === null`。全局事件采用有界内存队列和单次 best-effort 交付；队列饱和时丢弃事件并累计 `adapter_event.backpressure`。

以下扩展在表情回应通知中读取群信息：

```js
const ext = seal.ext.new("adapter-example", "example", "1.0.0");
ext.adapterEventFilter = {
  where: { notice_type: ["group_msg_emoji_like"] }
};
ext.onAdapterEvent = async function (ctx, event) {
  if (ctx === null) return;
  const response = await seal.adapter.callApi(event.endPoint, "get_group_info", {
    group_id: event.body.group_id
  });
  console.log("adapter-example", response.status);
};
seal.ext.register(ext);
```

### 即时调用与持久化发送

`endpoint` 接受端点对象或精确端点 ID 字符串。`action` 使用协议端 API 名称。`params` 默认为 `{}`，采用 JSON 可序列化值。

| `seal.adapter` 方法 | 返回值 | 语义 |
| --- | --- | --- |
| `callApi(endpoint, action, params?)` | Promise<object> | 返回完整协议响应对象 |
| `callApiRaw(endpoint, requestJson)` | Promise<string> | 返回完整原始响应 JSON |
| `enqueueApi(endpoint, action, params?)` | `{ id, status }` | 同步提交至加密 outbox，协议执行由 dispatcher 完成 |
| `enqueueApiRaw(endpoint, requestJson)` | `{ id, status }` | 将完整请求 JSON 提交至 outbox |
| `getOperation(id)` | `{ id, status, resultCode, errorCode }` | 查询操作状态；查找失败返回错误 |

`requestJson` 是包含 `action`、`params` 和协议扩展字段的完整 JSON 对象。适配器重建发送 envelope 并设置自己的 `echo`；其他字段及数字字面量保持语义。输入、补入 `echo` 后的发送帧和响应均受 256 KiB 上限约束。

即时调用保留发起者的插件、消息和 runtime generation，以异步 I/O 等待协议端响应。`status: "failed"` 作为完整协议响应返回；连接、超时、校验或 JSON 解析失败使 Promise 进入 rejected 状态。每次调用最多进行一次发送尝试，协议 I/O 独立于消息事务。普通对象使用引擎数值语义；精确数字文本使用 `rawJson`、`callApiRaw` 或 `enqueueApiRaw`。

Durable 回调内的 enqueue 返回 `staged`，与回调的其他修改原子提交或回滚；该回调可通过 `getOperation` 读取自己的暂存操作。宿主级调用独立提交并返回 `pending`。队列保存请求、操作状态和结果代码；完整协议响应使用即时接口获取。消息发送钩子对应消息 effect 的通知链路，透传 API 操作通过 operation 状态读取结果。

任意协议 action 使用 `EffectRetryNonIdempotent` 策略。派发后进入待确认状态的结果标记为 `ambiguous`，重发由操作者显式决策；OneBot `async` 确认表示请求已接收，对应 `ambiguous` 操作状态。

生命周期最终检查是回调与调用的准入点。扩展停用、删除或替换后，已准入工作按原期限结束；结果交付校验失败时丢弃结果，校验成功时交付至原 owner 和 `ctx`。已提交 outbox 操作按持久化状态继续执行。

### 敏感词策略

`callApi`、`callApiRaw`、`enqueueApi`、`enqueueApiRaw` 统一使用 Dice 的 `EnableCensor` 和 `CensorMode`。启用审查后，各模式覆盖以下入口：

| 模式 | 检查范围 |
| --- | --- |
| `OnlyOutputReply` | 四个调用接口的请求，包括全局调用；检查先于协议 I/O、outbox 暂存和提交 |
| `AllInput` | `onAdapterEvent` 接收的协议事件，包括全局事件 |
| `OnlyInputCommand` | Core 已识别为命令的 `message` 事件 |

审查递归匹配 JSON 字符串值。消息字段还检查连续文本段、转发节点、CQ 参数和 JSON 卡片的结构化内容；普通文本段保持字面语义。审查对象的字段名在各自对象内唯一，通过审查的请求保留原始 JSON。

内容命中返回 `adapter content rejected by censor`；审查器加载中或缺失时返回 `adapter censor unavailable`。即时调用以 Promise rejection 交付错误，enqueue 同步抛出错误，入站命中在扩展回调前完成拦截。

消息会话按来源发送者记录命中，同一上下文采用一次计数。处置通知独立提交，完成后再交付调用错误。全局调用与操作者待确认的协议事件采用内容准入检查；请求中的目标用户和群标识用于协议路由。

## 诊断

管理员使用已认证的接口查询 provider：

```text
GET /sd-api/js/runtime/status
```

响应提供 `installed`、`loaded`、`builtin`、`version`、`author`、`abi`、`path`、`capabilities`、`extensions` 和 `error`，表达内置已加载、外部已发现、加载成功，以及 ABI、架构、动态库或实例创建错误等状态。查询数据来自 manifest 和 provider 状态。
