# Runtime Plugin 信任边界

Scardice 的 JavaScript 扩展和 runtime plugin 是两种不同的安装与信任模型。

## JavaScript 扩展

QuickJS 这类 runtime plugin 作为独立原生 provider 被发现；每个脚本由按 UserScript 元数据或文件后缀选中的 runtime 执行，Core 只负责宿主 API、权限策略和生命周期。

## Runtime Plugin

Runtime plugin 是实现 `runtimeabi/include/scardice_runtime_v1.h` 的原生动态库。它在 Scardice 进程内加载，与 Scardice 进程拥有相同的操作系统权限：

- 可以执行任意原生代码；
- 可以访问该进程可访问的文件、网络和系统资源；
- 不受 JavaScript 扩展的 permissions 或脚本沙箱约束；
- 崩溃或内存破坏可能影响整个 Scardice 进程。

因此，`Runtime Plugin != JavaScript Extension`。安装 runtime plugin 等同于安装受信任的进程内代码，只应使用可信来源提供的构建产物。

## 安装与选择

runtime plugin 不能由普通 JavaScript 扩展自动安装。管理员应在停止或维护窗口中将经过验证的归档解压到 runtime 根目录：

```text
<scardice-data-or-install-root>/runtimes/quickjs/
├── runtime.json
├── LICENSES/
└── libscardice-runtime-quickjs.so  # Windows/macOS 使用对应平台文件名
```

归档由 [Scardice Runtime QuickJS](https://github.com/Scardice/scardice-runtime-quickjs) 的 CMake/CPack 配置生成，例如 `Scardice-runtime-quickjs-linux-amd64.tar.gz`。Core 通过 `runtime-plugins/quickjs` submodule 固定构建源码。runtime manifest 声明自己的 `id`、`author` 和脚本后缀：

```json
{
  "id": "quickjs",
  "author": "Scardice",
  "extensions": [".js", ".ts"]
}
```

`jsEngine` 仍决定默认/core loop，并保持旧版 API 的兼容行为：

```yaml
jsEngine: quickjs
```

扫描到的每个 UserScript 则单独选择 runtime。可在元数据头用 `@runtime runtimeID:author` 显式指定；多个候选用逗号分隔，按书写顺序尝试：

```js
// ==UserScript==
// @name QuickJS plugin
// @runtime quickjs:Scardice,goja:Scardice
// ==/UserScript==
```

显式候选不存在、未安装或无法打开时继续尝试下一个；全部失败后按脚本文件后缀自动选择。多个 runtime 声明同一后缀时，按 runtime 注册/发现顺序取首个。Core 内置 Goja 先注册，因此 `.js`/`.ts` 在没有 `@runtime` 时默认落到 Goja；要使用 QuickJS，应显式写 `@runtime quickjs:Scardice`。没有可用候选或 runtime 未声明该后缀时，脚本加载失败并保留错误，不静默执行。

每次重载会先为启用脚本打开并准入 runtime，固定最终的 runtime 实例和 generation，再执行插件依赖检查。依赖检查看到的是实际执行引擎；打开失败的候选可以回退，但固定绑定后不会在加载阶段再次换引擎。Dice 宿主要求 provider 声明脚本、host object、host function 和 context propagation 能力，并验证已打开 loop 实现对应上下文接口。

回退到已经运行的 provider 时，Core 复用其 event loop，保留其他插件的状态。安装、移除或更新 runtime package 后应重启 Core；扫描器按当前 provider 顺序、身份及动态库文件状态校验元数据缓存，失效时会在依赖检查前重新解析脚本并选择 runtime。

隔离边界与插件依赖保持一致：

- 同一 runtime 的插件共享该 runtime 的 module/heap/global 与语言级 event loop，因此可以直接声明 `@depends` 或使用 module/package dependency。
- 不同 runtime 各自拥有独立的 realm、heap、global 和语言级 event loop；Core 会拒绝跨 runtime 的直接插件依赖，不把一个 runtime 的插件注入另一个 runtime 的全局对象。
- Host scheduler/reactor 属于 Core 宿主侧，可以被不同 runtime 的 host service 共享。

## 进入 realm 的两种方式

Core 用两个入口进入 JS realm，provider 无关：

- `jsengine.RunWithContext` 等待回调结束，只能在 realm 之外调用。消息管线、定时任务、启动流程属于这一类。
- `jsengine.ScheduleWithContext` 只把回调排队，不等待结果，可以在 realm 内部调用。宿主函数、timer、Promise continuation、host service completion 与发送后通知属于这一类。

realm 内部调用等待型入口会自锁：回调要等一个只能由当前忙碌的 realm 线程取出的任务。`seal.replyToSender` 触发的 `onMessageSend` 就是这种路径，因此它按通知排队而不是等待。不支持排队的 Loop 返回 `jsengine.ErrScheduleUnsupported`，不会退回到等待型入口。

## 诊断

管理员可以调用已认证的接口查看发现到的 provider：

```text
GET /sd-api/js/runtime/status
```

响应中的 `installed`、`loaded`、`builtin`、`version`、`author`、`abi`、`path`、`capabilities`、`extensions` 和 `error` 用于区分：

- 内置且已加载的 Goja；
- 已发现但尚未加载的外部 runtime；
- 已选择但 ABI、架构、动态库或创建阶段失败的 runtime。

状态查询只读取 manifest 和 provider 状态，不会为了展示诊断而加载外部动态库。

## 后续加固

ABI v1 只定义接口兼容性，不定义供应链信任。后续可以增加签名、manifest SHA-256 和可信发布者校验；在这些校验加入前，runtime plugin 必须按受信任的本地原生依赖管理。
