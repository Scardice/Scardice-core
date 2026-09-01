# Runtime Plugin 信任边界

Scardice 的 JavaScript 扩展和 runtime plugin 是两种不同的安装与信任模型。

## JavaScript 扩展

JavaScript 扩展由已选中的 `jsengine` runtime 执行，受 Scardice 的脚本开关、扩展权限和宿主 API 约束。扩展源码可以通过扩展管理流程加载、重载和删除。

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

归档由 `runtime-plugins/quickjs` 的 CMake/CPack 配置生成，例如 `Scardice-runtime-quickjs-linux-amd64.tar.gz`。解压归档后保留其中的 `quickjs/` 目录，再通过配置选择 runtime ID：

```yaml
jsEngine: quickjs
```

显式选择不可用或不兼容的 runtime 时，Scardice 会报告 provider、ABI、架构、库路径或创建失败；不会静默回退到 Goja。Goja 仍是内置默认 runtime。

## 诊断

管理员可以调用已认证的接口查看发现到的 provider：

```text
GET /sd-api/js/runtime/status
```

响应中的 `installed`、`loaded`、`builtin`、`version`、`abi`、`path`、`capabilities` 和 `error` 用于区分：

- 内置且已加载的 Goja；
- 已发现但尚未加载的外部 runtime；
- 已选择但 ABI、架构、动态库或创建阶段失败的 runtime。

状态查询只读取 manifest 和 provider 状态，不会为了展示诊断而加载外部动态库。

## 后续加固

ABI v1 只定义接口兼容性，不定义供应链信任。后续可以增加签名、manifest SHA-256 和可信发布者校验；在这些校验加入前，runtime plugin 必须按受信任的本地原生依赖管理。
