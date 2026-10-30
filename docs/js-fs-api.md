# JS Filesystem API

`Scardice-core` 为 Goja 与 QuickJS 提供受路径策略、SealPack 权限和兼容执行边界约束的文件系统 API。两种引擎共享路径解析与授权规则，JavaScript 方法集合按引擎区分。

## 引擎入口与能力

| 引擎 | 入口 | 方法 |
| --- | --- | --- |
| Goja | `globalThis.fs`、`globalThis.require("fs")`；两者指向同一对象 | 同步 `readFile`、`writeFile`、`stat`、`readDir`、`mkdir`、`remove`；异步 `*Async` 与 `fs.promises.*` |
| QuickJS | `globalThis.fs`、`require("fs")`、`require("fs/promises")`、ESM `fs` / `fs/promises`；CommonJS 与 ESM 均接受 `node:` 别名 | `readFile`、`writeFile`、`readFileSync`、`writeFileSync`、`fs.promises.readFile`、`fs.promises.writeFile` |

QuickJS 的文件系统方法集合以上表为界。访问 `mkdir`、`readdir`、`stat`、`lstat`、`unlink` 或 `rename` 等表外成员得到 `undefined`，调用该值产生 JavaScript `TypeError`。

## 路径解析

### 扩展数据路径 `data://`

格式：

```text
data://relative/path
```

映射结果：

```text
<DataDir>/extensions/<extName>/data/<relative/path>
```

- `<DataDir>` 来自 `BaseConfig.DataDir`，例如 `data/default/`。
- `<extName>` 取当前插件名称；顶层脚本上下文使用脚本名称。
- `data://` 接受根内相对路径。`..`、绝对路径、Windows volume 名称和反斜杠路径返回路径校验错误。
- 现有目标及写入父目录解析符号链接后仍须位于扩展数据根内。
- `writeFile` 递归创建父目录；Goja 的 `mkdir` 递归创建目标目录。

例如，扩展 `fetchWeather` 写入 `data://cache/today.json` 时，目标为：

```text
data/default/extensions/fetchWeather/data/cache/today.json
```

### 主机绝对路径

格式示例：

```text
/etc/hostname
C:\Windows\system.ini
```

`data/<dice-name>/advanced.yaml` 中的以下设置授予主机路径能力：

```yaml
allowFilesystemUnrestrictedAccess: true
```

调用沿操作系统符号链接解析规则，以 Core 进程身份访问目标。

### 核心可执行文件相对路径

`deck/a.json`、`./config.yaml` 等主机相对路径同样要求 `allowFilesystemUnrestrictedAccess: true`。解析基准为核心可执行文件所在目录；`os.Executable()` 返回错误时使用 `os.Args[0]` 所在目录。

例如，核心可执行文件为 `/opt/seal/sealdice-core` 时，`deck/a.json` 解析为 `/opt/seal/deck/a.json`。

### 主机访问边界

`allowFilesystemUnrestrictedAccess: true` 把 Core 进程可访问的主机路径纳入普通脚本能力范围，包括配置、凭据和其他扩展数据。启用该设置的信任边界覆盖所有已加载普通脚本。SealPack 脚本继续叠加清单权限。

运行时在每次调用时读取该设置。一次调用绑定调用时刻的授权结果和解析路径；后续设置变更作用于后续调用。

## SealPack 权限

带 `PackageID` 的脚本使用清单中的 `file_read` 与 `file_write` 路径模式。授权目标按以下规则生成：

| JavaScript 路径 | 权限匹配目标 |
| --- | --- |
| `data://cache/item.json` | `data/cache/item.json` |
| 相对字符串 `_userdata/item.json` | `_userdata/item.json` |
| 主机绝对路径 | 相对包安装根归一化后的路径 |

读取方法匹配 `file_read`，写入、建目录和删除方法匹配 `file_write`。空 `file_read` 列表的匹配路径数为 0；空 `file_write` 列表采用 `_userdata/*`。`_userdata/item.json` 仍按核心可执行文件相对路径解析并应用 unrestricted gate。写入 `data://` 时需要匹配 `data/*` 的声明。最终授权条件为：

```text
SealPack 路径模式匹配 ∧ 本页路径策略匹配
```

普通脚本的 `PackageID` 为空，授权条件由本页路径策略决定。Promise、定时器和 QuickJS 异步 Host Service 均携带发起调用的脚本身份。

## Goja API

Goja 同步方法返回结果或抛出异常。异步方法返回 `Promise`；错误进入 rejected 状态。`fs.*Async` 与 `fs.promises.*` 是同一组能力的两个入口。

### 同步方法

| 方法 | 返回值 | 行为 |
| --- | --- | --- |
| `fs.readFile(path)` | `ArrayBuffer` | 读取完整文件 |
| `fs.writeFile(path, data, mode?)` | `undefined` | 原子写入并递归创建父目录；`mode` 默认为 `0o644` |
| `fs.stat(path)` | `{ name, size, mode, modTime, isDir }` | `modTime` 为 Unix 秒，`mode` 为 32 位无符号权限码 |
| `fs.readDir(path)` | `{ name, isDir }[]` | 返回直接子项 |
| `fs.mkdir(path, mode?)` | `undefined` | 递归创建目录；`mode` 默认为 `0o755` |
| `fs.remove(path)` | `undefined` | 删除文件或空目录 |

`writeFile` 的 `data` 接受字符串、`Uint8Array` / `Uint8ClampedArray` 导出的字节和 `number[]`；数字元素按 byte 转换。

### 异步方法

| `fs.*Async` | `fs.promises.*` | 结果 |
| --- | --- | --- |
| `fs.readFileAsync(path)` | `fs.promises.readFile(path)` | `Promise<ArrayBuffer>` |
| `fs.writeFileAsync(path, data, mode?)` | `fs.promises.writeFile(path, data, mode?)` | `Promise<void>` |
| `fs.statAsync(path)` | `fs.promises.stat(path)` | `Promise<{ name, size, mode, modTime, isDir }>` |
| `fs.readDirAsync(path)` | `fs.promises.readDir(path)` | `Promise<{ name, isDir }[]>` |
| `fs.mkdirAsync(path, mode?)` | `fs.promises.mkdir(path, mode?)` | `Promise<void>` |
| `fs.removeAsync(path)` | `fs.promises.remove(path)` | `Promise<void>` |

异步方法在调用时完成身份、权限、路径和兼容执行检查，再把已解析目标交给后台 I/O。

## QuickJS API

### 读取

```text
fs.readFileSync(path, options?)
fs.readFile(path, options?, callback?)
fs.promises.readFile(path, options?)
```

`options` 为 `"utf8"`、`"utf-8"` 或 `{ encoding: "utf8" | "utf-8" }` 时返回字符串；其他值返回 `Buffer`。`readFile` 在省略回调时返回 `Promise`，传入回调时调用 `callback(error, value)`。身份、权限、路径或 Host Service admission 错误在调用时同步抛出 `TypeError`；已接纳操作的 I/O 错误进入 Promise rejection 或回调的首个参数。

### 写入

```text
fs.writeFileSync(path, data)
fs.writeFile(path, data, options?, callback?)
fs.promises.writeFile(path, data)
```

`data` 接受字符串、`ArrayBuffer`、TypedArray/DataView、`number[]` 和 `Blob`。Core 使用 `0o644` 原子写入，并递归创建父目录。`writeFile` 在省略回调时返回 `Promise`，传入回调时调用 `callback(error)`；错误时序与读取方法一致。

### 资源上限

QuickJS 配置位于 `serve.yaml`：

```yaml
quickJSMemoryLimitMiB: 256
quickJSGCThresholdMiB: 64
quickJSMaxStackSizeKiB: 1024
quickJSMaxFilesystemReadMiB: 0
quickJSMaxFilesystemWriteMiB: 0
```

QuickJS runtime 选项来源按以下优先级选择：`jsRuntimeOptions.quickjs` provider payload、上列顶层字段。

同一 Dice 的 QuickJS runtime 共享 native heap、自动 GC 阈值和 JS 调用栈。前三项取值 `0` 时采用表中默认值；GC 阈值达到或超过内存上限时，运行时采用内存上限的四分之一。文件读写上限取值 `0` 表示按可用资源处理，正整数以 MiB 为单位限制单次载荷。`quickJSMaxFilesystemReadMiB` 在完整读取后校验返回长度；`quickJSMaxFilesystemWriteMiB` 在写入前校验输入长度。

资源上限在 QuickJS runtime 创建时载入；修改后通过 JS 重载创建采用新配置的 runtime。

## 兼容执行、重放与歧义

文件系统调用按以下顺序进入执行边界：

1. 校验 SealPack 权限、词法路径和已提供参数；QuickJS 读取在此阶段校验现有目标的符号链接边界。
2. 校验兼容执行模式。
3. 标记外部文件系统操作可能开始。
4. 执行其余基于文件系统状态的符号链接/父目录检查与 I/O。

live compatibility callback 进入第三项后处于外部操作区间。进程中断、callback panic、操作错误或回调结果丢失发生在该区间时，结果分类为 `ErrJSExternalEffectAmbiguous`，inbox 状态进入 `ambiguous`。该项保留诊断证据并释放同 lane 后继项的领取资格；重试由显式 inbox resolution 决定。

第三项之前的授权、词法路径和参数错误产生确定性 callback error。Projection replay 与 rebuild 通过事件解码器和 projector 恢复状态。Outbox 管理 durable outbound effects；文件系统与网络 I/O 在 live compatibility callback 中执行。

## 示例

### QuickJS ESM 私有数据

```javascript
import { readFile, writeFile } from "node:fs/promises";

const path = "data://settings.json";
const settings = { enabled: true };
await writeFile(path, JSON.stringify(settings));
const saved = JSON.parse(await readFile(path, "utf8"));
```

### Goja 同步私有数据

```javascript
const fs = globalThis.fs;

let ext = seal.ext.new("fetchWeather", "某人", "1.0.1");

ext.cmdMap["weather-count"] = seal.ext.newCmdItemInfo();
ext.cmdMap["weather-count"].solve = (ctx, msg, cmdArgs) => {
  const path = "data://count.json";

  let data = { count: 0 };
  try {
    const bytes = fs.readFile(path);
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch (error) {
    // 首次存储从初始计数开始。
  }

  data.count++;
  fs.writeFile(path, JSON.stringify(data));

  seal.replyToSender(ctx, msg, `共查询 ${data.count} 次天气`);
  return seal.ext.newCmdExecuteResult(true);
};

seal.ext.register(ext);
```

### Goja Promise 私有数据

```javascript
const fs = globalThis.fs;

let ext = seal.ext.new("fetchWeather", "某人", "1.0.1");

ext.cmdMap["weather-count-async"] = seal.ext.newCmdItemInfo();
ext.cmdMap["weather-count-async"].solve = async (ctx, msg, cmdArgs) => {
  const path = "data://count.json";

  let data = { count: 0 };
  try {
    const bytes = await fs.promises.readFile(path);
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch (error) {
    // 首次存储从初始计数开始。
  }

  data.count++;
  await fs.promises.writeFile(path, JSON.stringify(data));

  seal.replyToSender(ctx, msg, `共查询 ${data.count} 次天气`);
  return seal.ext.newCmdExecuteResult(true);
};

seal.ext.register(ext);
```

两个 Goja 示例写入：

```text
<DataDir>/extensions/fetchWeather/data/count.json
```

### Goja 主机路径

前提：

```yaml
allowFilesystemUnrestrictedAccess: true
```

```javascript
const fs = globalThis.fs;

// 列出核心可执行文件同目录的 deck 文件夹。
const entries = fs.readDir("deck");
for (const entry of entries) {
  console.log(entry.name, entry.isDir);
}

// 读取主机绝对路径。
const bytes = fs.readFile("/etc/hostname");
console.log(new TextDecoder().decode(bytes));
```

## 错误结果

| 条件 | 结果 |
| --- | --- |
| 空路径 | `路径不能为空` |
| `data://` 调用的扩展或脚本身份为空 | `无法确定当前扩展身份,data:// 路径不可用` |
| `data://` 包含穿越、绝对形式、反斜杠或 Windows volume | `data:// 路径不允许穿越或绝对: <path>` |
| `data://` 符号链接目标位于根外 | `路径越过 data:// 根目录: <path>` |
| 主机路径的 unrestricted gate 为 `false` | `当前未开启 AllowFilesystemUnrestrictedAccess,仅支持 data:// 路径` |
| SealPack 路径模式匹配结果为 false | `PermissionError`，`permission` 为 `file_read`、`file_write` 或 `file_access` |
| SealPack `PackageManager` 为 `nil` | `扩展包沙箱未初始化,拒绝文件访问` |
| Goja 异步 event loop 为 `nil` | rejected Promise：`JS event loop 未初始化,无法执行异步 fs 操作` |
| QuickJS 单次载荷超过配置值 | 错误文本为 `filesystem read exceeds <N> MiB` 或 `filesystem write exceeds <N> MiB`；同步方法与异步 admission 同步抛出 `TypeError`，已接纳读取的超限结果进入 rejected Promise |
| QuickJS 调用表外方法 | JavaScript `TypeError` |
| 操作系统 I/O 返回错误 | Goja 同步方法抛出异常、异步方法返回 rejected Promise；QuickJS 同步方法抛出 `TypeError`，已接纳异步操作进入 Promise rejection 或回调首个参数 |
