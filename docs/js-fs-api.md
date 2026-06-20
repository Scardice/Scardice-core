# JS Filesystem API

本文档说明 `Scardice-core` 在 Goja 中暴露的文件系统 `fs` API。

## 对外入口

- **全局对象**：`fs`
- **require 导入**：`require("fs")`

两种方式获取的是同一个对象。

---

## 设计取向

当前插件生态以单文件 JS 为主,SealPack 体系尚未完善。`fs` 模块当前只提供两类能力:

1. **按扩展隔离的用户数据区** (`data://`):无需开关,默认可用,各扩展互不干扰
2. **完全文件系统访问** (绝对路径 / 核心可执行文件相对路径):仅在高级设置 `allowFilesystemUnrestrictedAccess: true` 时可用

未来 SealPack 完善后,可基于声明式的 `file_read` / `file_write` permissions 引入更细粒度的沙箱路径风格。

---

## 路径规则(Path Styles)

调用 `fs` 方法时,路径参数支持以下三种风格:

### 1. 扩展数据路径 `data://X` (推荐)

格式:`"data://relative/path"`

实际路径:`<DataDir>/extensions/<extName>/data/<X>`

- `<DataDir>` = 海豹配置中的 `BaseConfig.DataDir`,如 `data/default/`
- `<extName>` = 当前正在执行的扩展名,即 `seal.ext.new(name, ...)` 中的 `name`
- 路径穿越被严格禁止,`data://../x` 会抛出错误
- **无需开启任何高级设置**,默认可用
- 各扩展的数据完全隔离,卸载/更新扩展不会污染其他扩展的数据

**示例**:扩展 `fetchWeather` 调用 `fs.writeFile("data://cache/today.json", ...)`,实际写入到 `data/default/extensions/fetchWeather/data/cache/today.json`。

### 2. 绝对路径(危险)

格式:`/etc/foo` 或 `C:\Windows\xxx`

- 仅当 `data/<dice-name>/advanced.yaml` 中 `allowFilesystemUnrestrictedAccess: true` 时允许
- 未开启时抛出错误

### 3. 相对核心可执行文件路径(危险)

格式:`deck/a.json` / `./config.yaml` (任何非 `data://` 开头且非绝对路径)

- 仅当 `allowFilesystemUnrestrictedAccess: true` 时允许
- 解析基准:核心可执行文件所在目录(`os.Executable()` 失败时回退 `os.Args[0]` 所在目录)
- 例如可执行文件位于 `/opt/seal/sealdice-core`,则 `deck/a.json` → `/opt/seal/deck/a.json`

---

## API 方法

`fs` 同时提供同步与 Promise 风格异步接口:

- 同步接口失败时**抛出异常**。
- 异步接口返回 `Promise`,失败时进入 rejected 状态,可用 `await` + `try/catch` 捕获。
- `fs.promises.*` 与 `fs.*Async` 是同一组异步能力的两种命名入口。

### 同步接口

### `fs.readFile(path: string): Uint8Array`

读取整个文件,返回字节数组。

### `fs.writeFile(path: string, data: string | Uint8Array | number[], mode?: number): void`

写入文件。若父目录不存在自动创建。`mode` 默认 `0o644`。`data` 支持字符串、字节数组、或 0-255 整数数组。

### `fs.stat(path: string): { name, size, mode, modTime, isDir }`

获取文件信息。`modTime` 为 Unix 秒,`mode` 为 32 位无符号权限码,`isDir` 为布尔。

### `fs.readDir(path: string): { name, isDir }[]`

读取目录,返回直接子项列表。

### `fs.mkdir(path: string, mode?: number): void`

递归创建目录。`mode` 默认 `0o755`。

### `fs.remove(path: string): void`

删除文件或空目录。

### 异步接口

以下接口均返回 `Promise`:

| `fs.*Async`                           | `fs.promises.*`                     | 说明             |
| ------------------------------------- | ----------------------------------- | ---------------- |
| `fs.readFileAsync(path)`              | `fs.promises.readFile(path)`        | 读取文件字节     |
| `fs.writeFileAsync(path, data, mode)` | `fs.promises.writeFile(path, data)` | 写入文件         |
| `fs.statAsync(path)`                  | `fs.promises.stat(path)`            | 获取文件信息     |
| `fs.readDirAsync(path)`               | `fs.promises.readDir(path)`         | 读取目录         |
| `fs.mkdirAsync(path, mode)`           | `fs.promises.mkdir(path, mode)`     | 递归创建目录     |
| `fs.removeAsync(path)`                | `fs.promises.remove(path)`          | 删除文件或空目录 |

异步接口与同步接口共享完全相同的路径规则与安全限制。`data://` 沙箱、路径穿越拒绝、symlink escape 防护、以及 `allowFilesystemUnrestrictedAccess` 门控均一致生效。

异步接口会在调用当下完成路径解析与权限检查。若操作已经开始,之后再修改 `allowFilesystemUnrestrictedAccess` 不会影响该次已发起的文件操作。

---

## 简短示例:扩展私有数据存储

```javascript
const fs = require("fs");

let ext = seal.ext.new("fetchWeather", "某人", "1.0.1");

ext.cmdMap["weather-count"] = seal.ext.newCmdItemInfo();
ext.cmdMap["weather-count"].solve = (ctx, msg, cmdArgs) => {
  const path = "data://count.json";

  let data = { count: 0 };
  try {
    const bytes = fs.readFile(path);
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    // 首次调用文件不存在,使用默认值
  }

  data.count++;
  fs.writeFile(path, JSON.stringify(data));

  seal.replyToSender(ctx, msg, `共查询 ${data.count} 次天气`);
  return seal.ext.newCmdExecuteResult(true);
};

seal.ext.register(ext);
```

异步写法:

```javascript
const fs = require("fs");

let ext = seal.ext.new("fetchWeather", "某人", "1.0.1");

ext.cmdMap["weather-count-async"] = seal.ext.newCmdItemInfo();
ext.cmdMap["weather-count-async"].solve = async (ctx, msg, cmdArgs) => {
  const path = "data://count.json";

  let data = { count: 0 };
  try {
    const bytes = await fs.promises.readFile(path);
    data = JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    // 首次调用文件不存在,使用默认值
  }

  data.count++;
  await fs.promises.writeFile(path, JSON.stringify(data));

  seal.replyToSender(ctx, msg, `共查询 ${data.count} 次天气`);
  return seal.ext.newCmdExecuteResult(true);
};

seal.ext.register(ext);
```

上面示例最终写入的真实路径是:`<DataDir>/extensions/fetchWeather/data/count.json` (例如 `data/default/extensions/fetchWeather/data/count.json`)。

---

## 简短示例:读取核心目录下的文件 (需开启完全访问)

> 前提:`data/<dice-name>/advanced.yaml` 中 `allowFilesystemUnrestrictedAccess: true`

```javascript
const fs = require("fs");

// 列出核心可执行文件同目录的 deck 文件夹
const entries = fs.readDir("deck");
for (const e of entries) {
  console.log(e.name, e.isDir);
}

// 读取绝对路径
const bytes = fs.readFile("/etc/hostname");
console.log(new TextDecoder().decode(bytes));
```

---

## 错误参考

| 触发场景                      | 错误信息                                                           |
| ----------------------------- | ------------------------------------------------------------------ |
| 传入空字符串                  | `路径不能为空`                                                     |
| `data://` 但当前没有扩展身份  | `无法确定当前扩展身份,data:// 路径不可用`                          |
| `data://` 路径穿越(`..`)      | `data:// 路径不允许穿越或绝对`                                     |
| 普通/绝对路径但未开启完全访问 | `当前未开启 AllowFilesystemUnrestrictedAccess,仅支持 data:// 路径` |
| 文件系统操作失败              | 原始 `os.*` 错误,如 `no such file or directory`                    |
