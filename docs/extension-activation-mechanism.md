# 扩展注册、代理与群级激活状态

本页定义扩展注册表、JS wrapper、群级激活状态和 `ActiveWith` 联动的运行时契约。扩展查询使用全局注册表，消息分派使用群级激活列表，JS 扩展通过稳定 wrapper 解析到当前真实实例。

## 运行时对象

扩展系统由全局索引、JS 实例索引和群级状态共同组成。

| 对象 | 内容 | 作用 |
|---|---|---|
| `Dice.ExtList` | 有序的 `[]*ExtInfo` | 保存可枚举扩展；内置扩展存放真实对象，JS 扩展存放 wrapper |
| `Dice.ExtRegistry` | 名称或别名到 `*ExtInfo` 的并发映射 | 提供名称、别名和小写键查询；JS 条目指向 wrapper |
| `Dice.JsExtRegistry` | JS 扩展名到真实 `*ExtInfo` 的并发映射 | 保存当前 JS runtime generation 注册的实例 |
| `Dice.ActiveWithGraph` | 目标扩展名到伴随扩展名列表的反向图 | 驱动传递开启和关闭 |
| `GroupInfo.activatedExtList` | 当前群的有序 `[]*ExtInfo` | 提供命令解析和钩子分派的扩展顺序 |
| `GroupInfo.InactivatedExtSet` | `StringSet` | 记录手动关闭或按默认设置保持关闭的扩展名 |

`ExtRegistryVersion` 在 `RegisterExtension` 成功时递增，供群组发现新增扩展。`ExtUpdateTime` 在 JS 实例注册或删除时更新，供群组刷新 wrapper 状态。

## 全局注册

全局注册把扩展加入枚举列表和名称索引，并使伴随图进入待重建状态。

### `RegisterExtension`

`Dice.RegisterExtension(extInfo)` 注册内置扩展、原生扩展或新建的 JS wrapper。

1. `Name` 与每个 `Aliases` 先通过 `ExtFind` 检查名称碰撞。
2. 名称碰撞触发 panic：`扩展<新扩展>的名称"键"与扩展<已有扩展>冲突`。
3. 注册成功后，`extInfo.dice` 指向所属 `Dice`，对象追加到 `ExtList`。
4. `ExtRegistry` 写入名称、别名及其小写键；空键直接跳过。
5. `ExtRegistryVersion` 递增，`ActiveWithGraph` 置为待重建状态。

### JS 扩展注册

`seal.ext.new(name, author, version)` 创建 `AutoActive=true` 的真实 JS `ExtInfo`。`seal.ext.register(realExt)` 按名称维护稳定 wrapper 和当前真实实例。

| 前置状态 | 结果 |
|---|---|
| `realExt == nil` | 返回 `注册扩展失败: 扩展为空` |
| 名称属于 `help`、`all` | 返回保留关键字错误 |
| `ExtRegistry[name]` 指向真实扩展 | 返回 `注册扩展失败: 扩展名 %q 已被占用` |
| 持久身份注册失败 | 返回包含扩展名和底层原因的错误 |

新名称创建 wrapper，并通过 `RegisterExtension` 写入 `ExtList` 和 `ExtRegistry`。wrapper 保存 `Name`、`TargetName`、`AutoActive`、`ActiveWith`、来源和 JS loop generation；`JsExtRegistry[name]` 保存真实对象。

已有 wrapper 复用原指针，并更新 `Author`、`Version`、`Source`、`JSLoopVersion` 和 `ActiveWith`，同时设置 `IsDeleted=false`、把伴随图置为待重建状态。`AutoActive`、`Official`、`Brief` 和 `TargetName` 保持 wrapper 当前值。随后 `JsExtRegistry[name]` 原子替换为新真实对象；已有真实对象与新对象指针各异时记录来源告警。最后更新 `ExtUpdateTime`，并在 `OnLoad` 存在时立即执行回调。wrapper 注册触发的 panic 由 `seal.ext.register` 转换为 `注册扩展失败` 错误。

## Wrapper 解析

wrapper 让群级列表和全局索引持有稳定对象，同时把命令与钩子解析到当前 JS 实例。

`ExtFind` 接受名称、别名和 `author/name`。普通查询依次使用 `ExtRegistry` 原键、小写键和 `ExtList` 回退匹配；完整名称对作者与名称执行大小写折叠匹配。查找缺席时 `ExtFind` 返回 `nil`；`ExtAliasToName` 在注册命中时返回主名称，在查找缺席时返回输入字符串。

| API 或状态 | 解析结果 |
|---|---|
| `ExtFind(name, false)` | 返回内置真实对象或 JS wrapper |
| `ExtFind(name, true)` | JS wrapper 返回 `JsExtRegistry[TargetName]`；官方扩展返回命令表副本 |
| `GetRealExt()` 作用于真实对象 | 返回对象自身 |
| `GetRealExt()` 作用于有效 wrapper | 返回当前真实 JS 对象 |
| `IsDeleted=true`、owner 缺席或真实实例缺席 | `GetRealExt()` 返回 `nil` |
| `GetCmdMap()` 解析成功 | 返回真实扩展命令表的快照 |
| `JsReloading=true` 或真实实例解析结果为 `nil` | `GetCmdMap()` 返回空 `CmdMapCls` |

命令查询通过 `GetCmdMap()` 取得并发安全快照。`CallOnMessage*`、`CallOnCommand*`、`CallOnPoke` 等 wrapper 方法先调用 `GetRealExt()`，解析成功后进入对应 runtime generation；解析结果为 `nil` 时，本次分派结束。

JS 删除把 wrapper 置为 `IsDeleted=true`，关闭真实扩展存储，并从 `JsExtRegistry` 删除真实对象。群级列表继续保留 wrapper 名称；同名扩展再次注册时复用该 wrapper 并恢复解析。

## 群级状态

每个群通过激活列表和关闭集合保存扩展状态。

| 字段 | 状态语义 |
|---|---|
| `activatedExtList` 包含扩展名 | 该条目参与命令与钩子分派 |
| `InactivatedExtSet` 包含扩展名 | 该扩展保持关闭 |
| 两处均缺席 | 下一次同步按有效 `AutoActive` 值确定初始状态 |
| `ExtAppliedVersion` | 最近应用的 `ExtRegistryVersion` |
| `ExtAppliedTime` | 最近应用的 `ExtUpdateTime`；值 `0` 触发运行时初始化 |

有效自动激活条件为：

```go
ext.AutoActive || (ext.DefaultSetting != nil && ext.DefaultSetting.AutoActive)
```

条件为 `true` 时扩展进入激活列表；条件为 `false` 时扩展名进入 `InactivatedExtSet`。

## 延迟初始化与同步

群组在消息路径上完成引用解析和新增扩展同步。`GetPlayerInfoBySenderRaw` 依次调用 `SyncWrapperStatus` 和 `SyncExtensionsOnMessage`。

`GetActivatedExtList(d)` 在 `ExtAppliedTime == 0` 时执行以下转换：

1. 按名称把已保存条目解析为 `ExtList` 中的当前对象。
2. 注册实体缺席的已保存名称保留占位对象；`UnmarshalJSON` 为这类名称提供 `extPlaceholderPool` 中共享的 `ExtInfo{Name: name}`。
3. 对 `ExtList` 中同时缺席于激活列表和关闭集合的扩展应用有效 `AutoActive` 条件。
4. 自动激活项插入列表头部；关闭项写入 `InactivatedExtSet`。
5. `ExtAppliedTime` 写入 `ExtUpdateTime`；全局时间为 `0` 时写入 `1`。

`SyncWrapperStatus(d)` 在 `ExtUpdateTime` 前进后过滤 `nil` 条目，并保留 `IsDeleted` wrapper 作为可恢复名称。`SyncExtensionsOnMessage(d)` 在注册表版本变化后重新解析占位对象、处理新增扩展，并写入当前 `ExtRegistryVersion`。

`ApplyExtDefaultSettings()` 把配置项绑定到扩展。`AutoActive=true` 的名称会从各群 `InactivatedExtSet` 移除，并把 `ExtAppliedVersion`、`ExtAppliedTime` 置为 `0`；下一条消息完成激活。`AutoActive=false` 作为新增扩展的初始关闭策略，已有激活条目继续保留在 `activatedExtList`。

## 激活操作

群级 API 在 `extInitMu` 保护下更新激活列表和关闭集合。

| API 或前置状态 | 结果 |
|---|---|
| `ei == nil` 或 `ei.dice == nil` | 激活状态保持当前值；关闭 API 返回 `nil` |
| `ExtActive(ei)` | `ei` 和 `ei.dice` 有效时，开启目标及其传递伴随扩展 |
| `ExtActivateBatch(exts, firstLoad)` | 候选名称位于激活列表和关闭集合之外；`firstLoad[name]=true` 或有效 `AutoActive=true` 时开启，其余候选写入关闭集合 |
| `ExtInactive(ei)` | 关闭目标及其传递伴随扩展，名称写入关闭集合 |
| `ExtInactiveSystem(ei)` | 关闭目标及其传递伴随扩展，关闭集合保持当前值 |
| `ExtInactiveByName(name)` | 找到激活条目时执行手动关闭并返回目标；查找缺席时返回 `nil` |
| `ExtGetActive(name)` | 返回同名激活条目；查找缺席时返回 `nil` |
| `GetActivatedExtList(d)` | 返回完成延迟初始化的列表 |
| `GetActivatedExtListRaw()` | 返回锁保护下的当前列表，供序列化和内部状态操作使用 |
| `SetActivatedExtList(list, d)` | 替换列表；`d` 有效时写入 `d.ExtUpdateTime`，`d == nil` 时写入 `1` |

`promoteExt` 先从 `InactivatedExtSet` 移除名称，再删除列表中的同名条目，最后把对象插入列表头部。每次手动开启或伴随开启都会应用这一顺序。

关闭操作从激活列表移除目标名称；真实扩展持有存储时同时执行 `StorageClose()`。`extActivateInternal` 和 `extDeactivateInternal` 在列表转换后调用 `MarkDirty`。

## `ActiveWith` 联动

`ExtInfo.ActiveWith` 声明当前扩展跟随的目标。`BuildActiveWithGraph` 将声明转换为反向图：`A -> [B, C]` 表示 `B`、`C` 跟随 `A`。

开启和关闭都使用深度优先遍历收集传递伴随项。遍历深度上限为 10；第 11 层触发告警并结束该分支。循环边触发告警，`visited` 集合保证每个伴随名称处理一次。

开启流程先提升主扩展，再按遍历结果逐项调用 `promoteExt`；较晚提升的条目位于列表更前。关闭流程对主扩展和同一传递闭包执行移除。

## 持久化

群组 JSON 通过自定义 `MarshalJSON` 和 `UnmarshalJSON` 序列化激活条目，并在反序列化时按名称解析共享对象。

- `activatedExtList` 序列化选择 `ext != nil` 的条目，包括 `IsDeleted` wrapper。
- 反序列化只读取每个条目的 `name`；已注册名称解析到全局共享 `ExtInfo`，注册实体缺席的名称解析到 `extPlaceholderPool`。
- 同一缺席名称在所有群中共享一个占位指针。
- `InactivatedExtSet` 的运行时结构为 `map[string]struct{}`；YAML 表示为排序后的字符串数组。
- `ExtAppliedTime` 属于运行时状态；进程启动后由消息路径重新建立。
