# 性能与资源效率

Scardice Core 通过有界读取、索引化调度、事务内复用和显式生命周期管理控制 CPU、分配与常驻对象。数据库保存耐久事实，通知负责唤醒，缓存负责复用，事务与围栏负责最终授权。

## 可靠性边界

性能机制遵循以下数据安全与一致性约束。

- SQLite 事件库使用 `synchronous=FULL`，事件信封使用 SHA-256 校验，敏感载荷使用 AES-GCM。
- `Commit`、队列领取和投影发布均在数据库事务内完成授权；privacy fence、readiness 和 publication lock 共同约束写入。
- Inbox 与 outbox 通过 lane 顺序、幂等标识、版本、租约 epoch、TTL 和 `ambiguous` 隔离状态表达处理进度。
- 写库与协议发送均绑定唯一 operation、inbox 或 effect 标识，并通过耐久状态转换记录执行边界；恢复流程读取耐久状态后决定下一次动作。
- 属性写入以 revision 和缓存代际为发布条件；保存成功且 revision 保持一致时，`IsSaved` 转为 `true`，其余结果持续保留脏状态。

## 文本与配置解析

文本和配置入口复用编译结果，并按原始字符串偏移处理数据。

| 路径 | 当前机制 | 语义约束 |
| --- | --- | --- |
| `utils.SplitLongText` | 包级 `cqCodePattern` 只编译一次；`findSplitPoint` 扫描到首个超限 UTF-8 边界；分页循环沿原字符串切片前进 | 长度按字节计算；CQ 码整体保留；连续换行、末个换行、空白页过滤和分页提示保持既定优先级 |
| `GroupInfo.UnmarshalJSON` | `sonic.Unmarshal` 一次解码 alias 字段和 `activatedExtList` 名称；扩展注册表就绪后加载群配置 | 已注册名称解析为共享 `ExtInfo`；其余名称解析为占位对象；序列化继续保存扩展名称与启用状态 |
| `censor.trie.Match` | 直接遍历字符串 rune 起点，并从当前字节偏移继续 trie 匹配 | 每个起点采用首个终止词；结果按词键归并，`Censor.Check` 再映射到原词并计算最高等级 |

## Readiness 与密钥读取

事件库将高频校验和完整审计分配到各自的数据范围。

- `Commit` 先锁定 `store_readiness` 与 `projection_control`，随后把同一行传给 `validateReadinessSnapshotOnDB`。内部校验借用行内 manifest 字节；`GetReadiness` 为调用方复制所有字节切片。
- 运行时 readiness 查询读取元数据、摘要和 manifest 长度；`ValidateReadiness` 与投影重建执行完整 manifest、终点和加密根引用审计。
- `readinessRootReferences` 通过七个 `DISTINCT` 分支组成 `UNION ALL`，覆盖 adapter secret、operation private context、artifact、inbox、outbox 以及 plugin key/value 密文。Go 以区分大小写的字符串集合归并 root ID。
- `LocalFileKeySource` 在首次成功读取后保存 32 字节 index root。encryption root 与 `current` root ID 使用默认 5 秒 TTL，读取调用负责到期刷新；所有公开返回值均为材料副本。

## 耐久队列调度

Inbox 与 outbox 各使用一个协调器管理空闲探测，worker 池继续并发处理可领取 lane。

- `lane_heads` 为每个 queue kind 与 lane 保存 active ID、序列、就绪动作和就绪时间；`ix_lane_heads_action_ready` 支持按 `ready_at`、`active_since` 和 `lane_hmac` 选择候选。
- 提交后的容量 4 通知通道触发协调器广播；定时探测从 inbox 50 ms、outbox 100 ms 开始退避，上限为 500 ms。
- 每个协调器持续执行探测与广播。四个 callback worker 和四个 effect worker 分别执行回调与发送；单次执行占用一个 worker，其余 worker 继续领取可用 lane。
- `HasInboxWork` 与 `HasOutboxWork` 提供唤醒判定；`ClaimInbox` 与 `ClaimOutbox` 在 publication lock 下完成行锁、载荷认证、版本条件更新和 lane head 刷新。
- TTL 清理按状态分支执行 `UNION ALL`，每批最多选择 128 个 ID，再按主键锁定实体行并更新调度头。

## 投影与属性恢复

属性投影通过 keyset 游标和完整快照令牌保持分页一致性。

- `ProjectionPageRequest` 每页范围为 1 到 `MaxProjectionReadPageRows`，当前上限为 5000。查询按 `row_key` 升序读取，并以 `AfterRowKey` 推进游标。
- `ProjectionSnapshot` 组合 generation、terminal position 和 history revision。后续页携带 `ExpectedSnapshot`；发布、实时终点或隐私修订变化返回 `ErrParticipantConflict`。
- Dice 属性范围使用长度前缀编码和半开区间定位；返回前再次校验完整 row key 与 `DiceID`，数据库 collation 与公开身份语义保持分离。
- 启动先通过 `ValidateProjected` 分页校验全局投影，再按同一快照读取当前 Dice 的元数据。密文恢复以 5000 条为一批，明文字节在批处理结束时清理。
- 普通角色列表在单次事务内按 Dice row-key 前缀读取，并逐行校验完整编码身份。

## 属性缓存生命周期

`AttrsManager` 用 ID 与 group 两层代际令牌控制并发加载、保存和失效。

- 同一 ID 的冷读取由 `singleflight.Group` 合并；获选调用从耐久状态解析 `ValueMap`，并把同一结果交给并发调用方。
- 代际令牌以指针身份表示一次有效期，并记录 resident、load 和 save owner。失效操作标记令牌、移除活动槽位并对对应 ID 调用 `singleflight.Forget`。
- 在途加载发布前核对 ID 与 group 令牌；代际变化时，加载循环取得当前令牌并重新读取。
- 保存操作在 I/O 期间持有两层令牌和 save revision；返回后仅向当前代际发布 state。
- 已保存、空闲超过 10 分钟、修改超过 10 分钟且 `savesInFlight == 0` 的对象进入回收路径。令牌表按 owner 归零回收槽位，并在累计空槽达到阈值时重建活动 map。
- 启动恢复将完整有效属性集写入内存缓存；后续回收与冷读取共享同一代际协议。

## 消息与端点生命周期

消息执行和端点切换在工作完成边界释放引用并发布终态。

- `MsgContext.releaseExecutionState` 通过 `sync.Once` 停止本次 JS execution，并清理 VM、命令解析、牌堆池和随机源引用。同步执行在返回边界释放；异步命令与扩展回调在最后一个执行单元结束时释放；durable callback 在事务结果收集完成后释放。
- `PendingQuits` 以 group 与 endpoint 组成键，成功消费执行一次 `LoadAndDelete`。30 秒 housekeeping 使用指针 `CompareAndDelete` 清理到期项，键被替换时保留当前登记。
- Supervisor 的 lifecycle observation 携带 generation 与 desired version。完成命令遇到围栏推进时读取耐久端点状态并收敛已过期观察；当前围栏错误返回调用方。
- replace 与 relogin 清理沿 worker 自身围栏发布终态；显式 stop 与 delete 沿命令围栏发布终态。后继连接在自身 lifecycle observation 到达后完成对应 operation。
