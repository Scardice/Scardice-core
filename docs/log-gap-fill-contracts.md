# Scardice 群消息 log 补全：契约与边界

本文记录群消息 log 自动补全的实现契约、边界条件与验证规则，供后续维护和评审参考。

## 四个契约（同一件事只能有一个真相）

1. **覆盖契约**
   - 历史区间拉取用 `HistoryRangeResult{ReachedStart, Boundary}`，不再用一个 `complete` bool。
   - 只有 `ReachedStart`（已到 FromSeq+1）或 `Boundary`（平台明确没有更早历史）才能前移/清除 pending。
   - 部分页非空、首屏空页都不能当“整段完成”；首屏空页按 fail-closed 保留 pending。
   - 绝不能把已取到消息的最大 seq 当 coveredTo。

2. **成员契约**
   - “这个骰子还在这个群服务” = 端点 `Enable` + `DiceIDExistsMap` 中存在。
   - `DiceIDActiveMap` 只是“曾经激活”，不能单独作为活跃依据；退群只删 ExistsMap，ActiveMap 会留脏 ID。
   - ExistsMap 为空（老数据/加载未完成）时保留旧行为，避免误判。
   - 唯一例外：启动对账 `reconcileLogGapForGroup` 在 ExistsMap 完全没有该端点时允许
     用 ActiveMap 兜底（偶有老数据缺 ExistsMap）；不要在其它新路径复制这个兜底。

3. **解析契约**
   - 实时命令走 Segment（`CommandParseNew`）；历史解析必须用 `historicalCommandText`：
     跳过第一个文本段之前的引用/图片/表情，保留前导 @。
   - 不能再直接解析 `m.Message`，否则 `[CQ:reply]` 或前置图片会让 `.bot off` 绕过禁执行、`.log on/off` 漏识别。
   - 新增/修改命令解析时应加差分测试：同一消息的实时文本与历史文本解析结果一致。

4. **状态契约**
   - `GroupInfo` 日志相关字段约 30 个；新增 bool 前先问能否并入派生 `logPhase`（Off/Recording/PausedByBotOff）。
   - 合法组合：Recording = LogOn+name；PausedByBotOff = !LogOn+name+flag；Off = !LogOn。
   - `SetLogState`/`ClearLogState` 必须维护不变量：Recording 不可能同时 Paused；无 name 不保留 Paused/ResumeSkipGap。
   - 任何新状态转换都要有测试，不能只靠注释。

## 多段补全的额外规则

- **不要逐段复用 trigger 锚点**：SnowLuma 的 message_id 路径从触发消息向旧翻页；如果每段都从同一个 trigger 拉，越早的段重复拉取越多，缺口超过页数上限时第 1 段永远到不了起点。正确做法是先按整条缺口预取一次，再在内存里分段过滤。
- **识别 5000 / 补录 2000**：识别窗口最多 5000 条，真正写日志最多 2000 条；超过上限的较早消息不补录，并在群内说明条数，不能保留 pending 无限重试。识别窗口裁剪后仍会回看最多 5000 条前缀来判断窗口起点 on/off；文案必须写成“不补录，仅回看用于判断起点状态”，不能写“不识别”。
- **历史 .log off 生效后要清理实时误记行**：补录拉历史期间实时路径仍会按“日志开启”写库；任务确认历史最终 off 后，只删触发那一条不够，必须删除 `seq > lastOffSeq && time >= lastOffTime` 的行（保留 off 命令本身和 on 段）。否则最终上传的日志会包含关闭期间的聊天。
- **0 条可补也要发关闭通知**：`.log off` 行可能已被上一次失败补录写入、这次被去重，导致 `missing == 0` 但历史状态是 off；此时必须发“离线期间的 .log off 已生效”，不能静默关闭日志。
- **预取不完整时一条都不要写**：只拿到段尾后缀、而 `.log off/.log on` 在没拉到的前缀里时，按 `startOn=true` 过滤会把 off 段写进日志。先确认 ReachedStart/Boundary，再写。
- **旧 HistoryFetcher 的空页例外**：严格的 ReachedStart/Boundary 契约只对
  `HistoryRangeFetcher` 成立。只实现旧 `HistoryFetcher` 的适配器没有边界信号，
  首屏空页按“历史保留期已到”处理并跳过该窗口，否则会无限重试。生产
  go-cqhttp/OneBot 都走 RangeFetcher；新增适配器不要再依赖旧接口。
- **上传/导出前检查 pending**：`.log end/get/masterget/export` 在补全任务/区间未完成时阻止，并提示等待；否则会直接上传缺失的日志。
- **启动后主动对账**：核心重启后不要等第一条群消息才检查；端点就绪后取最新历史 seq 与本地已记录 seq 比较，有缺口就入队。
- **失败要告知**：拉取/去重/无进展/写入失败不能只写核心日志；群内限频提示“将自动重试”。

## 验证规则

- 每个修复至少带一个“当前实现不处理”的反例：部分页、首屏空页、引用回复 `.bot off`、退群但仍启用 ID、关闭日志 ID=0。
- 覆盖契约用属性测试：未 ReachedStart/未 Boundary 时 pending 起点不能前移；多段部分页不得 advance pending。
- 平台语义用真实 wire 形状回放（SnowLuma signed int32 message_id / message_seq / message 段数组；go-cqhttp 19 条/页）；fixture 可以 scrub，但字段形状不能自己发明。
- 测试全绿后仍要做真实群/真实 API 冒烟；测试全绿不等于语义正确。
