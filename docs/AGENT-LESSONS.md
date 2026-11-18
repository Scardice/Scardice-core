# Scardice 日志补全：给后续 Agent 的教训

这份文档记录 1115→1120 反复出 bug 的根因，避免后续对话继续“加 if 修症状”。

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

## 多段补全的额外规则（1120 实测）

- **不要逐段复用 trigger 锚点**：SnowLuma 的 message_id 路径从触发消息向旧翻页；如果每段都从同一个 trigger 拉，越早的段重复拉取越多，缺口超过页数上限时第 1 段永远到不了起点。正确做法是先按整条缺口预取一次，再在内存里分段过滤。
- **预取不完整时一条都不要写**：只拿到段尾后缀、而 `.log off/.log on` 在没拉到的前缀里时，按 `startOn=true` 过滤会把 off 段写进日志。先确认 ReachedStart/Boundary，再写。
- **上传/导出前检查 pending**：`.log end/get/masterget/export` 在补全任务/区间未完成时阻止，并提示等待；否则会直接上传缺失的日志。
- **启动后主动对账**：核心重启后不要等第一条群消息才检查；端点就绪后取最新历史 seq 与本地已记录 seq 比较，有缺口就入队。
- **失败要告知**：拉取/去重/无进展/写入失败不能只写核心日志；群内限频提示“将自动重试”。

## 验证规则

- 每个修复至少带一个“当前实现不处理”的反例：部分页、首屏空页、引用回复 `.bot off`、退群但仍启用 ID、关闭日志 ID=0。
- 覆盖契约用属性测试：未 ReachedStart/未 Boundary 时 pending 起点不能前移；多段部分页不得 advance pending。
- 平台语义用真实 wire 形状回放（SnowLuma signed int32 message_id / message_seq / message 段数组；go-cqhttp 19 条/页）；fixture 可以 scrub，但字段形状不能自己发明。
- 测试全绿后仍要做真实群/真实 API 冒烟；测试全绿不等于语义正确。

## 节奏

- 1115 一个版本打了 7 个 fix 包；1115→1119.fix1 有 15 个提交改 `dice/ext_log.go`。按最新症状缩范围、加局部 guard，会导致模型债务累积。
- 优先做“不加功能、只收敛契约”的版本；fix 包只做已确认的小修。
- 交付说明必须写 known boundaries 和未修项，不能拿测试全绿代替验收。
