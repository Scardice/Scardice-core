# Slice05 Task5：统一消息执行路径报告

## Ownership 与调用者

本任务只修改 `dice` 消息入口相关代码：

- `dice/im_session.go`
  - 删除原 `ExecuteNew` 的完整复制主体。
  - 新增唯一内部 `executeMessage` 算法。
  - `IMSession.Execute` 仅选择 legacy 字符串 parser 与 `runInSync`。
  - `IMSession.ExecuteNew` 仅选择 segment-aware parser 与异步调度。
- `dice/execute_new_test.go`
  - 增加 wrapper differential、segment/@、unsupported、sync/async hook 行为测试。
- `dice/platform_adapter_onebot_inbound.go`
  - `ExecutePureOnebotInbound` 不再直接调用 `ExecuteNew`。
  - 通过 `IMSession.PureOnebotInboundExecutor adapterapi.CorePort` 注入 durable ingress seam。
  - 覆盖无 durable executor、receipt ID、ProviderEventID fallback 及注入 CorePort 的转发行为。
  - 删除仅供旧直 dispatch 使用的 dead `pureOnebotCoreMessage` mapper。

已核对的真实 legacy callers 保持原签名：DingTalk、Discord、DoDo、GoCQ、GoCQ channel、Kook、Minecraft、Official QQ、Red、Satori 等继续调用 `Execute(..., runInSync)`；Milky、现有 OneBot legacy adapter、补录路径和测试继续调用 `ExecuteNew`。未改动 UI sibling、`core/messageflow` 或 `eventstore`。

## 算法与行为

`executeMessage` 统一完成 context 建立、群组/玩家状态、权限、消息接收与预处理 hook、禁用/敏感词拦截、命令解析、命令/非命令 hook 调度和异常处理。`messageExecutionOptions` 只承载 parser mode 与 scheduling policy：

- legacy wrapper 使用 `CommandParse`、旧文本 @ 解析，并严格保留 `runInSync=true/false`。
- new wrapper 使用 `CommandParseNew`、segment-aware mention 解析，且保持异步 command/non-command hook 行为。
- `messageExecutionResult` 记录 command、mention、intercepted、unsupported；dispatch 和提前返回依据同一个结果，不再存在两份主体。
- segment 文本重建仍在统一入口完成，保留 `ExecuteNew` 的 segment/@ 语义。

## Pure OneBot 边界

纯 OneBot runtime 的生产 transport 路径已经是 `handleInbound -> CorePort.HandleInbound`，由 supervisor 绑定 generation/fence 后进入 durable inbound service；本任务没有绕过该路径接入 legacy core。

历史 `ExecutePureOnebotInbound` helper 曾直接构造 `Message` 并调用 `ExecuteNew`，现已改为仅将 provider-neutral `adapterapi.InboundMessage` 转发到可注入 `CorePort`；不再合成 rejected/accepted receipt 的 InboxID，accepted/duplicate 必须由 durable executor 返回真实 InboxID。没有注入 durable executor 时明确返回 `ErrPureOnebotInboundUnavailable`，避免伪装成已持久化。startup composition 尚未把该历史 helper 绑定到具体 callback worker；这属于 callback service worker/startup wiring 的明确后续边界。当前实际纯 OneBot runtime 不使用该 helper，也不在 provider reader goroutine 中执行 legacy `ExecuteNew`。

## TDD / focused evidence

先增加 durable ingress seam 测试并运行红测：

```text
go test ./dice -run 'TestExecutePureOnebotInbound' -count=1
FAIL: PureOnebotInboundExecutor undefined
```

完成最小实现后通过：

```text
go test ./dice -run 'TestExecutePureOnebotInbound' -count=1
ok
```

wrapper 与边界 focused 测试通过：

```text
go test ./dice -run 'TestExecuteWrappersShare|TestExecuteNewPreservesSegment|TestExecuteRunInSync|TestExecuteSetsTempVarsBeforeNonCommandHook|TestExecuteLeavesUnsupportedMessageUnchanged|TestExecutePureOnebotInbound|TestExecutePureOnebotInboundRejectsMissingDurableInboxID' -count=1
ok
```

验收 focused 集合通过：

```text
go test ./dice -run 'Execute|PureOnebot|Onebot|MessageAlgorithm|MessageFlow' -count=1
ok
```

未运行 formatter、linter 或项目级全套测试。

## 实现提交

本任务实现提交：`dcc27905309c5a8a732811dc3293fb7c3ec9aa80`；兼容行为修正提交：`46fae7b87142b9fd587f1432ac743eec8467a4f7`；回归修正、receipt 校验、unsupported ordering、private logs 与 dead mapper 清理提交：`5d4bf316df24d21c9ae3ec112a320cea8eba5b40`。三个代码提交均仅包含本任务 ownership 内的文件；集成 owner 可在合并其他 slice 后继续生成上层集成提交。
