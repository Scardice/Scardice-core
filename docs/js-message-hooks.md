# JS 消息钩子

| 钩子 | 时机 |
|---|---|
| `onMessagePreprocess(ctx, msg)` | 收到消息后、解析命令前；可以改写或取消入站消息 |
| `onBeforeMessageSend(ctx, outgoing, flag)` | 逻辑出站文本成形后、输出审查和拆包前；可以改写或取消发送 |
| `onMessageSend(ctx, msg, flag)` | 适配器通知；不能改写或取消发送 |

## `onBeforeMessageSend`

`outgoing` 描述实际发送目标，`ctx` 仍是发起发送的上下文。比如暗骰从群上下文发私聊时，应根据 `outgoing.messageType` 和 `outgoing.targetId` 判断目标。

| 字段 | 含义 |
|---|---|
| `message` | 已拼入回复前缀、尚未拆分的文本 |
| `messageType` | `group` 或 `private` |
| `targetId` | 群 ID 或收件用户 ID |
| `groupId` | 群 ID，私聊时为空 |
| `platform`、`sender` | 实际发送平台和机器人身份 |

`flag` 保持原发送标记。只读取钩子的返回值；直接改写 `outgoing` 不会修改文本或目标。

| 返回值 | 行为 |
|---|---|
| `undefined`、`null` | 放行 |
| 非空字符串、`{ message: "文本" }` | 替换整条文本 |
| `""`、`{ message: "", reason: "原因" }` | 取消；`reason` 可省略 |

对象须有自有 `message` 属性。与 `onMessagePreprocess` 一样，对象中的 `false`、`0`、`null`、`undefined` 也表示取消，其他未定义的返回值放行。钩子同步执行，不等待 Promise；抛异常时跳过该扩展。不要在钩子内同步调用 `seal.reply*`。

按实际目的会话发送开始时的激活顺序执行。下一扩展收到前一次改写的文本；取消后不再执行后续扩展，也不触发发送通知。没有已启用的目标会话时照常发送，不建立新会话。

适用于普通群聊和私聊文本回复、主动通知和欢迎语等，包含文本里的 CQ 码、余烬码和合并转发块。不拦截独立 `seal.replyForward`、原生消息段、文件、内部审查、封禁与限流告警、编辑、撤回或协议直发。
