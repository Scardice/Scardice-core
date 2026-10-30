# OneBot 出站消息码

OneBot 出站文本支持混排纯文本、海豹资源码和 CQ 码。运行时把有效消息码转换为 OneBot 消息段，把 `recall` 转换为撤回指令，再通过协议端执行发送与撤回。

## 解析流程

消息码解析覆盖纯文本 payload 和分段 payload 中的 `text` 段。运行时按原始顺序扫描以下语法：

```text
\[(img|图|文本|text|语音|voice|视频|video):资源]
\[CQ:类型,键=值,...]
```

相邻消息码之间的内容生成 `text` 段。语法匹配或参数校验失败的片段同样生成 `text` 段，并保留原文。分段 payload 中的 `mention` 段要求 `QQ:<正整数>`，成功后生成 `at` 段。

## 海豹资源码

海豹资源码把单个资源引用转换为图片、语音或视频段。

| 写法 | OneBot 消息段 | 说明 |
|---|---|---|
| `[图:<资源>]`、`[img:<资源>]` | `image` | 图片 |
| `[文本:<资源>]`、`[text:<资源>]` | `image` | 图片别名 |
| `[语音:<资源>]`、`[voice:<资源>]` | `record` | 语音 |
| `[视频:<资源>]`、`[video:<资源>]` | `video` | 视频 |

示例：

```text
检定结果：[图:data/images/result.png]
```

海豹资源值接受 `http://`、`https://`、`base64://` 和本地资源路径。资源解析失败时，该码生成内容为 `[找不到图片/文件]` 的 `text` 段。

## CQ 码

CQ 码语法为 `[CQ:<类型>,<键>=<值>,...]`，其中 `CQ` 前缀采用大写拼写。类型名接受字母、数字、下划线、点和连字符；参数键经过首尾空白裁剪，重复键采用最后一个值。

参数值支持以下 CQ 转义：

| 源文本 | 解析值 |
|---|---|
| `&amp;` | `&` |
| `&#91;` | `[` |
| `&#93;` | `]` |
| `&#44;` | `,` |

以下类型带有运行时语义：

| 类型 | 处理结果 |
|---|---|
| `image`、`file`、`record`、`video` | 解析 `file` 或 `url`，然后生成同名资源段 |
| `recall` | 生成撤回指令并从待发送消息链中消费 |

资源类型和 `recall` 按小写形式匹配；生成的资源段使用小写类型名。通用类型保留输入中的大小写。

其余语法有效的类型保留原类型名和参数并生成 OneBot 段，例如 `at`、`tts`、`reply`、`poke`、`face`、`forward`、`json`、`xml`、`share` 和 `location`。协议端对这些段给出最终执行结果。

资源型 CQ 码要求 `file` 或 `url` 至少提供一个有效引用。两个字段同时存在时分别解析；解析成功的字段写回转换结果，其余参数保持原值。`url` 是唯一引用时，解析结果同时写入 `url` 和 `file`。字段同时缺席时，完整 CQ 码作为文本保留。

## 资源解析

资源解析按直接引用、本地文件、OneBot 上传资源 ID 的顺序执行。

| 输入 | 前置条件 | 结果 |
|---|---|---|
| `http://...`、`https://...`、`base64://...` | scheme 大小写任意 | 原值进入资源段 |
| 相对路径 | `images/a.png`、`data/images/a.png` 等路径最终位于共享 `data/` 根目录 | 解析为 Base64 或资源服务 URL |
| 绝对路径 | 规范化及符号链接解析结果位于共享 `data/` 根目录 | 解析为 Base64 或资源服务 URL |
| `file://` URL | host 为空或 `localhost`，query 与 fragment 为空，路径位于共享 `data/` 根目录 | 解析为 Base64 或资源服务 URL |
| OneBot 上传资源 ID | CQ 资源字段为单段名称，且本地文件解析返回错误 | 原值交给协议端 |

运行时将 `ResourceRoot` 的父目录作为共享资源根。例如 `ResourceRoot=data/default` 对应 `data/`；构造参数省略资源根时采用 `./data`。

本地文件分支由 `resolveLocalAsset` 按以下边界转换：

| 文件状态 | 转换结果 |
|---|---|
| 大小 `<= 200 KiB` | `base64://<内容>` |
| 大小 `> 200 KiB` 且 `<= 10 MiB`，资源访问 token 与 base URL 齐备 | `<baseURL>/assets-img/<token>/<data内相对路径>` |
| 大小 `> 200 KiB` 且 `<= 10 MiB`，URL 发布条件缺席 | `base64://<内容>` |
| 文件缺席、目录、根目录外路径、符号链接逃逸、大小 `> 10 MiB` | `resolveLocalAsset` 返回错误，随后进入 CQ 上传资源 ID 条件判断 |

`http`、`https` 和 `base64` 构成直接引用 scheme 集合，`file` 进入本地文件分支。其余 scheme 在海豹资源码中产生解析错误；CQ 资源字段的单段值进入上传资源 ID 分支，包含 `/` 或 `\` 的其余 scheme 产生解析错误。

配置项 `imageAssetBaseUrl` 接受 host 有效且 userinfo、fragment 为空的 HTTP/HTTPS URL。该配置为空且资源访问 token 存在时，运行时使用资源服务端口和候选 IPv4 推导 HTTP base URL；候选集合为空时使用 `127.0.0.1`。资源型消息码把最终解析错误转换为 `[找不到图片/文件]` 文本段。

## 撤回语法

`[CQ:recall]` 支持显式消息 ID、刚发送消息的 ID 和毫秒级延时。

```text
[CQ:recall,id=123456]
消息内容[CQ:recall]
消息内容[CQ:recall,delay=5000]
```

| 参数 | 有效值与结果 |
|---|---|
| `id` | 十进制有符号 `int64`，有效范围为 `[-9223372036854775808, -1]` 和 `[1, 9223372036854775807]` |
| `id` 省略 | 使用本次正文发送返回的 `message_id` |
| `delay` | `0` 到 `9223372036854` 毫秒；省略或 `0` 表示立即撤回，正数表示延时撤回 |

运行时先解析全部撤回指令，再为带有效目标的延时撤回预留容量。正文消息发送成功后，省略 `id` 的指令绑定返回的 `message_id`；显式 `id` 始终指向该 ID。立即撤回在当前调用中执行，延时撤回在计时器登记完成后异步执行。

每个端点最多容纳 64 个等待中或执行中的延时撤回。每个延时撤回占用一个槽位，槽位在协议调用完成或运行时取消后释放。延时到达后，`delete_msg` 调用使用 30 秒超时；端点停止会取消该端点的计时器和执行上下文。

## 校验与执行结果

消息码完成校验后进入协议 I/O，结果按以下规则分类。

| 条件 | 结果 |
|---|---|
| 消息码语法或 CQ 参数格式校验失败 | 原片段作为 `text` 段发送 |
| 资源型 CQ 码的 `file` 与 `url` 同时缺席 | 完整 CQ 码作为 `text` 段发送 |
| 海豹资源码或资源型 CQ 码的可用引用全部解析失败 | 生成内容为 `[找不到图片/文件]` 的 `text` 段 |
| 分段 payload 的 kind 位于 `{text, mention}` 之外，或 `mention` 文本超出 `QQ:<正整数>` 语法 | `EffectUnsupported`，原因 `onebot_unsupported_segment`，协议调用数为 `0` |
| `recall.id` 为 `0`、十进制解析失败或超出 `int64` | 该 CQ 码作为文本发送 |
| `recall.delay` 为负数、解析失败或超出上限 | 该 CQ 码作为文本发送 |
| 消息链长度为 `0`，且全部撤回指令均缺少可用目标 | `EffectUnsupported`，原因 `onebot_recall_target_missing` |
| 延时撤回剩余容量小于本次需求，或运行时已停止 | `EffectTerminal`，原因 `onebot_recall_queue_full`，协议调用数为 `0` |
| 正文发送响应缺少有效 `message_id` | uncertain 结果，原因 `onebot_response_uncertain` |
| 正文发送成功，随后延时撤回登记失败 | `EffectAmbiguous`，原因 `onebot_recall_schedule_failed`，并返回正文 `ProviderID` |
| 仅含显式立即撤回，且 `delete_msg` 返回错误 | 按 `delete_msg` provider error 分类返回 |
| 正文发送成功，随后立即撤回返回错误 | 正文结果保持 `EffectSucceeded`，`outbound.recall_failed` 计数递增 |
| 延时 `delete_msg` 返回错误 | `outbound.recall_failed` 计数递增，已完成的发送结果保持原值 |
