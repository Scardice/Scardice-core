# JavaScript 插件示例

## 合并转发转染色器 Log

[`logConvertForwardDemo.js`](./logConvertForwardDemo.js) 是一个可直接导入的完整插件，也是一份带注释的开发示例。它展示了：

- 用 `ext.onMessageReceived` 读取 `msg.segment`；
- 识别 `ForwardElement`，并按顺序读取 `forward.nodes`；
- 读取节点的发送者、时间和结构化消息段；
- 注册 `.logconvert` 与 `.log转写` 两个命令名；
- 按群聊/私聊分别保存一次收集任务；
- 不依赖核心 Log API，直接生成故事染色器 V1 JSON、zlib 和 multipart 请求；
- 使用 `fetch` 上传到 `https://story-painter.cn.xuetao.host/api/dice/log`。

使用流程：

```text
.logconvert 开始
（发送一个或多个合并转发）
.logconvert 结束
```

插件只会收集合并转发中的聊天节点，普通消息不会进入 Log。收集状态位于内存中，重载插件或重启骰子会清除未完成的任务。
