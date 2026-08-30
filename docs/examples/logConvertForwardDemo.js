// ==UserScript==
// @name         合并转发转染色器 Log（Demo）
// @author       Scardice
// @version      1.0.0
// @description  演示读取合并转发、按会话收集聊天记录，并直接上传到故事染色器。
// @timestamp    2026-08-30
// @license      MIT
// ==/UserScript==

/*
 * 使用方式（可直接作为 JS 插件导入）：
 *   .logconvert 开始
 *   （在同一群聊或私聊中发送任意数量的合并转发）
 *   .logconvert 结束
 *
 * 中文别名：.log转写 开始 / .log转写 结束
 *
 * 这个 Demo 特意不调用核心的 Log 上传接口，而是完整演示以下过程：
 *   1. 从 msg.segment 找到 type === "forward" 的合并转发；
 *   2. 从 forward.nodes 读取 senderId / senderName / time / elements；
 *   3. 生成故事染色器 V1（version=101）日志；
 *   4. 用纯 JavaScript 生成 zlib 数据；
 *   5. 自己拼 multipart/form-data，并用 fetch PUT 到染色器后端。
 *
 * 收集状态只保存在内存中。重载插件或重启骰子会终止尚未结束的收集任务。
 */

const LOG_CONVERT_BACKEND = "https://story-painter.cn.xuetao.host/api/dice/log";
const STORY_LOG_VERSION = 101;

let ext = seal.ext.find("logConvertForwardDemo");
if (!ext) {
  ext = seal.ext.new("logConvertForwardDemo", "Scardice", "1.0.0");
  seal.ext.register(ext);
}

// Map 的 key 是“骰子账号 + 平台 + 群/私聊”，所以不同会话可以同时收集。
const collectingSessions = new Map();

function listItems(value) {
  if (!value || typeof value.length !== "number") return [];
  const result = [];
  for (let i = 0; i < value.length; i++) result.push(value[i]);
  return result;
}

function conversationKey(ctx, msg) {
  const endpointId = ctx.endPoint && (ctx.endPoint.id || ctx.endPoint.userId) || "unknown-endpoint";
  const placeId = msg.messageType === "group" ? msg.groupId : msg.sender.userId;
  return [endpointId, msg.platform, msg.messageType, placeId].join("|");
}

function logGroupId(msg) {
  return msg.messageType === "group" ? msg.groupId : "Private:" + msg.sender.userId;
}

function cqEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/\[/g, "&#91;")
    .replace(/\]/g, "&#93;")
    .replace(/,/g, "&#44;");
}

// ForwardNode.elements 是结构化消息段。这里给出常见消息段转为日志文本的写法。
// 实际插件可以继续扩展更多平台特有类型。
function elementToLogText(element) {
  if (!element) return "";
  if (typeof element.content === "string") return element.content;
  if (element.target !== undefined) return `[CQ:at,qq=${cqEscape(element.target)}]`;
  if (element.url !== undefined || element.file !== undefined) {
    const file = element.url || element.file || "";
    return `[CQ:image,file=${cqEscape(file)}]`;
  }
  if (element.faceId !== undefined) return `[CQ:face,id=${cqEscape(element.faceId)}]`;
  if (element.replySeq !== undefined) return `[CQ:reply,id=${cqEscape(element.replySeq)}]`;
  return "[不支持的消息段]";
}

function isForwardElement(element) {
  return !!element && (element.type === "forward" || element.nodes !== undefined);
}

function normalizeUserId(senderId, platform) {
  const id = String(senderId || "");
  if (!id) return "Unknown:0";
  if (id.includes(":")) return id;
  return String(platform).toUpperCase() === "QQ" ? "QQ:" + id : platform + ":" + id;
}

function normalizeUnixTime(value, fallback) {
  let time = Number(value || fallback || Math.floor(Date.now() / 1000));
  if (time > 1000000000000) time = Math.floor(time / 1000);
  return Math.floor(time);
}

function appendLogItem(session, node, outerMsg, text) {
  session.items.push({
    id: session.items.length + 1,
    GroupID: logGroupId(outerMsg),
    nickname: String(node.senderName || "未知用户"),
    IMUserId: normalizeUserId(node.senderId, outerMsg.platform),
    time: normalizeUnixTime(node.time, outerMsg.time),
    message: text,
    isDice: false,
    commandId: 0,
    commandInfo: null,
    rawMsgId: node.messageId || outerMsg.rawId || "",
    uniformId: normalizeUserId(node.senderId, outerMsg.platform),
    channel: outerMsg.channelId || ""
  });
}

// 递归展开嵌套合并转发。普通节点成为一条日志；节点中的嵌套转发随后按顺序展开。
function collectForwardNode(session, node, outerMsg, depth) {
  if (depth > 8) {
    session.warnings.push("嵌套合并转发超过 8 层，已停止继续展开");
    return;
  }

  const nestedForwards = [];
  let text = "";
  for (const element of listItems(node.elements)) {
    if (isForwardElement(element)) nestedForwards.push(element);
    else text += elementToLogText(element);
  }

  if (text !== "") appendLogItem(session, node, outerMsg, text);

  for (const forward of nestedForwards) {
    collectForwardElement(session, forward, outerMsg, depth + 1);
  }
}

function collectForwardElement(session, forward, outerMsg, depth) {
  if (!forward.loaded) {
    session.warnings.push("有一条合并转发未能展开：" + (forward.loadError || forward.forwardId || "未知错误"));
    return;
  }
  for (const node of listItems(forward.nodes)) {
    collectForwardNode(session, node, outerMsg, depth);
  }
}

// onMessageReceived 比指令解析更早执行，但这里只处理 forward，因此“开始/结束”命令不会进入日志。
ext.onMessageReceived = (ctx, msg) => {
  const session = collectingSessions.get(conversationKey(ctx, msg));
  if (!session || session.uploading) return;

  for (const element of listItems(msg.segment)) {
    if (isForwardElement(element)) collectForwardElement(session, element, msg, 0);
  }
};

function concatBytes(parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function adler32(bytes) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

// 生成合法的 zlib 数据。DEFLATE 使用“未压缩块”，代码短且不依赖第三方库；
// HTTP 传输内容会稍大，但非常适合教学 Demo。
function zlibStore(bytes) {
  const parts = [new Uint8Array([0x78, 0x01])];
  if (bytes.length === 0) parts.push(new Uint8Array([1, 0, 0, 255, 255]));

  for (let offset = 0; offset < bytes.length; offset += 65535) {
    const length = Math.min(65535, bytes.length - offset);
    const finalBlock = offset + length >= bytes.length ? 1 : 0;
    const nlen = (~length) & 0xffff;
    parts.push(new Uint8Array([
      finalBlock,
      length & 0xff,
      (length >>> 8) & 0xff,
      nlen & 0xff,
      (nlen >>> 8) & 0xff
    ]));
    parts.push(bytes.slice(offset, offset + length));
  }

  const checksum = adler32(bytes);
  parts.push(new Uint8Array([
    (checksum >>> 24) & 0xff,
    (checksum >>> 16) & 0xff,
    (checksum >>> 8) & 0xff,
    checksum & 0xff
  ]));
  return concatBytes(parts);
}

function multipartField(boundary, name, value) {
  const safeValue = String(value).replace(/[\r\n]/g, " ");
  return new TextEncoder().encode(
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${safeValue}\r\n`
  );
}

function buildUploadBody(logName, uniformId, compressed) {
  const boundary = "----ScardiceLogDemo" + Date.now().toString(16) + Math.random().toString(16).slice(2);
  const fileHeader = new TextEncoder().encode(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="log-zlib-compressed"\r\n` +
    `Content-Type: application/octet-stream\r\n\r\n`
  );
  const ending = new TextEncoder().encode(`\r\n--${boundary}--\r\n`);
  const body = concatBytes([
    multipartField(boundary, "name", logName),
    multipartField(boundary, "uniform_id", uniformId),
    multipartField(boundary, "client", "SealDice"),
    multipartField(boundary, "version", STORY_LOG_VERSION),
    fileHeader,
    compressed,
    ending
  ]);
  return { boundary, body };
}

async function uploadLog(session, ctx) {
  const logName = "合并转发 Log " + new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const log = { version: STORY_LOG_VERSION, items: session.items };
  const jsonBytes = new TextEncoder().encode(JSON.stringify(log));
  const compressed = zlibStore(jsonBytes);
  const request = buildUploadBody(logName, ctx.endPoint.userId, compressed);

  const response = await fetch(LOG_CONVERT_BACKEND, {
    method: "PUT",
    headers: { "Content-Type": `multipart/form-data; boundary=${request.boundary}` },
    body: request.body
  });
  const responseText = await response.text();
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${responseText.slice(0, 300)}`);

  let result;
  try {
    result = JSON.parse(responseText);
  } catch (_) {
    throw new Error("染色器返回的不是 JSON：" + responseText.slice(0, 300));
  }
  if (!result.url) throw new Error("染色器返回结果中没有 url：" + responseText.slice(0, 300));
  return result.url;
}

const command = seal.ext.newCmdItemInfo();
command.name = "logconvert";
command.help = [
  ".logconvert 开始 // 开始收集此群/私聊随后收到的合并转发",
  ".logconvert 结束 // 停止收集、生成 Log、上传并返回染色器地址",
  "中文别名：.log转写 开始 / .log转写 结束"
].join("\n");

command.solve = (ctx, msg, cmdArgs) => {
  const action = String(cmdArgs.getArgN(1) || "").trim().toLowerCase();
  const key = conversationKey(ctx, msg);

  if (action === "开始" || action === "start") {
    if (collectingSessions.has(key)) {
      seal.replyToSender(ctx, msg, "当前群聊/私聊已经在收集合并转发。发送 .logconvert 结束 即可上传。");
      return seal.ext.newCmdExecuteResult(true);
    }
    collectingSessions.set(key, {
      ownerId: msg.sender.userId,
      items: [],
      warnings: [],
      uploading: false
    });
    seal.replyToSender(ctx, msg, "已开始收集。接下来收到的所有合并转发会按顺序写入 Log；完成后发送 .logconvert 结束。");
    return seal.ext.newCmdExecuteResult(true);
  }

  if (action === "结束" || action === "end" || action === "stop") {
    const session = collectingSessions.get(key);
    if (!session) {
      seal.replyToSender(ctx, msg, "当前群聊/私聊没有正在进行的 Log 转写任务。请先发送 .logconvert 开始。");
      return seal.ext.newCmdExecuteResult(true);
    }
    if (session.uploading) {
      seal.replyToSender(ctx, msg, "Log 正在上传，请稍候。");
      return seal.ext.newCmdExecuteResult(true);
    }
    if (session.items.length === 0) {
      collectingSessions.delete(key);
      seal.replyToSender(ctx, msg, "收集已结束，但没有读到任何合并转发聊天记录，因此没有上传。");
      return seal.ext.newCmdExecuteResult(true);
    }

    session.uploading = true;
    seal.replyToSender(ctx, msg, `收集结束，共 ${session.items.length} 条聊天记录，正在上传染色器……`);

    // 不让 solve 等待网络请求：先正常结束指令，异步完成后再回复链接。
    uploadLog(session, ctx).then((url) => {
      collectingSessions.delete(key);
      const warning = session.warnings.length > 0
        ? `\n注意：另有 ${session.warnings.length} 条解析警告。`
        : "";
      seal.replyToSender(ctx, msg, `Log 上传成功：\n${url}${warning}`);
    }).catch((error) => {
      session.uploading = false; // 保留已收集内容，用户可以再次发送“结束”重试。
      seal.replyToSender(ctx, msg, "Log 上传失败，已保留收集内容，可再次发送 .logconvert 结束 重试。\n" + String(error));
    });
    return seal.ext.newCmdExecuteResult(true);
  }

  const result = seal.ext.newCmdExecuteResult(true);
  result.showHelp = true;
  return result;
};

ext.cmdMap["logconvert"] = command;
ext.cmdMap["log转写"] = command;
