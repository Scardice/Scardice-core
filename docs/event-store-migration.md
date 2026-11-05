# EventStore 迁移与运行边界

Scardice 以独立所有权 EventStore 的 readiness gate 作为启动前提。启动与事件溯源导入使用 `migrate/eventsourcing`；`migrate/v2` 的适用范围为 legacy 工具链。

## 启动配置

托管或远程部署在启动前设置 endpoint store 变量。管理员身份与浏览器来源为可选项。

```text
SCARDICE_ENDPOINT_DB=/var/lib/scardice/events.db
SCARDICE_ENDPOINT_DB_ID=events-prod-2026-09
SCARDICE_ADMIN_PRINCIPAL_ID=local-admin
SCARDICE_ADMIN_ORIGINS=https://admin.example
```

全新本地安装可选择自动引导模式：将全部 `SCARDICE_ENDPOINT_*` 数据库变量保持为空。可执行文件随后在 `data/endpoint/` 创建 SQLite 引导数据，并把稳定数据库身份写入 `data/endpoint/config.json`。后续启动复用该身份。事件库不使用任何密钥文件。

显式环境配置具有最高优先级。部分环境配置或残缺本地引导数据会得到配置错误，现有文件保持原状。启动日志默认写入 `data/main.log`，记录自动创建或复用决策；日志字段限定为 action、path 与 database identity summary，含凭据的 DSN 不写入日志。

事件库 schema v2 直接保存明文载荷与原始标识符；不加密、不使用 HMAC 身份或 codec 标记。普通 SHA-256 仅用于事件完整性、请求去重及非唯一候选索引；候选查询仍比较原始身份。访问控制由文件系统权限、WebUI 登录与账号权限承担：能读写程序文件的人拥有最高权限，其下依次是 WebUI、权限 100、权限 70 与普通用户。

### 数据库后端

可执行文件的环境适配器接受 SQLite。`eventstore.DatabaseConfig` 同时定义 MySQL 与 PostgreSQL 配置；远程部署集成负责 TLS 与发布配置。

SQLite 运行库使用单 writer、WAL、foreign keys 和 `synchronous=FULL`。可重建的 publication-pending 本地导入 candidate 临时使用较低同步级别与内存 temp store；验证或发布前恢复 `synchronous=FULL`，执行 truncating WAL checkpoint，关闭并重新打开同一个数据库。

Runtime PRAGMA 应用于每个新物理连接及其 replacement。旧加密格式与未知 schema 在普通数据库打开之前拒绝，不能通过 AutoMigrate 就地改成新格式。

Schema 初始化把 `QueryTimeout` 应用于每条 SQL，调用者 context 管理完整多表生命周期。普通 store query 继续使用各自调用者 context。Queue 升级按 version index 分批执行，并在实际升级期间报告 progress。

## Readiness 与启动顺序

`eventstore.NewStore` 为全新数据库写入 `store_readiness.mode=fresh`。Readiness 只保存 `Mode`、`SchemaVersion`、`DatabaseIdentity`、`CompletedAt` 四项业务字段；singleton key 仅用于定位该行。运行时只做轻量元数据检查，没有 manifest、密钥审计或 `--verify-event-store` 入口。

已完成的 `import` 可直接启动，无论旧文件是否仍在。没有 legacy 数据的 `fresh` 可直接启动；有 legacy 数据且事件库为空时先询问迁移，已有持久状态时则拒绝混合来源。这个规则也适用于旧版遗留的空 `fresh` 加密库：有 legacy 数据时选择来源 A，不把空库转换成一次已完成的来源 B 导入。

Provider、callback 与 dispatcher admission 前，启动流程先完成一次终态 inbox 清理。之后由同一个 `eventWorkerGroup` 每小时执行清理；关闭时取消并等待在途事务结束。

Callback 与 outbound effect 各使用四个 worker。Inbox 或 outbox commit 会立即唤醒等待 worker；500 ms polling 负责 idle 与 scheduled-retry fallback。Mutex、block 与 pprof 记录分别通过 `--mutex-profile`、`--block-profile` 和 `--pprof-record` 显式启用。

关闭流程为 JS loading、JS cron、普通 cron、event worker 与 endpoint supervisor 共享一个 30 秒 deadline。并发 cleanup 请求加入同一关闭操作。deadline 到达后的结果为 escalation log 与数据库句柄保留至进程退出；新 worker 与 JS-load admission 在等待资源退出前关闭。

## 管理鉴权与 endpoint 生命周期

`/sd-api/endpoints`、`/sd-api/operations` 及其它 Core 管理 API 接受已认证 WebUI session。登录成功后发送：

```text
Authorization: Bearer <session token>
```

凭据解析位置为 `Authorization` header；query-string 凭据得到拒绝结果。当前鉴权读取集为 WebUI session token，`SCARDICE_ADMIN_TOKEN` 的鉴权权重为 0。

认证后的 `GET /sd-api/endpoints` 返回可管理集合：

- `enabled`、`disabled` endpoint 始终列出；
- `removing` endpoint 在删除完成前列出；
- `desiredState: deleted` 的 endpoint 通过 `GET /sd-api/endpoints/:id` 查询终态；
- 删除 operation 通过 `GET /sd-api/operations/:id` 查询终态。

Endpoint events 与 projection tombstones 持久保存，用于历史、恢复和 endpoint ID 复用保护。

启动 reconciler 的处理集合为 `desiredState: enabled`。其它 lifecycle operation 保持 pending，等待 provider 状态证据。对于 pending disable：

1. 确认 provider 或资源已经停止。
2. 由 operation owner 调用认证后的 `POST /sd-api/operations/:id/resolve`。
3. 提交 `resolution: "confirmed-success"`、`confirm: true`、当前 `expectedOperationVersion`、当前 `expectedAggregateVersion`，以及唯一 `idempotencyKey` 或 `Idempotency-Key` header。
4. 等待 endpoint 显示 `disabled/stopped`，随后按标准 delete flow 执行删除。

Core 将该请求记录为 owner confirmation；provider 状态核验责任属于 operation owner。

`SCARDICE_ADMIN_PRINCIPAL_ID` 设置稳定 audit 与 operation owner 身份，默认值为 `local-admin`。`SCARDICE_ADMIN_ORIGINS` 添加允许的浏览器 origin；省略时应用 same-origin 策略。Dice Master 权限属于 Dice 领域，Core 管理权限来源为认证 WebUI session。

### 最近管理活动

认证后的 `GET /sd-api/activity/recent?limit=20` 返回跨客户端管理活动。默认 limit 为 20，最大值为 100，空历史为 `items: []`。

Core 将管理 mutation、migration 与 backup 摘要追加到现有 EventStore 的 `management_activities`。Runtime log、sign-in、preview、read 与 connectivity check 保留在各自观测系统中。

每条活动包含 ID、Unix 毫秒时间、固定 action 与 label、注册 route pattern、HTTP status、result、认证 actor 和完整 source IP。Result 值为：

- `succeeded`：操作完成；
- `accepted`：HTTP 202 submission 已入队；
- `failed`：HTTP 错误或 HTTP 200 business failure。

Source IP 的唯一来源为连接 `RemoteAddr` 去除端口后的值。反向代理部署因此记录 proxy peer IP。活动 schema 只包含 ID、时间、action、label、route、status、result、actor 与 source IP。

Activity append 在业务操作之后单独写入。记录错误进入诊断日志，业务 response 保持原结果。历史 store unavailable 时接口返回 HTTP 503。

### 测试实例访问开关

以下开关仅在值精确等于 `1` 时生效：

- `SCARDICE_TEST_WEBUI_AUTH_BYPASS=1`：legacy API 与 endpoint management API 接受省略、空值或任意 credential；endpoint management 继续使用标准 Origin 与 rate limit，legacy cross-origin 继续使用标准 Origin 策略。
- `SCARDICE_TEST_WEBUI_ORIGIN_RATE_LIMIT_BYPASS=1`：endpoint management API 使用 Origin/rate-limit bypass policy，并接受 cross-origin `Authorization` preflight；credential 继续使用标准认证。
- 两个开关同时启用：legacy 与 endpoint management API 均接受 cross-origin request 和任意 credential。

任一开关生效时，WebUI 持续显示红色警告。受支持的部署范围为隔离测试实例；网络可达客户端会获得对应的高权限访问能力。

## Queue、事务与诊断

Inbox 与 outbox 的领取资格来自 indexed active lane head。每次 queue mutation（含 privacy resolution）在同一事务中更新 lane head。跨 lane 选择按 ready time 排序；claim 在写入 lease 前再次校验 row state 与 due time。

Active lease、正在运行的 callback 和已 dispatch effect 保持 lane 顺序。`failed` 与 `ambiguous` 项持久保留诊断证据，同时释放同 lane 后继项的领取资格。`ambiguous` 的重试入口为显式 operator resolution。

Outbox payload 在 provider dispatch 前过期时进入 `failed`。带 dispatch marker 的过期 effect 进入 `ambiguous`，包括 provider-idempotent effect；该次 expiry 的 provider 调用次数保持原值。未知 post-dispatch 结果的 retry eligibility 限于 provider-idempotent effect。

终态 inbox 保留正文，不在 callback 完成时清空。已有 `CompletedAt` 且严格早于 30 天前的 `confirmed-consumed`、`failed`、`skip` 与 `ambiguous` 行由 housekeeping 整行删除；边界当天、无完成时间和非终态行保留。清理不重放 ambiguous 消息。

Callback 在等待 commit fence 时持续续租。最后一次 renewal 的 version 传入 terminal CAS，commit context 的 expiry 早于 lease expiry。Cancellation 结束当前 attempt，已经启动的 Host 保持单次执行。

委托命令共享 callback transaction、commit fence 与 post-commit coordination。`.ob @user` 等命令用目标玩家自身 expected version 完成 load/save。Durable reply 由 owning callback 执行；Host 在收集并 finalize mutation 后释放 execution state。

插件配置的 definition、default 与 current value 使用普通 typed extension-state facts，在同一事务中注册。重新注册可更新默认值和说明，但保留已保存的 current value，包括显式空值；真实 `ConfigSecret` 仍保存引用并遵循既有 API 脱敏规则。Public plugin storage 不占用内部配置 namespace，空串、空格及 opaque key 保持独立。

Group refresh 与 WebUI quit 使用 durable action boundary。普通 inbound callback 按 cooldown 请求 refresh。经过验证的 observation 更新 group cache；空名称和省略的 count 字段沿用已有值。

WebUI quit 在一个事务中接收全部 farewell part 与 quit action，维持 lane 顺序，并为相同文本 segment 分配独立 emission identity。只有 accepted 且 committed 的请求应用 membership removal 与 success notice。Callback quit（含跨群 master command）把 canonical membership 与 outbound intent 一起 commit；local membership 在 callback CAS 成功后发布。

`data/queue-failures.log` 的固定字段为 queue、item ID、state 与 failure context，不记录消息正文或凭据。日志使用 10 MB rotation、3 个 backup 和 7 天 retention。该文件提供 best-effort 诊断；committed queue state 与 outcome event 是权威记录，原始载荷保存在明文数据库中。

OneBot failure 的新 outcome event 与诊断日志保存有界、脱敏的 action、status、return code 与 provider cause。旧 schema 记录继续保留其原字段。保存模板中的 `$t` 是普通文本；request-local attribute key 的生命周期为当前 request。

## 群日志缺口恢复

Pure OneBot 把 `message_seq` 映射到 normalized inbound message。群日志处于 recording 状态时，live callback commit 后的 sequence gap 启动有界 history query。Query 从真实已接收消息向后分页，在 exclusive sequence boundaries 内按 oldest-first 返回，最多 1000 条。

Provider entry 的 admission 需要可定位的 timestamp 与 identity；校验失败的 entry 进入 skip 结果。候选消息集合只包含 peer message。

缺口批次按大小选择执行路径：

- 1–5 条：进入普通 command processing，可执行历史 command、plugin hook、player-state mutation 与 reply。
- 6–1000 条：进入独立 record-only inbox lane，只提交日志记录。

Live lane 与 record-only lane 独立推进。Summary 统计 durable inbox outcome；timeout 将仍处于 pending 的 item 单独列出。`failed` 与 `ambiguous` callback 保留各自结果，供操作者处理。

启动或恢复日志时，触发消息的 sequence 持久化为**起始序列**。恢复边界的下界是该起始序列，session scope 是当前 log session。旧日志在收到首条带 sequence 的消息时采用该值作为恢复边界。

### 手动检查

Dice Master 在目标群执行：

```text
.log check <afterSeq> <beforeSeq>
```

前置条件：

- 当前日志状态为 recording；
- exclusive boundaries 覆盖 1–1000 个 sequence position；
- `beforeSeq` 对应 provider 可用于 history anchor 的真实消息；
- 请求范围位于当前 session 的恢复边界内。

手动检查先按当前日志的 message ID 去重，再应用五条消息阈值。既有 inbox identity 提供重复执行保护；早先的 `failed` 或 `ambiguous` identity 保持其终态。完成摘要发送到目标群，provider/query error 写入 Core log。

认证后的管理接口为 `POST /sd-api/story/check`，JSON 字段是 `endpointId`、`groupId`、`afterSeq` 与 `beforeSeq`。它使用相同 recording 与恢复边界校验。HTTP 202 表示 background check 已接受；最终 commit 状态由后续 archive 或 operation 查询确定。

Archive read 按 timestamp、sequence anchor 和 entry ID 排序。恢复 command 的 reply 继承 trigger 的原 timestamp 与 sequence。Sequence-free entry 继承可用 anchor；sequence-free log 使用 timestamp/storage order。

## 备份与资源

手动备份通过后台任务执行。`POST /sd-api/backup/do_backup` 接收 `selection` 位掩码，返回 HTTP 202 与 `{success: true, job}`；已有任务执行时返回 HTTP 409 与当前 `job`。`GET /sd-api/backup/status` 返回 `{job}`，`job` 初始为 `null`。两个接口使用 WebUI 会话认证。

Job 的 `status` 为 `running`、`succeeded` 或 `failed`，`stage` 可取 `preparing`、`snapshot`、`collecting`、`archiving`、`finalizing`。文件总数确定后，`completedFiles` 与 `totalFiles` 提供归档进度；快照和 legacy 流式归档使用阶段提示。`startedAt`、`finishedAt` 使用 Unix 毫秒时间，`filename` 为归档文件名，`error` 提供失败原因。Core 在当前进程内保存最新任务状态，WebUI 刷新后恢复显示；手动备份、内部调用和定时备份共享任务执行权。

EventStore 模式的手动和自动 backup 使用 SQLite `VACUUM INTO` 生成 `data/endpoint/events.db` 的一致性 snapshot。Snapshot 包含 committed WAL transaction 与 typed Story archive。Optional selection flag 控制额外 filesystem export，EventStore snapshot 始终包含数据库内数据。

Backup archive 只包含数据与 `backup_info.json`，不含任何密钥材料。恢复时把 runtime 配置指向解压后的 snapshot 即可。ZIP 仍按含聊天记录与凭据的数据处理；Unix 上的 snapshot entry 保留 owner-only `0600` mode。Snapshot 与 ZIP 使用 `backups/` 下的隐藏暂存目录，archive close 与 sync 完成后在同一文件系统原子发布。

一致性 snapshot 的 backend scope 为 SQLite；其它 backend 的 backup request 返回 capability error。

Filesystem-backed list API（如 `/sd-api/backup/list`、`/sd-api/resource/page`）在目录 lookup 返回 `os.ErrNotExist` 时返回 empty array，目录生命周期保持由写操作管理。`/sd-api/resource/data` 把可解码图片返回为 PNG，thumbnail width 为 64；解码错误返回 HTTP 422。

## 转换上一版本的加密事件库（来源 B）

升级前停止所有实例，备份**整个 `data/`**，并保留旧可执行文件及与数据库匹配的 `keys/`。新版本在普通数据库打开之前探测 v1；发现加密格式时打印确切迁移命令并询问 `[y/N]`。输入 `y` 成功后继续本次启动；其它输入不转换，无终端时只提示并退出。也可从安装目录执行下一节的 `--import-legacy` 命令，成功后再正常启动。

转换只读取旧库已发布的**当前状态**，不重放全部事件历史：

| 保留内容 | 新库中的表示 |
| --- | --- |
| 群、玩家、属性、封禁、配置、扩展 | 当前状态的普通基线事件；属性历史不保留 |
| 当前 owner 引用的最新 secret | 解密后写入版本 1；事件、projection 与嵌套凭据引用同步改为版本 1 |
| 插件 KV 与旧版内部配置值 | 原始 KV 保留；内部配置值合入 typed 配置，显式空值优先 |
| 已归档 Story 会话、状态、条目 | 保留正文、元数据和关联；条目/会话代理 ID 可重新分配 |
| 管理活动 feed | 保留活动内容与时间 |

不迁移 inbox、outbox、operation、artifact、execution receipt、出站 effect 历史及尚未发出的 Story 回复意图；日志分别报告总数、非终态 outbox 与待发送 Story 意图数。旧版已阅后即焚的正文无法恢复。未引用的 secret 不解密，原数据只留在旧库备份中。未知当前投影、缺失或不一致的当前凭据、无法恢复的旧属性值会使转换失败，不会重置为空。

转换在私有副本上处理 main/WAL/SHM，源文件不检查点、不写入。候选库重建、关闭重开，并对实际事件、引用和值、KV、规范化后的投影、Story 及管理活动读回对账；成功后写入 schema 2、`mode=import` 和完成时间，数据库身份沿用配置。

发布前先持久化并 fsync `events.db.v1-swap.json`，再将原 main/WAL/SHM 改名为 `events.db.v1.<UTC 时间>.bak` 及配套 sidecar，最后安装并同步候选库。返回式失败恢复原文件；进程中断留下的 marker（包括 `.writing`）会让下次启动明确拒绝，而不是误建空库。旧 `keys/` 不改动，只有转换读取 `SCARDICE_ENDPOINT_KEY_INDEX` / `SCARDICE_ENDPOINT_KEY_ROOTS`。

需要回退时，停止新进程，把新库另存，并用旧备份的 main **及存在的同名 `-wal` / `-shm`** 一起恢复为原路径。恢复整套旧安装配置，包括原 `data/dice.yaml`、`keys/`、旧可执行文件及旧版所需的密钥路径配置；只复制数据库与密钥不等于恢复整个 `data/`。若存在未完成交换 marker，先根据其中路径恢复完整原文件集，确认后再移除 marker；程序不自动猜测恢复方向。新版本写入的数据不会出现在旧库中。

来源 B 就地转换仅支持本地 SQLite。远程加密 v1 与未知 schema 明确拒绝，远程数据库不作修改。

## 导入 legacy 数据

### 运行导入

导入前停止其它实例并备份整个 `data/`，从安装目录执行：

```bash
./Scardice-core --import-legacy --hide-ui --container-mode
```

可执行文件读取 `data/` 下的 legacy 文件，写入独立 candidate database，完成验证后发布。成功结果写入 `legacy import published` 并退出；随后按普通方式启动 Scardice。

直接启动未迁移安装时，程序释放事件库后打印针对当前可执行文件的完整命令，询问 `[y/N]`。回车、`n`、输入结束或其它内容退出；输入 `y`（或 `yes`）执行相同来源选择与导入，成功后继续本次启动，不再等待第二次 Enter。无终端时不自动导入。

Local bootstrap 创建的空数据库可复用 pinned identity。Importer 在关闭前读取 persistent runtime state；empty classification 要求 persistent state count 为 0。

`migrate/eventsourcing` 按以下顺序执行：

1. 清点处于 stopped 状态的 source，并保持 source 内容原状。
2. 以 `ModeImport` 调用 `DecidePreflight`。
3. 创建 owner-only snapshot tree。
4. 重新读取 source metadata。
5. 校验真实 source payload，构建 sorted、length-prefixed semantic manifest。
6. 初始化新 target identity，以每批最多 500 records、8 MiB payload 加 manifest metadata 的边界导入 deterministic batch。
7. 重建 projection，关闭并重新打开同一个 target，对比 source 与 target manifest。
8. 再次读取 source metadata。
9. 在全部检查成功后向 target 写入 `store_readiness.mode=import`。

完整 source/target record set 使用规范化 SHA-256 对账；这些 manifest 是导入过程的局部验证材料，不进入运行时 readiness 表。

### Candidate 发布

`SQLiteTarget` 写入独立候选库，验证后同步并原子替换 active path；普通来源 A 的临时 hard-link backup 保留到 replacement reopen 成功，错误时恢复原状。若替换的是已证明为空的 fresh v1，则使用来源 B 的持久化交换 marker 与旧文件备份协议。

Runtime 与 migration 使用同一 Core/Endpoint projection registry。每个 batch 在一个 `UnitOfWork` 中提交事件、原始 secret 与 plugin KV；participant 错误回滚整批。零长度 BuntDB key 仍是可寻址的普通 key。

重开后在一致、有界分页快照中读回实际事件、secret、KV 与 Story 资源并比较内容。Story receipt 使用候选索引加原始身份比较；session mapping 保持条目和当前状态的关联。目标数据库、WAL 与 SHM 使用 owner-only 权限。

Activation 成功后的 handle-close error 记录为 cleanup warning，已激活 target 继续保持 published 状态。

### Source 安全边界

Pre-publication error 创建 owner-only `.quarantine` marker。Source metadata 在 target creation 前和 publication 前各校验一次。原 active readiness repository 只用于 preflight read，所有 import write 指向 candidate。

Source inventory 必须提供完整 ownership map 与每条 record 的真实 payload。Digest-only record 或 ownership map 缺项会得到 validation error。`LegacySource` 映射 local YAML、SQLite、credential 与 BuntDB owner。

Local SQLite importer 清点 resolved `data.db` 旁的 optional `data-logs.db` 及其 `-wal`、`-shm` sidecar。Source 保持 stopped 状态；reader 使用完整 database/sidecar set 的 private scratch copy，并只重建该 copy 的 SHM index。

Inventory、snapshot 与 read 通过 held、descriptor-backed `os.Root` 遍历 SQLite/log sidecar、group/configuration data、extension storage 与 remote-filesystem snapshot。显式 root symlink 先 canonicalize；root 内的 absolute `DataDir` 可参与 path mapping。Descendant symlink 得到 source-path validation error，descriptor-rooted operation 将访问范围固定在选定 source root。

### Story 日志导入

Log importer 将 legacy log 与 item 映射到 typed session、entry 和 current-state record。它保留 nullable `extra`、upload/session metadata，以及 message text、nickname、user ID、timestamp、command info、raw/uniform message ID、sequence、removal state 和 parent ID。

Source-scoped record identity 关联 entry、current state 与 session。每个 batch 在同一 `UnitOfWork` 中写 archive resource 与 import receipt；相同 retry 产生幂等结果，content conflict 返回冲突错误。

Target reopen 后读回实际 imported resource，与 source 的规范化内容比较。Legacy log-table import 当前覆盖 local SQLite source；remote legacy log source 返回 capability-validation error。Remote SQL EventStore runtime backend 继续通过 `eventstore.DatabaseConfig` 集成。

## 迁移后的运行语义

### 协议与 endpoint

- Inbound text 与 structured mention 进入 segment command parser；message edit 与 delete 分别进入对应 callback。
- Provider member role 与 Core master privilege 使用独立 authority source。Provider permission lookup error 返回权限错误。
- Telegram entity 使用 UTF-16 offset，覆盖 caption、explicit user mention、bot username 和从早先消息学习到的 username。
- Observed bot identity 优先于 configured account hint。OneBot group identity 在 command reply 全程使用 `QQ-Group:<id>`。
- SealChat 通过 generation-fenced Core service 提供 `character.get`、`set`、`list`、`new`、`save`、`tag`、`untagAll`、`load` 与 `delete`。Mutation 持久化完成后返回 success；name 与 attribute key 可包含空格。每个 Runtime 的 write limit 为 60/minute，burst 为 5。
- Pure OneBot 设置使用 OneBot canonical field set；embedded-client protocol、app-version 与 signing-server field 归属 embedded-client configuration。UI 只把 `succeeded` 显示为成功；`failed`、`expired` 与 `ambiguous` 显示为错误。
- Endpoint adapter `SecretRef` 只在 owning endpoint/adapter tuple 匹配时返回值；不匹配视为引用不存在。Provider identity observation 保留 event correlation；endpoint state 与 projection 保留 active lifecycle operation ID 及 correlation。
- OneBot guild message 使用 `QQ-CH-Group:<guild>-<channel>` 并保留 opaque provider message ID；group recall 进入 deletion callback。Meta-event heartbeat 进入 observability-only 路径。Request/notice allowlist failure 计为 rejection，endpoint worker 继续运行。
- Official QQ websocket process 注册一个 static BotGo handler key，并为每个 Runtime generation 分配唯一 process-local route token。只有 active token 接受 event；stale generation event 进入 stale-drop 结果。Channel group ID `OpenQQCH-Channel:<guild>-<channel>` 与 private scope `PG-OpenQQCH:<user>` 参与 group-user ownership、cache generation 与 privacy selection。
- Endpoint lifecycle intent 从 endpoint event 恢复，并由 supervisor reconcile；provider outbox 的范围是 provider effect。Built-in process startup 中的 explicit stop 产生 normal shutdown；parent cancellation 与 startup failure 保留各自 error result。
- Explicit disable 或 removal 的 runtime stop 成功后完成当前 lifecycle command。Replaced worker callback 保留 worker-start fence，并通过 stale-update validation。
- Compatibility callback 请求的 group-card change 是 callback `UnitOfWork` 内的 durable outbox action；empty card 表示清除 member card。Provider dispatch 在 commit 后开始。

### 属性与 privacy

- Durable callback 的 attribute update 在 `UnitOfWork` commit 后 invalidates shared cache。Character service operation 与 callback 串行化；group privacy invalidation evicts attribute cache 与 binding state。
- Private group-user load 共享 group-generation fence，在途加载发布前验证缓存 generation；不再有解密阶段。
- 群删除在**一个数据库事务**内重新计算 dry-run 摘要、计数与活动状态，检查确认值后删除所选完整事件流、aggregate head、对应 projection、属性全部 secret 版本、Story 五张表和精确 Subject 匹配的 inbox/outbox，并刷新受影响的 lane。失败时整笔回滚。
- Projection 按其 namespace 选择，不会仅凭相同 row key 删除其它类型。保留 character/global、其它群和其它 Dice 的属性；存在身份歧义的 malformed `group_user` 使 dry-run 与删除失败，不猜测归属。
- `logs` 必须显式选择，默认 scope 是 `group_record`。响应返回实际删除计数及未覆盖的数据类别；没有 operation/resume/phase 或持久化 privacy audit。
- 删除事务发布新的 projection generation，使旧 stamped read 与删除后同 ID、同版本重建的 stream 冲突；保留所需 stream/catalog/plugin revisions。没有 subject fence、HistoryRevision 或 tombstone，已删除全局位置形成的空洞属于正常状态，事件位置和 checksum 仍按原约束校验。
- 其它群、未选择 scope、plugin KV、全局角色、外部导出和备份不随本次删除。Cache invalidation 在数据库 commit 后执行；删除完成不代表外部副本也已清除。

### Story archive 与管理视图

- EventStore 明文 archive 保存 Story session、current group state、entry、outbound intent 与 import receipt。Dice/group、scope、名称与原始消息 ID 保留原文；非唯一候选索引只缩小查询范围，仍比较完整身份。Selected session 与 on/off state 跨重启持久化。
- Inbound callback 的 log update 与 callback 其它 durable change 进入同一 `UnitOfWork`。Legacy adapter 使用相同 repository boundary。`.log`（含 `.log list`）、`.stat log`、Story API、log export 的 write target 均为 selected repository。
- Session `created_at` 与 `updated_at` 是 canonical content timestamp，entry `Time` 的 scope 限于该 entry。Append、content-changing edit 与 recall 在同一事务中推进 `updated_at` 并清除 cached upload URL/time；unchanged edit 保留 cache，upload 保留 content timestamp，legacy import 保留 source session timestamp。
- Durable advanced-config view 持久化 `StoryLogApiVersion`。GET-derived full update 会保留该设置与 token reference；GET 的 token field 返回 empty value，实现 write-only redaction。
- 认证后的 `/sd-api/dice/exec` 为每条 synthetic UI message 生成 `UI:exec:<uuid>` raw ID，并通过共享 `IMSession.Execute` hook 执行。该 ID 的类别是 server-generated UI identity；每次相同文本 submission 都获得独立 ID 与 archive entry。后续 `.r` input 及 bot reply 也进入 archive。Provider inbound message 继续要求 provider message ID。
- Successful outbound delivery 在 terminal transaction 中提交 archived entry 并移除 pending intent。`failed` 与 `expired` 保留各自终态。Intent 绑定原 session ID，删除后创建同名 session 不会接收旧 intent 的迟到结果。
- 认证后的 `GET /sd-api/dice/recentMessage?cursor=<cursor>` 返回 `{ cursor, messages, truncated }`。每条消息包含 `uid`、`message`、`messageType`；空批次的 `messages` 为 `[]`。各页面独立保存游标，共享最近 256 条回复。空游标从当前尾部订阅；游标失效或落后于保留窗口时返回现存记录并设置 `truncated: true`。
- Event-sourced Core 连接 selected Story repository；legacy log database 属于 legacy SQL runtime。Selected repository unavailable 时 Story API 返回 503，log callback 返回 unavailable result。
- `/sd-api/group/list` 从 selected Dice runtime map 返回 group row。`tmpPlayerNum` 统计所有 Dice owner 下按 `(group_id,user_id)` 去重的 active EventStore player profile；该值表示 shared local-profile count。Player projection unavailable 时返回 503。
- Censor 启用时执行匹配检查。Per-user、per-level threshold count 保存在进程内存中，restart 后从初始值开始。`/sd-api/censor/logs/page` 返回 `data: []`、`total: 0`。Manager initialization error 保留 error result。

### 启动服务与配置

- Event-sourced startup 先初始化 package manager，再异步加载 JS script，使 enabled package script 可被 loader 发现。Script 完成后恢复 built-in、user 与 enabled-package template；同名 file-backed template 优先，JS-only template 保留。Endpoint worker 在 JS load 完成后启动。Store backend metadata 在首次访问时 probe。
- 同步初始化及最终 `MarkModified` 完成后，Core 派发 native extension `OnLoad`；启用 JS 时先等待 `WaitStartupJsLoaded`。Deck extension 在 `OnLoad` 扫描 `data/decks`。
- Local random-name resource 异步加载；`.name` 与 `.namednd` 在资源 ready 后生成结果。
- Fresh EventStore Dice configuration seed 默认 master `UI:1001`。Fresh store 且 Dice config stream 恰有一个 `dice_config.outer_changed` event 时执行 default backfill；imported 或 later-edited master list 保持持久化值。
- 依赖 projection 的 legacy configuration view 在 data unavailable 时返回 503；base settings 与 custom reply page 显示 unavailable state。
- Startup 在等待 JS 前把 initial HelpDoc publication 标记为 pending。Pending 或 reload 时 status 为 `loading`。HTTP read/mutation 等待 publication，并返回 controlled cancellation 或 load error。`Parent.ReloadHelp` 在 startup gate owner path 内直接执行 reload 并保持 pending；final publication 完成后 startup 标记 ready。Native `.help` 与 `.find` 在 manager read lock 下读取完整 index。
- Dice 的 extension-state event count 为 0 时，extension-state read 返回 empty state；event count 大于 0 且 projection row unavailable 时返回 503。
- EventStore runtime 以 `moderation` stream、projection 与明文详情 secret 作为 active ban list 的权威来源，在同一事务提交。Name、reason、time、place 和 ban timestamp 保持普通完整性校验；`ban_info` 和 `ban-list.json` 属于 legacy path。当前 projection 或详情读取失败使启动失败；列表、变更、导入与导出仍要求 WebUI authentication。
- User-authored text template 保存于 Dice data directory 的 `configs/text-template.yaml`，生命周期独立于 EventStore projection。文件存在时，两条 runtime initialization path 以该文件为权威内容；该路径返回 `os.ErrNotExist` 时加载 built-in template。两条路径均从 selected template 生成 runtime 与 WebUI lookup map。
- 认证后的 Dice configuration endpoint 在一个 EventStore `UnitOfWork` 中 commit Dice settings、manager settings、authentication change 与 extension default。Runtime state 在 commit 后发布；validation 或 commit error 保留全部 owner 的先前版本。Persisted extension override 集合精确等于 `extDefaultSettings` array 中的 entries；empty array 生成 empty override set。
- 默认 PCG random source 在 startup 初始化。GM、NIST、CRNG 与 hybrid source 在显式选择或 inspection 时初始化；普通实例的 entropy allocation 范围为 PCG。
