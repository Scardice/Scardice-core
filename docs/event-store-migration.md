# EventStore 迁移与运行边界

Scardice 以独立所有权 EventStore 的 readiness gate 作为启动前提。启动与事件溯源导入使用 `migrate/eventsourcing`；`migrate/v2` 的适用范围为 legacy 工具链。

## 启动配置

托管或远程部署在启动前设置 endpoint store 变量。管理员身份与浏览器来源为可选项。

```text
SCARDICE_ENDPOINT_DB=/var/lib/scardice/events.db
SCARDICE_ENDPOINT_KEY_INDEX=/var/lib/scardice/keys/index
SCARDICE_ENDPOINT_KEY_ROOTS=/var/lib/scardice/keys/roots
SCARDICE_ENDPOINT_DB_ID=events-prod-2026-09
SCARDICE_ADMIN_PRINCIPAL_ID=local-admin
SCARDICE_ADMIN_ORIGINS=https://admin.example
```

全新本地安装可选择自动引导模式：将全部 `SCARDICE_ENDPOINT_*` 数据库变量保持为空。可执行文件随后在 `data/endpoint/` 创建 SQLite 引导数据，生成 owner-only 密钥材料，并把稳定数据库身份写入 `data/endpoint/config.json`。后续启动复用该身份与密钥。

显式环境配置具有最高优先级。部分环境配置或残缺本地引导数据会得到配置错误，现有文件保持原状。启动日志默认写入 `data/main.log`，记录自动创建或复用决策；日志字段限定为 action、path 与 database identity summary，密钥、secret 与含凭据的 DSN 继续由配置和 key provider 持有。

索引根与加密根由外部 key provider 持有。迁移快照保存数据与引用元数据，外部 key provider 材料继续驻留在配置路径。

### 数据库后端

可执行文件的环境适配器接受 SQLite。`eventstore.DatabaseConfig` 同时定义 MySQL 与 PostgreSQL 配置；远程部署集成负责 TLS 与发布配置。

SQLite 运行库使用单 writer、WAL、foreign keys 和 `synchronous=FULL`。可重建的 publication-pending 本地导入 candidate 临时使用较低同步级别与内存 temp store；验证或发布前恢复 `synchronous=FULL`，执行 truncating WAL checkpoint，关闭并重新打开同一个数据库。

Runtime PRAGMA 应用于每个新物理连接及其 replacement。projection payload-presence 升级在一个事务中添加字段、校正数据并记录完成状态；中断后从完成点恢复。完成记录使启动直接进入 ready 路径。

Schema 初始化把 `QueryTimeout` 应用于每条 SQL，调用者 context 管理完整多表生命周期。普通 store query 继续使用各自调用者 context。Queue 升级按 version index 分批执行，并在实际升级期间报告 progress。

## Readiness 与启动顺序

`eventstore.NewStore` 为全新数据库写入 `store_readiness.mode=fresh`。Core、Supervisor、dispatcher 与 UI server 构造之前，启动流程校验 pinned database identity、index root、projection metadata 与 readiness metadata。

普通启动与 commit 使用有界 metadata gate。执行以下命令可在 serving 前完成 manifest hash 与 encryption-root reference 的全量审计：

```bash
./Scardice-core --verify-event-store
```

导入发布始终执行完整 source/target 验证。普通加密记录读取执行 AES-GCM authentication 与 ownership 校验；历史 root-reference 扫描及闲置历史密钥加载属于显式审计。

Legacy state 的启动资格要求 `store_readiness.mode=import` 通过校验；其它 mode 返回 migration-required。流程终止于 readiness gate，provider worker 与 legacy launcher 保持 pre-start 状态。

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

Callback 在等待 commit fence 时持续续租。最后一次 renewal 的 version 传入 terminal CAS，commit context 的 expiry 早于 lease expiry。Cancellation 结束当前 attempt，已经启动的 Host 保持单次执行。

委托命令共享 callback transaction、commit fence 与 post-commit coordination。`.ob @user` 等命令用目标玩家自身 expected version 完成 load/save。Durable reply 由 owning callback 执行；Host 在收集并 finalize mutation 后释放 execution state。

Sensitive plugin default 与 current value 使用独立加密 PluginKV namespace。注册过程在一个 commit 中写 definition 与 initial value；显式值（含 empty value）优先于 default。Public plugin storage 保持自己的完整 key space。

Group refresh 与 WebUI quit 使用 durable action boundary。普通 inbound callback 按 cooldown 请求 refresh。经过验证的 observation 更新 group cache；空名称和省略的 count 字段沿用已有值。

WebUI quit 在一个事务中接收全部 farewell part 与 quit action，维持 lane 顺序，并为相同文本 segment 分配独立 emission identity。只有 accepted 且 committed 的请求应用 membership removal 与 success notice。Callback quit（含跨群 master command）把 canonical membership 与 outbound intent 一起 commit；local membership 在 callback CAS 成功后发布。

`data/queue-failures.log` 的固定字段为 queue、item ID、state 与 failure context。Message content 与 cryptographic material 继续由 encrypted payload store 持有。日志使用 10 MB rotation、3 个 backup 和 7 天 retention。该文件提供 best-effort 诊断；committed queue state 与 outcome event 是权威记录。

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

Backup archive 把 local file-backed key 保存到 `data/endpoint/keys/`。显式路径恢复时，将 runtime 配置指向解压后的 snapshot 与 key。ZIP 按敏感数据处理；Unix 上的 snapshot 与 bundled key entry 保留 owner-only `0600` mode。Snapshot 与 ZIP 使用 `backups/` 下的隐藏暂存目录，archive close 与 sync 完成后在同一文件系统原子发布。

Windows 上的 bundled local key 使用 DPAPI，portable scope 为原 DPAPI context、原用户与原设备。External key source 继续由部署方保管，`backup_info.json` 记录该边界。

一致性 snapshot 的 backend scope 为 SQLite；其它 backend 的 backup request 返回 capability error。

Filesystem-backed list API（如 `/sd-api/backup/list`、`/sd-api/resource/page`）在目录 lookup 返回 `os.ErrNotExist` 时返回 empty array，目录生命周期保持由写操作管理。`/sd-api/resource/data` 把可解码图片返回为 PNG，thumbnail width 为 64；解码错误返回 HTTP 422。

## 导入 legacy 数据

### 运行导入

导入前停止本地 SQLite 安装，并从安装目录执行：

```bash
./Scardice-core --import-legacy --hide-ui --container-mode
```

可执行文件读取 `data/` 下的 legacy 文件，写入独立 candidate database，完成验证后发布。成功结果写入 `legacy import published` 并退出；随后按普通方式启动 Scardice。

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

完整 sorted source/target record set 均计算 canonical SHA-256 digest，发布条件是两端 digest 相同。Canonical manifest bytes 在 64 MiB readiness metadata limit 内直接保存；更大导入保存 matching digest，manifest body 继续由 candidate 数据重建。

### Candidate 发布与加密

`SQLiteTarget` 提供本地 target。导入写入独立 candidate，active database path 在原子 activation 时才切换。Candidate 验证后执行 sync，并以 atomic rename 覆盖 active path；同步 hard-link backup 保留到 replacement reopen 成功。Activation error 触发 rollback，然后返回错误。

Runtime startup 与 migration 使用同一套完整 Core/Endpoint projection registry。每个 batch 在一个 `UnitOfWork` 中 commit aggregate event、AES-GCM credential 与 encrypted plugin KV。Zero-length legacy BuntDB key 作为 opaque、addressable key 保留。Participant error 回滚整批。

Reopen 后，aggregate event、credential 与 plugin value 在一个 consistent bounded-page transaction 中完成 integrity check。Credential 与 plugin plaintext 的比较使用 per-attempt in-memory HMAC；persisted semantic manifest 保存语义证据与 digest，plaintext 生命周期限定为该 attempt。

Story-log receipt 使用 Dice/identity composite keyset index。Encrypted resource 按 bounded page 读取，并复用 session mapping 与已准入 privacy/encryption key material。Payload encryption 为 AES-GCM，canonical integrity 为 SHA-256。Target database、WAL 与 SHM 均使用 owner-only mode。

Activation 成功后的 handle-close error 记录为 cleanup warning，已激活 target 继续保持 published 状态。

### Source 安全边界

Pre-publication error 创建 owner-only `.quarantine` marker。Source metadata 在 target creation 前和 publication 前各校验一次。原 active readiness repository 只用于 preflight read，所有 import write 指向 candidate。

Source inventory 必须提供完整 ownership map 与每条 record 的真实 payload。Digest-only record 或 ownership map 缺项会得到 validation error。`LegacySource` 映射 local YAML、SQLite、credential 与 BuntDB owner。

Local SQLite importer 清点 resolved `data.db` 旁的 optional `data-logs.db` 及其 `-wal`、`-shm` sidecar。Source 保持 stopped 状态；reader 使用完整 database/sidecar set 的 private scratch copy，并只重建该 copy 的 SHM index。

Inventory、snapshot 与 read 通过 held、descriptor-backed `os.Root` 遍历 SQLite/log sidecar、group/configuration data、extension storage 与 remote-filesystem snapshot。显式 root symlink 先 canonicalize；root 内的 absolute `DataDir` 可参与 path mapping。Descendant symlink 得到 source-path validation error，descriptor-rooted operation 将访问范围固定在选定 source root。

### Story 日志导入

Log importer 将 legacy log 与 item 映射到 typed session、entry 和 current-state record。它保留 nullable `extra`、upload/session metadata，以及 message text、nickname、user ID、timestamp、command info、raw/uniform message ID、sequence、removal state 和 parent ID。

Source-scoped record identity 关联 entry、current state 与 session。每个 batch 在同一 `UnitOfWork` 中写 archive resource 与 import receipt；相同 retry 产生幂等结果，content conflict 返回冲突错误。

Target reopen 后，verification 解密实际 imported resource，并把 key-backed semantic manifest 与 source 比较。Legacy log-table import capability 当前覆盖 local SQLite source；remote legacy log source 返回 capability-validation error。Remote SQL EventStore runtime backend 继续通过 `eventstore.DatabaseConfig` 集成。

## 迁移后的运行语义

### 协议与 endpoint

- Inbound text 与 structured mention 进入 segment command parser；message edit 与 delete 分别进入对应 callback。
- Provider member role 与 Core master privilege 使用独立 authority source。Provider permission lookup error 返回权限错误。
- Telegram entity 使用 UTF-16 offset，覆盖 caption、explicit user mention、bot username 和从早先消息学习到的 username。
- Observed bot identity 优先于 configured account hint。OneBot group identity 在 command reply 全程使用 `QQ-Group:<id>`。
- SealChat 通过 generation-fenced Core service 提供 `character.get`、`set`、`list`、`new`、`save`、`tag`、`untagAll`、`load` 与 `delete`。Mutation 持久化完成后返回 success；name 与 attribute key 可包含空格。每个 Runtime 的 write limit 为 60/minute，burst 为 5。
- Pure OneBot 设置使用 OneBot canonical field set；embedded-client protocol、app-version 与 signing-server field 归属 embedded-client configuration。UI 只把 `succeeded` 显示为成功；`failed`、`expired` 与 `ambiguous` 显示为错误。
- Endpoint adapter `SecretRef` 的 resolution scope 是 owning endpoint/adapter tuple。Owner match 是 decrypt prerequisite；mismatch 返回 reference-absent result，decrypt attempt count 为 0。Provider identity observation 保留 event correlation；endpoint state 与 projection 保留 active lifecycle operation ID 及 correlation。
- OneBot guild message 使用 `QQ-CH-Group:<guild>-<channel>` 并保留 opaque provider message ID；group recall 进入 deletion callback。Meta-event heartbeat 进入 observability-only 路径。Request/notice allowlist failure 计为 rejection，endpoint worker 继续运行。
- Official QQ websocket process 注册一个 static BotGo handler key，并为每个 Runtime generation 分配唯一 process-local route token。只有 active token 接受 event；stale generation event 进入 stale-drop 结果。Channel group ID `OpenQQCH-Channel:<guild>-<channel>` 与 private scope `PG-OpenQQCH:<user>` 参与 group-user ownership、cache generation 与 privacy selection。
- Endpoint lifecycle intent 从 endpoint event 恢复，并由 supervisor reconcile；provider outbox 的范围是 provider effect。Built-in process startup 中的 explicit stop 产生 normal shutdown；parent cancellation 与 startup failure 保留各自 error result。
- Explicit disable 或 removal 的 runtime stop 成功后完成当前 lifecycle command。Replaced worker callback 保留 worker-start fence，并通过 stale-update validation。
- Compatibility callback 请求的 group-card change 是 callback `UnitOfWork` 内的 durable outbox action；empty card 表示清除 member card。Provider dispatch 在 commit 后开始。

### 属性与 privacy

- Durable callback 的 attribute update 在 `UnitOfWork` commit 后 invalidates shared cache。Character service operation 与 callback 串行化；group privacy invalidation evicts attribute cache 与 binding state。
- Private group-user load 共享 group-generation fence，pre-invalidation decrypt 结果在 publication 前经过 generation validation。
- Group privacy purge 按 exact stream identity 选择 durable group/group-user `attributes` stream，也覆盖 `attrsType` 标记错误的 legacy snapshot。Purge 在最后一个 selected event 后移除 projection 与全部 secret version，同时保留 character/global 和其它 group attribute，并以 stream owner 校验 group HMAC。
- Privacy fence active 时，unkeyed group write 返回 fenced-write error。Owner identity 存在歧义的 malformed `group_user` 在 dry-run 与 deletion 返回 metadata error；修复 identity 后即可重试。
- `logs` scope 需要 caller 显式选择，默认 scope 为 `group_record`。Dry-run 与 audit count 覆盖 sessions、states、entries、intents 与 import receipts 五张 archive table。
- Log privacy deletion 使用 fenced、bounded、resumable table purge。Domain event 归属其它 privacy scope；pending intent 受 deletion fence 约束，terminal transition 保持 session tombstone。
- Archive digest 每页最多 materialize 8 MiB payload；oversized ciphertext 以 chunk stream 进入 canonical digest，deletion 只读取 metadata。其它 Dice、其它 group、external export、backup 与 original source 保持各自生命周期。
- Privacy deletion 将每个 erased global event position 作为 tombstone，与 event deletion、history revision 原子 commit。Projection rebuild 可跳过具有 tombstone position proof 的位置；其它 history gap 返回 invariant failure，legacy deletion gap 采用同一结果。
- Rebuild shadow generation 同时受 published generation 与 privacy-history revision fence 约束。Concurrent purge 或 publication 使 in-flight rebuild 进入 invalidated 结果。Readiness check 通过一个 database snapshot；remote backend 使用 shared publication lock。

### Story archive 与管理视图

- EventStore encrypted archive 保存 Story session、current group state、entry、outbound intent 与 import receipt。Selected session 及其 on/off state 跨 restart 持久化。Dice/group scope 使用 keyed HMAC，encrypted payload 绑定 scope 与 owner。
- Inbound callback 的 log update 与 callback 其它 durable change 进入同一 `UnitOfWork`。Legacy adapter 使用相同 repository boundary。`.log`（含 `.log list`）、`.stat log`、Story API、log export 的 write target 均为 selected repository。
- Session `created_at` 与 `updated_at` 是 canonical content timestamp，entry `Time` 的 scope 限于该 entry。Append、content-changing edit 与 recall 在同一事务中推进 `updated_at` 并清除 cached upload URL/time；unchanged edit 保留 cache，upload 保留 content timestamp，legacy import 保留 source session timestamp。
- Durable advanced-config view 持久化 `StoryLogApiVersion`。GET-derived full update 会保留该设置与 token reference；GET 的 token field 返回 empty value，实现 write-only redaction。
- 认证后的 `/sd-api/dice/exec` 为每条 synthetic UI message 生成 `UI:exec:<uuid>` raw ID，并通过共享 `IMSession.Execute` hook 执行。该 ID 的类别是 server-generated UI identity；每次相同文本 submission 都获得独立 ID 与 archive entry。后续 `.r` input 及 bot reply 也进入 archive。Provider inbound message 继续要求 provider message ID。
- Successful outbound delivery 在 terminal transaction 中 commit archived entry 并移除 pending intent。Archive entry 的创建条件是 successful delivery；`failed` 与 `expired` effect 保持各自 terminal result，late terminal transition 受 deleted-session fence 约束。
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
- EventStore runtime 以 `moderation` stream 与 projection 作为 active ban list 的权威来源。每次 mutation 在一个 EventStore transaction 中 commit moderation event 与 encrypted detail secret。Name、reason、time、place 与 ban timestamp 保存在 encrypted history。EventStore persistence set 由 moderation stream、projection 与 encrypted secret 组成；`ban_info` 和 `ban-list.json` 属于 legacy persistence path。Projection 或 encrypted history read error 使 startup 返回 readiness error。List、mutation、import 与 export route 要求 WebUI authentication。
- User-authored text template 保存于 Dice data directory 的 `configs/text-template.yaml`，生命周期独立于 EventStore projection。文件存在时，两条 runtime initialization path 以该文件为权威内容；该路径返回 `os.ErrNotExist` 时加载 built-in template。两条路径均从 selected template 生成 runtime 与 WebUI lookup map。
- 认证后的 Dice configuration endpoint 在一个 EventStore `UnitOfWork` 中 commit Dice settings、manager settings、authentication change 与 extension default。Runtime state 在 commit 后发布；validation 或 commit error 保留全部 owner 的先前版本。Persisted extension override 集合精确等于 `extDefaultSettings` array 中的 entries；empty array 生成 empty override set。
- 默认 PCG random source 在 startup 初始化。GM、NIST、CRNG 与 hybrid source 在显式选择或 inspection 时初始化；普通实例的 entropy allocation 范围为 PCG。
