# Phase 0 Baseline 任务报告

## 变更文件

仅新增以下两个文件，未修改生产代码：

- `docs/runtime-abi/baseline.md`
- `.superpowers/sdd/plan/task-0-report.md`

未处理用户已有的 `Scardice-ui` 子模块修改或未跟踪 `plan.md`；未处理 `plan.md` 内容，也未执行格式化、lint 或额外项目级测试。

## 权威 checkout 状态

- 分支：`feat/pluggable-plugin-runtime`
- 提交：`b15c8ebb518f38639ca5d369735ed88c4d0dac15`
- Go：`go1.27.0-X:nodwarf5 linux/amd64`
- `CGO_ENABLED=1`，`GOOS=linux`，`GOARCH=amd64`，编译器 `gcc`
- 原始用户已有工作区状态：

  ```text
   m Scardice-ui
  ?? plan.md
  ```

完整符号清单已写入 `docs/runtime-abi/baseline.md`，包括选择/初始化、loop 访问/执行和全部 `.Export(` 匹配点，并将 `plan.md` 中的规划文本匹配与已跟踪生产源分开。

## 基线命令与原始输出

以下命令按简报要求逐一运行，均以退出码 `0` 完成。

### `go test ./utils/jsengine/...`

```text
ok  Scardice-core/utils/jsengine  (cached)
ok  Scardice-core/utils/jsengine/goja  (cached)
ok  Scardice-core/utils/jsengine/quickjs  (cached)
```

### `go test ./dice/...`

```text
ok  Scardice-core/dice  (cached)
ok  Scardice-core/dice/censor  (cached)
ok  Scardice-core/dice/docengine  (cached)
?   Scardice-core/dice/events  [no test files]
ok  Scardice-core/dice/imsdk/onebot  (cached)
?   Scardice-core/dice/imsdk/onebot/schema  [no test files]
?   Scardice-core/dice/imsdk/onebot/types  [no test files]
ok  Scardice-core/dice/sealpack  (cached)
ok  Scardice-core/dice/service  (cached)
ok  Scardice-core/dice/storylog  (cached)
```

### `go test -race ./...`

观察到的工具汇总：`go test: 28 packages ok, 35 no tests`；退出码为 `0`，race 检测未报告问题。原始逐包输出如下：

```text
ok  	Scardice-core	1.210s
ok  	Scardice-core/api	(cached)
ok  	Scardice-core/dice	(cached)
ok  	Scardice-core/dice/censor	(cached)
ok  	Scardice-core/dice/docengine	(cached)
?   	Scardice-core/dice/events	[no test files]
ok  	Scardice-core/dice/imsdk/onebot	(cached)
?   	Scardice-core/dice/imsdk/onebot/schema	[no test files]
?   	Scardice-core/dice/imsdk/onebot/types	[no test files]
ok  	Scardice-core/dice/sealpack	(cached)
ok  	Scardice-core/dice/service	(cached)
ok  	Scardice-core/dice/storylog	(cached)
?   	Scardice-core/icon	[no test files]
ok  	Scardice-core/logger	(cached)
ok  	Scardice-core/message	(cached)
?   	Scardice-core/migrate	[no test files]
ok  	Scardice-core/migrate/v2	(cached)
?   	Scardice-core/migrate/v2/v120	[no test files]
?   	Scardice-core/migrate/v2/v131	[no test files]
?   	Scardice-core/migrate/v2/v141	[no test files]
?   	Scardice-core/migrate/v2/v144	[no test files]
?   	Scardice-core/migrate/v2/v150	[no test files]
?   	Scardice-core/migrate/v2/v151	[no test files]
?   	Scardice-core/migrate/v2/v162	[no test files]
?   	Scardice-core/migrate/v2/v2test	[no test files]
?   	Scardice-core/model	[no test files]
?   	Scardice-core/scripts/randomness	[no test files]
?   	Scardice-core/signature	[no test files]
?   	Scardice-core/signature/gen	[no test files]
?   	Scardice-core/static	[no test files]
?   	Scardice-core/static/gen	[no test files]
ok  	Scardice-core/utils	(cached)
?   	Scardice-core/utils/constant	[no test files]
?   	Scardice-core/utils/crypto	[no test files]
?   	Scardice-core/utils/dboperator	[no test files]
?   	Scardice-core/utils/dboperator/dbutil	[no test files]
?   	Scardice-core/utils/dboperator/engine	[no test files]
?   	Scardice-core/utils/dboperator/engine/mysql	[no test files]
ok  	Scardice-core/utils/dboperator/engine/pgsql	(cached)
ok  	Scardice-core/utils/dboperator/engine/sqlite	(cached)
ok  	Scardice-core/utils/dboperator/schema	(cached)
ok  	Scardice-core/utils/jsengine	(cached)
ok  	Scardice-core/utils/jsengine/goja	(cached)
ok  	Scardice-core/utils/jsengine/quickjs	(cached)
?   	Scardice-core/utils/oschecker	[no test files]
?   	Scardice-core/utils/panicHandler	[no test files]
?   	Scardice-core/utils/paniclog	[no test files]
?   	Scardice-core/utils/plugin/abort	[no test files]
ok  	Scardice-core/utils/plugin/crypto	(cached)
ok  	Scardice-core/utils/plugin/httpextra	(cached)
?   	Scardice-core/utils/plugin/structuredclone	[no test files]
?   	Scardice-core/utils/plugin/utilinspect	[no test files]
ok  	Scardice-core/utils/plugin/websocket	(cached)
?   	Scardice-core/utils/procs	[no test files]
?   	Scardice-core/utils/public_dice	[no test files]
?   	Scardice-core/utils/random	(cached)
?   	Scardice-core/utils/satori	[no test files]
?   	Scardice-core/utils/spinner	[no test files]
ok  	Scardice-core/utils/throttle	(cached)
ok  	Scardice-core/utils/upgrader	(cached)
ok  	Scardice-core/utils/upgrader/store	(cached)
```

## 区分现状与未来失败

本阶段只建立改造前基线，没有执行 Runtime Plugin C ABI 改造。因此当前没有“未来改造失败”；上述三个命令反映的是既有 checkout 的基线状态，不应与用户已有工作区改动混淆。

## Concerns

- `Scardice-ui` 仍是用户修改状态，`plan.md` 仍未跟踪；两者均有意保持原状。
- 三个基线命令输出使用了缓存结果（输出中的 `(cached)`）；这是本地 checkout 的实际结果。
- 提交链：`abad4774`（`docs: record runtime ABI baseline`）→ `e717cafc`（`docs: finalize runtime ABI report`）。
