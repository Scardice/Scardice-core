# Runtime Plugin C ABI Phase 0 基线

## 范围与状态

本报告基于当前本地 checkout 建立，未修改生产代码。以下“现有工作区状态”与“未来改造失败”严格分开：本次基线命令均成功；Phase 0 未执行任何未来改造，因此没有未来改造失败可报告。

## 环境与 checkout

| 项目 | 值 |
| --- | --- |
| 分支 | `feat/pluggable-plugin-runtime` |
| 本地提交（日期无关） | `b15c8ebb518f38639ca5d369735ed88c4d0dac15` |
| Go | `go1.27.0-X:nodwarf5 linux/amd64` |
| `CGO_ENABLED` | `1` |
| `GOOS` | `linux` |
| `GOARCH` | `amd64` |
| 编译器（`go env CC`） | `gcc` |

确认命令：

```text
git branch --show-current && git rev-parse HEAD && git status --short
go version && go env CGO_ENABLED GOOS GOARCH CC
```

## 用户已有工作区改动

在本次报告文件创建前，`git status --short` 的原始结果为：

```text
 m Scardice-ui
?? plan.md
```

这是用户已有状态：修改的 `Scardice-ui` 子模块和未跟踪的 `plan.md` 均未处理、未丢弃、未暂存，也未纳入本次变更。它们不是基线测试失败。

## 本地符号清单

清单按当前 checkout 的文本匹配建立；行号对应上述基线提交中的源文件。`plan.md` 是用户已有的未跟踪规划文件，仅作为“本地出现”单独标出，不属于生产实现。

### 选择与初始化

| 符号 | 已跟踪源文件位置 | 用户已有 `plan.md` 位置 |
| --- | --- | --- |
| `jsInitQuickJS` | `dice/dice_jsvm.go:348`（调用）；`dice/js_quickjs.go:82,84`（注释、定义） | `plan.md:176,2269` |
| `configuredJSEngine` | `dice/dice_jsvm.go:339`；`dice/js_engine_config.go:5`；`dice/js_engine_config_test.go:30,33,38,41,53,58`；`dice/js_quickjs.go:168` | `plan.md:2247` |
| `isQuickJSExperiment` | `dice/dice_jsvm.go:1650`；`dice/js_quickjs.go:167` | `plan.md:2247` |
| `EngineQuickJS` | `api/js.go:62`；`dice/dice_jsvm.go:347`；`dice/dice_jsvm_dangerous_expose.go:53`；`dice/dice_jsvm_test.go:120`；`dice/js_engine_config_test.go:23,57,58`；`dice/js_loop_manager_test.go:26,27`；`dice/js_quickjs.go:169`；`dice/js_quickjs_node_test.go:31`；`utils/jsengine/engine.go:15,16,25,26`；`utils/jsengine/engine_test.go:16`；`utils/jsengine/quickjs/runtime.go:172,188`；`utils/jsengine/quickjs/runtime_test.go:111,112` | `plan.md:138,175,2247,2978` |

### Loop 访问与执行

| 符号 | 已跟踪源文件位置 | 用户已有 `plan.md` 位置 |
| --- | --- | --- |
| `GetWebLoop` | `api/js.go:81`；`dice/dice.go:172`（定义）；`dice/dice_jsvm.go:1666`；`dice/dice_jsvm_test.go:64`；`dice/forward_validation_test.go:457`；`dice/im_session.go:3157` | `plan.md:1509,2251` |
| `GetEngineLoop` | `dice/dice.go:199,201`（注释、定义）；`dice/dice_jsvm_test.go:116`；`dice/ext.go:395`；`dice/im_session.go:2998`；`dice/js_loop_manager_test.go:19,21,24`；`dice/js_quickjs_node_test.go:59` | `plan.md:231,1510,2251` |
| `SetEngineLoop` | `api/js_test.go:38`；`dice/dice.go:219,221`（注释、定义）；`dice/dice_jsvm_test.go:104,179`；`dice/im_session_command_solve_test.go:597`；`dice/js_engine_value_test.go:107`；`dice/js_quickjs.go:109,142,147`；`dice/js_quickjs_node_test.go:34,190` | `plan.md:233,1511,2251` |
| `RunOnLoop` | `api/js.go:88`；`dice/dice.go:302`（注释）；`dice/dice_jsvm.go:2074`；`dice/dice_jsvm_fs.go:215`；`dice/dice_jsvm_fs_test.go:303`；`dice/dice_jsvm_test.go:66`；`dice/ext.go:429,492`；`dice/forward_validation_test.go:459`；`dice/im_session.go:1443,1722,3168`；`dice/im_session_command_solve_test.go:513`；`utils/plugin/httpextra/fetch.go:69`；`utils/plugin/httpextra/httpextra_test.go:35`；`utils/plugin/websocket/websocket.go:695`；`utils/plugin/websocket/websocket_test.go:28` | `plan.md:256,1551,2251` |

### `.Export(` 边界

| 已跟踪源文件 | 匹配位置（行） |
| --- | --- |
| `api/js.go` | 77, 104 |
| `dice/dice_jsvm_dangerous_expose_test.go` | 80 |
| `dice/dice_jsvm_fs.go` | 512 |
| `dice/ext.go` | 331, 337, 350, 351, 357, 360 |
| `dice/im_session.go` | 2835, 2845, 2848, 2868 |
| `dice/js_engine_value.go` | 18 |
| `dice/js_host_api_test.go` | 72 |
| `dice/js_quickjs_fs_test.go` | 76 |
| `utils/jsengine/runtime_contract_test.go` | 60, 116, 174, 225, 278, 334, 394, 499, 582 |
| `utils/jsengine/goja/runtime.go` | 121 |
| `utils/jsengine/goja/runtime_test.go` | 22 |
| `utils/jsengine/quickjs/runtime_test.go` | 102, 136, 172 |
| `utils/plugin/crypto/alg_helpers.go` | 36 |
| `utils/plugin/crypto/crypto_test.go` | 18, 20, 42, 44, 67, 69, 132, 134, 171, 173, 210, 212, 251, 253, 283, 285, 315, 317, 346, 348 |
| `utils/plugin/crypto/key_io.go` | 686, 694 |
| `utils/plugin/crypto/runtime_helpers.go` | 17, 159, 218, 240, 282, 293 |
| `utils/plugin/httpextra/fetch.go` | 215 |
| `utils/plugin/httpextra/httpextra.go` | 156, 467, 484 |
| `utils/plugin/httpextra/httpextra_test.go` | 288, 290, 295, 297, 319, 321 |
| `utils/plugin/websocket/websocket.go` | 390 |

未跟踪 `plan.md` 中仅出现了检索命令文本 `\.Export\(`，不是生产调用点。

## 基线命令结果

以下是本次实际运行的三个、且仅三个基线测试命令。退出码均为 `0`。

### `go test ./utils/jsengine/...`

```text
ok  Scardice-core/utils/jsengine  (cached)
ok  Scardice-core/utils/jsengine/goja  (cached)
ok  Scardice-core/utils/jsengine/quickjs  (cached)
```

结果：成功，3 个包通过。

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

结果：成功，7 个包通过，3 个包无测试文件。

### `go test -race ./...`

```text
go test: 28 packages ok, 35 no tests
ok   Scardice-core  1.210s
ok   Scardice-core/api  (cached)
ok   Scardice-core/dice  (cached)
ok   Scardice-core/dice/censor  (cached)
ok   Scardice-core/dice/docengine  (cached)
?    Scardice-core/dice/events  [no test files]
ok   Scardice-core/dice/imsdk/onebot  (cached)
?    Scardice-core/dice/imsdk/onebot/schema  [no test files]
?    Scardice-core/dice/imsdk/onebot/types  [no test files]
ok   Scardice-core/dice/sealpack  (cached)
ok   Scardice-core/dice/service  (cached)
ok   Scardice-core/dice/storylog  (cached)
?    Scardice-core/icon  [no test files]
ok   Scardice-core/logger  (cached)
ok   Scardice-core/message  (cached)
?    Scardice-core/migrate  [no test files]
ok   Scardice-core/migrate/v2  (cached)
?    Scardice-core/migrate/v2/v120  [no test files]
?    Scardice-core/migrate/v2/v131  [no test files]
?    Scardice-core/migrate/v2/v141  [no test files]
?    Scardice-core/migrate/v2/v144  [no test files]
?    Scardice-core/migrate/v2/v150  [no test files]
?    Scardice-core/migrate/v2/v151  [no test files]
?    Scardice-core/migrate/v2/v162  [no test files]
?    Scardice-core/migrate/v2/v2test  [no test files]
?    Scardice-core/model  [no test files]
?    Scardice-core/scripts/randomness  [no test files]
?    Scardice-core/signature  [no test files]
?    Scardice-core/signature/gen  [no test files]
?    Scardice-core/static  [no test files]
?    Scardice-core/static/gen  [no test files]
ok   Scardice-core/utils  (cached)
?    Scardice-core/utils/constant  [no test files]
?    Scardice-core/utils/crypto  [no test files]
?    Scardice-core/utils/dboperator  [no test files]
?    Scardice-core/utils/dboperator/dbutil  [no test files]
?    Scardice-core/utils/dboperator/engine  [no test files]
?    Scardice-core/utils/dboperator/engine/mysql  [no test files]
?    Scardice-core/utils/dboperator/engine/pgsql  (cached)
ok   Scardice-core/utils/dboperator/engine/sqlite  (cached)
ok   Scardice-core/utils/dboperator/schema  (cached)
ok   Scardice-core/utils/jsengine  (cached)
ok   Scardice-core/utils/jsengine/goja  (cached)
ok   Scardice-core/utils/jsengine/quickjs  (cached)
?    Scardice-core/utils/oschecker  [no test files]
?    Scardice-core/utils/panicHandler  [no test files]
?    Scardice-core/utils/paniclog  [no test files]
?    Scardice-core/utils/plugin/abort  [no test files]
ok   Scardice-core/utils/plugin/crypto  (cached)
ok   Scardice-core/utils/plugin/httpextra  (cached)
?    Scardice-core/utils/plugin/structuredclone  [no test files]
?    Scardice-core/utils/plugin/utilinspect  [no test files]
?    Scardice-core/utils/plugin/websocket  (cached)
?    Scardice-core/utils/procs  [no test files]
?    Scardice-core/utils/public_dice  [no test files]
?    Scardice-core/utils/random  (cached)
?    Scardice-core/utils/satori  [no test files]
?    Scardice-core/utils/spinner  [no test files]
ok   Scardice-core/utils/throttle  (cached)
ok   Scardice-core/utils/upgrader  (cached)
ok   Scardice-core/utils/upgrader/store  (cached)
```

结果：成功（退出码 `0`）；工具汇总为 28 个包通过、35 个包无测试文件，且 race 检测未报告问题。

## 未来改造失败（明确为空）

本 Phase 仅建立基线，没有开始 Runtime Plugin C ABI 改造；因此没有可归因于未来改造的编译、测试或运行时失败。若后续阶段出现失败，应与上述用户已有 `Scardice-ui`/`plan.md` 工作区状态及本节基线结果分开记录。
