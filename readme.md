# Scardice

![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)
![Core](https://img.shields.io/badge/Scardice-Core-blue)

余烬 TRPG 骰点核心，开源跑团辅助工具，支持 QQ/Kook/Discord 等。

轻量 · 易用 · 全能

## 文档

见 [使用手册](https://sealdice.github.io/sealdice-manual-next/)。

## Scardice Project

- [核心](https://github.com/Scardice/Scardice-core)（本仓库）：Go 后端代码仓库，也作为余烬的主仓库，Bug 可反馈在该仓库的 issue 中；
- [UI](https://github.com/Scardice/Scardice-ui)：前端代码，基于 Vue3 + ElementPlus 开发；
- [手册](https://github.com/sealdice/sealdice-manual-next)：官方手册源码，由 VitePress 驱动；
- [构建](https://github.com/sealdice/sealdice-build)：自动构建仓库，用于自动化发布余烬的每日构建包与 Release；
- [Android](https://github.com/sealdice/sealdice-android)：Android 应用源码；
- ……

注：如无特殊说明，所有代码文件均遵循 MIT 开源协议

## Core 开发环境搭建

### golang 开发环境

编译的 golang 版本为 1.25.0。在 [构建](https://github.com/sealdice/sealdice-build) 仓库中采用对 go 进行修补的方式以支持 Windows 7 等低版本系统。

因部分依赖库的需求，可能需要配置国内镜像，个人使用 [https://goproxy.cn/](https://goproxy.cn/) 镜像。

#### 代码格式化

本项目要求所有代码使用 goimports 进行格式化。这一行为已经设定在本项目的编辑器配置文件中。

#### 在本地配置 LINTER

本项目使用 golangci-lint 工具进行静态分析。

此工具对于代码开发**不是**必要的。但是，本项目的 CI 流程中配置了 linter 检查，不符合规范的代码不能被合入。

因此，强烈推荐开发者在本地安装此工具，请参考[这份文档](https://golangci-lint.run/welcome/install/#local-installation)。分析器的相关配置位于 `.golangci.toml` 文件中。

你可能需要调整编辑器的相关配置，使用 golangci-lint 为默认的分析工具，并开启自动检查。

> 对于 Visual Studio Code，列出以下配置项供参考：
>
> 1. `go.lintTool` 选择 golangci-lint
> 2. `go.lintFlags` 添加一项 `--fast`
> 3. `go.lintOnSave` **不能**选择 file，因为只分析单个文件会导致无法正确解析符号引用
>
> 以上配置没有写入项目的统一设置，以允许开发者不本地使用 golangci-lint

#### 提交前 lint hook

仓库提供 `.githooks/pre-commit`，用于在本地提交前检查已暂存的 Go 文件格式，并对本次暂存改动涉及的 Go 包运行低成本的 `golangci-lint` 增量检查。

安装依赖并启用 Git hook：

```bash
task install
```

如果已经完成依赖安装，也可以只启用 Git hook：

```bash
task install-hooks
```

该配置会写入当前仓库的本地 Git 配置：

```bash
git config core.hooksPath .githooks
```

Git 不会从远端仓库自动启用客户端 hook；每个本地 checkout 都需要执行一次上述配置。

### 测试

Go 测试按功能与行为边界组织，同包场景共享测试夹具。用例名称描述输入条件与预期结果；适配器协议、持久化恢复、迁移、运行时生命周期和兼容性分别保留对应覆盖。

```bash
go test ./...
go test -race ./...
go vet ./...
```

原生 QuickJS 集成测试使用已安装的运行时包。按照 [QuickJS 构建说明](runtime-plugins/quickjs/README.md) 生成包后运行：

```bash
SCARDICE_QUICKJS_PACKAGE=/path/to/runtime-root go test ./utils/jsengine/native ./runtime-plugins/quickjs/test -count=1
```

WebUI 的浏览器集成测试在 Scardice-ui 仓库通过 `pnpm test` 运行，覆盖备份、牌堆操作、新闻、分页、资源预览及设置持久化。

### 编译运行

#### 使用 Python 构建器

仓库根目录的 `build.py` 使用 Python 标准库构建并打包 Scardice。准备 Python 3.9+、Go、Git；发布构建还需要 Node.js 和 pnpm。若系统有 npm 但没有 pnpm，脚本会尝试通过 npm 全局安装 pnpm。

在 Linux 或 macOS 上运行：

```bash
python3 build.py
```

在 Windows 上运行：

```powershell
py build.py
```

在交互终端中不传配置组时，脚本会逐项询问构建选项，并以 `default` 组的值作为默认值。非交互环境直接使用 default 组。指定配置组后不显示交互提示：

```bash
python3 build.py --config-group default
python3 build.py --config-group dev
```

Windows PowerShell 使用 Python Launcher：

```powershell
py build.py --config-group default
py build.py --config-group dev
```

`default` 组构建单个本机目标并生成发布压缩包；`dev` 组只编译 core，并在仓库根目录生成本机可执行文件（Windows 使用 `.exe`）。配置组定义在根目录的 `build-config.json`。每个组会继承 `default_group` 指向组的值，再覆盖自己指定的字段。下面是可运行的配置示例：

```json
{
  "default_group": "default",
  "groups": {
    "default": {
      "version_main": null,
      "version_prerelease": "-dev",
      "app_channel": "dev",
      "appname": "Scardice",
      "build_mode": "single",
      "targets": ["host/host"]
    },
    "linux-release": {
      "build_mode": "multi",
      "targets": ["linux/amd64", "linux/arm64"],
      "cgo": false
    }
  }
}
```

然后运行 `python3 build.py --config-group linux-release`；Windows PowerShell 对应使用 `py build.py --config-group linux-release`。`build_mode` 支持 `single` 和 `multi`；`targets` 使用 `goos/goarch` 字符串数组。启用 CGO 交叉编译前，先安装目标平台对应的 C 编译器。

发布构建默认会更新 `Scardice-ui` 和 `sealdice-builtins` submodule，按 UI 提交与 lockfile 指纹决定是否重建 UI，并在 `output/` 生成压缩包。过程缓存保存在 `.build-cache/`。构建器不会清空 `output/`：只替换同名归档，保留其他文件；构建期间会暂存嵌入用的 UI 文件，并在结束后恢复原有 `static/frontend/`。

配置组可通过 `update_submodules`、`pack_runtime_assets`、`strict_runtime_assets`、`compatible_names` 和 `upx` 控制 submodule、运行时资源、兼容命名与 UPX。下载代理和超时仍可通过 `BUILD_PROXY`、`DOWNLOAD_*` 等环境变量设置。


#### 使用 `go-task`

你可以安装 [go-task](https://taskfile.dev/installation) 以执行预置好的任务。安装后可执行：

```bash
# 初次编译运行（包括安装依赖和相关工具）
task install run

# 后续编译运行
task run
```

#### 手动执行

你也可以按照以下步骤手动进行编译运行：

##### 拉取代码并配置数据文件

使用 git 拉取项目代码

从已发布的余烬二进制包中，解压 `data`、`lagrange` 两个目录到代码目录下。

同时需要在项目的 `static/frontend` 下放置用于打包进 core 的 ui 静态资源文件，可手动提供，也可通过命令自动从 github 拉取：

```bash
go generate ./...
```

放置静态资源大致如下：

```text
static
│
└─frontend
   │  CNAME
   │  favicon.svg
   │  index.html
   │
   └─assets
```

##### 运行编译命令

打开项目，或使用终端访问项目目录，运行：

```bash
go mod download
go install github.com/pointlander/peg@v1.0.1
go build
```

或者直接使用：

```shell
go run .
```

启动项目，大功告成！

## 重点

### 从哪开始看

从 `main.go` 开始，这里余烬分出了几个线程，一个启动核心并提供服务，另一个提供 ui 的 http 服务。

可以顺藤摸瓜了解余烬如何启动，如何提供服务，如何响应指令。指令响应的部分写在 `im_session.go` 中

注意有部分代码还在构思中，实际并未使用，例如 `CharacterTemplate`，请阅读时先 Find Usage 加以区分

### 重要数据结构

`dice.go` 中的 `Dice` 结构体存放着各种核心配置，每个 `Dice` 实例是一个骰子，而每个骰子下面可以挂靠多个端点 (EndPoint)。端点即交互渠道，例如一个 QQ 账号是一个端点。

所有的端点由 `IMSession` 来统一管理，同样的，这个类也负责接收和分发指令。

可能你会注意到有 `IMSession` 和 `IMSessionLegacy`，只看前一个就行，`IMSessionLegacy` 对应的是 0.99.13 的上古版本之前的数据结构，仅用于升级配置文件。

`GroupInfo` 是群组信息

`GroupPlayerInfo` 是玩家信息

### 为余烬添加更多平台支持

余烬使用叫做 `PlatformAdapter` 的接口来接入平台，只需将接口全部实现，再创建一个 `EndPointInfo` 塞入当前用户的 `IMSession` 对象之中即可。

注：每次在 UI 上添加 QQ 账号，其实就是创建了一个 `EndPointInfo` 对象，并制定 Adapter 为 `PlatformAdapterQQOnebot`

目前实现的两个 adapter，一个对应 onebot 协议，主要用于 QQ，另一个对应 http，用于 UI 后台的测试窗口。

观察 `PlatformAdapterHttp` 如何运作起来是一个很好的切入点，因为他非常简单。

### 改动扩展模块，如 dnd5e，coc7 等

对应 `dice/ext_xxx.go` 系列文件

推荐从 `ext_template.go` 入手，以 `ext_dnd5e.go` 为参考，因为这个模块书写时间较晚，相对较为完善。

### 暂不建议修改的地方

#### 表达式解析器

`dice/roll.peg` 是余烬的骰点指令文法文件

`dice/rollvm.go` 是骰点指令虚拟机

1.5 后，已经替换使用 dicescript (RollVM V2) 作为表达式解释器，现有版本不宜轻动。

关于 dicescript 的信息，请移步 [https://github.com/sealdice/dicescript](https://github.com/sealdice/dicescript)

而出于兼容性的考虑，V1 版本的解释器将继续保留，直到 2.0 版本。
