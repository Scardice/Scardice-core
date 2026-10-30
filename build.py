#!/usr/bin/env python3
"""Cross-platform Scardice build and packaging entry point."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Iterator


ROOT_DIR = Path(__file__).resolve().parent
ALL_GOOS = ("linux", "windows", "darwin", "freebsd", "openbsd", "netbsd")
ALL_GOARCH = ("amd64", "arm64", "386", "arm", "ppc64le", "riscv64", "s390x")
CONFIG_KEYS = {
    "version_main",
    "version_prerelease",
    "app_channel",
    "appname",
    "build_mode",
    "targets",
    "cgo",
    "redownload_runtime_assets",
    "compatible_names",
    "upx",
    "development",
    "update_submodules",
    "pack_runtime_assets",
    "strict_runtime_assets",
    "output_dir",
    "dev_output_dir",
    "ui_submodule_dir",
    "builtins_submodule_dir",
    "static_frontend_dir",
    "build_cache_dir",
    "private_key_file",
    "sign_key_file",
    "sign_v3_url_file",
}
BOOL_CONFIG_KEYS = {
    "cgo",
    "development",
    "update_submodules",
    "pack_runtime_assets",
    "strict_runtime_assets",
    "compatible_names",
}
OPTIONAL_BOOL_CONFIG_KEYS = {"upx", "redownload_runtime_assets"}
STRING_CONFIG_KEYS = {
    "version_prerelease",
    "app_channel",
    "appname",
    "build_mode",
    "output_dir",
    "dev_output_dir",
    "ui_submodule_dir",
    "builtins_submodule_dir",
    "static_frontend_dir",
    "build_cache_dir",
    "private_key_file",
    "sign_key_file",
    "sign_v3_url_file",
}


INVALID_FILENAME_CHARACTERS = frozenset('<>:"/\\|?*')


class BuildError(RuntimeError):
    """A configuration or build failure with a user-facing message."""


def _validate_version_component(name: str, value: str) -> None:
    if any(ord(char) < 32 or char in INVALID_FILENAME_CHARACTERS for char in value):
        raise BuildError(f"{name} 不能包含路径分隔符或文件名非法字符")


def _ensure_path_within(parent: Path, candidate: Path, label: str) -> None:
    resolved_parent = parent.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_parent)
    except ValueError as exc:
        raise BuildError(f"{label}路径必须位于 {resolved_parent} 内：{candidate}") from exc
    if resolved_candidate == resolved_parent:
        raise BuildError(f"{label}路径不能与目录相同：{candidate}")


def validate_config(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise BuildError("构建配置顶层必须是 JSON 对象")
    unknown_top = set(config) - {"default_group", "groups"}
    if unknown_top:
        raise BuildError(f"构建配置包含未知字段：{', '.join(sorted(unknown_top))}")

    default_group = config.get("default_group")
    groups = config.get("groups")
    if not isinstance(default_group, str) or not default_group:
        raise BuildError("构建配置必须设置非空 default_group")
    if not isinstance(groups, dict) or not groups:
        raise BuildError("构建配置必须包含非空 groups 对象")
    if default_group not in groups:
        raise BuildError(f"默认配置组不存在：{default_group}")

    for name, values in groups.items():
        if not isinstance(name, str) or not name:
            raise BuildError("配置组名称必须是非空字符串")
        if not isinstance(values, dict):
            raise BuildError(f"配置组 {name!r} 必须是 JSON 对象")
        unknown = set(values) - CONFIG_KEYS
        if unknown:
            raise BuildError(f"配置组 {name!r} 包含未知字段：{', '.join(sorted(unknown))}")
        for key in BOOL_CONFIG_KEYS:
            if key in values and not isinstance(values[key], bool):
                raise BuildError(f"配置组 {name!r} 的 {key} 必须是布尔值")
        for key in OPTIONAL_BOOL_CONFIG_KEYS:
            if key in values and values[key] is not None and not isinstance(values[key], bool):
                raise BuildError(f"配置组 {name!r} 的 {key} 必须是布尔值或 null")
        for key in STRING_CONFIG_KEYS:
            if key in values and not isinstance(values[key], str):
                raise BuildError(f"配置组 {name!r} 的 {key} 必须是字符串")
        if "version_main" in values and values["version_main"] is not None:
            if not isinstance(values["version_main"], str):
                raise BuildError(f"配置组 {name!r} 的 version_main 必须是字符串或 null")
        for key in ("version_main", "version_prerelease"):
            if key in values and values[key] is not None:
                _validate_version_component(key, values[key])
        if "build_mode" in values and values["build_mode"] not in {"single", "multi"}:
            raise BuildError(f"配置组 {name!r} 的 build_mode 必须是 single 或 multi")
        if "targets" in values:
            targets = values["targets"]
            if not isinstance(targets, list) or any(not isinstance(item, str) for item in targets):
                raise BuildError(f"配置组 {name!r} 的 targets 必须是字符串数组")
        for key in ("appname", "version_prerelease", "app_channel"):
            if key in values and not values[key].strip():
                raise BuildError(f"配置组 {name!r} 的 {key} 不能为空")

    return config


def load_config(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(f"无法读取构建配置 {path}: {exc}") from exc
    try:
        return validate_config(json.loads(content))
    except json.JSONDecodeError as exc:
        raise BuildError(f"构建配置 JSON 无效（{path}:{exc.lineno}:{exc.colno}）：{exc.msg}") from exc


def resolve_config_group(
    config: dict[str, Any], requested_group: str | None
) -> tuple[str, dict[str, Any]]:
    validate_config(config)
    group_name = requested_group or config["default_group"]
    groups = config["groups"]
    if group_name not in groups:
        available = ", ".join(sorted(groups))
        raise BuildError(f"未知配置组 {group_name!r}；可选配置组：{available}")

    defaults = groups[config["default_group"]]
    settings = dict(defaults)
    settings.update(groups[group_name])
    if isinstance(settings.get("targets"), list):
        settings["targets"] = list(settings["targets"])
    return group_name, settings


def should_prompt_for_settings(group_name: str | None, stdin_isatty: bool) -> bool:
    return group_name is None and stdin_isatty


def parse_targets(
    target_values: Any, host_goos: str, host_goarch: str
) -> list[tuple[str, str]]:
    if isinstance(target_values, str):
        raw_targets = [part.strip() for part in target_values.split(",") if part.strip()]
    elif isinstance(target_values, list):
        raw_targets = [part.strip() for part in target_values if isinstance(part, str) and part.strip()]
        if len(raw_targets) != len(target_values):
            raise BuildError("目标平台列表中的每一项都必须是非空字符串")
    else:
        raise BuildError("targets 必须是字符串数组或逗号分隔字符串")

    if not raw_targets:
        raise BuildError("至少需要指定一个构建目标")

    parsed: list[tuple[str, str]] = []
    for raw in raw_targets:
        if raw.count("/") != 1:
            raise BuildError(f"目标格式无效：{raw!r}（应为 goos/goarch）")
        goos, goarch = (part.strip() for part in raw.split("/", 1))
        if goos == "host" and goarch == "host":
            goos, goarch = host_goos, host_goarch
        if goos not in ALL_GOOS or goarch not in ALL_GOARCH:
            raise BuildError(f"不支持的构建目标：{raw!r}")
        parsed.append((goos, goarch))
    return parsed

def resolve_targets_for_mode(
    build_mode: str, target_values: Any, host_goos: str, host_goarch: str
) -> list[tuple[str, str]]:
    if build_mode not in {"single", "multi"}:
        raise BuildError("构建模式必须是 single 或 multi")
    if not target_values:
        if build_mode == "multi":
            raise BuildError("multi 模式至少需要一个构建目标")
        target_values = ["host/host"]

    targets = parse_targets(target_values, host_goos, host_goarch)
    if build_mode == "single" and len(targets) != 1:
        raise BuildError("single 模式必须且只能指定一个构建目标")
    return targets


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="构建并打包 Scardice-core（需要 Python 3.9+、Go、Git；发布构建还需要 pnpm）"
    )
    parser.add_argument(
        "--config-group",
        metavar="NAME",
        help="使用 build-config.json 中的配置组；指定后不显示交互提示",
    )
    return parser.parse_args(argv)


def run_command(
    args: list[str | Path],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    label: str,
    check: bool = True,
    capture: bool = False,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [str(arg) for arg in args]
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise BuildError(f"未找到命令 {command[0]!r}，无法{label}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"{label}超时") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() if capture else ""
        suffix = f"\n{detail}" if detail else ""
        raise BuildError(f"{label}失败（exit={result.returncode}）{suffix}")
    return result


def find_command(name: str) -> str | None:
    return shutil.which(name)


def get_host_target() -> tuple[str, str]:
    go = find_command("go")
    if not go:
        raise BuildError("未找到 Go 命令；请先安装 Go 并加入 PATH")
    result = run_command(
        [go, "env", "GOOS", "GOARCH"], label="读取 Go 主机构建目标", capture=True
    )
    values = result.stdout.splitlines()
    if len(values) < 2 or not values[0].strip() or not values[1].strip():
        raise BuildError("go env 未返回有效的 GOOS/GOARCH")
    return values[0].strip(), values[1].strip()


def read_default_version(root: Path = ROOT_DIR) -> str:
    version_file = root / "dice" / "version.go"
    if version_file.is_file():
        content = version_file.read_text(encoding="utf-8")
        match = re.search(r'^\s*VERSION_MAIN\s*=\s*"([^"]*)"', content, re.MULTILINE)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return "1.6.1"


def build_metadata(root: Path = ROOT_DIR) -> str:
    date = datetime.datetime.now().strftime("%Y%m%d")
    git = find_command("git")
    if not git:
        return f"+{date}.nogit"
    result = run_command(
        [git, "rev-parse", "--short=7", "HEAD"],
        cwd=root,
        label="读取 Git 提交号",
        check=False,
        capture=True,
    )
    commit = result.stdout.strip() if result.returncode == 0 else ""
    return f"+{date}.{commit or 'nogit'}"


def _go_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _has_go_symbol(symbol: str, root: Path) -> bool:
    candidates = [root / "main.go"]
    dice_dir = root / "dice"
    if dice_dir.is_dir():
        candidates.extend(dice_dir.rglob("*.go"))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            if symbol in path.read_text(encoding="utf-8", errors="ignore"):
                return True
        except OSError:
            continue
    return False


def _read_key(path: Path, label: str) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        print(f"[Build] 警告：{label}不存在或不可读，跳过注入：{path}")
        return None
    if not raw:
        print(f"[Build] 警告：{label}为空，跳过注入：{path}")
        return None
    return "".join(raw.decode("utf-8", errors="ignore").split())


def build_linker_flags(settings: dict[str, Any], root: Path = ROOT_DIR) -> str:
    version_main = settings.get("version_main") or read_default_version(root)
    prerelease = settings["version_prerelease"]
    app_channel = settings["app_channel"]
    appname = settings["appname"]
    values = [
        f"Scardice-core/dice.VERSION_MAIN={version_main}",
        f"Scardice-core/dice.VERSION_PRERELEASE={prerelease}",
        f"Scardice-core/dice.VERSION_BUILD_METADATA={build_metadata(root)}",
        f"Scardice-core/dice.APP_CHANNEL={app_channel}",
        f"Scardice-core/dice.APPNAME={appname}",
    ]
    flags = ["-s", "-w"]
    if settings["compatible_names"]:
        values.append("main.LockFileName=sealdice-core.lock")
    for value in values:
        flags.extend(("-X", _go_string(value)))

    private_key_path = resolve_path(settings, "private_key_file", "signature/seal_trusted_private_key.pem", root)
    if private_key_path.is_file() and private_key_path.stat().st_size:
        encoded = base64.b64encode(private_key_path.read_bytes()).decode("ascii")
        if _has_go_symbol("SealTrustedClientPrivateKey", root):
            flags.extend(("-X", _go_string(f"Scardice-core/dice.SealTrustedClientPrivateKey=base64:{encoded}")))
            print("[Build] 已通过 ldflags 以 base64 形式注入可信客户端私钥")
        else:
            print("[Build] 警告：未找到 SealTrustedClientPrivateKey 符号，跳过私钥注入")
    else:
        print(f"[Build] 警告：可信私钥文件不存在或为空，跳过注入：{private_key_path}")

    sign_key_path = resolve_path(settings, "sign_key_file", "signature/seal_sign_private_key.bin", root)
    sign_key = _read_key(sign_key_path, "签名客户端私钥")
    if sign_key:
        if _has_go_symbol("SealSignClientPrivateKey", root):
            flags.extend(("-X", _go_string(f"Scardice-core/dice.SealSignClientPrivateKey={sign_key}")))
            print("[Build] 已通过 ldflags 注入签名客户端私钥")
        else:
            print("[Build] 警告：未找到 SealSignClientPrivateKey 符号，跳过注入")

    sign_url_path = resolve_path(settings, "sign_v3_url_file", "signature/SealSignV3Url", root)
    sign_url = _read_key(sign_url_path, "签名服务 V3 URL")
    if sign_url:
        if _has_go_symbol("SealSignV3Url", root):
            flags.extend(("-X", _go_string(f"Scardice-core/dice.SealSignV3Url={sign_url}")))
            print("[Build] 已通过 ldflags 注入 SealSignV3Url")
        else:
            print("[Build] 警告：未找到 SealSignV3Url 符号，跳过注入")

    return " ".join(flags)


def resolve_path(
    settings: dict[str, Any], key: str, default: str, root: Path = ROOT_DIR
) -> Path:
    raw = settings.get(key, default)
    path = Path(raw).expanduser()
    return path if path.is_absolute() else root / path


def _yes_no(prompt: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        try:
            value = input(f"{prompt} [{suffix}]: ").strip().lower()
        except EOFError as exc:
            raise BuildError("交互输入已结束；在非交互环境请使用 --config-group") from exc
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("请输入 y 或 n。")


def _text_value(prompt: str, default: str) -> str:
    try:
        value = input(f"{prompt}（默认：{default}）: ").strip()
    except EOFError as exc:
        raise BuildError("交互输入已结束；在非交互环境请使用 --config-group") from exc
    return value or default


def _menu_value(prompt: str, options: tuple[str, ...], default: str) -> str:
    print(prompt)
    for index, value in enumerate(options, 1):
        marker = "（本机）" if value == default else ""
        print(f"  {index}) {value}{marker}")
    while True:
        try:
            selected = input(f"请选择 [1-{len(options)}]（默认：{default}）: ").strip()
        except EOFError as exc:
            raise BuildError("交互输入已结束；在非交互环境请使用 --config-group") from exc
        if not selected:
            return default
        if selected.isdigit() and 1 <= int(selected) <= len(options):
            return options[int(selected) - 1]
        print(f"输入无效，请输入 1-{len(options)} 的数字。")


def _runtime_cache_file(cache_dir: Path, asset: str, goos: str, goarch: str) -> Path:
    target = f"{goos}-{goarch}"
    if asset == "lagrange":
        return cache_dir / f"Lagrange.OneBot.{target}.zip"
    if asset == "milky":
        suffix = ".exe" if goos == "windows" else ""
        return cache_dir / f"lagrangeV2.{target}{suffix}"
    return cache_dir / f"yogurt.{target}.zip"


def _asset_url(asset: str, goos: str, goarch: str) -> str | None:
    target = f"{goos}/{goarch}"
    lagrange = {
        "linux/arm64": "https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_linux-arm64_8.0.zip?v=3",
        "linux/amd64": "https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_linux-x64_8.0.zip?v=3",
        "windows/amd64": "https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_win-x64_8.0.zip?v=3",
        "windows/386": "https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_win-x86_8.0.zip?v=3",
        "darwin/arm64": "https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_osx-arm64_8.0.zip?v=3",
        "darwin/amd64": "https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_osx-x64_8.0.zip?v=3",
    }
    milky = {
        "linux/arm64": "https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-linux-arm64",
        "linux/amd64": "https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-linux-x64",
        "darwin/arm64": "https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-osx-arm64",
        "windows/amd64": "https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-win-x64.exe",
    }
    yogurt = {
        "linux/arm64": "https://github.com/sealdice/acidify/releases/download/dev/yogurt-linux-arm64.zip",
        "linux/amd64": "https://github.com/sealdice/acidify/releases/download/dev/yogurt-linux-x64.zip",
        "darwin/arm64": "https://github.com/sealdice/acidify/releases/download/dev/yogurt-macos-arm64.zip",
        "windows/amd64": "https://github.com/sealdice/acidify/releases/download/dev/yogurt-windows-x64.zip",
        "android/arm64": "https://github.com/sealdice/acidify/releases/download/dev/yogurt-android-arm64.zip",
    }
    return {"lagrange": lagrange, "milky": milky, "yogurt": yogurt}[asset].get(target)


def _cache_has_runtime_assets(cache_dir: Path, targets: list[tuple[str, str]]) -> bool:
    for goos, goarch in targets:
        for asset in ("lagrange", "milky"):
            if _asset_url(asset, goos, goarch):
                cached = _runtime_cache_file(cache_dir, asset, goos, goarch)
                if cached.is_file() and cached.stat().st_size:
                    return True
    return False


def interactive_settings(
    settings: dict[str, Any], host_goos: str, host_goarch: str, cache_dir: Path
) -> dict[str, Any]:
    settings = dict(settings)
    settings["version_main"] = _text_value(
        "请输入 VERSION_MAIN", settings.get("version_main") or read_default_version()
    )
    settings["version_prerelease"] = _text_value(
        "请输入 VERSION_PRERELEASE", settings.get("version_prerelease", "-dev")
    )
    settings["app_channel"] = _text_value(
        "请输入 APP_CHANNEL", settings.get("app_channel", "dev")
    )
    settings["appname"] = _text_value("请输入 APPNAME", settings.get("appname", "Scardice"))

    mode = settings.get("build_mode", "single")
    while True:
        mode = _text_value("请选择构建模式 [single/multi]，可输入 s/m", mode).lower()
        mode = {"s": "single", "m": "multi"}.get(mode, mode)
        if mode in {"single", "multi"}:
            break
        print("构建模式必须是 single 或 multi。")
    settings["build_mode"] = mode

    current_targets = settings.get("targets") or ["host/host"]
    default_targets = parse_targets(current_targets, host_goos, host_goarch)
    if mode == "single":
        default_goos, default_goarch = default_targets[0]
        goos = _menu_value("请选择目标 GOOS:", ALL_GOOS, default_goos)
        goarch = _menu_value("请选择目标 GOARCH:", ALL_GOARCH, default_goarch)
        settings["targets"] = [f"{goos}/{goarch}"]
    else:
        print("支持格式示例：linux/amd64,windows/amd64,linux/arm64")
        default_value = ",".join(f"{goos}/{goarch}" for goos, goarch in default_targets)
        value = _text_value("请输入 multi 目标（goos/goarch,...）", default_value)
        settings["targets"] = [part.strip() for part in value.split(",") if part.strip()]

    targets = parse_targets(settings["targets"], host_goos, host_goarch)
    if settings.get("pack_runtime_assets", True) and _cache_has_runtime_assets(cache_dir, targets):
        settings["redownload_runtime_assets"] = _yes_no(
            "是否重新下载内置客户端文件", bool(settings.get("redownload_runtime_assets"))
        )
    else:
        settings["redownload_runtime_assets"] = True

    settings["cgo"] = _yes_no("是否启用 CGO", bool(settings.get("cgo", False)))
    settings["compatible_names"] = _yes_no(
        "使用兼容的 lock 和可执行文件名", bool(settings.get("compatible_names", False))
    )
    upx = find_command("upx")
    if upx:
        upx_default = settings.get("upx")
        settings["upx"] = _yes_no(
            "是否使用 UPX 压缩二进制文件", True if upx_default is None else upx_default
        )
    else:
        print("[Build] 未找到 upx，将跳过压缩。")
        settings["upx"] = False
    return settings


def _env_integer(name: str, default: int, minimum: int = 0) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise BuildError(f"环境变量 {name} 必须是整数") from exc
    if parsed < minimum:
        raise BuildError(f"环境变量 {name} 不能小于 {minimum}")
    return parsed


def _env_switch(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if value.strip().lower() in {"0", "false", "no", "off"}:
        return False
    raise BuildError(f"环境变量 {name} 必须是 0/1 或 true/false")


def runtime_settings(settings: dict[str, Any]) -> dict[str, Any]:
    resolved = dict(settings)
    resolved["pack_runtime_assets"] = _env_switch(
        "PACK_RUNTIME_ASSETS", bool(resolved.get("pack_runtime_assets", True))
    )
    resolved["strict_runtime_assets"] = _env_switch(
        "RUNTIME_ASSETS_STRICT", bool(resolved.get("strict_runtime_assets", True))
    )
    resolved["download_retries"] = _env_integer("DOWNLOAD_RETRIES", 3, 1)
    resolved["download_max_time"] = _env_integer("DOWNLOAD_MAX_TIME", 600, 1)
    resolved["download_connect_timeout"] = _env_integer("DOWNLOAD_CONNECT_TIMEOUT", 15, 1)
    resolved["download_speed_limit"] = _env_integer("DOWNLOAD_SPEED_LIMIT", 10240, 0)
    resolved["download_speed_time"] = _env_integer("DOWNLOAD_SPEED_TIME", 30, 1)
    resolved["download_axel_timeout"] = _env_integer("DOWNLOAD_AXEL_TIMEOUT", 300, 1)
    resolved["runtime_axel_connections"] = _env_integer("RUNTIME_AXEL_CONNECTIONS", 8, 1)
    return resolved


def resolve_download_proxy() -> tuple[str | None, bool]:
    explicit = os.environ.get("BUILD_PROXY", "").strip()
    if explicit:
        return explicit, True
    for name in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "all_proxy", "https_proxy", "http_proxy"):
        value = os.environ.get(name, "").strip()
        if value:
            return value, False

    gsettings = find_command("gsettings")
    if gsettings:
        def read_setting(name: str) -> str:
            result = subprocess.run(
                [gsettings, "get", "org.gnome.system.proxy", name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return result.stdout.strip().strip("'") if result.returncode == 0 else ""

        if read_setting("mode") == "manual":
            for protocol in ("socks", "https", "http"):
                host = read_setting(f"{protocol} host")
                port = read_setting(f"{protocol} port")
                if host and port and port != "0":
                    scheme = "socks5h" if protocol == "socks" else "http"
                    return f"{scheme}://{host}:{port}", True
    return None, False


def _make_url_opener(proxy: str | None, explicit_proxy: bool) -> urllib.request.OpenerDirector:
    if explicit_proxy and proxy:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    return urllib.request.build_opener()


def _download_via_curl(
    url: str,
    destination: Path,
    proxy: str | None,
    settings: dict[str, Any],
    force_ipv4: bool,
) -> bool:
    curl = find_command("curl")
    if not curl:
        return False
    args: list[str | Path] = [
        curl,
        "-fsSL",
        "--retry",
        "1",
        "--connect-timeout",
        str(settings["download_connect_timeout"]),
        "--max-time",
        str(settings["download_max_time"]),
        "--speed-limit",
        str(settings["download_speed_limit"]),
        "--speed-time",
        str(settings["download_speed_time"]),
        "-o",
        destination,
    ]
    if proxy:
        args.extend(("-x", proxy))
    if force_ipv4:
        args.append("--ipv4")
    args.append(url)
    try:
        result = subprocess.run(
            [str(arg) for arg in args],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=settings["download_max_time"] + 5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and destination.is_file() and destination.stat().st_size > 0


def _download_via_python(
    url: str,
    destination: Path,
    opener: urllib.request.OpenerDirector,
    settings: dict[str, Any],
) -> None:
    started = time.monotonic()
    total = 0
    request = urllib.request.Request(url, headers={"User-Agent": "Scardice-build/1"})
    with opener.open(request, timeout=settings["download_connect_timeout"]) as response:
        with destination.open("wb") as output:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                output.write(chunk)
                total += len(chunk)
                elapsed = time.monotonic() - started
                if elapsed > settings["download_max_time"]:
                    raise TimeoutError("download exceeded maximum time")
                if (
                    settings["download_speed_limit"]
                    and elapsed >= settings["download_speed_time"]
                    and total / elapsed < settings["download_speed_limit"]
                ):
                    raise TimeoutError("download speed fell below configured limit")
    if total == 0:
        raise OSError("download returned an empty file")


def download_file_with_cache(
    url: str,
    destination: Path,
    label: str,
    settings: dict[str, Any],
    redownload: bool,
) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and destination.stat().st_size and not redownload:
        print(f"[Build] 使用缓存的 {label}：{destination}")
        return True
    if redownload and destination.is_file() and destination.stat().st_size:
        print(f"[Build] 已选择重新下载 {label}，忽略缓存：{destination}")

    proxy, explicit_proxy = resolve_download_proxy()
    if proxy:
        print("[Build] 下载将使用已配置的网络代理。")
    else:
        print("[Build] 未检测到下载代理，直连下载。")
    opener = _make_url_opener(proxy, explicit_proxy)
    temp_path = destination.with_name(f"{destination.name}.tmp-{os.getpid()}")
    temp_path.unlink(missing_ok=True)

    axel = find_command("axel") if not proxy else None
    if axel:
        print(f"[Build] 使用 axel 下载 {label}：{url}")
        try:
            result = subprocess.run(
                [
                    axel,
                    "-q",
                    "-a",
                    "-n",
                    str(settings["runtime_axel_connections"]),
                    "-o",
                    str(temp_path),
                    url,
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=settings["download_axel_timeout"],
            )
            if result.returncode == 0 and temp_path.is_file() and temp_path.stat().st_size:
                os.replace(temp_path, destination)
                Path(f"{temp_path}.st").unlink(missing_ok=True)
                Path(f"{destination}.stamp").touch()
                return True
            print(f"[Build] 警告：axel 下载 {label} 失败，回退到 Python 下载。")
        except (OSError, subprocess.TimeoutExpired):
            print(f"[Build] 警告：axel 下载 {label} 超时或不可用，回退到 Python 下载。")
        temp_path.unlink(missing_ok=True)
        Path(f"{temp_path}.st").unlink(missing_ok=True)

    last_error: Exception | None = None
    for attempt in range(1, settings["download_retries"] + 1):
        temp_path.unlink(missing_ok=True)
        try:
            print(f"[Build] 下载 {label}（第 {attempt}/{settings['download_retries']} 次）：{url}")
            if proxy and proxy.lower().startswith("socks"):
                if not _download_via_curl(url, temp_path, proxy, settings, attempt > 1):
                    raise OSError("SOCKS 代理下载需要可用的 curl 命令")
            elif attempt > 1 and find_command("curl"):
                if not _download_via_curl(url, temp_path, proxy, settings, True):
                    _download_via_python(url, temp_path, opener, settings)
            else:
                _download_via_python(url, temp_path, opener, settings)
            if not temp_path.is_file() or not temp_path.stat().st_size:
                raise OSError("download returned an empty file")
            os.replace(temp_path, destination)
            Path(f"{destination}.stamp").touch()
            return True
        except (OSError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            last_error = exc
            temp_path.unlink(missing_ok=True)
            print(f"[Build] 警告：下载 {label} 第 {attempt} 次失败：{exc}")
            if attempt < settings["download_retries"]:
                time.sleep(attempt * 2)

    temp_path.unlink(missing_ok=True)
    if destination.is_file() and destination.stat().st_size:
        print(f"[Build] 警告：刷新 {label} 失败，继续使用旧缓存：{destination}")
        return True
    print(f"[Build] 警告：下载 {label} 失败。")
    if last_error:
        print(f"[Build] 详情：{last_error}")
    return False


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with zipfile.ZipFile(archive) as zipped:
        for item in zipped.infolist():
            target = (destination / item.filename).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise BuildError(f"归档包含越界路径：{item.filename}") from exc
        zipped.extractall(destination)


def sync_cached_archive_dir(archive: Path, destination: Path, label: str) -> bool:
    stamp = Path(f"{destination}.stamp")
    if destination.is_dir() and stamp.is_file() and archive.stat().st_mtime < stamp.stat().st_mtime:
        return True
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="extract-", dir=destination.parent) as temp:
        extracted = Path(temp) / "contents"
        extracted.mkdir()
        try:
            _safe_extract_zip(archive, extracted)
        except (OSError, zipfile.BadZipFile, BuildError) as exc:
            print(f"[Build] 警告：解压 {label} 失败：{exc}")
            return False
        if destination.exists():
            shutil.rmtree(destination)
        extracted.rename(destination)
    stamp.touch()
    return True


def sync_cached_file_dir(source: Path, destination: Path, destination_name: str, label: str) -> bool:
    stamp = Path(f"{destination}.stamp")
    target = destination / destination_name
    if destination.is_dir() and target.is_file() and stamp.is_file() and source.stat().st_mtime < stamp.stat().st_mtime:
        return True
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    stamp.touch()
    print(f"[Build] 已准备 {label}：{target}")
    return True


def prepare_target_runtime_assets(
    goos: str, goarch: str, cache_dir: Path, settings: dict[str, Any]
) -> dict[str, Path | None]:
    assets: dict[str, Path | None] = {"lagrange": None, "milky": None, "yogurt": None}
    if not settings["pack_runtime_assets"]:
        return assets

    cache_dir.mkdir(parents=True, exist_ok=True)
    target = f"{goos}-{goarch}"
    for name in ("lagrange", "milky", "yogurt"):
        url = _asset_url(name, goos, goarch)
        if not url:
            print(f"[Build] 提示：{goos}/{goarch} 没有可用的 {name} 打包资源，跳过。")
            continue
        cached = _runtime_cache_file(cache_dir, name, goos, goarch)
        label = f"{name.capitalize()} {goos}/{goarch}"
        if not download_file_with_cache(
            url, cached, label, settings, bool(settings.get("redownload_runtime_assets"))
        ):
            if settings["strict_runtime_assets"]:
                raise BuildError(f"无法准备 {label}")
            continue

        if name in {"lagrange", "yogurt"}:
            extracted = cache_dir / f"{name}.{target}"
            if not sync_cached_archive_dir(cached, extracted, label):
                if settings["strict_runtime_assets"]:
                    raise BuildError(f"无法解压 {label}")
                continue
            if name == "yogurt":
                old_name = extracted / "yogurt.kexe"
                final_name = "yogurt.exe" if goos == "windows" else "yogurt"
                final_path = extracted / final_name
                if not final_path.is_file() and old_name.is_file():
                    old_name.replace(final_path)
            assets[name] = extracted
        else:
            extracted = cache_dir / f"milky.{target}"
            source_name = "lagrangeV2.exe" if goos == "windows" else "lagrangeV2"
            if not sync_cached_file_dir(cached, extracted, source_name, label):
                if settings["strict_runtime_assets"]:
                    raise BuildError(f"无法准备 {label}")
                continue
            assets[name] = extracted
    return assets


def _copy_runtime_tree(source: Path | None, destination: Path, label: str) -> None:
    if source is None:
        return
    if not source.exists():
        print(f"[Build] 警告：{label}资源不存在，跳过：{source}")
        return
    destination.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        for child in source.iterdir():
            target = destination / child.name
            if child.is_dir():
                shutil.copytree(child, target, dirs_exist_ok=True)
            else:
                shutil.copy2(child, target)
    else:
        shutil.copy2(source, destination / source.name)
    print(f"[Build] 已打包 {label}：{destination}")


def _check_command(name: str, hint: str) -> None:
    if not find_command(name):
        raise BuildError(f"启用 CGO 构建需要命令 {name!r}，但未找到。建议安装：{hint}")


def cross_compiler(goos: str, goarch: str, host_goos: str, host_goarch: str, cgo: bool) -> str | None:
    if not cgo or (goos == host_goos and goarch == host_goarch):
        return None
    if goos == "windows" and host_goos == "windows":
        return None
    if goos == "windows" and goarch == "amd64":
        return "x86_64-w64-mingw32-gcc"
    if goos == "windows" and goarch == "386":
        return "i686-w64-mingw32-gcc"
    if goos == "linux" and goarch == "arm64" and (host_goos, host_goarch) != ("linux", "arm64"):
        return next(
            (name for name in ("aarch64-linux-musl-gcc", "aarch64-linux-gnu-gcc") if find_command(name)),
            None,
        )
    if goos == "linux" and goarch == "amd64" and (host_goos, host_goarch) != ("linux", "amd64"):
        return next(
            (name for name in ("x86_64-linux-gnu-gcc", "musl-gcc") if find_command(name)),
            None,
        )
    return None


def check_cgo_dependencies(
    targets: list[tuple[str, str]], host_goos: str, host_goarch: str, cgo: bool
) -> None:
    if not cgo:
        return
    for goos, goarch in targets:
        target = f"{goos}/{goarch}"
        if goos == "darwin" and host_goos != "darwin":
            raise BuildError(f"目标 {target} 启用 CGO 通常需要 macOS/osxcross 工具链；请关闭 CGO 或在 macOS 构建")
        if goos in {"freebsd", "openbsd", "netbsd"} and host_goos != goos:
            raise BuildError(f"目标 {target} 的 CGO 交叉工具链未内置支持；请关闭 CGO 或在目标系统构建")
        if (goos, goarch) == (host_goos, host_goarch) or (
            goos == "windows" and host_goos == "windows"
        ):
            candidates = [os.environ.get("CC", ""), "cc", "gcc", "clang"]
            if host_goos == "windows":
                candidates.extend(("cl.exe", "gcc.exe", "clang.exe"))
            if not any(candidate and find_command(candidate) for candidate in candidates):
                raise BuildError("启用 CGO 需要系统 C 编译器（cc/gcc/clang/cl.exe）")
            continue
        if goos == "windows" and goarch == "amd64":
            _check_command("x86_64-w64-mingw32-gcc", "mingw-w64")
        elif goos == "windows" and goarch == "386":
            _check_command("i686-w64-mingw32-gcc", "mingw-w64")
        elif goos == "windows" and goarch == "arm64":
            raise BuildError(f"目标 {target} 的 CGO 交叉工具链没有内置支持")
        elif goos == "linux" and goarch == "arm64":
            if not any(find_command(name) for name in ("aarch64-linux-musl-gcc", "aarch64-linux-gnu-gcc")):
                raise BuildError(f"目标 {target} 启用 CGO 需要 aarch64-linux-musl-gcc 或 aarch64-linux-gnu-gcc")
        elif goos == "linux" and goarch == "amd64":
            if not any(find_command(name) for name in ("x86_64-linux-gnu-gcc", "musl-gcc")):
                raise BuildError(f"目标 {target} 启用 CGO 需要 x86_64-linux-gnu-gcc 或 musl-gcc")


def go_build_environment(cache_dir: Path, goos: str, goarch: str, cgo: bool, cc: str | None) -> dict[str, str]:
    go_cache = cache_dir / "go-cache"
    go_temp = cache_dir / "tmp"
    go_cache.mkdir(parents=True, exist_ok=True)
    go_temp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.setdefault("GOCACHE", str(go_cache))
    env.setdefault("TMPDIR", str(go_temp))
    env.setdefault("TMP", str(go_temp))
    env.setdefault("TEMP", str(go_temp))
    env.update({"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "1" if cgo else "0"})
    if cc:
        env["CC"] = cc
    return env


def build_binary(
    output: Path,
    target: tuple[str, str],
    linker_flags: str,
    cache_dir: Path,
    cgo: bool,
    cc: str | None,
) -> None:
    goos, goarch = target
    go = find_command("go")
    if not go:
        raise BuildError("未找到 Go 命令；请先安装 Go 并加入 PATH")
    env = go_build_environment(cache_dir, goos, goarch, cgo, cc)
    print(f"[Build] 开始 go build: {goos}/{goarch}")
    if cc:
        print(f"[Build] 使用交叉编译器 CC={cc}")
    run_command(
        [go, "build", "-trimpath", "-ldflags", linker_flags, "-o", output, "."],
        cwd=ROOT_DIR,
        env=env,
        label=f"编译 {goos}/{goarch}",
    )


def update_submodules_and_sync_local_ui(ui_dir: Path) -> None:
    git = find_command("git")
    if not git:
        raise BuildError("发布构建需要 Git，但未找到 git 命令")
    print("[Build] 更新 submodule 到远端最新提交")
    remote_update = run_command(
        [git, "submodule", "update", "--init", "--recursive", "--remote"],
        cwd=ROOT_DIR,
        label="更新 submodule",
        check=False,
    )
    if remote_update.returncode == 0:
        return

    print("[Build] 警告：远端 submodule 更新失败，尝试使用本地已有提交")
    run_command(
        [git, "submodule", "update", "--init", "--recursive"],
        cwd=ROOT_DIR,
        label="恢复 submodule 当前提交",
        check=False,
    )

    candidates = (ROOT_DIR.parent / "Scardice-ui", Path.home() / "Scardice-ui")
    for local_ui in candidates:
        if not (local_ui / "package.json").is_file() or not (local_ui / ".git").exists():
            continue
        local_head = git_output(local_ui, "rev-parse", "HEAD")
        dirty = git_output(ui_dir, "status", "--porcelain", "--untracked-files=all")
        if not local_head:
            print("[Build] 警告：无法读取本地 UI 提交，跳过回退同步")
            break
        if dirty:
            print("[Build] UI 子模块有本地改动，跳过回退同步并保留工作区")
            break

        if not (ui_dir / ".git").exists():
            if ui_dir.exists() and any(ui_dir.iterdir()):
                print("[Build] UI 子模块目录含有文件但未初始化，跳过克隆以保护现有内容")
                break
            ui_dir.parent.mkdir(parents=True, exist_ok=True)
            cloned = run_command(
                [git, "clone", "--no-checkout", local_ui, ui_dir],
                cwd=ROOT_DIR,
                label="克隆本地 UI 仓库",
                check=False,
            )
            if cloned.returncode == 0:
                run_command(
                    [git, "checkout", local_head],
                    cwd=ui_dir,
                    label="切换本地 UI 提交",
                    check=False,
                )
            else:
                print("[Build] 无法克隆本地 UI 仓库，保留现有目录")
            break

        fetched = run_command(
            [git, "fetch", "--no-tags", local_ui, "+HEAD:refs/remotes/local-ui/HEAD"],
            cwd=ui_dir,
            label="获取本地 UI 提交",
            check=False,
            capture=True,
        )
        if fetched.returncode != 0:
            fetched = run_command(
                [git, "fetch", "--no-tags", local_ui, "HEAD"],
                cwd=ui_dir,
                label="获取本地 UI 提交",
                check=False,
                capture=True,
            )
        if fetched.returncode != 0:
            print("[Build] 无法读取本地 UI 提交，保留当前子模块内容")
            break

        local_head = git_output(local_ui, "rev-parse", "HEAD") or local_head
        current_head = git_output(ui_dir, "rev-parse", "HEAD")
        dirty = git_output(ui_dir, "status", "--porcelain", "--untracked-files=all")
        if dirty:
            print("[Build] UI 子模块在同步期间出现本地改动，跳过回退同步")
        elif not current_head or git_is_ancestor(ui_dir, current_head, local_head):
            print(f"[Build] 使用本地 UI 的前向提交同步 Scardice-ui：{local_ui} @ {local_head[:7]}")
            run_command(
                [git, "checkout", local_head], cwd=ui_dir, label="同步本地 UI 提交", check=False
            )
        elif git_is_ancestor(ui_dir, local_head, current_head):
            print("[Build] 本地 UI 提交不比子模块更新，跳过回退同步")
        else:
            print("[Build] 本地 UI 与子模块提交分叉，跳过回退同步")
        break


def git_output(cwd: Path, *args: str) -> str:
    git = find_command("git")
    if not git:
        return ""
    result = run_command(
        [git, "-C", cwd, *args], cwd=ROOT_DIR, label="读取 Git 状态", check=False, capture=True
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def git_is_ancestor(cwd: Path, ancestor: str, descendant: str) -> bool:
    git = find_command("git")
    if not git:
        return False
    result = run_command(
        [git, "-C", cwd, "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=ROOT_DIR,
        label="比较 Git 提交",
        check=False,
        capture=True,
    )
    return result.returncode == 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_ui(ui_dir: Path, cache_dir: Path) -> Path:
    package_json = ui_dir / "package.json"
    if not package_json.is_file():
        raise BuildError(f"未找到 UI 子模块目录或 package.json：{ui_dir}")
    git_commit = git_output(ui_dir, "rev-parse", "HEAD")
    if not git_commit:
        raise BuildError(f"无法读取 UI 提交号：{ui_dir}")
    lock_candidates = (ui_dir / "pnpm-lock.yaml", ui_dir / "package-lock.json", package_json)
    lock_file = next((path for path in lock_candidates if path.is_file()), None)
    if lock_file is None:
        raise BuildError(f"未找到 UI lockfile 或 package.json：{ui_dir}")
    expected = f"ui_commit={git_commit};lock_hash={sha256_file(lock_file)}"
    dirty = git_output(ui_dir, "status", "--porcelain", "--untracked-files=all")
    dist = ui_dir / "dist"
    marker_dir = cache_dir / "ui-build-markers"
    marker_name = hashlib.sha256(str(ui_dir.resolve()).encode("utf-8")).hexdigest()[:16]
    marker = marker_dir / f"{marker_name}.txt"

    if not dirty and dist.joinpath("index.html").is_file() and marker.is_file():
        if marker.read_text(encoding="utf-8").strip() == expected:
            print("[Build] Scardice-ui 已是最新构建，跳过构建")
            return dist

    print("[Build] 构建 Scardice-ui")
    pnpm = find_command("pnpm")
    if not pnpm:
        npm = find_command("npm")
        if not npm:
            raise BuildError("未找到 pnpm 或 npm，无法构建 UI")
        print("[Build] 未检测到 pnpm，正在通过 npm 全局安装 pnpm")
        run_command([npm, "install", "-g", "pnpm"], cwd=ui_dir, label="安装 pnpm")
        pnpm = find_command("pnpm")
    if not pnpm:
        raise BuildError("pnpm 安装完成后仍未找到 pnpm 命令")
    run_command([pnpm, "install", "--frozen-lockfile"], cwd=ui_dir, label="安装 UI 依赖")
    run_command([pnpm, "build"], cwd=ui_dir, label="构建 UI")
    if not dist.is_dir():
        raise BuildError(f"UI 构建完成但 dist 目录不存在：{dist}")
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker.write_text(expected + "\n", encoding="utf-8")
    return dist


@contextlib.contextmanager
def staged_frontend_assets(source: Path, destination: Path) -> Iterator[None]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".frontend-stage-", dir=destination.parent) as temp_dir:
        temp = Path(temp_dir)
        staged = temp / "staged"
        backup = destination.parent / f".{destination.name}.backup-{temp.name}"
        shutil.copytree(source, staged)
        had_original = destination.exists() or destination.is_symlink()
        moved_original = False
        installed_stage = False
        try:
            if had_original:
                destination.rename(backup)
                moved_original = True
            staged.rename(destination)
            installed_stage = True
            yield
        finally:
            if installed_stage and (destination.exists() or destination.is_symlink()):
                if destination.is_symlink() or destination.is_file():
                    destination.unlink()
                else:
                    shutil.rmtree(destination)
            if moved_original and backup.exists():
                try:
                    backup.rename(destination)
                except OSError as exc:
                    raise BuildError(
                        f"无法恢复原有前端目录；备份保留在 {backup}：{exc}"
                    ) from exc


def ensure_submodule_data(data_dir: Path) -> None:
    if not data_dir.is_dir():
        raise BuildError(f"未找到内置资源目录：{data_dir}")


def binary_name(goos: str, compatible: bool) -> str:
    stem = "sealdice-core" if compatible else "Scardice-core"
    return stem + (".exe" if goos == "windows" else "")


def _copy_builtin_data(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=True)
        else:
            shutil.copy2(child, target)


def _set_executable(path: Path) -> None:
    if path.is_file():
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _archive_zip(package_dir: Path, package_name: str, output: Path) -> None:
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            paths = [package_dir, *sorted(package_dir.rglob("*"))]
            for path in paths:
                relative = Path(package_name) / path.relative_to(package_dir) if path != package_dir else Path(package_name)
                arcname = relative.as_posix() + ("/" if path.is_dir() else "")
                archive.write(path, arcname=arcname, compress_type=zipfile.ZIP_DEFLATED)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def _archive_tar_gz(package_dir: Path, package_name: str, output: Path) -> None:
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            archive.add(package_dir, arcname=package_name)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def _upx_binary(binary: Path, enabled: bool) -> None:
    if not enabled:
        return
    upx = find_command("upx")
    if not upx:
        raise BuildError("配置启用了 UPX，但 PATH 中未找到 upx")
    print(f"[Build] 正在压缩二进制文件：{binary.name}")
    result = run_command([upx, "-q", binary], label="UPX 压缩", check=False, capture=True)
    if result.returncode != 0:
        print("[Build] 警告：UPX 压缩失败，跳过压缩。")


def build_development(
    settings: dict[str, Any],
    host: tuple[str, str],
    cache_dir: Path,
    linker_flags: str,
) -> Path:
    goos, goarch = host
    output_dir = resolve_path(settings, "dev_output_dir", "output/dev")
    env_output = os.environ.get("BUILD_DEV_OUTPUT_DIR")
    if env_output:
        output_dir = Path(env_output).expanduser()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    name = binary_name(goos, bool(settings["compatible_names"]))
    output = output_dir / name
    build_binary(output, host, linker_flags, cache_dir, bool(settings["cgo"]), None)
    if goos != "windows":
        _set_executable(output)
    print(f"[Build] 开发构建完成：{output} ({output.stat().st_size:,} bytes)")
    return output


def build_release(
    settings: dict[str, Any],
    targets: list[tuple[str, str]],
    host: tuple[str, str],
    cache_dir: Path,
    linker_flags: str,
) -> list[Path]:
    ui_dir = resolve_path(settings, "ui_submodule_dir", "Scardice-ui")
    builtins_dir = resolve_path(settings, "builtins_submodule_dir", "sealdice-builtins")
    static_frontend_dir = resolve_path(settings, "static_frontend_dir", "static/frontend")
    data_dir = builtins_dir / "data"
    if settings["update_submodules"]:
        update_submodules_and_sync_local_ui(ui_dir)
    if not (ui_dir / "package.json").is_file():
        raise BuildError(f"未找到 UI 子模块目录或 package.json：{ui_dir}")
    ensure_submodule_data(data_dir)
    ui_dist = prepare_ui(ui_dir, cache_dir)

    output_dir = resolve_path(settings, "output_dir", "output")
    env_output = os.environ.get("BUILD_OUTPUT_DIR")
    if env_output:
        output_dir = Path(env_output).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    package_work = cache_dir / "package-work"
    package_work.mkdir(parents=True, exist_ok=True)
    archives: list[Path] = []

    with staged_frontend_assets(ui_dist, static_frontend_dir):
        with tempfile.TemporaryDirectory(prefix="release-", dir=package_work) as work:
            work_dir = Path(work)
            for goos, goarch in targets:
                target = f"{goos}-{goarch}"
                target_work = work_dir / target
                target_work.mkdir(parents=True, exist_ok=True)
                name = binary_name(goos, bool(settings["compatible_names"]))
                binary = target_work / name
                cc = cross_compiler(goos, goarch, host[0], host[1], bool(settings["cgo"]))
                build_binary(binary, (goos, goarch), linker_flags, cache_dir, bool(settings["cgo"]), cc)
                _upx_binary(binary, bool(settings["upx"]))

                package_name = f"Scardice_{settings['version_main']}{settings['version_prerelease']}_{goos}_{goarch}"
                package_dir = target_work / package_name
                _ensure_path_within(target_work, package_dir, "发布目录")
                package_dir.mkdir(parents=True)
                shutil.copy2(binary, package_dir / name)
                _copy_builtin_data(data_dir, package_dir / "data")
                assets = prepare_target_runtime_assets(goos, goarch, cache_dir / "runtime", settings)
                _copy_runtime_tree(assets["lagrange"], package_dir / "lagrange", f"Lagrange {target}")
                _copy_runtime_tree(assets["milky"], package_dir / "milky", f"Milky {target}")
                _copy_runtime_tree(assets["yogurt"], package_dir / "milky", f"Yogurt {target}")

                if goos != "windows":
                    _set_executable(package_dir / name)
                    for candidate in (
                        package_dir / "lagrange" / "Lagrange.OneBot",
                        package_dir / "milky" / "lagrangeV2",
                        package_dir / "milky" / "yogurt",
                    ):
                        _set_executable(candidate)

                extension = ".zip" if goos == "windows" else ".tar.gz"
                archive_path = output_dir / f"{package_name}{extension}"
                _ensure_path_within(output_dir, archive_path, "发布归档")
                print(f"[Build] 组装发布目录：{package_dir}")
                if goos == "windows":
                    _archive_zip(package_dir, package_name, archive_path)
                else:
                    _archive_tar_gz(package_dir, package_name, archive_path)
                archives.append(archive_path)

    print(f"[Build] 打包完成，共 {len(archives)} 个文件：")
    for archive in archives:
        print(f"  - {archive}")
    return archives


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        config = load_config(ROOT_DIR / "build-config.json")
        group_name, settings = resolve_config_group(config, args.config_group)
        host = get_host_target()
        if should_prompt_for_settings(args.config_group, sys.stdin.isatty()):
            cache_dir = resolve_path(settings, "build_cache_dir", ".build-cache")
            settings = interactive_settings(settings, host[0], host[1], cache_dir / "runtime")
        settings = runtime_settings(settings)
        settings["version_main"] = settings.get("version_main") or read_default_version()
        settings["appname"] = settings.get("appname", "Scardice")
        settings["version_prerelease"] = settings.get("version_prerelease", "-dev")
        settings["app_channel"] = settings.get("app_channel", "dev")
        _validate_version_component("version_main", settings["version_main"])
        _validate_version_component("version_prerelease", settings["version_prerelease"])
        settings["cgo"] = bool(settings.get("cgo", False))
        settings["compatible_names"] = bool(settings.get("compatible_names", False))
        settings["upx"] = bool(settings.get("upx", False))
        settings["development"] = bool(settings.get("development", False))
        settings["update_submodules"] = bool(settings.get("update_submodules", True))
        settings["redownload_runtime_assets"] = bool(settings.get("redownload_runtime_assets", False))
        mode = settings.get("build_mode", "single")
        targets = resolve_targets_for_mode(mode, settings.get("targets"), host[0], host[1])

        print(f"[Build] 配置组={group_name}")
        print(f"[Build] VERSION_MAIN={settings['version_main']}")
        print(f"[Build] VERSION_PRERELEASE={settings['version_prerelease']}")
        print(f"[Build] APP_CHANNEL={settings['app_channel']}")
        print(f"[Build] APPNAME={settings['appname']}")
        print(f"[Build] BUILD_MODE={mode}")
        print(f"[Build] TARGETS={', '.join(f'{goos}/{goarch}' for goos, goarch in targets)}")
        print(f"[Build] CGO_ENABLED={1 if settings['cgo'] else 0}")
        print(f"[Build] USE_COMPATIBLE_NAMES={int(settings['compatible_names'])}")
        print(f"[Build] LOCK_FILE_NAME={'sealdice-core.lock' if settings['compatible_names'] else 'Scardice-lock.lock'}")

        check_cgo_dependencies(targets, host[0], host[1], settings["cgo"])
        cache_dir = resolve_path(settings, "build_cache_dir", ".build-cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        linker_flags = build_linker_flags(settings)
        if settings["development"]:
            build_development(settings, host, cache_dir, linker_flags)
        else:
            build_release(settings, targets, host, cache_dir, linker_flags)
        return 0
    except BuildError as exc:
        print(f"[Build] 错误：{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[Build] 已取消。", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"[Build] 文件操作失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
