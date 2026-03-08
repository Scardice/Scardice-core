#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

DEFAULT_VERSION_PRERELEASE="-dev"
DEFAULT_APP_CHANNEL="dev"
DEFAULT_APPNAME="Scardice"
DEFAULT_VERSION_MAIN="$(sed -n 's/^[[:space:]]*VERSION_MAIN = \"\\([^\"]*\\)\".*/\\1/p' dice/version.go | head -n1)"
DEFAULT_VERSION_MAIN="${DEFAULT_VERSION_MAIN:-1.5.1}"
PRIVATE_KEY_FILE="./signature/seal_trusted_private_key.pem"
DEFAULT_TARGET_GOOS="$(go env GOOS)"
DEFAULT_TARGET_GOARCH="$(go env GOARCH)"
OUTPUT_DIR="$ROOT_DIR/output"
UI_SUBMODULE_DIR="$ROOT_DIR/Scardice-ui"
BUILTINS_SUBMODULE_DIR="$ROOT_DIR/sealdice-builtins"
STATIC_FRONTEND_DIR="$ROOT_DIR/static/frontend"
BUILD_CACHE_DIR="$ROOT_DIR/.build-cache"
GO_CACHE_DIR="$BUILD_CACHE_DIR/go-cache"
GO_TMP_DIR="$BUILD_CACHE_DIR/tmp"
UI_BUILD_MARKER="$UI_SUBMODULE_DIR/dist/.build-meta"
PACKAGE_WORK_DIR="$BUILD_CACHE_DIR/package-work"
ALL_GOOS=(linux windows darwin freebsd openbsd netbsd)
ALL_GOARCH=(amd64 arm64 386 arm ppc64le riscv64 s390x)
HOST_GOOS="$DEFAULT_TARGET_GOOS"
HOST_GOARCH="$DEFAULT_TARGET_GOARCH"

choose_from_menu() {
  local prompt="$1"
  local default_value="$2"
  shift 2
  local options=("$@")
  local count="${#options[@]}"
  local idx=1

  echo "${prompt}" >&2
  while [[ $idx -le $count ]]; do
    local val="${options[$((idx - 1))]}"
    if [[ "$val" == "$default_value" ]]; then
      echo "  ${idx}) ${val} (本机)" >&2
    else
      echo "  ${idx}) ${val}" >&2
    fi
    idx=$((idx + 1))
  done

  while true; do
    read -r -p "请选择 [1-${count}]（默认：${default_value}）: " selected
    if [[ -z "$selected" ]]; then
      echo "$default_value"
      return 0
    fi
    if [[ "$selected" =~ ^[0-9]+$ ]] && (( selected >= 1 && selected <= count )); then
      echo "${options[$((selected - 1))]}"
      return 0
    fi
    echo "输入无效，请输入 1-${count} 的数字。" >&2
  done
}

calc_file_hash() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
    return 0
  fi
  echo "nohash"
}

join_by_comma() {
  local IFS=", "
  echo "$*"
}

print_multi_target_guide() {
  echo "------ Multi Target Guide ------"
  echo "理论支持的平台: $(join_by_comma "${ALL_GOOS[@]}")"
  echo "理论支持的架构: $(join_by_comma "${ALL_GOARCH[@]}")"
  echo "理论上难以支持的组合:"
  echo "  - darwin/* (在非 macOS 主机且启用 CGO 时)"
  echo "  - freebsd/*、openbsd/*、netbsd/* (启用 CGO 的跨平台编译)"
  echo "  - windows/arm64 (常见环境缺少稳定可用的 CGO 交叉工具链)"
  echo "输入格式示例: linux/amd64,windows/amd64,linux/arm64"
  echo "-------------------------------"
}

validate_target_format() {
  local target="$1"
  local goos="${target%%/*}"
  local goarch="${target##*/}"
  local supported_os=0
  local supported_arch=0
  local i
  for i in "${ALL_GOOS[@]}"; do
    if [[ "$i" == "$goos" ]]; then
      supported_os=1
      break
    fi
  done
  for i in "${ALL_GOARCH[@]}"; do
    if [[ "$i" == "$goarch" ]]; then
      supported_arch=1
      break
    fi
  done
  if [[ $supported_os -ne 1 || $supported_arch -ne 1 ]]; then
    return 1
  fi
  return 0
}

require_command_or_exit() {
  local cmd="$1"
  local hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[Build] 错误：启用 CGO 构建需要命令 '$cmd'，但未找到。"
    echo "[Build] 建议安装：$hint"
    exit 1
  fi
}

check_cgo_dependency_or_exit() {
  local goos="$1"
  local goarch="$2"
  local target="${goos}/${goarch}"
  if [[ "${CGO_ENABLED_VALUE}" -ne 1 ]]; then
    return 0
  fi

  if [[ "$goos" == "darwin" && "$HOST_GOOS" != "darwin" ]]; then
    echo "[Build] 错误：目标 ${target} 启用 CGO 时通常需要 macOS/完整 osxcross 工具链。"
    echo "[Build] 建议改为关闭 CGO 或在 macOS 环境构建。"
    exit 1
  fi

  if [[ "$goos" == "freebsd" || "$goos" == "openbsd" || "$goos" == "netbsd" ]]; then
    if [[ "$HOST_GOOS" != "$goos" ]]; then
      echo "[Build] 错误：目标 ${target} 启用 CGO 的跨平台工具链未在脚本中内置支持。"
      echo "[Build] 建议改为关闭 CGO，或在对应系统上原生构建。"
      exit 1
    fi
  fi

  if [[ "$goos" == "$HOST_GOOS" && "$goarch" == "$HOST_GOARCH" ]]; then
    if command -v cc >/dev/null 2>&1; then
      return 0
    fi
    if command -v gcc >/dev/null 2>&1; then
      return 0
    fi
    if command -v clang >/dev/null 2>&1; then
      return 0
    fi
    echo "[Build] 错误：启用 CGO 需要系统 C 编译器（cc/gcc/clang）。"
    echo "[Build] 建议安装：build-essential 或 clang"
    exit 1
  fi

  if [[ "$goos" == "windows" && "$goarch" == "amd64" ]]; then
    require_command_or_exit "x86_64-w64-mingw32-gcc" "sudo apt-get install -y mingw-w64"
    return 0
  fi

  if [[ "$goos" == "windows" && "$goarch" == "386" ]]; then
    require_command_or_exit "i686-w64-mingw32-gcc" "sudo apt-get install -y mingw-w64"
    return 0
  fi

  if [[ "$goos" == "linux" && "$goarch" == "arm64" && ! ( "$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "arm64" ) ]]; then
    if command -v aarch64-linux-musl-gcc >/dev/null 2>&1 || command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      return 0
    fi
    echo "[Build] 错误：目标 ${target} 启用 CGO 需要 aarch64 交叉编译器。"
    echo "[Build] 建议安装：aarch64-linux-musl-gcc 或 aarch64-linux-gnu-gcc"
    exit 1
  fi

  if [[ "$goos" == "linux" && "$goarch" == "amd64" && ! ( "$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "amd64" ) ]]; then
    if command -v x86_64-linux-gnu-gcc >/dev/null 2>&1 || command -v musl-gcc >/dev/null 2>&1; then
      return 0
    fi
    echo "[Build] 错误：目标 ${target} 启用 CGO 需要 x86_64 Linux 交叉编译器。"
    echo "[Build] 建议安装：x86_64-linux-gnu-gcc 或 musl-gcc"
    exit 1
  fi
}

select_cc_for_target() {
  local goos="$1"
  local goarch="$2"

  if [[ "${CGO_ENABLED_VALUE}" -ne 1 ]]; then
    return 0
  fi

  if [[ "$goos" == "$HOST_GOOS" && "$goarch" == "$HOST_GOARCH" ]]; then
    echo ""
    return 0
  fi

  if [[ "$goos" == "windows" && "$goarch" == "amd64" ]]; then
    echo "x86_64-w64-mingw32-gcc"
    return 0
  fi

  if [[ "$goos" == "windows" && "$goarch" == "386" ]]; then
    echo "i686-w64-mingw32-gcc"
    return 0
  fi

  if [[ "$goos" == "linux" && "$goarch" == "arm64" && ! ( "$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "arm64" ) ]]; then
    if command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
      echo "aarch64-linux-musl-gcc"
      return 0
    fi
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      echo "aarch64-linux-gnu-gcc"
      return 0
    fi
  fi

  if [[ "$goos" == "linux" && "$goarch" == "amd64" && ! ( "$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "amd64" ) ]]; then
    if command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
      echo "x86_64-linux-gnu-gcc"
      return 0
    fi
    if command -v musl-gcc >/dev/null 2>&1; then
      echo "musl-gcc"
      return 0
    fi
  fi

  echo ""
}

pick_binary_name() {
  local goos="$1"
  if [[ $USE_COMPATIBLE_NAMES -eq 1 ]]; then
    if [[ "$goos" == "windows" ]]; then
      echo "sealdice-core.exe"
    else
      echo "sealdice-core"
    fi
  else
    if [[ "$goos" == "windows" ]]; then
      echo "Scardice-core.exe"
    else
      echo "Scardice-core"
    fi
  fi
}

read -r -p "请输入 VERSION_MAIN（默认：${DEFAULT_VERSION_MAIN}）: " VERSION_MAIN
VERSION_MAIN="${VERSION_MAIN:-$DEFAULT_VERSION_MAIN}"

read -r -p "请输入 VERSION_PRERELEASE（默认：${DEFAULT_VERSION_PRERELEASE}）: " VERSION_PRERELEASE
VERSION_PRERELEASE="${VERSION_PRERELEASE:-$DEFAULT_VERSION_PRERELEASE}"

read -r -p "请输入 APP_CHANNEL（默认：${DEFAULT_APP_CHANNEL}）: " APP_CHANNEL
APP_CHANNEL="${APP_CHANNEL:-$DEFAULT_APP_CHANNEL}"

read -r -p "请输入 APPNAME（默认：${DEFAULT_APPNAME}）: " APPNAME
APPNAME="${APPNAME:-$DEFAULT_APPNAME}"

read -r -p "请选择构建模式 [single/multi]（默认：single，可输入 s/m）: " BUILD_MODE_INPUT
BUILD_MODE_INPUT="${BUILD_MODE_INPUT:-single}"
case "${BUILD_MODE_INPUT}" in
  s|S)
    BUILD_MODE_INPUT="single"
    ;;
  m|M)
    BUILD_MODE_INPUT="multi"
    ;;
esac
if [[ "$BUILD_MODE_INPUT" != "single" && "$BUILD_MODE_INPUT" != "multi" ]]; then
  echo "[Build] 错误：构建模式必须是 single 或 multi"
  exit 1
fi

TARGETS=()
if [[ "$BUILD_MODE_INPUT" == "single" ]]; then
  TARGET_GOOS="$(choose_from_menu "请选择目标 GOOS:" "${DEFAULT_TARGET_GOOS}" "${ALL_GOOS[@]}")"
  TARGET_GOARCH="$(choose_from_menu "请选择目标 GOARCH:" "${DEFAULT_TARGET_GOARCH}" "${ALL_GOARCH[@]}")"
  TARGETS+=("${TARGET_GOOS}/${TARGET_GOARCH}")
else
  print_multi_target_guide
  read -r -p "请输入 multi 目标（goos/goarch,...）: " MULTI_TARGET_INPUT
  MULTI_TARGET_INPUT="${MULTI_TARGET_INPUT//[[:space:]]/}"
  if [[ -z "$MULTI_TARGET_INPUT" ]]; then
    echo "[Build] 错误：multi 模式至少需要一个目标"
    exit 1
  fi
  IFS=',' read -r -a RAW_TARGETS <<< "$MULTI_TARGET_INPUT"
  for target in "${RAW_TARGETS[@]}"; do
    if [[ "$target" != */* ]]; then
      echo "[Build] 错误：目标格式无效: $target（应为 goos/goarch）"
      exit 1
    fi
    if ! validate_target_format "$target"; then
      echo "[Build] 错误：目标不在理论支持列表内: $target"
      exit 1
    fi
    TARGETS+=("$target")
  done
fi

read -r -p "是否启用 CGO？[y/N]: " ENABLE_CGO_INPUT
if [[ "${ENABLE_CGO_INPUT}" =~ ^[Yy]$ ]]; then
  CGO_ENABLED_VALUE=1
else
  CGO_ENABLED_VALUE=0
fi

read -r -p "使用兼容的lock和可执行文件文件名？[y/N]: " COMPATIBLE_NAMES_INPUT
if [[ "${COMPATIBLE_NAMES_INPUT}" =~ ^[Yy]$ ]]; then
  USE_COMPATIBLE_NAMES=1
else
  USE_COMPATIBLE_NAMES=0
fi

if [[ "${CGO_ENABLED_VALUE}" -eq 1 ]]; then
  echo "[Build] 预检查 CGO 依赖..."
  for target in "${TARGETS[@]}"; do
    TARGET_GOOS="${target%%/*}"
    TARGET_GOARCH="${target##*/}"
    check_cgo_dependency_or_exit "$TARGET_GOOS" "$TARGET_GOARCH"
  done
fi

CUR_TIME="$(date +%Y%m%d)"
if GIT_HASH="$(git rev-parse --short=7 HEAD 2>/dev/null)"; then
  VERSION_BUILD_METADATA="+${CUR_TIME}.${GIT_HASH}"
else
  VERSION_BUILD_METADATA="+${CUR_TIME}.nogit"
fi

if [[ -s "$PRIVATE_KEY_FILE" ]]; then
  echo "[Build] 已找到私钥文件：$PRIVATE_KEY_FILE"
else
  echo "[Build] 错误：私钥文件不存在或为空：$PRIVATE_KEY_FILE"
  exit 1
fi

PRIVATE_KEY_CONTENT="$(cat "$PRIVATE_KEY_FILE")"
PRIVATE_KEY_CONTENT_ESCAPED="${PRIVATE_KEY_CONTENT//$'\n'/\\n}"

LDFLAGS="-s -w"
LDFLAGS+=" -X Scardice-core/dice.VERSION_MAIN=${VERSION_MAIN}"
LDFLAGS+=" -X Scardice-core/dice.VERSION_PRERELEASE=${VERSION_PRERELEASE}"
LDFLAGS+=" -X Scardice-core/dice.VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
LDFLAGS+=" -X Scardice-core/dice.APP_CHANNEL=${APP_CHANNEL}"
LDFLAGS+=" -X Scardice-core/dice.APPNAME=${APPNAME}"
if [[ $USE_COMPATIBLE_NAMES -eq 1 ]]; then
  LDFLAGS+=" -X main.LockFileName=sealdice-core.lock"
fi

if rg -q "SealTrustedClientPrivateKey" ./dice ./main.go 2>/dev/null; then
  LDFLAGS+=" -X 'Scardice-core/dice.SealTrustedClientPrivateKey=${PRIVATE_KEY_CONTENT_ESCAPED}'"
  echo "[Build] 已通过 ldflags 注入私钥"
else
  echo "[Build] 警告：未找到 SealTrustedClientPrivateKey 符号，跳过 ldflags 私钥注入"
fi

echo "[Build] VERSION_MAIN=${VERSION_MAIN}"
echo "[Build] VERSION_PRERELEASE=${VERSION_PRERELEASE}"
echo "[Build] VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
echo "[Build] APP_CHANNEL=${APP_CHANNEL}"
echo "[Build] APPNAME=${APPNAME}"
echo "[Build] BUILD_MODE=${BUILD_MODE_INPUT}"
echo "[Build] TARGETS=$(join_by_comma "${TARGETS[@]}")"
echo "[Build] CGO_ENABLED=${CGO_ENABLED_VALUE}"
echo "[Build] USE_COMPATIBLE_NAMES=${USE_COMPATIBLE_NAMES}"
if [[ $USE_COMPATIBLE_NAMES -eq 1 ]]; then
  echo "[Build] LOCK_FILE_NAME=sealdice-core.lock"
else
  echo "[Build] LOCK_FILE_NAME=Scardice-lock.lock"
fi

mkdir -p "$GO_CACHE_DIR" "$GO_TMP_DIR"
export GOCACHE="${GOCACHE:-$GO_CACHE_DIR}"
export TMPDIR="${TMPDIR:-$GO_TMP_DIR}"
echo "[Build] GOCACHE=${GOCACHE}"
echo "[Build] TMPDIR=${TMPDIR}"

echo "[Build] 更新 submodule 到远端最新提交"
git submodule update --init --recursive --remote

if [[ ! -f "$UI_SUBMODULE_DIR/package.json" ]]; then
  echo "[Build] 错误：未找到 UI 子模块目录或 package.json：$UI_SUBMODULE_DIR"
  exit 1
fi

if [[ ! -d "$BUILTINS_SUBMODULE_DIR/data" ]]; then
  echo "[Build] 错误：未找到内置资源目录：$BUILTINS_SUBMODULE_DIR/data"
  exit 1
fi

UI_COMMIT="$(git -C "$UI_SUBMODULE_DIR" rev-parse HEAD)"
if [[ -f "$UI_SUBMODULE_DIR/pnpm-lock.yaml" ]]; then
  UI_LOCK_HASH="$(calc_file_hash "$UI_SUBMODULE_DIR/pnpm-lock.yaml")"
elif [[ -f "$UI_SUBMODULE_DIR/package-lock.json" ]]; then
  UI_LOCK_HASH="$(calc_file_hash "$UI_SUBMODULE_DIR/package-lock.json")"
else
  UI_LOCK_HASH="$(calc_file_hash "$UI_SUBMODULE_DIR/package.json")"
fi

UI_MARKER_EXPECTED="ui_commit=${UI_COMMIT};lock_hash=${UI_LOCK_HASH}"
UI_BUILD_NEEDED=1
if [[ -f "$UI_BUILD_MARKER" && -f "$UI_SUBMODULE_DIR/dist/index.html" ]]; then
  UI_MARKER_CURRENT="$(cat "$UI_BUILD_MARKER" 2>/dev/null || true)"
  if [[ "$UI_MARKER_CURRENT" == "$UI_MARKER_EXPECTED" ]]; then
    UI_BUILD_NEEDED=0
  fi
fi

if [[ $UI_BUILD_NEEDED -eq 0 ]]; then
  echo "[Build] Scardice-ui 已是最新构建，跳过构建"
else
  echo "[Build] 构建 Scardice-ui"
  if ! command -v pnpm >/dev/null 2>&1; then
    if command -v npm >/dev/null 2>&1; then
      echo "[Build] 未检测到 pnpm，正在通过 npm 全局安装 pnpm"
      npm install -g pnpm
    else
      echo "[Build] 错误：未找到 pnpm 或 npm，无法构建 UI"
      exit 1
    fi
  fi

  if command -v pnpm >/dev/null 2>&1; then
    (
      cd "$UI_SUBMODULE_DIR"
      pnpm install --frozen-lockfile
      pnpm build
    )
  else
    echo "[Build] 错误：未找到 pnpm 或 npm，无法构建 UI"
    exit 1
  fi

  if [[ ! -d "$UI_SUBMODULE_DIR/dist" ]]; then
    echo "[Build] 错误：UI 构建完成但 dist 目录不存在：$UI_SUBMODULE_DIR/dist"
    exit 1
  fi
  echo "$UI_MARKER_EXPECTED" > "$UI_BUILD_MARKER"
fi

echo "[Build] 同步 UI 资源到 static/frontend"
rm -rf "$STATIC_FRONTEND_DIR"
mkdir -p "$STATIC_FRONTEND_DIR"
cp -a "$UI_SUBMODULE_DIR/dist/." "$STATIC_FRONTEND_DIR/"

mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_DIR"/*
rm -rf "$PACKAGE_WORK_DIR"
mkdir -p "$PACKAGE_WORK_DIR"

ARCHIVES=()
for target in "${TARGETS[@]}"; do
  TARGET_GOOS="${target%%/*}"
  TARGET_GOARCH="${target##*/}"

  BINARY_NAME="$(pick_binary_name "$TARGET_GOOS")"
  TARGET_WORK_DIR="$PACKAGE_WORK_DIR/${TARGET_GOOS}-${TARGET_GOARCH}"
  BINARY_PATH="$TARGET_WORK_DIR/$BINARY_NAME"
  PACKAGE_BASENAME="Scardice_${VERSION_MAIN}${VERSION_PRERELEASE}_${TARGET_GOOS}_${TARGET_GOARCH}"
  PACKAGE_DIR="$TARGET_WORK_DIR/${PACKAGE_BASENAME}"
  CC_VALUE="$(select_cc_for_target "$TARGET_GOOS" "$TARGET_GOARCH")"

  echo "[Build] 开始 go build: ${target}"
  rm -rf "$TARGET_WORK_DIR"
  mkdir -p "$TARGET_WORK_DIR"
  if [[ -n "$CC_VALUE" ]]; then
    echo "[Build] 使用交叉编译器 CC=${CC_VALUE}"
    GOOS="${TARGET_GOOS}" GOARCH="${TARGET_GOARCH}" CGO_ENABLED="${CGO_ENABLED_VALUE}" CC="${CC_VALUE}" \
      go build -trimpath -ldflags "$LDFLAGS" -o "${BINARY_PATH}" .
  else
    GOOS="${TARGET_GOOS}" GOARCH="${TARGET_GOARCH}" CGO_ENABLED="${CGO_ENABLED_VALUE}" \
      go build -trimpath -ldflags "$LDFLAGS" -o "${BINARY_PATH}" .
  fi

  echo "[Build] 组装发布目录：${PACKAGE_DIR}"
  rm -rf "$PACKAGE_DIR"
  mkdir -p "$PACKAGE_DIR/data"
  cp -a "$BINARY_PATH" "$PACKAGE_DIR/$BINARY_NAME"
  cp -a "$BUILTINS_SUBMODULE_DIR/data/." "$PACKAGE_DIR/data/"

  if [[ "${TARGET_GOOS}" == "windows" ]]; then
    ARCHIVE_PATH="$OUTPUT_DIR/${PACKAGE_BASENAME}.zip"
    rm -f "$ARCHIVE_PATH"
    (
      cd "$TARGET_WORK_DIR"
      zip -rq "$(basename "$ARCHIVE_PATH")" "$PACKAGE_BASENAME"
      mv "$(basename "$ARCHIVE_PATH")" "$ARCHIVE_PATH"
    )
  else
    ARCHIVE_PATH="$OUTPUT_DIR/${PACKAGE_BASENAME}.tar.gz"
    rm -f "$ARCHIVE_PATH"
    (
      cd "$TARGET_WORK_DIR"
      tar -zcf "$(basename "$ARCHIVE_PATH")" "$PACKAGE_BASENAME"
      mv "$(basename "$ARCHIVE_PATH")" "$ARCHIVE_PATH"
    )
  fi
  ARCHIVES+=("$ARCHIVE_PATH")
done

rm -rf "$PACKAGE_WORK_DIR"
echo "[Build] 打包完成，共 ${#ARCHIVES[@]} 个文件："
for archive in "${ARCHIVES[@]}"; do
  echo "  - ${archive}"
done
