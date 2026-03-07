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

read -r -p "请输入 VERSION_MAIN（默认：${DEFAULT_VERSION_MAIN}）: " VERSION_MAIN
VERSION_MAIN="${VERSION_MAIN:-$DEFAULT_VERSION_MAIN}"

read -r -p "请输入 VERSION_PRERELEASE（默认：${DEFAULT_VERSION_PRERELEASE}）: " VERSION_PRERELEASE
VERSION_PRERELEASE="${VERSION_PRERELEASE:-$DEFAULT_VERSION_PRERELEASE}"

read -r -p "请输入 APP_CHANNEL（默认：${DEFAULT_APP_CHANNEL}）: " APP_CHANNEL
APP_CHANNEL="${APP_CHANNEL:-$DEFAULT_APP_CHANNEL}"

read -r -p "请输入 APPNAME（默认：${DEFAULT_APPNAME}）: " APPNAME
APPNAME="${APPNAME:-$DEFAULT_APPNAME}"

TARGET_GOOS="$(choose_from_menu "请选择目标 GOOS:" "${DEFAULT_TARGET_GOOS}" \
  linux windows darwin freebsd openbsd netbsd)"
TARGET_GOARCH="$(choose_from_menu "请选择目标 GOARCH:" "${DEFAULT_TARGET_GOARCH}" \
  amd64 arm64 386 arm ppc64le riscv64 s390x)"

read -r -p "是否启用 CGO？[y/N]: " ENABLE_CGO_INPUT
if [[ "${ENABLE_CGO_INPUT}" =~ ^[Yy]$ ]]; then
  CGO_ENABLED_VALUE=1
else
  CGO_ENABLED_VALUE=0
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

if [[ "${TARGET_GOOS}" == "windows" ]]; then
  BINARY_PATH="./Scardice-core-${TARGET_GOOS}-${TARGET_GOARCH}.exe"
else
  BINARY_PATH="./Scardice-core-${TARGET_GOOS}-${TARGET_GOARCH}"
fi

LDFLAGS="-s -w"
LDFLAGS+=" -X Scardice-core/dice.VERSION_MAIN=${VERSION_MAIN}"
LDFLAGS+=" -X Scardice-core/dice.VERSION_PRERELEASE=${VERSION_PRERELEASE}"
LDFLAGS+=" -X Scardice-core/dice.VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
LDFLAGS+=" -X Scardice-core/dice.APP_CHANNEL=${APP_CHANNEL}"
LDFLAGS+=" -X Scardice-core/dice.APPNAME=${APPNAME}"

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
echo "[Build] TARGET_GOOS=${TARGET_GOOS}"
echo "[Build] TARGET_GOARCH=${TARGET_GOARCH}"
echo "[Build] CGO_ENABLED=${CGO_ENABLED_VALUE}"
echo "[Build] 输出文件：${BINARY_PATH}"

GOOS="${TARGET_GOOS}" GOARCH="${TARGET_GOARCH}" CGO_ENABLED="${CGO_ENABLED_VALUE}" \
  go build -trimpath -ldflags "$LDFLAGS" -o "${BINARY_PATH}" .

echo "[Build] 完成"
