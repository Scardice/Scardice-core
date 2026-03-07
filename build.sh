#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

DEFAULT_VERSION_PRERELEASE="-dev"
DEFAULT_APP_CHANNEL="dev"
DEFAULT_APPNAME="Scardice"
PRIVATE_KEY_FILE="./signature/seal_trusted_private_key.pem"

read -r -p "请输入 VERSION_PRERELEASE（默认：${DEFAULT_VERSION_PRERELEASE}）: " VERSION_PRERELEASE
VERSION_PRERELEASE="${VERSION_PRERELEASE:-$DEFAULT_VERSION_PRERELEASE}"

read -r -p "请输入 APP_CHANNEL（默认：${DEFAULT_APP_CHANNEL}）: " APP_CHANNEL
APP_CHANNEL="${APP_CHANNEL:-$DEFAULT_APP_CHANNEL}"

read -r -p "请输入 APPNAME（默认：${DEFAULT_APPNAME}）: " APPNAME
APPNAME="${APPNAME:-$DEFAULT_APPNAME}"

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

if [[ "$(uname -s)" == "MINGW"* || "$(uname -s)" == "MSYS"* || "$(uname -s)" == "CYGWIN"* ]]; then
  BINARY_PATH="./Scardice-core.exe"
else
  BINARY_PATH="./Scardice-core"
fi

LDFLAGS="-s -w"
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

echo "[Build] VERSION_PRERELEASE=${VERSION_PRERELEASE}"
echo "[Build] VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
echo "[Build] APP_CHANNEL=${APP_CHANNEL}"
echo "[Build] APPNAME=${APPNAME}"
echo "[Build] CGO_ENABLED=${CGO_ENABLED_VALUE}"
echo "[Build] 输出文件：${BINARY_PATH}"

CGO_ENABLED="${CGO_ENABLED_VALUE}" go build -trimpath -ldflags "$LDFLAGS" -o "${BINARY_PATH}" .

echo "[Build] 完成"
