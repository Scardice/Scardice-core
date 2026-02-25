#!/usr/bin/env bash
set -euo pipefail

# QuickJS 构建校验脚本（modernc 版本）
# 用法：
#   1) 仅校验当前平台：
#      ./scripts/quickjs_build_check.sh native
#   2) 校验单个目标：
#      ./scripts/quickjs_build_check.sh target linux arm64
#   3) 校验预设矩阵：
#      ./scripts/quickjs_build_check.sh matrix

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
export GOCACHE="${GOCACHE:-/tmp/gocache}"

run_native() {
  echo "[quickjs-check] native: GOOS=$(go env GOOS) GOARCH=$(go env GOARCH)"
  go test -tags quickjs ./dice/jsengine/quickjs -count=1
  echo "[quickjs-check] native ok"
}

run_target() {
  local goos="$1"
  local goarch="$2"

  echo "[quickjs-check] target: ${goos}/${goarch}"

  GOOS="${goos}" GOARCH="${goarch}" \
  go test -c -tags quickjs ./dice/jsengine/quickjs >/dev/null
  rm -f quickjs.test
  echo "[quickjs-check] target ok: ${goos}/${goarch}"
}

run_matrix() {
  # Linux
  run_target linux amd64
  run_target linux arm64
  run_target windows amd64
  run_target windows arm64
  run_target darwin amd64
  run_target darwin arm64

  echo "[quickjs-check] matrix done"
}

main() {
  local mode="${1:-native}"
  case "${mode}" in
    native)
      run_native
      ;;
    target)
      if [[ $# -ne 3 ]]; then
        echo "usage: $0 target <goos> <goarch>"
        exit 2
      fi
      run_target "$2" "$3"
      ;;
    matrix)
      run_matrix
      ;;
    *)
      echo "usage: $0 [native|target|matrix]"
      exit 2
      ;;
  esac
}

main "$@"
