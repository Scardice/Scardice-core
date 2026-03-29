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
SIGN_KEY_FILE="./signature/seal_sign_private_key.bin"
ANDROID_PROJECT_DIR_PRIMARY="$(dirname "$ROOT_DIR")/Scardice-android"
ANDROID_PROJECT_DIR_SECONDARY="$ROOT_DIR/Scardice-android"
ANDROID_SIGNING_ENV_FILE="$ROOT_DIR/signature/github-secrets.env"
ANDROID_KEYSTORE_FILE="$ROOT_DIR/signature/scardice-android-release.jks"
ANDROID_APK_OUTPUT_DIR=""
ANDROID_PACKAGE_BASENAME=""
ANDROID_APP_RUNNER_ARCHIVE="${ANDROID_APP_RUNNER_ARCHIVE:-}"
ANDROID_LAGRANGE_DIR="${ANDROID_LAGRANGE_DIR:-}"
ANDROID_MILKY_DIR="${ANDROID_MILKY_DIR:-}"
ANDROID_GOCQ_LAGRANGE_DIR="${ANDROID_GOCQ_LAGRANGE_DIR:-}"
ANDROID_RUNTIME_CACHE_DIR=""
ANDROID_RUNTIME_CACHE_TTL_SECONDS="${ANDROID_RUNTIME_CACHE_TTL_SECONDS:-86400}"
ANDROID_AXEL_CONNECTIONS="${ANDROID_AXEL_CONNECTIONS:-8}"
ANDROID_JAVA_API_BASE_URL="${ANDROID_JAVA_API_BASE_URL:-https://api.adoptium.net/v3/binary/latest/17/ga}"
ANDROID_JAVA_HOME="${ANDROID_JAVA_HOME:-}"
ANDROID_NDK_BASE_URL="${ANDROID_NDK_BASE_URL:-https://dl.google.com/android/repository}"
ANDROID_CMDLINE_TOOLS_URL="${ANDROID_CMDLINE_TOOLS_URL:-https://dl.google.com/android/repository/commandlinetools-linux-14742923_latest.zip}"
ANDROID_ACRA_URL="${ANDROID_ACRA_URL:-}"
ANDROID_ACRA_BASIC_AUTH="${ANDROID_ACRA_BASIC_AUTH:-}"
ANDROID_ACRA_LOGIN_PASS="${ANDROID_ACRA_LOGIN_PASS:-}"
ANDROID_APP_RUNNER_URL="https://d1.sealdice.com/lagrange/app-runner-std-arm64.tar.gz"
ANDROID_LAGRANGE_URL="https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_linux-musl-arm64_8.0.zip?v=3"
ANDROID_MILKY_URL="https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-linux-arm64"
ANDROID_GOCQ_LAGRANGE_URL="https://d1.sealdice.com/go-cqhttp-largrange/0.0.3/lagrange-gocq_android_arm64.zip"
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
		if [[ "$selected" =~ ^[0-9]+$ ]] && ((selected >= 1 && selected <= count)); then
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

download_file_with_cache() {
	local url="$1"
	local destination="$2"
	local label="$3"
	local stamp_file="${destination}.stamp"
	local temp_path="${destination}.tmp.$$"
	local download_success=1

	mkdir -p "$(dirname "$destination")"
	if [[ -s "$destination" ]] && cache_entry_is_fresh "$destination" "$stamp_file"; then
		echo "[Build] 使用缓存的 ${label}：$destination" >&2
		return 0
	fi

	rm -f "$temp_path"
	if command -v axel >/dev/null 2>&1; then
		echo "[Build] 下载 ${label}（axel 优先）：$url" >&2
		if axel -q -a -n "$ANDROID_AXEL_CONNECTIONS" -o "$temp_path" "$url" >/dev/null 2>&1; then
			download_success=0
		else
			rm -f "$temp_path"
			echo "[Build] 警告：axel 下载 ${label} 失败，回退到 curl。" >&2
		fi
	fi

	if [[ $download_success -ne 0 ]]; then
		if command -v curl >/dev/null 2>&1; then
			echo "[Build] 下载 ${label}（curl 回退）：$url" >&2
			if curl -fsSL --retry 2 --connect-timeout 15 "$url" -o "$temp_path"; then
				download_success=0
			else
				rm -f "$temp_path"
			fi
		else
			echo "[Build] 警告：未找到 curl，无法作为 ${label} 的回退下载器。" >&2
		fi
	fi

	if [[ $download_success -eq 0 ]]; then
		mv -f "$temp_path" "$destination"
		mark_cache_entry_fresh "$stamp_file"
		return 0
	fi

	rm -f "$temp_path"
	if [[ -s "$destination" ]]; then
		echo "[Build] 警告：刷新 ${label} 失败，继续使用旧缓存：$destination" >&2
		return 0
	fi
	echo "[Build] 警告：下载 ${label} 失败，跳过自动获取。" >&2
	return 1
}

extract_archive_to_dir() {
	local archive_path="$1"
	local destination_dir="$2"
	local label="$3"

	rm -rf "$destination_dir"
	mkdir -p "$destination_dir"
	if command -v unzip >/dev/null 2>&1; then
		if unzip -oq "$archive_path" -d "$destination_dir"; then
			return 0
		fi
	fi
	if command -v bsdtar >/dev/null 2>&1; then
		if bsdtar -xf "$archive_path" -C "$destination_dir"; then
			return 0
		fi
	fi
	echo "[Build] 警告：解压 ${label} 失败，需要 unzip 或 bsdtar。"
	return 1
}

mark_cache_entry_fresh() {
	local stamp_file="$1"
	mkdir -p "$(dirname "$stamp_file")"
	: >"$stamp_file"
}

cache_entry_is_fresh() {
	local cache_path="$1"
	local stamp_file="$2"
	local ttl="${ANDROID_RUNTIME_CACHE_TTL_SECONDS:-86400}"
	local now_ts stamp_ts

	if [[ ! -s "$cache_path" || ! -f "$stamp_file" ]]; then
		return 1
	fi
	if [[ ! "$ttl" =~ ^[0-9]+$ ]]; then
		return 1
	fi
	if ((ttl <= 0)); then
		return 1
	fi
	now_ts="$(date +%s)"
	stamp_ts="$(date -r "$stamp_file" +%s 2>/dev/null || echo 0)"
	((now_ts - stamp_ts < ttl))
}

sync_cached_archive_dir() {
	local archive_path="$1"
	local destination_dir="$2"
	local label="$3"
	local stamp_file="${destination_dir}.stamp"

	if [[ -d "$destination_dir" ]] && [[ -f "$stamp_file" ]] && [[ "$archive_path" -ot "$stamp_file" ]]; then
		return 0
	fi
	if extract_archive_to_dir "$archive_path" "$destination_dir" "$label"; then
		mark_cache_entry_fresh "$stamp_file"
		return 0
	fi
	return 1
}

sync_cached_file_dir() {
	local source_file="$1"
	local destination_dir="$2"
	local destination_name="$3"
	local label="$4"
	local stamp_file="${destination_dir}.stamp"

	if [[ -d "$destination_dir" ]] && [[ -f "$destination_dir/$destination_name" ]] && [[ -f "$stamp_file" ]] && [[ "$source_file" -ot "$stamp_file" ]]; then
		return 0
	fi
	rm -rf "$destination_dir"
	mkdir -p "$destination_dir"
	cp -f "$source_file" "$destination_dir/$destination_name"
	mark_cache_entry_fresh "$stamp_file"
}

resolve_android_version_name() {
	local git_short="${GIT_HASH:-nogit}"
	echo "dev-${CUR_TIME}.${git_short}"
}

prepare_android_optional_runtime_assets() {
	ANDROID_RUNTIME_CACHE_DIR="$BUILD_CACHE_DIR/android-runtime"
	mkdir -p "$ANDROID_RUNTIME_CACHE_DIR"

	if [[ -z "$ANDROID_APP_RUNNER_ARCHIVE" ]]; then
		local app_runner_path="$ANDROID_RUNTIME_CACHE_DIR/app-runner-arm64.tar.gz"
		if download_file_with_cache "$ANDROID_APP_RUNNER_URL" "$app_runner_path" "Android App Runner"; then
			ANDROID_APP_RUNNER_ARCHIVE="$app_runner_path"
		fi
	fi

	if [[ -z "$ANDROID_LAGRANGE_DIR" ]]; then
		local lagrange_zip="$ANDROID_RUNTIME_CACHE_DIR/Lagrange.OneBot.android-arm64.zip"
		local lagrange_dir="$ANDROID_RUNTIME_CACHE_DIR/lagrange.android-arm64"
		if download_file_with_cache "$ANDROID_LAGRANGE_URL" "$lagrange_zip" "Android Lagrange" && sync_cached_archive_dir "$lagrange_zip" "$lagrange_dir" "Android Lagrange"; then
			ANDROID_LAGRANGE_DIR="$lagrange_dir"
		fi
	fi

	if [[ -z "$ANDROID_MILKY_DIR" ]]; then
		local milky_bin="$ANDROID_RUNTIME_CACHE_DIR/milky.linux-arm64"
		local milky_dir="$ANDROID_RUNTIME_CACHE_DIR/milky.linux-arm64.dir"
		if download_file_with_cache "$ANDROID_MILKY_URL" "$milky_bin" "Android Milky"; then
			if sync_cached_file_dir "$milky_bin" "$milky_dir" "milky" "Android Milky"; then
				ANDROID_MILKY_DIR="$milky_dir"
			fi
		fi
	fi

	if [[ -z "$ANDROID_GOCQ_LAGRANGE_DIR" ]]; then
		local gocq_zip="$ANDROID_RUNTIME_CACHE_DIR/lagrange-gocq.android-arm64.zip"
		local gocq_dir="$ANDROID_RUNTIME_CACHE_DIR/lagrange-gocq.android-arm64"
		if download_file_with_cache "$ANDROID_GOCQ_LAGRANGE_URL" "$gocq_zip" "Android Gocq-Lagrange" && sync_cached_archive_dir "$gocq_zip" "$gocq_dir" "Android Gocq-Lagrange"; then
			ANDROID_GOCQ_LAGRANGE_DIR="$gocq_dir"
		fi
	fi
}

resolve_android_project_dir() {
	local candidate
	for candidate in "$ANDROID_PROJECT_DIR_PRIMARY" "$ANDROID_PROJECT_DIR_SECONDARY"; do
		if [[ -f "$candidate/gradlew" ]]; then
			echo "$candidate"
			return 0
		fi
	done

	echo ""
}

java_major_version() {
	local java_bin="$1"
	local version_output version_token major

	if [[ ! -x "$java_bin" ]]; then
		return 1
	fi
	version_output="$("$java_bin" -version 2>&1 | head -n1)" || return 1
	version_token="$(sed -n 's/.*version "\([^"]*\)".*/\1/p' <<<"$version_output")"
	if [[ -z "$version_token" ]]; then
		return 1
	fi
	major="${version_token%%.*}"
	if [[ "$major" == "1" ]]; then
		version_token="${version_token#1.}"
		major="${version_token%%.*}"
	fi
	if [[ ! "$major" =~ ^[0-9]+$ ]]; then
		return 1
	fi
	echo "$major"
}

find_android_java_home() {
	local candidate java_bin major
	local candidates=()

	if [[ -n "${ANDROID_JAVA_HOME:-}" ]]; then
		candidates+=("$ANDROID_JAVA_HOME")
	fi
	if [[ -n "${JAVA_HOME:-}" ]]; then
		candidates+=("$JAVA_HOME")
	fi
	candidates+=(
		"/usr/lib/jvm/java-17-openjdk"
		"/usr/lib/jvm/java-17-openjdk-amd64"
		"/usr/lib/jvm/java-17-openjdk-arm64"
		"/usr/lib/jvm/temurin-17-jdk"
		"/usr/lib/jvm/temurin-17"
	)

	for candidate in "${candidates[@]}"; do
		java_bin="$candidate/bin/java"
		major="$(java_major_version "$java_bin" || true)"
		if [[ "$major" == "17" ]]; then
			echo "$candidate"
			return 0
		fi
	done

	return 1
}

download_android_java_home() {
	local host_os host_arch archive_path extract_dir extracted_home download_url
	host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	host_arch="$(uname -m)"

	case "$host_arch" in
	x86_64 | amd64)
		host_arch="x64"
		;;
	aarch64 | arm64)
		host_arch="aarch64"
		;;
	*)
		echo "[Build] 错误：Android 构建暂不支持自动下载 JDK 的架构：$host_arch" >&2
		return 1
		;;
	esac

	if [[ "$host_os" != "linux" ]]; then
		echo "[Build] 错误：Android 构建暂不支持自动下载 JDK 的系统：$host_os" >&2
		return 1
	fi

	download_url="${ANDROID_JAVA_API_BASE_URL}/${host_os}/${host_arch}/jdk/hotspot/normal/eclipse"
	archive_path="$BUILD_CACHE_DIR/android-jdk/OpenJDK17U-jdk_${host_arch}_${host_os}_hotspot_latest.tar.gz"
	extract_dir="$BUILD_CACHE_DIR/android-jdk/jdk17-${host_os}-${host_arch}"

	if ! download_file_with_cache \
		"$download_url" \
		"$archive_path" \
		"Android JDK 17" >&2; then
		return 1
	fi

	if [[ ! -d "$extract_dir" || "$archive_path" -nt "$extract_dir/.stamp" ]]; then
		rm -rf "$extract_dir"
		mkdir -p "$extract_dir"
		if tar -xzf "$archive_path" -C "$extract_dir"; then
			mark_cache_entry_fresh "$extract_dir/.stamp"
		else
			echo "[Build] 错误：解压 Android JDK 17 失败：$archive_path" >&2
			return 1
		fi
	fi

	extracted_home="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n1)"
	if [[ -z "$extracted_home" || ! -x "$extracted_home/bin/java" ]]; then
		echo "[Build] 错误：Android JDK 17 内容无效：$extract_dir" >&2
		return 1
	fi

	echo "$extracted_home"
}

resolve_android_java_home() {
	local java_home=""
	local java_major=""

	java_home="$(find_android_java_home || true)"
	if [[ -n "$java_home" ]]; then
		echo "$java_home"
		return 0
	fi

	java_major="$(java_major_version "$(command -v java 2>/dev/null || true)" || true)"
	if [[ -n "$java_major" && "$java_major" -ne 17 ]]; then
		echo "[Build] 提示：当前默认 JDK 为 $java_major，Android 构建将改用 JDK 17。" >&2
	fi

	java_home="$(download_android_java_home)"
	if [[ -n "$java_home" ]]; then
		echo "$java_home"
		return 0
	fi

	return 1
}

find_android_sdk_dir() {
	local candidate
	local candidates=()

	if [[ -n "${ANDROID_HOME:-}" ]]; then
		candidates+=("$ANDROID_HOME")
	fi
	if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
		candidates+=("$ANDROID_SDK_ROOT")
	fi
	candidates+=(
		"$HOME/Android/Sdk"
		"$HOME/Android/sdk"
		"/opt/android-sdk"
		"/opt/android-sdk-linux"
		"/usr/lib/android-sdk"
		"/usr/local/android-sdk"
		"$HOME/Library/Android/sdk"
	)

	for candidate in "${candidates[@]}"; do
		if [[ -d "$candidate/platform-tools" || -d "$candidate/build-tools" || -d "$candidate/platforms" ]]; then
			echo "$candidate"
			return 0
		fi
	done

	return 1
}

download_android_cmdline_tools() {
	local sdk_root="$1"
	local archive_path="$BUILD_CACHE_DIR/android-sdk/commandlinetools-linux-latest.zip"
	local extract_dir="$BUILD_CACHE_DIR/android-sdk/cmdline-tools-extract"
	local install_dir="$sdk_root/cmdline-tools/latest"
	local extracted_dir=""

	if [[ -x "$install_dir/bin/sdkmanager" ]]; then
		echo "$install_dir/bin/sdkmanager"
		return 0
	fi

	if ! download_file_with_cache \
		"$ANDROID_CMDLINE_TOOLS_URL" \
		"$archive_path" \
		"Android Command-line Tools"; then
		return 1
	fi

	rm -rf "$extract_dir"
	mkdir -p "$extract_dir" "$install_dir"
	if command -v unzip >/dev/null 2>&1; then
		if ! unzip -oq "$archive_path" -d "$extract_dir"; then
			echo "[Build] 错误：解压 Android Command-line Tools 失败：$archive_path" >&2
			return 1
		fi
	elif command -v bsdtar >/dev/null 2>&1; then
		if ! bsdtar -xf "$archive_path" -C "$extract_dir"; then
			echo "[Build] 错误：解压 Android Command-line Tools 失败：$archive_path" >&2
			return 1
		fi
	else
		echo "[Build] 错误：解压 Android Command-line Tools 需要 unzip 或 bsdtar。" >&2
		return 1
	fi

	extracted_dir="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n1)"
	if [[ -z "$extracted_dir" || ! -d "$extracted_dir/bin" ]]; then
		echo "[Build] 错误：Android Command-line Tools 内容无效：$extract_dir" >&2
		return 1
	fi

	rm -rf "$install_dir"
	mkdir -p "$install_dir"
	cp -a "$extracted_dir"/. "$install_dir"/
	echo "$install_dir/bin/sdkmanager"
}

resolve_android_sdk_root() {
	local detected_sdk_dir
	local cached_sdk_dir="$BUILD_CACHE_DIR/android-sdk/sdk-root"

	detected_sdk_dir="$(find_android_sdk_dir || true)"
	if [[ -n "$detected_sdk_dir" ]]; then
		echo "$detected_sdk_dir"
		return 0
	fi

	mkdir -p "$cached_sdk_dir"
	echo "$cached_sdk_dir"
}

find_android_ndk_dir() {
	local required_version="${1:-}"
	local candidate candidate_version
	local candidates=()

	if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
		candidates+=("$ANDROID_NDK_HOME")
	fi
	if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
		candidates+=("$ANDROID_NDK_ROOT")
	fi
	candidates+=(
		"/opt/android-ndk"
		"/opt/android-ndk-r29"
	)

	for candidate in "${candidates[@]}"; do
		if [[ -x "$candidate/ndk-build" || -f "$candidate/source.properties" ]]; then
			if [[ -n "$required_version" ]]; then
				candidate_version="$(sed -n 's/^Pkg.Revision = //p' "$candidate/source.properties" 2>/dev/null | head -n1)"
				if [[ "$candidate_version" != "$required_version" ]]; then
					continue
				fi
			fi
			echo "$candidate"
			return 0
		fi
	done

	return 1
}

find_android_sdk_ndk_dir() {
	local sdk_dir="$1"
	local required_version="$2"
	local candidate="$sdk_dir/ndk/$required_version"

	if [[ -x "$candidate/ndk-build" || -f "$candidate/source.properties" ]]; then
		echo "$candidate"
		return 0
	fi

	return 1
}

resolve_android_required_ndk_version() {
	local project_dir="$1"
	sed -n "s/.*ndkVersion ['\"]\\([^'\"]*\\)['\"].*/\\1/p" "$project_dir/app/build.gradle" | head -n1
}

resolve_android_ndk_package_info() {
	local ndk_version="$1"
	local host_os host_arch release_name archive_name

	host_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	host_arch="$(uname -m)"

	case "$host_os" in
	linux)
		host_os="linux"
		;;
	*)
		echo "[Build] 错误：Android NDK 自动下载暂不支持当前系统：$host_os" >&2
		return 1
		;;
	esac

	case "$host_arch" in
	x86_64 | amd64)
		host_arch="linux"
		;;
	*)
		echo "[Build] 错误：Android NDK 自动下载暂不支持当前架构：$host_arch" >&2
		return 1
		;;
	esac

	case "$ndk_version" in
	25.2.9519653)
		release_name="r25c"
		;;
	*)
		echo "[Build] 错误：暂未内置 Android NDK $ndk_version 的下载映射。" >&2
		return 1
		;;
	esac

	archive_name="android-ndk-${release_name}-${host_os}.zip"
	printf '%s|%s\n' "$release_name" "$archive_name"
}

download_android_ndk_dir() {
	local ndk_version="$1"
	local package_info release_name archive_name archive_path extract_dir extracted_home

	package_info="$(resolve_android_ndk_package_info "$ndk_version")" || return 1
	release_name="${package_info%%|*}"
	archive_name="${package_info##*|}"
	archive_path="$BUILD_CACHE_DIR/android-ndk/$archive_name"
	extract_dir="$BUILD_CACHE_DIR/android-ndk/android-ndk-${release_name}"

	if ! download_file_with_cache \
		"$ANDROID_NDK_BASE_URL/$archive_name" \
		"$archive_path" \
		"Android NDK $ndk_version"; then
		return 1
	fi

	if [[ ! -d "$extract_dir" || "$archive_path" -nt "$extract_dir/.stamp" ]]; then
		rm -rf "$extract_dir"
		mkdir -p "$extract_dir"
		if command -v unzip >/dev/null 2>&1; then
			if ! unzip -oq "$archive_path" -d "$extract_dir"; then
				echo "[Build] 错误：解压 Android NDK 失败：$archive_path" >&2
				return 1
			fi
		elif command -v bsdtar >/dev/null 2>&1; then
			if ! bsdtar -xf "$archive_path" -C "$extract_dir"; then
				echo "[Build] 错误：解压 Android NDK 失败：$archive_path" >&2
				return 1
			fi
		else
			echo "[Build] 错误：解压 Android NDK 需要 unzip 或 bsdtar。" >&2
			return 1
		fi
		mark_cache_entry_fresh "$extract_dir/.stamp"
	fi

	extracted_home="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n1)"
	if [[ -z "$extracted_home" || ! -f "$extracted_home/source.properties" ]]; then
		echo "[Build] 错误：Android NDK 内容无效：$extract_dir" >&2
		return 1
	fi

	echo "$extracted_home"
}

write_android_local_properties() {
	local project_dir="$1"
	local sdk_dir="$2"
	local local_properties_path="$project_dir/local.properties"

	{
		echo "# Auto-generated by build-android.sh"
		echo "sdk.dir=$sdk_dir"
	} >"$local_properties_path"
}

ensure_android_sdk_component() {
	local sdk_dir="$1"
	local relative_path="$2"
	local label="$3"

	if [[ ! -e "$sdk_dir/$relative_path" ]]; then
		echo "[Build] 错误：缺少 Android SDK 组件 ${label}：$sdk_dir/$relative_path"
		return 1
	fi

	return 0
}

ensure_android_sdk_licenses() {
	local sdk_dir="$1"
	local license_dir="$sdk_dir/licenses"

	if [[ ! -d "$license_dir" ]]; then
		echo "[Build] 错误：缺少 Android SDK licenses 目录：$license_dir"
		echo "[Build] 请先接受 SDK 许可，或从已授权环境复制 licenses 目录。"
		return 1
	fi
	if [[ ! -s "$license_dir/android-sdk-license" ]]; then
		echo "[Build] 错误：缺少 Android SDK license 文件：$license_dir/android-sdk-license"
		echo "[Build] 请先接受 SDK 许可，或从已授权环境复制 licenses 目录。"
		return 1
	fi

	return 0
}

prepare_android_sdk() {
	local sdk_dir="$1"
	local sdkmanager_bin="$2"
	local licenses_ready=0

	mkdir -p "$sdk_dir"
	if ensure_android_sdk_licenses "$sdk_dir"; then
		licenses_ready=1
	fi
	if [[ $licenses_ready -ne 1 ]]; then
		echo "[Build] 自动接受 Android SDK licenses"
		if [[ "$sdk_dir" == "/opt/android-sdk" && -x "/opt/android-sdk/cmdline-tools/latest/bin/sdkmanager" ]]; then
			if ! yes | sudo /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null 2>&1; then
				echo "[Build] 错误：自动接受 Android SDK licenses 失败。"
				return 1
			fi
		else
			if ! yes | "$sdkmanager_bin" --sdk_root="$sdk_dir" --licenses >/dev/null 2>&1; then
				echo "[Build] 错误：自动接受 Android SDK licenses 失败。"
				return 1
			fi
		fi
	fi

	echo "[Build] 自动下载 Android SDK 组件：platforms;android-33, build-tools;33.0.1, platform-tools"
	if ! "$sdkmanager_bin" --sdk_root="$sdk_dir" \
		"platforms;android-33" \
		"build-tools;33.0.1" \
		"platform-tools"; then
		echo "[Build] 错误：自动下载 Android SDK 组件失败。"
		return 1
	fi

	return 0
}

copy_android_tree_if_present() {
	local src_path="$1"
	local dest_path="$2"
	local label="$3"

	if [[ -z "$src_path" ]]; then
		echo "[Build] 提示：未提供 ${label} 资源路径，跳过。"
		return 0
	fi
	if [[ ! -e "$src_path" ]]; then
		echo "[Build] 警告：${label} 资源不存在，跳过：$src_path"
		return 0
	fi

	mkdir -p "$dest_path"
	if [[ -d "$src_path" ]]; then
		cp -a "$src_path"/. "$dest_path"/
	else
		cp -a "$src_path" "$dest_path"/
	fi
}

ensure_android_auth_source() {
	local project_dir="$1"
	local auth_dir="$project_dir/app/src/main/java/com/sealdice/dice/secrets"
	local auth_file="$auth_dir/Auth.java"

	if [[ -f "$auth_file" ]]; then
		return 0
	fi

	mkdir -p "$auth_dir"
	cat >"$auth_file" <<EOF
package com.sealdice.dice.secrets;

public class Auth {
    public static String ACRA_URL = "${ANDROID_ACRA_URL}";
    public static String ACRA_BASIC_AUTH = "${ANDROID_ACRA_BASIC_AUTH}";
    public static String ACRA_LOGIN_PASS = "${ANDROID_ACRA_LOGIN_PASS}";
}
EOF
	echo "[Build] 已自动生成 Android ACRA 占位配置：$auth_file"
}

build_android_apk() {
	local binary_path="$1"
	local package_basename="$2"
	local project_dir
	local android_version_name
	local android_java_home
	local android_sdk_dir
	local android_sdkmanager_bin
	local android_required_ndk_version
	local android_ndk_dir
	project_dir="$(resolve_android_project_dir)"
	if [[ -z "$project_dir" ]]; then
		echo "[Build] 错误：Android 构建需要 Scardice-android 工程，但未找到 gradlew。已检查："
		echo "  - $ANDROID_PROJECT_DIR_PRIMARY"
		echo "  - $ANDROID_PROJECT_DIR_SECONDARY"
		return 1
	fi

	local assets_root="$project_dir/app/src/main/assets"
	local sealdice_assets_dir="$assets_root/sealdice"
	local sealdice_data_dir="$sealdice_assets_dir/data"
	local sealdice_lagrange_dir="$sealdice_assets_dir/lagrange"
	local sealdice_milky_dir="$sealdice_assets_dir/milky"
	local apk_output_dir="$project_dir/app/build/outputs/apk/debug"
	android_version_name="$(resolve_android_version_name)"
	android_java_home="$(resolve_android_java_home)"
	android_sdk_dir="$(resolve_android_sdk_root || true)"
	android_required_ndk_version="$(resolve_android_required_ndk_version "$project_dir")"
	if [[ -z "$android_java_home" ]]; then
		echo "[Build] 错误：无法为 Android 构建准备 JDK 17。"
		return 1
	fi
	if [[ -z "$android_sdk_dir" ]]; then
		echo "[Build] 错误：未找到 Android SDK。请安装 SDK，或设置 ANDROID_HOME / ANDROID_SDK_ROOT。"
		return 1
	fi
	android_sdkmanager_bin="$(download_android_cmdline_tools "$android_sdk_dir" || true)"
	if [[ -z "$android_sdkmanager_bin" || ! -x "$android_sdkmanager_bin" ]]; then
		echo "[Build] 错误：无法准备 Android sdkmanager。"
		return 1
	fi
	if [[ -n "$android_required_ndk_version" ]]; then
		android_ndk_dir="$(find_android_sdk_ndk_dir "$android_sdk_dir" "$android_required_ndk_version" || true)"
		if [[ -z "$android_ndk_dir" ]]; then
			android_ndk_dir="$(find_android_ndk_dir "$android_required_ndk_version" || true)"
		fi
		if [[ -z "$android_ndk_dir" ]]; then
			echo "[Build] 提示：未找到项目要求的 Android NDK $android_required_ndk_version，尝试下载到缓存目录。"
			android_ndk_dir="$(download_android_ndk_dir "$android_required_ndk_version" || true)"
		fi
	fi

	echo "[Build] Android 目标改用 APK 打包流程：$project_dir"
	echo "[Build] Android 构建使用 JAVA_HOME=$android_java_home"
	echo "[Build] Android 构建使用 SDK=$android_sdk_dir"
	if [[ -n "$android_ndk_dir" ]]; then
		echo "[Build] Android 构建使用 NDK=$android_ndk_dir"
	elif [[ -n "$android_required_ndk_version" ]]; then
		echo "[Build] 提示：未找到项目要求的 Android NDK $android_required_ndk_version，将依赖 SDK 内已安装的同版本 NDK。"
	fi
	prepare_android_optional_runtime_assets
	rm -rf "$sealdice_assets_dir"
	rm -f "$assets_root/app-runner-arm64.tar.gz"
	rm -rf "$apk_output_dir"
	mkdir -p "$sealdice_data_dir" "$sealdice_lagrange_dir" "$sealdice_milky_dir"
	ensure_android_auth_source "$project_dir"
	write_android_local_properties "$project_dir" "$android_sdk_dir"
	if ! ensure_android_sdk_licenses "$android_sdk_dir" ||
		[[ ! -e "$android_sdk_dir/platforms/android-33" ]] ||
		[[ ! -e "$android_sdk_dir/build-tools/33.0.1" ]]; then
		prepare_android_sdk "$android_sdk_dir" "$android_sdkmanager_bin" || return 1
	fi
	ensure_android_sdk_licenses "$android_sdk_dir" || return 1
	ensure_android_sdk_component "$android_sdk_dir" "platforms/android-33" "platforms;android-33" || return 1
	ensure_android_sdk_component "$android_sdk_dir" "build-tools/33.0.1" "build-tools;33.0.1" || return 1

	cp -a "$binary_path" "$sealdice_assets_dir/$(basename "$binary_path")"
	if [[ "$(basename "$binary_path")" == "Scardice-core" ]]; then
		cp -a "$binary_path" "$sealdice_assets_dir/sealdice-core"
	elif [[ "$(basename "$binary_path")" == "sealdice-core" ]]; then
		cp -a "$binary_path" "$sealdice_assets_dir/Scardice-core"
	fi
	cp -a "$BUILTINS_SUBMODULE_DIR/data"/. "$sealdice_data_dir"/
	copy_android_tree_if_present "$ANDROID_APP_RUNNER_ARCHIVE" "$assets_root" "Android App Runner"
	copy_android_tree_if_present "$ANDROID_LAGRANGE_DIR" "$sealdice_lagrange_dir" "Android Lagrange"
	copy_android_tree_if_present "$ANDROID_MILKY_DIR" "$sealdice_milky_dir" "Android Milky"
	copy_android_tree_if_present "$ANDROID_GOCQ_LAGRANGE_DIR" "$sealdice_lagrange_dir" "Android Gocq-Lagrange"

	chmod +x "$project_dir/gradlew"
	if (
		cd "$project_dir"
		export JAVA_HOME="$android_java_home"
		export PATH="$JAVA_HOME/bin:$PATH"
		export ANDROID_HOME="$android_sdk_dir"
		export ANDROID_SDK_ROOT="$android_sdk_dir"
		if [[ -n "$android_ndk_dir" ]]; then
			export ANDROID_NDK_HOME="$android_ndk_dir"
			export ANDROID_NDK_ROOT="$android_ndk_dir"
		fi
		SCARDICE_VERSION_NAME="$android_version_name" \
			SCARDICE_ANDROID_NDK_PATH="$android_ndk_dir" \
			bash ./gradlew -PSCARDICE_ANDROID_NDK_PATH="$android_ndk_dir" assembleDebug --stacktrace
	); then
		:
	else
		return $?
	fi

	ANDROID_APK_OUTPUT_DIR="$apk_output_dir"
	ANDROID_PACKAGE_BASENAME="$package_basename"
	return 0
}

collect_android_apk_output() {
	if [[ -z "$ANDROID_PACKAGE_BASENAME" ]]; then
		return 0
	fi
	if [[ -z "$ANDROID_APK_OUTPUT_DIR" || ! -d "$ANDROID_APK_OUTPUT_DIR" ]]; then
		echo "[Build] 错误：Android APK 输出目录不存在：$ANDROID_APK_OUTPUT_DIR"
		return 1
	fi

	local selected_apk=""
	local apk_candidates=()
	shopt -s nullglob
	apk_candidates=("$ANDROID_APK_OUTPUT_DIR"/*-signed.apk)
	if [[ ${#apk_candidates[@]} -eq 0 ]]; then
		apk_candidates=("$ANDROID_APK_OUTPUT_DIR"/*.apk)
	fi
	shopt -u nullglob
	if [[ ${#apk_candidates[@]} -eq 0 ]]; then
		echo "[Build] 错误：未找到 Android APK 输出文件：$ANDROID_APK_OUTPUT_DIR"
		return 1
	fi

	selected_apk="${apk_candidates[0]}"
	local final_apk="$OUTPUT_DIR/${ANDROID_PACKAGE_BASENAME}.apk"
	cp -f "$selected_apk" "$final_apk"
	ARCHIVES+=("$final_apk")
	echo "[Build] Android APK 已输出：$final_apk"
	return 0
}

load_android_signing_config() {
	if [[ ! -f "$ANDROID_SIGNING_ENV_FILE" ]]; then
		echo "[Build] 警告：未找到 Android 签名配置文件：$ANDROID_SIGNING_ENV_FILE"
		return 1
	fi
	if [[ ! -f "$ANDROID_KEYSTORE_FILE" ]]; then
		echo "[Build] 警告：未找到 Android keystore：$ANDROID_KEYSTORE_FILE"
		return 1
	fi

	local alias_value=""
	local store_password=""
	local key_password=""

	while IFS='=' read -r raw_key raw_value; do
		local key="${raw_key%%[[:space:]]*}"
		local value="$raw_value"
		case "$key" in
		ALIAS)
			alias_value="$value"
			;;
		KEY_STORE_PASSWORD)
			store_password="$value"
			;;
		KEY_PASSWORD)
			key_password="$value"
			;;
		esac
	done < <(grep -E '^(ALIAS|KEY_STORE_PASSWORD|KEY_PASSWORD)=' "$ANDROID_SIGNING_ENV_FILE")

	if [[ -z "$alias_value" || -z "$store_password" || -z "$key_password" ]]; then
		echo "[Build] 警告：Android 签名配置不完整，请检查：$ANDROID_SIGNING_ENV_FILE"
		return 1
	fi

	ANDROID_KEY_ALIAS="$alias_value"
	ANDROID_KEYSTORE_PASSWORD="$store_password"
	ANDROID_KEY_PASSWORD="$key_password"
	return 0
}

sign_android_apks_if_present() {
	local has_android_target=0
	local target
	local apksigner_cmd=""
	for target in "${TARGETS[@]}"; do
		if [[ "$target" == "android/arm64" ]]; then
			has_android_target=1
			break
		fi
	done

	if [[ $has_android_target -ne 1 ]]; then
		return 0
	fi
	if [[ -z "$ANDROID_APK_OUTPUT_DIR" ]]; then
		return 0
	fi
	if [[ ! -d "$ANDROID_APK_OUTPUT_DIR" ]]; then
		echo "[Build] 未检测到 Android APK 输出目录，跳过 APK 签名：$ANDROID_APK_OUTPUT_DIR"
		return 0
	fi
	if command -v apksigner >/dev/null 2>&1; then
		apksigner_cmd="$(command -v apksigner)"
	elif [[ -n "${ANDROID_SDK_ROOT:-}" && -x "${ANDROID_SDK_ROOT}/build-tools/33.0.1/apksigner" ]]; then
		apksigner_cmd="${ANDROID_SDK_ROOT}/build-tools/33.0.1/apksigner"
	elif [[ -x "/opt/android-sdk/build-tools/33.0.1/apksigner" ]]; then
		apksigner_cmd="/opt/android-sdk/build-tools/33.0.1/apksigner"
	fi
	if [[ -z "$apksigner_cmd" ]]; then
		echo "[Build] 警告：未找到 apksigner，跳过 Android APK 签名。"
		return 0
	fi
	if ! load_android_signing_config; then
		return 0
	fi

	shopt -s nullglob
	local apk
	local candidates=("$ANDROID_APK_OUTPUT_DIR"/*.apk)
	shopt -u nullglob
	if [[ ${#candidates[@]} -eq 0 ]]; then
		echo "[Build] 未发现待签名的 Android APK，跳过。"
		return 0
	fi

	for apk in "${candidates[@]}"; do
		local apk_name="$(basename "$apk")"
		if [[ "$apk_name" == *-signed.apk ]]; then
			continue
		fi
		local signed_apk="${apk%.apk}-signed.apk"
		rm -f "$signed_apk"
		echo "[Build] 使用 $ANDROID_KEYSTORE_FILE 为 Android APK 签名：$apk_name"
		"$apksigner_cmd" sign \
			--ks "$ANDROID_KEYSTORE_FILE" \
			--ks-pass "pass:${ANDROID_KEYSTORE_PASSWORD}" \
			--ks-key-alias "$ANDROID_KEY_ALIAS" \
			--key-pass "pass:${ANDROID_KEY_PASSWORD}" \
			--out "$signed_apk" \
			"$apk"
		"$apksigner_cmd" verify "$signed_apk" >/dev/null
		echo "[Build] Android APK 签名完成：$(basename "$signed_apk")"
	done
}

find_android_ndk_clang() {
	local search_roots=()
	local root
	local clang_path

	if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
		search_roots+=("${ANDROID_NDK_HOME}")
	fi
	if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
		search_roots+=("${ANDROID_NDK_ROOT}")
	fi
	if [[ -d "/opt/android-sdk/ndk" ]]; then
		for root in /opt/android-sdk/ndk/*; do
			[[ -d "$root" ]] && search_roots+=("$root")
		done
	fi
	if [[ -d "$HOME/Android/Sdk/ndk" ]]; then
		for root in "$HOME"/Android/Sdk/ndk/*; do
			[[ -d "$root" ]] && search_roots+=("$root")
		done
	fi

	for root in "${search_roots[@]}"; do
		clang_path="$root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
		if [[ -x "$clang_path" ]]; then
			echo "$clang_path"
			return 0
		fi
	done

	echo ""
}

join_by_comma() {
	local IFS=", "
	echo "$*"
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

	if [[ "$goos" == "android" ]]; then
		if [[ "$goarch" != "arm64" ]]; then
			echo "[Build] 错误：目标 ${target} 当前脚本仅支持 android/arm64。"
			exit 1
		fi
		if [[ -n "$(find_android_ndk_clang)" ]]; then
			return 0
		fi
		echo "[Build] 错误：目标 ${target} 启用 CGO 需要 Android NDK clang。"
		echo "[Build] 建议安装：sudo pacman -S android-ndk，或设置 ANDROID_NDK_HOME/ANDROID_NDK_ROOT。"
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

	if [[ "$goos" == "linux" && "$goarch" == "arm64" && ! ("$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "arm64") ]]; then
		if command -v aarch64-linux-musl-gcc >/dev/null 2>&1 || command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
			return 0
		fi
		echo "[Build] 错误：目标 ${target} 启用 CGO 需要 aarch64 交叉编译器。"
		echo "[Build] 建议安装：aarch64-linux-musl-gcc 或 aarch64-linux-gnu-gcc"
		exit 1
	fi

	if [[ "$goos" == "linux" && "$goarch" == "amd64" && ! ("$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "amd64") ]]; then
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

	if [[ "$goos" == "android" && "$goarch" == "arm64" ]]; then
		find_android_ndk_clang
		return 0
	fi

	if [[ "$goos" == "linux" && "$goarch" == "arm64" && ! ("$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "arm64") ]]; then
		if command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
			echo "aarch64-linux-musl-gcc"
			return 0
		fi
		if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
			echo "aarch64-linux-gnu-gcc"
			return 0
		fi
	fi

	if [[ "$goos" == "linux" && "$goarch" == "amd64" && ! ("$HOST_GOOS" == "linux" && "$HOST_GOARCH" == "amd64") ]]; then
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

TARGETS=("android/arm64")

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

USE_UPX=0

if [[ "${CGO_ENABLED_VALUE}" -eq 1 ]]; then
	echo "[Build] 预检查 CGO 依赖..."
	check_cgo_dependency_or_exit "android" "arm64"
fi

CUR_TIME="$(date +%Y%m%d)"
if GIT_HASH="$(git rev-parse --short=7 HEAD 2>/dev/null)"; then
	VERSION_BUILD_METADATA="+${CUR_TIME}.${GIT_HASH}"
else
	VERSION_BUILD_METADATA="+${CUR_TIME}.nogit"
fi

# 处理可信客户端私钥 (SealTrustedClientPrivateKey)
if [[ -s "$PRIVATE_KEY_FILE" ]]; then
	echo "[Build] 已找到可信私钥文件：$PRIVATE_KEY_FILE"
	PRIVATE_KEY_CONTENT_B64="$(base64 <"$PRIVATE_KEY_FILE" | tr -d '\n')"
else
	echo "[Build] 错误：可信私钥文件不存在：$PRIVATE_KEY_FILE"
	exit 1
fi

# 处理签名客户端私钥 (SealSignClientPrivateKey)
if [[ -s "$SIGN_KEY_FILE" ]]; then
	echo "[Build] 已找到签名私钥文件：$SIGN_KEY_FILE"
	SIGN_KEY_CONTENT="$(tr -d '[:space:]' <"$SIGN_KEY_FILE")"
else
	echo "[Build] 警告：签名私钥文件不存在或为空，跳过注入：$SIGN_KEY_FILE"
fi

LDFLAGS="-s -w"
LDFLAGS+=" -X Scardice-core/dice.VERSION_MAIN=${VERSION_MAIN}"
LDFLAGS+=" -X Scardice-core/dice.VERSION_PRERELEASE=${VERSION_PRERELEASE}"
LDFLAGS+=" -X Scardice-core/dice.VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
LDFLAGS+=" -X Scardice-core/dice.APP_CHANNEL=${APP_CHANNEL}"
LDFLAGS+=" -X Scardice-core/dice.APPNAME=${APPNAME}"
if [[ $USE_COMPATIBLE_NAMES -eq 1 ]]; then
	LDFLAGS+=" -X main.LockFileName=sealdice-core.lock"
fi

if [[ -n "${PRIVATE_KEY_CONTENT_B64:-}" ]] && rg -q "SealTrustedClientPrivateKey" ./dice ./main.go 2>/dev/null; then
	LDFLAGS+=" -X 'Scardice-core/dice.SealTrustedClientPrivateKey=base64:${PRIVATE_KEY_CONTENT_B64}'"
	echo "[Build] 已通过 ldflags 以 base64 形式注入 SealTrustedClientPrivateKey"
else
	echo "[Build] 警告：未找到 SealTrustedClientPrivateKey 符号或内容为空，跳过私钥注入"
fi

if [[ -n "${SIGN_KEY_CONTENT:-}" ]] && rg -q "SealSignClientPrivateKey" ./dice ./main.go 2>/dev/null; then
	LDFLAGS+=" -X 'Scardice-core/dice.SealSignClientPrivateKey=${SIGN_KEY_CONTENT}'"
	echo "[Build] 已通过 ldflags 注入 SealSignClientPrivateKey"
else
	echo "[Build] 警告：未找到 SealSignClientPrivateKey 符号或内容为空，跳过注入"
fi

echo "[Build] VERSION_MAIN=${VERSION_MAIN}"
echo "[Build] VERSION_PRERELEASE=${VERSION_PRERELEASE}"
echo "[Build] VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
echo "[Build] APP_CHANNEL=${APP_CHANNEL}"
echo "[Build] APPNAME=${APPNAME}"
echo "[Build] TARGET=android/arm64"
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
	echo "$UI_MARKER_EXPECTED" >"$UI_BUILD_MARKER"
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
TARGET_GOOS="android"
TARGET_GOARCH="arm64"
BINARY_NAME="$(pick_binary_name "$TARGET_GOOS")"
TARGET_WORK_DIR="$PACKAGE_WORK_DIR/${TARGET_GOOS}-${TARGET_GOARCH}"
BINARY_PATH="$TARGET_WORK_DIR/$BINARY_NAME"
PACKAGE_BASENAME="Scardice_${VERSION_MAIN}${VERSION_PRERELEASE}_${TARGET_GOOS}_${TARGET_GOARCH}"
CC_VALUE="$(select_cc_for_target "$TARGET_GOOS" "$TARGET_GOARCH")"

echo "[Build] 开始 go build: ${TARGET_GOOS}/${TARGET_GOARCH}"
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

build_android_apk "$BINARY_PATH" "$PACKAGE_BASENAME"

sign_android_apks_if_present
collect_android_apk_output

rm -rf "$PACKAGE_WORK_DIR"
echo "[Build] 打包完成，共 ${#ARCHIVES[@]} 个文件："
for archive in "${ARCHIVES[@]}"; do
	echo "  - ${archive}"
done
