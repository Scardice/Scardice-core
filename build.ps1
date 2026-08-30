<#
.SYNOPSIS
    Scardice-core 构建脚本 (PowerShell port of build.sh)
.DESCRIPTION
    完整的构建脚本，支持开发模式、发布模式、多目标构建、CGO 交叉编译、
    运行时资源缓存与打包、代码签名密钥注入等功能。
.PARAMETER Dev
    开发构建模式：跳过交互式提示，使用本机默认值。
.PARAMETER RemainingArgs
    支持 --dev 作为后备参数（与 bash 版本兼容）。
#>

param(
    [switch]$Dev,
    [Parameter(ValueFromRemainingArguments)]
    [string[]]$RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:DEV_MODE = $Dev.IsPresent

foreach ($arg in $RemainingArgs) {
    switch ($arg) {
        '--dev' {
            $script:DEV_MODE = $true
        }
        default {
            Write-Host "[Build] 错误：未知参数 $arg"
            exit 1
        }
    }
}

$script:ROOT_DIR = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Set-Location $script:ROOT_DIR

$script:DEFAULT_VERSION_PRERELEASE = '-dev'
$script:DEFAULT_APP_CHANNEL = 'dev'
$script:DEFAULT_APPNAME = 'Scardice'

# 从 dice/version.go 解析 VERSION_MAIN
$script:DEFAULT_VERSION_MAIN = '1.6.1'
$versionGoPath = Join-Path $script:ROOT_DIR 'dice/version.go'
if (Test-Path $versionGoPath) {
    $vmLine = Select-String -Path $versionGoPath -Pattern "^\s*VERSION_MAIN\s*=\s*""([^""]*)""" -ErrorAction SilentlyContinue
    if ($vmLine -and $vmLine.Matches -and $vmLine.Matches.Count -gt 0 -and $vmLine.Matches[0].Groups -and $vmLine.Matches[0].Groups.Count -gt 1) {
        $parsedVer = $vmLine.Matches[0].Groups[1].Value
        if (-not [string]::IsNullOrWhiteSpace($parsedVer)) {
            $script:DEFAULT_VERSION_MAIN = $parsedVer
        }
    }
}

# 密钥文件
$script:PRIVATE_KEY_FILE = Join-Path $script:ROOT_DIR 'signature/seal_trusted_private_key.pem'
$script:SIGN_KEY_FILE = Join-Path $script:ROOT_DIR 'signature/seal_sign_private_key.bin'
$script:SIGN_V3_URL_FILE = Join-Path $script:ROOT_DIR 'signature/SealSignV3Url'

# 从 go env 获取本机 GOOS/GOARCH
$goEnvGoos = & go env GOOS 2>$null
$script:DEFAULT_TARGET_GOOS = if ($goEnvGoos) { $goEnvGoos.Trim() } else { 'linux' }
$goEnvGoarch = & go env GOARCH 2>$null
$script:DEFAULT_TARGET_GOARCH = if ($goEnvGoarch) { $goEnvGoarch.Trim() } else { 'amd64' }

# 目录路径
$script:OUTPUT_DIR = Join-Path $script:ROOT_DIR 'output'
$script:UI_SUBMODULE_DIR = Join-Path $script:ROOT_DIR 'Scardice-ui'
$script:BUILTINS_SUBMODULE_DIR = Join-Path $script:ROOT_DIR 'sealdice-builtins'
$script:STATIC_FRONTEND_DIR = Join-Path $script:ROOT_DIR 'static/frontend'
$script:BUILD_CACHE_DIR = Join-Path $script:ROOT_DIR '.build-cache'
$script:GO_CACHE_DIR = Join-Path $script:BUILD_CACHE_DIR 'go-cache'
$script:GO_TMP_DIR = Join-Path $script:BUILD_CACHE_DIR 'tmp'
$script:UI_BUILD_MARKER = Join-Path $script:UI_SUBMODULE_DIR 'dist/.build-meta'
$script:PACKAGE_WORK_DIR = Join-Path $script:BUILD_CACHE_DIR 'package-work'
$script:RUNTIME_CACHE_DIR = Join-Path $script:BUILD_CACHE_DIR 'runtime'

# 运行时配置
$script:RUNTIME_CACHE_TTL_SECONDS = if ($env:RUNTIME_CACHE_TTL_SECONDS) { [int]$env:RUNTIME_CACHE_TTL_SECONDS } else { 86400 }
$script:RUNTIME_AXEL_CONNECTIONS = if ($env:RUNTIME_AXEL_CONNECTIONS) { [int]$env:RUNTIME_AXEL_CONNECTIONS } else { 8 }
$script:PACK_RUNTIME_ASSETS = if ($env:PACK_RUNTIME_ASSETS) { [int]$env:PACK_RUNTIME_ASSETS } else { 1 }
$script:RUNTIME_ASSETS_STRICT = if ($env:RUNTIME_ASSETS_STRICT) { [int]$env:RUNTIME_ASSETS_STRICT } else { 1 }
$script:REDOWNLOAD_RUNTIME_ASSETS = 0

# 支持的目标平台
$script:ALL_GOOS = @('linux', 'windows', 'darwin', 'freebsd', 'openbsd', 'netbsd')
$script:ALL_GOARCH = @('amd64', 'arm64', '386', 'arm', 'ppc64le', 'riscv64', 's390x')

# 本机平台
$script:HOST_GOOS = $script:DEFAULT_TARGET_GOOS
$script:HOST_GOARCH = $script:DEFAULT_TARGET_GOARCH

# UPX 检测
$script:UPX_CMD = if (Get-Command 'upx' -ErrorAction SilentlyContinue) { 'upx' } else { '' }

# 全局构建变量
$script:VERSION_MAIN = ''
$script:VERSION_PRERELEASE = ''
$script:APP_CHANNEL = ''
$script:APPNAME = ''
$script:BUILD_MODE_INPUT = ''
$script:CGO_ENABLED_VALUE = 0
$script:USE_COMPATIBLE_NAMES = 0
$script:USE_UPX = 0
$script:TARGETS = @()
$script:PRIVATE_KEY_CONTENT_B64 = ''
$script:SIGN_KEY_CONTENT = ''
$script:SIGN_V3_URL_CONTENT = ''
$script:TARGET_LAGRANGE_DIR = ''
$script:TARGET_MILKY_DIR = ''
$script:TARGET_YOGURT_DIR = ''

function ExecSafe {
    <#
    .SYNOPSIS
        执行外部命令并检查退出码。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [string]$ErrorMessage = ''
    )
    & $ScriptBlock
    $exitCode = $global:LASTEXITCODE
    if ($exitCode -ne 0) {
        if ([string]::IsNullOrWhiteSpace($ErrorMessage)) {
            Write-Host "[Build] 错误：命令执行失败，退出代码 ${exitCode}"
        } else {
            Write-Host "${ErrorMessage}，退出代码 ${exitCode}"
        }
        exit $exitCode
    }
}

function Show-Menu {
    <#
    .SYNOPSIS
        交互式选择菜单，默认选项标记 (本机)。
    .PARAMETER Prompt
        提示信息。
    .PARAMETER DefaultValue
        默认选中的值。
    .PARAMETER Options
        可选项数组。
    .OUTPUTS
        string 选中的值。
    #>
    param(
        [string]$Prompt,
        [string]$DefaultValue,
        [string[]]$Options
    )
    $count = $Options.Count
    Write-Host $Prompt
    for ($i = 0; $i -lt $count; $i++) {
        $val = $Options[$i]
        if ($val -eq $DefaultValue) {
            Write-Host "  $($i + 1)) ${val} (本机)"
        } else {
            Write-Host "  $($i + 1)) ${val}"
        }
    }
    while ($true) {
        $selected = Read-Host "请选择 [1-${count}]（默认：${DefaultValue}）"
        if ([string]::IsNullOrWhiteSpace($selected)) {
            return $DefaultValue
        }
        $num = 0
        if ([int]::TryParse($selected, [ref]$num) -and $num -ge 1 -and $num -le $count) {
            return $Options[$num - 1]
        }
        Write-Host "输入无效，请输入 1-${count} 的数字。"
    }
}

function Get-CalcFileHash {
    <#
    .SYNOPSIS
        计算文件的 SHA256 哈希值。
    .PARAMETER FilePath
        文件路径。
    .OUTPUTS
        string 哈希值或 'nohash'。
    #>
    param([string]$FilePath)
    # Try Get-FileHash (native PowerShell)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        if ($hash) {
            return $hash.Hash.ToLower()
        }
    } catch {
        # ignore, try fallback
    }
    # Try sha256sum
    $sha256sumCmd = Get-Command 'sha256sum' -ErrorAction SilentlyContinue
    if ($sha256sumCmd) {
        $result = & sha256sum $FilePath 2>$null
        if ($LASTEXITCODE -eq 0 -and $result) {
            return ($result -split '\s+')[0]
        }
    }
    # Try shasum
    $shasumCmd = Get-Command 'shasum' -ErrorAction SilentlyContinue
    if ($shasumCmd) {
        $result = & shasum -a 256 $FilePath 2>$null
        if ($LASTEXITCODE -eq 0 -and $result) {
            return ($result -split '\s+')[0]
        }
    }
    # Try openssl
    $opensslCmd = Get-Command 'openssl' -ErrorAction SilentlyContinue
    if ($opensslCmd) {
        $result = & openssl dgst -sha256 $FilePath 2>$null
        if ($LASTEXITCODE -eq 0 -and $result) {
            return ($result -split ' ')[-1]
        }
    }
    return 'nohash'
}

function Set-CacheStamp {
    <#
    .SYNOPSIS
        标记缓存条目为最新（创建/更新时间戳文件）。
    #>
    param([string]$StampFile)
    $dir = Split-Path $StampFile -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    # 创建或更新 stamp 文件（空内容）
    Out-File -FilePath $StampFile -Encoding ASCII -InputObject '' -Force
}

function Test-CacheFresh {
    <#
    .SYNOPSIS
        判断缓存是否仍在 TTL 内。
    #>
    param(
        [string]$CachePath,
        [string]$StampFile
    )
    $ttl = $script:RUNTIME_CACHE_TTL_SECONDS
    if (-not (Test-Path $CachePath) -or -not (Test-Path $StampFile)) {
        return $false
    }
    $cacheItem = Get-Item $CachePath -ErrorAction SilentlyContinue
    if (-not $cacheItem -or $cacheItem.Length -eq 0) {
        return $false
    }
    if ($ttl -le 0) {
        return $false
    }
    $stampItem = Get-Item $StampFile -ErrorAction SilentlyContinue
    if (-not $stampItem) {
        return $false
    }
    $now = [datetime]::UtcNow
    $age = ($now - $stampItem.LastWriteTimeUtc).TotalSeconds
    return ($age -lt $ttl)
}

function Invoke-DownloadWithCache {
    <#
    .SYNOPSIS
        带缓存的下载函数。优先使用 axel，其次是 curl，最后 Invoke-WebRequest。
    #>
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Label
    )
    $stampFile = "${Destination}.stamp"
    $tempPath = "${Destination}.tmp.$PID"

    $destDir = Split-Path $Destination -Parent
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    }

    if ($script:REDOWNLOAD_RUNTIME_ASSETS -ne 1 -and (Test-Path $Destination)) {
        $di = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($di -and $di.Length -gt 0) {
            Write-Host "[Build] 使用缓存的 ${Label}：$Destination"
            return $true
        }
    }

    if ($script:REDOWNLOAD_RUNTIME_ASSETS -eq 1 -and (Test-Path $Destination)) {
        $di = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($di -and $di.Length -gt 0) {
            Write-Host "[Build] 已选择重新下载 ${Label}，忽略缓存：$Destination"
        }
    }

    # 清理临时文件
    Remove-Item -Path $tempPath -ErrorAction SilentlyContinue

    $downloadSuccess = $false

    # 尝试 axel
    $axelCmd = Get-Command 'axel' -ErrorAction SilentlyContinue
    if ($axelCmd) {
        Write-Host "[Build] 下载 ${Label}（axel 优先）：$Url"
        $axelOutput = & axel -q -a -n $script:RUNTIME_AXEL_CONNECTIONS -o $tempPath $Url 2>&1
        if ($LASTEXITCODE -eq 0) {
            $downloadSuccess = $true
        } else {
            Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
            Write-Host "[Build] 警告：axel 下载 ${Label} 失败，回退到 curl。"
        }
    }

    # 尝试 curl
    if (-not $downloadSuccess) {
        $curlCmd = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
        if (-not $curlCmd) {
            $curlCmd = Get-Command 'curl' -ErrorAction SilentlyContinue
        }
        if ($curlCmd) {
            Write-Host "[Build] 下载 ${Label}（curl 回退）：$Url"
            $curlResult = & $curlCmd -fsSL --retry 2 --connect-timeout 15 $Url -o $tempPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                $downloadSuccess = $true
            } else {
                Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "[Build] 警告：未找到 curl，无法下载 ${Label}。"
        }
    }

    # 尝试 Invoke-WebRequest
    if (-not $downloadSuccess) {
        Write-Host "[Build] 下载 ${Label}（Invoke-WebRequest 回退）：$Url"
        $iwrSuccess = $false
        $maxRetries = 2
        for ($retry = 0; $retry -le $maxRetries; $retry++) {
            try {
                $null = Invoke-WebRequest -Uri $Url -OutFile $tempPath -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
                $iwrSuccess = $true
                break
            } catch {
                if ($retry -lt $maxRetries) {
                    Start-Sleep -Seconds 3
                }
            }
        }
        if ($iwrSuccess) {
            $downloadSuccess = $true
        } else {
            Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
        }
    }

    if ($downloadSuccess) {
        Move-Item -Force -Path $tempPath -Destination $Destination
        Set-CacheStamp -StampFile $stampFile
        return $true
    }

    # 下载失败：尝试保留旧缓存
    Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
    if (Test-Path $Destination) {
        $di = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($di -and $di.Length -gt 0) {
            Write-Host "[Build] 警告：刷新 ${Label} 失败，继续使用旧缓存：$Destination"
            return $true
        }
    }
    Write-Host "[Build] 警告：下载 ${Label} 失败。"
    return $false
}

function Get-LagrangeCachePath {
    param([string]$Goos, [string]$Goarch)
    $target = "${Goos}-${Goarch}"
    return Join-Path $script:RUNTIME_CACHE_DIR "Lagrange.OneBot.${target}.zip"
}

function Get-MilkyCachePath {
    param([string]$Goos, [string]$Goarch)
    $target = "${Goos}-${Goarch}"
    $cacheFile = Join-Path $script:RUNTIME_CACHE_DIR "lagrangeV2.${target}"
    if ($Goos -eq 'windows') {
        $cacheFile = "${cacheFile}.exe"
    }
    return $cacheFile
}

function Get-YogurtCachePath {
    param([string]$Goos, [string]$Goarch)
    $target = "${Goos}-${Goarch}"
    return Join-Path $script:RUNTIME_CACHE_DIR "yogurt.${target}.zip"
}

function Test-RuntimeAssetCache {
    param([string]$Goos, [string]$Goarch)
    $lagrangeUrl = Get-LagrangeUrl $Goos $Goarch
    if (-not [string]::IsNullOrWhiteSpace($lagrangeUrl)) {
        $cachePath = Get-LagrangeCachePath $Goos $Goarch
        if (Test-Path $cachePath) {
            $ci = Get-Item $cachePath -ErrorAction SilentlyContinue
            if ($ci -and $ci.Length -gt 0) {
                return $true
            }
        }
    }
    $milkyUrl = Get-MilkyUrl $Goos $Goarch
    if (-not [string]::IsNullOrWhiteSpace($milkyUrl)) {
        $cachePath = Get-MilkyCachePath $Goos $Goarch
        if (Test-Path $cachePath) {
            $ci = Get-Item $cachePath -ErrorAction SilentlyContinue
            if ($ci -and $ci.Length -gt 0) {
                return $true
            }
        }
    }
    return $false
}

function Test-RuntimeAssetCacheForTargets {
    param([string[]]$Targets)
    foreach ($target in $Targets) {
        $parts = $target.Split('/')
        if ($parts.Count -lt 2) { continue }
        $goos = $parts[0]
        $goarch = $parts[1]
        if (Test-RuntimeAssetCache $goos $goarch) {
            return $true
        }
    }
    return $false
}

function Expand-ArchiveToDir {
    <#
    .SYNOPSIS
        解压归档到指定目录。依次尝试 unzip、tar、Expand-Archive。
    #>
    param(
        [string]$ArchivePath,
        [string]$DestinationDir,
        [string]$Label
    )
    Remove-Item -Recurse -Force -Path $DestinationDir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null

    # 尝试 unzip
    $unzipCmd = Get-Command 'unzip' -ErrorAction SilentlyContinue
    if ($unzipCmd) {
        $null = & unzip -oq $ArchivePath -d $DestinationDir 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    # 尝试 tar（Windows 10+ 内置，也作为 bsdtar）
    $tarCmd = Get-Command 'tar' -ErrorAction SilentlyContinue
    if ($tarCmd) {
        $null = & tar -xf $ArchivePath -C $DestinationDir 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $true
        }
    }

    # 尝试 PowerShell 原生的 Expand-Archive
    try {
        if (Get-Command 'Microsoft.PowerShell.Archive\Expand-Archive' -ErrorAction SilentlyContinue) {
            Microsoft.PowerShell.Archive\Expand-Archive -Path $ArchivePath -DestinationPath $DestinationDir -Force
            return $true
        }
    } catch {
        # ignore
    }

    Write-Host "[Build] 警告：解压 ${Label} 失败，需要 unzip、tar 或 Expand-Archive。"
    return $false
}

function Sync-CachedArchive {
    <#
    .SYNOPSIS
        将缓存的归档同步到解压目录（使用时间戳缓存）。
    #>
    param(
        [string]$ArchivePath,
        [string]$DestinationDir,
        [string]$Label
    )
    $stampFile = "${DestinationDir}.stamp"
    if ((Test-Path $DestinationDir) -and (Test-Path $stampFile)) {
        $archiveTime = (Get-Item $ArchivePath -ErrorAction SilentlyContinue).LastWriteTimeUtc
        $stampTime = (Get-Item $stampFile -ErrorAction SilentlyContinue).LastWriteTimeUtc
        if ($archiveTime -and $stampTime -and $archiveTime -lt $stampTime) {
            return $true
        }
    }
    if (Expand-ArchiveToDir -ArchivePath $ArchivePath -DestinationDir $DestinationDir -Label $Label) {
        Set-CacheStamp -StampFile $stampFile
        return $true
    }
    return $false
}

function Sync-CachedFile {
    <#
    .SYNOPSIS
        将缓存的单文件同步到目标目录。
    #>
    param(
        [string]$SourceFile,
        [string]$DestinationDir,
        [string]$DestinationName,
        [string]$Label
    )
    $stampFile = "${DestinationDir}.stamp"
    $destPath = Join-Path $DestinationDir $DestinationName
    if ((Test-Path $DestinationDir) -and (Test-Path $destPath) -and (Test-Path $stampFile)) {
        $sourceTime = (Get-Item $SourceFile -ErrorAction SilentlyContinue).LastWriteTimeUtc
        $stampTime = (Get-Item $stampFile -ErrorAction SilentlyContinue).LastWriteTimeUtc
        if ($sourceTime -and $stampTime -and $sourceTime -lt $stampTime) {
            return $true
        }
    }
    Remove-Item -Recurse -Force -Path $DestinationDir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
    Copy-Item -Path $SourceFile -Destination (Join-Path $DestinationDir $DestinationName) -Force
    Set-CacheStamp -StampFile $stampFile
    Write-Host "[Build] 已准备 ${Label}：${destPath}"
    return $true
}

function Get-LagrangeUrl {
    param([string]$Goos, [string]$Goarch)
    switch ("${Goos}/${Goarch}") {
        'linux/arm64'   { return 'https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_linux-arm64_8.0.zip?v=3' }
        'linux/amd64'   { return 'https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_linux-x64_8.0.zip?v=3' }
        'windows/amd64' { return 'https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_win-x64_8.0.zip?v=3' }
        'windows/386'   { return 'https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_win-x86_8.0.zip?v=3' }
        'darwin/arm64'  { return 'https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_osx-arm64_8.0.zip?v=3' }
        'darwin/amd64'  { return 'https://d1.sealdice.com/lagrange/0.0.6/Lagrange.OneBot_osx-x64_8.0.zip?v=3' }
        default         { return '' }
    }
}

function Get-MilkyUrl {
    param([string]$Goos, [string]$Goarch)
    switch ("${Goos}/${Goarch}") {
        'linux/arm64'   { return 'https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-linux-arm64' }
        'linux/amd64'   { return 'https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-linux-x64' }
        'darwin/arm64'  { return 'https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-osx-arm64' }
        'windows/amd64' { return 'https://github.com/sealdice/LagrangeV2/releases/download/nightly/Lagrange.Milky-win-x64.exe' }
        default         { return '' }
    }
}

function Get-YogurtUrl {
    param([string]$Goos, [string]$Goarch)
    switch ("${Goos}/${Goarch}") {
        'linux/arm64'    { return 'https://github.com/sealdice/acidify/releases/download/dev/yogurt-linux-arm64.zip' }
        'linux/amd64'    { return 'https://github.com/sealdice/acidify/releases/download/dev/yogurt-linux-x64.zip' }
        'darwin/arm64'   { return 'https://github.com/sealdice/acidify/releases/download/dev/yogurt-macos-arm64.zip' }
        'windows/amd64'  { return 'https://github.com/sealdice/acidify/releases/download/dev/yogurt-windows-x64.zip' }
        'android/arm64'  { return 'https://github.com/sealdice/acidify/releases/download/dev/yogurt-android-arm64.zip' }
        default          { return '' }
    }
}

function Invoke-PrepareRuntimeAssets {
    <#
    .SYNOPSIS
        准备目标平台的运行时资源（Lagrange、Milky、Yogurt）。
        设置 TARGET_LAGRANGE_DIR、TARGET_MILKY_DIR、TARGET_YOGURT_DIR。
    #>
    param([string]$Goos, [string]$Goarch)
    $target = "${Goos}-${Goarch}"
    $script:TARGET_LAGRANGE_DIR = ''
    $script:TARGET_MILKY_DIR = ''
    $script:TARGET_YOGURT_DIR = ''

    if ($script:PACK_RUNTIME_ASSETS -ne 1) {
        return
    }

    New-Item -ItemType Directory -Force -Path $script:RUNTIME_CACHE_DIR | Out-Null

    # Lagrange
    $lagrangeUrl = Get-LagrangeUrl $Goos $Goarch
    if (-not [string]::IsNullOrWhiteSpace($lagrangeUrl)) {
        $lagrangeZip = Get-LagrangeCachePath $Goos $Goarch
        $lagrangeDir = Join-Path $script:RUNTIME_CACHE_DIR "lagrange.${target}"
        $dlOk = Invoke-DownloadWithCache -Url $lagrangeUrl -Destination $lagrangeZip -Label "Lagrange ${Goos}/${Goarch}"
        if ($dlOk -and (Sync-CachedArchive -ArchivePath $lagrangeZip -DestinationDir $lagrangeDir -Label "Lagrange ${Goos}/${Goarch}")) {
            $script:TARGET_LAGRANGE_DIR = $lagrangeDir
        } elseif ($script:RUNTIME_ASSETS_STRICT -eq 1) {
            Write-Host "[Build] 错误：无法准备 Lagrange ${Goos}/${Goarch}"
            exit 1
        }
    } else {
        Write-Host "[Build] 提示：${Goos}/${Goarch} 没有可用的 Lagrange 打包资源，跳过。"
    }

    # Milky
    $milkyUrl = Get-MilkyUrl $Goos $Goarch
    if (-not [string]::IsNullOrWhiteSpace($milkyUrl)) {
        $milkySourceName = 'lagrangeV2'
        $milkyCacheFile = Get-MilkyCachePath $Goos $Goarch
        $milkyDir = Join-Path $script:RUNTIME_CACHE_DIR "milky.${target}"
        if ($Goos -eq 'windows') {
            $milkySourceName = 'lagrangeV2.exe'
        }
        $dlOk = Invoke-DownloadWithCache -Url $milkyUrl -Destination $milkyCacheFile -Label "Milky ${Goos}/${Goarch}"
        if ($dlOk -and (Sync-CachedFile -SourceFile $milkyCacheFile -DestinationDir $milkyDir -DestinationName $milkySourceName -Label "Milky ${Goos}/${Goarch}")) {
            $script:TARGET_MILKY_DIR = $milkyDir
        } elseif ($script:RUNTIME_ASSETS_STRICT -eq 1) {
            Write-Host "[Build] 错误：无法准备 Milky ${Goos}/${Goarch}"
            exit 1
        }
    } else {
        Write-Host "[Build] 提示：${Goos}/${Goarch} 没有可用的 Milky 打包资源，跳过。"
    }

    # Yogurt
    $yogurtUrl = Get-YogurtUrl $Goos $Goarch
    if (-not [string]::IsNullOrWhiteSpace($yogurtUrl)) {
        $yogurtZip = Get-YogurtCachePath $Goos $Goarch
        $yogurtDir = Join-Path $script:RUNTIME_CACHE_DIR "yogurt.${target}"
        $dlOk = Invoke-DownloadWithCache -Url $yogurtUrl -Destination $yogurtZip -Label "Yogurt ${Goos}/${Goarch}"
        if ($dlOk -and (Sync-CachedArchive -ArchivePath $yogurtZip -DestinationDir $yogurtDir -Label "Yogurt ${Goos}/${Goarch}")) {
            # Yogurt kexe 重命名规则
            if ($Goos -eq 'windows') {
                $yogurtExe = Join-Path $yogurtDir 'yogurt.exe'
                $yogurtKexe = Join-Path $yogurtDir 'yogurt.kexe'
                if (-not (Test-Path $yogurtExe) -and (Test-Path $yogurtKexe)) {
                    Move-Item -Force -Path $yogurtKexe -Destination $yogurtExe
                }
            } else {
                $yogurtBin = Join-Path $yogurtDir 'yogurt'
                $yogurtKexe = Join-Path $yogurtDir 'yogurt.kexe'
                if (Test-Path $yogurtKexe) {
                    Move-Item -Force -Path $yogurtKexe -Destination $yogurtBin
                }
            }
            $script:TARGET_YOGURT_DIR = $yogurtDir
        } elseif ($script:RUNTIME_ASSETS_STRICT -eq 1) {
            Write-Host "[Build] 错误：无法准备 Yogurt ${Goos}/${Goarch}"
            exit 1
        }
    } else {
        Write-Host "[Build] 提示：${Goos}/${Goarch} 没有可用的 Yogurt 打包资源，跳过。"
    }
}

function Copy-RuntimeTreeIfPresent {
    <#
    .SYNOPSIS
        如果源路径存在，将其复制到目标目录。
    #>
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($SourcePath)) {
        return
    }
    if (-not (Test-Path $SourcePath)) {
        Write-Host "[Build] 警告：${Label} 资源不存在，跳过：$SourcePath"
        return
    }
    New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
    if (Test-Path $SourcePath -PathType Container) {
        # 目录：复制内容
        Get-ChildItem -Path $SourcePath | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $DestinationPath -Recurse -Force
        }
    } else {
        # 文件：复制到目录中
        Copy-Item -Path $SourcePath -Destination (Join-Path $DestinationPath (Split-Path $SourcePath -Leaf)) -Force
    }
    Write-Host "[Build] 已打包 ${Label}：$DestinationPath"
}

function Join-ByComma {
    <#
    .SYNOPSIS
        用逗号和空格连接字符串数组。
    #>
    param([string[]]$Values)
    return ($Values -join ', ')
}

function Write-MultiTargetGuide {
    <#
    .SYNOPSIS
        打印多目标构建指南。
    #>
    Write-Host '------ Multi Target Guide ------'
    Write-Host "理论支持的平台: $(Join-ByComma $script:ALL_GOOS)"
    Write-Host "理论支持的架构: $(Join-ByComma $script:ALL_GOARCH)"
    Write-Host '理论上难以支持的组合:'
    Write-Host '  - darwin/* (在非 macOS 主机且启用 CGO 时)'
    Write-Host '  - freebsd/*、openbsd/*、netbsd/* (启用 CGO 的跨平台编译)'
    Write-Host '  - windows/arm64 (常见环境缺少稳定可用的 CGO 交叉工具链)'
    Write-Host '输入格式示例: linux/amd64,windows/amd64,linux/arm64'
    Write-Host '-------------------------------'
}

function Test-TargetFormat {
    <#
    .SYNOPSIS
        验证目标格式是否为 goos/goarch 且在支持列表中。
    .OUTPUTS
        bool
    #>
    param([string]$Target)
    $parts = $Target.Split('/')
    if ($parts.Count -lt 2) { return $false }
    $goos = $parts[0]
    $goarch = $parts[1]
    $osOk = $false
    $archOk = $false
    foreach ($o in $script:ALL_GOOS) {
        if ($o -eq $goos) { $osOk = $true; break }
    }
    foreach ($a in $script:ALL_GOARCH) {
        if ($a -eq $goarch) { $archOk = $true; break }
    }
    return ($osOk -and $archOk)
}

function Require-CommandOrExit {
    <#
    .SYNOPSIS
        检查命令是否存在，若不存在则退出。
    #>
    param(
        [string]$Command,
        [string]$Hint
    )
    $cmdCheck = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $cmdCheck) {
        Write-Host "[Build] 错误：启用 CGO 构建需要命令 '$Command'，但未找到。"
        Write-Host "[Build] 建议安装：$Hint"
        exit 1
    }
}

function Test-CGoDependency {
    <#
    .SYNOPSIS
        检查 CGO 交叉编译依赖。对于 Windows 主机构建 Windows 目标时不
        要求 mingw 交叉编译器，改为检查本机 C 编译器。
    #>
    param([string]$Goos, [string]$Goarch)
    $target = "${Goos}/${Goarch}"

    if ($script:CGO_ENABLED_VALUE -ne 1) {
        return
    }

    # darwin 交叉编译检查
    if ($Goos -eq 'darwin' -and $script:HOST_GOOS -ne 'darwin') {
        Write-Host "[Build] 错误：目标 ${target} 启用 CGO 时通常需要 macOS/完整 osxcross 工具链。"
        Write-Host "[Build] 建议改为关闭 CGO 或在 macOS 环境构建。"
        exit 1
    }

    # *BSD 交叉编译检查
    if ($Goos -eq 'freebsd' -or $Goos -eq 'openbsd' -or $Goos -eq 'netbsd') {
        if ($script:HOST_GOOS -ne $Goos) {
            Write-Host "[Build] 错误：目标 ${target} 启用 CGO 的跨平台工具链未在脚本中内置支持。"
            Write-Host "[Build] 建议改为关闭 CGO，或在对应系统上原生构建。"
            exit 1
        }
    }

    # 本机构建：检查 C 编译器
    if ($Goos -eq $script:HOST_GOOS -and $goarch -eq $script:HOST_GOARCH) {
        $ccFound = $false
        foreach ($cc in @('cc', 'gcc', 'clang')) {
            if (Get-Command $cc -ErrorAction SilentlyContinue) { $ccFound = $true; break }
        }
        # Windows 上额外检查 cl.exe
        if (-not $ccFound -and $script:HOST_GOOS -eq 'windows') {
            if (Get-Command 'cl.exe' -ErrorAction SilentlyContinue) { $ccFound = $true }
        }
        if ($ccFound) { return }
        Write-Host "[Build] 错误：启用 CGO 需要系统 C 编译器（cc/gcc/clang）。"
        Write-Host "[Build] 建议安装：build-essential 或 clang"
        exit 1
    }

    # Windows 主机构建 Windows 目标（非同架构）：使用本机编译器，不需要 mingw
    if ($Goos -eq 'windows' -and $script:HOST_GOOS -eq 'windows') {
        $ccFound = $false
        foreach ($cc in @('cl.exe', 'gcc.exe', 'clang.exe', 'cc', 'gcc', 'clang')) {
            if (Get-Command $cc -ErrorAction SilentlyContinue) { $ccFound = $true; break }
        }
        if ($ccFound) { return }
        Write-Host "[Build] 错误：启用 CGO 构建 Windows 目标需要系统 C 编译器（cl.exe/gcc/clang）。"
        Write-Host "[Build] 建议安装：Visual Studio Build Tools 或 MinGW-w64"
        exit 1
    }

    # Linux 主机 -> Windows/amd64 交叉编译
    if ($Goos -eq 'windows' -and $Goarch -eq 'amd64') {
        Require-CommandOrExit -Command 'x86_64-w64-mingw32-gcc' -Hint 'sudo apt-get install -y mingw-w64'
        return
    }

    # Linux 主机 -> Windows/386 交叉编译
    if ($Goos -eq 'windows' -and $Goarch -eq '386') {
        Require-CommandOrExit -Command 'i686-w64-mingw32-gcc' -Hint 'sudo apt-get install -y mingw-w64'
        return
    }

    # Linux/arm64 交叉（非本机 arm64）
    if ($Goos -eq 'linux' -and $Goarch -eq 'arm64' -and -not ($script:HOST_GOOS -eq 'linux' -and $script:HOST_GOARCH -eq 'arm64')) {
        $aarch64Found = $false
        foreach ($cc in @('aarch64-linux-musl-gcc', 'aarch64-linux-gnu-gcc')) {
            if (Get-Command $cc -ErrorAction SilentlyContinue) { $aarch64Found = $true; break }
        }
        if ($aarch64Found) { return }
        Write-Host "[Build] 错误：目标 ${target} 启用 CGO 需要 aarch64 交叉编译器。"
        Write-Host "[Build] 建议安装：aarch64-linux-musl-gcc 或 aarch64-linux-gnu-gcc"
        exit 1
    }

    # Linux/amd64 交叉（非本机 amd64）
    if ($Goos -eq 'linux' -and $Goarch -eq 'amd64' -and -not ($script:HOST_GOOS -eq 'linux' -and $script:HOST_GOARCH -eq 'amd64')) {
        $x86_64Found = $false
        foreach ($cc in @('x86_64-linux-gnu-gcc', 'musl-gcc')) {
            if (Get-Command $cc -ErrorAction SilentlyContinue) { $x86_64Found = $true; break }
        }
        if ($x86_64Found) { return }
        Write-Host "[Build] 错误：目标 ${target} 启用 CGO 需要 x86_64 Linux 交叉编译器。"
        Write-Host "[Build] 建议安装：x86_64-linux-gnu-gcc 或 musl-gcc"
        exit 1
    }
}

function Get-CrossCompiler {
    <#
    .SYNOPSIS
        返回目标平台的 C 交叉编译器名称。若不需要则返回空字符串。
    #>
    param([string]$Goos, [string]$Goarch)

    if ($script:CGO_ENABLED_VALUE -ne 1) {
        return ''
    }

    # 本机构建
    if ($Goos -eq $script:HOST_GOOS -and $Goarch -eq $script:HOST_GOARCH) {
        return ''
    }

    # Windows 构建 Windows
    if ($Goos -eq 'windows' -and $script:HOST_GOOS -eq 'windows') {
        return ''
    }

    # Windows amd64 交叉编译
    if ($Goos -eq 'windows' -and $Goarch -eq 'amd64') {
        return 'x86_64-w64-mingw32-gcc'
    }

    # Windows 386 交叉编译
    if ($Goos -eq 'windows' -and $Goarch -eq '386') {
        return 'i686-w64-mingw32-gcc'
    }

    # Linux arm64 交叉
    if ($Goos -eq 'linux' -and $Goarch -eq 'arm64' -and -not ($script:HOST_GOOS -eq 'linux' -and $script:HOST_GOARCH -eq 'arm64')) {
        if (Get-Command 'aarch64-linux-musl-gcc' -ErrorAction SilentlyContinue) {
            return 'aarch64-linux-musl-gcc'
        }
        if (Get-Command 'aarch64-linux-gnu-gcc' -ErrorAction SilentlyContinue) {
            return 'aarch64-linux-gnu-gcc'
        }
    }

    # Linux amd64 交叉
    if ($Goos -eq 'linux' -and $Goarch -eq 'amd64' -and -not ($script:HOST_GOOS -eq 'linux' -and $script:HOST_GOARCH -eq 'amd64')) {
        if (Get-Command 'x86_64-linux-gnu-gcc' -ErrorAction SilentlyContinue) {
            return 'x86_64-linux-gnu-gcc'
        }
        if (Get-Command 'musl-gcc' -ErrorAction SilentlyContinue) {
            return 'musl-gcc'
        }
    }

    return ''
}

function Get-BinaryName {
    <#
    .SYNOPSIS
        根据目标和兼容性设置返回可执行文件名。
    #>
    param([string]$Goos)
    if ($script:USE_COMPATIBLE_NAMES -eq 1) {
        if ($Goos -eq 'windows') {
            return 'sealdice-core.exe'
        } else {
            return 'sealdice-core'
        }
    } else {
        if ($Goos -eq 'windows') {
            return 'Scardice-core.exe'
        } else {
            return 'Scardice-core'
        }
    }
}

function Get-ArchivePath {
    <#
    .SYNOPSIS
        返回目标平台的打包文件完整路径。
    #>
    param(
        [string]$Goos,
        [string]$PackageBasename,
        [string]$OutputDir
    )
    if ($Goos -eq 'windows') {
        return Join-Path $OutputDir "${PackageBasename}.zip"
    } else {
        return Join-Path $OutputDir "${PackageBasename}.tar.gz"
    }
}

function Test-SymbolExists {
    <#
    .SYNOPSIS
        检查符号是否存在于源码文件中。优先使用 rg（ripgrep），
        回退到 Select-String。
    #>
    param([string]$Symbol)
    $rgCmd = Get-Command 'rg' -ErrorAction SilentlyContinue
    if ($rgCmd) {
        $null = & rg -q $Symbol ./dice ./main.go 2>$null
        return ($LASTEXITCODE -eq 0)
    }
    # 回退 Select-String
    if (Test-Path './dice') {
        $goFiles = Get-ChildItem -Path './dice' -Recurse -Filter '*.go' -ErrorAction SilentlyContinue
        foreach ($f in $goFiles) {
            $match = Select-String -Path $f.FullName -Pattern $Symbol -SimpleMatch -ErrorAction SilentlyContinue
            if ($match) { return $true }
        }
    }
    if (Test-Path './main.go') {
        $match = Select-String -Path './main.go' -Pattern $Symbol -SimpleMatch -ErrorAction SilentlyContinue
        if ($match) { return $true }
    }
    return $false
}

if ($script:DEV_MODE) {
    Write-Host '[Build] 开发构建模式（--dev）：跳过交互式提示，使用本机默认值'
    $script:VERSION_MAIN = $script:DEFAULT_VERSION_MAIN
    $script:VERSION_PRERELEASE = $script:DEFAULT_VERSION_PRERELEASE
    $script:APP_CHANNEL = $script:DEFAULT_APP_CHANNEL
    $script:APPNAME = $script:DEFAULT_APPNAME
    $script:BUILD_MODE_INPUT = 'single'
    $script:TARGETS = @("${script:HOST_GOOS}/${script:HOST_GOARCH}")
    $script:REDOWNLOAD_RUNTIME_ASSETS = 0
    $script:CGO_ENABLED_VALUE = 0
    $script:USE_COMPATIBLE_NAMES = 0
    $script:USE_UPX = 0
} else {
    # 交互式提示
    $inputVm = Read-Host "请输入 VERSION_MAIN（默认：${script:DEFAULT_VERSION_MAIN}）"
    $script:VERSION_MAIN = if ([string]::IsNullOrWhiteSpace($inputVm)) { $script:DEFAULT_VERSION_MAIN } else { $inputVm }

    $inputVp = Read-Host "请输入 VERSION_PRERELEASE（默认：${script:DEFAULT_VERSION_PRERELEASE}）"
    $script:VERSION_PRERELEASE = if ([string]::IsNullOrWhiteSpace($inputVp)) { $script:DEFAULT_VERSION_PRERELEASE } else { $inputVp }

    $inputAc = Read-Host "请输入 APP_CHANNEL（默认：${script:DEFAULT_APP_CHANNEL}）"
    $script:APP_CHANNEL = if ([string]::IsNullOrWhiteSpace($inputAc)) { $script:DEFAULT_APP_CHANNEL } else { $inputAc }

    $inputAn = Read-Host "请输入 APPNAME（默认：${script:DEFAULT_APPNAME}）"
    $script:APPNAME = if ([string]::IsNullOrWhiteSpace($inputAn)) { $script:DEFAULT_APPNAME } else { $inputAn }

    $buildModeInput = Read-Host "请选择构建模式 [single/multi]（默认：single，可输入 s/m）"
    if ([string]::IsNullOrWhiteSpace($buildModeInput)) {
        $script:BUILD_MODE_INPUT = 'single'
    } else {
        switch ($buildModeInput) {
            's' { $script:BUILD_MODE_INPUT = 'single' }
            'S' { $script:BUILD_MODE_INPUT = 'single' }
            'm' { $script:BUILD_MODE_INPUT = 'multi' }
            'M' { $script:BUILD_MODE_INPUT = 'multi' }
            default { $script:BUILD_MODE_INPUT = $buildModeInput }
        }
    }
    if ($script:BUILD_MODE_INPUT -ne 'single' -and $script:BUILD_MODE_INPUT -ne 'multi') {
        Write-Host '[Build] 错误：构建模式必须是 single 或 multi'
        exit 1
    }

    if ($script:BUILD_MODE_INPUT -eq 'single') {
        $selectedGoos = Show-Menu -Prompt '请选择目标 GOOS:' -DefaultValue $script:DEFAULT_TARGET_GOOS -Options $script:ALL_GOOS
        $selectedGoarch = Show-Menu -Prompt '请选择目标 GOARCH:' -DefaultValue $script:DEFAULT_TARGET_GOARCH -Options $script:ALL_GOARCH
        $script:TARGETS = @("${selectedGoos}/${selectedGoarch}")
    } else {
        Write-MultiTargetGuide
        $multiInput = Read-Host '请输入 multi 目标（goos/goarch,...）'
        $multiInput = $multiInput -replace '\s', ''
        if ([string]::IsNullOrWhiteSpace($multiInput)) {
            Write-Host '[Build] 错误：multi 模式至少需要一个目标'
            exit 1
        }
        $rawTargets = $multiInput -split ','
        foreach ($rawTarget in $rawTargets) {
            if ($rawTarget -notlike '*/*') {
                Write-Host "[Build] 错误：目标格式无效: ${rawTarget}（应为 goos/goarch）"
                exit 1
            }
            if (-not (Test-TargetFormat $rawTarget)) {
                Write-Host "[Build] 错误：目标不在理论支持列表内: ${rawTarget}"
                exit 1
            }
            $script:TARGETS += $rawTarget
        }
    }

    # 询问是否重新下载运行时缓存
    if ($script:PACK_RUNTIME_ASSETS -eq 1 -and (Test-RuntimeAssetCacheForTargets $script:TARGETS)) {
        $redownloadInput = Read-Host '是否重新下载内置客户端文件 [y/N]'
        if ($redownloadInput -match '^[Yy]$') {
            $script:REDOWNLOAD_RUNTIME_ASSETS = 1
        } else {
            $script:REDOWNLOAD_RUNTIME_ASSETS = 0
        }
    } else {
        $script:REDOWNLOAD_RUNTIME_ASSETS = 1
    }

    # 询问 CGO
    $cgoInput = Read-Host '是否启用 CGO？[y/N]'
    if ($cgoInput -match '^[Yy]$') {
        $script:CGO_ENABLED_VALUE = 1
    } else {
        $script:CGO_ENABLED_VALUE = 0
    }

    # 询问兼容名称
    $compatInput = Read-Host '使用兼容的lock和可执行文件文件名？[y/N]'
    if ($compatInput -match '^[Yy]$') {
        $script:USE_COMPATIBLE_NAMES = 1
    } else {
        $script:USE_COMPATIBLE_NAMES = 0
    }

    # UPX
    if (-not [string]::IsNullOrWhiteSpace($script:UPX_CMD)) {
        $upxInput = Read-Host '是否使用 UPX 压缩二进制文件？[Y/n]'
        if ($upxInput -match '^[Nn]$') {
            $script:USE_UPX = 0
        } else {
            $script:USE_UPX = 1
        }
    } else {
        Write-Host '[Build] 未在系统中找到 upx 命令，将跳过压缩步骤询问。'
        $script:USE_UPX = 0
    }
}

# CGO 依赖预检查
if ($script:CGO_ENABLED_VALUE -eq 1) {
    Write-Host '[Build] 预检查 CGO 依赖...'
    foreach ($target in $script:TARGETS) {
        $parts = $target.Split('/')
        $targetGoos = $parts[0]
        $targetGoarch = $parts[1]
        Test-CGoDependency -Goos $targetGoos -Goarch $targetGoarch
    }
}

# 版本与构建元数据
$CUR_TIME = Get-Date -Format 'yyyyMMdd'
$gitHash = & git rev-parse --short=7 HEAD 2>$null
if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gitHash)) {
    $VERSION_BUILD_METADATA = "+${CUR_TIME}.$($gitHash.Trim())"
} else {
    $VERSION_BUILD_METADATA = "+${CUR_TIME}.nogit"
}

# SealTrustedClientPrivateKey
if (Test-Path $script:PRIVATE_KEY_FILE) {
    $pkItem = Get-Item $script:PRIVATE_KEY_FILE -ErrorAction SilentlyContinue
    if ($pkItem -and $pkItem.Length -gt 0) {
        Write-Host "[Build] 已找到可信私钥文件：$($script:PRIVATE_KEY_FILE)"
        $script:PRIVATE_KEY_CONTENT_B64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($script:PRIVATE_KEY_FILE))
    } else {
        Write-Host "[Build] 警告：可信私钥文件不存在或为空，跳过注入：$($script:PRIVATE_KEY_FILE)"
    }
} else {
    Write-Host "[Build] 警告：可信私钥文件不存在或为空，跳过注入：$($script:PRIVATE_KEY_FILE)"
}

# SealSignClientPrivateKey
if (Test-Path $script:SIGN_KEY_FILE) {
    $skItem = Get-Item $script:SIGN_KEY_FILE -ErrorAction SilentlyContinue
    if ($skItem -and $skItem.Length -gt 0) {
        Write-Host "[Build] 已找到签名私钥文件：$($script:SIGN_KEY_FILE)"
        $content = Get-Content $script:SIGN_KEY_FILE -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $script:SIGN_KEY_CONTENT = $content -replace '\s', ''
        }
    } else {
        Write-Host "[Build] 警告：签名私钥文件不存在或为空，跳过注入：$($script:SIGN_KEY_FILE)"
    }
} else {
    Write-Host "[Build] 警告：签名私钥文件不存在或为空，跳过注入：$($script:SIGN_KEY_FILE)"
}

# SealSignV3Url
if (Test-Path $script:SIGN_V3_URL_FILE) {
    $sv3Item = Get-Item $script:SIGN_V3_URL_FILE -ErrorAction SilentlyContinue
    if ($sv3Item -and $sv3Item.Length -gt 0) {
        Write-Host "[Build] 已找到签名服务 V3 URL 文件：$($script:SIGN_V3_URL_FILE)"
        $content = Get-Content $script:SIGN_V3_URL_FILE -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $script:SIGN_V3_URL_CONTENT = $content -replace '\s', ''
        }
    } else {
        Write-Host "[Build] 警告：签名服务 V3 URL 文件不存在或为空，跳过注入：$($script:SIGN_V3_URL_FILE)"
    }
} else {
    Write-Host "[Build] 警告：签名服务 V3 URL 文件不存在或为空，跳过注入：$($script:SIGN_V3_URL_FILE)"
}

# LDFLAGS
$LDFLAGS = '-s -w'
$LDFLAGS += " -X Scardice-core/dice.VERSION_MAIN=${script:VERSION_MAIN}"
$LDFLAGS += " -X Scardice-core/dice.VERSION_PRERELEASE=${script:VERSION_PRERELEASE}"
$LDFLAGS += " -X Scardice-core/dice.VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
$LDFLAGS += " -X Scardice-core/dice.APP_CHANNEL=${script:APP_CHANNEL}"
$LDFLAGS += " -X Scardice-core/dice.APPNAME=${script:APPNAME}"

if ($script:USE_COMPATIBLE_NAMES -eq 1) {
    $LDFLAGS += ' -X main.LockFileName=sealdice-core.lock'
}

if (-not [string]::IsNullOrWhiteSpace($script:PRIVATE_KEY_CONTENT_B64) -and (Test-SymbolExists 'SealTrustedClientPrivateKey')) {
    $LDFLAGS += " -X 'Scardice-core/dice.SealTrustedClientPrivateKey=base64:${script:PRIVATE_KEY_CONTENT_B64}'"
    Write-Host '[Build] 已通过 ldflags 以 base64 形式注入 SealTrustedClientPrivateKey'
} else {
    Write-Host '[Build] 警告：未找到 SealTrustedClientPrivateKey 符号或内容为空，跳过私钥注入'
}

if (-not [string]::IsNullOrWhiteSpace($script:SIGN_KEY_CONTENT) -and (Test-SymbolExists 'SealSignClientPrivateKey')) {
    $LDFLAGS += " -X 'Scardice-core/dice.SealSignClientPrivateKey=${script:SIGN_KEY_CONTENT}'"
    Write-Host '[Build] 已通过 ldflags 注入 SealSignClientPrivateKey'
} else {
    Write-Host '[Build] 警告：未找到 SealSignClientPrivateKey 符号或内容为空，跳过注入'
}

if (-not [string]::IsNullOrWhiteSpace($script:SIGN_V3_URL_CONTENT) -and (Test-SymbolExists 'SealSignV3Url')) {
    $LDFLAGS += " -X 'Scardice-core/dice.SealSignV3Url=${script:SIGN_V3_URL_CONTENT}'"
    Write-Host '[Build] 已通过 ldflags 注入 SealSignV3Url'
} else {
    Write-Host '[Build] 警告：未找到 SealSignV3Url 符号或内容为空，跳过注入'
}

# 构建信息输出
Write-Host "[Build] VERSION_MAIN=${script:VERSION_MAIN}"
Write-Host "[Build] VERSION_PRERELEASE=${script:VERSION_PRERELEASE}"
Write-Host "[Build] VERSION_BUILD_METADATA=${VERSION_BUILD_METADATA}"
Write-Host "[Build] APP_CHANNEL=${script:APP_CHANNEL}"
Write-Host "[Build] APPNAME=${script:APPNAME}"
Write-Host "[Build] BUILD_MODE=${script:BUILD_MODE_INPUT}"
Write-Host "[Build] TARGETS=$(Join-ByComma $script:TARGETS)"
Write-Host "[Build] CGO_ENABLED=${script:CGO_ENABLED_VALUE}"
Write-Host "[Build] USE_COMPATIBLE_NAMES=${script:USE_COMPATIBLE_NAMES}"
if ($script:USE_COMPATIBLE_NAMES -eq 1) {
    Write-Host '[Build] LOCK_FILE_NAME=sealdice-core.lock'
} else {
    Write-Host '[Build] LOCK_FILE_NAME=Scardice-lock.lock'
}

# Go 缓存目录
New-Item -ItemType Directory -Force -Path $script:GO_CACHE_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $script:GO_TMP_DIR | Out-Null
$env:GOCACHE = if ($env:GOCACHE) { $env:GOCACHE } else { $script:GO_CACHE_DIR }
$env:TMPDIR = if ($env:TMPDIR) { $env:TMPDIR } else { $script:GO_TMP_DIR }
Write-Host "[Build] GOCACHE=${env:GOCACHE}"
Write-Host "[Build] TMPDIR=${env:TMPDIR}"

# 开发构建（--dev）
if ($script:DEV_MODE) {
    $devBinaryName = Get-BinaryName -Goos $script:HOST_GOOS
    $devBinaryPath = Join-Path $script:ROOT_DIR $devBinaryName
    Write-Host "[Build] --dev 仅构建本机可执行文件：${devBinaryPath}"

    $env:GOOS = $script:HOST_GOOS
    $env:GOARCH = $script:HOST_GOARCH
    $env:CGO_ENABLED = $script:CGO_ENABLED_VALUE
    ExecSafe { go build -trimpath -ldflags $LDFLAGS -o $devBinaryPath . }

    # chmod（非 Windows ）
    if ($script:HOST_GOOS -ne 'windows') {
        $chmodCmd = Get-Command 'chmod' -ErrorAction SilentlyContinue
        if ($chmodCmd) {
            $null = & chmod +x $devBinaryPath 2>$null
        }
    }

    $fi = Get-Item $devBinaryPath -ErrorAction SilentlyContinue
    if ($fi) {
        Write-Host "[Build] 二进制文件大小：$($fi.Length) 字节"
    }
    exit 0
}


Write-Host '[Build] 更新 submodule 到远端最新提交'
ExecSafe { git submodule update --init --recursive --remote }

if (-not (Test-Path (Join-Path $script:UI_SUBMODULE_DIR 'package.json'))) {
    Write-Host "[Build] 错误：未找到 UI 子模块目录或 package.json：$($script:UI_SUBMODULE_DIR)"
    exit 1
}

$builtinsDataDir = Join-Path $script:BUILTINS_SUBMODULE_DIR 'data'
if (-not (Test-Path $builtinsDataDir)) {
    Write-Host "[Build] 错误：未找到内置资源目录：${builtinsDataDir}"
    exit 1
}

# UI 构建标记
$uiCommit = & git -C $script:UI_SUBMODULE_DIR rev-parse HEAD 2>$null
if ($LASTEXITCODE -ne 0) { $uiCommit = 'unknown' }
$uiCommit = $uiCommit.Trim()

$lockHash = ''
$pnpmLock = Join-Path $script:UI_SUBMODULE_DIR 'pnpm-lock.yaml'
$npmLock = Join-Path $script:UI_SUBMODULE_DIR 'package-lock.json'
$pkgJson = Join-Path $script:UI_SUBMODULE_DIR 'package.json'

if (Test-Path $pnpmLock) {
    $lockHash = Get-CalcFileHash -FilePath $pnpmLock
} elseif (Test-Path $npmLock) {
    $lockHash = Get-CalcFileHash -FilePath $npmLock
} else {
    $lockHash = Get-CalcFileHash -FilePath $pkgJson
}

$UI_MARKER_EXPECTED = "ui_commit=${uiCommit};lock_hash=${lockHash}"
$UI_BUILD_NEEDED = 1
$uiBuildMarkerDir = Split-Path $script:UI_BUILD_MARKER -Parent
$uiDistIndex = Join-Path $script:UI_SUBMODULE_DIR 'dist/index.html'

if ((Test-Path $script:UI_BUILD_MARKER) -and (Test-Path $uiDistIndex)) {
    $markerCurrent = Get-Content $script:UI_BUILD_MARKER -Raw -ErrorAction SilentlyContinue
    if ($markerCurrent) {
        $markerCurrent = $markerCurrent.Trim()
        if ($markerCurrent -eq $UI_MARKER_EXPECTED) {
            $UI_BUILD_NEEDED = 0
        }
    }
}

if ($UI_BUILD_NEEDED -eq 0) {
    Write-Host '[Build] Scardice-ui 已是最新构建，跳过构建'
} else {
    Write-Host '[Build] 构建 Scardice-ui'

    $pnpmCmd = Get-Command 'pnpm' -ErrorAction SilentlyContinue
    if (-not $pnpmCmd) {
        $npmCmd = Get-Command 'npm' -ErrorAction SilentlyContinue
        if ($npmCmd) {
            Write-Host '[Build] 未检测到 pnpm，正在通过 npm 全局安装 pnpm'
            ExecSafe { npm install -g pnpm }
        } else {
            Write-Host '[Build] 错误：未找到 pnpm 或 npm，无法构建 UI'
            exit 1
        }
    }

    $pnpmCmd = Get-Command 'pnpm' -ErrorAction SilentlyContinue
    if ($pnpmCmd) {
        Push-Location $script:UI_SUBMODULE_DIR
        try {
            ExecSafe { pnpm install --frozen-lockfile }
            ExecSafe { pnpm build }
        } finally {
            Pop-Location
        }
    } else {
        Write-Host '[Build] 错误：未找到 pnpm 或 npm，无法构建 UI'
        exit 1
    }

    $uiDistDir = Join-Path $script:UI_SUBMODULE_DIR 'dist'
    if (-not (Test-Path $uiDistDir)) {
        Write-Host "[Build] 错误：UI 构建完成但 dist 目录不存在：${uiDistDir}"
        exit 1
    }
    Set-Content -Path $script:UI_BUILD_MARKER -Value $UI_MARKER_EXPECTED -Encoding ASCII -Force
}

Write-Host '[Build] 同步 UI 资源到 static/frontend'
Remove-Item -Recurse -Force -Path $script:STATIC_FRONTEND_DIR -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $script:STATIC_FRONTEND_DIR | Out-Null
Get-ChildItem -Path (Join-Path $script:UI_SUBMODULE_DIR 'dist') | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $script:STATIC_FRONTEND_DIR -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $script:OUTPUT_DIR | Out-Null
Remove-Item -Recurse -Force -Path (Join-Path $script:OUTPUT_DIR '*') -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force -Path $script:PACKAGE_WORK_DIR -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $script:PACKAGE_WORK_DIR | Out-Null

$ARCHIVES = @()

foreach ($target in $script:TARGETS) {
    $parts = $target.Split('/')
    $TARGET_GOOS = $parts[0]
    $TARGET_GOARCH = $parts[1]

    $BINARY_NAME = Get-BinaryName -Goos $TARGET_GOOS
    $TARGET_WORK_DIR = Join-Path $script:PACKAGE_WORK_DIR "${TARGET_GOOS}-${TARGET_GOARCH}"
    $BINARY_PATH = Join-Path $TARGET_WORK_DIR $BINARY_NAME
    $PACKAGE_BASENAME = "Scardice_${script:VERSION_MAIN}${script:VERSION_PRERELEASE}_${TARGET_GOOS}_${TARGET_GOARCH}"
    $PACKAGE_DIR = Join-Path $TARGET_WORK_DIR $PACKAGE_BASENAME
    $CC_VALUE = Get-CrossCompiler -Goos $TARGET_GOOS -Goarch $TARGET_GOARCH

    Write-Host "[Build] 开始 go build: ${target}"
    Remove-Item -Recurse -Force -Path $TARGET_WORK_DIR -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $TARGET_WORK_DIR | Out-Null

    $env:GOOS = $TARGET_GOOS
    $env:GOARCH = $TARGET_GOARCH
    $env:CGO_ENABLED = $script:CGO_ENABLED_VALUE
    if (-not [string]::IsNullOrWhiteSpace($CC_VALUE)) {
        Write-Host "[Build] 使用交叉编译器 CC=${CC_VALUE}"
        $env:CC = $CC_VALUE
        ExecSafe { go build -trimpath -ldflags $LDFLAGS -o $BINARY_PATH . }
    } else {
        # 清除 CC 环境变量
        $env:CC = ''
        ExecSafe { go build -trimpath -ldflags $LDFLAGS -o $BINARY_PATH . }
    }

    # UPX 压缩
    if ($script:USE_UPX -eq 1 -and -not [string]::IsNullOrWhiteSpace($script:UPX_CMD)) {
        Write-Host "[Build] 正在对 ${BINARY_NAME} 进行 UPX 压缩..."
        $null = & $script:UPX_CMD -q $BINARY_PATH 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[Build] 警告：UPX 压缩失败，跳过压缩'
        }
    }

    Write-Host "[Build] 组装发布目录：${PACKAGE_DIR}"
    Remove-Item -Recurse -Force -Path $PACKAGE_DIR -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path (Join-Path $PACKAGE_DIR 'data') | Out-Null
    Copy-Item -Path $BINARY_PATH -Destination (Join-Path $PACKAGE_DIR $BINARY_NAME) -Force
    Get-ChildItem -Path $builtinsDataDir | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination (Join-Path $PACKAGE_DIR 'data') -Recurse -Force
    }

    # 运行时资源
    Invoke-PrepareRuntimeAssets -Goos $TARGET_GOOS -Goarch $TARGET_GOARCH
    Copy-RuntimeTreeIfPresent -SourcePath $script:TARGET_LAGRANGE_DIR -DestinationPath (Join-Path $PACKAGE_DIR 'lagrange') -Label "Lagrange ${TARGET_GOOS}/${TARGET_GOARCH}"
    Copy-RuntimeTreeIfPresent -SourcePath $script:TARGET_MILKY_DIR -DestinationPath (Join-Path $PACKAGE_DIR 'milky') -Label "Milky ${TARGET_GOOS}/${TARGET_GOARCH}"
    Copy-RuntimeTreeIfPresent -SourcePath $script:TARGET_YOGURT_DIR -DestinationPath (Join-Path $PACKAGE_DIR 'milky') -Label "Yogurt ${TARGET_GOOS}/${TARGET_GOARCH}"

    # chmod（非 Windows ）
    if ($TARGET_GOOS -ne 'windows') {
        $chmodCmd = Get-Command 'chmod' -ErrorAction SilentlyContinue
        if ($chmodCmd) {
            $null = & chmod +x (Join-Path $PACKAGE_DIR $BINARY_NAME) 2>$null
            $lagrangePath = Join-Path $PACKAGE_DIR 'lagrange/Lagrange.OneBot'
            if (Test-Path $lagrangePath) { $null = & chmod +x $lagrangePath 2>$null }
            $milkyLagrangePath = Join-Path $PACKAGE_DIR 'milky/lagrangeV2'
            if (Test-Path $milkyLagrangePath) { $null = & chmod +x $milkyLagrangePath 2>$null }
            $yogurtPath = Join-Path $PACKAGE_DIR 'milky/yogurt'
            if (Test-Path $yogurtPath) { $null = & chmod +x $yogurtPath 2>$null }
        }
    }

    # 打包
    $ARCHIVE_PATH = Get-ArchivePath -Goos $TARGET_GOOS -PackageBasename $PACKAGE_BASENAME -OutputDir $script:OUTPUT_DIR
    Remove-Item -Force -Path $ARCHIVE_PATH -ErrorAction SilentlyContinue

    if ($TARGET_GOOS -eq 'windows') {
        # Windows: 创建 .zip
        # 优先使用 tar -a
        $tarCmd = Get-Command 'tar' -ErrorAction SilentlyContinue
        if ($tarCmd) {
            Push-Location $TARGET_WORK_DIR
            try {
                & tar -a -cf $ARCHIVE_PATH $PACKAGE_BASENAME 2>$null
                if ($LASTEXITCODE -ne 0) { throw 'tar -a failed' }
            } catch {
                # 回退到 zip
                $zipCmd = Get-Command 'zip' -ErrorAction SilentlyContinue
                if ($zipCmd) {
                    $null = & zip -rq (Join-Path $TARGET_WORK_DIR "${PACKAGE_BASENAME}.zip") $PACKAGE_BASENAME
                    Move-Item -Force -Path (Join-Path $TARGET_WORK_DIR "${PACKAGE_BASENAME}.zip") -Destination $ARCHIVE_PATH
                } else {
                    # 最后回退到 Compress-Archive
                    Compress-Archive -Path (Join-Path $TARGET_WORK_DIR $PACKAGE_BASENAME) -DestinationPath $ARCHIVE_PATH -Force
                }
            } finally {
                Pop-Location
            }
        } else {
            $zipCmd = Get-Command 'zip' -ErrorAction SilentlyContinue
            if ($zipCmd) {
                Push-Location $TARGET_WORK_DIR
                try {
                    $null = & zip -rq (Join-Path $TARGET_WORK_DIR "${PACKAGE_BASENAME}.zip") $PACKAGE_BASENAME
                    Move-Item -Force -Path (Join-Path $TARGET_WORK_DIR "${PACKAGE_BASENAME}.zip") -Destination $ARCHIVE_PATH
                } finally {
                    Pop-Location
                }
            } else {
                Compress-Archive -Path (Join-Path $TARGET_WORK_DIR $PACKAGE_BASENAME) -DestinationPath $ARCHIVE_PATH -Force
            }
        }
    } else {
        # 非 Windows: 创建 .tar.gz
        Push-Location $TARGET_WORK_DIR
        try {
            & tar -zcf $ARCHIVE_PATH $PACKAGE_BASENAME
        } finally {
            Pop-Location
        }
    }

    $ARCHIVES += $ARCHIVE_PATH
}

Remove-Item -Recurse -Force -Path $script:PACKAGE_WORK_DIR -ErrorAction SilentlyContinue
Write-Host "[Build] 打包完成，共 $($ARCHIVES.Count) 个文件："
foreach ($archive in $ARCHIVES) {
    Write-Host "  - ${archive}"
}
