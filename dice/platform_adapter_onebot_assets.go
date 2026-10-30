package dice

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const (
	OnebotAssetInlineThreshold = 200 * 1024       // 200KB，小于此值 base64 内嵌
	OnebotAssetMaxSize         = 10 * 1024 * 1024 // 10MB 硬上限，拒绝超大文件防 OOM
)

// onebotAssetInlineThreshold / onebotAssetMaxSize 为包内兼容别名。
const onebotAssetInlineThreshold = OnebotAssetInlineThreshold
const onebotAssetMaxSize = OnebotAssetMaxSize

// onebotAssetResolver 把 data/ 下的本地资源转换成 OneBot 协议端可访问的形式。
// 它只持有显式传入的资源配置，不依赖 Dice、会话或端点。
type onebotAssetResolver struct {
	ImageAssetBaseURL string
	assetRoot         string
	assetImageToken   string
	assetServeAddress string
	logger            *zap.SugaredLogger

	derivedURLMu         sync.Mutex
	cachedDerivedBaseURL string
}

// deriveImageAssetBaseURL 在用户未显式配置 ImageAssetBaseURL 时，
// 从资源服务地址提取端口 + 枚举非 loopback IPv4，自动推导出协议端可访问的 base URL。
// 结果缓存；返回值不含末尾斜杠，形如 "http://172.21.0.5:3211"。
func (p *onebotAssetResolver) deriveImageAssetBaseURL() string {
	p.derivedURLMu.Lock()
	defer p.derivedURLMu.Unlock()
	if p.cachedDerivedBaseURL != "" {
		return p.cachedDerivedBaseURL
	}
	url, _ := p.computeDerivedBaseURL(true)
	p.cachedDerivedBaseURL = url
	return url
}

// DeriveImageAssetBaseURLForDisplay 仅供 API/UI 展示用，不写缓存，额外返回候选 IP 列表。
// 当用户已显式配置 ImageAssetBaseURL 时，返回 (用户配置值, nil)。
func (p *onebotAssetResolver) DeriveImageAssetBaseURLForDisplay() (string, []string) {
	if p.ImageAssetBaseURL != "" {
		return p.ImageAssetBaseURL, nil
	}
	return p.computeDerivedBaseURL(false)
}

// invalidateDerivedBaseURL 清空自动推导缓存。
func (p *onebotAssetResolver) invalidateDerivedBaseURL() {
	p.derivedURLMu.Lock()
	defer p.derivedURLMu.Unlock()
	p.cachedDerivedBaseURL = ""
}

// InvalidateDerivedBaseURL 是 invalidateDerivedBaseURL 的 exported 版本。
func (p *onebotAssetResolver) InvalidateDerivedBaseURL() {
	p.invalidateDerivedBaseURL()
}

// computeDerivedBaseURL 是底层推导逻辑。
// 参数 withWarn：首次推导时是否打 warn 日志（列出候选+选中+提示）。
// 返回 (选中的 baseURL, 候选 IP 列表)。
func (p *onebotAssetResolver) computeDerivedBaseURL(withWarn bool) (string, []string) {
	port := p.extractServePort()
	candidates := enumNonLoopbackIPv4()
	if len(candidates) == 0 {
		if withWarn && p.logger != nil {
			p.logger.Warnf("OneBot 自动推导 ImageAssetBaseURL: 未找到非 loopback IPv4，使用 127.0.0.1 兜底（跨容器场景需手动配置 imageAssetBaseUrl）")
		}
		return "http://127.0.0.1:" + port, nil
	}
	chosen := candidates[0]
	if withWarn && p.logger != nil {
		p.logger.Warnf("OneBot 自动推导 ImageAssetBaseURL: 选中 http://%s:%s（候选: %s）。如协议端无法访问请手动配置 imageAssetBaseUrl",
			chosen, port, strings.Join(candidates, ", "))
	}
	return "http://" + chosen + ":" + port, candidates
}

// extractServePort 从运行时资源服务地址提取端口，默认 3211。
func (p *onebotAssetResolver) extractServePort() string {
	addr := strings.TrimSpace(p.assetServeAddress)
	if addr == "" {
		return "3211"
	}
	// 形如 0.0.0.0:3211 / 127.0.0.1:3211 / :3211
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "3211"
	}
	// SplitHostPort 对 "1.2.3.4:notaport" 会返回 port="notaport"，需校验数字
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "3211"
	}
	return port
}

// enumNonLoopbackIPv4 枚举当前容器内所有非 loopback、非 link-local 的 IPv4 地址。
// 过滤 docker0 默认网关 172.17.0.1，返回排序稳定的 IP 字符串列表。
func enumNonLoopbackIPv4() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		v4 := ipNet.IP.To4()
		if v4 == nil {
			continue
		}
		// 过滤 link-local 169.254.0.0/16
		if v4[0] == 169 && v4[1] == 254 {
			continue
		}
		// 过滤 docker0 默认网关 172.17.0.1（非容器自身 IP）
		if v4[0] == 172 && v4[1] == 17 && v4[2] == 0 && v4[3] == 1 {
			continue
		}
		out = append(out, v4.String())
	}
	return out
}

// resolveLocalAsset 将 data/ 下的本地资源解析为 OneBot 协议端可访问的形式：
//   - ≤ 200KB: base64 内嵌
//   - > 200KB 且配置了 ImageAssetBaseURL: HTTP URL
//   - > 200KB 未配置: 降级 base64（warn 日志）
//
// 相对路径、data/ 前缀、file URL 和 data/ 内的绝对路径均会归一化；
// 路径最终必须落在 data/ 下，拒绝穿越和符号链接逃逸。
func (p *onebotAssetResolver) resolveLocalAsset(reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", errors.New("empty local asset path")
	}

	localPath := reference
	if strings.HasPrefix(strings.ToLower(reference), "file://") {
		parsed, err := url.Parse(reference)
		if err != nil || !strings.EqualFold(parsed.Scheme, "file") || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost")) {
			return "", fmt.Errorf("invalid local asset file URL: %s", reference)
		}
		localPath = filepath.FromSlash(parsed.Path)
		if runtime.GOOS == "windows" && len(localPath) >= 3 && localPath[0] == filepath.Separator && localPath[2] == ':' {
			localPath = localPath[1:]
		}
	} else if hasURLScheme(reference) {
		return "", fmt.Errorf("unsupported local asset scheme: %s", reference)
	}

	rootPath := strings.TrimSpace(p.assetRoot)
	if rootPath == "" {
		rootPath = filepath.Join(".", "data")
	}
	rootPath, err := filepath.Abs(rootPath)
	if err != nil {
		return "", fmt.Errorf("resolve data root: %w", err)
	}
	absRootData, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return "", fmt.Errorf("resolve data root: %w", err)
	}

	var candidate string
	if filepath.IsAbs(localPath) {
		candidate = filepath.Clean(localPath)
	} else {
		localPath = filepath.FromSlash(strings.TrimPrefix(localPath, "./"))
		localPath = filepath.Clean(localPath)
		if localPath == "data" {
			return "", errors.New("refuse data root")
		}
		dataPrefix := "data" + string(filepath.Separator)
		localPath = strings.TrimPrefix(localPath, dataPrefix)
		if localPath == ".." || strings.HasPrefix(localPath, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("path outside data: %s", reference)
		}
		candidate = filepath.Join(absRootData, localPath)
	}

	absFile, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("eval symlinks failed: %w", err)
	}
	relativePath, err := filepath.Rel(absRootData, absFile)
	if err != nil || relativePath == "." || relativePath == ".." ||
		strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		if filepath.IsAbs(localPath) {
			return "", fmt.Errorf("refuse absolute path outside data: %s", reference)
		}
		return "", fmt.Errorf("path escapes data after symlink resolution: %s -> %s", reference, absFile)
	}

	info, err := os.Stat(absFile)
	if err != nil {
		return "", fmt.Errorf("stat failed: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("is directory: %s", reference)
	}
	if info.Size() > onebotAssetMaxSize {
		return "", fmt.Errorf("file too large: %d bytes (max %d)", info.Size(), onebotAssetMaxSize)
	}

	if info.Size() <= onebotAssetInlineThreshold {
		data, err := os.ReadFile(absFile)
		if err != nil {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return "base64://" + base64.StdEncoding.EncodeToString(data), nil
	}

	token := strings.TrimSpace(p.assetImageToken)
	baseURL := p.ImageAssetBaseURL
	if baseURL == "" && token != "" {
		baseURL = p.deriveImageAssetBaseURL()
	}
	if baseURL == "" || token == "" {
		if p.logger != nil {
			p.logger.Warnf("OneBot 资源 %s 大小 %d 超阈值但 baseURL/token 不可用（baseURL=%q token=%d），使用 base64",
				relativePath, info.Size(), baseURL, len(token))
		}
		data, err := os.ReadFile(absFile)
		if err != nil {
			return "", fmt.Errorf("read failed: %w", err)
		}
		return "base64://" + base64.StdEncoding.EncodeToString(data), nil
	}
	resourceURL, err := url.JoinPath(
		strings.TrimRight(baseURL, "/"),
		"assets-img",
		token,
		filepath.ToSlash(relativePath),
	)
	if err != nil {
		return "", fmt.Errorf("build asset URL failed: %w", err)
	}
	return resourceURL, nil
}
