package dice

import (
	"net"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

func TestEnumNonLoopbackIPv4_Filters(t *testing.T) {
	// enumNonLoopbackIPv4 依赖系统网卡，此处仅验证过滤规则：
	// 构造一批 IP，手动复现过滤逻辑验证。
	cases := []struct {
		name     string
		ip       string
		filtered bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 alt", "127.0.0.2", true},
		{"link-local", "169.254.1.1", true},
		{"docker0 gw", "172.17.0.1", true},
		{"normal container ip", "172.21.0.5", false},
		{"normal lan ip", "192.168.1.10", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip).To4()
		if ip == nil {
			t.Fatalf("%s: parse failed", c.ip)
		}
		loopback := ip.IsLoopback()
		linkLocal := ip[0] == 169 && ip[1] == 254
		dockerGw := ip[0] == 172 && ip[1] == 17 && ip[2] == 0 && ip[3] == 1
		gotFiltered := loopback || linkLocal || dockerGw
		if gotFiltered != c.filtered {
			t.Errorf("%s: expected filtered=%v, got %v", c.name, c.filtered, gotFiltered)
		}
	}
}

func TestExtractServePort_DefaultAndParsed(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"", "3211"},
		{"0.0.0.0:3211", "3211"},
		{"127.0.0.1:3211", "3211"},
		{":3211", "3211"},
		{"0.0.0.0:8080", "8080"},
		{"invalid", "3211"},
		{"1.2.3.4:notaport", "3211"},
	}
	for _, c := range cases {
		p := &PlatformAdapterOnebot{
			Session: &IMSession{
				Parent: &Dice{
					Parent: &DiceManager{ServeAddress: c.addr},
				},
			},
			logger: zap.NewNop().Sugar(),
		}
		got := p.extractServePort()
		if got != c.want {
			t.Errorf("addr=%q: want port %q, got %q", c.addr, c.want, got)
		}
	}
}

func TestDeriveImageAssetBaseURL_UserConfigWins(t *testing.T) {
	p := &PlatformAdapterOnebot{
		ImageAssetBaseURL: "http://user-configured:9999",
		Session: &IMSession{
			Parent: &Dice{Parent: &DiceManager{ServeAddress: "0.0.0.0:3211"}},
		},
		logger: zap.NewNop().Sugar(),
	}
	url, candidates := p.DeriveImageAssetBaseURLForDisplay()
	if url != "http://user-configured:9999" {
		t.Errorf("user config should win, got %q", url)
	}
	if candidates != nil {
		t.Errorf("candidates should be nil when user configured, got %v", candidates)
	}
}

func TestDeriveImageAssetBaseURL_AutoFallbackToLoopback(t *testing.T) {
	// 在无网卡或仅有 loopback 的测试环境，自动推导应兜底 127.0.0.1
	p := &PlatformAdapterOnebot{
		Session: &IMSession{
			Parent: &Dice{Parent: &DiceManager{ServeAddress: "0.0.0.0:3211"}},
		},
		logger: zap.NewNop().Sugar(),
	}
	url, candidates := p.DeriveImageAssetBaseURLForDisplay()
	// 不能假设测试环境必然无 IPv4，但 url 必须是 http:// 开头 + 端口 3211
	if !strings.HasPrefix(url, "http://") {
		t.Errorf("url should start with http://, got %q", url)
	}
	if !strings.HasSuffix(url, ":3211") {
		t.Errorf("url should end with :3211, got %q", url)
	}
	// 如果有候选，candidates 非空；如果兜底，candidates 应为 nil
	if candidates != nil && len(candidates) == 0 {
		t.Error("candidates should be nil or non-empty, not empty slice")
	}
}

func TestInvalidateDerivedBaseURL_ResetsCache(t *testing.T) {
	p := &PlatformAdapterOnebot{
		Session: &IMSession{
			Parent: &Dice{Parent: &DiceManager{ServeAddress: "0.0.0.0:3211"}},
		},
		logger: zap.NewNop().Sugar(),
	}
	// 第一次推导，写入缓存
	url1 := p.deriveImageAssetBaseURL()
	if url1 == "" {
		t.Fatal("first derive returned empty")
	}
	if p.cachedDerivedBaseURL != url1 {
		t.Errorf("cache should hold %q, got %q", url1, p.cachedDerivedBaseURL)
	}
	// 失效缓存
	p.invalidateDerivedBaseURL()
	if p.cachedDerivedBaseURL != "" {
		t.Errorf("cache should be cleared, got %q", p.cachedDerivedBaseURL)
	}
	// 再次推导应重新计算
	url2 := p.deriveImageAssetBaseURL()
	if url2 == "" {
		t.Fatal("second derive returned empty")
	}
	// 两次结果应该一致（同一环境）
	if url1 != url2 {
		t.Logf("note: derive results differ between calls (env changed?): %q vs %q", url1, url2)
	}
}

// TestDeriveImageAssetBaseURL_ConcurrentWithInvalidate 检测 sync.Once 字段替换的数据竞态。
// 用 `go test -race` 运行：当前实现 p.derivedURLOnce = sync.Once{} 替换 struct 字段不是原子操作，
// 与并发 deriveImageAssetBaseURL 的 Do 调用访问同一字段会产生 DATA RACE。
func TestDeriveImageAssetBaseURL_ConcurrentWithInvalidate(t *testing.T) {
	p := &PlatformAdapterOnebot{
		Session: &IMSession{
			Parent: &Dice{Parent: &DiceManager{ServeAddress: "0.0.0.0:3211"}},
		},
		logger: zap.NewNop().Sugar(),
	}

	var wg sync.WaitGroup
	const workers = 8
	const iterations = 200

	// 一半 goroutine 持续 derive，一半持续 invalidate
	for w := range workers {
		wg.Add(1)
		go func(mode int) {
			defer wg.Done()
			for range iterations {
				if mode == 0 {
					_ = p.deriveImageAssetBaseURL()
				} else {
					p.invalidateDerivedBaseURL()
				}
			}
		}(w % 2)
	}
	wg.Wait()
}

// TestDeriveImageAssetBaseURLForDisplay_UrlConsistentWithCandidates 验证
// 返回的 url 与 candidates[0] 一致（之前实现两次调用 computeDerivedBaseURL，
// enumNonLoopbackIPv4 顺序不稳定导致 url 和 candidates 可能不匹配）。
func TestDeriveImageAssetBaseURLForDisplay_UrlConsistentWithCandidates(t *testing.T) {
	p := &PlatformAdapterOnebot{
		Session: &IMSession{
			Parent: &Dice{Parent: &DiceManager{ServeAddress: "0.0.0.0:3211"}},
		},
		logger: zap.NewNop().Sugar(),
	}
	url, candidates := p.DeriveImageAssetBaseURLForDisplay()
	if !strings.HasPrefix(url, "http://") {
		t.Fatalf("url should start with http://, got %q", url)
	}
	if candidates == nil {
		// 兜底场景（无非 loopback IPv4），url 必须是 127.0.0.1:3211
		if !strings.Contains(url, "127.0.0.1") {
			t.Errorf("no candidates but url is not loopback fallback: %q", url)
		}
		return
	}
	if len(candidates) == 0 {
		t.Fatal("candidates should be nil or non-empty")
	}
	// url 应该使用 candidates[0]
	expected := "http://" + candidates[0] + ":3211"
	if url != expected {
		t.Errorf("url %q should match candidates[0]: expected %q", url, expected)
	}
}
