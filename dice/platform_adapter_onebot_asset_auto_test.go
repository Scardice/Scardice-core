package dice

import (
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

func newServingAssetResolver(serveAddress string) *onebotAssetResolver {
	return &onebotAssetResolver{assetServeAddress: serveAddress, logger: zap.NewNop().Sugar()}
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
		{"1.2.3.4:0", "3211"},
		{"1.2.3.4:65536", "3211"},
	}
	for _, c := range cases {
		got := newServingAssetResolver(c.addr).extractServePort()
		if got != c.want {
			t.Errorf("addr=%q: want port %q, got %q", c.addr, c.want, got)
		}
	}
}

func TestDeriveImageAssetBaseURL_UserConfigWins(t *testing.T) {
	p := newServingAssetResolver("0.0.0.0:3211")
	p.ImageAssetBaseURL = "http://user-configured:9999"
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
	p := newServingAssetResolver("0.0.0.0:3211")
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
	p := newServingAssetResolver("0.0.0.0:3211")
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

// TestDeriveImageAssetBaseURL_ConcurrentWithInvalidate 在 `go test -race` 下检测缓存的并发读写。
func TestDeriveImageAssetBaseURL_ConcurrentWithInvalidate(t *testing.T) {
	p := newServingAssetResolver("0.0.0.0:3211")

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
	p := newServingAssetResolver("0.0.0.0:3211")
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
