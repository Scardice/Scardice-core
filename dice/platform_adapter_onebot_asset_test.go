package dice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func newTestAssetResolver(t *testing.T) *onebotAssetResolver {
	t.Helper()
	return &onebotAssetResolver{logger: zap.NewNop().Sugar()}
}

func TestHasURLScheme_CaseInsensitive(t *testing.T) {
	cases := map[string]bool{
		"http://example.com":  true,
		"https://example.com": true,
		"file:///etc/hosts":   true,
		"base64://aGVsbG8=":   true,
		"HTTP://EXAMPLE.COM":  true,
		"FILE:///etc/hosts":   true,
		"BASE64://aGVsbG8=":   true,
		"HtTp://mixed":        true,
		"data/images/foo.png": false,
		"./images/foo.png":    false,
		"images/foo.png":      false,
		"/etc/passwd":         false,
		"":                    false,
		"javascript:alert(1)": false, // 无 //
	}
	for in, want := range cases {
		got := hasURLScheme(in)
		if got != want {
			t.Errorf("hasURLScheme(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestResolveLocalAsset_RejectAbsolute(t *testing.T) {
	p := newTestAssetResolver(t)
	_, err := p.resolveLocalAsset("/etc/passwd")
	if err == nil {
		t.Fatal("expected error for absolute path, got nil")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestResolveLocalAsset_RejectTraversal(t *testing.T) {
	p := newTestAssetResolver(t)
	_, err := p.resolveLocalAsset("../../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for traversal path, got nil")
	}
}

func TestResolveLocalAsset_RejectOutsideWhitelist(t *testing.T) {
	p := newTestAssetResolver(t)
	_, err := p.resolveLocalAsset("database.log")
	if err == nil {
		t.Fatal("expected error for non-whitelisted dir, got nil")
	}
}

func TestResolveLocalAsset_SmallFileBase64(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	imgDir := filepath.Join("data", "images")
	_ = os.MkdirAll(imgDir, 0o755)
	small := []byte("hello world")
	_ = os.WriteFile(filepath.Join(imgDir, "small.txt"), small, 0o644)

	p := newTestAssetResolver(t)
	got, err := p.resolveLocalAsset("images/small.txt")
	if err != nil {
		t.Fatalf("resolveLocalAsset failed: %v", err)
	}
	if !strings.HasPrefix(got, "base64://") {
		t.Fatalf("expected base64:// prefix, got %q", got)
	}
}

func TestResolveLocalAsset_LargeFileHTTPURL(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	imgDir := filepath.Join("data", "images")
	_ = os.MkdirAll(imgDir, 0o755)
	large := make([]byte, 201*1024) // > 200KB
	_ = os.WriteFile(filepath.Join(imgDir, "large.bin"), large, 0o644)

	p := newTestAssetResolver(t)
	p.ImageAssetBaseURL = "http://scardice-core:3211"
	p.assetImageToken = "testtoken123"

	got, err := p.resolveLocalAsset("images/large.bin")
	if err != nil {
		t.Fatalf("resolveLocalAsset failed: %v", err)
	}
	if !strings.HasPrefix(got, "http://") {
		t.Fatalf("expected http:// prefix, got %q", got)
	}
	if !strings.Contains(got, "assets-img") {
		t.Fatalf("expected assets-img in URL, got %q", got)
	}
	if !strings.Contains(got, "testtoken123") {
		t.Fatalf("expected token in URL, got %q", got)
	}
}

func TestResolveLocalAsset_LargeFileFallbackBase64(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	imgDir := filepath.Join("data", "images")
	_ = os.MkdirAll(imgDir, 0o755)
	large := make([]byte, 201*1024)
	_ = os.WriteFile(filepath.Join(imgDir, "large.bin"), large, 0o644)

	p := newTestAssetResolver(t)
	// 未配置 ImageAssetBaseURL → 降级 base64
	got, err := p.resolveLocalAsset("images/large.bin")
	if err != nil {
		t.Fatalf("resolveLocalAsset failed: %v", err)
	}
	if !strings.HasPrefix(got, "base64://") {
		t.Fatalf("expected base64:// fallback, got %q", got)
	}
}

func TestResolveLocalAsset_SymlinkTraversalRejected(t *testing.T) {
	// Critical #1 PoC: data/images/evil-link -> /etc, resolveLocalAsset 必须
	// 通过 EvalSymlinks 拦截 symlink 穿越并返回 error。
	// 失败说明：若未返回 error，则 base64 路径会读取 /etc/passwd 内容并泄露给协议端。
	dir := t.TempDir()
	t.Chdir(dir)

	imgDir := filepath.Join("data", "images")
	_ = os.MkdirAll(imgDir, 0o755)
	// 创建指向 /etc 的符号链接
	if err := os.Symlink("/etc", filepath.Join(imgDir, "evil-link")); err != nil {
		// 某些环境（如无 /etc 或权限不足）无法创建 symlink，跳过
		t.Skipf("cannot create symlink to /etc: %v", err)
	}

	p := newTestAssetResolver(t)
	got, err := p.resolveLocalAsset("images/evil-link/passwd")
	if err == nil {
		t.Fatalf("FAIL: symlink traversal not blocked. got=%q (expected error)", got)
	}
	// 返回值不能包含 base64:// 前缀（否则意味着 /etc/passwd 被读取并编码）
	if strings.HasPrefix(got, "base64://") {
		t.Fatalf("FAIL: symlink traversal leaked file content as base64: %q", got[:min(60, len(got))]+"...")
	}
}

func TestResolveLocalAsset_TooLargeRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	imgDir := filepath.Join("data", "images")
	_ = os.MkdirAll(imgDir, 0o755)
	// 创建 > 10MB 文件
	huge := make([]byte, 10*1024*1024+1)
	_ = os.WriteFile(filepath.Join(imgDir, "huge.bin"), huge, 0o644)

	p := newTestAssetResolver(t)
	_, err := p.resolveLocalAsset("images/huge.bin")
	if err == nil {
		t.Fatal("expected error for >10MB file, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too large error, got %v", err)
	}
}

// 已有 scheme 的 URL 不应被当成本地资源：大小写不同的 scheme 同样直传。
func TestOutboundResourceKeepsRemoteSchemesVerbatimRegardlessOfCase(t *testing.T) {
	p := newTestAssetResolver(t)
	for _, reference := range []string{"http://example.com/img.png", "HTTP://example.com/img.png", "Https://example.com/img.png", "BASE64://aGVsbG8="} {
		got, err := resolveOnebotOutboundResource(p, reference, false)
		if err != nil || got != reference {
			t.Errorf("resolveOnebotOutboundResource(%q) = %q, %v; want it unchanged", reference, got, err)
		}
	}
}
