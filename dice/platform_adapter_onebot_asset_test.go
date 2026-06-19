package dice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/message"
)

func newTestAdapter(t *testing.T) *PlatformAdapterOnebot {
	t.Helper()
	return &PlatformAdapterOnebot{
		logger: zap.NewNop().Sugar(),
	}
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
	p := newTestAdapter(t)
	_, err := p.resolveLocalAsset("/etc/passwd")
	if err == nil {
		t.Fatal("expected error for absolute path, got nil")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path error, got %v", err)
	}
}

func TestResolveLocalAsset_RejectTraversal(t *testing.T) {
	p := newTestAdapter(t)
	_, err := p.resolveLocalAsset("../../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for traversal path, got nil")
	}
}

func TestResolveLocalAsset_RejectOutsideWhitelist(t *testing.T) {
	p := newTestAdapter(t)
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

	p := newTestAdapter(t)
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

	p := newTestAdapter(t)
	p.ImageAssetBaseURL = "http://scardice-core:3211"
	p.Session = &IMSession{Parent: &Dice{Parent: &DiceManager{AssetImageToken: "testtoken123"}}}

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

	p := newTestAdapter(t)
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

	p := newTestAdapter(t)
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

	p := newTestAdapter(t)
	_, err := p.resolveLocalAsset("images/huge.bin")
	if err == nil {
		t.Fatal("expected error for >10MB file, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too large error, got %v", err)
	}
}

func TestConvertSealMsgToMessageChain_ImageWithHTTPURL(t *testing.T) {
	// 已有 scheme 的 URL 应原样直传
	p := newTestAdapter(t)
	input := []message.IMessageElement{
		&message.ImageElement{URL: "http://example.com/img.png"},
	}
	chain, cq := p.convertSealMsgToMessageChain(input)
	if len(chain) != 1 || chain[0].Type != "image" {
		t.Fatalf("expected 1 image chain element, got %v", chain)
	}
	if !strings.Contains(cq, "http://example.com/img.png") {
		t.Fatalf("expected http URL in cq, got %q", cq)
	}
}

func TestConvertSealMsgToMessageChain_ImageWithUppercaseScheme(t *testing.T) {
	// High #3: 大写 scheme 应被识别为 URL，直传不转 base64
	p := newTestAdapter(t)
	input := []message.IMessageElement{
		&message.ImageElement{URL: "HTTP://example.com/img.png"},
	}
	chain, cq := p.convertSealMsgToMessageChain(input)
	if len(chain) != 1 {
		t.Fatalf("expected 1 chain element, got %d", len(chain))
	}
	if !strings.Contains(cq, "HTTP://example.com/img.png") {
		t.Fatalf("expected uppercase HTTP URL preserved, got %q", cq)
	}
}
